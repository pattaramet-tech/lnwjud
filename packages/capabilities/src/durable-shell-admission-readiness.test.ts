import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { WindowsNativeAuthority, type NativeAttemptBinding, type WindowsContainmentRpcRequest, type WindowsContainmentServiceClient } from '@lnwjud/process';
import { DurableShellTaskStore } from './durable-shell-task-store.js';
import { SharedManagedWriterAdmission } from './shared-managed-writer-admission.js';

// Every launch in this file stops at this isolated pre-spawn failure. Never
// dispatch a target, native helper, installed service or durable worker.
vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>();
  return { ...actual, spawn: vi.fn(() => { throw new Error('isolated pre-spawn failure'); }) };
});

const roots: string[] = [];
afterEach(async () => {
  vi.clearAllMocks();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function fixture(): Promise<{
  root: string; directory: string; authority: WindowsNativeAuthority; requests: WindowsContainmentRpcRequest[];
  setAvailabilityFailure(reason: string | undefined): void; setAbortUnavailable(value: boolean): void;
}> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'lnwjud-admission-readiness-'));
  roots.push(root);
  const requests: WindowsContainmentRpcRequest[] = [];
  const aborted = new Map<string, NativeAttemptBinding>();
  let availabilityFailure: string | undefined;
  let abortUnavailable = false;
  const client: WindowsContainmentServiceClient = {
    async request<T>(request: WindowsContainmentRpcRequest): Promise<T> {
      requests.push(request);
      if (request.command === 'check_readiness') {
        if (availabilityFailure !== undefined) throw new Error(availabilityFailure);
        return { protocol: 3, state: 'ready' } as T;
      }
      if (abortUnavailable) throw new Error('NATIVE_SERVICE_RPC_TIMEOUT');
      if (request.command === 'abort') aborted.set(request.identity.attemptId, request.identity);
      else if (request.command !== 'inspect' || JSON.stringify(aborted.get(request.identity.attemptId)) !== JSON.stringify(request.identity)) {
        throw new Error('ATTEMPT_OWNER_MISMATCH');
      }
      return { identity: request.identity, phase: 2, reservationHeld: false } as T;
    },
    async startWatcher(): Promise<void> { throw new Error('No watcher is permitted in the isolated fixture'); },
  };
  const authority = new WindowsNativeAuthority({ helper: { executable: path.join(root, 'helper.exe'), sha256: 'a'.repeat(64), buildId: 'lnwjud-containment-v2' },
    pin: { modulePath: path.join(root, 'pin.node'), sha256: 'b'.repeat(64) } }, client);
  return { root, directory: path.join(root, 'tasks'), authority, requests,
    setAvailabilityFailure: (reason): void => { availabilityFailure = reason; },
    setAbortUnavailable: (value): void => { abortUnavailable = value; } };
}

const launchRequest = (cwd: string): Parameters<DurableShellTaskStore['launch']>[0] => ({
  taskId: 'isolated-task', executable: process.execPath, arguments: [], cwd, timeoutSeconds: 10,
  includeStdout: false, includeStderr: false, maxOutputBytes: 1024,
  owner: { clientId: 'client', sessionId: 'session', workspaceId: 'workspace' },
});

async function activeFiles(directory: string): Promise<string[]> {
  return readdir(path.join(directory, '.index', 'v1', 'active')).catch(() => []);
}

describe('Windows admission before reservation', () => {
  it('refuses missing native authority and uncontained writers before any marker or process', async () => {
    const f = await fixture();
    expect(await new DurableShellTaskStore(f.directory, { platform: 'win32' }).launch(launchRequest(f.root))).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    const admission = new SharedManagedWriterAdmission(f.directory, undefined, 'win32');
    expect(await admission.enter({ actorClientId: 'client', workspaceId: 'workspace', kind: 'uncontained_process' })).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    expect(await activeFiles(f.directory)).toEqual([]);
    expect(spawn).not.toHaveBeenCalled();
    expect(f.requests).toEqual([]);
  });

  it.each(['SERVICE_ENDPOINT_NOT_INSTALLED', 'SERVICE_ENDPOINT_PACKAGE_MISMATCH', 'NATIVE_SERVICE_RPC_TIMEOUT', 'private error C:\\secret'])('retains old reservations and refuses repeated new admissions when service fails: %s', async (failure) => {
    const f = await fixture();
    f.setAvailabilityFailure(failure);
    const markers = path.join(f.directory, '.index', 'v1', 'active');
    await mkdir(markers, { recursive: true });
    const oldMarker = JSON.stringify({ version: 2, taskId: 'held-old-task', requestDigest: 'c'.repeat(64), mutationKind: 'opaque_uncontained', ownerClientId: 'old-client' });
    const oldPath = path.join(markers, createHash('sha256').update('held-old-task').digest('hex') + '.json');
    await writeFile(oldPath, oldMarker);
    const store = new DurableShellTaskStore(f.directory, { platform: 'win32', windowsNativeAuthority: f.authority });
    const admission = new SharedManagedWriterAdmission(f.directory, f.authority, 'win32');
    for (let retry = 0; retry < 3; retry += 1) {
      const shell = await store.launch(launchRequest(f.root));
      expect(shell).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
      expect(JSON.stringify(shell)).not.toContain('C:\\secret');
      expect(await admission.enter({ actorClientId: 'client', actorSessionId: 'session', workspaceId: 'workspace', kind: 'contained_process',
        nativeTaskId: 'native-task', nativeReceiptPath: path.join(f.root, 'native-task', 'containment.receipt.json') })).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    }
    expect(await activeFiles(f.directory)).toHaveLength(1);
    expect(await readFile(oldPath, 'utf8')).toBe(oldMarker);
    expect(f.requests).toHaveLength(6);
    expect(f.requests.every((request) => request.command === 'check_readiness')).toBe(true);
    expect(spawn).not.toHaveBeenCalled();
  });

  it('retries after transport recovery and releases pre-spawn failure only with authenticated abort proof', async () => {
    const f = await fixture();
    const store = new DurableShellTaskStore(f.directory, { platform: 'win32', windowsNativeAuthority: f.authority });
    f.setAvailabilityFailure('NATIVE_SERVICE_RPC_TIMEOUT');
    expect(await store.launch(launchRequest(f.root))).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    expect(await activeFiles(f.directory)).toEqual([]);
    f.setAvailabilityFailure(undefined);
    expect(await store.launch(launchRequest(f.root))).toMatchObject({ ok: false });
    expect(spawn).toHaveBeenCalledTimes(1);
    expect(f.requests.some((request) => request.command === 'abort')).toBe(true);
    expect(f.requests.some((request) => request.command === 'prepare' || request.command === 'run')).toBe(false);
    expect(await activeFiles(f.directory)).toEqual([]);
    expect(await store.launch(launchRequest(f.root))).toMatchObject({ ok: true, value: { state: 'failed' } });
    expect(spawn).toHaveBeenCalledTimes(1);
  });

  it('holds an interrupted pre-spawn reservation across restart when service abort proof is unavailable', async () => {
    const f = await fixture();
    f.setAbortUnavailable(true);
    const options = { platform: 'win32' as const, windowsNativeAuthority: f.authority };
    const store = new DurableShellTaskStore(f.directory, options);
    expect(await store.launch(launchRequest(f.root))).toMatchObject({ ok: false });
    expect(await activeFiles(f.directory)).toHaveLength(1);
    const restarted = new DurableShellTaskStore(f.directory, options);
    expect(await restarted.launch(launchRequest(f.root))).toMatchObject({ ok: true, value: { state: 'termination_unverified' } });
    expect(await activeFiles(f.directory)).toHaveLength(1);
    expect(spawn).toHaveBeenCalledTimes(1);
  });
});
