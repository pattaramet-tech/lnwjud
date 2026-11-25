import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { WindowsNativeAuthority } from '@lnwjud/process';
import { DurableShellTaskStore, durableShellNativeBinding } from './durable-shell-task-store.js';
import { SecureRepositoryImportRuntime } from './repository-import-runtime.js';
import { repositoryImportWorkerSource } from './repository-import-worker-source.js';

const owner = { clientId: 'client', sessionId: 'session', workspaceId: 'workspace' };
const requestId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const taskId = 'repository-import-' + requestId;
const commit = 'a'.repeat(40);
const identity = '0123456789ABCDEF-0123456789ABCDEF0123456789ABCDEF';
const binding = { taskId, reservationId: taskId, attemptId: taskId, generation: 1, requestDigest: 'b'.repeat(64), ownerClientId: owner.clientId, ownerSessionId: owner.sessionId, workspaceId: owner.workspaceId };

async function fixture(version = 2): Promise<{
  root: string; directory: string; manifest: Record<string, unknown>;
  inspectControl: ReturnType<typeof vi.fn>; control: ReturnType<typeof vi.fn>; runtime: SecureRepositoryImportRuntime;
}> {
  // Hosted Windows runners can expose the TEMP parent through an 8.3 alias.
  // The production import correctly refuses noncanonical workspace roots.
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'lnwjud-import-recovery-')));
  const directory = path.join(root, 'repository-imports', requestId); await mkdir(directory, { recursive: true });
  const originalInput = { request: { workspaceId: owner.workspaceId, requestId, url: 'https://example.invalid/repo.git', destination: 'published', commit }, owner, workspaceRoot: root };
  const requestDigest = createHash('sha256').update(JSON.stringify({ input: originalInput })).digest('hex');
  const core = { version, requestId, owner, commit, workspaceRoot: root, destination: 'published', url: originalInput.request.url, requestDigest, originalInput,
    stagePath: path.join(path.dirname(root), '.lnwjud-import-stage-' + requestId), privateHome: path.join(directory, 'home') };
  const manifestDigest = createHash('sha256').update(JSON.stringify(core)).digest('hex');
  const actualBinding = durableShellNativeBinding({
    mutationKind: 'repository_import', taskId, executable: process.execPath,
    arguments: [path.join(directory, 'worker.cjs'), path.join(directory, 'spec.json'), requestDigest, manifestDigest], cwd: directory,
    timeoutSeconds: 900, maxOutputBytes: 4096, includeStdout: true, includeStderr: false, owner,
  });
  const manifest = { ...core, manifestDigest, binding: actualBinding };
  await writeFile(path.join(directory, 'spec.json'), JSON.stringify(manifest));
  const inspectControl = vi.fn().mockResolvedValue({ state: 'termination_unknown', binding, reason: 'missing' });
  const control = vi.fn().mockResolvedValue({ state: 'termination_unknown', binding, reason: 'missing' });
  const authority = { inspectControl, control, config: {} } as unknown as WindowsNativeAuthority;
  return { root, directory, manifest, inspectControl, control, runtime: new SecureRepositoryImportRuntime(root, authority) };
}
function proof(state: 'prepared' | 'published' = 'published'): {
  state: string; binding: typeof binding; command: string;
  result: { version: number; state: 'prepared' | 'published'; nativeIdentity: string; commit: string };
} {
  return { state: 'control_verified', binding, command: state === 'prepared' ? 'prepare_import' : 'publish_import', result: { version: 2, state, nativeIdentity: identity, commit } };
}

afterEach(() => vi.restoreAllMocks());
describe('authenticated repository import recovery', () => {
  it('keeps launch admission starting until native acknowledgement instead of reporting failure', async () => {
    const f = await fixture();
    try {
      vi.spyOn(DurableShellTaskStore.prototype, 'snapshot').mockResolvedValue({ ok: true, value: { state: 'starting' } });
      expect(await f.runtime.status({ taskId, owner })).toMatchObject({ ok: true, value: { state: 'starting' } });
      expect(f.inspectControl).not.toHaveBeenCalled(); expect(f.control).not.toHaveBeenCalled();
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });
  it('leaves legacy unsigned publication unresolved without replay or native inspection', async () => {
    const f = await fixture(1);
    try {
      const launch = vi.spyOn(DurableShellTaskStore.prototype, 'launch');
      const snapshot = vi.spyOn(DurableShellTaskStore.prototype, 'snapshot');
      expect(await f.runtime.status({ taskId, owner })).toMatchObject({ ok: true, value: { state: 'unresolved', detail: expect.stringContaining('Legacy') } });
      expect(snapshot).not.toHaveBeenCalled(); expect(launch).not.toHaveBeenCalled(); expect(f.control).not.toHaveBeenCalled();
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });

  it('never trusts a shape-compatible unsigned receipt even after worker success', async () => {
    const f = await fixture();
    try {
      vi.spyOn(DurableShellTaskStore.prototype, 'snapshot').mockResolvedValue({ ok: true, value: { state: 'completed', exit_code: 0 } });
      await writeFile(path.join(f.directory, 'publication.json'), JSON.stringify(proof().result));
      expect(await f.runtime.status({ taskId, owner })).toMatchObject({ ok: true, value: { state: 'unresolved', detail: 'Native publication proof is incomplete' } });
      expect(f.control).not.toHaveBeenCalled();
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });

  it('keeps a stopped worker unresolved if authenticated preparation may precede a crashed rename', async () => {
    const f = await fixture();
    try {
      vi.spyOn(DurableShellTaskStore.prototype, 'snapshot').mockResolvedValue({ ok: true, value: { state: 'failed', exit_code: 7 } });
      f.inspectControl.mockImplementation(async (input: { command: string }) => input.command === 'prepare_import' ? proof('prepared') : { state: 'termination_unknown' });
      expect(await f.runtime.status({ taskId, owner })).toMatchObject({ ok: true, value: { state: 'unresolved', detail: expect.stringContaining('publication may have occurred') } });
      expect(f.control).not.toHaveBeenCalled();
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });

  it.skipIf(process.platform !== 'win32')('requires authenticated live native identity and successful worker cessation before completion', async () => {
    const f = await fixture();
    try {
      const snapshot = vi.spyOn(DurableShellTaskStore.prototype, 'snapshot').mockResolvedValue({ ok: true, value: { state: 'completed', exit_code: 0 } });
      f.inspectControl.mockResolvedValue(proof()); f.control.mockResolvedValue(proof());
      expect(await f.runtime.status({ taskId, owner })).toMatchObject({ ok: true, value: { state: 'completed', native_identity: identity } });
      f.control.mockResolvedValue({ ...proof(), result: { ...proof().result, nativeIdentity: '0'.repeat(16) + '-' + '0'.repeat(32) } });
      expect(await f.runtime.status({ taskId, owner })).toMatchObject({ ok: true, value: { state: 'unresolved' } });
      snapshot.mockResolvedValue({ ok: true, value: { state: 'termination_unverified' } });
      f.control.mockClear();
      expect(await f.runtime.status({ taskId, owner })).toMatchObject({ ok: true, value: { state: 'unresolved' } });
      expect(f.control).not.toHaveBeenCalled();
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });

  it.skipIf(process.platform !== 'win32')('reconciles existing native publication before returning a stale worker state', async () => {
    const f = await fixture();
    try {
      const snapshot = vi.spyOn(DurableShellTaskStore.prototype, 'snapshot')
        .mockResolvedValueOnce({ ok: true, value: { state: 'termination_unverified' } })
        .mockResolvedValue({ ok: true, value: { state: 'completed', exit_code: 0 } });
      f.inspectControl.mockImplementation(async (input: { command: string }) =>
        input.command === 'publish_import' ? proof() : { state: 'termination_unknown' });
      f.control.mockResolvedValue(proof());
      const result = await f.runtime.status({ taskId, owner });
      expect(snapshot).toHaveBeenCalledTimes(2);
      expect(f.inspectControl).toHaveBeenCalledWith(expect.objectContaining({ command: 'publish_import' }));
      expect(result).toMatchObject({ ok: true, value: { state: 'completed', native_identity: identity } });
      expect(f.control).not.toHaveBeenCalledWith(expect.objectContaining({ command: 'publish_import' }));
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });

  it('uses the original digest-bound executable rather than the upgraded runtime path', async () => {
    const f = await fixture();
    try {
      const { manifestDigest: _digest, binding: _binding, ...core } = f.manifest;
      const launchExecutable = path.join(f.root, 'old-install', 'lnwjud.exe');
      const upgradedCore = { ...core, launchExecutable };
      const manifestDigest = createHash('sha256').update(JSON.stringify(upgradedCore)).digest('hex');
      const originalBinding = durableShellNativeBinding({
        mutationKind: 'repository_import', taskId, executable: launchExecutable,
        arguments: [path.join(f.directory, 'worker.cjs'), path.join(f.directory, 'spec.json'), String(core.requestDigest), manifestDigest],
        cwd: f.directory, timeoutSeconds: 900, maxOutputBytes: 4096, includeStdout: true, includeStderr: false, owner,
      });
      const manifest = { ...upgradedCore, manifestDigest, binding: originalBinding };
      await writeFile(path.join(f.directory, 'spec.json'), JSON.stringify(manifest));
      vi.spyOn(DurableShellTaskStore.prototype, 'snapshot').mockResolvedValue({ ok: true, value: { state: 'starting' } });
      expect(await f.runtime.status({ taskId, owner })).toMatchObject({ ok: true, value: { state: 'starting' } });
      await writeFile(path.join(f.directory, 'spec.json'), JSON.stringify({ ...manifest, launchExecutable: process.execPath }));
      expect(await f.runtime.status({ taskId, owner })).toMatchObject({ ok: false, error: { code: 'PERMISSION_DENIED' } });
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });

  it('uses a digest-matching durable worker spec for a legacy manifest after executable relocation', async () => {
    const f = await fixture();
    try {
      const oldExe = path.join(f.root, 'old-slot', 'lnwjud.exe');
      const args = [path.join(f.directory, 'worker.cjs'), path.join(f.directory, 'spec.json'), String(f.manifest.requestDigest), String(f.manifest.manifestDigest)];
      const oldBinding = durableShellNativeBinding({
        mutationKind: 'repository_import', taskId, executable: oldExe, arguments: args,
        cwd: f.directory, timeoutSeconds: 900, maxOutputBytes: 4096, includeStdout: true, includeStderr: false, owner,
      });
      const directory = path.join(f.root, 'background-tasks', taskId);
      await mkdir(directory, { recursive: true });
      const started = new Date().toISOString();
      await writeFile(path.join(directory, 'task.json'), JSON.stringify({
        version: 2, task_id: taskId, state: 'running', started_at: started, deadline_at: started,
        include_stdout: true, include_stderr: false, max_output_bytes: 4096,
        owner_client_id: owner.clientId, owner_session_id: owner.sessionId, owner_workspace_id: owner.workspaceId,
        request_digest: oldBinding.requestDigest, containment: 'windows_job_v2', containmentBinding: oldBinding,
      }));
      const spec = { version: 1, taskId, executable: oldExe, arguments: args, cwd: f.directory,
        timeoutMs: 900_000, maxOutputBytes: 4096, includeStdout: true, includeStderr: false,
        electronRunAsNode: true, requestDigest: oldBinding.requestDigest, native: { binding: oldBinding } };
      await writeFile(path.join(f.directory, 'spec.json'), JSON.stringify({ ...f.manifest, binding: oldBinding }));
      await writeFile(path.join(directory, 'spec.json'), JSON.stringify(spec));
      vi.spyOn(DurableShellTaskStore.prototype, 'snapshot').mockResolvedValue({ ok: true, value: { state: 'starting' } });
      expect(await f.runtime.status({ taskId, owner })).toMatchObject({ ok: true, value: { state: 'starting' } });
      await writeFile(path.join(directory, 'spec.json'), JSON.stringify({ ...spec, executable: process.execPath }));
      expect(await f.runtime.status({ taskId, owner })).toMatchObject({ ok: false, error: { code: 'PERMISSION_DENIED' } });
      expect(f.control).not.toHaveBeenCalled();
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });

  it('uses explicit owner cancellation to recover a terminal import blocked by its native hold', async () => {
    const f = await fixture();
    try {
      const snapshot = vi.spyOn(DurableShellTaskStore.prototype, 'snapshot').mockResolvedValue({ ok: true, value: { state: 'failed', exit_code: 1 } });
      const cancel = vi.spyOn(DurableShellTaskStore.prototype, 'cancel');
      const aborted = { ...proof(), binding: f.manifest.binding, command: 'abort_import', result: { ...proof().result, state: 'aborted' } };
      f.control.mockResolvedValue(aborted); f.inspectControl.mockResolvedValue(aborted);
      expect(await f.runtime.cancel({ taskId, owner })).toMatchObject({ ok: true, value: { state: 'cancelled', import_outcome: 'aborted' } });
      expect(f.control).toHaveBeenCalledWith(expect.objectContaining({ binding: f.manifest.binding, command: 'abort_import', request: {
        workspaceRoot: f.root, destination: 'published', stagePath: f.manifest.stagePath, privateHome: f.manifest.privateHome, commit,
      } }));
      expect(cancel).not.toHaveBeenCalled();
      const release = vi.spyOn(DurableShellTaskStore.prototype, 'repositoryImportReservationReleased').mockResolvedValue(false);
      expect(await f.runtime.status({ taskId, owner })).toMatchObject({ ok: true, value: { state: 'unresolved', import_outcome: 'aborted', detail: 'Native abort verified; runtime reservation release is not verified' } });
      expect(release).toHaveBeenCalledWith(f.manifest.binding);
      release.mockRestore();
      snapshot.mockResolvedValue({ ok: true, value: { state: 'termination_unverified' } });
      expect(await f.runtime.status({ taskId, owner })).toMatchObject({ ok: true, value: { state: 'unresolved', import_outcome: 'aborted' } });
      expect(f.control).toHaveBeenCalledTimes(1);
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });

  it('never starts abort recovery for a foreign owner or legacy manifest', async () => {
    const f = await fixture(1);
    try {
      const cancel = vi.spyOn(DurableShellTaskStore.prototype, 'cancel').mockResolvedValue({ ok: true, value: { state: 'termination_unverified' } });
      expect(await f.runtime.cancel({ taskId, owner: { ...owner, sessionId: 'foreign' } })).toMatchObject({ ok: false, error: { code: 'PERMISSION_DENIED' } });
      expect(cancel).not.toHaveBeenCalled();
      expect(await f.runtime.cancel({ taskId, owner })).toMatchObject({ ok: true, value: { state: 'unresolved' } });
      expect(f.control).not.toHaveBeenCalled();
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });

  it('separately host-approved recovery retains original binding and never cancels an active or unverified task', async () => {
    const f = await fixture();
    try {
      const cancel = vi.spyOn(DurableShellTaskStore.prototype, 'cancel');
      const nextOwner = { ...owner, sessionId: 'http-reconnected' };
      expect(await f.runtime.status({ taskId, owner: nextOwner })).toMatchObject({ ok: false, error: { code: 'PERMISSION_DENIED' } });
      expect(await f.runtime.recoverTerminal({ taskId, owner: { ...nextOwner, clientId: 'foreign' }, workspaceRoot: f.root })).toMatchObject({ ok: false });
      expect(await f.runtime.recoverTerminal({ taskId, owner: nextOwner, workspaceRoot: f.root + '-foreign' })).toMatchObject({ ok: false });
      expect(f.control).not.toHaveBeenCalled();
      expect(await f.runtime.recoverTerminal({ taskId, owner: nextOwner, workspaceRoot: f.root })).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
      expect(cancel).not.toHaveBeenCalled();
      expect(f.control).toHaveBeenCalledWith(expect.objectContaining({ binding: f.manifest.binding, command: 'abort_import', request: expect.objectContaining({ recoverLegacy: true }) }));
      f.control.mockResolvedValue({ state: 'termination_unknown', reason: 'SERVICE_IMPORT_LEGACY_NEW_BOOT_REQUIRED' });
      expect(await f.runtime.recoverTerminal({ taskId, owner: nextOwner, workspaceRoot: f.root })).toMatchObject({ ok: false, error: { code: 'CONFLICT', message: expect.stringContaining('distinct verified kernel boot') } });
      expect(cancel).not.toHaveBeenCalled();
      const aborted = { ...proof(), binding: f.manifest.binding, command: 'abort_import', result: { ...proof().result, state: 'aborted' } };
      f.control.mockResolvedValue(aborted); f.inspectControl.mockImplementation(async (input: { command: string }) =>
        input.command === 'abort_import' ? aborted : { state: 'termination_unknown' });
      const snapshot = vi.spyOn(DurableShellTaskStore.prototype, 'snapshot').mockResolvedValue({ ok: true, value: { state: 'failed', exit_code: 1 } });
      expect(await f.runtime.recoverTerminal({ taskId, owner: nextOwner, workspaceRoot: f.root })).toMatchObject({ ok: true, value: { state: 'cancelled', import_outcome: 'aborted' } });
      expect(snapshot).toHaveBeenCalledWith(taskId, undefined, owner);
      expect(cancel).not.toHaveBeenCalled();
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });

  it('does not report cancellation as verified when native abort is refused', async () => {
    const f = await fixture();
    try {
      vi.spyOn(DurableShellTaskStore.prototype, 'cancel').mockResolvedValue({ ok: true, value: { state: 'termination_unverified' } });
      vi.spyOn(DurableShellTaskStore.prototype, 'snapshot').mockResolvedValue({ ok: true, value: { state: 'termination_unverified' } });
      expect(await f.runtime.cancel({ taskId, owner })).toMatchObject({ ok: true, value: { state: 'unresolved' } });
      expect(f.control).toHaveBeenCalledTimes(2);
      for (const [invocation] of f.control.mock.calls) expect(invocation.request).not.toHaveProperty('recoverLegacy');
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });

  it('does not expose another owner manifest', async () => {
    const f = await fixture();
    try {
      expect(await f.runtime.status({ taskId, owner: { ...owner, sessionId: 'other' } })).toMatchObject({ ok: false, error: { code: 'PERMISSION_DENIED' } });
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });

  it('rejects a manifest whose receipt binding is copied from another attempt or owner', async () => {
    const f = await fixture();
    try {
      for (const changed of [{ attemptId: 'other' }, { reservationId: 'other' }, { ownerSessionId: 'other' }, { workspaceId: 'other' }, { generation: 2 }]) {
        await writeFile(path.join(f.directory, 'spec.json'), JSON.stringify({ ...f.manifest, binding: { ...binding, ...changed } }));
        expect(await f.runtime.status({ taskId, owner })).toMatchObject({ ok: false, error: { code: 'PERMISSION_DENIED' } });
      }
      expect(f.inspectControl).not.toHaveBeenCalled();
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });

  it('rejects changed manifest content before trusting any publication or launching a helper', async () => {
    const f = await fixture();
    try {
      for (const changed of [{ destination: 'foreign' }, { workspaceRoot: f.root + '-foreign' }, { url: 'https://example.invalid/other.git' }, { stagePath: 'C:\\foreign' }, { processModule: 'C:\\foreign.js' }]) {
        await writeFile(path.join(f.directory, 'spec.json'), JSON.stringify({ ...f.manifest, ...changed }));
        expect(await f.runtime.status({ taskId, owner })).toMatchObject({ ok: false, error: { code: 'PERMISSION_DENIED' } });
      }
      expect(f.inspectControl).not.toHaveBeenCalled(); expect(f.control).not.toHaveBeenCalled();
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });

  it.skipIf(process.platform !== 'win32')('observes a repeated request without cloning or publishing again after interrupted admission', async () => {
    const f = await fixture();
    try {
      const input = { request: { workspaceId: owner.workspaceId, requestId, url: 'https://example.invalid/repo.git', destination: 'published', commit }, owner, workspaceRoot: f.root };
      const requestDigest = createHash('sha256').update(JSON.stringify({ input })).digest('hex');
      await writeFile(path.join(f.directory, 'spec.json'), JSON.stringify({ ...f.manifest, requestDigest }));
      vi.spyOn(DurableShellTaskStore.prototype, 'snapshot').mockResolvedValue({ ok: false, error: { code: 'PROCESS_NOT_FOUND', message: 'missing', recoverable: false } });
      const launch = vi.spyOn(DurableShellTaskStore.prototype, 'launch');
      expect(await f.runtime.start(input)).toMatchObject({ ok: true, value: { state: 'unresolved' } });
      expect(launch).not.toHaveBeenCalled(); expect(f.control).not.toHaveBeenCalled();
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });

  it('removes executable PowerShell control assets from the worker and verifies durable authenticated readback', () => {
    expect(repositoryImportWorkerSource).not.toMatch(/powershell|ExecutionPolicy|Bypass|stage-acl\.ps1|publish\.ps1/i);
    expect(repositoryImportWorkerSource).toContain('authority.inspectControl');
    expect(repositoryImportWorkerSource).toContain("JSON.stringify({ input: spec.originalInput })");
  });
});
