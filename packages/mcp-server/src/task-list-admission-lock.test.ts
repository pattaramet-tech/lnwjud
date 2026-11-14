import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ShellCapabilityBackend } from '@lnwjud/capabilities';
import { WindowsNativeAuthority } from '@lnwjud/process';
import { DurableShellTaskIndex } from '../../capabilities/src/durable-shell-task-index.js';
import { CAPABILITY_TASK_OWNER_METADATA_KEY } from '../../capabilities/src/task-ownership.js';
import { UpgradeRuntimeService } from './upgrade-runtime.js';
import { mapResult, type McpToolResponse } from './result-mapper.js';

const roots: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function snapshot(root: string): Promise<Record<string, string>> {
  const files: Record<string, string> = {};
  async function visit(directory: string): Promise<void> {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const filename = path.join(directory, entry.name);
      if (entry.isDirectory()) await visit(filename);
      else files[path.relative(root, filename)] = (await readFile(filename)).toString('base64');
    }
  }
  await visit(root);
  return files;
}

async function fixture(version: number | null = 2): Promise<{
  root: string; tasks: string; index: string; active: string;
  owner: { clientId: string; sessionId: string; workspaceId: string };
  backend: ShellCapabilityBackend; list: () => Promise<McpToolResponse>; request: ReturnType<typeof vi.fn>;
}> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'lnwjud-task-list-diagnostic-'));
  roots.push(root);
  const tasks = path.join(root, 'tasks');
  const index = path.join(tasks, '.index', 'v1');
  const active = path.join(index, 'active');
  const taskId = 'private-task';
  const owner = { clientId: 'private-client', sessionId: 'private-session', workspaceId: 'workspace' };
  const digest = 'a'.repeat(64);
  await mkdir(active, { recursive: true });
  await mkdir(path.join(tasks, taskId));
  if (version !== null) await writeFile(path.join(index, 'ready.json'), JSON.stringify({
    version: 1, markerFormatVersion: version, readyAt: new Date(0).toISOString(),
  }));
  const marker = { version: 2, taskId, requestDigest: digest, mutationKind: 'opaque',
    capacityClass: 'durable_shell', ownerClientId: owner.clientId, ownerWorkspaceId: owner.workspaceId };
  await writeFile(path.join(active, createHash('sha256').update(taskId).digest('hex') + '.json'), JSON.stringify(marker));
  await writeFile(path.join(tasks, taskId, 'task.json'), JSON.stringify({
    version: 1, task_id: taskId, state: 'completed', request_digest: digest,
    started_at: new Date(0).toISOString(), finished_at: new Date(1000).toISOString(),
    deadline_at: new Date(10000).toISOString(), exit_code: 0,
    include_stdout: false, include_stderr: false, max_output_bytes: 1024,
    owner_client_id: owner.clientId, owner_session_id: owner.sessionId, owner_workspace_id: owner.workspaceId,
  }));
  await writeFile(path.join(index, 'launches.jsonl'), JSON.stringify({ version: 1, taskId,
    startedAt: new Date(0).toISOString(), ownerClientId: owner.clientId, ownerSessionId: owner.sessionId,
    ownerWorkspaceId: owner.workspaceId }) + '\n');
  const request = vi.fn(async (): Promise<never> => { throw new Error('Diagnosis must not invoke native containment'); });
  const authority = new WindowsNativeAuthority({
    helper: { executable: path.join(root, 'not-a-real-helper.exe'), sha256: 'a'.repeat(64), buildId: 'lnwjud-containment-v2' },
    pin: { modulePath: path.join(root, 'not-a-real-pin.node'), sha256: 'b'.repeat(64) },
  }, { request, async startWatcher(): Promise<void> { throw new Error('Diagnosis must not launch a watcher'); } });
  const backend = new ShellCapabilityBackend({ allowedRoots: [root], taskStateDirectory: tasks, windowsNativeAuthority: authority });
  const runtime = new UpgradeRuntimeService({ capabilities: {
    async execute(tool, input, signal, authorization): ReturnType<ShellCapabilityBackend['execute']> {
      if (tool !== 'shell') throw new Error('Unexpected capability');
      return backend.execute(input, signal, authorization);
    },
  } }, { clientId: owner.clientId, clientName: 'test', sessionId: owner.sessionId });
  const list = async (): Promise<McpToolResponse> => mapResult(await runtime.execute('task_list', { workspaceId: owner.workspaceId }));
  return { root, tasks, index, active, owner, backend, list, request };
}

describe('task_list admission diagnostics', () => {
  it('preserves trusted lock timeout and safe retry guidance without changing reservations', async () => {
    const f = await fixture();
    const lock = path.join(f.index, 'index.lock');
    await writeFile(lock, JSON.stringify({ version: 1, pid: process.pid, acquiredAt: new Date().toISOString() }));
    const before = await snapshot(f.tasks);
    const started = Date.now();
    let ticks = 0;
    const clock = vi.spyOn(Date, 'now').mockImplementation(() => started + ticks++ * 10001);
    try {
      for (let retry = 0; retry < 2; retry++) {
        const result = await f.list();
        expect(result).toMatchObject({ isError: true, structuredContent: { error: {
          code: 'CONFLICT', recoverable: true,
          message: expect.stringMatching(/retry the same request/),
          details: { reason: 'DURABLE_TASK_INDEX_LOCK_BUSY', retry_after_ms: 15 },
        } } });
        expect(JSON.stringify(result)).not.toContain(f.root);
        expect(JSON.stringify(result)).not.toContain(String(process.pid));
        expect(JSON.stringify(result)).not.toMatch(/private-task|private-client|private-session|leaseToken|index\.lock/);
        expect(await snapshot(f.tasks)).toEqual(before);
      }
    } finally { clock.mockRestore(); }
    await rm(lock); // Only this fixture's lock, after the simulated owner releases it.
    const afterUnlock = await snapshot(f.tasks);
    expect(await f.list()).toMatchObject({ structuredContent: { admission: { unresolved_reservations: 1, exclusive_writer_blocked: true } } });
    expect(await snapshot(f.tasks)).toEqual(afterUnlock);
    expect(f.request).not.toHaveBeenCalled();
  });

  it.each([null, 1])('does not initialize, migrate or create reservations in an unready index (%s)', async (version) => {
    const f = await fixture(version);
    await rm(f.active, { recursive: true });
    await mkdir(f.active);
    const before = await snapshot(f.tasks);
    expect(await f.list()).toMatchObject({ isError: true, structuredContent: { error: {
      code: 'CONFLICT', details: { reason: 'DURABLE_TASK_INDEX_NOT_READY' },
    } } });
    expect(await snapshot(f.tasks)).toEqual(before);
    expect(f.request).not.toHaveBeenCalled();
  });

  it.each([undefined, 1])('does not release terminal reservations while listing metadata (limit %s)', async (limit) => {
    const f = await fixture();
    const before = await snapshot(f.tasks);
    const result = limit === undefined ? await f.list() : mapResult(await f.backend.execute({
      operation: 'list', limit, metadata: { [CAPABILITY_TASK_OWNER_METADATA_KEY]: f.owner },
    }));
    expect(result).toMatchObject({ structuredContent: { tasks: [{ state: 'completed' }], admission: { unresolved_reservations: 1 } } });
    expect(await snapshot(f.tasks)).toEqual(before);
    expect(f.request).not.toHaveBeenCalled();
  });

  it('does not rebuild a missing launch journal during paginated diagnostics', async () => {
    const f = await fixture();
    await rm(path.join(f.index, 'launches.jsonl'));
    const before = await snapshot(f.tasks);
    const result = await f.backend.execute({ operation: 'list', limit: 1, metadata: { [CAPABILITY_TASK_OWNER_METADATA_KEY]: f.owner } });
    expect(result).toMatchObject({ ok: false, error: { code: 'CONFLICT', details: { reason: 'DURABLE_TASK_INDEX_NOT_READY' } } });
    expect(await snapshot(f.tasks)).toEqual(before);
  });

  it('keeps arbitrary or forged errors generic and redacted', async () => {
    const f = await fixture();
    const diagnostic = vi.spyOn(DurableShellTaskIndex.prototype, 'diagnostics');
    for (const error of [new Error('Durable task index lock is busy'),
      Object.assign(new Error('private path: ' + f.root), { details: { reason: 'DURABLE_TASK_INDEX_LOCK_BUSY' } })]) {
      diagnostic.mockRejectedValueOnce(error);
      const result = await f.list();
      expect(result).toMatchObject({ isError: true, structuredContent: { error: { code: 'INTERNAL_ERROR', message: 'Operation failed' } } });
      expect(JSON.stringify(result)).not.toContain(f.root);
      expect(JSON.stringify(result)).not.toContain('DURABLE_TASK_INDEX_LOCK_BUSY');
    }
  });

  it('does not reclaim a synchronous reservation or request process/native proof during index diagnostics', async () => {
    const f = await fixture();
    const [filename] = await readdir(f.active);
    const target = path.join(f.active, filename!);
    const marker = JSON.parse(await readFile(target, 'utf8'));
    await writeFile(target, JSON.stringify({ ...marker, mutationKind: 'synchronous_mutation', launcherPid: 99999999 }));
    const inspectTask = vi.fn(async () => 'terminal' as const);
    const isProcessProvenGone = vi.fn(() => true);
    const verifyContainedTermination = vi.fn(async () => true);
    const index = new DurableShellTaskIndex(f.tasks, { maxConcurrentTasks: 16, inspectTask, isProcessProvenGone, verifyContainedTermination });
    const before = await snapshot(f.tasks);
    expect(await index.diagnostics()).toMatchObject({ unresolved_reservations: 1 });
    expect(inspectTask).not.toHaveBeenCalled();
    expect(isProcessProvenGone).not.toHaveBeenCalled();
    expect(verifyContainedTermination).not.toHaveBeenCalled();
    expect(await snapshot(f.tasks)).toEqual(before);
  });
});
