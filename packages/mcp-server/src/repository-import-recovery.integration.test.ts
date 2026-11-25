import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { RepositoryImportService } from '@lnwjud/application';
import { SecureRepositoryImportRuntime, SharedManagedWriterAdmission, SqliteWorkspaceWriterLease } from '@lnwjud/capabilities';
import { permissionProfiles } from '@lnwjud/permissions';
import { WindowsNativeAuthority, type WindowsContainmentRpcRequest, type WindowsContainmentServiceClient } from '@lnwjud/process';
import { DurableShellTaskIndex } from '../../capabilities/src/durable-shell-task-index.js';
import { durableShellNativeBinding } from '../../capabilities/src/durable-shell-task-store.js';
import { ToolRegistry, type HostMutationApprovalRequest } from './tool-registry.js';

const nativeFixture = process.env.LNWJUD_NATIVE_IMPORT_RECOVERY_FIXTURE;

async function ready(child: ChildProcess): Promise<string> {
  return new Promise((resolve, reject) => {
    let output = '';
    let errors = '';
    const timer = setTimeout(() => reject(new Error('Native fixture startup timed out: ' + errors)), 15_000);
    child.stderr?.on('data', (chunk) => { errors += String(chunk); });
    child.stdout?.on('data', (chunk) => {
      output += String(chunk);
      const match = /READY (lnwjud-import-recovery-fixture-[0-9a-f]{32})\r?\n/.exec(output);
      if (match) { clearTimeout(timer); resolve(match[1]!); }
    });
    child.once('error', (error) => { clearTimeout(timer); reject(error); });
    child.once('exit', (code) => { clearTimeout(timer); reject(new Error('Native fixture exited: ' + code + ' ' + errors)); });
  });
}

describe('terminal repository import recovery integration', () => {
  // CI explicitly builds and supplies this test-only executable on Windows.
  it.skipIf(process.platform !== 'win32' || !nativeFixture)('recovers across MCP, real native service RPC and durable admission without taking a writer lease', async () => {
    const root = await realpath(await mkdtemp(path.join(tmpdir(), 'lnwjud-mcp-import-recovery-')));
    let server: ChildProcess | undefined;
    try {
      const workspaceId = 'workspace-a';
      const clientId = 'client-a';
      const owner = { clientId, sessionId: 'http-original', workspaceId };
      const requestId = randomUUID();
      const taskId = 'repository-import-' + requestId;
      const workspaceRoot = path.join(root, 'workspace');
      const stagePath = path.join(root, '.lnwjud-import-stage-' + randomUUID());
      const privateHome = path.join(root, 'home');
      const commit = 'a'.repeat(40);
      const destination = 'repo';
      const directory = path.join(root, 'repository-imports', requestId);
      const tasks = path.join(root, 'background-tasks');
      const taskDir = path.join(tasks, taskId);
      await mkdir(directory, { recursive: true });
      await mkdir(taskDir, { recursive: true });
      const originalInput = { request: { workspaceId, requestId, url: 'https://example.invalid/repo.git', destination, commit }, owner, workspaceRoot };
      const requestDigest = createHash('sha256').update(JSON.stringify({ input: originalInput })).digest('hex');
      const configuration = {
        helper: { executable: nativeFixture!, sha256: 'a'.repeat(64), buildId: 'lnwjud-containment-v2' },
        pin: { modulePath: path.join(root, 'fixture-pin.node'), sha256: 'a'.repeat(64) },
        profileDirectory: path.join(root, 'profile'),
      } as const;
      const core = { version: 2, requestDigest, owner, requestId, url: originalInput.request.url, commit,
        workspaceRoot, destination, stagePath, privateHome, authorityConfig: configuration, processModule: 'fixture',
        launchExecutable: process.execPath, originalInput };
      const manifestDigest = createHash('sha256').update(JSON.stringify(core)).digest('hex');
      const binding = durableShellNativeBinding({
        mutationKind: 'repository_import', taskId, executable: process.execPath,
        arguments: [path.join(directory, 'worker.cjs'), path.join(directory, 'spec.json'), requestDigest, manifestDigest],
        cwd: directory, timeoutSeconds: 900, maxOutputBytes: 4096, includeStdout: true, includeStderr: false, owner,
      });
      await writeFile(path.join(directory, 'spec.json'), JSON.stringify({ ...core, manifestDigest, binding }));
      await writeFile(path.join(root, 'fixture.json'), JSON.stringify({ identity: binding, request: { workspaceRoot, destination, stagePath, privateHome, commit } }));
      server = spawn(nativeFixture!, ['import-recovery-fixture-server', path.basename(root)], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
      const pipe = await ready(server);
      const rpcLog: WindowsContainmentRpcRequest[] = [];
      const client: WindowsContainmentServiceClient = {
        async request<T>(request: WindowsContainmentRpcRequest): Promise<T> {
          rpcLog.push(request);
          const reply = JSON.parse(execFileSync(nativeFixture!, ['import-recovery-fixture-rpc', pipe], {
            input: JSON.stringify(request) + '\n', encoding: 'utf8', windowsHide: true, timeout: 12_000, maxBuffer: 1024 * 1024,
          })) as { protocol: number; ok: boolean; result: T; error?: string };
          if (reply.protocol !== 3 || !reply.ok) throw new Error(reply.error ?? 'Native fixture RPC refused');
          return reply.result;
        },
        async startWatcher(): Promise<void> { /* The fixture has a real isolated server. */ },
      };
      const authority = new WindowsNativeAuthority(configuration, client);
      const nativeBefore = await client.request<{ phase: number; reservationHeld: boolean }>({ protocol: 3, command: 'inspect', identity: binding });
      expect(nativeBefore).toMatchObject({ phase: 4, reservationHeld: true });
      const admission = new SharedManagedWriterAdmission(tasks, authority, 'win32');
      let time = Date.now();
      const lease = new SqliteWorkspaceWriterLease(path.join(root, 'leases.sqlite'), () => time, admission);
      const priorLease = await lease.acquire(workspaceId, clientId, owner.sessionId, 30);
      expect(priorLease.ok).toBe(true);
      const start = new Date(Date.now() - 60_000).toISOString();
      await writeFile(path.join(taskDir, 'task.json'), JSON.stringify({
        version: 2, task_id: taskId, state: 'running', started_at: start, deadline_at: new Date(Date.now() + 600_000).toISOString(),
        include_stdout: true, include_stderr: false, max_output_bytes: 4096, worker_pid: 99999999, worker_started_at: start,
        owner_client_id: clientId, owner_session_id: owner.sessionId, owner_workspace_id: workspaceId,
        request_digest: binding.requestDigest, containment: 'windows_job_v2', containmentBinding: binding,
      }));
      const index = new DurableShellTaskIndex(tasks, { maxConcurrentTasks: 8, inspectTask: async () => 'active' });
      expect(await index.reserve({ taskId, capacityClass: 'durable_shell', mutationKind: 'repository_import',
        requestDigest: binding.requestDigest, ownerClientId: clientId, ownerWorkspaceId: workspaceId,
        nativeBinding: binding, nativeReceiptPath: path.join(taskDir, 'containment.receipt.json') })).toMatchObject({ ok: true });
      time += 31_000;
      expect(await lease.acquire(workspaceId, clientId, 'http-reconnected', 60)).toMatchObject({ ok: false });
      const runtime = new SecureRepositoryImportRuntime(root, authority);
      const repositoryImport = new RepositoryImportService({ get: async (id: string) => id === workspaceId ? { realRootPath: workspaceRoot } : null } as never, runtime);
      const services = { workspaceWriterLease: lease, repositoryImport };
      const approval: HostMutationApprovalRequest[] = [];
      const registry = (sessionId: string, caller = clientId, approved = true, bypass = false): ToolRegistry =>
        new ToolRegistry(services, { clientId: caller, clientName: 'fixture' }, {
          sessionId, profileProvider: () => permissionProfiles.full,
          ...(bypass ? { authorizationModeProvider: () => 'full_bypass' as const } : {}),
          activeWorkspaceScopeProvider: () => ({ workspaceId, rootPath: workspaceRoot }),
          hostMutationApprovalProvider: async (request) => { approval.push(request); return approved; },
        });
      const reconnect = registry('http-reconnected');
      const handle = { workspaceId, taskId };
      const recover = { ...handle, recoverTerminal: true, userConfirmed: true };
      expect((await reconnect.invoke('git_clone_status', handle)).isError).toBe(true);
      expect((await reconnect.invoke('git_clone_cancel', { ...handle, userConfirmed: true })).isError).toBe(true);
      expect((await reconnect.invoke('git_clone_cancel', { ...handle, recoverTerminal: true })).isError).toBe(true);
      expect((await registry('http-reconnected', clientId, false).invoke('git_clone_cancel', recover)).isError).toBe(true);
      expect((await registry('http-reconnected', 'foreign-client').invoke('git_clone_cancel', recover)).isError).toBe(true);
      expect((await registry('http-reconnected', clientId, true, true).invoke('git_clone_cancel', recover)).isError).toBe(true);
      expect(rpcLog.some((r) => r.command === 'control' && r.controlCommand === 'abort_import')).toBe(false);
      expect(await index.hasReservation(taskId, binding.requestDigest)).toBe(true);
      expect(await client.request({ protocol: 3, command: 'inspect', identity: binding })).toMatchObject({ phase: 4, reservationHeld: true });

      const result = await reconnect.invoke('git_clone_cancel', recover);
      if (result.isError) throw new Error(JSON.stringify(result));
      expect(result.structuredContent).toMatchObject({ state: 'cancelled', import_outcome: 'aborted' });
      expect(approval.some((request) => request.summary.includes(taskId) && request.summary.includes(workspaceId))).toBe(true);
      const abortRequests = rpcLog.filter((r) => r.command === 'control' && r.controlCommand === 'abort_import');
      expect(abortRequests).toHaveLength(1);
      expect(abortRequests[0]).toMatchObject({ identity: binding, controlRequest: { recoverLegacy: true } }); // original HTTP session, not impersonated current binding
      expect(await client.request({ protocol: 3, command: 'inspect', identity: binding })).toMatchObject({ phase: 4, reservationHeld: false });
      expect(await index.hasReservation(taskId, binding.requestDigest)).toBe(false);
      expect(await lease.inspect(workspaceId)).toMatchObject({ ok: true, value: { state: 'expired', generation: 1, activeCalls: 0 } });
      expect(await lease.acquire(workspaceId, clientId, 'http-reconnected', 60)).toMatchObject({ ok: true, value: { generation: 2 } });
      expect(await readFile(path.join(workspaceRoot, destination, 'existing.txt'), 'utf8')).toBe('preserve destination');
      expect(await readFile(path.join(stagePath, 'stage.txt'), 'utf8')).toBe('preserve stage');
      const nextId = randomUUID();
      const nextBinding = { ...binding, taskId: nextId, reservationId: nextId, attemptId: nextId, requestDigest: 'b'.repeat(64), ownerSessionId: 'http-reconnected' };
      const operation = { kind: 'run_process' as const, executable: nativeFixture!, args: ['sleep', '10'], cwd: root,
        timeoutMs: 1000, windowsVerbatimArguments: false, environment: {}, maximumOutputBytes: 1024 };
      expect(await client.request({ protocol: 3, command: 'prepare', identity: nextBinding, reservationKey: 'fixture', operation })).toMatchObject({ phase: 0, reservationHeld: true });
      expect(await client.request({ protocol: 3, command: 'abort', identity: nextBinding, reservationKey: 'fixture', operation })).toMatchObject({ phase: 2 });
      console.log('PASS MCP host approval, cross-session terminal-only recovery, native hold and durable index released, next writer admitted');
    } finally {
      if (server && server.exitCode === null && server.signalCode === null) {
        const done = once(server, 'close');
        server.stdin?.end('\n');
        const timeout = setTimeout(() => server?.kill(), 10_000);
        try { await done; } finally { clearTimeout(timeout); }
      }
      await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  }, 60_000);
});
