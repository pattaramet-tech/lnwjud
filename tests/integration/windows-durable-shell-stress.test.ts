import { execFile } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { PathExecutableResolver, toWindowsSpawnInvocation } from '@lnwjud/process';
import { expect, it } from 'vitest';
import { DurableShellTaskStore, durableShellNativeBinding, type DurableShellLaunchRequest } from '../../packages/capabilities/src/durable-shell-task-store.js';
import { createHostWindowsNativeAuthority } from '../../packages/capabilities/src/host-native-authority.js';
import { SharedManagedWriterAdmission } from '../../packages/capabilities/src/shared-managed-writer-admission.js';

const phases = [
  { concurrency: 1, taskCount: 16 },
  { concurrency: 2, taskCount: 32 },
  { concurrency: 4, taskCount: 64 },
  { concurrency: 8, taskCount: 888 },
];
const runBudgetMs = 23 * 60_000;
const runOnHostedWindows = process.env.LNWJUD_WINDOWS_DURABLE_STRESS === '1';
const emptyReservations = {
  durable_shell_reservations: 0,
  managed_writer_reservations: 0,
  unresolved_reservations: 0,
  unreadable_reservations: 0,
  blockers: [],
  exclusive_writer_blocked: false,
};

function stdoutFor(taskId: string): string {
  return `  ${taskId} ไทย 😀\n`;
}

function stderrFor(taskId: string): string {
  return `\t${taskId} warning ไทย\n`;
}

const childSource = String.raw`
import { existsSync } from 'node:fs';
import { setTimeout } from 'node:timers/promises';
const [taskId, gate] = process.argv.slice(2);
while (gate && !existsSync(gate)) await setTimeout(25);
process.stdout.write('  ' + taskId + ' ไทย 😀\n');
process.stderr.write('\t' + taskId + ' warning ไทย\n');
`;

const sha256 = (data: Buffer | string): string => createHash('sha256').update(data).digest('hex');
type Authority = NonNullable<ReturnType<typeof createHostWindowsNativeAuthority>>;

function disposableServiceDirectory(): string {
  const { GITHUB_ACTIONS, GITHUB_RUN_ID, RUNNER_ENVIRONMENT, RUNNER_OS, ProgramFiles } = process.env;
  if (process.platform !== 'win32' || process.arch !== 'x64' || RUNNER_OS !== 'Windows'
    || RUNNER_ENVIRONMENT !== 'github-hosted' || GITHUB_ACTIONS !== 'true'
    || GITHUB_RUN_ID === undefined || !/^\d+$/.test(GITHUB_RUN_ID)
    || ProgramFiles === undefined || !path.isAbsolute(ProgramFiles)) {
    throw new Error('The native stress fixture requires a disposable GitHub-hosted Windows x64 runner');
  }
  return path.join(ProgramFiles, `lnwjud-ci-${GITHUB_RUN_ID}`, 'resources', 'native-containment');
}

async function assertDisposableService(authority: Authority, serviceDirectory: string): Promise<void> {
  const installedHelper = path.join(serviceDirectory, 'lnwjud-containment.exe');
  const installedPin = path.join(serviceDirectory, 'lnwjud-containment-pin.node');
  const { stdout } = await promisify(execFile)('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-Command',
    `Get-CimInstance Win32_Service -Filter "Name='LnwjudContainment'" | Select-Object State, StartName, PathName | ConvertTo-Json -Compress`,
  ], { timeout: 10_000, windowsHide: true });
  const service = JSON.parse(stdout);
  expect(service).toMatchObject({ State: 'Running', StartName: 'LocalSystem' });
  expect(String(service.PathName).toLowerCase()).toBe(`"${installedHelper}" service`.toLowerCase());
  expect(sha256(await readFile(installedHelper))).toBe(authority.configuration.helper.sha256);
  expect(sha256(await readFile(installedPin))).toBe(authority.configuration.pin.sha256);
}

async function checkResult(
  store: DurableShellTaskStore,
  authority: Authority,
  stateDirectory: string,
  request: DurableShellLaunchRequest,
): Promise<Record<string, unknown>> {
  const taskDirectory = path.join(stateDirectory, request.taskId);
  const binding = durableShellNativeBinding(request);
  // Avoid adding native RPC traffic while the detached worker is capturing its
  // short-lived child. Verify the canonical worker write before asking for the
  // supported result, which also verifies and releases the application marker.
  await expect.poll(async () => {
    const raw = await readFile(path.join(taskDirectory, 'task.json'), 'utf8').catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT' || error.code === 'EBUSY' || error.code === 'EACCES' || error.code === 'EPERM') return undefined;
      throw error;
    });
    return raw === undefined ? undefined : JSON.parse(raw);
  }, { timeout: 60_000, interval: 100 }).toMatchObject({
    task_id: request.taskId, containmentBinding: binding, finished_at: expect.any(String), output_finalized: true,
  });
  const observed = await store.wait(request.taskId, 10, undefined, request.owner);
  if (!observed.ok) throw new Error(`Task ${request.taskId} result read failed: ${observed.error.message}`);
  expect(observed.value).toMatchObject({ task_id: request.taskId, exit_code: expect.any(Number), durable: true,
    truncated: false, stdout: expect.any(String), stderr: expect.any(String),
  });
  expect(observed.value.state).toBe(observed.value.exit_code === 0 ? 'completed' : 'failed');
  expect(await authority.inspect({ directory: taskDirectory, binding })).toEqual({
    state: 'terminal_verified', binding, outcome: 'completed', exitCode: observed.value.exit_code, activeProcesses: 0,
  });
  const marker = path.join(stateDirectory, '.index', 'v1', 'active', `${sha256(request.taskId)}.json`);
  await expect(access(marker)).rejects.toMatchObject({ code: 'ENOENT' });
  return observed.value;
}

it.runIf(runOnHostedWindows)('verifies 1,000 short native tasks and writer release at 1, 2, 4 and 8 agents', async () => {
  const serviceDirectory = disposableServiceDirectory();
  const root = await mkdtemp(path.join(os.tmpdir(), 'lnwjud-durable-stress-'));
  const stateDirectory = path.join(root, 'tasks');
  const authority = createHostWindowsNativeAuthority(root);
  if (authority === undefined) throw new Error('The opt-in native stress fixture must run on Windows');
  await assertDisposableService(authority, serviceDirectory);
  const store = new DurableShellTaskStore(stateDirectory, { windowsNativeAuthority: authority });
  const admission = new SharedManagedWriterAdmission(stateDirectory, authority);
  const script = path.join(root, 'short-task.mjs');
  const workspaceIds = new Set<string>();
  const taskIds = new Set<string>();
  const startedAt = Date.now();
  let completed = false;
  try {
    await writeFile(script, childSource, { flag: 'wx' });
    expect(await store.admissionDiagnostics()).toMatchObject(emptyReservations);
    for (const { concurrency, taskCount } of phases) {
      const beganAt = Date.now();
      const gate = path.join(root, `release-${concurrency}`);
      const lanes = await Promise.all(Array.from({ length: concurrency }, async (_, lane) => {
        const workspaceId = `stress-workspace-${concurrency}-${lane}`;
        const cwd = path.join(root, workspaceId);
        await mkdir(cwd);
        workspaceIds.add(workspaceId);
        return { cwd, owner: { clientId: 'windows-stress-client', sessionId: `http-stress-${concurrency}-${lane}`, workspaceId } };
      }));
      const launch = async (lane: number, held: boolean): Promise<DurableShellLaunchRequest> => {
        if (Date.now() - startedAt >= runBudgetMs) throw new Error('Native stress fixture exceeded its launch time budget');
        const taskId = randomUUID();
        const request: DurableShellLaunchRequest = {
          ...lanes[lane]!, taskId, executable: process.execPath,
          arguments: [script, taskId, ...(held ? [gate] : [])], timeoutSeconds: 45,
          maxOutputBytes: 1024, includeStdout: true, includeStderr: true,
        };
        expect(taskIds.has(taskId)).toBe(false);
        taskIds.add(taskId);
        expect(await store.launch(request)).toMatchObject({ ok: true, value: { task_id: taskId, durable: true } });
        return request;
      };

      // The first task in each lane stays alive until this shared gate opens,
      // making the exact peak reservation count observable without timing races.
      const held = await Promise.allSettled(lanes.map((_, lane) => launch(lane, true)));
      let initialRequests: DurableShellLaunchRequest[];
      let reservationsBeforeResults: number;
      try {
        initialRequests = held.map((result) => {
          if (result.status === 'rejected') throw result.reason;
          return result.value;
        });
        const heldDiagnostics = await store.admissionDiagnostics();
        reservationsBeforeResults = heldDiagnostics.durable_shell_reservations;
        expect(heldDiagnostics).toMatchObject({
          durable_shell_reservations: concurrency, managed_writer_reservations: 0,
          unresolved_reservations: concurrency, unreadable_reservations: 0, exclusive_writer_blocked: true,
        });
        expect(heldDiagnostics.blockers.map((marker) => marker.reservation_id).sort())
          .toEqual(initialRequests.map(({ taskId }) => sha256(taskId)).sort());
        const blocked = await admission.holdExclusiveProbe('stress-distinct-writer-workspace');
        if (blocked.ok) await blocked.value.releaseAfterVerifiedTermination();
        expect(blocked).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
      } finally {
        await writeFile(gate, '', { flag: 'wx' });
      }

      let stopLaunching = false;
      const verify = async (request: DurableShellLaunchRequest): Promise<void> => {
        expect(await checkResult(store, authority, stateDirectory, request)).toMatchObject({
          state: 'completed', exit_code: 0, stdout: stdoutFor(request.taskId), stderr: stderrFor(request.taskId),
        });
      };
      const results = await Promise.allSettled(lanes.map(async (_, lane) => {
        try {
          const first = initialRequests[lane]!;
          const otherSession = { ...first.owner, sessionId: 'http-stress-foreign' };
          const otherWorkspace = { ...first.owner, workspaceId: 'stress-foreign-workspace' };
          for (const requester of [otherSession, otherWorkspace]) {
            expect(await store.snapshot(first.taskId, undefined, requester)).toMatchObject({ ok: false, error: { code: 'PERMISSION_DENIED' } });
            expect(await store.launch({ ...first, owner: requester })).toMatchObject({ ok: false, error: { code: 'PERMISSION_DENIED' } });
          }
          await verify(first);
          for (let index = concurrency + lane; index < taskCount && !stopLaunching; index += concurrency) {
            await verify(await launch(lane, false));
          }
        } catch (error) {
          stopLaunching = true;
          throw error;
        }
      }));
      const failure = results.find((result) => result.status === 'rejected');
      if (failure !== undefined) throw failure.reason;
      const after = await store.admissionDiagnostics();
      expect(after).toMatchObject(emptyReservations);
      const probe = await admission.holdExclusiveProbe('stress-distinct-writer-workspace');
      expect(probe.ok).toBe(true);
      if (!probe.ok) throw new Error(probe.error.message);
      try {
        expect(await store.admissionDiagnostics()).toMatchObject({ ...emptyReservations,
          managed_writer_reservations: 1, unresolved_reservations: 1, exclusive_writer_blocked: true,
          blockers: [expect.objectContaining({ reservation_id: sha256(probe.value.id) })],
        });
      } finally {
        await probe.value.releaseAfterVerifiedTermination();
      }
      expect(await store.admissionDiagnostics()).toMatchObject(emptyReservations);
      console.info(JSON.stringify({ concurrency, verifiedTasks: taskCount, reservationsBeforeResults,
        reservationsAfterResults: after.unresolved_reservations, elapsedMs: Date.now() - beganAt }));
    }
    expect(workspaceIds.size).toBe(15);
    expect(taskIds.size).toBe(1_000);
    const journal = (await readFile(path.join(stateDirectory, '.index', 'v1', 'launches.jsonl'), 'utf8')).trim().split('\n');
    expect(journal).toHaveLength(1_000);
    expect(new Set(journal.map((line) => JSON.parse(line).taskId))).toEqual(taskIds);
    expect(await store.admissionDiagnostics()).toMatchObject(emptyReservations);
    completed = true;
  } finally {
    if (completed) {
      await rm(root, { recursive: true, force: true, maxRetries: 30, retryDelay: 100 });
    } else {
      // The runner is disposable. Preserve failed-attempt evidence without
      // deleting an active marker while its native task may still be held.
      console.error(`Native stress fixture retained at ${root}`);
    }
  }
}, 24 * 60_000);

it.runIf(runOnHostedWindows)('observes native receipts and release for the affected Windows command shapes', async () => {
  const serviceDirectory = disposableServiceDirectory();
  const root = await mkdtemp(path.join(os.tmpdir(), 'lnwjud-durable-smoke-'));
  const stateDirectory = path.join(root, 'tasks');
  const authority = createHostWindowsNativeAuthority(root);
  if (authority === undefined) throw new Error('The opt-in native command fixture must run on Windows');
  await assertDisposableService(authority, serviceDirectory);
  const store = new DurableShellTaskStore(stateDirectory, { windowsNativeAuthority: authority });
  const resolver = new PathExecutableResolver();
  const owner = { clientId: 'windows-smoke-client', sessionId: 'http-smoke', workspaceId: 'smoke-workspace' };
  const commands = [
    { executable: 'docker', args: ['ps', '-a', '--format', '{{.Names}} {{.Image}} {{.Ports}} {{.Status}}'] },
    { executable: 'docker', args: ['version'] },
    { executable: 'node', args: ['--version'], version: /^v\d+\.\d+\.\d+/ },
    { executable: 'pnpm', args: ['--version'], version: /^\d+\.\d+\.\d+/ },
  ];
  let completed = false;
  try {
    expect(await store.admissionDiagnostics()).toMatchObject(emptyReservations);
    for (const command of commands) {
      const resolved = await resolver.resolve(command.executable);
      if (!resolved.ok) {
        expect(command.executable).toBe('docker');
        expect(resolved.error.code).toBe('EXECUTABLE_NOT_FOUND');
        console.info(JSON.stringify({ command: [command.executable, ...command.args], result: 'executable_not_found' }));
        continue;
      }
      const invocation = toWindowsSpawnInvocation(resolved.value, command.args);
      if (!invocation.ok) throw new Error(invocation.error.message);
      const request: DurableShellLaunchRequest = {
        taskId: randomUUID(), cwd: root, owner, executable: invocation.value.executable, arguments: invocation.value.args,
        ...(invocation.value.windowsVerbatimArguments === undefined ? {} : { windowsVerbatimArguments: invocation.value.windowsVerbatimArguments }),
        timeoutSeconds: 30, maxOutputBytes: 16 * 1024, includeStdout: true, includeStderr: true,
      };
      expect(await store.launch(request)).toMatchObject({ ok: true, value: { task_id: request.taskId, durable: true } });
      const result = await checkResult(store, authority, stateDirectory, request);
      const exitCode = result.exit_code;
      const stdout = String(result.stdout);
      let disposition = 'verified_exit';
      if (command.executable === 'docker' && exitCode !== 0) {
        expect(`${stdout}\n${String(result.stderr)}`).toMatch(/failed to connect to the Docker API|cannot connect to the docker daemon|error during connect|docker daemon .* running|open .*docker.*engine/i);
        disposition = 'docker_daemon_unavailable';
      } else {
        expect(exitCode).toBe(0);
        if (command.version !== undefined) expect(stdout.trim()).toMatch(command.version);
      }
      expect(await store.admissionDiagnostics()).toMatchObject(emptyReservations);
      console.info(JSON.stringify({ command: [command.executable, ...command.args], result: disposition, exitCode,
        ...(command.version === undefined ? {} : { version: stdout.trim() }), reservations: 0 }));
    }
    completed = true;
  } finally {
    if (completed) await rm(root, { recursive: true, force: true, maxRetries: 30, retryDelay: 100 });
    else console.error(`Native command fixture retained at ${root}`);
  }
}, 5 * 60_000);
