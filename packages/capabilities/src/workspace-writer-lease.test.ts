import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, describe, expect, it } from 'vitest';
import { appError } from '@lnwjud/domain';
import { SqliteWorkspaceWriterLease, type WorkspaceWriterGlobalExclusion } from './workspace-writer-lease.js';

const roots: string[] = [];
const WINDOWS_WRITER_IO_TEST_TIMEOUT_MS = process.platform === 'win32' ? 20_000 : 5_000;
afterEach(async () => { await Promise.all(roots.splice(0).map((r) => rm(r, { recursive: true, force: true }))); });

async function fixture(now?: () => number): Promise<{ one: SqliteWorkspaceWriterLease; two: SqliteWorkspaceWriterLease }> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'lnwjud-workspace-lease-'));
  roots.push(root);
  const filename = path.join(root, 'fences.sqlite');
  return {
    one: new SqliteWorkspaceWriterLease(filename, now),
    two: new SqliteWorkspaceWriterLease(filename, now),
  };
}

describe('durable multi-session workspace writer lease', () => {
  it('refuses release during native writer activity instead of creating an unleased mutation window', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'lnwjud-release-native-block-'));
    roots.push(root);
    let nativeBusy = false;
    let probeCalls = 0;
    const exclusion = {
      async holdExclusiveProbe(): ReturnType<WorkspaceWriterGlobalExclusion['holdExclusiveProbe']> {
        probeCalls += 1;
        return nativeBusy
          ? { ok: false as const, error: appError('CONFLICT', 'Native writer is still active') }
          : { ok: true as const, value: { releaseAfterVerifiedTermination: async (): Promise<void> => undefined } };
      },
    };
    const lease = new SqliteWorkspaceWriterLease(path.join(root, 'fences.sqlite'), Date.now, exclusion);
    const acquired = await lease.acquire('workspace', 'owner', 'session', 60);
    expect(acquired.ok).toBe(true);
    if (!acquired.ok) return;
    nativeBusy = true;
    const beforeReleaseProbes = probeCalls;
    expect(await lease.release('workspace', 'owner', 'session', acquired.value)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    expect(probeCalls).toBe(beforeReleaseProbes + 1);
    expect(await lease.inspect('workspace')).toMatchObject({ ok: true, value: { state: 'active' } });
    expect(await lease.begin('workspace', 'other-owner', 'other-session', 'unleased-mutation'))
      .toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    expect(await lease.acquire('workspace', 'other-owner', 'other-session', 60))
      .toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    nativeBusy = false;
    expect(await lease.release('workspace', 'owner', 'session', acquired.value)).toMatchObject({ ok: true });
    expect(await lease.inspect('workspace')).toMatchObject({ ok: true, value: { state: 'unleased' } });
  }, WINDOWS_WRITER_IO_TEST_TIMEOUT_MS);

  it('prevents a lease from racing a mutation admitted while no lease existed', async () => {
    const { one, two } = await fixture();
    const admitted = await one.begin('workspace', 'unleased-client', 'session-one', 'unleased-call');
    expect(admitted).toMatchObject({ ok: true, value: { required: false, generation: 0 } });
    expect(await two.inspect('workspace')).toMatchObject({
      ok: true, value: { state: 'blocked', activeCalls: 1, generation: 0 },
    });
    expect(await two.assessAbandonment('workspace', 'new-owner'))
      .toMatchObject({ ok: true, value: { live: true, reason: 'live_invocation' } });
    expect(await two.revokeAbandoned('workspace', 'new-owner'))
      .toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    expect(await two.acquire('workspace', 'new-owner', 'session-two', 60))
      .toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    await one.end('workspace', 'unleased-call', 0);
    expect(await two.acquire('workspace', 'new-owner', 'session-two', 60))
      .toMatchObject({ ok: true, value: { generation: 1 } });
  }, WINDOWS_WRITER_IO_TEST_TIMEOUT_MS);

  it('journals terminal-only recovery without granting or renewing a writer lease', async () => {
    let time = 100_000;
    const { one, two } = await fixture(() => time);
    const task = 'repository-import-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
    const first = await one.acquire('workspace', 'owner', 'old-session', 30);
    if (!first.ok) throw new Error('lease setup failed');
    expect(await one.beginTerminalImportRecovery('workspace', 'owner', 'new-session', 'active', task)).toMatchObject({ ok: false });
    expect(await one.begin('workspace', 'owner', 'old-session', 'live-call', first.value)).toMatchObject({ ok: true });
    time += 31_000;
    expect(await two.beginTerminalImportRecovery('workspace', 'owner', 'new-session', 'blocked', task)).toMatchObject({ ok: false });
    await one.end('workspace', 'live-call', first.value.generation);
    expect(await two.beginTerminalImportRecovery('workspace', 'foreign', 'new-session', 'foreign', task)).toMatchObject({ ok: false });
    expect(await two.beginTerminalImportRecovery('workspace', 'owner', 'new-session', 'stale', task, first.value)).toMatchObject({ ok: false });
    expect(await two.beginTerminalImportRecovery('workspace', 'owner', 'new-session', 'recovery', task)).toMatchObject({ ok: true, value: { required: false, generation: 1 } });
    expect(await one.acquire('workspace', 'owner', 'new-session', 60)).toMatchObject({ ok: false });
    expect(await one.begin('workspace', 'owner', 'old-session', 'write', first.value)).toMatchObject({ ok: false });
    await expect(two.heartbeat('workspace', 'recovery', 1)).rejects.toThrow();
    expect(await one.inspect('workspace')).toMatchObject({ ok: true, value: { generation: 1, activeCalls: 1, state: 'blocked' } });
    await two.end('workspace', 'recovery', 1);
    expect(await one.inspect('workspace')).toMatchObject({ ok: true, value: { generation: 1, activeCalls: 0, state: 'expired' } });
    expect(await one.acquire('workspace', 'owner', 'new-session', 60)).toMatchObject({ ok: true, value: { generation: 2 } });
  }, WINDOWS_WRITER_IO_TEST_TIMEOUT_MS);

  it('migrates an old SQLite schema and fences exact pre-upgrade INSERTs during recovery', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'lnwjud-mixed-writer-'));
    roots.push(root);
    const filename = path.join(root, 'fences.sqlite');
    const old = new DatabaseSync(filename);
    try {
      old.exec(`CREATE TABLE workspace_writer_leases (
        workspace_id TEXT PRIMARY KEY, generation INTEGER NOT NULL, lease_id TEXT, token_hash TEXT,
        owner_client_id TEXT, owner_session_id TEXT, expires_at INTEGER NOT NULL DEFAULT 0,
        last_activity_at INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE workspace_writer_calls (call_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL,
          generation INTEGER NOT NULL, pid INTEGER NOT NULL);`);
      // The exact column list used by pre-upgrade begin(), including unleased calls.
      const oldInsert = (id: string, ws: string, generation: number): unknown =>
        old.prepare('INSERT INTO workspace_writer_calls(call_id,workspace_id,generation,pid) VALUES(?,?,?,?)')
          .run(id, ws, generation, process.pid);
      oldInsert('prior', 'unleased', 0);
      const upgraded = new SqliteWorkspaceWriterLease(filename, () => 100_000);
      expect(await upgraded.inspect('unleased')).toMatchObject({ ok: true, value: { state: 'blocked', activeCalls: 1 } });
      const task = 'repository-import-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
      expect(await upgraded.beginTerminalImportRecovery('unleased', 'owner', 'new', 'r0', task)).toMatchObject({ ok: false });
      await upgraded.end('unleased', 'prior', 0);
      expect(await upgraded.beginTerminalImportRecovery('unleased', 'owner', 'new', 'r0', task)).toMatchObject({ ok: true });
      expect(() => oldInsert('old-1', 'unleased', 0)).toThrow(/TERMINAL_IMPORT_RECOVERY_IN_FLIGHT/);
      expect(() => oldInsert('unrelated', 'another-workspace', 0)).not.toThrow();
      const active = await upgraded.acquire('leased', 'owner', 'new', 60);
      if (!active.ok) throw new Error('fixture lease refused');
      expect(await upgraded.beginTerminalImportRecovery('leased', 'owner', 'new', 'r1', task, active.value)).toMatchObject({ ok: true });
      expect(() => oldInsert('old-2', 'leased', active.value.generation)).toThrow(/TERMINAL_IMPORT_RECOVERY_IN_FLIGHT/);
      expect(await upgraded.inspect('leased')).toMatchObject({ ok: true, value: { generation: 1, activeCalls: 1 } });
      await upgraded.end('leased', 'r1', active.value.generation);
      await upgraded.end('unleased', 'r0', 0);
      expect(() => oldInsert('old-after', 'leased', active.value.generation)).not.toThrow();
      expect(() => oldInsert('old-after2', 'unleased', 0)).not.toThrow();
    } finally { old.close(); }
  }, WINDOWS_WRITER_IO_TEST_TIMEOUT_MS);

  it('rejects lease proof when there is no active lease instead of silently ignoring it', async () => {
    const { one } = await fixture();
    expect(await one.begin('workspace', 'owner', 'session', 'forged-call', {
      leaseId: 'none', leaseToken: 'none', generation: 0,
    })).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
  });

  it('excludes independent processes/clients from the same workspace while allowing other workspaces', async () => {
    const { one, two } = await fixture();
    const acquired = await one.acquire('workspace', 'client-one', 'session-one', 60);
    expect(acquired.ok).toBe(true);
    if (!acquired.ok) return;
    expect(await two.acquire('workspace', 'client-two', 'session-two', 60)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    expect(await two.begin('workspace', 'client-two', 'session-two', 'other-call')).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    expect(await two.begin('workspace', 'client-one', 'wrong-session', 'other-call', acquired.value)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    expect(await two.begin('workspace-two', 'client-two', 'session-two', 'other-call')).toMatchObject({ ok: true, value: { required: false } });
    const admitted = await one.begin('workspace', 'client-one', 'session-one', 'owned-call', acquired.value);
    expect(admitted).toMatchObject({ ok: true, value: { required: true } });
    expect(await two.release('workspace', 'client-one', 'session-one', acquired.value)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    await one.end('workspace', 'owned-call', acquired.value.generation);
    expect(await two.release('workspace', 'client-one', 'session-one', acquired.value)).toMatchObject({ ok: true });
    expect(await two.begin('workspace', 'client-two', 'session-two', 'next-call')).toMatchObject({ ok: true, value: { required: false } });
  }, 20_000);

  it('rotates fencing generation on expiry, rejects stale proof and recovers a stopped owner', async () => {
    let time = 0;
    const { one, two } = await fixture(() => time);
    const first = await one.acquire('workspace', 'owner', 'session', 30);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    time = 40_000;
    const second = await two.acquire('workspace', 'new-owner', 'new-session', 30);
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    expect(second.value.generation).toBe(first.value.generation + 1);
    expect(await one.begin('workspace', 'owner', 'session', 'stale', first.value)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    expect(await one.release('workspace', 'owner', 'session', first.value)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    expect(await two.begin('workspace', 'new-owner', 'new-session', 'new-call', second.value)).toMatchObject({ ok: true });
    await two.end('workspace', 'new-call', second.value.generation);
  });

  it('refuses expiry takeover while a live prior invocation is still pinned', async () => {
    let time = 0;
    const { one, two } = await fixture(() => time);
    const first = await one.acquire('workspace', 'owner', 'session', 30);
    if (!first.ok) throw new Error('unexpected acquisition failure');
    expect(await one.begin('workspace', 'owner', 'session', 'running', first.value)).toMatchObject({ ok: true });
    time = 35_000;
    expect(await two.acquire('workspace', 'different', 'session-2', 30)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    await one.end('workspace', 'running', first.value.generation);
    expect(await two.acquire('workspace', 'different', 'session-2', 30)).toMatchObject({ ok: true });
  });

  it('does not prematurely recover a pre-migration lease with unknown activity', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'lnwjud-writer-upgrade-'));
    roots.push(root);
    const filename = path.join(root, 'existing.sqlite');
    const db = new DatabaseSync(filename);
    try {
      db.exec('CREATE TABLE workspace_writer_leases (workspace_id TEXT PRIMARY KEY, generation INTEGER NOT NULL, lease_id TEXT, token_hash TEXT, owner_client_id TEXT, owner_session_id TEXT, expires_at INTEGER NOT NULL DEFAULT 0)');
      db.prepare('INSERT INTO workspace_writer_leases VALUES (?,?,?,?,?,?,?)')
        .run('workspace', 12, 'old-lease', 'old-digest', 'owner', 'prior', 500_000);
    } finally {
      db.close();
    }
    const lease = new SqliteWorkspaceWriterLease(filename, () => 100_000);
    expect(await lease.inspect('workspace')).toMatchObject({ ok: true, value: { state: 'active', generation: 12 } });
    expect(await lease.acquire('workspace', 'owner', 'new-session', 600, true))
      .toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
  });

  it('recovers an idle same-client session after grace and revokes stale proof', async () => {
    let time = 100_000;
    const { one, two } = await fixture(() => time);
    const first = await one.acquire('workspace', 'owner', 'old-session', 600);
    if (!first.ok) throw new Error('unexpected lease failure');
    expect(await two.acquire('workspace', 'owner', 'new-session', 600, true)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    time += 61_000;
    expect(await two.acquire('workspace', 'other-owner', 'new-session', 600, true)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    expect(await two.assessAbandonment('workspace', 'owner')).toMatchObject({ ok: true, value: { live: false, reason: 'idle_beyond_grace' } });
    expect(await two.acquire('workspace', 'owner', 'new-session', 600))
      .toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    const second = await two.acquire('workspace', 'owner', 'new-session', 600, true);
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    expect(second.value.generation).toBe(first.value.generation + 1);
    expect(await one.begin('workspace', 'owner', 'old-session', 'stale', first.value)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    expect(await one.release('workspace', 'owner', 'old-session', first.value)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    expect(await two.begin('workspace', 'owner', 'new-session', 'new-call', second.value)).toMatchObject({ ok: true });
    await two.end('workspace', 'new-call', second.value.generation);
  });

  it('blocks an active writer and waits another grace interval after it finishes', async () => {
    let time = 100_000;
    const { one, two } = await fixture(() => time);
    const owned = await one.acquire('workspace', 'owner', 'old-session', 600);
    if (!owned.ok) throw new Error('lease not acquired');
    expect(await one.begin('workspace', 'owner', 'old-session', 'active-call', owned.value)).toMatchObject({ ok: true });
    time += 61_000;
    expect(await two.acquire('workspace', 'owner', 'new-session', 600, true)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    await one.end('workspace', 'active-call', owned.value.generation);
    expect(await two.acquire('workspace', 'owner', 'new-session', 600, true)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    time += 61_000;
    expect(await two.acquire('workspace', 'owner', 'new-session', 600, true)).toMatchObject({ ok: true, value: { generation: 2 } });
  });

  it('only grants one recovery when two same-client sessions race', async () => {
    let time = 100_000;
    const { one, two } = await fixture(() => time);
    const original = await one.acquire('workspace', 'owner', 'initial-session', 600);
    if (!original.ok) throw new Error('lease not acquired');
    time += 61_000;
    const result = await Promise.all([
      one.acquire('workspace', 'owner', 'next-a', 600, true),
      two.acquire('workspace', 'owner', 'next-b', 600, true),
    ]);
    expect(result.filter((entry) => entry.ok)).toHaveLength(1);
    expect(result.filter((entry) => !entry.ok)).toHaveLength(1);
    expect(result.find((entry) => entry.ok)).toMatchObject({ ok: true, value: { generation: 2 } });
    expect(result.find((entry) => !entry.ok)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
  });

  it('allows same-client same-session recovery after grace when reconnecting or proof is lost', async () => {
    let time = 100_000;
    const { one } = await fixture(() => time);
    const original = await one.acquire('workspace', 'desktop-mcp-http', 'tunnel-session-1', 600);
    expect(original.ok).toBe(true);
    if (!original.ok) return;

    // Within 60 seconds: recovery blocked even with recoverAbandoned
    time += 30_000;
    expect(await one.acquire('workspace', 'desktop-mcp-http', 'tunnel-session-1', 600, true))
      .toMatchObject({ ok: false, error: { code: 'CONFLICT' } });

    // After 60 seconds: same session can safely recover its own abandoned lease
    time += 31_000;
    const recovered = await one.acquire('workspace', 'desktop-mcp-http', 'tunnel-session-1', 600, true);
    expect(recovered.ok).toBe(true);
    if (!recovered.ok) return;
    expect(recovered.value.generation).toBe(original.value.generation + 1);

    // Old proof is rejected
    expect(await one.begin('workspace', 'desktop-mcp-http', 'tunnel-session-1', 'call-stale', original.value))
      .toMatchObject({ ok: false, error: { code: 'CONFLICT' } });

    // New proof is admitted
    expect(await one.begin('workspace', 'desktop-mcp-http', 'tunnel-session-1', 'call-new', recovered.value))
      .toMatchObject({ ok: true, value: { required: true, generation: 2 } });
    await one.end('workspace', 'call-new', 2);
  });

  it('heartbeat extends activity and resets the 60-second stale-recovery grace window', async () => {
    let time = 100_000;
    const { one, two } = await fixture(() => time);
    const acquired = await one.acquire('workspace', 'owner', 'session-1', 600);
    expect(acquired.ok).toBe(true);
    if (!acquired.ok) return;

    const admitted = await one.begin('workspace', 'owner', 'session-1', 'call-long', acquired.value);
    expect(admitted.ok).toBe(true);

    // Advance 50 seconds and heartbeat
    time += 50_000;
    await one.heartbeat('workspace', 'call-long', acquired.value.generation);

    // Another 30 seconds (80 seconds total from acquire, but only 30 from heartbeat)
    time += 30_000;
    expect(await two.assessAbandonment('workspace', 'owner')).toMatchObject({
      ok: true,
      value: { live: true, reason: 'live_invocation' },
    });

    // In-flight call still active: recovery blocked
    expect(await two.acquire('workspace', 'owner', 'session-2', 600, true))
      .toMatchObject({ ok: false, error: { code: 'CONFLICT' } });

    await one.end('workspace', 'call-long', acquired.value.generation);

    // Right after call ends, only 0 seconds idle: still within grace
    expect(await two.assessAbandonment('workspace', 'owner')).toMatchObject({
      ok: true,
      value: { live: true, reason: 'within_stale_grace' },
    });
    expect(await two.acquire('workspace', 'owner', 'session-2', 600, true))
      .toMatchObject({ ok: false, error: { code: 'CONFLICT' } });

    // Advance full 60 seconds after call ended: now idle beyond grace
    time += 60_000;
    expect(await two.assessAbandonment('workspace', 'owner')).toMatchObject({
      ok: true,
      value: { live: false, reason: 'idle_beyond_grace' },
    });
    expect(await two.acquire('workspace', 'owner', 'session-2', 600, true))
      .toMatchObject({ ok: true, value: { generation: acquired.value.generation + 1 } });
  });

  it('atomically revokes abandoned lease and rejects previous generation mutations', async () => {
    let time = 100_000;
    const { one, two } = await fixture(() => time);
    const first = await one.acquire('workspace', 'owner', 'session-1', 600);
    expect(first.ok).toBe(true);
    if (!first.ok) return;

    // Cannot revoke while owner is active
    expect(await two.revokeAbandoned('workspace', 'owner')).toMatchObject({
      ok: false,
      error: { code: 'CONFLICT' },
    });

    time += 61_000;
    // Beyond grace: atomic revoke succeeds and increments generation
    const revoked = await two.revokeAbandoned('workspace', 'owner');
    expect(revoked).toMatchObject({
      ok: true,
      value: { revoked: true, previousGeneration: 1, generation: 2 },
    });

    // Subsequent revoke on already unleased returns revoked: false without extra increment
    expect(await two.revokeAbandoned('workspace', 'owner')).toMatchObject({
      ok: true,
      value: { revoked: false, previousGeneration: 2, generation: 2 },
    });

    // Old proof is rejected
    expect(await one.begin('workspace', 'owner', 'session-1', 'call-stale', first.value))
      .toMatchObject({ ok: false, error: { code: 'CONFLICT' } });

    // Inspect shows unleased
    expect(await two.inspect('workspace')).toMatchObject({
      ok: true,
      value: { state: 'unleased', generation: 2 },
    });
  });
});
