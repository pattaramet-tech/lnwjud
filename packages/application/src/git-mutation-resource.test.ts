import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { appError, err } from '@lnwjud/domain';
import type { Workspace, WorkspaceRepository } from '@lnwjud/workspace';
import { expect, it, vi } from 'vitest';
import { gitMutationResource } from './git-mutation-resource.js';
import { GitService } from './git-service.js';
import type { ManagedWriterAdmissionPort } from './writer-admission.js';

const runGit = promisify(execFile);

it('fences typed Git writes by their real common directory across linked worktrees', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'lnwjud-git-writer-resource-')));
  try {
    const main = path.join(root, 'main');
    const linked = path.join(root, 'linked worktree');
    const other = path.join(root, 'other');
    await mkdir(main);
    await mkdir(other);
    await runGit('git', ['init', '-q'], { cwd: main });
    await runGit('git', ['init', '-q'], { cwd: other });
    await runGit('git', ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--allow-empty', '-qm', 'fixture'], { cwd: main });
    await runGit('git', ['worktree', 'add', '-qb', 'fixture-linked', linked], { cwd: main });

    const workspaces: Workspace[] = [main, linked, other].map((directory, index) => ({
      id: `workspace-${index}`, displayName: path.basename(directory), rootPath: directory,
      realRootPath: directory, createdAt: new Date(0).toISOString(),
    }));
    const repository: WorkspaceRepository = {
      async list() { return workspaces; },
      async get(id) { return workspaces.find((workspace) => workspace.id === id) ?? null; },
      async insert() {},
      async delete() {},
    };
    const enter = vi.fn<ManagedWriterAdmissionPort['enter']>().mockResolvedValue(err(appError('CONFLICT', 'Fixture stops before launch')));
    const service = new GitService(repository, undefined, undefined, {
      writerAdmission: { enter }, nativeContainmentRoot: path.join(root, 'native'),
    });
    for (const workspace of workspaces) {
      await expect(service.run({ clientId: workspace.id, clientName: 'fixture' }, {
        args: ['worktree', 'add', 'not-created'], workspaceId: workspace.id, userConfirmed: true,
      })).resolves.toMatchObject({ ok: false, error: { code: 'CONFLICT', message: 'Fixture stops before launch' } });
    }
    const resources = enter.mock.calls.map(([request]) => request.gitResource);
    expect(resources).toHaveLength(3);
    expect(resources[0]).toMatchObject({ kind: 'common-directory', digest: expect.stringMatching(/^[a-f0-9]{64}$/) });
    expect(resources[1]).toEqual(resources[0]);
    expect(resources[2]).toMatchObject({ kind: 'common-directory' });
    expect(resources[2]).not.toEqual(resources[0]);

    await expect(gitMutationResource(main, ['--git-dir', path.join(other, '.git'), 'branch', 'x']))
      .resolves.toEqual({ kind: 'unresolved' });
    vi.stubEnv('GIT_COMMON_DIR', path.join(other, '.git'));
    try {
      await expect(gitMutationResource(main, ['worktree', 'add', 'not-created']))
        .resolves.toEqual({ kind: 'unresolved' });
    } finally {
      vi.unstubAllEnvs();
    }
    const malformed = path.join(root, 'malformed worktree');
    await mkdir(malformed);
    await writeFile(path.join(malformed, '.git'), 'malformed metadata\n');
    await expect(gitMutationResource(malformed, ['worktree', 'add', 'not-created'])).resolves.toEqual({ kind: 'unresolved' });
  } finally {
    await rm(root, { recursive: true, force: true, maxRetries: 3 });
  }
});
