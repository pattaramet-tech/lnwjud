import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import type { GitWriterResource } from '@lnwjud/shared';

const UNRESOLVED: GitWriterResource = { kind: 'unresolved' };
const MAX_GIT_PATH_BYTES = 32 * 1024;
const SCOPED_WORKTREE_OPERATIONS = new Set(['add', 'move', 'lock', 'unlock', 'remove', 'prune']);
const REPOSITORY_OVERRIDE = /^GIT_(?:(?:DIR|COMMON_DIR|WORK_TREE|NAMESPACE|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|INDEX_FILE|CEILING_DIRECTORIES|DISCOVERY_ACROSS_FILESYSTEM)$|CONFIG(?:$|_))/i;

/** Derive an additional Git fence without executing a subprocess before admission. */
export async function gitMutationResource(cwd: string, args: readonly string[]): Promise<GitWriterResource> {
  const [command, subcommand] = args;
  if (command !== 'worktree' || subcommand === undefined || !SCOPED_WORKTREE_OPERATIONS.has(subcommand)
    || Object.keys(process.env).some((name) => REPOSITORY_OVERRIDE.test(name))) return UNRESOLVED;

  try {
    const worktreeRoot = await canonicalDirectory(cwd);
    const dotGit = path.join(worktreeRoot, '.git');
    const metadata = await lstat(dotGit);
    if (!metadata.isDirectory() && !metadata.isFile()) return UNRESOLVED;
    const gitDirectory = await canonicalDirectory(metadata.isDirectory() ? dotGit : path.resolve(worktreeRoot, await readGitPath(dotGit, 'gitdir: ')));
    if (!(await stat(path.join(gitDirectory, 'HEAD'))).isFile()) return UNRESOLVED;

    const common = await readGitPath(path.join(gitDirectory, 'commondir'), '').catch((error: unknown): undefined => {
      if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return undefined;
      throw error;
    });
    const canonical = common === undefined ? gitDirectory : await canonicalDirectory(path.resolve(gitDirectory, common));
    if (!(await stat(path.join(canonical, 'objects'))).isDirectory() || !(await stat(path.join(canonical, 'refs'))).isDirectory()) return UNRESOLVED;
    const identity = process.platform === 'win32' ? canonical.toLowerCase() : canonical;
    return { kind: 'common-directory', digest: createHash('sha256').update(identity).digest('hex') };
  } catch {
    return UNRESOLVED;
  }
}

async function canonicalDirectory(filename: string): Promise<string> {
  if (process.platform === 'win32' && !/^[a-z]:\\/i.test(filename)) throw new Error('Unsupported Git directory path');
  const canonical = await realpath(filename);
  if (process.platform === 'win32' && !/^[a-z]:\\/i.test(canonical)) throw new Error('Unsupported canonical Git directory path');
  return canonical;
}

async function readGitPath(filename: string, prefix: string): Promise<string> {
  const file = await open(filename, constants.O_RDONLY | (process.platform === 'win32' ? 0 : constants.O_NONBLOCK));
  try {
    const info = await file.stat();
    if (!info.isFile() || info.size > MAX_GIT_PATH_BYTES) throw new Error('Invalid Git directory metadata');
    const bytes = Buffer.alloc(MAX_GIT_PATH_BYTES + 1);
    const { bytesRead } = await file.read(bytes, 0, bytes.length, 0);
    if (bytesRead !== info.size) throw new Error('Git directory metadata changed while reading');
    const value = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, bytesRead)).replace(/[\r\n]+$/, '');
    const target = value.slice(prefix.length);
    if (!value.startsWith(prefix) || target.length === 0 || Array.from(target).some((character) => character.charCodeAt(0) < 32)) {
      throw new Error('Invalid Git directory metadata');
    }
    return target;
  } finally {
    await file.close();
  }
}
