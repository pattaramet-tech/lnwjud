import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
// @ts-expect-error Standalone Node packaging script.
import { prepareDevWindowsArtifact, verifyDevWindowsArtifact } from '../../apps/desktop/scripts/prepare-dev-windows-artifact.mjs';
// @ts-expect-error Standalone Node packaging script.
import { prepareInstalledLayout } from '../../scripts/update-trust/prepare-installed-layout.mjs';

const sha = 'a'.repeat(40);
const roots: string[] = [];
const hash = (data: Buffer) => createHash('sha256').update(data).digest('hex');
afterEach(async () => { for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true }); });

async function fixture() {
  const base = await realpath(await mkdtemp(path.join(os.tmpdir(), 'lnwjud-dev-artifact-')));
  roots.push(base);
  const source = path.join(base, 'source');
  const output = path.join(base, 'artifact');
  const installed = path.join(source, 'win-unpacked');
  await mkdir(path.join(installed, 'resources', 'native-containment'), { recursive: true });
  await mkdir(path.join(installed, 'slots', 'A', 'resources'), { recursive: true });
  await writeFile(path.join(installed, 'lnwjud.exe'), 'launcher');
  await writeFile(path.join(installed, 'slots/A/lnwjud.exe'), 'application');
  await writeFile(path.join(installed, 'slots/A/resources/app.asar'), 'archive');
  const runtime = [];
  const containment: Record<string, { filename: string; sha256: string; sizeBytes: number }> = {};
  for (const [kind, filename] of Object.entries({ helper: 'lnwjud-containment.exe', pin: 'lnwjud-containment-pin.node', runtime: 'process-runtime.mjs' })) {
    const relativePath = 'resources/native-containment/' + filename;
    const data = Buffer.from(kind);
    await writeFile(path.join(installed, relativePath), data);
    const identity = { filename, sha256: hash(data), sizeBytes: data.length };
    containment[kind] = identity;
    runtime.push({ name: kind, relativePath, sha256: identity.sha256, sizeBytes: identity.sizeBytes });
  }
  const installedLayout = await prepareInstalledLayout({ rootDirectory: installed, outputDirectory: source });
  const version = '5.9.5';
  const artifacts = [];
  for (const name of [`lnwjud-Setup-${version}.exe`, `lnwjud-Setup-${version}.exe.blockmap`, `lnwjud-Portable-${version}.exe`, 'latest.yml', 'portable.yml']) {
    const bytes = Buffer.from(name);
    await writeFile(path.join(source, name), bytes);
    artifacts.push({ name, sha256: hash(bytes), sizeBytes: bytes.length });
  }
  // Payload bytes are a digest fixture, not an executable or ZIP acceptance test.
  const payload = Buffer.from('update payload fixture');
  const updatePayload = { name: `lnwjud-Update-${version}-win32-x64.zip`, sha256: hash(payload), sizeBytes: String(payload.length) };
  await writeFile(path.join(source, updatePayload.name), payload);
  const prov = Buffer.from(JSON.stringify({ schemaVersion: 1, product: 'lnwjud', version, platform: 'win32', arch: 'x64',
    source: { commit: sha, dirty: false }, artifacts, runtime, containment, installedLayout, updatePayload }));
  await writeFile(path.join(source, 'PROVENANCE.json'), prov);
  const sums = [...artifacts, { name: 'PROVENANCE.json', sha256: hash(prov) }, installedLayout, updatePayload,
    ...runtime.map(entry => ({ name: 'installed/' + entry.relativePath, sha256: entry.sha256 }))].map(entry => entry.sha256 + '  ' + entry.name).join('\n') + '\n';
  await writeFile(path.join(source, 'SHA256SUMS.txt'), sums);
  return { source, output, installed, sums, updatePayload };
}

describe('complete dev Windows artifact', () => {
  it('stages and independently verifies all checksum paths and complete installed slot', async () => {
    const f = await fixture();
    const result = await prepareDevWindowsArtifact(f.source, f.output, sha);
    expect(result.commit).toBe(sha);
    expect(result.checksums).toBe(11);
    expect(await verifyDevWindowsArtifact(f.output, sha)).toEqual(result);
    expect(await readFile(path.join(f.output, 'installed/slots/A/resources/app.asar'), 'utf8')).toBe('archive');
    await expect(prepareDevWindowsArtifact(f.source, f.output, sha)).rejects.toThrow();
  });
  it('refuses omitted layout or update payload', async () => {
    const f = await fixture();
    await rm(path.join(f.source, 'INSTALL-LAYOUT.json'));
    await expect(prepareDevWindowsArtifact(f.source, f.output, sha)).rejects.toThrow();
    const g = await fixture();
    await rm(path.join(g.source, g.updatePayload.name));
    await expect(prepareDevWindowsArtifact(g.source, g.output, sha)).rejects.toThrow();
  });
  it('rejects altered runtime and unlisted slot file changes', async () => {
    const f = await fixture();
    await prepareDevWindowsArtifact(f.source, f.output, sha);
    await writeFile(path.join(f.output, 'installed/resources/native-containment/lnwjud-containment.exe'), 'altered');
    await expect(verifyDevWindowsArtifact(f.output, sha)).rejects.toThrow('byte mismatch');
    const g = await fixture();
    await prepareDevWindowsArtifact(g.source, g.output, sha);
    await writeFile(path.join(g.output, 'installed/slots/A/resources/app.asar'), 'changed');
    await expect(verifyDevWindowsArtifact(g.output, sha)).rejects.toThrow();
  });
  it('rejects wrong commit, duplicate checksum, traversal and missing checksum', async () => {
    const f = await fixture();
    await expect(prepareDevWindowsArtifact(f.source, f.output, 'b'.repeat(40))).rejects.toThrow('source provenance');
    await writeFile(path.join(f.source, 'SHA256SUMS.txt'), f.sums + f.sums.split('\n')[0] + '\n');
    await expect(prepareDevWindowsArtifact(f.source, f.output, sha)).rejects.toThrow('duplicate checksum');
    await writeFile(path.join(f.source, 'SHA256SUMS.txt'), f.sums + '0'.repeat(64) + '  ../escape\n');
    await expect(prepareDevWindowsArtifact(f.source, f.output, sha)).rejects.toThrow('unsafe path');
    await writeFile(path.join(f.source, 'SHA256SUMS.txt'), f.sums.split('\n').slice(1).join('\n'));
    await expect(prepareDevWindowsArtifact(f.source, f.output, sha)).rejects.toThrow('checksum inventory');
  });
  it('requires the verification step before the single complete artifact upload', async () => {
    const workflow = await readFile(path.resolve(import.meta.dirname, '../../.github/workflows/dev-installer.yml'), 'utf8');
    const start = workflow.indexOf('- name: Prepare and verify complete dev installer artifact');
    const upload = workflow.indexOf('- name: Upload dev installer artifacts');
    expect(start).toBeGreaterThan(-1);
    expect(upload).toBeGreaterThan(start);
    expect(workflow.slice(start, upload)).toContain('DEV_INSTALLER_ARTIFACT_INCOMPLETE');
    expect(workflow.slice(upload, workflow.indexOf('native-replacement-acceptance:', upload))).toContain('path: ${{ env.LNWJUD_DEV_ARTIFACT_DIR }}/');
  });
});
