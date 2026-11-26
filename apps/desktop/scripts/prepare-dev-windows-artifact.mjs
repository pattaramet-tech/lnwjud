import { cp, copyFile, lstat, mkdir, readFile, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { readBoundedFile } from '../../../scripts/update-trust/verify-build-evidence.mjs';
import { verifyPreparedInstalledLayout } from '../../../scripts/update-trust/prepare-installed-layout.mjs';
import { verifyWindowsUpdatePayloadAsset } from './windows-update-layout.mjs';
import { validateContainmentEvidence } from './verify-containment-artifacts.mjs';

const maxFile = 4n * 1024n * 1024n * 1024n;
const fail = message => { throw new Error('DEV_ARTIFACT_INCOMPLETE: ' + message); };

function safeRelative(name) {
  if (typeof name !== 'string' || name.length > 240 || !name.split('/').every(part =>
    /^[A-Za-z0-9_][A-Za-z0-9._ -]*$/.test(part) && !/[. ]$/.test(part)
    && !/^(?:CON|NUL|AUX|PRN|COM[0-9]|LPT[0-9])(?:\.|$)/i.test(part))) fail('unsafe path');
  return name;
}

async function directory(filename) {
  const stat = await lstat(filename);
  if (!stat.isDirectory() || stat.isSymbolicLink() || await realpath(filename) !== filename) fail('noncanonical directory');
}

async function readMetadata(filename) {
  return (await readBoundedFile(filename, 16n * 1024n * 1024n)).bytes;
}

async function contract(root, expectedCommit) {
  await directory(root);
  const provenance = JSON.parse(await readMetadata(path.join(root, 'PROVENANCE.json')));
  const { version, source, installedLayout, updatePayload } = provenance;
  if (provenance.schemaVersion !== 1 || provenance.product !== 'lnwjud' || provenance.platform !== 'win32'
    || provenance.arch !== 'x64' || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(version)
    || !/^[0-9a-f]{40}$/.test(expectedCommit) || source?.commit !== expectedCommit || source?.dirty !== false)
    fail('source provenance');
  const top = [`lnwjud-Setup-${version}.exe`, `lnwjud-Setup-${version}.exe.blockmap`,
    `lnwjud-Portable-${version}.exe`, 'latest.yml', 'portable.yml'];
  if (installedLayout?.name !== 'INSTALL-LAYOUT.json' || updatePayload?.name !== `lnwjud-Update-${version}-win32-x64.zip`)
    fail('layout or update payload provenance');
  if (!Array.isArray(provenance.artifacts) || provenance.artifacts.length !== top.length
    || !Array.isArray(provenance.runtime) || provenance.runtime.length === 0) fail('provenance inventory');
  const expected = new Map();
  const folded = new Set();
  function add(name, identity) {
    safeRelative(name);
    const key = name.toUpperCase();
    const size = String(identity?.sizeBytes);
    if (folded.has(key) || !/^[0-9a-f]{64}$/.test(identity?.sha256) || !/^(0|[1-9][0-9]*)$/.test(size)
      || BigInt(size) > maxFile) fail('duplicate or invalid identity: ' + name);
    folded.add(key);
    expected.set(name, { sha256: identity.sha256, sizeBytes: size });
  }
  for (const item of provenance.artifacts) {
    if (!top.includes(item.name)) fail('unexpected artifact');
    add(item.name, item);
  }
  add('PROVENANCE.json', await readBoundedFile(path.join(root, 'PROVENANCE.json'), 16n * 1024n * 1024n));
  add(installedLayout.name, installedLayout);
  add(updatePayload.name, updatePayload);
  for (const item of provenance.runtime) add('installed/' + safeRelative(item.relativePath), item);
  validateContainmentEvidence(provenance.containment, provenance.runtime, 'win32');
  const sums = new Map();
  const seen = new Set();
  for (const line of (await readMetadata(path.join(root, 'SHA256SUMS.txt'))).toString('utf8').split(/\r?\n/)) {
    if (!line) continue;
    const match = /^([0-9a-f]{64}) {2}(.+)$/.exec(line);
    if (!match) fail('invalid checksum line');
    const name = safeRelative(match[2]);
    if (seen.has(name.toUpperCase())) fail('duplicate checksum');
    seen.add(name.toUpperCase());
    sums.set(name, match[1]);
  }
  if (sums.size !== expected.size) fail('checksum inventory size');
  for (const [name, identity] of expected) {
    if (sums.get(name) !== identity.sha256) fail('checksum inventory mismatch: ' + name);
  }
  return { provenance, expected, top: [...top, 'PROVENANCE.json', 'SHA256SUMS.txt', installedLayout.name, updatePayload.name] };
}

async function inspectTree(root) {
  await directory(root);
  let count = 0;
  async function visit(dir) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      if (++count > 1966080) fail('tree entry limit');
      const name = path.join(dir, entry.name);
      const info = await lstat(name);
      if (info.isSymbolicLink() || await realpath(name) !== name) fail('noncanonical tree entry');
      if (info.isDirectory()) await visit(name);
      else if (!info.isFile() || info.nlink !== 1) fail('nonordinary tree entry');
    }
  }
  await visit(root);
}

export async function verifyDevWindowsArtifact(root, expectedCommit) {
  root = path.resolve(root);
  const { provenance, expected, top } = await contract(root, expectedCommit);
  const names = await readdir(root);
  if (names.length !== top.length + 1 || names.some(name => name !== 'installed' && !top.includes(name)))
    fail('unexpected or missing top-level entry');
  const installed = path.join(root, 'installed');
  await inspectTree(installed);
  for (const [name, identity] of expected) {
    const actual = await readBoundedFile(path.join(root, ...name.split('/')), maxFile);
    if (actual.sha256 !== identity.sha256 || actual.sizeBytes !== identity.sizeBytes) fail('byte mismatch: ' + name);
  }
  await verifyPreparedInstalledLayout({ rootDirectory: installed, outputDirectory: root, platform: 'win32', architecture: 'x64' });
  await verifyWindowsUpdatePayloadAsset(root, provenance.updatePayload, provenance.version);
  return { commit: expectedCommit, checksums: expected.size, helperSha256: provenance.containment.helper.sha256 };
}

export async function prepareDevWindowsArtifact(source, output, expectedCommit) {
  source = path.resolve(source);
  output = path.resolve(output);
  const relative = path.relative(source, output);
  if (!relative || (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith('..' + path.sep)))
    fail('output must be outside source');
  const { top } = await contract(source, expectedCommit);
  const unpacked = path.join(source, 'win-unpacked');
  await inspectTree(unpacked);
  await mkdir(output); // never overwrite or reuse an existing staging directory
  for (const name of top) {
    await readBoundedFile(path.join(source, name), maxFile);
    await copyFile(path.join(source, name), path.join(output, name));
  }
  await cp(unpacked, path.join(output, 'installed'), { recursive: true, force: false, errorOnExist: true });
  return verifyDevWindowsArtifact(output, expectedCommit);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const [mode, ...args] = process.argv.slice(2);
  const result = mode === 'prepare' && args.length === 3 ? await prepareDevWindowsArtifact(...args)
    : mode === 'verify' && args.length === 2 ? await verifyDevWindowsArtifact(...args)
      : fail('usage: prepare <installers> <output> <commit> | verify <artifact> <commit>');
  console.log('DEV_ARTIFACT_COMPLETE ' + JSON.stringify(result));
}
