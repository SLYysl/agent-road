import assert from 'node:assert/strict';
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { loadReleaseManifest } from '../src/releases/release-manifest.mjs';

const EXPECTED_MANIFEST = {
  schemaVersion: 1,
  tailscaleWindows: {
    version: '1.98.9',
    url: 'https://pkgs.tailscale.com/stable/tailscale-setup-full-1.98.9.exe',
    sha256: 'b3f7e15eb33b90f0686d6037453a0c680c3553b55deca649b56b6b05635c9e7b',
    authenticodeSubject: 'CN=Tailscale Inc.',
  },
};

async function withManifest(t, value, { raw = false } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-release-manifest-'));
  const path = join(directory, 'releases.json');
  t.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(path, raw ? value : `${JSON.stringify(value, null, 2)}\n`);
  return path;
}

function cloneManifest() {
  return structuredClone(EXPECTED_MANIFEST);
}

test('loads the exact pinned production release manifest as a deeply frozen copy', async () => {
  const path = new URL('../config/releases.json', import.meta.url);

  const first = await loadReleaseManifest(path);
  const second = await loadReleaseManifest(path);

  assert.deepEqual(first, EXPECTED_MANIFEST);
  assert.notEqual(first, second);
  assert.notEqual(first.tailscaleWindows, second.tailscaleWindows);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.tailscaleWindows), true);
  assert.throws(() => { first.tailscaleWindows.version = '9.9.9'; }, TypeError);
});

test('rejects additional and missing properties at every object level', async (t) => {
  const cases = [
    { ...cloneManifest(), extra: true },
    { tailscaleWindows: cloneManifest().tailscaleWindows },
    {
      ...cloneManifest(),
      tailscaleWindows: { ...cloneManifest().tailscaleWindows, extra: true },
    },
    {
      ...cloneManifest(),
      tailscaleWindows: {
        version: '1.98.9',
        url: EXPECTED_MANIFEST.tailscaleWindows.url,
        sha256: EXPECTED_MANIFEST.tailscaleWindows.sha256,
      },
    },
  ];

  for (const value of cases) {
    const path = await withManifest(t, value);
    await assert.rejects(loadReleaseManifest(path), { code: 'RELEASE_MANIFEST_INVALID' });
  }
});

test('rejects unsupported schemas and invalid object shapes', async (t) => {
  for (const value of [
    null,
    [],
    { ...cloneManifest(), schemaVersion: 2 },
    { ...cloneManifest(), tailscaleWindows: [] },
  ]) {
    const path = await withManifest(t, value);
    await assert.rejects(loadReleaseManifest(path), { code: 'RELEASE_MANIFEST_INVALID' });
  }
});

test('rejects unsafe installer URLs', async (t) => {
  const urls = [
    'http://pkgs.tailscale.com/stable/tailscale-setup-full-1.98.9.exe',
    'https://example.com/stable/tailscale-setup-full-1.98.9.exe',
    'https://PKGS.tailscale.com/stable/tailscale-setup-full-1.98.9.exe',
    'https://pkgs.tailscale.com.evil.example/stable/tailscale-setup-full-1.98.9.exe',
    'https://user:pass@pkgs.tailscale.com/stable/tailscale-setup-full-1.98.9.exe',
    'https://pkgs.tailscale.com:444/stable/tailscale-setup-full-1.98.9.exe',
    'https://pkgs.tailscale.com/stable/tailscale-setup-full.exe',
    'https://pkgs.tailscale.com/stable/tailscale-setup-full-1.98.8.exe',
    'https://pkgs.tailscale.com/stable/tailscale-setup-full-1.98.9.exe?download=1',
    'https://pkgs.tailscale.com/stable/tailscale-setup-full-1.98.9.exe#digest',
  ];

  for (const url of urls) {
    const value = cloneManifest();
    value.tailscaleWindows.url = url;
    const path = await withManifest(t, value);
    await assert.rejects(loadReleaseManifest(path), { code: 'RELEASE_MANIFEST_INVALID' });
  }
});

test('rejects invalid versions and non-lowercase SHA-256 digests', async (t) => {
  const invalidVersions = ['', 'v1.98.9', '1.98', '1.98.9-beta', 1.989];
  for (const version of invalidVersions) {
    const value = cloneManifest();
    value.tailscaleWindows.version = version;
    const path = await withManifest(t, value);
    await assert.rejects(loadReleaseManifest(path), { code: 'RELEASE_MANIFEST_INVALID' });
  }

  const invalidDigests = [
    'B3f7e15eb33b90f0686d6037453a0c680c3553b55deca649b56b6b05635c9e7b',
    'b3f7e15eb33b90f0686d6037453a0c680c3553b55deca649b56b6b05635c9e7',
    `${EXPECTED_MANIFEST.tailscaleWindows.sha256}0`,
    'g'.repeat(64),
    123,
  ];
  for (const sha256 of invalidDigests) {
    const value = cloneManifest();
    value.tailscaleWindows.sha256 = sha256;
    const path = await withManifest(t, value);
    await assert.rejects(loadReleaseManifest(path), { code: 'RELEASE_MANIFEST_INVALID' });
  }
});

test('rejects any signer other than the exact allowlisted Authenticode subject', async (t) => {
  for (const authenticodeSubject of [
    'CN=Tailscale, Inc.',
    'CN=Tailscale Inc',
    'cn=Tailscale Inc.',
    ' CN=Tailscale Inc.',
  ]) {
    const value = cloneManifest();
    value.tailscaleWindows.authenticodeSubject = authenticodeSubject;
    const path = await withManifest(t, value);
    await assert.rejects(loadReleaseManifest(path), { code: 'RELEASE_MANIFEST_INVALID' });
  }
});

test('rejects malformed JSON, non-regular files, symlinks, and oversized input', async (t) => {
  const malformedPath = await withManifest(t, '{ malformed', { raw: true });
  await assert.rejects(loadReleaseManifest(malformedPath), { code: 'RELEASE_MANIFEST_INVALID' });

  const directory = await mkdtemp(join(tmpdir(), 'agent-road-release-manifest-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await assert.rejects(loadReleaseManifest(directory), { code: 'RELEASE_MANIFEST_UNSAFE_FILE' });

  const targetPath = join(directory, 'target.json');
  const linkPath = join(directory, 'link.json');
  await writeFile(targetPath, JSON.stringify(EXPECTED_MANIFEST));
  await symlink(targetPath, linkPath);
  await assert.rejects(loadReleaseManifest(linkPath), { code: 'RELEASE_MANIFEST_UNSAFE_FILE' });

  const oversizedPath = join(directory, 'oversized.json');
  await writeFile(oversizedPath, ' '.repeat(64 * 1024 + 1));
  await assert.rejects(loadReleaseManifest(oversizedPath), { code: 'RELEASE_MANIFEST_INVALID' });
});

test('rejects invalid paths without touching the filesystem', async () => {
  for (const path of ['', 'bad\0path', null]) {
    await assert.rejects(loadReleaseManifest(path), { code: 'RELEASE_MANIFEST_PATH_INVALID' });
  }
});
