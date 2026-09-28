import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

import { loadProductionRuntimeCatalog } from '../src/runtime/production-runtime-catalog.mjs';

const PRODUCTION_CATALOG_URL = new URL('../config/runtime-catalog.json', import.meta.url);
const CATALOG_EVIDENCE_URL = new URL('../docs/runtime-catalog-evidence.md', import.meta.url);
const LOADER_SOURCE_URL = new URL('../src/runtime/production-runtime-catalog.mjs', import.meta.url);
const VALIDATOR_SOURCE_URL = new URL('../src/runtime/runtime-catalog.mjs', import.meta.url);
const execFile = promisify(execFileCallback);

const EXPECTED_CATALOG = {
  schemaVersion: 1,
  catalogRevision: 1,
  platform: {
    os: 'windows',
    architecture: 'x64',
    minimumBuild: 17_763,
  },
  artifacts: [{
    id: 'powershell-7',
    version: '7.6.4',
    url: 'https://github.com/PowerShell/PowerShell/releases/download/v7.6.4/PowerShell-7.6.4-win-x64.zip',
    redirectOrigins: ['https://release-assets.githubusercontent.com'],
    bytes: 116_979_293,
    maximumExpandedBytes: 296_034_085,
    sha256: '80832551C52809301E6071C8BAC977BEB5A2F1EC953EB4DB9F94DEB953333793',
    packaging: 'zip',
    signerRule: 'microsoft-corporation',
    verificationCommandId: 'powershell-json-roundtrip',
  }],
  profiles: [
    { id: 'core', artifacts: ['powershell-7'], dependencies: [] },
    { id: 'base', artifacts: ['powershell-7'], dependencies: ['core'] },
  ],
};

let isolatedImportId = 0;

async function isolatedLoader(t) {
  const root = await mkdtemp(join(tmpdir(), 'agent-road-production-catalog-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const runtimeDirectory = join(root, 'src', 'runtime');
  const configDirectory = join(root, 'config');
  await mkdir(runtimeDirectory, { recursive: true });
  await mkdir(configDirectory, { recursive: true });
  const loaderPath = join(runtimeDirectory, 'production-runtime-catalog.mjs');
  const validatorPath = join(runtimeDirectory, 'runtime-catalog.mjs');
  const catalogPath = join(configDirectory, 'runtime-catalog.json');
  await Promise.all([
    writeFile(loaderPath, await readFile(LOADER_SOURCE_URL)),
    writeFile(validatorPath, await readFile(VALIDATOR_SOURCE_URL)),
  ]);
  const moduleUrl = `${pathToFileURL(loaderPath).href}?isolated=${isolatedImportId += 1}`;
  const loader = await import(moduleUrl);
  return {
    catalogPath,
    load: loader.loadProductionRuntimeCatalog,
    moduleUrl,
    root,
  };
}

async function rejectsInternal(promise, forbidden = []) {
  await assert.rejects(promise, (error) => {
    assert.equal(error.code, 'RUNTIME_INTERNAL_ERROR');
    assert.equal(error.message, 'RUNTIME_INTERNAL_ERROR');
    assert.deepEqual(Object.keys(error), ['code']);
    assert.equal(Object.hasOwn(error, 'cause'), false);
    for (const value of forbidden) assert.equal(error.message.includes(value), false);
    return true;
  });
}

test('loads the exact canonical checked-in catalog as detached deeply frozen data', async () => {
  assert.equal(loadProductionRuntimeCatalog.length, 0);
  const raw = await readFile(PRODUCTION_CATALOG_URL);
  assert.deepEqual(raw, Buffer.from(`${JSON.stringify(EXPECTED_CATALOG)}\n`, 'utf8'));

  const first = await loadProductionRuntimeCatalog();
  const second = await loadProductionRuntimeCatalog();

  assert.deepEqual(first, EXPECTED_CATALOG);
  assert.notEqual(first, second);
  assert.notEqual(first.artifacts[0], second.artifacts[0]);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.platform), true);
  assert.equal(Object.isFrozen(first.artifacts), true);
  assert.equal(Object.isFrozen(first.artifacts[0]), true);
  assert.equal(Object.isFrozen(first.artifacts[0].redirectOrigins), true);
  assert.equal(Object.isFrozen(first.profiles), true);
  assert.equal(Object.isFrozen(first.profiles[0]), true);
  assert.equal(Object.isFrozen(first.profiles[0].artifacts), true);
  assert.equal(Object.isFrozen(first.profiles[0].dependencies), true);
  assert.throws(() => { first.artifacts[0].redirectOrigins.push('https://hostile.example'); }, TypeError);
});

test('rejects canonical catalog bytes that do not match the reviewed production digest', async (t) => {
  const fixture = await isolatedLoader(t);
  const changed = structuredClone(EXPECTED_CATALOG);
  changed.catalogRevision = 2;
  await writeFile(fixture.catalogPath, `${JSON.stringify(changed)}\n`, { mode: 0o644 });

  await rejectsInternal(fixture.load(), [fixture.catalogPath, 'catalogRevision']);
});

test('rejects a group or world writable production catalog', async (t) => {
  const fixture = await isolatedLoader(t);
  await writeFile(
    fixture.catalogPath,
    `${JSON.stringify(EXPECTED_CATALOG)}\n`,
    { mode: 0o644 },
  );
  await chmod(fixture.catalogPath, 0o666);

  await rejectsInternal(fixture.load(), [fixture.catalogPath]);
});

test('rejects a group or world writable production catalog directory', async (t) => {
  const fixture = await isolatedLoader(t);
  await writeFile(
    fixture.catalogPath,
    `${JSON.stringify(EXPECTED_CATALOG)}\n`,
    { mode: 0o644 },
  );
  await chmod(join(fixture.root, 'config'), 0o777);

  await rejectsInternal(fixture.load(), [fixture.catalogPath]);
});

test('rejects Darwin extended ACLs on the production catalog trust boundary', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  for (const target of ['catalog', 'directory']) {
    const fixture = await isolatedLoader(t);
    await writeFile(
      fixture.catalogPath,
      `${JSON.stringify(EXPECTED_CATALOG)}\n`,
      { mode: 0o644 },
    );
    const aclTarget = target === 'catalog'
      ? fixture.catalogPath
      : join(fixture.root, 'config');
    await execFile('/bin/chmod', ['+a', 'everyone allow read', aclTarget]);

    await rejectsInternal(fixture.load(), [fixture.catalogPath]);
  }
});

test('records the exact official release, hash, install, and lifecycle sources', async () => {
  const evidence = await readFile(CATALOG_EVIDENCE_URL, 'utf8');

  assert.match(evidence, /https:\/\/github\.com\/PowerShell\/PowerShell\/releases\/tag\/v7\.6\.4/u);
  assert.match(evidence, /https:\/\/github\.com\/PowerShell\/PowerShell\/releases\/download\/v7\.6\.4\/hashes\.sha256/u);
  assert.match(
    evidence,
    /https:\/\/learn\.microsoft\.com\/en-us\/powershell\/scripting\/install\/install-powershell-on-windows\?view=powershell-7\.6/u,
  );
  assert.match(
    evidence,
    /https:\/\/learn\.microsoft\.com\/en-us\/powershell\/scripting\/install\/powershell-support-lifecycle\?view=powershell-7\.6/u,
  );
  assert.doesNotMatch(evidence, /installing-powershell-on-windows/u);
});

test('maps corrupt, noncanonical, and invalid UTF-8 catalog bytes to one path-free error', async (t) => {
  for (const bytes of [
    Buffer.from('{ malformed', 'utf8'),
    Buffer.from(`${JSON.stringify(EXPECTED_CATALOG, null, 2)}\n`, 'utf8'),
    Buffer.from([0xC3, 0x28]),
  ]) {
    await t.test(`case-${bytes.length}`, async (t) => {
      const fixture = await isolatedLoader(t);
      await writeFile(fixture.catalogPath, bytes);
      await rejectsInternal(fixture.load(), [fixture.root, fixture.catalogPath]);
    });
  }
});

test('maps symlink, nonregular, and oversized fixed catalog files to one path-free error', async (t) => {
  await t.test('symlink', async (t) => {
    const fixture = await isolatedLoader(t);
    const target = join(fixture.root, 'private-target.json');
    await writeFile(target, `${JSON.stringify(EXPECTED_CATALOG)}\n`);
    await symlink(target, fixture.catalogPath);
    await rejectsInternal(fixture.load(), [target, fixture.catalogPath]);
  });

  await t.test('nonregular', async (t) => {
    const fixture = await isolatedLoader(t);
    await mkdir(fixture.catalogPath);
    await rejectsInternal(fixture.load(), [fixture.catalogPath]);
  });

  await t.test('oversized', async (t) => {
    const fixture = await isolatedLoader(t);
    await writeFile(fixture.catalogPath, Buffer.alloc(64 * 1024 + 1, 0x20));
    await rejectsInternal(fixture.load(), [fixture.catalogPath]);
  });

  await t.test('fifo', async (t) => {
    const fixture = await isolatedLoader(t);
    await execFile('/usr/bin/mkfifo', [fixture.catalogPath]);
    const childSource = String.raw`
const { loadProductionRuntimeCatalog } = await import(process.argv[1]);
try {
  await loadProductionRuntimeCatalog();
  process.stdout.write(JSON.stringify({ status: 'fulfilled' }));
} catch (error) {
  process.stdout.write(JSON.stringify({
    status: 'rejected',
    code: error?.code,
    message: error?.message,
    keys: Object.keys(error),
    hasCause: Object.hasOwn(error, 'cause'),
  }));
}
`;
    const { stdout, stderr } = await execFile(process.execPath, [
      '--input-type=module',
      '--eval',
      childSource,
      fixture.moduleUrl,
    ], {
      timeout: 500,
      maxBuffer: 4 * 1024,
    });
    assert.equal(stderr, '');
    assert.deepEqual(JSON.parse(stdout), {
      status: 'rejected',
      code: 'RUNTIME_INTERNAL_ERROR',
      message: 'RUNTIME_INTERNAL_ERROR',
      keys: ['code'],
      hasCause: false,
    });
  });
});
