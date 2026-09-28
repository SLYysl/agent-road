import assert from 'node:assert/strict';
import test from 'node:test';

import {
  resolveRuntimeProfiles,
  validateRuntimeCatalog,
} from '../src/runtime/runtime-catalog.mjs';

const POWERSHELL = {
  id: 'powershell-7',
  version: '7.5.2',
  url: 'https://github.com/PowerShell/PowerShell/releases/download/v7.5.2/PowerShell-7.5.2-win-x64.zip',
  redirectOrigins: ['https://release-assets.githubusercontent.com'],
  bytes: 108_000_000,
  maximumExpandedBytes: 500_000_000,
  sha256: 'A'.repeat(64),
  packaging: 'zip',
  signerRule: 'microsoft-corporation',
  verificationCommandId: 'powershell-json-roundtrip',
};

const MINGIT = {
  id: 'mingit',
  version: '2.50.1',
  url: 'https://github.com/git-for-windows/git/releases/download/v2.50.1.windows.1/MinGit-2.50.1-64-bit.zip',
  redirectOrigins: [],
  bytes: 64_000_000,
  maximumExpandedBytes: 250_000_000,
  sha256: 'B'.repeat(64),
  packaging: 'zip',
  signerRule: 'git-for-windows',
  verificationCommandId: 'git-version-and-repository-read',
};

const VALID_CATALOG = {
  schemaVersion: 1,
  catalogRevision: 1,
  platform: {
    os: 'windows',
    architecture: 'x64',
    minimumBuild: 17_763,
  },
  artifacts: [MINGIT, POWERSHELL],
  profiles: [
    {
      id: 'base',
      artifacts: ['powershell-7', 'mingit'],
      dependencies: ['core'],
    },
    {
      id: 'core',
      artifacts: ['powershell-7'],
      dependencies: [],
    },
  ],
};

function cloneCatalog() {
  return structuredClone(VALID_CATALOG);
}

function rejectsInput(callback) {
  assert.throws(callback, { code: 'RUNTIME_INPUT_INVALID' });
}

test('validates an exact catalog into a deeply frozen canonical snapshot', () => {
  const input = cloneCatalog();
  const result = validateRuntimeCatalog(input);

  assert.deepEqual(result, {
    ...VALID_CATALOG,
    artifacts: [MINGIT, POWERSHELL],
    profiles: [
      {
        id: 'core',
        artifacts: ['powershell-7'],
        dependencies: [],
      },
      {
        id: 'base',
        artifacts: ['mingit', 'powershell-7'],
        dependencies: ['core'],
      },
    ],
  });
  assert.notEqual(result, input);
  assert.notEqual(result.platform, input.platform);
  assert.notEqual(result.artifacts, input.artifacts);
  assert.notEqual(result.artifacts[0], input.artifacts[0]);
  assert.notEqual(result.profiles, input.profiles);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.platform), true);
  assert.equal(Object.isFrozen(result.artifacts), true);
  assert.equal(Object.isFrozen(result.artifacts[0]), true);
  assert.equal(Object.isFrozen(result.artifacts[0].redirectOrigins), true);
  assert.equal(Object.isFrozen(result.profiles), true);
  assert.equal(Object.isFrozen(result.profiles[0]), true);
  assert.equal(Object.isFrozen(result.profiles[0].artifacts), true);
  assert.equal(Object.isFrozen(result.profiles[0].dependencies), true);
  assert.throws(() => { result.platform.minimumBuild = 0; }, TypeError);
  assert.throws(() => { result.artifacts.push(MINGIT); }, TypeError);
  assert.throws(() => { result.artifacts[1].redirectOrigins.push('https://hostile.example'); }, TypeError);
  assert.throws(() => { result.profiles[0].artifacts[0] = 'hostile'; }, TypeError);

  input.platform.minimumBuild = 99_999;
  input.artifacts[0].version = '9.9.9';
  input.profiles[0].artifacts[0] = 'hostile';
  assert.equal(result.platform.minimumBuild, 17_763);
  assert.equal(result.artifacts[0].version, '2.50.1');
  assert.deepEqual(result.profiles[1].artifacts, ['mingit', 'powershell-7']);
});

test('canonicalizes bounded unique HTTPS redirect origins after url', () => {
  const input = cloneCatalog();
  input.artifacts[1].redirectOrigins = [
    'https://z.example',
    'https://a.example',
  ];

  const result = validateRuntimeCatalog(input);
  const powershell = result.artifacts.find(({ id }) => id === 'powershell-7');

  assert.deepEqual(Object.keys(powershell), [
    'id',
    'version',
    'url',
    'redirectOrigins',
    'bytes',
    'maximumExpandedBytes',
    'sha256',
    'packaging',
    'signerRule',
    'verificationCommandId',
  ]);
  assert.deepEqual(powershell.redirectOrigins, [
    'https://a.example',
    'https://z.example',
  ]);
  assert.equal(Object.isFrozen(powershell.redirectOrigins), true);
  assert.deepEqual(input.artifacts[1].redirectOrigins, [
    'https://z.example',
    'https://a.example',
  ]);
});

test('rejects missing and extra fields at every catalog level', () => {
  const cases = [];

  const missingRoot = cloneCatalog();
  delete missingRoot.catalogRevision;
  cases.push(missingRoot, { ...cloneCatalog(), unexpected: true });

  const missingPlatform = cloneCatalog();
  delete missingPlatform.platform.minimumBuild;
  cases.push(missingPlatform);
  const extraPlatform = cloneCatalog();
  extraPlatform.platform.channel = 'stable';
  cases.push(extraPlatform);

  const missingArtifact = cloneCatalog();
  delete missingArtifact.artifacts[0].bytes;
  const missingRedirectOrigins = cloneCatalog();
  delete missingRedirectOrigins.artifacts[0].redirectOrigins;
  const missingExpandedBound = cloneCatalog();
  delete missingExpandedBound.artifacts[0].maximumExpandedBytes;
  cases.push(missingArtifact, missingRedirectOrigins, missingExpandedBound);
  const extraArtifact = cloneCatalog();
  extraArtifact.artifacts[0].mirrors = [];
  cases.push(extraArtifact);

  const missingProfile = cloneCatalog();
  delete missingProfile.profiles[0].dependencies;
  cases.push(missingProfile);
  const extraProfile = cloneCatalog();
  extraProfile.profiles[0].description = 'base';
  cases.push(extraProfile);

  for (const value of cases) rejectsInput(() => validateRuntimeCatalog(value));
});

test('rejects Proxy, getters, symbols, custom prototypes, functions and sparse arrays without invoking hostile code', () => {
  let getterReads = 0;
  const getterCatalog = cloneCatalog();
  Object.defineProperty(getterCatalog, 'schemaVersion', {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error('must not run');
    },
  });
  rejectsInput(() => validateRuntimeCatalog(getterCatalog));
  assert.equal(getterReads, 0);

  let proxyTraps = 0;
  const proxy = new Proxy(cloneCatalog(), {
    ownKeys() {
      proxyTraps += 1;
      throw new Error('must not run');
    },
  });
  rejectsInput(() => validateRuntimeCatalog(proxy));
  assert.equal(proxyTraps, 0);

  const revoked = Proxy.revocable(cloneCatalog(), {});
  revoked.revoke();
  rejectsInput(() => validateRuntimeCatalog(revoked.proxy));

  const symbolic = cloneCatalog();
  symbolic[Symbol('hostile')] = true;
  rejectsInput(() => validateRuntimeCatalog(symbolic));

  const inherited = cloneCatalog();
  Object.setPrototypeOf(inherited, { schemaVersion: 1 });
  rejectsInput(() => validateRuntimeCatalog(inherited));

  const nullPrototype = Object.assign(Object.create(null), cloneCatalog());
  rejectsInput(() => validateRuntimeCatalog(nullPrototype));

  const callable = cloneCatalog();
  callable.artifacts[0].verificationCommandId = () => 'git-version';
  rejectsInput(() => validateRuntimeCatalog(callable));

  const sparse = cloneCatalog();
  sparse.artifacts = [sparse.artifacts[0], , sparse.artifacts[1]];
  rejectsInput(() => validateRuntimeCatalog(sparse));
});

test('rejects unsupported schema, revision and platform values', () => {
  for (const [field, invalidValues] of [
    ['schemaVersion', [0, 2, '1']],
    ['catalogRevision', [0, -1, 2_147_483_648, 1.5, '1']],
  ]) {
    for (const value of invalidValues) {
      const catalog = cloneCatalog();
      catalog[field] = value;
      rejectsInput(() => validateRuntimeCatalog(catalog));
    }
  }

  for (const platform of [
    { os: 'Windows', architecture: 'x64', minimumBuild: 17_763 },
    { os: 'linux', architecture: 'x64', minimumBuild: 17_763 },
    { os: 'windows', architecture: 'AMD64', minimumBuild: 17_763 },
    { os: 'windows', architecture: 'arm64', minimumBuild: 17_763 },
    { os: 'windows', architecture: 'x64', minimumBuild: 17_762 },
    { os: 'windows', architecture: 'x64', minimumBuild: 100_000 },
    { os: 'windows', architecture: 'x64', minimumBuild: 17_763.5 },
  ]) {
    const catalog = cloneCatalog();
    catalog.platform = platform;
    rejectsInput(() => validateRuntimeCatalog(catalog));
  }
});

test('rejects noncanonical IDs, versions, URLs, hashes and finite contract identifiers', () => {
  const mutations = [
    ['id', 'PowerShell-7'],
    ['id', 'a'.repeat(65)],
    ['version', 'latest'],
    ['version', 'v7.5.2'],
    ['version', '07.5.2'],
    ['version', '7.5'],
    ['url', 'http://github.com/PowerShell/PowerShell/releases/download/v7.5.2/PowerShell-7.5.2-win-x64.zip'],
    ['url', 'https://GITHUB.com/PowerShell/PowerShell/releases/download/v7.5.2/PowerShell-7.5.2-win-x64.zip'],
    ['url', 'https://user@example.com/PowerShell-7.5.2-win-x64.zip'],
    ['url', 'https://example.com:444/PowerShell-7.5.2-win-x64.zip'],
    ['url', 'https://example.com/releases/latest/PowerShell-win-x64.zip'],
    ['url', 'https://example.com/releases/%6C%61%74%65%73%74/PowerShell-7.5.2-win-x64.zip'],
    ['url', 'https://example.com/PowerShell-7.5.2-win-x64.zip?download=1'],
    ['url', 'https://example.com/PowerShell-7.5.2-win-x64.zip#digest'],
    ['url', 'https://example.com/PowerShell-7.5.1-win-x64.zip'],
    ['url', 'https://example.com/17.5.20/PowerShell-win-x64.zip'],
    ['url', 'https://example.com/releases/7.5.2/PowerShell'],
    ['sha256', 'a'.repeat(64)],
    ['sha256', 'G'.repeat(64)],
    ['sha256', 'A'.repeat(63)],
    ['packaging', 'msi'],
    ['signerRule', 'Microsoft Corporation'],
    ['signerRule', 'a'.repeat(65)],
    ['verificationCommandId', 'powershell --version'],
    ['verificationCommandId', 'a'.repeat(65)],
  ];

  for (const [field, value] of mutations) {
    const catalog = cloneCatalog();
    catalog.artifacts[1][field] = value;
    rejectsInput(() => validateRuntimeCatalog(catalog));
  }
});

test('rejects noncanonical, duplicate, source-origin, and unbounded redirect origins', () => {
  const invalidOrigins = [
    ['http://cdn.example'],
    ['https://CDN.example'],
    ['https://user@cdn.example'],
    ['https://cdn.example:444'],
    ['https://cdn.example/'],
    ['https://cdn.example/path'],
    ['https://cdn.example?query=1'],
    ['https://cdn.example#fragment'],
    ['https://github.com'],
    ['https://cdn.example', 'https://cdn.example'],
    Array.from({ length: 5 }, (_, index) => `https://cdn-${index}.example`),
  ];

  for (const redirectOrigins of invalidOrigins) {
    const catalog = cloneCatalog();
    catalog.artifacts[1].redirectOrigins = redirectOrigins;
    rejectsInput(() => validateRuntimeCatalog(catalog));
  }
});

test('rejects hostile redirect-origin arrays without invoking accessors or proxy traps', () => {
  let getterReads = 0;
  const getterOrigins = ['https://cdn.example'];
  Object.defineProperty(getterOrigins, 0, {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error('must not run');
    },
  });
  const getterCatalog = cloneCatalog();
  getterCatalog.artifacts[1].redirectOrigins = getterOrigins;
  rejectsInput(() => validateRuntimeCatalog(getterCatalog));
  assert.equal(getterReads, 0);

  let proxyTraps = 0;
  const proxyOrigins = new Proxy(['https://cdn.example'], {
    ownKeys() {
      proxyTraps += 1;
      throw new Error('must not run');
    },
  });
  const proxyCatalog = cloneCatalog();
  proxyCatalog.artifacts[1].redirectOrigins = proxyOrigins;
  rejectsInput(() => validateRuntimeCatalog(proxyCatalog));
  assert.equal(proxyTraps, 0);
});

test('rejects unbounded catalog counts, strings, download bytes and expanded bytes', () => {
  for (const bytes of [0, -1, 256 * 1024 ** 2 + 1, Number.MAX_SAFE_INTEGER, 1.5, '1']) {
    const catalog = cloneCatalog();
    catalog.artifacts[0].bytes = bytes;
    rejectsInput(() => validateRuntimeCatalog(catalog));
  }

  for (const maximumExpandedBytes of [
    0,
    -1,
    32 * 1024 ** 3 + 1,
    Number.MAX_SAFE_INTEGER,
    1.5,
    '1',
  ]) {
    const catalog = cloneCatalog();
    catalog.artifacts[0].maximumExpandedBytes = maximumExpandedBytes;
    rejectsInput(() => validateRuntimeCatalog(catalog));
  }

  const tooManyArtifacts = cloneCatalog();
  tooManyArtifacts.artifacts = Array.from({ length: 33 }, (_, index) => ({
    ...POWERSHELL,
    id: `tool-${index}`,
    url: `https://example.com/tool-${index}-7.5.2.zip`,
    sha256: index.toString(16).toUpperCase().padStart(64, '0'),
  }));
  rejectsInput(() => validateRuntimeCatalog(tooManyArtifacts));

  for (const field of ['version', 'url']) {
    const catalog = cloneCatalog();
    catalog.artifacts[0][field] = 'a'.repeat(field === 'url' ? 2_049 : 65);
    rejectsInput(() => validateRuntimeCatalog(catalog));
  }
});

test('rejects duplicate artifact and profile IDs', () => {
  const duplicateArtifact = cloneCatalog();
  duplicateArtifact.artifacts[1].id = duplicateArtifact.artifacts[0].id;
  rejectsInput(() => validateRuntimeCatalog(duplicateArtifact));

  const duplicateProfile = cloneCatalog();
  duplicateProfile.profiles[1].id = duplicateProfile.profiles[0].id;
  rejectsInput(() => validateRuntimeCatalog(duplicateProfile));
});

test('rejects duplicate, unknown and cyclic profile references', () => {
  const duplicateArtifactReference = cloneCatalog();
  duplicateArtifactReference.profiles[0].artifacts = ['mingit', 'mingit'];
  rejectsInput(() => validateRuntimeCatalog(duplicateArtifactReference));

  const duplicateDependency = cloneCatalog();
  duplicateDependency.profiles[0].dependencies = ['core', 'core'];
  rejectsInput(() => validateRuntimeCatalog(duplicateDependency));

  const unknownArtifact = cloneCatalog();
  unknownArtifact.profiles[0].artifacts = ['missing-tool'];
  rejectsInput(() => validateRuntimeCatalog(unknownArtifact));

  const unknownProfile = cloneCatalog();
  unknownProfile.profiles[0].dependencies = ['future-profile'];
  rejectsInput(() => validateRuntimeCatalog(unknownProfile));

  const cycle = cloneCatalog();
  cycle.profiles.find(({ id }) => id === 'core').dependencies = ['base'];
  rejectsInput(() => validateRuntimeCatalog(cycle));
});

test('requires exactly core and base with base depending on core', () => {
  const missingCore = cloneCatalog();
  missingCore.profiles = missingCore.profiles.filter(({ id }) => id !== 'core');
  rejectsInput(() => validateRuntimeCatalog(missingCore));

  const futureProfile = cloneCatalog();
  futureProfile.profiles.push({ id: 'web', artifacts: ['mingit'], dependencies: ['base'] });
  rejectsInput(() => validateRuntimeCatalog(futureProfile));

  const baseWithoutCore = cloneCatalog();
  baseWithoutCore.profiles.find(({ id }) => id === 'base').dependencies = [];
  rejectsInput(() => validateRuntimeCatalog(baseWithoutCore));
});

test('resolves core implicitly and returns canonical artifacts and profiles', () => {
  const catalog = validateRuntimeCatalog(cloneCatalog());

  assert.deepEqual(resolveRuntimeProfiles(catalog, []), {
    schemaVersion: 1,
    catalogRevision: 1,
    platform: VALID_CATALOG.platform,
    profiles: ['core'],
    artifacts: [POWERSHELL],
  });
  assert.deepEqual(resolveRuntimeProfiles(catalog, ['base']), {
    schemaVersion: 1,
    catalogRevision: 1,
    platform: VALID_CATALOG.platform,
    profiles: ['core', 'base'],
    artifacts: [MINGIT, POWERSHELL],
  });
});

test('deduplicates shared artifacts and requested profile order cannot change resolution', () => {
  const catalog = validateRuntimeCatalog(cloneCatalog());
  const first = resolveRuntimeProfiles(catalog, ['base', 'core']);
  const second = resolveRuntimeProfiles(catalog, ['core', 'base']);

  assert.deepEqual(first, second);
  assert.deepEqual(first.artifacts.map(({ id }) => id), ['mingit', 'powershell-7']);
  assert.deepEqual(first.profiles, ['core', 'base']);
});

test('returns a deeply frozen resolution detached from catalog and caller arrays', () => {
  const catalog = validateRuntimeCatalog(cloneCatalog());
  const requested = ['base'];
  const result = resolveRuntimeProfiles(catalog, requested);

  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.platform), true);
  assert.equal(Object.isFrozen(result.profiles), true);
  assert.equal(Object.isFrozen(result.artifacts), true);
  assert.equal(Object.isFrozen(result.artifacts[0]), true);
  assert.notEqual(result.platform, catalog.platform);
  assert.notEqual(result.artifacts[0], catalog.artifacts[0]);
  assert.throws(() => { result.profiles.push('web'); }, TypeError);
  assert.throws(() => { result.artifacts[0].version = '9.9.9'; }, TypeError);

  requested[0] = 'core';
  assert.deepEqual(result.profiles, ['core', 'base']);
});

test('rejects unknown, duplicate and hostile requested profile lists', () => {
  const catalog = validateRuntimeCatalog(cloneCatalog());

  for (const requested of [
    ['web'],
    ['base', 'base'],
    ['BASE'],
    [1],
    'base',
    null,
  ]) {
    rejectsInput(() => resolveRuntimeProfiles(catalog, requested));
  }

  let getterReads = 0;
  const getterArray = ['base'];
  Object.defineProperty(getterArray, 0, {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error('must not run');
    },
  });
  rejectsInput(() => resolveRuntimeProfiles(catalog, getterArray));
  assert.equal(getterReads, 0);

  let proxyTraps = 0;
  const proxy = new Proxy(['base'], {
    ownKeys() {
      proxyTraps += 1;
      throw new Error('must not run');
    },
  });
  rejectsInput(() => resolveRuntimeProfiles(catalog, proxy));
  assert.equal(proxyTraps, 0);
});

test('resolver revalidates catalog inputs instead of trusting mutable or forged snapshots', () => {
  const mutable = cloneCatalog();
  mutable.profiles.push({ id: 'web', artifacts: ['mingit'], dependencies: ['base'] });
  rejectsInput(() => resolveRuntimeProfiles(mutable, ['base']));

  const hostile = cloneCatalog();
  Object.defineProperty(hostile.artifacts[0], 'bytes', {
    enumerable: true,
    get() {
      throw new Error('must not run');
    },
  });
  rejectsInput(() => resolveRuntimeProfiles(hostile, ['base']));
});
