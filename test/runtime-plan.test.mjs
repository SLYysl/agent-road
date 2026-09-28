import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import { validateRuntimeCatalog } from '../src/runtime/runtime-catalog.mjs';
import { digestRuntimeInventory } from '../src/runtime/runtime-inventory.mjs';
import { createRuntimePlan } from '../src/runtime/runtime-plan.mjs';

const SHA_A = 'A'.repeat(64);
const SHA_B = 'B'.repeat(64);
const SHA_C = 'C'.repeat(64);
const OPERATION_ID = '0123456789abcdef0123456789abcdef';
const CREATED_AT = '2026-07-29T10:00:00.000Z';
const DEVICE_ID = 'dev_0123456789abcdef0123456789abcdef';
const TRANSACTION_RESERVE_BYTES = 256 * 1024 ** 2;

function artifact({
  id,
  version,
  bytes,
  maximumExpandedBytes,
  sha256,
  signerRule,
  verificationCommandId,
}) {
  return {
    id,
    version,
    url: `https://example.com/${id}-${version}.zip`,
    redirectOrigins: [],
    bytes,
    maximumExpandedBytes,
    sha256,
    packaging: 'zip',
    signerRule,
    verificationCommandId,
  };
}

function catalog({ mingitVersion = '2.50.1' } = {}) {
  return {
    schemaVersion: 1,
    catalogRevision: 7,
    platform: {
      os: 'windows',
      architecture: 'x64',
      minimumBuild: 17_763,
    },
    artifacts: [
      artifact({
        id: 'mingit',
        version: mingitVersion,
        bytes: 64_000_000,
        maximumExpandedBytes: 250_000_000,
        sha256: SHA_A,
        signerRule: 'git-for-windows',
        verificationCommandId: 'git-version-and-repository-read',
      }),
      artifact({
        id: 'powershell-7',
        version: '7.5.2',
        bytes: 108_000_000,
        maximumExpandedBytes: 500_000_000,
        sha256: SHA_B,
        signerRule: 'microsoft-corporation',
        verificationCommandId: 'powershell-json-roundtrip',
      }),
    ],
    profiles: [
      { id: 'core', artifacts: ['powershell-7'], dependencies: [] },
      { id: 'base', artifacts: ['mingit', 'powershell-7'], dependencies: ['core'] },
    ],
  };
}

function emptyInventory() {
  return {
    schemaVersion: 1,
    platform: {
      os: 'windows',
      version: '10.0.26200',
      build: 26_200,
      edition: 'Microsoft Windows 11 Home',
      architecture: 'x64',
      windowsPowerShellVersion: '5.1.26100.8655',
      elevated: true,
    },
    freeBytes: 50_000_000_000,
    pendingReboot: false,
    interactiveSession: false,
    runtime: {
      schemaVersion: null,
      catalogRevision: null,
      catalogDigest: null,
      generationDigest: null,
      generationVerified: false,
      pendingOperationId: null,
      restartRequired: false,
    },
    managedArtifacts: [],
  };
}

function input(overrides = {}) {
  return {
    catalog: catalog(),
    requestedProfiles: ['base'],
    inventory: emptyInventory(),
    deviceId: DEVICE_ID,
    operationId: OPERATION_ID,
    createdAt: CREATED_AT,
    ...overrides,
  };
}

function currentArtifact(desired, overrides = {}) {
  return {
    id: desired.id,
    version: desired.version,
    bytes: desired.bytes,
    sha256: desired.sha256,
    verified: true,
    ...overrides,
  };
}

function verifiedInventoryFor(plan, desiredArtifacts, overrides = {}) {
  const inventory = emptyInventory();
  inventory.runtime = {
    schemaVersion: 1,
    catalogRevision: 7,
    catalogDigest: plan.catalogDigest,
    generationDigest: SHA_C,
    generationVerified: true,
    pendingOperationId: null,
    restartRequired: false,
  };
  inventory.managedArtifacts = desiredArtifacts.map((desired) => currentArtifact(desired));
  return Object.assign(inventory, overrides);
}

function rejectsInput(callback) {
  assert.throws(callback, { code: 'RUNTIME_INPUT_INVALID' });
}

function reverseObjectFields(value) {
  if (Array.isArray(value)) return value.map(reverseObjectFields);
  if (value === null || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value).reverse().map(([key, child]) => [key, reverseObjectFields(child)]),
  );
}

test('creates a deterministic base install plan with conservative generation space', () => {
  const source = input();
  const result = createRuntimePlan(source);

  assert.deepEqual(Object.keys(result), [
    'schemaVersion',
    'operationId',
    'createdAt',
    'deviceId',
    'inventoryDigest',
    'catalogDigest',
    'requestedProfiles',
    'profiles',
    'acquisition',
    'transactionMode',
    'status',
    'blockedReasons',
    'requiredFreeBytes',
    'items',
  ]);
  assert.equal(result.schemaVersion, 1);
  assert.equal(result.operationId, OPERATION_ID);
  assert.equal(result.createdAt, CREATED_AT);
  assert.equal(result.deviceId, DEVICE_ID);
  assert.match(result.inventoryDigest, /^[0-9A-F]{64}$/);
  assert.match(result.catalogDigest, /^[0-9A-F]{64}$/);
  assert.deepEqual(result.requestedProfiles, ['base']);
  assert.deepEqual(result.profiles, ['core', 'base']);
  assert.equal(result.acquisition, 'mac-relay');
  assert.equal(result.transactionMode, 'new');
  assert.equal(result.status, 'actionable');
  assert.deepEqual(result.blockedReasons, []);
  assert.equal(
    result.requiredFreeBytes,
    TRANSACTION_RESERVE_BYTES + 64_000_000 + 250_000_000 + 108_000_000 + 500_000_000,
  );
  assert.deepEqual(result.items.map(({ artifactId, action }) => [artifactId, action]), [
    ['mingit', 'install'],
    ['powershell-7', 'install'],
  ]);
  assert.deepEqual(Object.keys(result.items[0]), [
    'artifactId',
    'action',
    'reason',
    'desired',
    'current',
    'rollbackVersion',
  ]);
  assert.deepEqual(Object.keys(result.items[0].desired), [
    'version',
    'bytes',
    'maximumExpandedBytes',
    'sha256',
  ]);
  assert.equal(result.items[0].current, null);
  assert.deepEqual(result.items[0].desired, {
    version: '2.50.1',
    bytes: 64_000_000,
    maximumExpandedBytes: 250_000_000,
    sha256: SHA_A,
  });
  assert.equal(JSON.stringify(createRuntimePlan(input())), JSON.stringify(result));
});

test('returns present items and zero required bytes for an exact verified generation', () => {
  const seed = createRuntimePlan(input());
  const desired = seed.items.map(({ artifactId, desired: value }) => ({ id: artifactId, ...value }));
  const inventory = verifiedInventoryFor(seed, desired);
  const result = createRuntimePlan(input({ inventory }));

  assert.deepEqual(result.items.map(({ action }) => action), ['present', 'present']);
  assert.equal(result.requiredFreeBytes, 0);
  assert.equal(result.status, 'actionable');
  assert.deepEqual(result.blockedReasons, []);
});

test('repairs exact versions with invalid bytes, hash or verification state', () => {
  const seed = createRuntimePlan(input());
  const desired = seed.items.map(({ artifactId, desired: value }) => ({ id: artifactId, ...value }));

  for (const mutate of [
    (inventory) => { inventory.managedArtifacts[0].bytes += 1; },
    (inventory) => { inventory.managedArtifacts[0].sha256 = SHA_C; },
    (inventory) => {
      inventory.runtime.generationVerified = false;
      inventory.managedArtifacts[0].verified = false;
    },
  ]) {
    const inventory = verifiedInventoryFor(seed, desired);
    mutate(inventory);
    const result = createRuntimePlan(input({ inventory }));
    assert.equal(result.items[0].action, 'repair');
    assert.equal(result.items[0].rollbackVersion, null);
  }
});

test('blocks a verified same-revision catalog digest conflict', () => {
  const seed = createRuntimePlan(input());
  const desired = seed.items.map(({ artifactId, desired: value }) => ({ id: artifactId, ...value }));
  const inventory = verifiedInventoryFor(seed, desired);
  inventory.runtime.catalogDigest = SHA_C;

  const result = createRuntimePlan(input({ inventory }));
  assert.equal(result.status, 'blocked');
  assert.equal(result.blockedReasons.includes('catalog-revision-equivocation'), true);
});

test('repairs every exact artifact when generation verification or revision is stale', () => {
  const seed = createRuntimePlan(input());
  const desired = seed.items.map(({ artifactId, desired: value }) => ({ id: artifactId, ...value }));

  for (const mutate of [
    (inventory) => { inventory.runtime.generationVerified = false; },
    (inventory) => { inventory.runtime.catalogRevision -= 1; },
  ]) {
    const inventory = verifiedInventoryFor(seed, desired);
    mutate(inventory);
    const result = createRuntimePlan(input({ inventory }));
    assert.deepEqual(result.items.map(({ action }) => action), ['repair', 'repair']);
  }
});

test('uses numeric semantic version ordering for upgrade and blocks downgrade', () => {
  const upgradeCatalog = catalog({ mingitVersion: '2.10.0' });
  const seed = createRuntimePlan(input({ catalog: upgradeCatalog }));
  const desired = seed.items.map(({ artifactId, desired: value }) => ({ id: artifactId, ...value }));
  const upgradeInventory = verifiedInventoryFor(seed, desired);
  upgradeInventory.managedArtifacts[0].version = '2.9.0';
  const upgrade = createRuntimePlan(input({ catalog: upgradeCatalog, inventory: upgradeInventory }));
  assert.equal(upgrade.items[0].action, 'upgrade');
  assert.equal(upgrade.items[0].rollbackVersion, '2.9.0');

  const downgradeCatalog = catalog({ mingitVersion: '2.9.0' });
  const downgradeSeed = createRuntimePlan(input({ catalog: downgradeCatalog }));
  const downgradeDesired = downgradeSeed.items.map(
    ({ artifactId, desired: value }) => ({ id: artifactId, ...value }),
  );
  const downgradeInventory = verifiedInventoryFor(downgradeSeed, downgradeDesired);
  downgradeInventory.managedArtifacts[0].version = '2.10.0';
  const downgrade = createRuntimePlan(input({
    catalog: downgradeCatalog,
    inventory: downgradeInventory,
  }));
  assert.equal(downgrade.items[0].action, 'blocked');
  assert.equal(downgrade.items[0].reason, 'managed-version-newer');
  assert.deepEqual(downgrade.blockedReasons, ['managed-version-newer']);
  assert.equal(downgrade.status, 'blocked');
});

test('compares semantic version components beyond Number safe precision', () => {
  const hugeCatalog = catalog({ mingitVersion: '9007199254740993.0.0' });
  const seed = createRuntimePlan(input({ catalog: hugeCatalog }));
  const desired = seed.items.map(({ artifactId, desired: value }) => ({ id: artifactId, ...value }));
  const inventory = verifiedInventoryFor(seed, desired);
  inventory.managedArtifacts[0].version = '9007199254740992.0.0';

  const result = createRuntimePlan(input({ catalog: hugeCatalog, inventory }));
  assert.equal(result.items[0].action, 'upgrade');
});

test('retains only a verified older version as a rollback candidate', () => {
  const upgradeCatalog = catalog({ mingitVersion: '2.10.0' });
  const seed = createRuntimePlan(input({ catalog: upgradeCatalog }));
  const desired = seed.items.map(({ artifactId, desired: value }) => ({ id: artifactId, ...value }));
  const inventory = verifiedInventoryFor(seed, desired);
  inventory.managedArtifacts[0].version = '2.9.0';
  inventory.managedArtifacts[0].verified = false;
  inventory.runtime.generationVerified = false;

  const result = createRuntimePlan(input({ catalog: upgradeCatalog, inventory }));
  assert.equal(result.items[0].action, 'upgrade');
  assert.equal(result.items[0].rollbackVersion, null);

  const unknownSchema = verifiedInventoryFor(seed, desired);
  unknownSchema.managedArtifacts[0].version = '2.9.0';
  unknownSchema.runtime.schemaVersion = 2;
  const unknownResult = createRuntimePlan(input({
    catalog: upgradeCatalog,
    inventory: unknownSchema,
  }));
  assert.equal(unknownResult.items[0].action, 'upgrade');
  assert.equal(unknownResult.items[0].rollbackVersion, null);
});

test('emits finite global blockers in canonical order', () => {
  const inventory = emptyInventory();
  inventory.platform.architecture = 'arm64';
  inventory.platform.build = 17_762;
  inventory.platform.windowsPowerShellVersion = '4.0.0.0';
  inventory.platform.elevated = false;
  inventory.freeBytes = 0;
  inventory.pendingReboot = true;
  inventory.runtime = {
    schemaVersion: 2,
    catalogRevision: 7,
    catalogDigest: SHA_A,
    generationDigest: SHA_B,
    generationVerified: false,
    pendingOperationId: 'a'.repeat(32),
    restartRequired: true,
  };

  const result = createRuntimePlan(input({ inventory, requestedProfiles: [] }));
  assert.equal(result.status, 'blocked');
  assert.deepEqual(result.blockedReasons, [
    'platform-architecture-unsupported',
    'platform-build-unsupported',
    'windows-powershell-unsupported',
    'elevation-required',
    'pending-reboot',
    'runtime-schema-unsupported',
    'runtime-operation-conflict',
    'runtime-restart-required',
    'disk-insufficient',
  ]);
});

test('blocks a conflicting transaction but permits the same operation to reconcile', () => {
  const sameOperation = emptyInventory();
  sameOperation.runtime.pendingOperationId = OPERATION_ID;
  const sameResult = createRuntimePlan(input({ inventory: sameOperation }));
  assert.equal(sameResult.transactionMode, 'reconcile');
  assert.equal(sameResult.blockedReasons.includes('runtime-operation-conflict'), false);

  const conflictingOperation = emptyInventory();
  conflictingOperation.runtime.pendingOperationId = 'a'.repeat(32);
  const conflictingResult = createRuntimePlan(input({ inventory: conflictingOperation }));
  assert.equal(conflictingResult.transactionMode, 'conflict');
  assert.equal(conflictingResult.blockedReasons.includes('runtime-operation-conflict'), true);
});

test('blocks an active generation from a newer catalog revision', () => {
  const seed = createRuntimePlan(input());
  const desired = seed.items.map(({ artifactId, desired: value }) => ({ id: artifactId, ...value }));
  const inventory = verifiedInventoryFor(seed, desired);
  inventory.runtime.catalogRevision = 8;

  const result = createRuntimePlan(input({ inventory }));
  assert.equal(result.status, 'blocked');
  assert.equal(result.blockedReasons.includes('catalog-revision-newer'), true);
});

test('ignores unrelated managed artifacts and never accepts global tool substitutes', () => {
  const inventory = emptyInventory();
  inventory.managedArtifacts = [{
    id: 'unrelated-git',
    version: '9.9.9',
    bytes: 1,
    sha256: SHA_C,
    verified: false,
  }];
  const result = createRuntimePlan(input({ inventory, requestedProfiles: [] }));

  assert.deepEqual(result.items.map(({ artifactId, action }) => [artifactId, action]), [
    ['powershell-7', 'install'],
  ]);

  const hostileInventory = emptyInventory();
  hostileInventory.globalTools = { git: 'C:\\Git\\git.exe' };
  rejectsInput(() => createRuntimePlan(input({ inventory: hostileInventory })));
});

test('binds calculated full-catalog and inventory digests independent of field order', () => {
  const source = input({ requestedProfiles: [] });
  const result = createRuntimePlan(source);
  const expectedCatalogDigest = createHash('sha256')
    .update(JSON.stringify(validateRuntimeCatalog(source.catalog)), 'utf8')
    .digest('hex')
    .toUpperCase();
  assert.equal(result.catalogDigest, expectedCatalogDigest);
  assert.equal(result.inventoryDigest, digestRuntimeInventory(source.inventory));

  const changedCatalog = catalog({ mingitVersion: '2.50.2' });
  const changed = createRuntimePlan(input({ catalog: changedCatalog, requestedProfiles: [] }));
  assert.notEqual(changed.catalogDigest, result.catalogDigest);
  assert.deepEqual(changed.items, result.items);

  const reordered = createRuntimePlan(input({
    catalog: reverseObjectFields(source.catalog),
    inventory: reverseObjectFields(source.inventory),
    requestedProfiles: [],
  }));
  assert.equal(reordered.catalogDigest, result.catalogDigest);
  assert.equal(reordered.inventoryDigest, result.inventoryDigest);
});

test('binds redirect origin policy into the full catalog digest', () => {
  const baseline = createRuntimePlan(input({ requestedProfiles: [] }));
  const changedCatalog = catalog();
  changedCatalog.artifacts.find(({ id }) => id === 'powershell-7').redirectOrigins = [
    'https://release-assets.githubusercontent.com',
  ];
  const changed = createRuntimePlan(input({
    catalog: changedCatalog,
    requestedProfiles: [],
  }));

  assert.notEqual(changed.catalogDigest, baseline.catalogDigest);
  assert.deepEqual(changed.items, baseline.items);
});

test('uses all resolved artifacts for mutation space and exact disk boundary', () => {
  const seed = createRuntimePlan(input());
  const desired = seed.items.map(({ artifactId, desired: value }) => ({ id: artifactId, ...value }));
  const partial = verifiedInventoryFor(seed, desired.slice(0, 1));
  const partialResult = createRuntimePlan(input({ inventory: partial }));
  assert.deepEqual(partialResult.items.map(({ action }) => action), ['present', 'install']);
  assert.equal(partialResult.requiredFreeBytes, seed.requiredFreeBytes);

  const exact = emptyInventory();
  exact.freeBytes = seed.requiredFreeBytes;
  assert.equal(
    createRuntimePlan(input({ inventory: exact })).blockedReasons.includes('disk-insufficient'),
    false,
  );
  exact.freeBytes -= 1;
  assert.equal(
    createRuntimePlan(input({ inventory: exact })).blockedReasons.includes('disk-insufficient'),
    true,
  );

  const present = verifiedInventoryFor(seed, desired, { freeBytes: 0 });
  const presentResult = createRuntimePlan(input({ inventory: present }));
  assert.equal(presentResult.requiredFreeBytes, 0);
  assert.equal(presentResult.blockedReasons.includes('disk-insufficient'), false);
});

test('normalizes requested profile order and binds explicit operation inputs', () => {
  const first = createRuntimePlan(input({ requestedProfiles: ['base', 'core'] }));
  const second = createRuntimePlan(input({ requestedProfiles: ['core', 'base'] }));
  assert.deepEqual(first, second);
  assert.deepEqual(first.requestedProfiles, ['core', 'base']);

  for (const [field, values] of [
    ['deviceId', ['device', 'dev_', `dev_${'a'.repeat(61)}`, 1]],
    ['operationId', ['A'.repeat(32), 'a'.repeat(31), 'g'.repeat(32), 1]],
    ['createdAt', [
      '2026-07-29T10:00:00Z',
      '2026-07-29 10:00:00.000Z',
      '2026-02-30T10:00:00.000Z',
      '2026-07-29T18:00:00.000+08:00',
      'invalid',
      1,
    ]],
  ]) {
    for (const value of values) rejectsInput(() => createRuntimePlan(input({ [field]: value })));
  }

  rejectsInput(() => createRuntimePlan({ ...input(), inventoryDigest: SHA_A }));

  for (const requestedProfiles of [
    null,
    ['unknown'],
    ['core', 'core'],
    ['core', 'base', 'core'],
    Array(1),
  ]) {
    rejectsInput(() => createRuntimePlan(input({ requestedProfiles })));
  }
  const extraArrayProperty = ['core'];
  extraArrayProperty.extra = true;
  rejectsInput(() => createRuntimePlan(input({ requestedProfiles: extraArrayProperty })));
});

test('rejects malformed plan roots without invoking proxy traps', () => {
  const missing = input();
  delete missing.catalog;
  rejectsInput(() => createRuntimePlan(missing));
  rejectsInput(() => createRuntimePlan({ ...input(), extra: true }));

  const symbol = input();
  symbol[Symbol('extra')] = true;
  rejectsInput(() => createRuntimePlan(symbol));

  const customPrototype = Object.create({ inherited: true });
  Object.assign(customPrototype, input());
  rejectsInput(() => createRuntimePlan(customPrototype));

  let trapCalls = 0;
  const { proxy, revoke } = Proxy.revocable(input(), {
    ownKeys() {
      trapCalls += 1;
      return [];
    },
  });
  revoke();
  rejectsInput(() => createRuntimePlan(proxy));
  assert.equal(trapCalls, 0);
});

test('rejects hostile plan and requested-profile inputs without invoking code', () => {
  let getterReads = 0;
  const getterInput = input();
  Object.defineProperty(getterInput, 'deviceId', {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error('must not run');
    },
  });
  rejectsInput(() => createRuntimePlan(getterInput));
  assert.equal(getterReads, 0);

  let proxyTraps = 0;
  const proxy = new Proxy(input(), {
    ownKeys() {
      proxyTraps += 1;
      throw new Error('must not run');
    },
  });
  rejectsInput(() => createRuntimePlan(proxy));
  assert.equal(proxyTraps, 0);

  const requested = ['base'];
  Object.defineProperty(requested, 0, {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error('must not run');
    },
  });
  rejectsInput(() => createRuntimePlan(input({ requestedProfiles: requested })));
  assert.equal(getterReads, 0);
});

test('returns a deeply frozen plan detached from caller inputs', () => {
  const source = input();
  const result = createRuntimePlan(source);

  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.blockedReasons), true);
  assert.equal(Object.isFrozen(result.items), true);
  assert.equal(Object.isFrozen(result.items[0]), true);
  assert.equal(Object.isFrozen(result.items[0].desired), true);
  assert.throws(() => { result.items[0].action = 'present'; }, TypeError);
  assert.throws(() => { result.requestedProfiles.push('core'); }, TypeError);

  source.catalog.artifacts[0].version = '9.9.9';
  source.inventory.freeBytes = 0;
  source.requestedProfiles[0] = 'core';
  assert.equal(result.items[0].desired.version, '2.50.1');
  assert.deepEqual(result.requestedProfiles, ['base']);
});
