import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import test from 'node:test';

import { createRuntimePlan } from '../src/runtime/runtime-plan.mjs';
import {
  createSignedRuntimeManifest,
  deriveRuntimeControllerKeyIdentity,
} from '../src/runtime/runtime-manifest.mjs';

const RUNTIME_DOMAIN = Buffer.from('AGENT_ROAD_RUNTIME_V1\0', 'ascii');
const GENERATION_DOMAIN = Buffer.from('AGENT_ROAD_GENERATION_V1\0', 'ascii');
const CONTROLLER_KEY_DOMAIN = Buffer.from('AGENT_ROAD_CONTROLLER_KEY_V1\0', 'ascii');
const PHASES = [
  'discover',
  'verify-manifest',
  'verify-artifacts',
  'snapshot',
  'materialize-generation',
  'self-test',
  'atomic-activate',
  'validate',
  'commit',
  'rollback',
  'reconcile',
];
const DEVICE_ID = 'dev_0123456789abcdef0123456789abcdef';
const OPERATION_ID = '0123456789abcdef0123456789abcdef';
const CREATED_AT = '2026-07-29T10:00:00.000Z';
const SHA_A = 'A'.repeat(64);
const SHA_B = 'B'.repeat(64);

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 3072,
  publicExponent: 0x10001,
});
const publicJwk = publicKey.export({ format: 'jwk' });
const PUBLIC_PAYLOAD = {
  algorithm: 'RSA-SHA256',
  modulusBase64Url: publicJwk.n,
  exponentBase64Url: 'AQAB',
};

function hashBytes(...parts) {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest('hex').toUpperCase();
}

function artifact({ id, version, bytes, maximumExpandedBytes, sha256, signerRule, verificationCommandId }) {
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

function catalog() {
  return {
    schemaVersion: 1,
    catalogRevision: 7,
    platform: { os: 'windows', architecture: 'x64', minimumBuild: 17_763 },
    artifacts: [
      artifact({
        id: 'mingit', version: '2.50.1', bytes: 64_000_000,
        maximumExpandedBytes: 250_000_000, sha256: SHA_A,
        signerRule: 'git-for-windows',
        verificationCommandId: 'git-version-and-repository-read',
      }),
      artifact({
        id: 'powershell-7', version: '7.5.2', bytes: 108_000_000,
        maximumExpandedBytes: 500_000_000, sha256: SHA_B,
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

function inventory(overrides = {}) {
  return Object.assign({
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
  }, overrides);
}

function dependencies(overrides = {}) {
  const calls = { publicKey: 0, sign: 0, signedBytes: [] };
  return {
    calls,
    value: {
      async getSigningPublicKey() {
        calls.publicKey += 1;
        return structuredClone(PUBLIC_PAYLOAD);
      },
      async sign(bytes) {
        calls.sign += 1;
        calls.signedBytes.push(Buffer.from(bytes));
        return cryptoSign('RSA-SHA256', bytes, privateKey).toString('base64');
      },
      ...overrides,
    },
  };
}

function input({
  catalog: catalogValue = catalog(),
  inventory: inventoryValue = inventory(),
  requestedProfiles = ['base'],
  deviceId = DEVICE_ID,
  operationId = OPERATION_ID,
  createdAt = CREATED_AT,
  plan: planValue,
  dependencyOverrides = {},
} = {}) {
  const signing = dependencies(dependencyOverrides);
  const plan = planValue ?? createRuntimePlan({
    catalog: catalogValue,
    requestedProfiles,
    inventory: inventoryValue,
    deviceId,
    operationId,
    createdAt,
  });
  return {
    calls: signing.calls,
    value: {
      catalog: catalogValue,
      inventory: inventoryValue,
      plan,
      dependencies: signing.value,
    },
  };
}

async function rejectsCode(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.equal(error.code, code);
    assert.equal(error.message, code);
    assert.deepEqual(Object.keys(error), ['code']);
    assert.equal('cause' in error, false);
    return true;
  });
}

test('purely derives the exact controller key identity used by signing and plan authorization', () => {
  const result = deriveRuntimeControllerKeyIdentity(structuredClone(PUBLIC_PAYLOAD));
  const publicKeyJson = JSON.stringify(PUBLIC_PAYLOAD);
  assert.deepEqual(result, {
    controllerKeyId: hashBytes(
      CONTROLLER_KEY_DOMAIN,
      Buffer.from(publicKeyJson, 'utf8'),
    ),
    controllerPublicKeyJson: publicKeyJson,
    controllerPublicKey: PUBLIC_PAYLOAD,
  });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.controllerPublicKey), true);
});

test('returns the exact string capsule and signs canonical manifest bytes with runtime domain separation', async () => {
  const source = input();
  const result = await createSignedRuntimeManifest(source.value);
  const manifest = JSON.parse(result.manifestJson);

  assert.deepEqual(Object.keys(result), [
    'schemaVersion',
    'manifestJson',
    'manifestDigest',
    'generationDigest',
    'signatureAlgorithm',
    'signatureBase64',
    'controllerKeyId',
    'controllerPublicKeyJson',
  ]);
  assert.deepEqual(Object.keys(manifest), [
    'schemaVersion',
    'deviceId',
    'operationId',
    'createdAt',
    'platform',
    'catalogRevision',
    'catalogDigest',
    'inventoryDigest',
    'requestedProfiles',
    'profiles',
    'acquisition',
    'generationDigest',
    'phases',
    'components',
  ]);
  assert.equal(result.schemaVersion, 1);
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.deviceId, DEVICE_ID);
  assert.equal(manifest.operationId, OPERATION_ID);
  assert.equal(manifest.createdAt, CREATED_AT);
  assert.deepEqual(manifest.platform, inventory().platform);
  assert.equal(manifest.catalogRevision, 7);
  assert.equal(manifest.catalogDigest, source.value.plan.catalogDigest);
  assert.equal(manifest.inventoryDigest, source.value.plan.inventoryDigest);
  assert.deepEqual(manifest.requestedProfiles, ['base']);
  assert.deepEqual(manifest.profiles, ['core', 'base']);
  assert.equal(manifest.acquisition, 'mac-relay');
  assert.deepEqual(manifest.phases, PHASES);
  assert.deepEqual(manifest.components.map(({ id }) => id), ['mingit', 'powershell-7']);
  assert.deepEqual(Object.keys(manifest.components[0]), [
    'id', 'version', 'bytes', 'maximumExpandedBytes', 'sha256',
    'packaging', 'signerRule', 'verificationCommandId',
  ]);
  assert.equal('url' in manifest.components[0], false);
  assert.equal('redirectOrigins' in manifest.components[0], false);
  assert.equal('fileName' in manifest.components[0], false);
  assert.equal(result.manifestDigest, hashBytes(Buffer.from(result.manifestJson, 'utf8')));
  assert.equal(result.signatureAlgorithm, 'RSA-SHA256');
  assert.equal(result.controllerPublicKeyJson, JSON.stringify(PUBLIC_PAYLOAD));
  assert.equal(
    result.controllerKeyId,
    hashBytes(CONTROLLER_KEY_DOMAIN, Buffer.from(result.controllerPublicKeyJson, 'utf8')),
  );
  assert.match(result.signatureBase64, /^[A-Za-z0-9+/]{512}$/);
  assert.equal(source.calls.publicKey, 1);
  assert.equal(source.calls.sign, 1);

  const signedBytes = Buffer.concat([RUNTIME_DOMAIN, Buffer.from(result.manifestJson, 'utf8')]);
  assert.equal(source.calls.signedBytes[0].equals(signedBytes), true);
  assert.equal(cryptoVerify('RSA-SHA256', signedBytes, publicKey, Buffer.from(result.signatureBase64, 'base64')), true);
  assert.equal(cryptoVerify('RSA-SHA256', Buffer.from(result.manifestJson), publicKey, Buffer.from(result.signatureBase64, 'base64')), false);
});

test('derives generation digest from its own domain-separated stable descriptor', async () => {
  const first = await createSignedRuntimeManifest(input().value);
  const second = await createSignedRuntimeManifest(input({
    deviceId: 'dev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    operationId: 'ffffffffffffffffffffffffffffffff',
    createdAt: '2026-07-30T11:12:13.000Z',
    inventory: inventory({ freeBytes: 49_000_000_000 }),
  }).value);
  const manifest = JSON.parse(first.manifestJson);
  const generationDescriptor = {
    schemaVersion: 1,
    catalogRevision: manifest.catalogRevision,
    catalogDigest: manifest.catalogDigest,
    platform: catalog().platform,
    profiles: manifest.profiles,
    components: manifest.components,
  };

  assert.equal(
    first.generationDigest,
    hashBytes(GENERATION_DOMAIN, Buffer.from(JSON.stringify(generationDescriptor), 'utf8')),
  );
  assert.equal(second.generationDigest, first.generationDigest);
  assert.notEqual(second.manifestDigest, first.manifestDigest);
});

test('canonicalizes catalog/profile ordering and derives only resolved artifacts', async () => {
  const canonical = await createSignedRuntimeManifest(input().value);
  const reorderedCatalog = catalog();
  reorderedCatalog.artifacts.reverse();
  reorderedCatalog.profiles.reverse();
  const reordered = await createSignedRuntimeManifest(input({
    catalog: reorderedCatalog,
    requestedProfiles: ['base', 'core'],
  }).value);
  assert.equal(reordered.generationDigest, canonical.generationDigest);

  const coreOnly = await createSignedRuntimeManifest(input({ requestedProfiles: [] }).value);
  const manifest = JSON.parse(coreOnly.manifestJson);
  assert.deepEqual(manifest.requestedProfiles, []);
  assert.deepEqual(manifest.profiles, ['core']);
  assert.deepEqual(manifest.components.map(({ id }) => id), ['powershell-7']);
  assert.notEqual(coreOnly.generationDigest, canonical.generationDigest);
});

test('binds redirect origin policy through catalog and generation digests without adding it to components', async () => {
  const baselineInput = input({ requestedProfiles: [] });
  const baseline = await createSignedRuntimeManifest(baselineInput.value);
  const changedCatalog = catalog();
  changedCatalog.artifacts.find(({ id }) => id === 'powershell-7').redirectOrigins = [
    'https://release-assets.githubusercontent.com',
  ];
  const changedInput = input({ catalog: changedCatalog, requestedProfiles: [] });
  const changed = await createSignedRuntimeManifest(changedInput.value);
  const baselineManifest = JSON.parse(baseline.manifestJson);
  const changedManifest = JSON.parse(changed.manifestJson);

  assert.notEqual(changedManifest.catalogDigest, baselineManifest.catalogDigest);
  assert.notEqual(changed.generationDigest, baseline.generationDigest);
  assert.notEqual(changed.manifestDigest, baseline.manifestDigest);
  assert.equal(
    changedInput.calls.signedBytes[0].equals(baselineInput.calls.signedBytes[0]),
    false,
  );
  assert.equal('redirectOrigins' in changedManifest.components[0], false);
});

test('recomputes and requires exact canonical actionable new or reconcile plan', async () => {
  const reconcileInventory = inventory();
  reconcileInventory.runtime.pendingOperationId = OPERATION_ID;
  const reconcile = input({ inventory: reconcileInventory });
  const capsule = await createSignedRuntimeManifest(reconcile.value);
  assert.equal(JSON.parse(capsule.manifestJson).operationId, OPERATION_ID);

  const canonicalPlan = createRuntimePlan({
    catalog: catalog(), requestedProfiles: ['base'], inventory: inventory(),
    deviceId: DEVICE_ID, operationId: OPERATION_ID, createdAt: CREATED_AT,
  });
  const tampered = structuredClone(canonicalPlan);
  tampered.catalogDigest = 'F'.repeat(64);
  const tamperedSource = input({ plan: tampered });
  await rejectsCode(createSignedRuntimeManifest(tamperedSource.value), 'RUNTIME_INPUT_INVALID');
  assert.equal(tamperedSource.calls.publicKey, 0);

  const reorderedPlan = Object.fromEntries(Object.entries(canonicalPlan).reverse());
  const reorderedSource = input({ plan: reorderedPlan });
  await rejectsCode(createSignedRuntimeManifest(reorderedSource.value), 'RUNTIME_INPUT_INVALID');

  for (const blockedInventory of [
    inventory({ freeBytes: 1 }),
    inventory({ pendingReboot: true }),
    (() => {
      const value = inventory();
      value.runtime.pendingOperationId = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      return value;
    })(),
  ]) {
    const blocked = input({ inventory: blockedInventory });
    assert.equal(blocked.value.plan.status, 'blocked');
    await rejectsCode(createSignedRuntimeManifest(blocked.value), 'RUNTIME_INPUT_INVALID');
    assert.equal(blocked.calls.sign, 0);
  }
});

test('rejects exact-schema violations and hostile plan/input values without invoking code', async () => {
  const missing = input();
  delete missing.value.plan;
  await rejectsCode(createSignedRuntimeManifest(missing.value), 'RUNTIME_INPUT_INVALID');
  assert.equal(missing.calls.publicKey, 0);

  const extra = input();
  extra.value.path = '/private/manifest';
  await rejectsCode(createSignedRuntimeManifest(extra.value), 'RUNTIME_INPUT_INVALID');

  let getterReads = 0;
  const getterPlan = structuredClone(input().value.plan);
  Object.defineProperty(getterPlan, 'deviceId', {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error('/private/getter');
    },
  });
  const getter = input({ plan: getterPlan });
  await rejectsCode(createSignedRuntimeManifest(getter.value), 'RUNTIME_INPUT_INVALID');
  assert.equal(getterReads, 0);
  assert.equal(getter.calls.sign, 0);

  let proxyTraps = 0;
  const proxy = new Proxy(structuredClone(input().value.plan), {
    ownKeys() {
      proxyTraps += 1;
      throw new Error('/private/proxy');
    },
  });
  const proxied = input({ plan: proxy });
  await rejectsCode(createSignedRuntimeManifest(proxied.value), 'RUNTIME_INPUT_INVALID');
  assert.equal(proxyTraps, 0);

  const revoked = Proxy.revocable(structuredClone(input().value.plan), {});
  revoked.revoke();
  await rejectsCode(createSignedRuntimeManifest(input({ plan: revoked.proxy }).value), 'RUNTIME_INPUT_INVALID');

  const protoFieldPlan = structuredClone(input().value.plan);
  Object.defineProperty(protoFieldPlan.items[0].desired, '__proto__', {
    value: { hidden: 'must-not-disappear' },
    enumerable: true,
    configurable: true,
  });
  const protoField = input({ plan: protoFieldPlan });
  await rejectsCode(createSignedRuntimeManifest(protoField.value), 'RUNTIME_INPUT_INVALID');
  assert.equal(protoField.calls.publicKey, 0);
});

test('requires exact non-proxy signer dependencies before invoking either function', async () => {
  let getterReads = 0;
  const source = input();
  Object.defineProperty(source.value.dependencies, 'sign', {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error('/private/getter');
    },
  });
  await rejectsCode(createSignedRuntimeManifest(source.value), 'RUNTIME_INPUT_INVALID');
  assert.equal(getterReads, 0);
  assert.equal(source.calls.publicKey, 0);

  let proxyCalls = 0;
  const proxyFunction = new Proxy(async () => {
    proxyCalls += 1;
    return structuredClone(PUBLIC_PAYLOAD);
  }, {});
  const proxied = input({ dependencyOverrides: { getSigningPublicKey: proxyFunction } });
  await rejectsCode(createSignedRuntimeManifest(proxied.value), 'RUNTIME_INPUT_INVALID');
  assert.equal(proxyCalls, 0);
  assert.equal(proxied.calls.sign, 0);

  const revoked = Proxy.revocable(dependencies().value, {});
  revoked.revoke();
  const revokedSource = input();
  revokedSource.value.dependencies = revoked.proxy;
  await rejectsCode(createSignedRuntimeManifest(revokedSource.value), 'RUNTIME_INPUT_INVALID');
});

test('validates canonical RSA-3072 public payload and verified 384-byte signature with redacted errors', async () => {
  const shortModulus = Buffer.alloc(383, 0x80).toString('base64url');
  const lowModulus = Buffer.from(PUBLIC_PAYLOAD.modulusBase64Url, 'base64url');
  lowModulus[0] = 0x01;
  for (const payload of [
    { ...PUBLIC_PAYLOAD, algorithm: 'RSA-PSS' },
    { ...PUBLIC_PAYLOAD, exponentBase64Url: 'Aw' },
    { ...PUBLIC_PAYLOAD, modulusBase64Url: `${PUBLIC_PAYLOAD.modulusBase64Url}=` },
    { ...PUBLIC_PAYLOAD, modulusBase64Url: shortModulus },
    { ...PUBLIC_PAYLOAD, modulusBase64Url: lowModulus.toString('base64url') },
    { ...PUBLIC_PAYLOAD, extra: true },
  ]) {
    const source = input({ dependencyOverrides: { getSigningPublicKey: async () => payload } });
    await rejectsCode(createSignedRuntimeManifest(source.value), 'RUNTIME_SIGNATURE_INVALID');
    assert.equal(source.calls.sign, 0);
  }

  let getterReads = 0;
  const getterPayload = { ...PUBLIC_PAYLOAD };
  Object.defineProperty(getterPayload, 'algorithm', {
    enumerable: true,
    get() { getterReads += 1; throw new Error('/private/key'); },
  });
  await rejectsCode(createSignedRuntimeManifest(input({
    dependencyOverrides: { getSigningPublicKey: () => getterPayload },
  }).value), 'RUNTIME_SIGNATURE_INVALID');
  assert.equal(getterReads, 0);

  for (const signature of [
    '', 'not-base64', Buffer.alloc(383).toString('base64'),
    Buffer.alloc(384).toString('base64'), Buffer.alloc(384),
  ]) {
    await rejectsCode(createSignedRuntimeManifest(input({
      dependencyOverrides: { sign: async () => signature },
    }).value), 'RUNTIME_SIGNATURE_INVALID');
  }

  for (const dependencyOverrides of [
    { getSigningPublicKey: async () => { throw new Error('/private/public'); } },
    { sign: async () => { throw new Error('/private/private'); } },
  ]) {
    await rejectsCode(
      createSignedRuntimeManifest(input({ dependencyOverrides }).value),
      'RUNTIME_SIGNATURE_INVALID',
    );
  }

  const mutatingSigner = input({
    dependencyOverrides: {
      async sign(bytes) {
        bytes[0] ^= 0xff;
        return cryptoSign('RSA-SHA256', bytes, privateKey).toString('base64');
      },
    },
  });
  await rejectsCode(
    createSignedRuntimeManifest(mutatingSigner.value),
    'RUNTIME_SIGNATURE_INVALID',
  );
});

test('returns a detached frozen capsule containing only canonical strings and schema version', async () => {
  const mutablePayload = structuredClone(PUBLIC_PAYLOAD);
  const result = await createSignedRuntimeManifest(input({
    dependencyOverrides: { getSigningPublicKey: async () => mutablePayload },
  }).value);
  mutablePayload.algorithm = 'mutated';

  assert.equal(Object.isFrozen(result), true);
  assert.equal(result.controllerPublicKeyJson, JSON.stringify(PUBLIC_PAYLOAD));
  for (const [key, value] of Object.entries(result)) {
    if (key === 'schemaVersion') assert.equal(value, 1);
    else assert.equal(typeof value, 'string');
    assert.doesNotMatch(key, /path/i);
    assert.equal(Buffer.isBuffer(value), false);
  }
  assert.throws(() => { result.signatureAlgorithm = 'mutated'; }, TypeError);
});
