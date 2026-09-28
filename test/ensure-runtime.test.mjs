import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign as cryptoSign,
} from 'node:crypto';
import test from 'node:test';

import {
  doctorRuntime,
  ensureRuntime,
  runtimeStatus,
} from '../src/runtime/ensure-runtime.mjs';
import {
  digestRuntimeInventory,
  validateRuntimeInventory,
} from '../src/runtime/runtime-inventory.mjs';
import { validateRuntimeStateRecord } from '../src/runtime/runtime-state-store.mjs';

const DEVICE_ID = 'dev_abc123';
const OPERATION_ID = 'a'.repeat(32);
const NEXT_OPERATION_ID = 'b'.repeat(32);
const GENERATION_DIGEST = 'D'.repeat(64);
const ARTIFACT_BYTES = Buffer.from('runtime artifact fixture\n');
const ARTIFACT_SHA256 = createHash('sha256').update(ARTIFACT_BYTES).digest('hex').toUpperCase();
const REQUIRED_FREE_BYTES = 256 * 1024 ** 2 + ARTIFACT_BYTES.length + 1_024;
const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 3072,
  publicExponent: 0x10001,
});
const publicJwk = publicKey.export({ format: 'jwk' });
const PUBLIC_KEY = Object.freeze({
  algorithm: 'RSA-SHA256',
  modulusBase64Url: publicJwk.n,
  exponentBase64Url: 'AQAB',
});

function catalog() {
  return {
    schemaVersion: 1,
    catalogRevision: 1,
    platform: { os: 'windows', architecture: 'x64', minimumBuild: 17_763 },
    artifacts: [{
      id: 'powershell-7',
      version: '7.6.4',
      url: 'https://example.com/PowerShell-7.6.4-win-x64.zip',
      redirectOrigins: ['https://downloads.example.com'],
      bytes: ARTIFACT_BYTES.length,
      maximumExpandedBytes: 1_024,
      sha256: ARTIFACT_SHA256,
      packaging: 'zip',
      signerRule: 'microsoft-corporation',
      verificationCommandId: 'powershell-json-roundtrip',
    }],
    profiles: [
      { id: 'core', artifacts: ['powershell-7'], dependencies: [] },
      { id: 'base', artifacts: ['powershell-7'], dependencies: ['core'] },
    ],
  };
}

function inventory(overrides = {}) {
  const snapshot = {
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
  return {
    ...snapshot,
    ...overrides,
    platform: { ...snapshot.platform, ...overrides.platform },
    runtime: { ...snapshot.runtime, ...overrides.runtime },
  };
}

function state(overrides = {}) {
  return {
    schemaVersion: 1,
    deviceId: DEVICE_ID,
    runtimeStatus: 'UNPROVISIONED',
    requestedProfiles: [],
    readyProfiles: [],
    operationId: null,
    manifestDigest: null,
    generationDigest: null,
    failureCode: null,
    updatedAt: null,
    ...overrides,
  };
}

function error(code) {
  const value = new Error(code);
  value.code = code;
  return value;
}

function fixture(options = {}) {
  const calls = {
    factory: 0,
    target: 0,
    stateRead: 0,
    transitions: [],
    inventory: 0,
    catalog: 0,
    operationId: 0,
    clock: 0,
    publicKey: 0,
    sign: 0,
    acquire: [],
    provision: [],
  };
  const target = Object.freeze({
    device: Object.freeze({ id: DEVICE_ID }),
    identity: Object.freeze({
      privateKeyPath: `/tmp/agent-road/identity/devices/${DEVICE_ID}/id_ed25519`,
      publicKeyPath: `/tmp/agent-road/identity/devices/${DEVICE_ID}/id_ed25519.pub`,
      publicKey: 'ssh-ed25519 fixture',
    }),
    knownHostsPath: `/tmp/agent-road/known-hosts/agent-road-known-hosts-${DEVICE_ID}`,
  });
  let currentState = validateRuntimeStateRecord(options.state ?? state());
  const inventoryValues = options.inventories ?? [inventory(), inventory()];
  const dependencies = {
    loadTarget: async (deviceId) => {
      calls.target += 1;
      assert.equal(deviceId, DEVICE_ID);
      return target;
    },
    readState: async (deviceId) => {
      calls.stateRead += 1;
      assert.equal(deviceId, DEVICE_ID);
      return currentState;
    },
    transitionState: async (expected, next) => {
      if (options.failTransitionStatus === next.runtimeStatus) {
        throw new Error('private transition failure');
      }
      if (JSON.stringify(expected) !== JSON.stringify(currentState)) {
        throw error('RUNTIME_ALREADY_RUNNING');
      }
      const saved = validateRuntimeStateRecord(next);
      calls.transitions.push(saved);
      currentState = saved;
      if (options.commitThenFailTransitionStatus === next.runtimeStatus) {
        throw new Error('private post-commit response failure');
      }
      return saved;
    },
    readInventory: async (inputTarget) => {
      assert.equal(inputTarget, target);
      const value = inventoryValues[Math.min(calls.inventory, inventoryValues.length - 1)];
      calls.inventory += 1;
      return validateRuntimeInventory(value);
    },
    loadCatalog: async () => {
      calls.catalog += 1;
      return catalog();
    },
    getSigningPublicKey: async () => {
      calls.publicKey += 1;
      return PUBLIC_KEY;
    },
    sign: async (bytes) => {
      calls.sign += 1;
      return cryptoSign('RSA-SHA256', bytes, privateKey).toString('base64');
    },
    acquireArtifact: async (artifact) => {
      calls.acquire.push(artifact);
      return Object.freeze({
        artifactId: artifact.id,
        version: artifact.version,
        path: `/tmp/${artifact.sha256}.bin`,
        bytes: artifact.bytes,
        sha256: artifact.sha256,
      });
    },
    provision: async (input) => {
      calls.provision.push(input);
      return Object.freeze({
        schemaVersion: 1,
        status: 'committed',
        deviceId: DEVICE_ID,
        address: '100.64.0.10',
        operationId: input.plan.operationId,
        manifestDigest: input.capsule.manifestDigest,
        generationDigest: input.capsule.generationDigest,
        restartRequired: false,
        failureCode: null,
      });
    },
    operationId: () => {
      calls.operationId += 1;
      return options.operationId ?? OPERATION_ID;
    },
    clock: () => {
      calls.clock += 1;
      return new Date('2026-07-30T00:00:00.000Z');
    },
    ...options.dependencies,
  };
  return {
    calls,
    dependencies,
    dependencyFactory: () => {
      calls.factory += 1;
      return dependencies;
    },
    get state() { return currentState; },
  };
}

async function rejectsCode(pending, code) {
  await assert.rejects(pending, (caught) => {
    assert.equal(caught?.code, code);
    assert.equal(caught?.message, code);
    assert.deepEqual(Object.keys(caught), ['code']);
    return true;
  });
}

test('gates unavailable and invalid profiles before constructing production dependencies', async () => {
  for (const [requestedProfiles, code] of [
    [['base'], 'RUNTIME_PROFILE_UNAVAILABLE'],
    [['core', 'core'], 'RUNTIME_INPUT_INVALID'],
    [['unknown'], 'RUNTIME_INPUT_INVALID'],
  ]) {
    const f = fixture();
    await rejectsCode(ensureRuntime({
      deviceId: DEVICE_ID,
      requestedProfiles,
      dependencyFactory: f.dependencyFactory,
    }), code);
    assert.equal(f.calls.factory, 0);
  }
});

test('refuses persisted intermediate and uncertain states before inventory or signing', async () => {
  for (const [runtimeStatus, failureCode, expectedCode] of [
    ['ACQUIRING', null, 'RUNTIME_ALREADY_RUNNING'],
    ['FAILED', 'RUNTIME_COMPLETION_UNCERTAIN', 'RUNTIME_COMPLETION_UNCERTAIN'],
  ]) {
    const f = fixture({ state: state({
      runtimeStatus,
      requestedProfiles: ['core'],
      operationId: OPERATION_ID,
      manifestDigest: 'A'.repeat(64),
      generationDigest: 'B'.repeat(64),
      failureCode,
      updatedAt: '2026-07-29T23:59:59.000Z',
    }) });
    await rejectsCode(ensureRuntime({
      deviceId: DEVICE_ID,
      requestedProfiles: ['core'],
      dependencyFactory: f.dependencyFactory,
    }), expectedCode);
    assert.equal(f.calls.inventory, 0);
    assert.equal(f.calls.sign, 0);
    assert.equal(f.calls.acquire.length, 0);
    assert.equal(f.calls.provision.length, 0);
  }
});

test('rejects a RECOVERED operation replay before clock, catalog, inventory, or work', async () => {
  const recovered = state({
    schemaVersion: 2,
    runtimeStatus: 'RECOVERED',
    requestedProfiles: ['core'],
    operationId: OPERATION_ID,
    manifestDigest: 'A'.repeat(64),
    generationDigest: 'B'.repeat(64),
    updatedAt: '2026-07-29T23:59:59.000Z',
  });
  const f = fixture({ state: recovered });

  await rejectsCode(ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: f.dependencyFactory,
  }), 'RUNTIME_STATE_UNSUPPORTED');

  assert.equal(f.calls.operationId, 1);
  assert.equal(f.calls.clock, 0);
  assert.equal(f.calls.catalog, 0);
  assert.equal(f.calls.inventory, 0);
  assert.equal(f.calls.publicKey, 0);
  assert.equal(f.calls.sign, 0);
  assert.equal(f.calls.acquire.length, 0);
  assert.equal(f.calls.provision.length, 0);
  assert.equal(f.calls.transitions.length, 0);
});

test('runs a stable double inventory, signs internally, acquires the exact artifact, and commits READY', async () => {
  const f = fixture();
  const result = await ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: f.dependencyFactory,
  });

  assert.equal(result.runtimeStatus, 'READY');
  assert.deepEqual(result.readyProfiles, ['core']);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(f.calls.inventory, 2);
  assert.equal(f.calls.sign, 1);
  assert.deepEqual(f.calls.acquire, [{
    id: 'powershell-7',
    version: '7.6.4',
    url: 'https://example.com/PowerShell-7.6.4-win-x64.zip',
    redirectOrigins: ['https://downloads.example.com'],
    bytes: ARTIFACT_BYTES.length,
    sha256: ARTIFACT_SHA256,
  }]);
  assert.equal(f.calls.provision.length, 1);
  assert.deepEqual(f.calls.transitions.map(({ runtimeStatus }) => runtimeStatus), [
    'INVENTORY_READY',
    'PLAN_READY',
    'ACQUIRING',
    'READY',
  ]);
});

test('accepts above-threshold free-space drift and provisions from the second exact inventory snapshot', async () => {
  const first = inventory({ freeBytes: REQUIRED_FREE_BYTES + 10_000 });
  const second = inventory({ freeBytes: REQUIRED_FREE_BYTES + 1 });
  const f = fixture({ inventories: [first, second] });

  const result = await ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: f.dependencyFactory,
  });

  assert.equal(result.runtimeStatus, 'READY');
  assert.equal(f.calls.provision.length, 1);
  assert.deepEqual(f.calls.provision[0].inventorySnapshot, validateRuntimeInventory(second));
  assert.equal(
    f.calls.provision[0].plan.inventoryDigest,
    digestRuntimeInventory(second),
  );
});

test('keeps stable below-threshold inventories as a disk blocker', async () => {
  const f = fixture({ inventories: [
    inventory({ freeBytes: REQUIRED_FREE_BYTES - 10 }),
    inventory({ freeBytes: REQUIRED_FREE_BYTES - 1 }),
  ] });

  await rejectsCode(ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: f.dependencyFactory,
  }), 'RUNTIME_DISK_INSUFFICIENT');

  assert.deepEqual(f.calls.transitions.map(({ runtimeStatus }) => runtimeStatus), [
    'INVENTORY_READY',
    'FAILED',
  ]);
  assert.equal(f.calls.sign, 0);
  assert.equal(f.calls.acquire.length, 0);
  assert.equal(f.calls.provision.length, 0);
});

test('rejects threshold crossings and non-free inventory changes before state, signing, acquisition, or provision', async () => {
  const cases = [
    [
      inventory({ freeBytes: REQUIRED_FREE_BYTES + 1 }),
      inventory({ freeBytes: REQUIRED_FREE_BYTES - 1 }),
    ],
    [
      inventory({ freeBytes: REQUIRED_FREE_BYTES - 1 }),
      inventory({ freeBytes: REQUIRED_FREE_BYTES + 1 }),
    ],
    [
      inventory(),
      inventory({ pendingReboot: true }),
    ],
    [
      inventory(),
      inventory({ interactiveSession: true }),
    ],
  ];
  for (const inventories of cases) {
    const f = fixture({ inventories });
    await rejectsCode(ensureRuntime({
      deviceId: DEVICE_ID,
      requestedProfiles: ['core'],
      dependencyFactory: f.dependencyFactory,
    }), 'RUNTIME_INVENTORY_CHANGED');
    assert.equal(f.calls.transitions.length, 0);
    assert.equal(f.calls.sign, 0);
    assert.equal(f.calls.acquire.length, 0);
    assert.equal(f.calls.provision.length, 0);
  }
});

test('adopts an exact verified no-op without signing, acquisition, or provisioning', async () => {
  const desiredCatalog = catalog();
  const catalogDigest = createHash('sha256')
    .update(JSON.stringify(desiredCatalog), 'utf8')
    .digest('hex')
    .toUpperCase();
  const present = inventory({
    runtime: {
      schemaVersion: 1,
      catalogRevision: 1,
      catalogDigest,
      generationDigest: GENERATION_DIGEST,
      generationVerified: true,
    },
    managedArtifacts: [{
      id: 'powershell-7',
      version: '7.6.4',
      bytes: ARTIFACT_BYTES.length,
      sha256: ARTIFACT_SHA256,
      verified: true,
    }],
  });
  const f = fixture({ inventories: [present, present] });

  const result = await ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: f.dependencyFactory,
  });

  assert.equal(result.runtimeStatus, 'READY');
  assert.equal(result.operationId, null);
  assert.equal(result.manifestDigest, null);
  assert.equal(result.generationDigest, GENERATION_DIGEST);
  assert.deepEqual(f.calls.transitions.map(({ runtimeStatus }) => runtimeStatus), [
    'INVENTORY_READY',
    'READY',
  ]);
  assert.equal(f.calls.sign, 0);
  assert.equal(f.calls.acquire.length, 0);
  assert.equal(f.calls.provision.length, 0);
});

test('turns RECOVERED into a distinct schema-1 no-op attempt and READY', async () => {
  const desiredCatalog = catalog();
  const catalogDigest = createHash('sha256')
    .update(JSON.stringify(desiredCatalog), 'utf8')
    .digest('hex')
    .toUpperCase();
  const present = inventory({
    runtime: {
      schemaVersion: 1,
      catalogRevision: 1,
      catalogDigest,
      generationDigest: GENERATION_DIGEST,
      generationVerified: true,
    },
    managedArtifacts: [{
      id: 'powershell-7',
      version: '7.6.4',
      bytes: ARTIFACT_BYTES.length,
      sha256: ARTIFACT_SHA256,
      verified: true,
    }],
  });
  const recovered = state({
    schemaVersion: 2,
    runtimeStatus: 'RECOVERED',
    requestedProfiles: ['core'],
    operationId: OPERATION_ID,
    manifestDigest: 'A'.repeat(64),
    generationDigest: 'B'.repeat(64),
    updatedAt: '2026-07-29T23:59:59.000Z',
  });
  const f = fixture({
    state: recovered,
    inventories: [present, present],
    operationId: NEXT_OPERATION_ID,
  });

  const result = await ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: f.dependencyFactory,
  });

  assert.equal(result.schemaVersion, 1);
  assert.equal(result.runtimeStatus, 'READY');
  assert.notDeepEqual(result, validateRuntimeStateRecord(recovered));
  assert.deepEqual(f.calls.transitions.map(({ runtimeStatus }) => runtimeStatus), [
    'INVENTORY_READY',
    'READY',
  ]);
  assert.equal(f.calls.transitions[0].schemaVersion, 1);
  assert.equal(f.calls.transitions[0].operationId, NEXT_OPERATION_ID);
  assert.equal(f.calls.transitions[0].manifestDigest, null);
  assert.equal(f.calls.transitions[0].generationDigest, null);
  assert.equal(f.calls.sign, 0);
  assert.equal(f.calls.acquire.length, 0);
  assert.equal(f.calls.provision.length, 0);
});

test('doctor is read-only and runtime status verifies transport before reading local state', async () => {
  const f = fixture();
  const diagnosed = await doctorRuntime({
    deviceId: DEVICE_ID,
    dependencyFactory: f.dependencyFactory,
  });
  assert.deepEqual(diagnosed, validateRuntimeInventory(inventory()));
  assert.equal(f.calls.inventory, 1);
  assert.equal(f.calls.transitions.length, 0);

  const status = await runtimeStatus({
    deviceId: DEVICE_ID,
    dependencyFactory: f.dependencyFactory,
  });
  assert.deepEqual(status, state());
  assert.equal(f.calls.target, 2);
  assert.equal(f.calls.stateRead, 1);
});

test('runtime status may expose RECOVERED without treating it as READY', async () => {
  const recovered = state({
    schemaVersion: 2,
    runtimeStatus: 'RECOVERED',
    requestedProfiles: ['core'],
    operationId: OPERATION_ID,
    manifestDigest: 'A'.repeat(64),
    generationDigest: 'B'.repeat(64),
    updatedAt: '2026-07-29T23:59:59.000Z',
  });
  const f = fixture({ state: recovered });

  assert.deepEqual(await runtimeStatus({
    deviceId: DEVICE_ID,
    dependencyFactory: f.dependencyFactory,
  }), validateRuntimeStateRecord(recovered));
  assert.equal(f.calls.transitions.length, 0);
});

test('performs zero state writes when local READY already matches the verified generation', async () => {
  const desiredCatalog = catalog();
  const catalogDigest = createHash('sha256')
    .update(JSON.stringify(desiredCatalog), 'utf8')
    .digest('hex')
    .toUpperCase();
  const present = inventory({
    runtime: {
      schemaVersion: 1,
      catalogRevision: 1,
      catalogDigest,
      generationDigest: GENERATION_DIGEST,
      generationVerified: true,
    },
    managedArtifacts: [{
      id: 'powershell-7',
      version: '7.6.4',
      bytes: ARTIFACT_BYTES.length,
      sha256: ARTIFACT_SHA256,
      verified: true,
    }],
  });
  const ready = state({
    runtimeStatus: 'READY',
    requestedProfiles: ['core'],
    readyProfiles: ['core'],
    operationId: null,
    generationDigest: GENERATION_DIGEST,
    updatedAt: '2026-07-29T23:59:59.000Z',
  });
  const f = fixture({ state: ready, inventories: [present, present] });

  assert.deepEqual(await ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: f.dependencyFactory,
  }), validateRuntimeStateRecord(ready));
  assert.equal(f.calls.transitions.length, 0);
  assert.equal(f.calls.sign, 0);
  assert.equal(f.calls.acquire.length, 0);
  assert.equal(f.calls.provision.length, 0);
});

test('maps elevation blockers and records a monotonic finite failure', async () => {
  const f = fixture({
    state: state({
      runtimeStatus: 'FAILED',
      requestedProfiles: ['core'],
      operationId: 'b'.repeat(32),
      failureCode: 'RUNTIME_INSTALL_FAILED',
      updatedAt: '2026-07-30T00:00:00.000Z',
    }),
    inventories: [
      inventory({ platform: { elevated: false } }),
      inventory({ platform: { elevated: false } }),
    ],
  });

  await rejectsCode(ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: f.dependencyFactory,
  }), 'RUNTIME_ELEVATION_REQUIRED');
  assert.equal(f.state.runtimeStatus, 'FAILED');
  assert.equal(f.state.failureCode, 'RUNTIME_ELEVATION_REQUIRED');
  assert.equal(f.calls.transitions[0].updatedAt, '2026-07-30T00:00:00.001Z');
  assert.equal(f.calls.transitions[1].updatedAt, '2026-07-30T00:00:00.002Z');
});

test('rejects hostile factory results and nested target proxies without invoking traps', async () => {
  let thenReads = 0;
  const hostileThenable = {};
  Object.defineProperty(hostileThenable, 'then', {
    get() {
      thenReads += 1;
      throw new Error('then trap');
    },
    enumerable: true,
  });
  await rejectsCode(ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: () => hostileThenable,
  }), 'RUNTIME_INPUT_INVALID');
  assert.equal(thenReads, 0);

  let descriptorTraps = 0;
  const nestedProxy = new Proxy({}, {
    getOwnPropertyDescriptor() {
      descriptorTraps += 1;
      throw new Error('descriptor trap');
    },
  });
  const f = fixture({
    dependencies: {
      loadTarget: async () => Object.freeze({ device: nestedProxy }),
    },
  });
  await rejectsCode(ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: f.dependencyFactory,
  }), 'RUNTIME_INVENTORY_FAILED');
  assert.equal(descriptorTraps, 0);
});

test('maps factory throws and rejections to input failure without leaking private text', async () => {
  for (const dependencyFactory of [
    () => { throw new Error('private factory path'); },
    () => Promise.reject(new Error('private async factory path')),
  ]) {
    await rejectsCode(ensureRuntime({
      deviceId: DEVICE_ID,
      requestedProfiles: ['core'],
      dependencyFactory,
    }), 'RUNTIME_INPUT_INVALID');
  }
});

test('rejects non-exact target envelopes before reading runtime state', async () => {
  let stateReads = 0;
  const f = fixture({
    dependencies: {
      loadTarget: async () => Object.freeze({
        device: Object.freeze({ id: DEVICE_ID }),
        identity: Object.freeze({}),
        knownHostsPath: '/tmp/known-hosts',
        extra: 'untrusted',
      }),
      readState: async () => {
        stateReads += 1;
        return state();
      },
    },
  });
  await rejectsCode(ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: f.dependencyFactory,
  }), 'RUNTIME_INVENTORY_FAILED');
  assert.equal(stateReads, 0);
});

test('rejects artifact and provision binding mismatches and retains full operation digests', async () => {
  const badArtifact = fixture({
    dependencies: {
      acquireArtifact: async (artifact) => ({
        artifactId: artifact.id,
        version: artifact.version,
        path: `/tmp/${artifact.sha256}.bin`,
        bytes: artifact.bytes,
        sha256: 'E'.repeat(64),
      }),
    },
  });
  await rejectsCode(ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: badArtifact.dependencyFactory,
  }), 'RUNTIME_ARTIFACT_INVALID');
  assert.equal(badArtifact.state.runtimeStatus, 'FAILED');
  assert.match(badArtifact.state.manifestDigest, /^[A-F0-9]{64}$/u);
  assert.match(badArtifact.state.generationDigest, /^[A-F0-9]{64}$/u);

  const badProvision = fixture({
    dependencies: {
      provision: async (input) => ({
        schemaVersion: 1,
        status: 'committed',
        deviceId: DEVICE_ID,
        address: '100.64.0.10',
        operationId: input.plan.operationId,
        manifestDigest: input.capsule.manifestDigest,
        generationDigest: 'F'.repeat(64),
        restartRequired: false,
        failureCode: null,
      }),
    },
  });
  await rejectsCode(ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: badProvision.dependencyFactory,
  }), 'RUNTIME_COMPLETION_UNCERTAIN');
  assert.equal(badProvision.state.runtimeStatus, 'FAILED');
  assert.equal(badProvision.state.failureCode, 'RUNTIME_COMPLETION_UNCERTAIN');
  assert.match(badProvision.state.manifestDigest, /^[A-F0-9]{64}$/u);
  assert.match(badProvision.state.generationDigest, /^[A-F0-9]{64}$/u);
});

test('maps a post-provision READY persistence failure to completion uncertainty', async () => {
  const f = fixture({ failTransitionStatus: 'READY' });
  await rejectsCode(ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: f.dependencyFactory,
  }), 'RUNTIME_COMPLETION_UNCERTAIN');
  assert.equal(f.calls.provision.length, 1);
  assert.equal(f.state.runtimeStatus, 'FAILED');
  assert.equal(f.state.failureCode, 'RUNTIME_COMPLETION_UNCERTAIN');
});

test('lets only one concurrent ensure acquire the state CAS', async () => {
  let firstInventoryReaders = 0;
  let releaseReaders;
  const readers = new Promise((resolve) => { releaseReaders = resolve; });
  const f = fixture({
    dependencies: {
      readInventory: async () => {
        firstInventoryReaders += 1;
        if (firstInventoryReaders <= 2) {
          if (firstInventoryReaders === 2) releaseReaders();
          await readers;
        }
        return validateRuntimeInventory(inventory());
      },
    },
  });
  const results = await Promise.allSettled([
    ensureRuntime({
      deviceId: DEVICE_ID,
      requestedProfiles: ['core'],
      dependencyFactory: f.dependencyFactory,
    }),
    ensureRuntime({
      deviceId: DEVICE_ID,
      requestedProfiles: ['core'],
      dependencyFactory: f.dependencyFactory,
    }),
  ]);
  assert.equal(results.filter(({ status }) => status === 'fulfilled').length, 1);
  assert.equal(results.filter(({ status }) => status === 'rejected').length, 1);
  assert.equal(results.find(({ status }) => status === 'rejected').reason.code, 'RUNTIME_ALREADY_RUNNING');
});

test('maps an untrusted catalog dependency code to a finite internal failure', async () => {
  const f = fixture({
    dependencies: {
      loadCatalog: async () => { throw error('PRIVATE_CATALOG_PATH'); },
    },
  });
  await rejectsCode(ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: f.dependencyFactory,
  }), 'RUNTIME_INTERNAL_ERROR');
});

test('rejects native promises carrying own properties before awaiting them', async () => {
  const f = fixture();
  const pending = Promise.resolve(f.dependencies);
  Object.defineProperty(pending, Symbol('hostile'), { value: true });
  await rejectsCode(ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: () => pending,
  }), 'RUNTIME_INPUT_INVALID');
  assert.equal(f.calls.target, 0);
});

test('treats a post-commit READY response ambiguity as completion uncertainty', async () => {
  const f = fixture({ commitThenFailTransitionStatus: 'READY' });
  await rejectsCode(ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: f.dependencyFactory,
  }), 'RUNTIME_COMPLETION_UNCERTAIN');
  assert.equal(f.calls.provision.length, 1);
  assert.equal(f.state.runtimeStatus, 'READY');
});

test('uses phase-specific error allowlists for acquisition and provision', async () => {
  const acquisition = fixture({
    dependencies: {
      acquireArtifact: async () => { throw error('RUNTIME_ELEVATION_REQUIRED'); },
    },
  });
  await rejectsCode(ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: acquisition.dependencyFactory,
  }), 'RUNTIME_ARTIFACT_ACQUISITION_FAILED');

  const provision = fixture({
    dependencies: {
      provision: async () => { throw error('RUNTIME_CACHE_UNSAFE'); },
    },
  });
  await rejectsCode(ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: provision.dependencyFactory,
  }), 'RUNTIME_COMPLETION_UNCERTAIN');
});

test('maps every deterministic planner blocker to its stable controller code', async () => {
  const cases = [
    [{ platform: { architecture: 'arm64' } }, 'RUNTIME_PLATFORM_UNSUPPORTED'],
    [{ pendingReboot: true }, 'RUNTIME_REBOOT_REQUIRED'],
    [{ runtime: {
      schemaVersion: 2,
      catalogRevision: 1,
      catalogDigest: 'A'.repeat(64),
      generationDigest: 'B'.repeat(64),
    } }, 'RUNTIME_STATE_UNSUPPORTED'],
    [{ runtime: { pendingOperationId: 'b'.repeat(32) } }, 'RUNTIME_OPERATION_CONFLICT'],
    [{ freeBytes: 1 }, 'RUNTIME_DISK_INSUFFICIENT'],
  ];
  for (const [overrides, expected] of cases) {
    const blocked = inventory(overrides);
    const f = fixture({ inventories: [blocked, blocked] });
    await rejectsCode(ensureRuntime({
      deviceId: DEVICE_ID,
      requestedProfiles: ['core'],
      dependencyFactory: f.dependencyFactory,
    }), expected);
    assert.equal(f.state.failureCode, expected);
  }
});

test('rejects a decorated clock without invoking its properties', async () => {
  let getterReads = 0;
  const decorated = new Date('2026-07-30T00:00:00.000Z');
  Object.defineProperty(decorated, 'secret', {
    get() {
      getterReads += 1;
      throw new Error('clock getter trap');
    },
  });
  const f = fixture({ dependencies: { clock: () => decorated } });
  await rejectsCode(ensureRuntime({
    deviceId: DEVICE_ID,
    requestedProfiles: ['core'],
    dependencyFactory: f.dependencyFactory,
  }), 'RUNTIME_INTERNAL_ERROR');
  assert.equal(getterReads, 0);
  assert.equal(f.calls.inventory, 0);
});
