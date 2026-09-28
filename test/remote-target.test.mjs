import assert from 'node:assert/strict';
import test from 'node:test';

import { loadRemoteTarget, trustedInput } from '../src/remote/remote-target.mjs';

const DEVICE_ID = 'dev_abc123';
const HOST_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC agent-road';
const FINGERPRINT = 'SHA256:QdPGpp8sQwLyi6Qe18XpEi5eJQk+lxry0yNyb27T4lM';
const REPLACEMENT_HOST_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIENDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0ND replacement';
const REPLACEMENT_FINGERPRINT = `SHA256:${'A'.repeat(43)}`;
const PRIVATE_KEY_PATH = `/tmp/agent-road/identity/devices/${DEVICE_ID}/id_ed25519`;
const KNOWN_HOSTS_PATH = `/tmp/agent-road/known-hosts/agent-road-known-hosts-${DEVICE_ID}`;

const readyDevice = {
  id: DEVICE_ID,
  displayName: 'Ready Windows PC',
  controllerPlatform: 'darwin',
  targetPlatform: 'windows',
  status: 'CONNECTED_SSH_ONLY',
  capabilities: ['ssh', 'sftp', 'admin-powershell'],
  createdAt: '2026-07-28T00:00:00.000Z',
  updatedAt: '2026-07-28T00:00:00.000Z',
  target: {
    version: '10.0.26200',
    build: 26200,
    edition: 'Home',
    architecture: 'AMD64',
  },
  transport: {
    tailscaleAddresses: ['100.64.0.10'],
    sshUsername: 'AgentRoad',
    sshHostKeys: [HOST_KEY],
    sshHostKeyFingerprints: [FINGERPRINT],
  },
};

const identity = {
  privateKeyPath: PRIVATE_KEY_PATH,
  publicKeyPath: `${PRIVATE_KEY_PATH}.pub`,
  publicKey: 'ssh-ed25519 fixture agent-road:dev_abc123',
};

function dependencies(device = readyDevice, calls = []) {
  return {
    registry: {
      async get(deviceId) {
        calls.push(['registry.get', deviceId]);
        return device;
      },
    },
    sshIdentity: {
      async getExisting(deviceId) {
        calls.push(['sshIdentity.getExisting', deviceId]);
        return identity;
      },
    },
    knownHostsPath(deviceId) {
      calls.push(['knownHostsPath', deviceId]);
      return KNOWN_HOSTS_PATH;
    },
  };
}

test('loads and freezes only an explicitly named ready Windows target', async () => {
  const calls = [];
  const target = await loadRemoteTarget(DEVICE_ID, dependencies(readyDevice, calls));

  assert.deepEqual(target, {
    device: readyDevice,
    identity,
    knownHostsPath: KNOWN_HOSTS_PATH,
  });
  assert.deepEqual(calls, [
    ['registry.get', DEVICE_ID],
    ['sshIdentity.getExisting', DEVICE_ID],
    ['knownHostsPath', DEVICE_ID],
  ]);
  assert.equal(Object.isFrozen(target), true);
  assert.equal(Object.isFrozen(target.device), true);
  assert.equal(Object.isFrozen(target.device.capabilities), true);
  assert.equal(Object.isFrozen(target.device.transport), true);
  assert.equal(Object.isFrozen(target.device.transport.tailscaleAddresses), true);
  assert.equal(Object.isFrozen(target.identity), true);

  readyDevice.transport.tailscaleAddresses.push('100.64.0.11');
  identity.publicKey = 'mutated';
  assert.deepEqual(target.device.transport.tailscaleAddresses, ['100.64.0.10']);
  assert.notEqual(target.identity.publicKey, 'mutated');
  readyDevice.transport.tailscaleAddresses.pop();
  identity.publicKey = 'ssh-ed25519 fixture agent-road:dev_abc123';

  const ready = await loadRemoteTarget(
    DEVICE_ID,
    dependencies({ ...readyDevice, status: 'READY' }),
  );
  assert.equal(ready.device.status, 'READY');
});

test('reports a missing device before loading trust paths or identity', async () => {
  const calls = [];
  await assert.rejects(
    loadRemoteTarget(DEVICE_ID, dependencies(null, calls)),
    (error) => error.code === 'DEVICE_NOT_FOUND',
  );
  assert.deepEqual(calls, [['registry.get', DEVICE_ID]]);
});

test('normalizes registry persistence failures to DEVICE_NOT_READY', async (t) => {
  for (const failure of [
    new SyntaxError('malformed devices JSON'),
    Object.assign(new Error('registry read failed'), { code: 'EIO' }),
  ]) {
    await t.test(failure.constructor.name, async () => {
      const deps = dependencies();
      deps.registry.get = async () => { throw failure; };
      await assert.rejects(
        loadRemoteTarget(DEVICE_ID, deps),
        (error) => error.code === 'DEVICE_NOT_READY'
          && error.message === 'DEVICE_NOT_READY'
          && !error.message.includes(failure.message),
      );
    });
  }
});

test('normalizes missing or unreadable existing identities to DEVICE_NOT_READY', async (t) => {
  for (const failure of [
    Object.assign(new Error('SSH_IDENTITY_NOT_FOUND'), { code: 'SSH_IDENTITY_NOT_FOUND' }),
    Object.assign(new Error('identity read failed'), { code: 'EACCES' }),
  ]) {
    await t.test(failure.code, async () => {
      const deps = dependencies();
      deps.sshIdentity.getExisting = async () => { throw failure; };
      await assert.rejects(
        loadRemoteTarget(DEVICE_ID, deps),
        (error) => error.code === 'DEVICE_NOT_READY'
          && error.message === 'DEVICE_NOT_READY'
          && !error.message.includes(failure.message),
      );
    });
  }
});

test('rejects wrong status, platform, and each missing required capability before identity load', async (t) => {
  const cases = [
    ['status', { ...readyDevice, status: 'ENROLLING' }],
    ['platform', { ...readyDevice, targetPlatform: 'darwin' }],
    ...readyDevice.capabilities.map((capability) => [
      `capability ${capability}`,
      {
        ...readyDevice,
        capabilities: readyDevice.capabilities.filter((value) => value !== capability),
      },
    ]),
  ];

  for (const [name, device] of cases) {
    await t.test(name, async () => {
      const calls = [];
      await assert.rejects(
        loadRemoteTarget(DEVICE_ID, dependencies(device, calls)),
        (error) => error.code === 'DEVICE_NOT_READY',
      );
      assert.deepEqual(calls, [['registry.get', DEVICE_ID]]);
    });
  }
});

test('rejects incomplete or malformed registered transport before identity load', async (t) => {
  const cases = [
    ['missing', { ...readyDevice, transport: undefined }],
    ['empty addresses', {
      ...readyDevice,
      transport: { ...readyDevice.transport, tailscaleAddresses: [] },
    }],
    ['wrong username', {
      ...readyDevice,
      transport: { ...readyDevice.transport, sshUsername: 'Administrator' },
    }],
    ['missing host keys', {
      ...readyDevice,
      transport: { ...readyDevice.transport, sshHostKeys: [] },
    }],
    ['missing fingerprints', {
      ...readyDevice,
      transport: { ...readyDevice.transport, sshHostKeyFingerprints: [] },
    }],
    ['mismatched host-key metadata', {
      ...readyDevice,
      transport: {
        ...readyDevice.transport,
        sshHostKeys: [HOST_KEY, HOST_KEY.replace(' agent-road', ' second')],
      },
    }],
  ];

  for (const [name, device] of cases) {
    await t.test(name, async () => {
      const calls = [];
      await assert.rejects(
        loadRemoteTarget(DEVICE_ID, dependencies(device, calls)),
        (error) => error.code === 'DEVICE_NOT_READY',
      );
      assert.deepEqual(calls, [['registry.get', DEVICE_ID]]);
    });
  }
});

test('strictly validates device ids, dependencies, registry output, and known-hosts paths', async (t) => {
  for (const deviceId of ['', 'dev_', 'DEV_abc123', '../dev_abc123', `dev_${'a'.repeat(61)}`]) {
    await t.test(`device id ${JSON.stringify(deviceId)}`, async () => {
      let registryCalls = 0;
      const deps = dependencies();
      deps.registry.get = async () => { registryCalls += 1; };
      await assert.rejects(
        loadRemoteTarget(deviceId, deps),
        (error) => error.code === 'REMOTE_INPUT_INVALID',
      );
      assert.equal(registryCalls, 0);
    });
  }

  for (const deps of [
    null,
    {},
    { ...dependencies(), extra: true },
    { ...dependencies(), registry: {} },
    { ...dependencies(), sshIdentity: {} },
    { ...dependencies(), knownHostsPath: 'not a function' },
  ]) {
    await assert.rejects(
      loadRemoteTarget(DEVICE_ID, deps),
      (error) => error.code === 'REMOTE_INPUT_INVALID',
    );
  }

  for (const malformed of [[], { ...readyDevice, id: 'dev_other' }, { ...readyDevice, extra: true }]) {
    await assert.rejects(
      loadRemoteTarget(DEVICE_ID, dependencies(malformed)),
      (error) => error.code === 'DEVICE_NOT_READY',
    );
  }

  for (const invalidPath of [
    '',
    'relative-known-hosts',
    '/tmp/agent-road/known-hosts/wrong-name',
    `/var/tmp/agent-road-known-hosts-${DEVICE_ID}`,
    `${KNOWN_HOSTS_PATH}\0suffix`,
  ]) {
    const deps = dependencies();
    deps.knownHostsPath = () => invalidPath;
    await assert.rejects(
      loadRemoteTarget(DEVICE_ID, deps),
      (error) => error.code === 'REMOTE_INPUT_INVALID',
    );
  }
});

test('maps a frozen target to the exact immutable trusted-session input', async () => {
  const target = await loadRemoteTarget(DEVICE_ID, dependencies());
  const runProcess = async () => ({ exitCode: 0, signal: null, stdout: '', stderr: '' });
  const input = trustedInput(target, runProcess);

  assert.deepEqual(input, {
    deviceId: DEVICE_ID,
    addresses: ['100.64.0.10'],
    hostKeys: [HOST_KEY],
    fingerprints: [FINGERPRINT],
    privateKeyPath: PRIVATE_KEY_PATH,
    knownHostsPath: KNOWN_HOSTS_PATH,
    runProcess,
  });
  assert.notEqual(input.addresses, target.device.transport.tailscaleAddresses);
  assert.notEqual(input.hostKeys, target.device.transport.sshHostKeys);
  assert.notEqual(input.fingerprints, target.device.transport.sshHostKeyFingerprints);
  assert.equal(Object.isFrozen(input.addresses), true);
  assert.equal(Object.isFrozen(input.hostKeys), true);
  assert.equal(Object.isFrozen(input.fingerprints), true);
  assert.equal(Object.isFrozen(input), true);

  assert.throws(
    () => trustedInput(null, runProcess),
    (error) => error.code === 'REMOTE_INPUT_INVALID',
  );
  assert.throws(
    () => trustedInput(target, null),
    (error) => error.code === 'REMOTE_INPUT_INVALID',
  );
  assert.throws(
    () => trustedInput(Object.freeze({
      device: Object.freeze({}),
      identity: Object.freeze({}),
      knownHostsPath: KNOWN_HOSTS_PATH,
    }), runProcess),
    (error) => error.code === 'REMOTE_INPUT_INVALID',
  );
});

test('trustedInput rejects a hostile frozen device accessor without reading it', async () => {
  const target = await loadRemoteTarget(DEVICE_ID, dependencies());
  const replacementTransport = Object.freeze({
    tailscaleAddresses: Object.freeze(['100.64.0.99']),
    sshUsername: 'AgentRoad',
    sshHostKeys: Object.freeze([REPLACEMENT_HOST_KEY]),
    sshHostKeyFingerprints: Object.freeze([REPLACEMENT_FINGERPRINT]),
  });
  let transportReads = 0;
  const hostileDevice = { ...target.device };
  Object.defineProperty(hostileDevice, 'transport', {
    enumerable: true,
    get() {
      transportReads += 1;
      return transportReads <= 6 ? target.device.transport : replacementTransport;
    },
  });
  Object.freeze(hostileDevice);
  const hostileTarget = Object.freeze({ ...target, device: hostileDevice });
  const runProcess = async () => ({ exitCode: 0, signal: null, stdout: '', stderr: '' });

  assert.throws(
    () => trustedInput(hostileTarget, runProcess),
    (error) => error.code === 'REMOTE_INPUT_INVALID',
  );
  assert.equal(transportReads, 0);
});

test('trustedInput rejects frozen transport array accessors before reading them', async () => {
  const target = await loadRemoteTarget(DEVICE_ID, dependencies());
  const reads = {
    tailscaleAddresses: 0,
    sshHostKeys: 0,
    sshHostKeyFingerprints: 0,
  };
  const transport = { sshUsername: 'AgentRoad' };
  const values = {
    tailscaleAddresses: [target.device.transport.tailscaleAddresses, ['100.64.0.99']],
    sshHostKeys: [target.device.transport.sshHostKeys, [REPLACEMENT_HOST_KEY]],
    sshHostKeyFingerprints: [
      target.device.transport.sshHostKeyFingerprints,
      [REPLACEMENT_FINGERPRINT],
    ],
  };

  for (const field of Object.keys(values)) {
    Object.defineProperty(transport, field, {
      enumerable: true,
      get() {
        reads[field] += 1;
        return values[field][reads[field] <= 3 ? 0 : 1];
      },
    });
  }

  Object.freeze(transport);
  const hostileDevice = Object.freeze({ ...target.device, transport });
  const hostileTarget = Object.freeze({ ...target, device: hostileDevice });
  const runProcess = async () => ({ exitCode: 0, signal: null, stdout: '', stderr: '' });

  assert.throws(
    () => trustedInput(hostileTarget, runProcess),
    (error) => error.code === 'REMOTE_INPUT_INVALID',
  );
  assert.deepEqual(reads, {
    tailscaleAddresses: 0,
    sshHostKeys: 0,
    sshHostKeyFingerprints: 0,
  });
});

test('preserves local identity contention as DEVICE_BUSY without private diagnostics', async () => {
  const deps = dependencies();
  deps.sshIdentity.getExisting = async () => {
    throw Object.assign(new Error('/private/path owner details'), { code: 'SSH_IDENTITY_BUSY' });
  };
  await assert.rejects(loadRemoteTarget(DEVICE_ID, deps), error =>
    error.code === 'DEVICE_BUSY' && error.message === 'DEVICE_BUSY' && error.cause === undefined);
});
