import assert from 'node:assert/strict';
import test from 'node:test';

import { DEVICE_STATUSES, validateDeviceRecord } from '../src/core/device-model.mjs';
import { statePaths } from '../src/core/paths.mjs';

const validWindowsRecord = {
  id: 'dev_018f',
  displayName: 'Windows workstation',
  controllerPlatform: 'darwin',
  targetPlatform: 'windows',
  status: 'READY',
  capabilities: ['ssh', 'mcp'],
  createdAt: '2026-07-26T00:00:00.000Z',
  updatedAt: '2026-07-26T00:00:00.000Z',
};

const target = {
  version: '10.0.19045',
  build: 19045,
  edition: 'Professional',
  architecture: 'AMD64',
};

const transport = {
  tailscaleAddresses: ['100.64.0.10', 'fd7a:115c:a1e0::10'],
  sshUsername: 'AgentRoad',
  sshHostKeys: ['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC agent-road'],
  sshHostKeyFingerprints: ['SHA256:QdPGpp8sQwLyi6Qe18XpEi5eJQk+lxry0yNyb27T4lM'],
};

test('exports the exact device status array', () => {
  assert.deepEqual(DEVICE_STATUSES, [
    'ENROLLING',
    'CONNECTED_SSH_ONLY',
    'GUI_LOGIN_REQUIRED',
    'MCP_UNAVAILABLE',
    'TAILSCALE_AUTH_REQUIRED',
    'DEGRADED_RECOVERY_AVAILABLE',
    'REBOOT_RECOVERY_FAILED',
    'READY',
    'TAILSCALE_SERVE_AUTH_REQUIRED',
    'TAILSCALE_LOGIN_REQUIRED',
    'SSH_VERIFY_FAILED',
    'BOOTSTRAP_FAILED',
  ]);
  assert.ok(Object.isFrozen(DEVICE_STATUSES));
});

test('returns all bootstrap identity and known-host paths below the state root', () => {
  assert.deepEqual(statePaths({ AGENT_ROAD_HOME: '/tmp/agent-road-state' }), {
    root: '/tmp/agent-road-state',
    devices: '/tmp/agent-road-state/devices.json',
    tokens: '/tmp/agent-road-state/enrollment-tokens.json',
    signingPrivateKey: '/tmp/agent-road-state/identity/bootstrap-signing-private.pem',
    signingPublicKey: '/tmp/agent-road-state/identity/bootstrap-signing-public.json',
    sshIdentities: '/tmp/agent-road-state/identity/devices',
    knownHosts: '/tmp/agent-road-state/known-hosts',
    runtimeRoot: '/tmp/agent-road-state/runtime',
    runtimeArtifacts: '/tmp/agent-road-state/runtime/artifacts',
    runtimeDevices: '/tmp/agent-road-state/runtime/devices',
  });
});

test('validates, clones, and freezes Windows bootstrap target and transport metadata', () => {
  const inputTarget = { ...target };
  const inputTransport = {
    ...transport,
    tailscaleAddresses: [...transport.tailscaleAddresses],
    sshHostKeys: [...transport.sshHostKeys],
    sshHostKeyFingerprints: [...transport.sshHostKeyFingerprints],
  };
  const result = validateDeviceRecord({
    ...validWindowsRecord,
    status: 'CONNECTED_SSH_ONLY',
    target: inputTarget,
    transport: inputTransport,
  });

  assert.deepEqual(result.target, target);
  assert.deepEqual(result.transport, transport);
  assert.notEqual(result.target, inputTarget);
  assert.notEqual(result.transport, inputTransport);
  assert.notEqual(result.transport.tailscaleAddresses, inputTransport.tailscaleAddresses);
  assert.notEqual(result.transport.sshHostKeys, inputTransport.sshHostKeys);
  assert.notEqual(result.transport.sshHostKeyFingerprints, inputTransport.sshHostKeyFingerprints);
  assert.ok(Object.isFrozen(result.target));
  assert.ok(Object.isFrozen(result.transport));
  assert.ok(Object.isFrozen(result.transport.tailscaleAddresses));
  assert.ok(Object.isFrozen(result.transport.sshHostKeys));
  assert.ok(Object.isFrozen(result.transport.sshHostKeyFingerprints));

  inputTarget.edition = 'Mutated';
  inputTransport.tailscaleAddresses.push('100.64.0.11');
  inputTransport.sshHostKeys[0] = 'ssh-ed25519 AAAA';
  assert.equal(result.target.edition, 'Professional');
  assert.deepEqual(result.transport.tailscaleAddresses, ['100.64.0.10', 'fd7a:115c:a1e0::10']);
  assert.match(result.transport.sshHostKeys[0], /^ssh-ed25519 AAAAC3/);
});

test('rejects unknown top-level, target, and transport fields', () => {
  assert.throws(() => validateDeviceRecord({ ...validWindowsRecord, unexpected: true }), /unknown.*unexpected/i);
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, target: { ...target, channel: 'ltsc' } }),
    /target.*unknown.*channel/i,
  );
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, transport: { ...transport, proxy: 'no' } }),
    /transport.*unknown.*proxy/i,
  );
});

test('rejects invalid target metadata shapes and bounds', () => {
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, target: { ...target, version: ' '.repeat(33) } }),
    /target.*version/i,
  );
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, target: { ...target, build: 100_000 } }),
    /target.*build/i,
  );
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, target: { ...target, architecture: { name: 'AMD64' } } }),
    /target.*architecture/i,
  );
});

test('rejects invalid transport IPs, keys, fingerprints, usernames, and duplicates', () => {
  const validHostKeyBlob = 'AAAAC3NzaC1lZDI1NTE5AAAAIEJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC';
  const hostKeyWithTrailingBytes = Buffer.concat([
    Buffer.from(validHostKeyBlob, 'base64'),
    Buffer.from([0x00, 0x01]),
  ]).toString('base64');

  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, transport: { ...transport, tailscaleAddresses: [' 100.64.0.10'] } }),
    /tailscaleAddresses/i,
  );
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, transport: { ...transport, tailscaleAddresses: ['FD7A:115C:A1E0::10'] } }),
    /tailscaleAddresses/i,
  );
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, transport: { ...transport, sshUsername: 'Administrator' } }),
    /sshUsername/i,
  );
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, transport: { ...transport, sshHostKeys: ['ssh-ed25519 not-base64!'] } }),
    /sshHostKeys/i,
  );
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, transport: { ...transport, sshHostKeys: ['ssh-ed25519 AAAA\ncomment'] } }),
    /sshHostKeys/i,
  );
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, transport: { ...transport, sshHostKeys: ['ssh-ed25519 AAAAB3NzaC1yc2EAAAAgQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI='] } }),
    /sshHostKeys/i,
  );
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, transport: { ...transport, sshHostKeys: ['ssh-ed25519 AAAA'] } }),
    /sshHostKeys/i,
  );
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, transport: { ...transport, sshHostKeys: ['ssh-ed25519 /////w=='] } }),
    /sshHostKeys/i,
  );
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, transport: { ...transport, sshHostKeys: [`ssh-ed25519 ${hostKeyWithTrailingBytes}`] } }),
    /sshHostKeys/i,
  );
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, transport: { ...transport, sshHostKeyFingerprints: ['SHA256:not-a-fingerprint'] } }),
    /sshHostKeyFingerprints/i,
  );
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, transport: { ...transport, tailscaleAddresses: ['100.64.0.10', '100.64.0.10'] } }),
    /tailscaleAddresses.*duplicates/i,
  );
});

test('allows public ssh host keys while rejecting nested private keys', () => {
  assert.doesNotThrow(() => validateDeviceRecord({ ...validWindowsRecord, transport }));
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, transport: { ...transport, privateKey: 'forbidden' } }),
    /secret field is forbidden: privateKey/i,
  );
});

test('validates and freezes a Windows device record', () => {
  const result = validateDeviceRecord(validWindowsRecord);

  assert.deepEqual(result, validWindowsRecord);
  assert.notEqual(result, validWindowsRecord);
  assert.notEqual(result.capabilities, validWindowsRecord.capabilities);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.capabilities));
});

test('rejects a device record with a password field', () => {
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, password: 'not-allowed' }),
    /secret field is forbidden: password/i,
  );
});

test('rejects a nested secret-shaped field', () => {
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, transport: { token: 'not-allowed' } }),
    /secret field is forbidden: token/i,
  );
});

test('rejects object capabilities so mutable nested data cannot persist', () => {
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, capabilities: [{ name: 'ssh' }] }),
    /capabilities.*strings/i,
  );
});

test('rejects non-object device records', () => {
  assert.throws(() => validateDeviceRecord([]), {
    name: 'TypeError',
    message: 'device record must be an object',
  });
});

test('rejects a device record with an invalid required field', () => {
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, id: 'device_018f' }),
    /id/i,
  );
});

test('rejects a whitespace-only display name', () => {
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, displayName: ' \t ' }),
    /displayName.*non-empty/i,
  );
});

test('rejects a non-ISO timestamp that Date.parse accepts', () => {
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, updatedAt: '0' }),
    /updatedAt.*ISO/i,
  );
});
