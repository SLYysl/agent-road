import assert from 'node:assert/strict';
import { access, mkdir, mkdtemp, readFile, rm, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { DeviceRegistry } from '../src/storage/device-registry.mjs';

const device = {
  id: 'dev_abc123',
  displayName: 'New Windows PC',
  controllerPlatform: 'darwin',
  targetPlatform: 'windows',
  status: 'ENROLLING',
  capabilities: [],
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

async function createRegistry(t) {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-device-registry-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return new DeviceRegistry(join(directory, 'devices.json'));
}

function lockRecord(overrides = {}) {
  return JSON.stringify({
    owner: 'other-owner',
    pid: process.pid,
    createdAt: new Date().toISOString(),
    ...overrides,
  });
}

test('adds a device and lists mutable clones', async (t) => {
  const registry = await createRegistry(t);

  const added = await registry.add(device);
  added.capabilities.push('ssh');
  const listed = await registry.list();

  assert.deepEqual(listed, [device]);
  assert.notEqual(listed[0], added);
  assert.notEqual(listed[0].capabilities, added.capabilities);
});

test('gets a device by id or null when absent', async (t) => {
  const registry = await createRegistry(t);
  await registry.add(device);

  assert.deepEqual(await registry.get(device.id), device);
  assert.equal(await registry.get('dev_missing'), null);
});

test('updates a device status and timestamp', async (t) => {
  const registry = await createRegistry(t);
  await registry.add(device);

  const updated = await registry.updateStatus(
    device.id,
    'CONNECTED_SSH_ONLY',
    '2026-07-26T01:00:00.000Z',
  );

  assert.deepEqual(updated, {
    ...device,
    status: 'CONNECTED_SSH_ONLY',
    updatedAt: '2026-07-26T01:00:00.000Z',
  });
  assert.deepEqual(await registry.get(device.id), updated);
});

test('rejects duplicate device ids', async (t) => {
  const registry = await createRegistry(t);
  await registry.add(device);

  await assert.rejects(registry.add(device), new Error(`device already exists: ${device.id}`));
});

test('rejects status updates for missing devices', async (t) => {
  const registry = await createRegistry(t);

  await assert.rejects(
    registry.updateStatus(device.id, 'CONNECTED_SSH_ONLY', '2026-07-26T01:00:00.000Z'),
    new Error(`device not found: ${device.id}`),
  );
});

test('snapshots nested metadata before an awaited add', async (t) => {
  const registry = await createRegistry(t);
  const input = {
    ...device,
    target: { ...target },
    transport: { ...transport, tailscaleAddresses: [...transport.tailscaleAddresses] },
  };
  const lockPath = `${registry.path}.lock`;
  await writeFile(lockPath, lockRecord({ owner: 'held-owner' }));
  const adding = registry.add(input);
  input.transport.tailscaleAddresses.push('100.64.0.11');
  input.target.edition = 'Mutated';
  await new Promise((resolve) => setTimeout(resolve, 25));
  await rm(lockPath);

  assert.deepEqual(await adding, { ...device, target, transport });
  assert.deepEqual(await registry.get(device.id), { ...device, target, transport });
});

test('replaces an existing device and returns a mutable clone', async (t) => {
  const registry = await createRegistry(t);
  await registry.add(device);
  const replacement = {
    ...device,
    status: 'CONNECTED_SSH_ONLY',
    updatedAt: '2026-07-26T01:00:00.000Z',
    target,
    transport,
  };

  const replaced = await registry.replace(replacement);
  replaced.transport.tailscaleAddresses.push('100.64.0.11');

  assert.deepEqual(await registry.get(device.id), replacement);
});

test('rejects a replacement for a missing device', async (t) => {
  const registry = await createRegistry(t);

  await assert.rejects(registry.replace(device), new Error(`device not found: ${device.id}`));
});

test('snapshots nested metadata before an awaited replace', async (t) => {
  const registry = await createRegistry(t);
  await registry.add(device);
  const replacement = {
    ...device,
    status: 'CONNECTED_SSH_ONLY',
    updatedAt: '2026-07-26T01:00:00.000Z',
    target: { ...target },
    transport: { ...transport, tailscaleAddresses: [...transport.tailscaleAddresses] },
  };
  const lockPath = `${registry.path}.lock`;
  await writeFile(lockPath, lockRecord({ owner: 'held-owner' }));
  const replacing = registry.replace(replacement);
  replacement.target.edition = 'Mutated';
  replacement.transport.tailscaleAddresses.push('100.64.0.11');
  await new Promise((resolve) => setTimeout(resolve, 25));
  await rm(lockPath);

  assert.deepEqual(await replacing, {
    ...device,
    status: 'CONNECTED_SSH_ONLY',
    updatedAt: '2026-07-26T01:00:00.000Z',
    target,
    transport,
  });
});

test('serializes a replace with a concurrent add', async (t) => {
  const registry = await createRegistry(t);
  await registry.add(device);
  const second = { ...device, id: 'dev_def456', displayName: 'Second Windows PC' };
  const replacement = {
    ...device,
    status: 'CONNECTED_SSH_ONLY',
    updatedAt: '2026-07-26T01:00:00.000Z',
  };

  await Promise.all([registry.replace(replacement), registry.add(second)]);

  assert.deepEqual(await registry.get(device.id), replacement);
  assert.deepEqual(await registry.get(second.id), second);
});

test('retains both devices from concurrent adds', async (t) => {
  const registry = await createRegistry(t);
  const second = { ...device, id: 'dev_def456', displayName: 'Second Windows PC' };

  await Promise.all([registry.add(device), registry.add(second)]);

  assert.deepEqual(
    (await registry.list()).map(({ id }) => id).sort(),
    [device.id, second.id].sort(),
  );
});

test('allows exactly one concurrent add for a duplicate id', async (t) => {
  const registry = await createRegistry(t);

  const results = await Promise.allSettled([registry.add(device), registry.add(device)]);

  assert.equal(results.filter(({ status }) => status === 'fulfilled').length, 1);
  assert.equal(results.filter(({ status }) => status === 'rejected').length, 1);
  assert.equal(results.find(({ status }) => status === 'rejected').reason.message, `device already exists: ${device.id}`);
});

test('does not steal an old lock held by a live owner', async (t) => {
  const registry = await createRegistry(t);
  const lockPath = `${registry.path}.lock`;
  const staleTime = new Date(Date.now() - 60_000);
  await writeFile(lockPath, lockRecord({ createdAt: staleTime.toISOString() }));
  await utimes(lockPath, staleTime, staleTime);

  await assert.rejects(registry.add(device), /device registry is locked/);
  await access(lockPath);
});

test('leaves an abandoned lock untouched when concurrent contenders observe it', async (t) => {
  const registry = await createRegistry(t);
  const lockPath = `${registry.path}.lock`;
  const abandoned = lockRecord({ owner: 'dead-owner', pid: 999_999_999 });
  await writeFile(lockPath, abandoned);

  const results = await Promise.allSettled([
    registry.add(device),
    new DeviceRegistry(registry.path).add({ ...device, id: 'dev_def456' }),
  ]);

  assert.deepEqual(results.map(({ status }) => status), ['rejected', 'rejected']);
  assert.match(results[0].reason.message, /owner=dead-owner, pid=999999999 \(dead\)/);
  assert.equal(await readFile(lockPath, 'utf8'), abandoned);
});

test('leaves a stale corrupt lock untouched', async (t) => {
  const registry = await createRegistry(t);
  const lockPath = `${registry.path}.lock`;
  const corrupt = '{ corrupt lock';
  const staleTime = new Date(Date.now() - 60_000);
  await writeFile(lockPath, corrupt);
  await utimes(lockPath, staleTime, staleTime);

  await assert.rejects(registry.add(device), /device registry is locked/);
  assert.equal(await readFile(lockPath, 'utf8'), corrupt);
});

test('does not remove a lock whose owner changed during an operation', async (t) => {
  const registry = await createRegistry(t);
  const lockPath = `${registry.path}.lock`;
  const list = registry.list.bind(registry);
  registry.list = async () => {
    await writeFile(lockPath, lockRecord({ owner: 'replacement-owner' }));
    return list();
  };

  await registry.add(device);

  assert.equal(JSON.parse(await readFile(lockPath, 'utf8')).owner, 'replacement-owner');
});

test('preserves a registry operation error when lock cleanup fails', async (t) => {
  const registry = await createRegistry(t);
  const lockPath = `${registry.path}.lock`;
  const primaryError = new Error('registry operation failed');
  registry.list = async () => {
    await rm(lockPath);
    await mkdir(lockPath);
    throw primaryError;
  };

  await assert.rejects(registry.add(device), (error) => error === primaryError);
});
