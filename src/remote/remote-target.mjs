import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { isProxy } from 'node:util/types';

import { validateDeviceRecord } from '../core/device-model.mjs';

const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/;
const MAX_DEVICE_ID_LENGTH = 64;
const READY_STATUSES = new Set(['CONNECTED_SSH_ONLY', 'READY']);
const REQUIRED_CAPABILITIES = Object.freeze(['ssh', 'sftp', 'admin-powershell']);
const DEPENDENCY_FIELDS = new Set(['registry', 'sshIdentity', 'knownHostsPath']);
const TARGET_FIELDS = new Set(['device', 'identity', 'knownHostsPath']);

function remoteError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function failInput() {
  throw remoteError('REMOTE_INPUT_INVALID');
}

function validateDeviceId(deviceId) {
  if (
    typeof deviceId !== 'string'
    || deviceId.length > MAX_DEVICE_ID_LENGTH
    || !DEVICE_ID_PATTERN.test(deviceId)
  ) failInput();
  return deviceId;
}

function snapshotExactObject(input, fields) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) failInput();

  const snapshot = {};
  for (const key of Object.getOwnPropertyNames(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!fields.has(key) || !descriptor || !Object.hasOwn(descriptor, 'value')) failInput();
    snapshot[key] = descriptor.value;
  }
  for (const field of fields) {
    if (!Object.hasOwn(snapshot, field)) failInput();
  }
  return snapshot;
}

function snapshotPureData(input, ancestors = new WeakSet()) {
  if (input === null || typeof input !== 'object') return input;
  if (isProxy(input) || ancestors.has(input) || Object.getOwnPropertySymbols(input).length !== 0) {
    failInput();
  }

  const isArray = Array.isArray(input);
  const prototype = Object.getPrototypeOf(input);
  if (
    (isArray && prototype !== Array.prototype)
    || (!isArray && prototype !== Object.prototype && prototype !== null)
  ) failInput();

  ancestors.add(input);
  try {
    if (isArray) {
      const names = Object.getOwnPropertyNames(input);
      const lengthDescriptor = Object.getOwnPropertyDescriptor(input, 'length');
      if (
        !lengthDescriptor
        || !Object.hasOwn(lengthDescriptor, 'value')
        || !Number.isSafeInteger(lengthDescriptor.value)
        || lengthDescriptor.value < 0
        || names.length !== lengthDescriptor.value + 1
      ) failInput();

      const snapshot = [];
      for (let index = 0; index < lengthDescriptor.value; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
        if (!descriptor || !Object.hasOwn(descriptor, 'value')) failInput();
        snapshot.push(snapshotPureData(descriptor.value, ancestors));
      }
      return snapshot;
    }

    const snapshot = Object.create(null);
    for (const key of Object.getOwnPropertyNames(input)) {
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) failInput();
      snapshot[key] = snapshotPureData(descriptor.value, ancestors);
    }
    return snapshot;
  } finally {
    ancestors.delete(input);
  }
}

function validateDependencies(input) {
  const dependencies = snapshotExactObject(input, DEPENDENCY_FIELDS);
  if (
    dependencies.registry === null
    || (typeof dependencies.registry !== 'object' && typeof dependencies.registry !== 'function')
    || typeof dependencies.registry.get !== 'function'
    || dependencies.sshIdentity === null
    || (typeof dependencies.sshIdentity !== 'object' && typeof dependencies.sshIdentity !== 'function')
    || typeof dependencies.sshIdentity.getExisting !== 'function'
    || typeof dependencies.knownHostsPath !== 'function'
  ) failInput();
  return dependencies;
}

function validateKnownHostsPath(path, deviceId, identity) {
  const deviceDirectory = dirname(identity.privateKeyPath);
  const devicesDirectory = dirname(deviceDirectory);
  const identityDirectory = dirname(devicesDirectory);
  const expectedPath = join(
    dirname(identityDirectory),
    'known-hosts',
    `agent-road-known-hosts-${deviceId}`,
  );
  if (
    typeof path !== 'string'
    || path.length === 0
    || path.includes('\0')
    || !isAbsolute(path)
    || resolve(path) !== path
    || basename(path) !== `agent-road-known-hosts-${deviceId}`
    || path !== expectedPath
  ) failInput();
  return path;
}

function validateReadyDevice(input, expectedDeviceId) {
  let device;
  try {
    device = validateDeviceRecord(snapshotPureData(input));
  } catch {
    throw remoteError('DEVICE_NOT_READY');
  }

  const transport = device.transport;
  if (
    (expectedDeviceId !== undefined && device.id !== expectedDeviceId)
    || !READY_STATUSES.has(device.status)
    || device.targetPlatform !== 'windows'
    || !REQUIRED_CAPABILITIES.every((capability) => device.capabilities.includes(capability))
    || transport === undefined
    || transport.sshUsername !== 'AgentRoad'
    || transport.sshHostKeys.length !== transport.sshHostKeyFingerprints.length
  ) {
    throw remoteError('DEVICE_NOT_READY');
  }
  return device;
}

function validateIdentity(input, deviceId) {
  let identity;
  try {
    identity = snapshotExactObject(
      input,
      new Set(['privateKeyPath', 'publicKeyPath', 'publicKey']),
    );
  } catch {
    throw remoteError('DEVICE_NOT_READY');
  }
  const deviceDirectory = typeof identity.privateKeyPath === 'string'
    ? dirname(identity.privateKeyPath)
    : '';
  const devicesDirectory = dirname(deviceDirectory);
  const identityDirectory = dirname(devicesDirectory);
  if (
    typeof identity.privateKeyPath !== 'string'
    || identity.privateKeyPath.includes('\0')
    || !isAbsolute(identity.privateKeyPath)
    || resolve(identity.privateKeyPath) !== identity.privateKeyPath
    || basename(identity.privateKeyPath) !== 'id_ed25519'
    || basename(deviceDirectory) !== deviceId
    || basename(devicesDirectory) !== 'devices'
    || basename(identityDirectory) !== 'identity'
    || identity.publicKeyPath !== `${identity.privateKeyPath}.pub`
    || typeof identity.publicKey !== 'string'
    || identity.publicKey.length === 0
    || /[\r\n\0]/.test(identity.publicKey)
  ) throw remoteError('DEVICE_NOT_READY');
  return Object.freeze(identity);
}

export async function loadRemoteTarget(deviceId, inputDependencies) {
  const id = validateDeviceId(deviceId);
  const dependencies = validateDependencies(inputDependencies);
  let registered;
  try {
    registered = await dependencies.registry.get(id);
  } catch {
    throw remoteError('DEVICE_NOT_READY');
  }
  if (registered === null || registered === undefined) {
    throw remoteError('DEVICE_NOT_FOUND');
  }
  const device = validateReadyDevice(registered, id);

  let existingIdentity;
  try {
    existingIdentity = await dependencies.sshIdentity.getExisting(id);
  } catch (error) {
    if (error?.code === 'SSH_IDENTITY_BUSY') throw remoteError('DEVICE_BUSY');
    throw remoteError('DEVICE_NOT_READY');
  }
  const identity = validateIdentity(existingIdentity, id);
  let knownHostsPath;
  try {
    knownHostsPath = validateKnownHostsPath(dependencies.knownHostsPath(id), id, identity);
  } catch {
    failInput();
  }
  if (identity.privateKeyPath === knownHostsPath) failInput();
  return Object.freeze({ device, identity, knownHostsPath });
}

export function trustedInput(inputTarget, runProcess) {
  if (typeof runProcess !== 'function') failInput();
  let target;
  let device;
  let identity;
  let knownHostsPath;
  try {
    if (!Object.isFrozen(inputTarget)) failInput();
    target = snapshotExactObject(inputTarget, TARGET_FIELDS);
    if (
      !Object.isFrozen(target.device)
      || !Object.isFrozen(target.identity)
    ) failInput();
    device = validateReadyDevice(target.device);
    identity = validateIdentity(target.identity, device.id);
    knownHostsPath = validateKnownHostsPath(target.knownHostsPath, device.id, identity);
  } catch {
    failInput();
  }

  return Object.freeze({
    deviceId: device.id,
    addresses: device.transport.tailscaleAddresses,
    hostKeys: device.transport.sshHostKeys,
    fingerprints: device.transport.sshHostKeyFingerprints,
    privateKeyPath: identity.privateKeyPath,
    knownHostsPath,
    runProcess,
  });
}
