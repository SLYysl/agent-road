import { randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import { validateDeviceRecord } from '../core/device-model.mjs';
import { buildPowerShellEnrollmentCommand } from './powershell-command.mjs';

const ENROLLMENT_TTL_MS = 10 * 60 * 1000;
const MIN_ENROLLMENT_TTL_MS = 5 * 60 * 1000;
const MAX_ENROLLMENT_TTL_MS = 30 * 60 * 1000;
const PREFLIGHT_TOKEN = 'A'.repeat(43);

function snapshotCommandPayload(value) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
    || Object.getOwnPropertySymbols(value).length !== 0
  ) throw new TypeError('commandPayload must be an object');
  const snapshot = {};
  for (const key of Object.getOwnPropertyNames(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError('commandPayload must contain only data properties');
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function requireOneLineCommand(value) {
  if (typeof value !== 'string' || value.length === 0 || /[\r\n\0]/.test(value)) {
    throw new TypeError('enrollment command must be one line');
  }
  return value;
}

async function revokeAndRethrow(tokenStore, token, error) {
  try {
    await tokenStore.revoke(token);
  } catch (revokeError) {
    throw new AggregateError(
      [error, revokeError],
      'failed to add device and revoke enrollment token',
    );
  }
  throw error;
}

export async function createEnrollment({
  displayName,
  controllerUrl,
  buildCommand = buildPowerShellEnrollmentCommand,
  commandPayload,
  tokenTtlMs = ENROLLMENT_TTL_MS,
  now = () => new Date(),
  createDeviceId = () => `dev_${randomUUID().replaceAll('-', '')}`,
  registry,
  tokenStore,
}) {
  if (
    !Number.isInteger(tokenTtlMs)
    || tokenTtlMs < MIN_ENROLLMENT_TTL_MS
    || tokenTtlMs > MAX_ENROLLMENT_TTL_MS
  ) {
    throw new TypeError(`tokenTtlMs must be an integer from ${MIN_ENROLLMENT_TTL_MS} to ${MAX_ENROLLMENT_TTL_MS}`);
  }
  if (typeof buildCommand !== 'function') {
    throw new TypeError('buildCommand must be a function');
  }
  const payload = snapshotCommandPayload(commandPayload === undefined
    ? { controllerUrl }
    : commandPayload);
  const createdAt = now().toISOString();
  const deviceId = createDeviceId();
  const device = validateDeviceRecord({
    id: deviceId,
    displayName,
    controllerPlatform: 'darwin',
    targetPlatform: 'windows',
    status: 'ENROLLING',
    capabilities: [],
    createdAt,
    updatedAt: createdAt,
  });
  requireOneLineCommand(buildCommand({
    ...payload,
    deviceId,
    token: PREFLIGHT_TOKEN,
  }));

  const { token, expiresAt } = await tokenStore.issue({ deviceId, ttlMs: tokenTtlMs });
  let command;
  try {
    command = requireOneLineCommand(buildCommand({ ...payload, deviceId, token }));
  } catch (error) {
    await revokeAndRethrow(tokenStore, token, error);
  }
  try {
    await registry.add(device);
  } catch (addError) {
    let persistedDevice;
    try {
      persistedDevice = await registry.get(deviceId);
    } catch (reconciliationError) {
      throw new AggregateError(
        [addError, reconciliationError],
        'ambiguous enrollment persistence after registry add failure',
      );
    }
    if (!isDeepStrictEqual(persistedDevice, device)) {
      await revokeAndRethrow(tokenStore, token, addError);
    }
  }

  return {
    deviceId,
    device,
    expiresAt,
    command,
    revoke: () => tokenStore.revoke(token),
  };
}
