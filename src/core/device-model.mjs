import { isIP } from 'node:net';

export const DEVICE_STATUSES = Object.freeze([
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

const SECRET_FIELD_PATTERN = /password|secret|token|private.?key|credential/i;
const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/;
const PLATFORMS = new Set(['darwin', 'windows']);
const DEVICE_FIELDS = new Set([
  'id',
  'displayName',
  'controllerPlatform',
  'targetPlatform',
  'status',
  'capabilities',
  'createdAt',
  'updatedAt',
  'target',
  'transport',
]);
const TARGET_FIELDS = new Set(['version', 'build', 'edition', 'architecture']);
const TRANSPORT_FIELDS = new Set([
  'tailscaleAddresses',
  'sshUsername',
  'sshHostKeys',
  'sshHostKeyFingerprints',
]);
const MAX_WINDOWS_BUILD = 99_999;
const MAX_TARGET_VERSION_LENGTH = 32;
const MAX_TARGET_EDITION_LENGTH = 64;
const MAX_TARGET_ARCHITECTURE_LENGTH = 16;
const MAX_TRANSPORT_VALUES = 8;
const MAX_SSH_HOST_KEY_LENGTH = 1024;
const SSH_HOST_KEY_PATTERN = /^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})(?: ([^\s\r\n\x00-\x1F\x7F](?:[^\r\n\x00-\x1F\x7F]*[^\s\r\n\x00-\x1F\x7F])?))?$/;
const SSH_HOST_KEY_FINGERPRINT_PATTERN = /^SHA256:[A-Za-z0-9+/]{43}$/;
const SSH_ED25519_ALGORITHM = Buffer.from('ssh-ed25519');

function assertNoSecretFields(value, visited = new WeakSet()) {
  if (value === null || typeof value !== 'object' || visited.has(value)) {
    return;
  }

  visited.add(value);
  for (const key of Object.keys(value)) {
    if (SECRET_FIELD_PATTERN.test(key)) {
      throw new Error(`secret field is forbidden: ${key}`);
    }
    assertNoSecretFields(value[key], visited);
  }
}

function isCanonicalIsoTimestamp(value) {
  if (typeof value !== 'string') {
    return false;
  }

  const date = new Date(value);
  return !Number.isNaN(date.valueOf()) && date.toISOString() === value;
}

function assertExactObject(value, label, allowedFields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }

  for (const key of Object.keys(value)) {
    if (!allowedFields.has(key)) {
      throw new Error(`${label} contains unknown field: ${key}`);
    }
  }
}

function assertBoundedString(value, label, maxLength) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > maxLength
    || value !== value.trim()
    || /[\r\n\x00-\x1F\x7F]/.test(value)
  ) {
    throw new Error(`${label} must be a non-empty string up to ${maxLength} characters`);
  }
}

function validateTarget(target) {
  assertExactObject(target, 'device record target', TARGET_FIELDS);
  assertBoundedString(target.version, 'device record target version', MAX_TARGET_VERSION_LENGTH);
  assertBoundedString(target.edition, 'device record target edition', MAX_TARGET_EDITION_LENGTH);
  assertBoundedString(target.architecture, 'device record target architecture', MAX_TARGET_ARCHITECTURE_LENGTH);

  if (!Number.isInteger(target.build) || target.build < 0 || target.build > MAX_WINDOWS_BUILD) {
    throw new Error(`device record target build must be an integer from 0 to ${MAX_WINDOWS_BUILD}`);
  }

  return Object.freeze({
    version: target.version,
    build: target.build,
    edition: target.edition,
    architecture: target.architecture,
  });
}

function assertBoundedUniqueArray(value, label) {
  if (
    !Array.isArray(value)
    || value.length === 0
    || value.length > MAX_TRANSPORT_VALUES
  ) {
    throw new Error(`${label} must be a non-empty array with at most ${MAX_TRANSPORT_VALUES} values`);
  }
  if (new Set(value).size !== value.length) {
    throw new Error(`${label} must not contain duplicates`);
  }
}

function isCanonicalIpAddress(value) {
  if (typeof value !== 'string' || value !== value.trim()) {
    return false;
  }

  const family = isIP(value);
  if (family === 4) {
    return true;
  }
  if (family !== 6) {
    return false;
  }

  return new URL(`http://[${value}]/`).hostname === `[${value}]`;
}

function readSshString(blob, offset) {
  if (offset > blob.length - 4) {
    return null;
  }

  const length = blob.readUInt32BE(offset);
  const start = offset + 4;
  if (length > blob.length - start) {
    return null;
  }

  return { value: blob.subarray(start, start + length), nextOffset: start + length };
}

function isValidEd25519HostKey(blobBase64) {
  const blob = Buffer.from(blobBase64, 'base64');
  if (blob.toString('base64') !== blobBase64) {
    return false;
  }

  const algorithm = readSshString(blob, 0);
  if (algorithm === null || !algorithm.value.equals(SSH_ED25519_ALGORITHM)) {
    return false;
  }

  const publicKey = readSshString(blob, algorithm.nextOffset);
  return publicKey !== null && publicKey.value.length === 32 && publicKey.nextOffset === blob.length;
}

function validateTransport(transport) {
  assertExactObject(transport, 'device record transport', TRANSPORT_FIELDS);
  assertBoundedUniqueArray(transport.tailscaleAddresses, 'device record transport tailscaleAddresses');
  assertBoundedUniqueArray(transport.sshHostKeys, 'device record transport sshHostKeys');
  assertBoundedUniqueArray(transport.sshHostKeyFingerprints, 'device record transport sshHostKeyFingerprints');

  if (!transport.tailscaleAddresses.every(isCanonicalIpAddress)) {
    throw new Error('device record transport tailscaleAddresses must contain canonical IP addresses');
  }
  if (transport.sshUsername !== 'AgentRoad') {
    throw new Error('device record transport sshUsername must be AgentRoad');
  }
  if (!transport.sshHostKeys.every((hostKey) => {
    if (typeof hostKey !== 'string' || hostKey.length > MAX_SSH_HOST_KEY_LENGTH) {
      return false;
    }
    const match = SSH_HOST_KEY_PATTERN.exec(hostKey);
    return match !== null && isValidEd25519HostKey(match[1]);
  })) {
    throw new Error('device record transport sshHostKeys must contain valid ssh-ed25519 public keys');
  }
  if (!transport.sshHostKeyFingerprints.every((fingerprint) => (
    typeof fingerprint === 'string' && SSH_HOST_KEY_FINGERPRINT_PATTERN.test(fingerprint)
  ))) {
    throw new Error('device record transport sshHostKeyFingerprints must contain SHA256 fingerprints');
  }

  return Object.freeze({
    tailscaleAddresses: Object.freeze([...transport.tailscaleAddresses]),
    sshUsername: transport.sshUsername,
    sshHostKeys: Object.freeze([...transport.sshHostKeys]),
    sshHostKeyFingerprints: Object.freeze([...transport.sshHostKeyFingerprints]),
  });
}

export function validateDeviceRecord(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('device record must be an object');
  }

  assertNoSecretFields(input);
  assertExactObject(input, 'device record', DEVICE_FIELDS);

  if (typeof input.id !== 'string' || !DEVICE_ID_PATTERN.test(input.id)) {
    throw new Error('device record id must match /^dev_[a-z0-9]+$/');
  }

  if (typeof input.displayName !== 'string' || input.displayName.trim().length === 0) {
    throw new Error('device record displayName must be a non-empty string');
  }

  if (!PLATFORMS.has(input.controllerPlatform)) {
    throw new Error('device record controllerPlatform must be darwin or windows');
  }

  if (!PLATFORMS.has(input.targetPlatform)) {
    throw new Error('device record targetPlatform must be darwin or windows');
  }

  if (!DEVICE_STATUSES.includes(input.status)) {
    throw new Error('device record status must be a listed device status');
  }

  if (!Array.isArray(input.capabilities) || !input.capabilities.every((capability) => typeof capability === 'string')) {
    throw new Error('device record capabilities must be an array of strings');
  }

  for (const field of ['createdAt', 'updatedAt']) {
    if (!isCanonicalIsoTimestamp(input[field])) {
      throw new Error(`device record ${field} must be an ISO date`);
    }
  }

  const record = {
    id: input.id,
    displayName: input.displayName,
    controllerPlatform: input.controllerPlatform,
    targetPlatform: input.targetPlatform,
    status: input.status,
    capabilities: Object.freeze([...input.capabilities]),
    createdAt: input.createdAt,
    updatedAt: input.updatedAt,
  };

  if (Object.hasOwn(input, 'target')) {
    record.target = validateTarget(input.target);
  }
  if (Object.hasOwn(input, 'transport')) {
    record.transport = validateTransport(input.transport);
  }

  return Object.freeze(record);
}
