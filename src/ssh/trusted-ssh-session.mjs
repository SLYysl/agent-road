import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  rename,
  rm,
} from 'node:fs/promises';
import { constants } from 'node:fs';
import { isIP } from 'node:net';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { isProxy } from 'node:util/types';

import { withFileLock } from '../storage/file-lock.mjs';
import { createConnectionReuse } from './connection-reuse.mjs';

const SSH_PATH = '/usr/bin/ssh';
const SCP_PATH = '/usr/bin/scp';
const SSH_KEYGEN_PATH = '/usr/bin/ssh-keygen';
const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/;
const FINGERPRINT_PATTERN = /^SHA256:[A-Za-z0-9+/]{43}$/;
const HOST_KEY_PATTERN = /^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})(?: ([^\s\r\n\x00-\x1f\x7f](?:[^\r\n\x00-\x1f\x7f]*[^\s\r\n\x00-\x1f\x7f])?))?$/;
const SSH_ALGORITHM = Buffer.from('ssh-ed25519');
const MAX_KEYS = 8;
const MAX_HOST_KEY_BYTES = 1024;
const MAX_PRIVATE_KEY_BYTES = 64 * 1024;
const MAX_PROCESS_ARGS = 128;
const MAX_PROCESS_ARG_BYTES = 64 * 1024;
const MAX_PROCESS_ARGV_BYTES = 256 * 1024;
const MAX_PROCESS_STDIN_BYTES = 64 * 1024;
const DEFAULT_PROCESS_TIMEOUT_MS = 20_000;
const DEFAULT_PROCESS_OUTPUT_BYTES = 16 * 1024;
const MAX_PROCESS_TIMEOUT_MS = 31 * 60 * 1_000;
const MAX_PROCESS_OUTPUT_BYTES = 16 * 1024 * 1024;
const SSH_SESSION_LOCK_TIMEOUT_MS = 15 * 60 * 1_000;
const MIN_SSH_SESSION_LOCK_TIMEOUT_MS = 1_000;
const SENSITIVE_CLEANUP_ATTEMPTS = 3;
const SENSITIVE_CLEANUP_RETRY_MS = 10;
const INPUT_FIELDS = new Set([
  'deviceId',
  'addresses',
  'hostKeys',
  'fingerprints',
  'privateKeyPath',
  'knownHostsPath',
  'runProcess',
]);
const PROCESS_OPTION_FIELDS = new Set(['timeoutMs', 'maxOutputBytes', 'stdinText']);
const TRUSTED_SSH_SESSION_LOCK_ERRORS = new WeakSet();

function verifierError(code = 'SSH_VERIFY_FAILED') {
  const error = new Error(code);
  error.code = code;
  return error;
}

function trustedSshSessionLockError() {
  const error = verifierError('TRUSTED_SSH_SESSION_LOCKED');
  TRUSTED_SSH_SESSION_LOCK_ERRORS.add(error);
  return error;
}

function isGenericFileLockTimeout(error, name, path) {
  if (
    error === null
    || typeof error !== 'object'
    || Object.getPrototypeOf(error) !== Error.prototype
  ) return false;
  const message = Object.getOwnPropertyDescriptor(error, 'message');
  const prefix = `${name} is locked: ${path} (`;
  return Boolean(
    message
    && Object.hasOwn(message, 'value')
    && typeof message.value === 'string'
    && message.value.startsWith(prefix)
    && message.value.endsWith(')'),
  );
}

export function isTrustedSshSessionLockError(error) {
  return (
    error !== null
    && (typeof error === 'object' || typeof error === 'function')
    && TRUSTED_SSH_SESSION_LOCK_ERRORS.has(error)
  );
}

function cleanupFailure(primaryError) {
  const error = verifierError('SSH_VERIFY_CLEANUP_FAILED');
  if (typeof primaryError?.code === 'string' && /^SSH_VERIFY_[A-Z_]+$/.test(primaryError.code)) {
    error.primaryCode = primaryError.code;
  }
  return error;
}

function failInput() {
  throw verifierError('SSH_VERIFY_INPUT_INVALID');
}

function sessionOptions(input = {}) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
    || Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) failInput();
  const names = Object.getOwnPropertyNames(input);
  if (names.some((name) => !['lockTimeoutMs', 'reuseConnection'].includes(name))) failInput();
  let lockTimeoutMs = SSH_SESSION_LOCK_TIMEOUT_MS;
  if (names.includes('lockTimeoutMs')) {
    const descriptor = Object.getOwnPropertyDescriptor(input, 'lockTimeoutMs');
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) failInput();
    lockTimeoutMs = descriptor.value;
  }
  if (
    !Number.isSafeInteger(lockTimeoutMs)
    || lockTimeoutMs < MIN_SSH_SESSION_LOCK_TIMEOUT_MS
    || lockTimeoutMs > SSH_SESSION_LOCK_TIMEOUT_MS
  ) failInput();
  let reuseConnection = false;
  if (names.includes('reuseConnection')) {
    const descriptor = Object.getOwnPropertyDescriptor(input, 'reuseConnection');
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'boolean') failInput();
    reuseConnection = descriptor.value;
  }
  return Object.freeze({ lockTimeoutMs, reuseConnection });
}

function sshString(bytes, offset) {
  if (offset > bytes.length - 4) return null;
  const length = bytes.readUInt32BE(offset);
  const start = offset + 4;
  if (length > bytes.length - start) return null;
  return { bytes: bytes.subarray(start, start + length), next: start + length };
}

function validHostKey(line) {
  if (typeof line !== 'string' || Buffer.byteLength(line) > MAX_HOST_KEY_BYTES) return false;
  const match = HOST_KEY_PATTERN.exec(line);
  if (!match) return false;
  const blob = Buffer.from(match[1], 'base64');
  if (blob.length === 0 || blob.toString('base64') !== match[1]) return false;
  const algorithm = sshString(blob, 0);
  const key = algorithm && sshString(blob, algorithm.next);
  return Boolean(
    algorithm
    && key
    && algorithm.bytes.equals(SSH_ALGORITHM)
    && key.bytes.length === 32
    && key.next === blob.length,
  );
}

function canonicalAddress(value) {
  if (typeof value !== 'string' || value !== value.trim()) return false;
  const family = isIP(value);
  if (family === 4) return true;
  return family === 6 && new URL(`http://[${value}]/`).hostname === `[${value}]`;
}

function snapshotInput(input) {
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
    if (!INPUT_FIELDS.has(key) || !descriptor || !Object.hasOwn(descriptor, 'value')) failInput();
    snapshot[key] = descriptor.value;
  }
  for (const required of INPUT_FIELDS) {
    if (!Object.hasOwn(snapshot, required)) failInput();
  }
  return snapshot;
}

function snapshotArray(value, maximum, validator) {
  if (!Array.isArray(value) || value.length === 0 || value.length > maximum) failInput();
  const snapshot = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !validator(descriptor.value)) failInput();
    snapshot.push(descriptor.value);
  }
  if (new Set(snapshot).size !== snapshot.length) failInput();
  return snapshot;
}

function validateInputs({
  deviceId,
  addresses,
  hostKeys,
  fingerprints,
  privateKeyPath,
  knownHostsPath,
  runProcess,
}) {
  if (
    typeof deviceId !== 'string'
    || deviceId.length > 64
    || !DEVICE_ID_PATTERN.test(deviceId)
    || typeof runProcess !== 'function'
  ) failInput();

  const addressSnapshot = snapshotArray(addresses, 8, canonicalAddress);
  const hostKeySnapshot = snapshotArray(hostKeys, MAX_KEYS, validHostKey);
  const fingerprintSnapshot = snapshotArray(
    fingerprints,
    MAX_KEYS,
    (value) => typeof value === 'string' && FINGERPRINT_PATTERN.test(value),
  );
  if (fingerprintSnapshot.length !== hostKeySnapshot.length) failInput();
  for (const path of [privateKeyPath, knownHostsPath]) {
    if (
      typeof path !== 'string'
      || path.length === 0
      || path.includes('\0')
      || !isAbsolute(path)
      || resolve(path) !== path
    ) failInput();
  }
  if (basename(privateKeyPath) !== 'id_ed25519' || basename(dirname(privateKeyPath)) !== deviceId) {
    failInput();
  }
  if (basename(knownHostsPath) !== `agent-road-known-hosts-${deviceId}` || knownHostsPath === privateKeyPath) {
    failInput();
  }

  return {
    deviceId,
    addresses: addressSnapshot,
    hostKeys: hostKeySnapshot,
    fingerprints: fingerprintSnapshot,
    privateKeyPath,
    knownHostsPath,
    runProcess,
  };
}

function sameStats(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.nlink === right.nlink
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

function trustedOwner(stats) {
  const uid = process.getuid();
  return stats.uid === uid || stats.uid === 0;
}

async function validateDirectoryChain(start) {
  let path = start;
  let immediate = true;
  while (true) {
    const stats = await lstat(path);
    const mode = stats.mode & 0o7777;
    if (
      stats.isSymbolicLink()
      || !stats.isDirectory()
      || !trustedOwner(stats)
      || (immediate && (mode & 0o022) !== 0)
      || (!immediate && (mode & 0o022) !== 0 && !(stats.uid === 0 && (mode & 0o1000) !== 0))
    ) throw verifierError('SSH_VERIFY_UNSAFE_PATH');
    const parent = dirname(path);
    if (parent === path) return;
    path = parent;
    immediate = false;
  }
}

async function ensureSecureDirectory(path) {
  const missing = [];
  let existing = path;
  while (true) {
    try {
      await lstat(existing);
      break;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      missing.push(existing);
      const parent = dirname(existing);
      if (parent === existing) throw verifierError('SSH_VERIFY_UNSAFE_PATH');
      existing = parent;
    }
  }
  await validateDirectoryChain(existing);
  for (const directory of missing.reverse()) {
    await mkdir(directory, { mode: 0o700 });
    await chmod(directory, 0o700);
  }
  await validateDirectoryChain(path);
}

async function openSafeFile(path, { required = true, minBytes = 1, maxBytes = Infinity } = {}) {
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stats = await file.stat();
    if (
      !stats.isFile()
      || stats.nlink !== 1
      || !trustedOwner(stats)
      || (stats.mode & 0o077) !== 0
      || stats.size < minBytes
      || stats.size > maxBytes
    ) throw verifierError('SSH_VERIFY_UNSAFE_PATH');
    return { file, stats };
  } catch (error) {
    if (file) await file.close().catch(() => {});
    if (!required && error.code === 'ENOENT') return null;
    if (error.code === 'ELOOP') throw verifierError('SSH_VERIFY_UNSAFE_PATH');
    throw error;
  }
}

async function stableBytes(entry) {
  const before = await entry.file.stat();
  if (!sameStats(entry.stats, before)) throw verifierError('SSH_VERIFY_UNSAFE_PATH');
  const first = await entry.file.readFile();
  const middle = await entry.file.stat();
  entry.file.seek?.(0, 0);
  const second = Buffer.alloc(middle.size);
  let offset = 0;
  while (offset < second.length) {
    const part = await entry.file.read(second, offset, second.length - offset, offset);
    if (part.bytesRead === 0) break;
    offset += part.bytesRead;
  }
  const after = await entry.file.stat();
  if (!sameStats(before, middle) || !sameStats(middle, after) || offset !== second.length || !first.equals(second)) {
    throw verifierError('SSH_VERIFY_UNSAFE_PATH');
  }
  return first;
}

async function validatePrivateKey(path) {
  const parentStats = await lstat(dirname(path));
  if (parentStats.isSymbolicLink() || !parentStats.isDirectory()) {
    throw verifierError('SSH_VERIFY_UNSAFE_PATH');
  }
  const entry = await openSafeFile(path, { maxBytes: MAX_PRIVATE_KEY_BYTES });
  try {
    const bytes = await stableBytes(entry);
    return { entry, bytes, digest: createHash('sha256').update(bytes).digest() };
  } catch (error) {
    await entry.file.close().catch(() => {});
    throw error;
  }
}

async function assertPrivateUnchanged(path, snapshot) {
  const current = await openSafeFile(path, { maxBytes: MAX_PRIVATE_KEY_BYTES });
  try {
    if (current.stats.dev !== snapshot.entry.stats.dev || current.stats.ino !== snapshot.entry.stats.ino) {
      throw verifierError('SSH_VERIFY_UNSAFE_PATH');
    }
    const digest = createHash('sha256').update(await stableBytes(current)).digest();
    if (!timingSafeEqual(digest, snapshot.digest)) throw verifierError('SSH_VERIFY_UNSAFE_PATH');
  } finally {
    await current.file.close().catch(() => {});
  }
}

async function validateKnownHosts(path, expectedContent) {
  const entry = await openSafeFile(path, { maxBytes: 64 * 1024 });
  try {
    const bytes = await stableBytes(entry);
    if (!bytes.equals(Buffer.from(expectedContent))) throw verifierError('SSH_VERIFY_UNSAFE_PATH');
    return { entry, bytes, digest: createHash('sha256').update(bytes).digest() };
  } catch (error) {
    await entry.file.close().catch(() => {});
    throw error;
  }
}

async function assertKnownHostsUnchanged(path, snapshot) {
  const current = await openSafeFile(path, { maxBytes: 64 * 1024 });
  try {
    if (current.stats.dev !== snapshot.entry.stats.dev || current.stats.ino !== snapshot.entry.stats.ino) {
      throw verifierError('SSH_VERIFY_UNSAFE_PATH');
    }
    const digest = createHash('sha256').update(await stableBytes(current)).digest();
    if (!timingSafeEqual(digest, snapshot.digest)) throw verifierError('SSH_VERIFY_UNSAFE_PATH');
  } finally {
    await current.file.close().catch(() => {});
  }
}

async function writeSnapshotFile(path, bytes) {
  const file = await open(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    await file.writeFile(bytes);
    await file.sync();
  } finally {
    await file.close();
  }
}

async function createSessionSnapshots(config, privateSnapshot, knownHostsSnapshot) {
  const directory = join(
    dirname(config.knownHostsPath),
    `.verify-${config.deviceId}-${randomUUID()}`,
  );
  await mkdir(directory, { mode: 0o700 });
  await validateDirectoryChain(directory);
  const privateKeyPath = join(directory, 'id_ed25519');
  const knownHostsPath = join(directory, 'known_hosts');
  let sessionPrivate;
  let sessionKnownHosts;
  try {
    await writeSnapshotFile(privateKeyPath, privateSnapshot.bytes);
    await writeSnapshotFile(knownHostsPath, knownHostsSnapshot.bytes);
    sessionPrivate = await validatePrivateKey(privateKeyPath);
    sessionKnownHosts = await validateKnownHosts(
      knownHostsPath,
      knownHostsSnapshot.bytes.toString('utf8'),
    );
    return {
      directory,
      privateKeyPath,
      knownHostsPath,
      privateSnapshot: sessionPrivate,
      knownHostsSnapshot: sessionKnownHosts,
    };
  } catch (error) {
    await closeSessionSnapshots({
      directory,
      privateSnapshot: sessionPrivate,
      knownHostsSnapshot: sessionKnownHosts,
    }, error);
    throw error;
  }
}

async function retrySensitiveRemoval(path) {
  let lastError;
  for (let attempt = 0; attempt < SENSITIVE_CLEANUP_ATTEMPTS; attempt += 1) {
    try {
      await rm(path, { recursive: true, force: true });
      return;
    } catch (error) {
      lastError = error;
      if (attempt + 1 < SENSITIVE_CLEANUP_ATTEMPTS) {
        await new Promise((resolveDelay) => setTimeout(resolveDelay, SENSITIVE_CLEANUP_RETRY_MS));
      }
    }
  }
  throw lastError;
}

async function closeSessionSnapshots(session, primaryError) {
  if (!session) return;
  let failed = false;
  for (const snapshot of [session.privateSnapshot, session.knownHostsSnapshot].filter(Boolean)) {
    try { await snapshot.entry.file.close(); } catch (error) {
      failed = true;
    }
  }
  try { await retrySensitiveRemoval(session.directory); } catch {
    failed = true;
  }
  if (failed) throw cleanupFailure(primaryError);
}

function parseFingerprintOutput(result) {
  if (
    !result
    || result.exitCode !== 0
    || result.signal !== null
    || result.stderr !== ''
    || typeof result.stdout !== 'string'
  ) throw verifierError();
  const line = result.stdout.endsWith('\n') ? result.stdout.slice(0, -1) : result.stdout;
  if (line.includes('\n') || /[\r\x00-\x08\x0b-\x1f\x7f]/.test(line)) throw verifierError();
  const match = /^256 (SHA256:[A-Za-z0-9+/]{43})(?: [^\r\n]*)? \(ED25519\)$/.exec(line);
  if (!match) throw verifierError();
  return match[1];
}

async function verifyFingerprints(hostKeys, expected, runProcess) {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-host-key-'));
  await chmod(directory, 0o700);
  let primaryError;
  try {
    for (let index = 0; index < hostKeys.length; index += 1) {
      const keyPath = join(directory, `host-${index}.pub`);
      const file = await open(
        keyPath,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
      try {
        await file.writeFile(`${hostKeys[index]}\n`);
        await file.sync();
      } finally {
        await file.close();
      }
      let result;
      try {
        result = await runProcess(SSH_KEYGEN_PATH, ['-lf', keyPath], {
          timeoutMs: 10_000,
          maxOutputBytes: 4096,
        });
      } catch {
        throw verifierError();
      }
      if (parseFingerprintOutput(result) !== expected[index]) throw verifierError();
    }
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    await rm(directory, { recursive: true, force: true }).catch((error) => {
      if (!primaryError) throw error;
    });
  }
}

function knownHostsContent(addresses, hostKeys) {
  return `${addresses.flatMap((host) => hostKeys.map((key) => `${host} ${key}`)).join('\n')}\n`;
}

async function writeKnownHosts(path, content) {
  const parent = dirname(path);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const parentStats = await lstat(parent);
  if (parentStats.isSymbolicLink() || !parentStats.isDirectory()) {
    throw verifierError('SSH_VERIFY_UNSAFE_PATH');
  }
  const existing = await openSafeFile(path, { required: false, minBytes: 0, maxBytes: 64 * 1024 });
  if (existing) await existing.file.close();
  const temporary = join(parent, `.${basename(path)}.${randomUUID()}.tmp`);
  let file;
  let primaryError;
  try {
    file = await open(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    await file.writeFile(content);
    await file.sync();
    const temporaryStats = await file.stat();
    if (!temporaryStats.isFile() || temporaryStats.nlink !== 1 || (temporaryStats.mode & 0o077) !== 0) {
      throw verifierError('SSH_VERIFY_UNSAFE_PATH');
    }
    await file.close();
    file = null;
    await rename(temporary, path);
    const final = await openSafeFile(path, { maxBytes: 64 * 1024 });
    try {
      if (final.stats.dev !== temporaryStats.dev || final.stats.ino !== temporaryStats.ino) {
        throw verifierError('SSH_VERIFY_UNSAFE_PATH');
      }
      const actual = await stableBytes(final);
      if (!actual.equals(Buffer.from(content))) throw verifierError('SSH_VERIFY_UNSAFE_PATH');
    } finally {
      await final.file.close();
    }
    const directory = await open(parent, constants.O_RDONLY);
    try { await directory.sync(); } finally { await directory.close(); }
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    if (file) await file.close().catch(() => {});
    await rm(temporary, { force: true }).catch((error) => {
      if (!primaryError) throw error;
    });
  }
}

function strictClientOptions(knownHostsPath, privateKeyPath, portFlag) {
  return [
    '-F', 'none',
    '-o', 'GlobalKnownHostsFile=/dev/null',
    '-o', 'KnownHostsCommand=none',
    '-o', 'VerifyHostKeyDNS=no',
    '-o', 'ProxyCommand=none',
    '-o', 'ProxyJump=none',
    '-o', 'IdentityAgent=none',
    '-o', 'UpdateHostKeys=no',
    '-o', 'ControlMaster=no',
    '-o', 'ControlPath=none',
    '-o', 'WarnWeakCrypto=no',
    '-o', 'BatchMode=yes',
    '-o', 'PasswordAuthentication=no',
    '-o', 'KbdInteractiveAuthentication=no',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', `UserKnownHostsFile=${knownHostsPath}`,
    '-o', 'IdentitiesOnly=yes',
    '-i', privateKeyPath,
    portFlag, '22',
  ];
}

function snapshotProcessArgs(args, { minimum = 1, scp = false } = {}) {
  if (!Array.isArray(args) || args.length < minimum || args.length > MAX_PROCESS_ARGS) failInput();
  const snapshot = [];
  let totalBytes = 0;
  for (let index = 0; index < args.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(args, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'string') failInput();
    const bytes = Buffer.byteLength(descriptor.value);
    if (
      bytes === 0
      || bytes > MAX_PROCESS_ARG_BYTES
      || descriptor.value.includes('\0')
      || /[\r\n]/.test(descriptor.value)
      || (scp && descriptor.value.startsWith('-'))
    ) failInput();
    totalBytes += bytes;
    if (totalBytes > MAX_PROCESS_ARGV_BYTES) failInput();
    snapshot.push(descriptor.value);
  }
  return snapshot;
}

function positiveBoundedInteger(value, maximum) {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) failInput();
  return value;
}

function snapshotProcessStdin(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_PROCESS_STDIN_BYTES) {
    failInput();
  }
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0 || code > 0x7f) failInput();
  }
  return value;
}

function snapshotProcessOptions(options = {}, { allowStdin = false } = {}) {
  if (
    options === null
    || typeof options !== 'object'
    || Array.isArray(options)
    || isProxy(options)
    || Object.getPrototypeOf(options) !== Object.prototype
    || Object.getOwnPropertySymbols(options).length !== 0
  ) failInput();
  const snapshot = {};
  for (const key of Object.getOwnPropertyNames(options)) {
    const descriptor = Object.getOwnPropertyDescriptor(options, key);
    if (
      !PROCESS_OPTION_FIELDS.has(key)
      || (key === 'stdinText' && !allowStdin)
      || !descriptor
      || !Object.hasOwn(descriptor, 'value')
    ) failInput();
    snapshot[key] = descriptor.value;
  }
  const result = {
    timeoutMs: positiveBoundedInteger(
      Object.hasOwn(snapshot, 'timeoutMs') ? snapshot.timeoutMs : DEFAULT_PROCESS_TIMEOUT_MS,
      MAX_PROCESS_TIMEOUT_MS,
    ),
    maxOutputBytes: positiveBoundedInteger(
      Object.hasOwn(snapshot, 'maxOutputBytes') ? snapshot.maxOutputBytes : DEFAULT_PROCESS_OUTPUT_BYTES,
      MAX_PROCESS_OUTPUT_BYTES,
    ),
  };
  if (Object.hasOwn(snapshot, 'stdinText')) {
    result.stdinText = snapshotProcessStdin(snapshot.stdinText);
  }
  return result;
}

function trustedAddress(addresses, address) {
  if (!canonicalAddress(address) || !addresses.includes(address)) failInput();
  return address;
}

function safeRemotePath(path) {
  if (
    typeof path !== 'string'
    || path.length === 0
    || Buffer.byteLength(path) > MAX_PROCESS_ARG_BYTES
    || /[\0\r\n]/.test(path)
  ) failInput();
  return path;
}

function remotePrefix(address) {
  const host = isIP(address) === 6 ? `[${address}]` : address;
  return `AgentRoad@${host}:`;
}

function remoteSpec(address, path) {
  return `${remotePrefix(address)}${safeRemotePath(path)}`;
}

function snapshotScpOperands(args, addresses) {
  const snapshot = snapshotProcessArgs(args, { minimum: 2, scp: true });
  if (snapshot.length !== 2) failInput();
  let remoteCount = 0;
  for (const operand of snapshot) {
    if (operand.startsWith('AgentRoad@')) {
      const address = addresses.find((candidate) => operand.startsWith(remotePrefix(candidate)));
      if (!address) failInput();
      const prefix = remotePrefix(address);
      if (remoteSpec(address, operand.slice(prefix.length)) !== operand) failInput();
      remoteCount += 1;
    } else if (!isAbsolute(operand) || resolve(operand) !== operand) {
      failInput();
    }
  }
  if (remoteCount !== 1) failInput();
  return snapshot;
}

async function invoke(runProcess, command, args, options) {
  try {
    return await runProcess(command, args, options);
  } catch {
    throw verifierError();
  }
}

async function assertTrustUnchanged(trust) {
  await validateDirectoryChain(dirname(trust.original.privateKeyPath));
  await validateDirectoryChain(dirname(trust.original.knownHostsPath));
  await assertPrivateUnchanged(trust.original.privateKeyPath, trust.privateSnapshot);
  await assertKnownHostsUnchanged(trust.original.knownHostsPath, trust.knownHostsSnapshot);
  await assertSessionTrustUnchanged(trust);
}

async function assertSessionTrustUnchanged(trust) {
  await validateDirectoryChain(trust.session.directory);
  await assertPrivateUnchanged(trust.session.privateKeyPath, trust.session.privateSnapshot);
  await assertKnownHostsUnchanged(trust.session.knownHostsPath, trust.session.knownHostsSnapshot);
}

async function invokeTrusted(config, trust, command, args, options, { cleanup = false } = {}) {
  const assertUnchanged = cleanup ? assertSessionTrustUnchanged : assertTrustUnchanged;
  await assertUnchanged(trust);
  let result;
  let processError;
  try {
    result = await invoke(config.runProcess, command, args, options);
  } catch (error) {
    processError = error;
  }
  await assertUnchanged(trust);
  if (processError) throw processError;
  return result;
}

function frozenSession(config, trust, connections) {
  const addresses = Object.freeze([...config.addresses]);
  const sshOptions = strictClientOptions(
    trust.session.knownHostsPath,
    trust.session.privateKeyPath,
    '-p',
  );
  const scpOptions = strictClientOptions(
    trust.session.knownHostsPath,
    trust.session.privateKeyPath,
    '-P',
  );
  const dispatch = (address, command, options, operands, processOptions, extra) => {
    const invoke = (clientOptions) => invokeTrusted(config, trust, command,
      [...clientOptions, ...operands], processOptions, extra);
    return connections ? connections.run(address, options, invoke) : invoke(options);
  };
  return Object.freeze({
    addresses,
    invokeSsh(address, remoteArgs, options) {
      const target = trustedAddress(addresses, address);
      const args = snapshotProcessArgs(remoteArgs);
      const processOptions = snapshotProcessOptions(options, { allowStdin: true });
      return dispatch(target, SSH_PATH, sshOptions, [`AgentRoad@${target}`, ...args], processOptions);
    },
    invokeScp(args, options) {
      const argsSnapshot = snapshotScpOperands(args, addresses);
      const processOptions = snapshotProcessOptions(options);
      const target = addresses.find((address) => argsSnapshot.some((arg) => arg.startsWith(remotePrefix(address))));
      return dispatch(target, SCP_PATH, scpOptions, argsSnapshot, processOptions);
    },
    invokeCleanup(address, remoteArgs, options) {
      const target = trustedAddress(addresses, address);
      const args = snapshotProcessArgs(remoteArgs);
      const processOptions = snapshotProcessOptions(options, { allowStdin: true });
      return invokeTrusted(config, trust, SSH_PATH, [
        ...sshOptions,
        `AgentRoad@${target}`,
        ...args,
      ], processOptions, { cleanup: true });
    },
    remoteSpec(address, path) {
      const target = trustedAddress(addresses, address);
      return remoteSpec(target, path);
    },
  });
}

async function runSessionLocked(config, operation, reuseConnection) {
  let connections;
  let privateSnapshot;
  let knownHostsSnapshot;
  let session;
  let primaryError;
  try {
    await validateDirectoryChain(dirname(config.privateKeyPath));
    await validateDirectoryChain(dirname(config.knownHostsPath));
    privateSnapshot = await validatePrivateKey(config.privateKeyPath);
    await verifyFingerprints(config.hostKeys, config.fingerprints, config.runProcess);
    await assertPrivateUnchanged(config.privateKeyPath, privateSnapshot);
    const expectedKnownHosts = knownHostsContent(config.addresses, config.hostKeys);
    await writeKnownHosts(config.knownHostsPath, expectedKnownHosts);
    knownHostsSnapshot = await validateKnownHosts(config.knownHostsPath, expectedKnownHosts);
    session = await createSessionSnapshots(config, privateSnapshot, knownHostsSnapshot);
    const trust = {
      original: config,
      privateSnapshot,
      knownHostsSnapshot,
      session,
    };
    if (reuseConnection) connections = await createConnectionReuse(config, validateDirectoryChain);
    const sessionApi = frozenSession(config, trust, connections);
    let result;
    let operationError;
    try {
      result = await operation(sessionApi);
    } catch (error) {
      operationError = error;
    }
    await assertTrustUnchanged(trust);
    if (operationError) throw operationError;
    return result;
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    let closeError;
    try { await connections?.close(); } catch (error) { closeError = cleanupFailure(primaryError); }
    try { await closeSessionSnapshots(session, primaryError); } catch (error) {
      closeError = error;
    }
    if (privateSnapshot) {
      try { await privateSnapshot.entry.file.close(); } catch (error) {
        if (!closeError) closeError = cleanupFailure(primaryError);
      }
    }
    if (knownHostsSnapshot) {
      try { await knownHostsSnapshot.entry.file.close(); } catch (error) {
        if (!closeError) closeError = cleanupFailure(primaryError);
      }
    }
    if (closeError) throw closeError;
  }
}

export async function withTrustedSshSession(input, operation, options = {}) {
  const { lockTimeoutMs, reuseConnection } = sessionOptions(options);
  const config = validateInputs(snapshotInput(input));
  if (typeof operation !== 'function') failInput();
  await validateDirectoryChain(dirname(config.privateKeyPath));
  const lockName = `Trusted SSH session ${config.deviceId}`;
  let entered = false;
  try {
    return await withFileLock(
      config.privateKeyPath,
      async () => {
        entered = true;
        await ensureSecureDirectory(dirname(config.knownHostsPath));
        return runSessionLocked(config, operation, reuseConnection);
      },
      {
        name: lockName,
        timeoutMs: lockTimeoutMs,
        retryDelayMs: 10,
      },
    );
  } catch (error) {
    if (!entered && isGenericFileLockTimeout(error, lockName, config.privateKeyPath)) {
      throw trustedSshSessionLockError();
    }
    if (error !== null && (typeof error === 'object' || typeof error === 'function')) {
      TRUSTED_SSH_SESSION_LOCK_ERRORS.delete(error);
    }
    throw error;
  }
}
