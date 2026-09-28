import {
  chmod,
  lstat,
  mkdir,
  open,
  realpath,
  rm,
} from 'node:fs/promises';
import { constants } from 'node:fs';
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';

import { runProcess as defaultRunProcess } from '../process/run-process.mjs';
import { isFileLockTimeout, withFileLock } from '../storage/file-lock.mjs';

const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/;
const MAX_DEVICE_ID_LENGTH = 64;
const MAX_PUBLIC_KEY_BYTES = 4096;
const MAX_PRIVATE_KEY_BYTES = 64 * 1024;
const SSH_KEY_TYPE = 'ssh-ed25519';
const SSH_KEYGEN_PATH = '/usr/bin/ssh-keygen';
const SSH_DERIVE_TIMEOUT_MS = 10_000;

function identityError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function validateDeviceId(deviceId) {
  if (
    typeof deviceId !== 'string'
    || deviceId.length > MAX_DEVICE_ID_LENGTH
    || !DEVICE_ID_PATTERN.test(deviceId)
  ) {
    throw identityError('SSH_IDENTITY_DEVICE_ID_INVALID');
  }
  return deviceId;
}

function validateRoot(root) {
  if (typeof root !== 'string' || root.length === 0 || root.includes('\0')) {
    throw identityError('SSH_IDENTITY_ROOT_INVALID');
  }
  return resolve(root);
}

function validateExecutable(path) {
  if (typeof path !== 'string' || path.length === 0 || path.includes('\0') || !isAbsolute(path)) {
    throw identityError('SSH_IDENTITY_EXECUTABLE_INVALID');
  }
  return path;
}

async function ensureDirectory(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const stats = await lstat(path);
  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw identityError('SSH_IDENTITY_UNSAFE_PATH');
  }
  await chmod(path, 0o700);
}

async function openFinalFile(path) {
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stats = await file.stat();
    if (!stats.isFile() || stats.nlink !== 1) {
      throw identityError('SSH_IDENTITY_UNSAFE_PATH');
    }
    return { file, stats };
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    if (file) await file.close().catch(() => {});
    if (error.code === 'ELOOP') throw identityError('SSH_IDENTITY_UNSAFE_PATH');
    throw error;
  }
}

async function openPair(privateKeyPath, publicKeyPath) {
  let privateEntry;
  try {
    privateEntry = await openFinalFile(privateKeyPath);
    const publicEntry = await openFinalFile(publicKeyPath);
    return { privateEntry, publicEntry };
  } catch (error) {
    if (privateEntry) await privateEntry.file.close().catch(() => {});
    throw error;
  }
}

async function closePair(pair, primaryError) {
  if (!pair) return;
  for (const entry of [pair.privateEntry, pair.publicEntry]) {
    if (!entry) continue;
    try {
      await entry.file.close();
    } catch (error) {
      if (!primaryError) throw error;
    }
  }
}

function sameFileState(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.nlink === right.nlink
    && left.mode === right.mode
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

async function readExactAtStart(file, size) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const { bytesRead } = await file.read(bytes, offset, size - offset, offset);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  if (offset !== size) throw identityError('SSH_IDENTITY_UNSAFE_PATH');
  return bytes;
}

async function readStableBytes(entry, maxBytes, invalidCode) {
  const before = await entry.file.stat();
  if (!sameFileState(entry.stats, before)) {
    throw identityError('SSH_IDENTITY_UNSAFE_PATH');
  }
  if (before.size <= 0 || before.size > maxBytes) {
    throw identityError(invalidCode);
  }
  const first = await readExactAtStart(entry.file, before.size);
  const middle = await entry.file.stat();
  if (!sameFileState(before, middle)) {
    throw identityError('SSH_IDENTITY_UNSAFE_PATH');
  }
  const second = await readExactAtStart(entry.file, before.size);
  const after = await entry.file.stat();
  if (!sameFileState(middle, after) || !first.equals(second)) {
    throw identityError('SSH_IDENTITY_UNSAFE_PATH');
  }
  return first;
}

function digest(bytes) {
  return createHash('sha256').update(bytes).digest();
}

async function createPrivateSnapshot(privateKeyPath, privateEntry) {
  const snapshotPath = join(dirname(privateKeyPath), `.derive-${randomUUID()}.key`);
  let snapshotFile;
  let primaryError;
  try {
    const privateBytes = await readStableBytes(
      privateEntry,
      MAX_PRIVATE_KEY_BYTES,
      'SSH_IDENTITY_PRIVATE_INVALID',
    );
    snapshotFile = await open(
      snapshotPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    const snapshotStats = await snapshotFile.stat();
    if (!snapshotStats.isFile() || snapshotStats.nlink !== 1 || (snapshotStats.mode & 0o077) !== 0) {
      throw identityError('SSH_IDENTITY_UNSAFE_PATH');
    }
    await snapshotFile.writeFile(privateBytes);
    await snapshotFile.sync();
    return { path: snapshotPath, privateDigest: digest(privateBytes) };
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    if (snapshotFile) {
      try {
        await snapshotFile.close();
      } catch (error) {
        if (!primaryError) throw error;
      }
    }
    if (primaryError) {
      await cleanupNewFiles([snapshotPath], primaryError);
    }
  }
}

function parseSshString(blob, offset) {
  if (offset + 4 > blob.length) return null;
  const length = blob.readUInt32BE(offset);
  const start = offset + 4;
  const end = start + length;
  if (end > blob.length) return null;
  return { bytes: blob.subarray(start, end), offset: end };
}

function validateKeyBlob(encoded) {
  const blob = Buffer.from(encoded, 'base64');
  if (blob.length === 0 || blob.toString('base64') !== encoded) {
    throw identityError('SSH_IDENTITY_PUBLIC_INVALID');
  }
  const algorithm = parseSshString(blob, 0);
  const key = algorithm && parseSshString(blob, algorithm.offset);
  if (
    !algorithm
    || !key
    || algorithm.bytes.toString('ascii') !== SSH_KEY_TYPE
    || key.bytes.length !== 32
    || key.offset !== blob.length
  ) {
    throw identityError('SSH_IDENTITY_PUBLIC_INVALID');
  }
  return encoded;
}

function oneLine(content) {
  if (
    Buffer.byteLength(content, 'utf8') <= 0
    || Buffer.byteLength(content, 'utf8') > MAX_PUBLIC_KEY_BYTES
    || /[\x00-\x09\x0b-\x1f\x7f]/.test(content)
  ) {
    throw identityError('SSH_IDENTITY_PUBLIC_INVALID');
  }
  const line = content.endsWith('\n') ? content.slice(0, -1) : content;
  if (line.includes('\n')) {
    throw identityError('SSH_IDENTITY_PUBLIC_INVALID');
  }
  return line;
}

function validatePublicLine(content, deviceId) {
  const line = oneLine(content);
  const match = /^(ssh-ed25519) ([A-Za-z0-9+/]+={0,2}) (agent-road:dev_[a-z0-9]+)$/.exec(line);
  if (!match || match[1] !== SSH_KEY_TYPE || match[3] !== `agent-road:${deviceId}`) {
    throw identityError('SSH_IDENTITY_PUBLIC_INVALID');
  }

  return { line, blob: validateKeyBlob(match[2]) };
}

function validateDerivedPublic(content, deviceId) {
  try {
    const line = oneLine(content);
    const match = /^(ssh-ed25519) ([A-Za-z0-9+/]+={0,2})(?: (agent-road:dev_[a-z0-9]+))?$/.exec(line);
    if (!match) throw identityError('SSH_IDENTITY_PRIVATE_INVALID');
    if (match[3] !== undefined && match[3] !== `agent-road:${deviceId}`) {
      throw identityError('SSH_IDENTITY_PRIVATE_INVALID');
    }
    return validateKeyBlob(match[2]);
  } catch {
    throw identityError('SSH_IDENTITY_PRIVATE_INVALID');
  }
}

async function cleanupNewFiles(paths, primaryError) {
  for (const path of paths) {
    try {
      await rm(path, { force: true });
    } catch (error) {
      if (!primaryError) throw error;
    }
  }
}

function identitySnapshot(privateKeyPath, publicKeyPath, publicKey) {
  return Object.freeze({ privateKeyPath, publicKeyPath, publicKey });
}

export class SshIdentityStore {
  constructor(root, {
    runProcess = defaultRunProcess,
    sshKeygen = '/usr/bin/ssh-keygen',
  } = {}) {
    this.root = validateRoot(root);
    if (typeof runProcess !== 'function') {
      throw new TypeError('runProcess must be a function');
    }
    this.runProcess = runProcess;
    this.sshKeygen = validateExecutable(sshKeygen);
  }

  async getExisting(inputDeviceId) {
    const deviceId = validateDeviceId(inputDeviceId);
    const paths = this.#devicePaths(deviceId);

    try {
      await this.#requireContainedDeviceDirectory(paths);
    } catch (error) {
      if (error.code === 'ENOENT') throw identityError('SSH_IDENTITY_NOT_FOUND');
      throw error;
    }

    let entered = false;
    try {
      return await withFileLock(paths.privateKeyPath, async () => {
        entered = true;
        await this.#requireContainedDeviceDirectory(paths);
        const identity = await this.#loadValidatedPair(paths, deviceId);
        if (identity === null) throw identityError('SSH_IDENTITY_NOT_FOUND');
        return identity;
      }, { name: `SSH identity ${deviceId}` });
    } catch (error) {
      if (!entered && isFileLockTimeout(error)) throw identityError('SSH_IDENTITY_BUSY');
      throw error;
    }
  }

  async getOrCreate(inputDeviceId) {
    const deviceId = validateDeviceId(inputDeviceId);
    const paths = this.#devicePaths(deviceId);
    const { deviceDirectory, privateKeyPath, publicKeyPath } = paths;

    await ensureDirectory(this.root);
    await ensureDirectory(deviceDirectory);
    await this.#requireContainedDeviceDirectory(paths);

    return withFileLock(privateKeyPath, async () => {
      await ensureDirectory(this.root);
      await ensureDirectory(deviceDirectory);
      await this.#requireContainedDeviceDirectory(paths);

      const existing = await this.#loadValidatedPair(paths, deviceId);
      if (existing !== null) return existing;

      let primaryError;
      let generatedPair;
      try {
        const result = await this.runProcess(this.sshKeygen, [
          '-q',
          '-t',
          'ed25519',
          '-N',
          '',
          '-C',
          `agent-road:${deviceId}`,
          '-f',
          privateKeyPath,
        ]);
        if (!result || result.exitCode !== 0 || result.signal !== null) {
          throw identityError('SSH_IDENTITY_KEYGEN_FAILED');
        }

        generatedPair = await openPair(privateKeyPath, publicKeyPath);
        const { privateEntry, publicEntry } = generatedPair;
        if (!privateEntry || !publicEntry) {
          throw identityError('SSH_IDENTITY_GENERATED_INVALID');
        }
        await privateEntry.file.chmod(0o600);
        await publicEntry.file.chmod(0o600);
        privateEntry.stats = await privateEntry.file.stat();
        publicEntry.stats = await publicEntry.file.stat();
        const parsedPublic = await this.#readValidatedPublic(publicEntry, deviceId);
        await this.#requireMatchingPrivate(
          privateKeyPath,
          privateEntry,
          publicEntry,
          parsedPublic,
          deviceId,
        );
        return identitySnapshot(privateKeyPath, publicKeyPath, parsedPublic.line);
      } catch (error) {
        primaryError = error;
        throw error;
      } finally {
        await closePair(generatedPair, primaryError);
        if (primaryError) {
          await cleanupNewFiles([privateKeyPath, publicKeyPath], primaryError);
        }
      }
    }, { name: `SSH identity ${deviceId}` });
  }

  #devicePaths(deviceId) {
    const deviceDirectory = join(this.root, deviceId);
    const relativeDevice = relative(this.root, deviceDirectory);
    if (relativeDevice !== deviceId || relativeDevice.startsWith('..') || isAbsolute(relativeDevice)) {
      throw identityError('SSH_IDENTITY_UNSAFE_PATH');
    }
    const privateKeyPath = join(deviceDirectory, 'id_ed25519');
    return {
      deviceId,
      deviceDirectory,
      privateKeyPath,
      publicKeyPath: `${privateKeyPath}.pub`,
    };
  }

  async #requireContainedDeviceDirectory({ deviceId, deviceDirectory }) {
    const rootStats = await lstat(this.root);
    const deviceStats = await lstat(deviceDirectory);
    if (
      rootStats.isSymbolicLink()
      || !rootStats.isDirectory()
      || deviceStats.isSymbolicLink()
      || !deviceStats.isDirectory()
      || await realpath(deviceDirectory) !== join(await realpath(this.root), deviceId)
    ) {
      throw identityError('SSH_IDENTITY_UNSAFE_PATH');
    }
  }

  async #loadValidatedPair({ privateKeyPath, publicKeyPath }, deviceId) {
    let pair;
    let primaryError;
    try {
      pair = await openPair(privateKeyPath, publicKeyPath);
      const { privateEntry, publicEntry } = pair;
      if (Boolean(privateEntry) !== Boolean(publicEntry)) {
        throw identityError('SSH_IDENTITY_PARTIAL');
      }
      if (!privateEntry || !publicEntry) return null;
      if ((privateEntry.stats.mode & 0o077) !== 0 || (publicEntry.stats.mode & 0o077) !== 0) {
        throw identityError('SSH_IDENTITY_PERMISSIONS');
      }
      const parsedPublic = await this.#readValidatedPublic(publicEntry, deviceId);
      await this.#requireMatchingPrivate(
        privateKeyPath,
        privateEntry,
        publicEntry,
        parsedPublic,
        deviceId,
      );
      await privateEntry.file.chmod(0o600);
      await publicEntry.file.chmod(0o600);
      return identitySnapshot(privateKeyPath, publicKeyPath, parsedPublic.line);
    } catch (error) {
      primaryError = error;
      throw error;
    } finally {
      await closePair(pair, primaryError);
    }
  }

  async #readValidatedPublic(entry, deviceId) {
    let content;
    try {
      content = (await readStableBytes(
        entry,
        MAX_PUBLIC_KEY_BYTES,
        'SSH_IDENTITY_PUBLIC_INVALID',
      )).toString('utf8');
    } catch {
      throw identityError('SSH_IDENTITY_PUBLIC_INVALID');
    }
    return validatePublicLine(content, deviceId);
  }

  async #requireMatchingPrivate(
    privateKeyPath,
    privateEntry,
    publicEntry,
    expectedPublic,
    deviceId,
  ) {
    let snapshotPath;
    let privateDigest;
    let primaryError;
    try {
      try {
        const snapshot = await createPrivateSnapshot(privateKeyPath, privateEntry);
        snapshotPath = snapshot.path;
        privateDigest = snapshot.privateDigest;
      } catch {
        throw identityError('SSH_IDENTITY_PRIVATE_INVALID');
      }
      let result;
      try {
        result = await this.runProcess(SSH_KEYGEN_PATH, ['-y', '-f', snapshotPath], {
          timeoutMs: SSH_DERIVE_TIMEOUT_MS,
          maxOutputBytes: MAX_PUBLIC_KEY_BYTES,
        });
      } catch {
        throw identityError('SSH_IDENTITY_PRIVATE_INVALID');
      }
      let derivedBlob;
      try {
        if (
          !result
          || result.exitCode !== 0
          || result.signal !== null
          || result.stderr !== ''
          || typeof result.stdout !== 'string'
        ) {
          throw identityError('SSH_IDENTITY_PRIVATE_INVALID');
        }
        derivedBlob = validateDerivedPublic(result.stdout, deviceId);
      } catch {
        throw identityError('SSH_IDENTITY_PRIVATE_INVALID');
      }
      if (derivedBlob !== expectedPublic.blob) {
        throw identityError('SSH_IDENTITY_MISMATCH');
      }

      const currentPrivateBytes = await readStableBytes(
        privateEntry,
        MAX_PRIVATE_KEY_BYTES,
        'SSH_IDENTITY_PRIVATE_INVALID',
      );
      if (!timingSafeEqual(privateDigest, digest(currentPrivateBytes))) {
        throw identityError('SSH_IDENTITY_UNSAFE_PATH');
      }
      const currentPublic = await this.#readValidatedPublic(publicEntry, deviceId);
      if (
        currentPublic.line !== expectedPublic.line
        || currentPublic.blob !== expectedPublic.blob
      ) {
        throw identityError('SSH_IDENTITY_MISMATCH');
      }

      let currentEntry;
      let currentPrimaryError;
      try {
        currentEntry = await openFinalFile(privateKeyPath);
        if (
          !currentEntry
          || currentEntry.stats.dev !== privateEntry.stats.dev
          || currentEntry.stats.ino !== privateEntry.stats.ino
        ) {
          throw identityError('SSH_IDENTITY_UNSAFE_PATH');
        }
      } catch (error) {
        currentPrimaryError = error;
        throw error;
      } finally {
        await closePair(
          currentEntry ? { privateEntry: currentEntry, publicEntry: null } : null,
          currentPrimaryError,
        );
      }
    } catch (error) {
      primaryError = error;
      throw error;
    } finally {
      if (snapshotPath) {
        await cleanupNewFiles([snapshotPath], primaryError);
      }
    }
  }
}
