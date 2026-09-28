import { execFile as execFileCallback } from 'node:child_process';
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync as defaultGenerateKeyPairSync,
  sign as cryptoSign,
} from 'node:crypto';
import {
  chmod,
  lstat,
  mkdir,
  open,
  realpath,
  rename,
  rm,
} from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { promisify } from 'node:util';
import { isProxy } from 'node:util/types';

import { withFileLock } from '../storage/file-lock.mjs';

const MAX_PRIVATE_KEY_BYTES = 64 * 1024;
const MAX_PUBLIC_KEY_BYTES = 16 * 1024;
const MAX_STAGE_ONE_BYTES = 1024 * 1024;
const BOOTSTRAP_SIGNING_LOCK_TIMEOUT_MS = 30_000;
const PUBLIC_KEYS = ['algorithm', 'modulusBase64Url', 'exponentBase64Url'];
const PRIVATE_KEY_PEM_LABEL = ['PRIVATE', 'KEY'].join(' ');
const PRIVATE_KEY_PEM_HEADER = `-----BEGIN ${PRIVATE_KEY_PEM_LABEL}-----`;
const PRIVATE_KEY_PEM_FOOTER = `-----END ${PRIVATE_KEY_PEM_LABEL}-----`;
const execFile = promisify(execFileCallback);

function identityError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

async function assertNoDarwinExtendedAcl(path) {
  if (process.platform !== 'darwin') return;
  let output;
  try {
    output = await execFile('/bin/ls', ['-lde', '--', path], {
      encoding: 'utf8',
      env: Object.freeze({ LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' }),
      maxBuffer: 16 * 1_024,
      timeout: 2_000,
    });
  } catch {
    throw identityError('BOOTSTRAP_SIGNING_KEY_PERMISSIONS');
  }
  if (
    output === null
    || typeof output !== 'object'
    || typeof output.stdout !== 'string'
    || typeof output.stderr !== 'string'
    || output.stderr.length !== 0
    || output.stdout.length === 0
    || output.stdout.includes('\0')
    || /^\s+[0-9]+:\s/mu.test(output.stdout)
  ) throw identityError('BOOTSTRAP_SIGNING_KEY_PERMISSIONS');
}

function validatePath(path) {
  if (typeof path !== 'string' || path.length === 0 || path.includes('\0')) {
    throw identityError('BOOTSTRAP_SIGNING_KEY_PATH_INVALID');
  }
  return resolve(path);
}

async function ensureSecureDirectory(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const stats = await lstat(path);
  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw identityError('BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE');
  }
  if (typeof process.geteuid === 'function' && stats.uid !== process.geteuid()) {
    throw identityError('BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE');
  }
  if ((stats.mode & 0o777) !== 0o700) await chmod(path, 0o700);
  await secureDirectorySnapshot(path);
}

async function openExistingRegularFile(path, openFile = open) {
  let file;
  try {
    file = await openFile(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stats = await file.stat();
    assertSecureRegularFile(stats);
    const entry = { file, stats };
    await assertEntryUnchanged(path, entry);
    return entry;
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    if (file) await file.close().catch(() => {});
    if (error.code === 'ELOOP') {
      throw identityError('BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE');
    }
    throw error;
  }
}

async function closeEntries(entries, primaryError) {
  for (const entry of entries) {
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
    && left.uid === right.uid
    && left.gid === right.gid
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

function sameDirectoryState(left, right) {
  return sameFileState(left, right)
    && left.isDirectory()
    && right.isDirectory()
    && !left.isSymbolicLink()
    && !right.isSymbolicLink();
}

function sameDirectoryEndpoint(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.isDirectory()
    && right.isDirectory()
    && !left.isSymbolicLink()
    && !right.isSymbolicLink();
}

function assertSecureDirectoryStats(stats) {
  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw identityError('BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE');
  }
  if ((stats.mode & 0o077) !== 0) {
    throw identityError('BOOTSTRAP_SIGNING_KEY_PERMISSIONS');
  }
  if (typeof process.geteuid === 'function' && stats.uid !== process.geteuid()) {
    throw identityError('BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE');
  }
}

function assertSecureRegularFile(stats) {
  if (stats.isSymbolicLink() || !stats.isFile() || stats.nlink !== 1) {
    throw identityError('BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE');
  }
  if ((stats.mode & 0o077) !== 0) {
    throw identityError('BOOTSTRAP_SIGNING_KEY_PERMISSIONS');
  }
  if (typeof process.geteuid === 'function' && stats.uid !== process.geteuid()) {
    throw identityError('BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE');
  }
}

async function secureDirectorySnapshot(path, missingCode = null) {
  let before;
  let canonical;
  let after;
  try {
    before = await lstat(path);
    assertSecureDirectoryStats(before);
    await assertNoDarwinExtendedAcl(path);
    canonical = await realpath(path);
    await assertNoDarwinExtendedAcl(path);
    after = await lstat(path);
    assertSecureDirectoryStats(after);
  } catch (error) {
    if (error?.code === 'ENOENT' && missingCode !== null) throw identityError(missingCode);
    throw error;
  }
  if (canonical !== path || !sameDirectoryEndpoint(before, after)) {
    throw identityError('BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE');
  }
  return after;
}

async function secureParentSnapshot(path) {
  const parent = dirname(path);
  const stats = await secureDirectorySnapshot(parent, 'BOOTSTRAP_SIGNING_KEY_PARTIAL');
  return Object.freeze({ parent, stats });
}

async function assertParentUnchanged(snapshot) {
  let current;
  try {
    current = await secureDirectorySnapshot(
      snapshot.parent,
      'BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE',
    );
  } catch (error) {
    if (error?.code === 'BOOTSTRAP_SIGNING_KEY_PERMISSIONS') throw error;
    throw identityError('BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE');
  }
  if (!sameDirectoryState(snapshot.stats, current)) {
    throw identityError('BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE');
  }
}

async function assertEntryUnchanged(path, entry) {
  let handleBefore;
  let pathBefore;
  let canonical;
  let handleAfter;
  let pathAfter;
  try {
    handleBefore = await entry.file.stat();
    pathBefore = await lstat(path);
    assertSecureRegularFile(handleBefore);
    assertSecureRegularFile(pathBefore);
    await assertNoDarwinExtendedAcl(path);
    canonical = await realpath(path);
    await assertNoDarwinExtendedAcl(path);
    handleAfter = await entry.file.stat();
    pathAfter = await lstat(path);
    assertSecureRegularFile(handleAfter);
    assertSecureRegularFile(pathAfter);
  } catch (error) {
    if (error?.code === 'BOOTSTRAP_SIGNING_KEY_PERMISSIONS') throw error;
    throw identityError('BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE');
  }
  if (
    canonical !== path
    || !sameFileState(entry.stats, handleBefore)
    || !sameFileState(handleBefore, pathBefore)
    || !sameFileState(pathBefore, handleAfter)
    || !sameFileState(handleAfter, pathAfter)
  ) throw identityError('BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE');
}

async function readExactAtStart(file, size) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const { bytesRead } = await file.read(bytes, offset, size - offset, offset);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  if (offset !== size) throw identityError('BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE');
  return bytes;
}

async function readStableBytes(entry, maxBytes, invalidCode) {
  const before = await entry.file.stat();
  if (!sameFileState(entry.stats, before)) {
    throw identityError('BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE');
  }
  if (before.size <= 0 || before.size > maxBytes) {
    throw identityError(invalidCode);
  }
  const first = await readExactAtStart(entry.file, before.size);
  const middle = await entry.file.stat();
  if (!sameFileState(before, middle)) {
    throw identityError('BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE');
  }
  const second = await readExactAtStart(entry.file, before.size);
  const after = await entry.file.stat();
  if (!sameFileState(middle, after) || !first.equals(second)) {
    throw identityError('BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE');
  }
  return first;
}

async function withOpenFile(openFile, path, flags, mode, operation) {
  const file = await openFile(path, flags, mode);
  let primaryError;
  try {
    return await operation(file);
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    try {
      await file.close();
    } catch (error) {
      if (!primaryError) throw error;
    }
  }
}

async function writeBytesAtomic(path, bytes, openFile) {
  const temporaryPath = `${path}.${randomUUID()}.tmp`;
  let primaryError;
  try {
    await withOpenFile(openFile, temporaryPath, 'wx', 0o600, async (file) => {
      await file.writeFile(bytes);
      await file.sync();
    });
    await rename(temporaryPath, path);
    await withOpenFile(openFile, dirname(path), 'r', undefined, (directory) => directory.sync());
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    try {
      await rm(temporaryPath, { force: true });
    } catch (error) {
      if (!primaryError) throw error;
    }
  }
}

function decodeCanonicalBase64Url(value) {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    return null;
  }
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length > 0 && bytes.toString('base64url') === value ? bytes : null;
}

function validatePublicPayload(value) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).length !== PUBLIC_KEYS.length
    || !PUBLIC_KEYS.every((key) => Object.hasOwn(value, key))
    || value.algorithm !== 'RSA-SHA256'
    || value.exponentBase64Url !== 'AQAB'
    || !decodeCanonicalBase64Url(value.modulusBase64Url)
  ) {
    throw identityError('BOOTSTRAP_SIGNING_KEY_PUBLIC_INVALID');
  }
  return value;
}

function payloadFromPrivateKey(privateKey) {
  const publicKey = createPublicKey(privateKey);
  const { n, e, kty } = publicKey.export({ format: 'jwk' });
  if (kty !== 'RSA' || e !== 'AQAB' || !decodeCanonicalBase64Url(n)) {
    throw identityError('BOOTSTRAP_SIGNING_KEY_PRIVATE_INVALID');
  }
  return {
    algorithm: 'RSA-SHA256',
    modulusBase64Url: n,
    exponentBase64Url: e,
  };
}

function isPkcs8Pem(pem) {
  const content = pem.endsWith('\n') ? pem.slice(0, -1) : pem;
  const prefix = `${PRIVATE_KEY_PEM_HEADER}\n`;
  const suffix = `\n${PRIVATE_KEY_PEM_FOOTER}`;
  return content.startsWith(prefix)
    && content.endsWith(suffix)
    && content.length > prefix.length + suffix.length;
}

async function loadPrivateKey(entry) {
  let pem;
  let privateKey;
  try {
    pem = (await readStableBytes(
      entry,
      MAX_PRIVATE_KEY_BYTES,
      'BOOTSTRAP_SIGNING_KEY_PRIVATE_INVALID',
    )).toString('utf8');
    if (!isPkcs8Pem(pem)) {
      throw new Error('not PKCS8 PEM');
    }
    privateKey = createPrivateKey({ key: pem, format: 'pem', type: 'pkcs8' });
  } catch (error) {
    if (error?.code === 'BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE') throw error;
    throw identityError('BOOTSTRAP_SIGNING_KEY_PRIVATE_INVALID');
  }
  if (
    privateKey.asymmetricKeyType !== 'rsa'
    || !privateKey.asymmetricKeyDetails
    || privateKey.asymmetricKeyDetails.modulusLength !== 3072
    || privateKey.asymmetricKeyDetails.publicExponent !== 65537n
  ) {
    throw identityError('BOOTSTRAP_SIGNING_KEY_PRIVATE_INVALID');
  }
  return privateKey;
}

async function loadPublicPayload(entry) {
  try {
    const bytes = await readStableBytes(
      entry,
      MAX_PUBLIC_KEY_BYTES,
      'BOOTSTRAP_SIGNING_KEY_PUBLIC_INVALID',
    );
    return validatePublicPayload(JSON.parse(bytes.toString('utf8')));
  } catch (error) {
    if ([
      'BOOTSTRAP_SIGNING_KEY_PUBLIC_INVALID',
      'BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE',
    ].includes(error?.code)) throw error;
    throw identityError('BOOTSTRAP_SIGNING_KEY_PUBLIC_INVALID');
  }
}

function samePayload(left, right) {
  return PUBLIC_KEYS.every((key) => left[key] === right[key]);
}

function publicSnapshot(payload) {
  return Object.freeze({
    algorithm: payload.algorithm,
    modulusBase64Url: payload.modulusBase64Url,
    exponentBase64Url: payload.exponentBase64Url,
  });
}

function expectedPublicSnapshot(input) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) throw identityError('BOOTSTRAP_SIGNING_KEY_PUBLIC_INVALID');
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== PUBLIC_KEYS.length || !PUBLIC_KEYS.every((field) => names.includes(field))) {
    throw identityError('BOOTSTRAP_SIGNING_KEY_PUBLIC_INVALID');
  }
  const value = {};
  for (const field of PUBLIC_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      throw identityError('BOOTSTRAP_SIGNING_KEY_PUBLIC_INVALID');
    }
    value[field] = descriptor.value;
  }
  return publicSnapshot(validatePublicPayload(value));
}

async function withExistingPair(privateKeyPath, publicKeyPath, openFile, operation) {
  const privateParent = await secureParentSnapshot(privateKeyPath);
  const publicParent = privateParent.parent === dirname(publicKeyPath)
    ? privateParent
    : await secureParentSnapshot(publicKeyPath);
  let privateEntry;
  let publicEntry;
  let primaryError;
  try {
    privateEntry = await openExistingRegularFile(privateKeyPath, openFile);
    publicEntry = await openExistingRegularFile(publicKeyPath, openFile);
    if (!privateEntry || !publicEntry) {
      throw identityError('BOOTSTRAP_SIGNING_KEY_PARTIAL');
    }
    const privateKey = await loadPrivateKey(privateEntry);
    const stored = await loadPublicPayload(publicEntry);
    if (!samePayload(payloadFromPrivateKey(privateKey), stored)) {
      throw identityError('BOOTSTRAP_SIGNING_KEY_MISMATCH');
    }
    const result = await operation(privateKey, stored);
    await assertEntryUnchanged(privateKeyPath, privateEntry);
    await assertEntryUnchanged(publicKeyPath, publicEntry);
    await assertParentUnchanged(privateParent);
    if (publicParent !== privateParent) await assertParentUnchanged(publicParent);
    return result;
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    await closeEntries([privateEntry, publicEntry], primaryError);
  }
}

export class BootstrapSigner {
  constructor(privateKeyPath, publicKeyPath, {
    generateKeyPairSync = defaultGenerateKeyPairSync,
    openFile = open,
  } = {}) {
    this.privateKeyPath = validatePath(privateKeyPath);
    this.publicKeyPath = validatePath(publicKeyPath);
    if (this.privateKeyPath === this.publicKeyPath) {
      throw identityError('BOOTSTRAP_SIGNING_KEY_PATH_INVALID');
    }
    if (typeof generateKeyPairSync !== 'function' || typeof openFile !== 'function') {
      throw new TypeError('invalid BootstrapSigner dependency');
    }
    this.generateKeyPairSync = generateKeyPairSync;
    this.openFile = openFile;
  }

  async getOrCreate() {
    await ensureSecureDirectory(dirname(this.privateKeyPath));
    await ensureSecureDirectory(dirname(this.publicKeyPath));

    return withFileLock(this.privateKeyPath, async () => {
      await ensureSecureDirectory(dirname(this.privateKeyPath));
      await ensureSecureDirectory(dirname(this.publicKeyPath));
      let privateEntry;
      let publicEntry;
      let primaryError;
      try {
        privateEntry = await openExistingRegularFile(this.privateKeyPath);
        publicEntry = await openExistingRegularFile(this.publicKeyPath);

        if (!privateEntry && publicEntry) {
          throw identityError('BOOTSTRAP_SIGNING_KEY_PARTIAL');
        }

        if (privateEntry) {
          const privateKey = await loadPrivateKey(privateEntry);
          const derived = payloadFromPrivateKey(privateKey);
          if (!publicEntry) {
            await writeBytesAtomic(
              this.publicKeyPath,
              `${JSON.stringify(derived, null, 2)}\n`,
              this.openFile,
            );
            publicEntry = await openExistingRegularFile(this.publicKeyPath);
            if (!publicEntry) {
              throw identityError('BOOTSTRAP_SIGNING_KEY_PARTIAL');
            }
            const reconciled = await loadPublicPayload(publicEntry);
            if (!samePayload(derived, reconciled)) {
              throw identityError('BOOTSTRAP_SIGNING_KEY_MISMATCH');
            }
            return publicSnapshot(reconciled);
          }
          const stored = await loadPublicPayload(publicEntry);
          if (!samePayload(derived, stored)) {
            throw identityError('BOOTSTRAP_SIGNING_KEY_MISMATCH');
          }
          return publicSnapshot(stored);
        }

        const { privateKey, publicKey } = this.generateKeyPairSync('rsa', {
          modulusLength: 3072,
          publicExponent: 0x10001,
        });
        const pem = privateKey.export({ format: 'pem', type: 'pkcs8' });
        const payload = payloadFromPrivateKey(privateKey);
        const generatedPublic = publicKey.export({ format: 'jwk' });
        if (generatedPublic.n !== payload.modulusBase64Url || generatedPublic.e !== payload.exponentBase64Url) {
          throw identityError('BOOTSTRAP_SIGNING_KEY_PRIVATE_INVALID');
        }
        await writeBytesAtomic(this.privateKeyPath, pem, this.openFile);
        await writeBytesAtomic(
          this.publicKeyPath,
          `${JSON.stringify(payload, null, 2)}\n`,
          this.openFile,
        );
        privateEntry = await openExistingRegularFile(this.privateKeyPath);
        publicEntry = await openExistingRegularFile(this.publicKeyPath);
        if (!privateEntry || !publicEntry) {
          throw identityError('BOOTSTRAP_SIGNING_KEY_PARTIAL');
        }
        const persistedPrivateKey = await loadPrivateKey(privateEntry);
        const persistedPublic = await loadPublicPayload(publicEntry);
        if (!samePayload(payloadFromPrivateKey(persistedPrivateKey), persistedPublic)) {
          throw identityError('BOOTSTRAP_SIGNING_KEY_MISMATCH');
        }
        return publicSnapshot(persistedPublic);
      } catch (error) {
        primaryError = error;
        throw error;
      } finally {
        await closeEntries([privateEntry, publicEntry], primaryError);
      }
    }, {
      name: 'bootstrap signing key',
      timeoutMs: BOOTSTRAP_SIGNING_LOCK_TIMEOUT_MS,
    });
  }

  async getExisting() {
    return withExistingPair(
      this.privateKeyPath,
      this.publicKeyPath,
      this.openFile,
      async (_privateKey, stored) => publicSnapshot(stored),
    );
  }

  async signExisting(stageOneBytes, expectedPublicKey) {
    if (
      !(Buffer.isBuffer(stageOneBytes) || stageOneBytes instanceof Uint8Array)
      || stageOneBytes instanceof DataView
      || stageOneBytes.byteLength <= 0
      || stageOneBytes.byteLength > MAX_STAGE_ONE_BYTES
    ) {
      throw identityError('BOOTSTRAP_SIGNING_KEY_INPUT_INVALID');
    }
    const bytes = Buffer.from(stageOneBytes);
    const expected = expectedPublicSnapshot(expectedPublicKey);
    return withExistingPair(
      this.privateKeyPath,
      this.publicKeyPath,
      this.openFile,
      async (privateKey, stored) => {
        if (!samePayload(stored, expected)) {
          throw identityError('BOOTSTRAP_SIGNING_KEY_MISMATCH');
        }
        return cryptoSign('RSA-SHA256', bytes, privateKey).toString('base64');
      },
    );
  }

  async sign(stageOneBytes) {
    if (
      !(Buffer.isBuffer(stageOneBytes) || stageOneBytes instanceof Uint8Array)
      || stageOneBytes instanceof DataView
      || stageOneBytes.byteLength <= 0
      || stageOneBytes.byteLength > MAX_STAGE_ONE_BYTES
    ) {
      throw identityError('BOOTSTRAP_SIGNING_KEY_INPUT_INVALID');
    }
    const bytes = Buffer.from(stageOneBytes);
    await this.getOrCreate();
    return withFileLock(this.privateKeyPath, async () => {
      let privateEntry;
      let publicEntry;
      let primaryError;
      try {
        privateEntry = await openExistingRegularFile(this.privateKeyPath);
        publicEntry = await openExistingRegularFile(this.publicKeyPath);
        if (!privateEntry || !publicEntry) {
          throw identityError('BOOTSTRAP_SIGNING_KEY_PARTIAL');
        }
        const privateKey = await loadPrivateKey(privateEntry);
        const stored = await loadPublicPayload(publicEntry);
        if (!samePayload(payloadFromPrivateKey(privateKey), stored)) {
          throw identityError('BOOTSTRAP_SIGNING_KEY_MISMATCH');
        }
        return cryptoSign('RSA-SHA256', bytes, privateKey).toString('base64');
      } catch (error) {
        primaryError = error;
        throw error;
      } finally {
        await closeEntries([privateEntry, publicEntry], primaryError);
      }
    }, {
      name: 'bootstrap signing key',
      timeoutMs: BOOTSTRAP_SIGNING_LOCK_TIMEOUT_MS,
    });
  }
}
