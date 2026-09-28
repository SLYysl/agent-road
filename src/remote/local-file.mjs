import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { constants } from 'node:fs';
import {
  chmod,
  link,
  lstat,
  mkdtemp,
  open,
  rename,
  rmdir,
  unlink,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { isProxy } from 'node:util/types';

const MAX_FILE_BYTES = 256 * 1024 * 1024;
const MAX_PATH_BYTES = 4096;
const MAX_RECOVERY_JOURNAL_BYTES = 2048;
const SHA256_PATTERN = /^[A-F0-9]{64}$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/u;
const OWNER_TOKEN_PATTERN = /^[a-f0-9]{32}$/u;
const CREATED_AT_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const RECOVERY_PHASE = 'overwrite-replace-pending';
const LOCAL_FILE_TEST_HOOK = Symbol.for('agent-road.local-file.test-hook');
const NO_TEST_HOOK = Object.freeze(async () => {});
const SNAPSHOT_OPTION_FIELDS = new Set(['minimumBytes', 'maximumBytes']);
const DESTINATION_OPTION_FIELDS = new Set([
  'overwrite',
  'expectedBytes',
  'expectedSha256',
]);
const RECOVERY_JOURNAL_FIELDS = new Set([
  'schemaVersion',
  'phase',
  'targetPathSha256',
  'destinationBytes',
  'destinationSha256',
  'oldDev',
  'oldIno',
  'ownerToken',
  'ownerPid',
  'createdAt',
]);
const PUBLIC_ERROR_CODES = new Set([
  'REMOTE_INPUT_INVALID',
  'FILE_TRANSFER_FAILED',
  'FILE_INTEGRITY_FAILED',
  'LOCAL_CLEANUP_FAILED',
]);

function localError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function failInput() {
  throw localError('REMOTE_INPUT_INVALID');
}

function cleanupFailure(primaryError, fallbackCode) {
  const error = localError('LOCAL_CLEANUP_FAILED');
  let primaryCode = typeof primaryError?.primaryCode === 'string'
    ? primaryError.primaryCode
    : primaryError?.code;
  if (!PUBLIC_ERROR_CODES.has(primaryCode)) primaryCode = fallbackCode;
  if (typeof primaryCode === 'string' && /^[A-Z][A-Z0-9_]*$/u.test(primaryCode)) {
    error.primaryCode = primaryCode;
  }
  return error;
}

function publicError(error, fallbackCode) {
  return PUBLIC_ERROR_CODES.has(error?.code) ? error : localError(fallbackCode);
}

function publishDestinationError(error) {
  if (error?.code !== 'LOCAL_CLEANUP_FAILED') return localError('FILE_TRANSFER_FAILED');
  return typeof error.primaryCode === 'string'
    ? cleanupFailure(localError('FILE_TRANSFER_FAILED'))
    : localError('LOCAL_CLEANUP_FAILED');
}

async function closeFileHandle(file, primaryError, fallbackCode) {
  if (!file) {
    if (primaryError) throw primaryError;
    return;
  }
  try {
    await file.close();
    await runLocalFileTestHook('afterFileHandleClose', {
      fallbackCode,
      primaryCode: primaryError?.code,
    });
  } catch {
    throw cleanupFailure(primaryError, fallbackCode);
  }
  if (primaryError) throw primaryError;
}

async function runLocalFileTestHook(event, context) {
  let hook = NO_TEST_HOOK;
  if (process.env.NODE_TEST_CONTEXT !== undefined) {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, LOCAL_FILE_TEST_HOOK);
    if (descriptor && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'function') {
      hook = descriptor.value;
    }
  }
  await hook(event, Object.freeze({ ...context }));
}

function exactObject(input, fields) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
    || (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) failInput();
  const snapshot = Object.create(null);
  for (const key of Object.getOwnPropertyNames(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!fields.has(key) || !descriptor || !Object.hasOwn(descriptor, 'value')) failInput();
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function positiveBound(value, minimum = 1) {
  if (!Number.isSafeInteger(value) || value < minimum || value > MAX_FILE_BYTES) failInput();
  return value;
}

function snapshotBounds(input) {
  const options = exactObject(input, SNAPSHOT_OPTION_FIELDS);
  if (!Object.hasOwn(options, 'maximumBytes')) failInput();
  const minimumBytes = positiveBound(
    Object.hasOwn(options, 'minimumBytes') ? options.minimumBytes : 1,
    0,
  );
  const maximumBytes = positiveBound(options.maximumBytes);
  if (minimumBytes > maximumBytes) failInput();
  return { minimumBytes, maximumBytes };
}

function destinationOptions(input) {
  const options = exactObject(input, DESTINATION_OPTION_FIELDS);
  for (const field of DESTINATION_OPTION_FIELDS) {
    if (!Object.hasOwn(options, field)) failInput();
  }
  if (
    typeof options.overwrite !== 'boolean'
    || !SHA256_PATTERN.test(options.expectedSha256)
  ) failInput();
  return {
    overwrite: options.overwrite,
    expectedBytes: positiveBound(options.expectedBytes, 0),
    expectedSha256: options.expectedSha256,
  };
}

function canonicalPath(input) {
  if (
    typeof input !== 'string'
    || input.length === 0
    || Buffer.byteLength(input) > MAX_PATH_BYTES
    || input.includes('\0')
    || !isAbsolute(input)
    || resolve(input) !== input
    || basename(input).length === 0
  ) failInput();
  return input;
}

function sameMetadata(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.nlink === right.nlink
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function safeRegular(stats, { minimumBytes = 1, maximumBytes = MAX_FILE_BYTES } = {}) {
  return stats.isFile()
    && !stats.isSymbolicLink()
    && stats.nlink === 1n
    && stats.size >= BigInt(minimumBytes)
    && stats.size <= BigInt(maximumBytes);
}

async function readExact(file, size) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const result = await file.read(bytes, offset, size - offset, offset);
    if (result.bytesRead === 0) break;
    offset += result.bytesRead;
  }
  if (offset !== size) failInput();
  return bytes;
}

async function stableFileBytes(file, initial, bounds, inputPath) {
  const before = await file.stat({ bigint: true });
  if (!sameMetadata(initial, before) || !safeRegular(before, bounds)) failInput();
  const size = Number(before.size);
  const first = await readExact(file, size);
  await runLocalFileTestHook('afterStableFirstRead', { path: inputPath });
  const middle = await file.stat({ bigint: true });
  const second = await readExact(file, size);
  const after = await file.stat({ bigint: true });
  if (
    !sameMetadata(before, middle)
    || !sameMetadata(middle, after)
    || !timingSafeEqual(first, second)
  ) failInput();
  if (inputPath !== undefined) {
    let pathStats;
    try {
      pathStats = await lstat(inputPath, { bigint: true });
    } catch {
      failInput();
    }
    if (!sameMetadata(after, pathStats)) failInput();
  }
  return first;
}

async function openRegular(path, bounds, { missing = false } = {}) {
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stats = await file.stat({ bigint: true });
    if (!safeRegular(stats, bounds)) failInput();
    const pathStats = await lstat(path, { bigint: true });
    if (!sameMetadata(stats, pathStats)) failInput();
    return { file, stats };
  } catch (error) {
    if (!file && missing && error?.code === 'ENOENT') return null;
    const primary = publicError(error, 'REMOTE_INPUT_INVALID');
    await closeFileHandle(file, primary, 'REMOTE_INPUT_INVALID');
    throw primary;
  }
}

async function ownerOnlyFile(path, bytes, {
  minimumBytes = 1,
  errorCode = 'FILE_TRANSFER_FAILED',
} = {}) {
  let file;
  let stats;
  let primaryError;
  try {
    file = await open(
      path,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    await file.writeFile(bytes);
    await file.sync();
    stats = await file.stat({ bigint: true });
    if (!safeRegular(stats, { minimumBytes, maximumBytes: MAX_FILE_BYTES }) || (stats.mode & 0o777n) !== 0o600n) {
      failInput();
    }
  } catch (error) {
    primaryError = publicError(error, errorCode);
    if (file && !stats) {
      try { stats = await file.stat({ bigint: true }); } catch {}
    }
  } finally {
    try { await file?.close(); } catch (error) {
      primaryError = cleanupFailure(primaryError, errorCode);
    }
  }
  if (primaryError) {
    if (!file) throw primaryError;
    try {
      if (!stats) throw cleanupFailure(primaryError);
      await removeOwnedFile(path, stats);
    } catch {
      throw cleanupFailure(primaryError, errorCode);
    }
    throw primaryError;
  }
  return stats;
}

function idempotent(operation) {
  let pending;
  const invoke = () => {
    if (!pending) pending = operation();
    return pending;
  };
  return Object.freeze(invoke);
}

async function removeOwnedFile(path, identity) {
  let stats;
  try {
    stats = await lstat(path, { bigint: true });
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  if (
    stats.isSymbolicLink()
    || !stats.isFile()
    || stats.nlink !== 1n
    || stats.dev !== identity.dev
    || stats.ino !== identity.ino
  ) throw cleanupFailure();
  await unlink(path);
}

async function makeSnapshot(bytes) {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-local-snapshot-'));
  await chmod(directory, 0o700);
  const path = join(directory, 'snapshot.bin');
  let identity;
  let primaryError;
  try {
    identity = await ownerOnlyFile(path, bytes, { errorCode: 'REMOTE_INPUT_INVALID', minimumBytes: 0 });
    const close = idempotent(async () => {
      try {
        await removeOwnedFile(path, identity);
        await rmdir(directory);
      } catch {
        throw cleanupFailure();
      }
    });
    return Object.freeze({
      path,
      bytes: bytes.length,
      sha256: createHash('sha256').update(bytes).digest('hex').toUpperCase(),
      close,
    });
  } catch (error) {
    primaryError = error;
    try {
      if (identity) await removeOwnedFile(path, identity);
      await rmdir(directory);
    } catch {
      throw cleanupFailure(primaryError);
    }
    throw publicError(error, 'REMOTE_INPUT_INVALID');
  }
}

export async function snapshotLocalFile(inputPath, inputOptions) {
  const path = canonicalPath(inputPath);
  const bounds = snapshotBounds(inputOptions);
  const entry = await openRegular(path, bounds);
  let bytes;
  let primaryError;
  try {
    bytes = await stableFileBytes(entry.file, entry.stats, bounds, path);
  } catch (error) {
    primaryError = publicError(error, 'REMOTE_INPUT_INVALID');
  }
  await closeFileHandle(entry.file, primaryError, 'REMOTE_INPUT_INVALID');
  return makeSnapshot(bytes);
}

export async function snapshotBytes(inputBytes, inputOptions) {
  const bounds = snapshotBounds(inputOptions);
  if (
    isProxy(inputBytes)
    || (!Buffer.isBuffer(inputBytes) && !(inputBytes instanceof Uint8Array))
    || (typeof SharedArrayBuffer === 'function' && inputBytes.buffer instanceof SharedArrayBuffer)
  ) failInput();
  let bytes;
  try {
    bytes = Buffer.from(inputBytes);
  } catch {
    failInput();
  }
  if (bytes.length < bounds.minimumBytes || bytes.length > bounds.maximumBytes) failInput();
  return makeSnapshot(bytes);
}

async function validateDirectory(path) {
  let current = path;
  while (true) {
    let stats;
    try {
      stats = await lstat(current, { bigint: true });
    } catch {
      failInput();
    }
    if (stats.isSymbolicLink() || !stats.isDirectory()) failInput();
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

async function existingDestination(path) {
  return openRegular(path, { minimumBytes: 0, maximumBytes: Number.MAX_SAFE_INTEGER }, { missing: true });
}

async function syncDirectory(path, fallbackCode = 'FILE_TRANSFER_FAILED') {
  let directory;
  let primaryError;
  try {
    directory = await open(path, constants.O_RDONLY);
    await directory.sync();
  } catch (error) {
    primaryError = publicError(error, fallbackCode);
  }
  await closeFileHandle(directory, primaryError, fallbackCode);
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

async function inspectIdentity(path, expected, allowedLinks = [1n]) {
  let file;
  let stats;
  let primaryError;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    stats = await file.stat({ bigint: true });
    const pathStats = await lstat(path, { bigint: true });
    if (
      !stats.isFile()
      || pathStats.isSymbolicLink()
      || !pathStats.isFile()
      || !sameIdentity(stats, pathStats)
      || !sameIdentity(stats, expected)
      || !allowedLinks.includes(stats.nlink)
      || stats.nlink !== pathStats.nlink
    ) throw localError('FILE_TRANSFER_FAILED');
  } catch (error) {
    primaryError = publicError(error, 'FILE_TRANSFER_FAILED');
  }
  await closeFileHandle(file, primaryError, 'FILE_TRANSFER_FAILED');
  return stats;
}

async function inspectAnyRegular(path, allowedLinks = [1n, 2n]) {
  let file;
  let stats;
  let primaryError;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    stats = await file.stat({ bigint: true });
    const pathStats = await lstat(path, { bigint: true });
    if (
      !stats.isFile()
      || pathStats.isSymbolicLink()
      || !pathStats.isFile()
      || !sameIdentity(stats, pathStats)
      || !allowedLinks.includes(stats.nlink)
      || stats.nlink !== pathStats.nlink
    ) throw localError('FILE_TRANSFER_FAILED');
  } catch (error) {
    primaryError = publicError(error, 'FILE_TRANSFER_FAILED');
  }
  await closeFileHandle(file, primaryError, 'FILE_TRANSFER_FAILED');
  return stats;
}

async function removeExpectedPath(path, expected, allowedLinks = [1n]) {
  await inspectIdentity(path, expected, allowedLinks);
  await unlink(path);
}

async function restoreExpectedPath(source, destination, expected) {
  await inspectIdentity(source, expected, [1n]);
  await link(source, destination);
  await inspectIdentity(source, expected, [2n]);
  await inspectIdentity(destination, expected, [2n]);
  await unlink(source);
  await inspectIdentity(destination, expected, [1n]);
}

function siblingTransactionPath(path, label) {
  return join(dirname(path), `.${basename(path)}.${label}-${randomUUID()}`);
}

function overwriteRecoveryPaths(path) {
  const targetId = createHash('sha256').update(path, 'utf8').digest('hex');
  const prefix = join(dirname(path), `.agent-road-overwrite-${targetId}`);
  return {
    backupPath: `${prefix}.backup`,
    journalPath: `${prefix}.journal`,
  };
}

function recoveryJournalBytes(path, options, oldIdentity, owner) {
  return Buffer.from(`${JSON.stringify({
    schemaVersion: 1,
    phase: RECOVERY_PHASE,
    targetPathSha256: createHash('sha256').update(path, 'utf8').digest('hex').toUpperCase(),
    destinationBytes: options.expectedBytes,
    destinationSha256: options.expectedSha256,
    oldDev: String(oldIdentity.dev),
    oldIno: String(oldIdentity.ino),
    ownerToken: owner.token,
    ownerPid: owner.pid,
    createdAt: owner.createdAt,
  })}\n`, 'utf8');
}

function canonicalCreatedAt(value) {
  if (typeof value !== 'string' || !CREATED_AT_PATTERN.test(value)) return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function isProcessAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code !== 'ESRCH';
  }
}

async function readRecoveryJournal(path, destinationPath) {
  let entry;
  let record;
  let primaryError;
  try {
    entry = await openRegular(path, {
      minimumBytes: 1,
      maximumBytes: MAX_RECOVERY_JOURNAL_BYTES,
    }, { missing: true });
    if (!entry) return null;
    if (
      (entry.stats.mode & 0o777n) !== 0o600n
      || (typeof process.getuid === 'function' && entry.stats.uid !== BigInt(process.getuid()))
    ) throw localError('LOCAL_CLEANUP_FAILED');
    const bytes = await stableFileBytes(entry.file, entry.stats, {
      minimumBytes: 1,
      maximumBytes: MAX_RECOVERY_JOURNAL_BYTES,
    }, path);
    const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    record = exactObject(parsed, RECOVERY_JOURNAL_FIELDS);
    for (const field of RECOVERY_JOURNAL_FIELDS) {
      if (!Object.hasOwn(record, field)) throw localError('LOCAL_CLEANUP_FAILED');
    }
    if (
      record.schemaVersion !== 1
      || record.phase !== RECOVERY_PHASE
      || record.targetPathSha256 !== createHash('sha256').update(destinationPath, 'utf8').digest('hex').toUpperCase()
      || !Number.isSafeInteger(record.destinationBytes)
      || record.destinationBytes < 0
      || record.destinationBytes > MAX_FILE_BYTES
      || !SHA256_PATTERN.test(record.destinationSha256)
      || typeof record.oldDev !== 'string'
      || !DECIMAL_PATTERN.test(record.oldDev)
      || typeof record.oldIno !== 'string'
      || !DECIMAL_PATTERN.test(record.oldIno)
      || typeof record.ownerToken !== 'string'
      || !OWNER_TOKEN_PATTERN.test(record.ownerToken)
      || !Number.isSafeInteger(record.ownerPid)
      || record.ownerPid <= 0
      || record.ownerPid > 2_147_483_647
      || !canonicalCreatedAt(record.createdAt)
    ) throw localError('LOCAL_CLEANUP_FAILED');
    const canonical = recoveryJournalBytes(destinationPath, {
      expectedBytes: record.destinationBytes,
      expectedSha256: record.destinationSha256,
    }, { dev: BigInt(record.oldDev), ino: BigInt(record.oldIno) }, {
      token: record.ownerToken,
      pid: record.ownerPid,
      createdAt: record.createdAt,
    });
    if (canonical.length !== bytes.length || !timingSafeEqual(canonical, bytes)) {
      throw localError('LOCAL_CLEANUP_FAILED');
    }
  } catch (error) {
    primaryError = error?.code === 'LOCAL_CLEANUP_FAILED'
      ? error
      : localError('LOCAL_CLEANUP_FAILED');
  }
  await closeFileHandle(entry?.file, primaryError, 'LOCAL_CLEANUP_FAILED');
  return {
    identity: entry.stats,
    options: {
      expectedBytes: record.destinationBytes,
      expectedSha256: record.destinationSha256,
    },
    oldIdentity: {
      dev: BigInt(record.oldDev),
      ino: BigInt(record.oldIno),
    },
    owner: {
      token: record.ownerToken,
      pid: record.ownerPid,
      createdAt: record.createdAt,
    },
  };
}

async function optionalRegular(path, allowedLinks = [1n, 2n]) {
  try {
    await lstat(path, { bigint: true });
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw publicError(error, 'FILE_TRANSFER_FAILED');
  }
  return inspectAnyRegular(path, allowedLinks);
}

async function syncExpectedFile(path, expected, allowedLinks, fallbackCode) {
  let file;
  let primaryError;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stats = await file.stat({ bigint: true });
    const pathStats = await lstat(path, { bigint: true });
    if (
      !stats.isFile()
      || pathStats.isSymbolicLink()
      || !pathStats.isFile()
      || !sameIdentity(stats, pathStats)
      || !sameIdentity(stats, expected)
      || !allowedLinks.includes(stats.nlink)
      || stats.nlink !== pathStats.nlink
    ) throw localError(fallbackCode);
    await file.sync();
  } catch (error) {
    primaryError = publicError(error, fallbackCode);
  }
  await closeFileHandle(file, primaryError, fallbackCode);
}

async function removeDurableRecoveryFile(
  path,
  identity,
  allowedLinks,
  parent,
  phase,
  destinationPath,
) {
  try {
    await syncExpectedFile(path, identity, allowedLinks, 'LOCAL_CLEANUP_FAILED');
    await removeExpectedPath(path, identity, allowedLinks);
    await runLocalFileTestHook('beforeDirectorySync', { phase, path: destinationPath });
    await syncDirectory(parent, 'LOCAL_CLEANUP_FAILED');
  } catch (error) {
    if (error?.code === 'LOCAL_CLEANUP_FAILED') throw error;
    throw cleanupFailure();
  }
}

async function removeRecoveryJournal(journalPath, journalIdentity, parent, destinationPath) {
  try {
    await syncExpectedFile(journalPath, journalIdentity, [1n], 'LOCAL_CLEANUP_FAILED');
    await removeExpectedPath(journalPath, journalIdentity, [1n]);
    await runLocalFileTestHook('beforeDirectorySync', {
      phase: 'overwrite-journal-removed',
      path: destinationPath,
    });
    await syncDirectory(parent, 'LOCAL_CLEANUP_FAILED');
  } catch (error) {
    if (error?.code === 'LOCAL_CLEANUP_FAILED') throw error;
    throw cleanupFailure();
  }
}

async function reconcileOverwrite(path, parent) {
  const { backupPath, journalPath } = overwriteRecoveryPaths(path);
  const journal = await readRecoveryJournal(journalPath, path);
  if (journal && isProcessAlive(journal.owner.pid)) {
    throw localError('FILE_TRANSFER_FAILED');
  }
  try {
    const backup = await optionalRegular(backupPath);
    if (!journal) {
      if (backup) throw localError('LOCAL_CLEANUP_FAILED');
      return;
    }
    const destination = await optionalRegular(path);
    if (backup && !sameIdentity(backup, journal.oldIdentity)) {
      throw localError('LOCAL_CLEANUP_FAILED');
    }

    if (!destination) {
      if (!backup || backup.nlink !== 1n) throw localError('LOCAL_CLEANUP_FAILED');
      await rename(backupPath, path);
      await inspectIdentity(path, journal.oldIdentity, [1n]);
      await runLocalFileTestHook('beforeDirectorySync', { phase: 'overwrite-recovered', path });
      await syncDirectory(parent, 'LOCAL_CLEANUP_FAILED');
    } else if (sameIdentity(destination, journal.oldIdentity)) {
      if (backup) {
        if (destination.nlink !== 2n || backup.nlink !== 2n) {
          throw localError('LOCAL_CLEANUP_FAILED');
        }
        await removeDurableRecoveryFile(
          backupPath,
          journal.oldIdentity,
          [2n],
          parent,
          'overwrite-backup-removed',
          path,
        );
        await inspectIdentity(path, journal.oldIdentity, [1n]);
      } else if (destination.nlink !== 1n) {
        throw localError('LOCAL_CLEANUP_FAILED');
      }
    } else {
      if (destination.nlink !== 1n || (backup && backup.nlink !== 1n)) {
        throw localError('LOCAL_CLEANUP_FAILED');
      }
      await verifyDownloadedPath(path, destination, journal.options);
      if (backup) {
        await removeDurableRecoveryFile(
          backupPath,
          journal.oldIdentity,
          [1n],
          parent,
          'overwrite-backup-removed',
          path,
        );
      }
    }
    await removeRecoveryJournal(journalPath, journal.identity, parent, path);
  } catch (error) {
    if (error?.code === 'LOCAL_CLEANUP_FAILED') throw error;
    throw cleanupFailure(error, 'FILE_TRANSFER_FAILED');
  }
}

async function publishOverwrite(path, temporaryPath, expected, temporaryIdentity, parent, options) {
  const { backupPath, journalPath } = overwriteRecoveryPaths(path);
  const owner = Object.freeze({
    token: randomUUID().replaceAll('-', ''),
    pid: process.pid,
    createdAt: new Date().toISOString(),
  });
  let journalIdentity;
  let backupCreated = false;
  let replaced = false;
  try {
    try {
      journalIdentity = await ownerOnlyFile(
        journalPath,
        recoveryJournalBytes(path, options, expected, owner),
        { errorCode: 'FILE_TRANSFER_FAILED' },
      );
    } catch (error) {
      await syncDirectory(parent, 'LOCAL_CLEANUP_FAILED');
      throw error;
    }
    await runLocalFileTestHook('beforeDirectorySync', {
      phase: 'overwrite-journal-created',
      path,
    });
    await syncDirectory(parent);
    await link(path, backupPath);
    backupCreated = true;
    await inspectIdentity(backupPath, expected, [2n]);
    await inspectIdentity(path, expected, [2n]);
    await syncExpectedFile(backupPath, expected, [2n], 'FILE_TRANSFER_FAILED');
    await runLocalFileTestHook('beforeDirectorySync', {
      phase: 'overwrite-backup-created',
      path,
    });
    await syncDirectory(parent);
    await runLocalFileTestHook('afterOverwriteBackupLink', { path });
    await runLocalFileTestHook('afterOverwriteBackupSync', { path });
    await runLocalFileTestHook('beforeOverwriteFinalCheck', { path });
    // Node exposes no inode-conditional rename. Keep this last verification
    // adjacent to the single atomic replacement and never hide the old name.
    await inspectIdentity(path, expected, [2n]);
    await rename(temporaryPath, path);
    replaced = true;
    await inspectIdentity(path, temporaryIdentity, [1n]);
    await inspectIdentity(backupPath, expected, [1n]);
    return { backupPath, journalPath, journalIdentity };
  } catch (error) {
    const primary = publicError(error, 'FILE_TRANSFER_FAILED');
    if (replaced) {
      await rollbackPublished({
        path,
        parent,
        publishedIdentity: temporaryIdentity,
        backupPath,
        originalIdentity: expected,
        journalPath,
        journalIdentity,
        primary,
      });
    } else {
      try {
        if (backupCreated) {
          await removeDurableRecoveryFile(
            backupPath,
            expected,
            [1n, 2n],
            parent,
            'overwrite-backup-removed',
            path,
          );
        }
        if (journalIdentity) {
          await removeRecoveryJournal(journalPath, journalIdentity, parent, path);
        }
      } catch {
        throw cleanupFailure(primary, 'FILE_TRANSFER_FAILED');
      }
    }
    throw primary;
  }
}

async function validateDownloadedEntry(path, entry, identity, options, initial = entry.stats) {
  if (!sameIdentity(initial, identity)) throw localError('FILE_INTEGRITY_FAILED');
  const bytes = await stableFileBytes(entry.file, initial, {
    minimumBytes: options.expectedBytes,
    maximumBytes: options.expectedBytes,
  }, path);
  if (createHash('sha256').update(bytes).digest('hex').toUpperCase() !== options.expectedSha256) {
    throw localError('FILE_INTEGRITY_FAILED');
  }
}

async function withDownloadedEntry(path, identity, options, operation) {
  let entry;
  let primaryError;
  try {
    entry = await openRegular(path, {
      minimumBytes: options.expectedBytes,
      maximumBytes: options.expectedBytes,
    });
    await operation(entry);
  } catch (error) {
    primaryError = error?.code === 'LOCAL_CLEANUP_FAILED'
      ? error
      : localError('FILE_INTEGRITY_FAILED');
  }
  await closeFileHandle(entry?.file, primaryError, 'FILE_INTEGRITY_FAILED');
}

async function verifyDownloadedPath(path, identity, options) {
  await withDownloadedEntry(path, identity, options, async (entry) => {
    await validateDownloadedEntry(path, entry, identity, options);
  });
}

async function syncDownloadedPath(path, identity, options) {
  await withDownloadedEntry(path, identity, options, async (entry) => {
    await validateDownloadedEntry(path, entry, identity, options);
    await runLocalFileTestHook('beforeDownloadedFileSync', { path });
    await entry.file.sync();
    await runLocalFileTestHook('afterDownloadedFileSync', { path });
    const syncedStats = await entry.file.stat({ bigint: true });
    if (
      !sameIdentity(syncedStats, identity)
      || !safeRegular(syncedStats, {
        minimumBytes: options.expectedBytes,
        maximumBytes: options.expectedBytes,
      })
    ) throw localError('FILE_INTEGRITY_FAILED');
    await validateDownloadedEntry(path, entry, identity, options, syncedStats);
  });
}

async function rollbackPublished({
  path,
  parent,
  publishedIdentity,
  backupPath,
  originalIdentity,
  journalPath,
  journalIdentity,
  primary,
}) {
  if (backupPath) {
    try {
      await runLocalFileTestHook('beforeRollbackRestore', { path });
      await inspectIdentity(path, publishedIdentity, [1n]);
      await inspectIdentity(backupPath, originalIdentity, [1n]);
      await rename(backupPath, path);
      await inspectIdentity(path, originalIdentity, [1n]);
      await runLocalFileTestHook('beforeDirectorySync', { phase: 'rollback', path });
      await syncDirectory(parent);
      if (journalPath && journalIdentity) {
        await removeRecoveryJournal(journalPath, journalIdentity, parent, path);
      }
      return;
    } catch {
      throw cleanupFailure(primary, primary?.code);
    }
  }

  const failedPath = siblingTransactionPath(path, 'failed');
  try {
    await runLocalFileTestHook('beforeRollbackRestore', { path });
    await rename(path, failedPath);
    const observed = await inspectAnyRegular(failedPath);
    if (!sameIdentity(observed, publishedIdentity)) {
      await restoreExpectedPath(failedPath, path, observed);
      throw cleanupFailure(primary, primary?.code);
    }
    await removeExpectedPath(failedPath, publishedIdentity, [1n]);
    await runLocalFileTestHook('beforeDirectorySync', { phase: 'rollback', path });
    await syncDirectory(parent);
  } catch {
    throw cleanupFailure(primary, primary?.code);
  }
}

export async function createLocalDestination(inputPath, inputOptions) {
  const path = canonicalPath(inputPath);
  const options = destinationOptions(inputOptions);
  const parent = dirname(path);
  await validateDirectory(parent);
  await reconcileOverwrite(path, parent);

  const existing = await existingDestination(path);
  const existingStats = existing?.stats;
  await closeFileHandle(existing?.file, undefined, 'REMOTE_INPUT_INVALID');
  if (existing && !options.overwrite) failInput();

  const temporaryPath = join(parent, `.${basename(path)}.${randomUUID()}.download`);
  let temporaryIdentity;
  try {
    temporaryIdentity = await ownerOnlyFile(
      temporaryPath,
      Buffer.alloc(0),
      { minimumBytes: 0 },
    );
  } catch (error) {
    throw publicError(error, 'FILE_TRANSFER_FAILED');
  }
  const close = idempotent(async () => {
    try {
      await removeOwnedFile(temporaryPath, temporaryIdentity);
    } catch (error) {
      if (error?.code === 'LOCAL_CLEANUP_FAILED') throw error;
      throw cleanupFailure();
    }
  });

  const publish = idempotent(async () => {
    await syncDownloadedPath(temporaryPath, temporaryIdentity, options);

    let current;
    let currentStats;
    try {
      current = await existingDestination(path);
      currentStats = current?.stats;
      await closeFileHandle(current?.file, undefined, 'FILE_TRANSFER_FAILED');
    } catch (error) {
      throw publishDestinationError(error);
    }
    let recovery;
    if (existingStats) {
      if (
        !currentStats
        || !sameIdentity(currentStats, existingStats)
      ) throw localError('FILE_TRANSFER_FAILED');
      recovery = await publishOverwrite(
        path,
        temporaryPath,
        existingStats,
        temporaryIdentity,
        parent,
        options,
      );
    } else {
      if (currentStats) throw localError('FILE_TRANSFER_FAILED');
      let linked = false;
      try {
        await link(temporaryPath, path);
        linked = true;
        await inspectIdentity(temporaryPath, temporaryIdentity, [2n]);
        await inspectIdentity(path, temporaryIdentity, [2n]);
        await unlink(temporaryPath);
        await inspectIdentity(path, temporaryIdentity, [1n]);
      } catch (error) {
        const primary = publicError(error, 'FILE_TRANSFER_FAILED');
        if (linked) {
          await rollbackPublished({
            path,
            parent,
            publishedIdentity: temporaryIdentity,
            backupPath: undefined,
            originalIdentity: undefined,
            primary,
          });
        }
        throw primary;
      }
    }

    let postFailure;
    try {
      await runLocalFileTestHook('beforeDirectorySync', { phase: 'published', path });
      await syncDirectory(parent);
      await runLocalFileTestHook('beforePostIntegrity', { path });
      await verifyDownloadedPath(path, temporaryIdentity, options);
    } catch (error) {
      postFailure = publicError(error, 'FILE_TRANSFER_FAILED');
    }
    if (postFailure) {
      await rollbackPublished({
        path,
        parent,
        publishedIdentity: temporaryIdentity,
        backupPath: recovery?.backupPath,
        originalIdentity: existingStats,
        journalPath: recovery?.journalPath,
        journalIdentity: recovery?.journalIdentity,
        primary: postFailure,
      });
      throw postFailure;
    }

    if (recovery) {
      await removeDurableRecoveryFile(
        recovery.backupPath,
        existingStats,
        [1n],
        parent,
        'overwrite-backup-removed',
        path,
      );
      await removeRecoveryJournal(
        recovery.journalPath,
        recovery.journalIdentity,
        parent,
        path,
      );
    }
  });

  return Object.freeze({ temporaryPath, publish, close });
}
