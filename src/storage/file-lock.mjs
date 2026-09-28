import { randomUUID } from 'node:crypto';
import { mkdir, open, readFile, rm } from 'node:fs/promises';
import { dirname } from 'node:path';
import { performance } from 'node:perf_hooks';

const FILE_LOCK_TIMEOUTS = new WeakSet();

export function isFileLockTimeout(error) {
  return FILE_LOCK_TIMEOUTS.has(error);
}

const LOCK_RETRY_DELAY_MS = 10;
const LOCK_TIMEOUT_MS = 1_000;
const MAX_LOCK_TIMEOUT_MS = 15 * 60 * 1_000;
const MAX_LOCK_RETRY_DELAY_MS = 10_000;

async function waitForLockRetry(delayMs) {
  await new Promise((resolve) => setTimeout(resolve, delayMs));
}

function validatePositiveSafeInteger(value, name, maximum) {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw new TypeError(`${name} must be a positive safe integer no greater than ${maximum}`);
  }
  return value;
}

function lockOptions(options) {
  if (
    options === null
    || typeof options !== 'object'
    || Array.isArray(options)
    || Object.getPrototypeOf(options) !== Object.prototype
    || Object.getOwnPropertySymbols(options).length !== 0
  ) throw new TypeError('file lock options must be a plain object');
  const allowed = new Set(['name', 'timeoutMs', 'retryDelayMs']);
  const snapshot = {};
  for (const key of Object.getOwnPropertyNames(options)) {
    const descriptor = Object.getOwnPropertyDescriptor(options, key);
    if (!allowed.has(key) || !descriptor || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError('file lock options are invalid');
    }
    snapshot[key] = descriptor.value;
  }
  const name = Object.hasOwn(snapshot, 'name') ? snapshot.name : 'file';
  if (typeof name !== 'string' || name.length === 0 || /[\r\n\x00-\x1f\x7f]/.test(name)) {
    throw new TypeError('file lock name must be a nonempty safe string');
  }
  return {
    name,
    timeoutMs: validatePositiveSafeInteger(
      Object.hasOwn(snapshot, 'timeoutMs') ? snapshot.timeoutMs : LOCK_TIMEOUT_MS,
      'file lock timeoutMs',
      MAX_LOCK_TIMEOUT_MS,
    ),
    retryDelayMs: validatePositiveSafeInteger(
      Object.hasOwn(snapshot, 'retryDelayMs') ? snapshot.retryDelayMs : LOCK_RETRY_DELAY_MS,
      'file lock retryDelayMs',
      MAX_LOCK_RETRY_DELAY_MS,
    ),
  };
}

function parseLockRecord(content, name) {
  const lock = JSON.parse(content);
  if (
    lock === null
    || typeof lock !== 'object'
    || typeof lock.owner !== 'string'
    || lock.owner.length === 0
    || !Number.isInteger(lock.pid)
    || lock.pid <= 0
    || typeof lock.createdAt !== 'string'
  ) {
    throw new Error(`${name} lock is corrupt`);
  }
  return lock;
}

function isProcessAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error.code === 'EPERM') return true;
    if (error.code === 'ESRCH') return false;
    throw error;
  }
}

async function describeLock(lockPath, name) {
  try {
    const lock = parseLockRecord(await readFile(lockPath, 'utf8'), name);
    const state = isProcessAlive(lock.pid) ? 'alive' : 'dead';
    return `owner=${lock.owner}, pid=${lock.pid} (${state})`;
  } catch (error) {
    if (error.code === 'ENOENT') return 'missing';
    return 'corrupt metadata';
  }
}

async function createLock(lockPath) {
  const lock = {
    owner: randomUUID(),
    pid: process.pid,
    createdAt: new Date().toISOString(),
  };
  const file = await open(lockPath, 'wx', 0o600);
  try {
    await file.writeFile(`${JSON.stringify(lock)}\n`);
    await file.sync();
  } finally {
    await file.close();
  }
  return lock;
}

async function releaseLock(lockPath, owner, name) {
  try {
    const lock = parseLockRecord(await readFile(lockPath, 'utf8'), name);
    if (lock.owner === owner) await rm(lockPath, { force: true });
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

export async function withFileLock(path, operation, options = {}) {
  const { name, timeoutMs, retryDelayMs } = lockOptions(options);
  const lockPath = `${path}.lock`;
  await mkdir(dirname(lockPath), { recursive: true, mode: 0o700 });
  const deadline = performance.now() + timeoutMs;
  let firstAttempt = true;

  while (firstAttempt || performance.now() < deadline) {
    firstAttempt = false;
    let lock;
    try {
      lock = await createLock(lockPath);
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const remainingMs = deadline - performance.now();
      if (remainingMs <= 0) break;
      await waitForLockRetry(Math.min(retryDelayMs, remainingMs));
      continue;
    }

    let primaryError;
    try {
      return await operation();
    } catch (error) {
      primaryError = error;
      throw error;
    } finally {
      try {
        await releaseLock(lockPath, lock.owner, name);
      } catch (error) {
        if (!primaryError) throw error;
      }
    }
  }

  const error = new Error(`${name} is locked: ${path} (${await describeLock(lockPath, name)})`);
  FILE_LOCK_TIMEOUTS.add(error);
  throw error;
}
