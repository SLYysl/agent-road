import { execFile as execFileCallback } from 'node:child_process';
import {
  createHash,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
import { constants } from 'node:fs';
import {
  link,
  lstat,
  mkdir,
  open,
  opendir,
  realpath,
  rmdir,
  unlink,
} from 'node:fs/promises';
import {
  dirname,
  isAbsolute,
  join,
  resolve,
} from 'node:path';
import { performance } from 'node:perf_hooks';
import { promisify } from 'node:util';
import { isProxy } from 'node:util/types';

const MAX_PATH_BYTES = 4_096;
const MAX_ARTIFACT_BYTES = 256 * 1024 ** 2;
const MAX_VERSION_LENGTH = 64;
const MAX_TIMEOUT_MS = 30 * 60 * 1_000;
const MAX_REDIRECTS = 5;
const MAX_REDIRECT_ORIGINS = 4;
const ID_PATTERN = /^[a-z][a-z0-9-]{0,63}$/u;
const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const SHA256_PATTERN = /^[A-F0-9]{64}$/u;
const INPUT_FIELDS = Object.freeze(['cacheRoot', 'artifact', 'policy', 'dependencies']);
const ARTIFACT_FIELDS = Object.freeze([
  'id',
  'version',
  'url',
  'redirectOrigins',
  'bytes',
  'sha256',
]);
const POLICY_FIELDS = Object.freeze(['timeoutMs', 'maxRedirects']);
const DEPENDENCY_FIELDS = Object.freeze(['fetch']);
const LOCK_FIELDS = Object.freeze([
  'schemaVersion',
  'owner',
  'pid',
  'createdAt',
  'artifactSha256',
  'artifactPartName',
  'lockPartName',
]);
const LOCK_OWNER_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANONICAL_TIMESTAMP_PATTERN = /^(?:19|20)[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$/u;
const LOCK_RECORD_MAX_BYTES = 512;
const LOCK_RETRY_DELAY_MS = 10;
const ORPHAN_LIMIT = 4_096;
const MAX_CHUNK_BYTES = 1024 * 1024;
const DIRECTORY_STABILITY_ATTEMPTS = 8;
const CACHE_TEST_HOOK = Symbol.for('agent-road.artifact-cache.test-hook');
const NO_TEST_HOOK = Object.freeze(async () => {});
const INTERNAL_ERRORS = new WeakSet();
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_BYTE_LENGTH_GETTER = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  'byteLength',
).get;
const TYPED_ARRAY_SET = Uint8Array.prototype.set;
const BUFFER_PROTOTYPE = Object.getPrototypeOf(Buffer.alloc(0));
const execFile = promisify(execFileCallback);

function runtimeError(code) {
  const error = new Error(code);
  error.code = code;
  INTERNAL_ERRORS.add(error);
  return error;
}

function safeErrorCode(error) {
  if (
    error === null
    || (typeof error !== 'object' && typeof error !== 'function')
    || isProxy(error)
  ) return undefined;
  let descriptor;
  try {
    descriptor = Object.getOwnPropertyDescriptor(error, 'code');
  } catch {
    return undefined;
  }
  return descriptor !== undefined
    && Object.hasOwn(descriptor, 'value')
    && typeof descriptor.value === 'string'
    ? descriptor.value
    : undefined;
}

function internalErrorCode(error) {
  return (
    error !== null
    && (typeof error === 'object' || typeof error === 'function')
    && !isProxy(error)
    && INTERNAL_ERRORS.has(error)
  ) ? safeErrorCode(error) : undefined;
}

function failInput() {
  throw runtimeError('RUNTIME_INPUT_INVALID');
}

function createDeadline(timeoutMs) {
  const expiresAt = performance.now() + timeoutMs;
  const controller = new AbortController();
  let expired = false;
  let rejectTimeout;
  const timeout = new Promise((resolve, reject) => { rejectTimeout = reject; });
  timeout.catch(() => {});

  const expire = () => {
    if (expired) return;
    expired = true;
    controller.abort();
    rejectTimeout(runtimeError('RUNTIME_ARTIFACT_TIMEOUT'));
  };
  const timer = setTimeout(expire, timeoutMs);

  const assertLive = () => {
    if (!expired && performance.now() >= expiresAt) expire();
    if (expired) throw runtimeError('RUNTIME_ARTIFACT_TIMEOUT');
  };

  return Object.freeze({
    get expired() {
      return expired;
    },
    get remainingMs() {
      return Math.max(0, expiresAt - performance.now());
    },
    signal: controller.signal,
    assertLive,
    async run(operation) {
      assertLive();
      let pending;
      try {
        pending = Promise.resolve(operation());
      } catch (error) {
        throw error;
      }
      try {
        const value = await Promise.race([pending, timeout]);
        assertLive();
        return value;
      } catch (error) {
        assertLive();
        throw error;
      }
    },
    async cleanup(operation) {
      let pending;
      try {
        pending = Promise.resolve(operation());
      } catch (error) {
        return Object.freeze({ status: 'failed', error });
      }
      pending.catch(() => {});
      if (!expired && performance.now() >= expiresAt) expire();
      if (expired) return Object.freeze({ status: 'timeout' });
      try {
        await Promise.race([pending, timeout]);
        return Object.freeze({ status: 'completed' });
      } catch (error) {
        return Object.freeze({
          status: expired ? 'timeout' : 'failed',
          ...(expired ? {} : { error }),
        });
      }
    },
    dispose() {
      clearTimeout(timer);
    },
  });
}

function preserveTimeout(error, fallbackCode) {
  if (internalErrorCode(error) === 'RUNTIME_ARTIFACT_TIMEOUT') throw error;
  throw runtimeError(fallbackCode);
}

async function assertNoDarwinExtendedAcl(paths, deadline) {
  if (process.platform !== 'darwin') return;
  const list = Array.isArray(paths) ? paths : [paths];
  let output;
  try {
    output = await deadline.run(() => execFile('/bin/ls', [
      '-lde',
      '--',
      ...list,
    ], {
      encoding: 'utf8',
      env: Object.freeze({
        LANG: 'C',
        LC_ALL: 'C',
        PATH: '/usr/bin:/bin',
      }),
      maxBuffer: 32 * 1024,
      signal: deadline.signal,
    }));
  } catch (error) {
    preserveTimeout(error, 'RUNTIME_CACHE_UNSAFE');
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
  ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
  deadline.assertLive();
}

async function openWithinDeadline(deadline, path, flags, mode) {
  let pending;
  try {
    return await deadline.run(() => {
      pending = mode === undefined ? open(path, flags) : open(path, flags, mode);
      return pending;
    });
  } catch (error) {
    if (pending) {
      pending.then(
        (file) => file.close().catch(() => {}),
        () => {},
      );
    }
    throw error;
  }
}

async function opendirWithinDeadline(deadline, path) {
  let pending;
  try {
    return await deadline.run(() => {
      pending = opendir(path);
      return pending;
    });
  } catch (error) {
    if (pending) {
      pending.then(
        (directory) => directory.close().catch(() => {}),
        () => {},
      );
    }
    throw error;
  }
}

function readExactRecord(input, fields, failureCode = 'RUNTIME_INPUT_INVALID') {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || (Object.getPrototypeOf(input) !== Object.prototype
      && Object.getPrototypeOf(input) !== null)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) throw runtimeError(failureCode);

  const names = Object.getOwnPropertyNames(input);
  if (names.length !== fields.length || !fields.every((field) => names.includes(field))) {
    throw runtimeError(failureCode);
  }
  const values = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) throw runtimeError(failureCode);
    values[field] = descriptor.value;
  }
  return values;
}

function readExactArray(input, maximumLength) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || !Array.isArray(input)
    || Object.getPrototypeOf(input) !== Array.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) failInput();

  const lengthDescriptor = Object.getOwnPropertyDescriptor(input, 'length');
  if (
    lengthDescriptor === undefined
    || !Object.hasOwn(lengthDescriptor, 'value')
    || !Number.isInteger(lengthDescriptor.value)
    || lengthDescriptor.value < 0
    || lengthDescriptor.value > maximumLength
  ) failInput();

  const length = lengthDescriptor.value;
  const names = Object.getOwnPropertyNames(input);
  if (
    names.length !== length + 1
    || !names.every((name) => name === 'length' || /^(?:0|[1-9][0-9]*)$/u.test(name))
  ) failInput();

  const values = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) failInput();
    values.push(descriptor.value);
  }
  return values;
}

function canonicalRedirectOrigins(input, sourceOrigin) {
  const values = readExactArray(input, MAX_REDIRECT_ORIGINS);
  for (const value of values) {
    if (
      typeof value !== 'string'
      || value.length === 0
      || value.length > 2_048
      || value !== value.trim()
      || /[\x00-\x20\x7F]/u.test(value)
    ) failInput();
    let parsed;
    try {
      parsed = new URL(value);
    } catch {
      failInput();
    }
    if (
      parsed.protocol !== 'https:'
      || parsed.hostname.length === 0
      || parsed.username !== ''
      || parsed.password !== ''
      || parsed.port !== ''
      || parsed.pathname !== '/'
      || parsed.search !== ''
      || parsed.hash !== ''
      || parsed.origin !== value
    ) failInput();
  }
  if (new Set(values).size !== values.length || values.includes(sourceOrigin)) failInput();
  return Object.freeze([...values].sort());
}

function validateArtifact(input) {
  const value = readExactRecord(input, ARTIFACT_FIELDS);
  if (
    typeof value.id !== 'string'
    || !ID_PATTERN.test(value.id)
    || typeof value.version !== 'string'
    || value.version.length > MAX_VERSION_LENGTH
    || !VERSION_PATTERN.test(value.version)
    || !Number.isSafeInteger(value.bytes)
    || value.bytes <= 0
    || value.bytes > MAX_ARTIFACT_BYTES
    || typeof value.sha256 !== 'string'
    || !SHA256_PATTERN.test(value.sha256)
    || typeof value.url !== 'string'
    || value.url.length === 0
    || value.url.length > 2_048
    || value.url !== value.url.trim()
    || /[\x00-\x20\x7F]/u.test(value.url)
  ) failInput();

  let url;
  try {
    url = new URL(value.url);
  } catch {
    failInput();
  }
  const versionPattern = new RegExp(
    `(?:^|[^0-9])${value.version.replaceAll('.', '\\.')}(?:[^0-9]|$)`,
    'u',
  );
  if (
    url.protocol !== 'https:'
    || url.href !== value.url
    || url.hostname.length === 0
    || url.username !== ''
    || url.password !== ''
    || url.port !== ''
    || url.search !== ''
    || url.hash !== ''
    || url.pathname.includes('%')
    || url.pathname.toLowerCase().includes('latest')
    || !versionPattern.test(url.pathname)
    || !url.pathname.endsWith('.zip')
  ) failInput();
  return Object.freeze({
    id: value.id,
    version: value.version,
    url: value.url,
    redirectOrigins: canonicalRedirectOrigins(value.redirectOrigins, url.origin),
    bytes: value.bytes,
    sha256: value.sha256,
  });
}

function validateInput(input) {
  const value = readExactRecord(input, INPUT_FIELDS);
  const artifact = validateArtifact(value.artifact);
  const policy = readExactRecord(value.policy, POLICY_FIELDS);
  const dependencies = readExactRecord(value.dependencies, DEPENDENCY_FIELDS);
  if (
    typeof value.cacheRoot !== 'string'
    || value.cacheRoot.length === 0
    || Buffer.byteLength(value.cacheRoot, 'utf8') > MAX_PATH_BYTES
    || value.cacheRoot.includes('\0')
    || !isAbsolute(value.cacheRoot)
    || resolve(value.cacheRoot) !== value.cacheRoot
    || !Number.isSafeInteger(policy.timeoutMs)
    || policy.timeoutMs <= 0
    || policy.timeoutMs > MAX_TIMEOUT_MS
    || !Number.isSafeInteger(policy.maxRedirects)
    || policy.maxRedirects < 0
    || policy.maxRedirects > MAX_REDIRECTS
    || typeof dependencies.fetch !== 'function'
    || isProxy(dependencies.fetch)
  ) failInput();
  return {
    cacheRoot: value.cacheRoot,
    artifact,
    policy: Object.freeze({ ...policy }),
    fetch: dependencies.fetch,
  };
}

async function runCacheTestHook(event, context) {
  let hook = NO_TEST_HOOK;
  if (process.env.NODE_TEST_CONTEXT !== undefined) {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, CACHE_TEST_HOOK);
    if (descriptor && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'function') {
      hook = descriptor.value;
    }
  }
  await hook(event, Object.freeze({ ...context }));
}

async function ownerOnlyDirectory(path, deadline, recursive = false) {
  try {
    try {
      await deadline.run(() => mkdir(path, { recursive, mode: 0o700 }));
    } catch (error) {
      if (safeErrorCode(error) !== 'EEXIST') throw error;
    }
    const stats = await deadline.run(() => lstat(path));
    if (
      !stats.isDirectory()
      || stats.isSymbolicLink()
      || (stats.mode & 0o777) !== 0o700
      || (typeof process.getuid === 'function' && stats.uid !== process.getuid())
    ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
  } catch (error) {
    preserveTimeout(error, 'RUNTIME_CACHE_UNSAFE');
  }
}

async function assertOwnerOnlyDirectories(paths, deadline, expectedIdentities) {
  try {
    for (let attempt = 0; attempt < DIRECTORY_STABILITY_ATTEMPTS; attempt += 1) {
      const before = await deadline.run(() => Promise.all(
        paths.map((path) => lstat(path, { bigint: true })),
      ));
      for (const stats of before) {
        if (
          !stats.isDirectory()
          || stats.isSymbolicLink()
          || (stats.mode & 0o777n) !== 0o700n
          || (typeof process.getuid === 'function' && stats.uid !== BigInt(process.getuid()))
        ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
      }
      await assertNoDarwinExtendedAcl(paths, deadline);
      await deadline.run(() => runCacheTestHook('afterDirectoryAclCheck', {
        paths: Object.freeze([...paths]),
      }));
      const after = await deadline.run(() => Promise.all(
        paths.map((path) => lstat(path, { bigint: true })),
      ));
      if (before.every((stats, index) => sameMetadata(stats, after[index]))) {
        if (
          expectedIdentities !== undefined
          && (
            expectedIdentities.length !== after.length
            || !after.every((stats, index) => sameIdentity(stats, expectedIdentities[index]))
          )
        ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
        return Object.freeze(after.map((stats) => Object.freeze({
          dev: stats.dev,
          ino: stats.ino,
        })));
      }
    }
    throw runtimeError('RUNTIME_CACHE_UNSAFE');
  } catch (error) {
    preserveTimeout(error, 'RUNTIME_CACHE_UNSAFE');
  }
}

async function assertOwnerOnlyRealParent(path, deadline, expectedIdentity) {
  const parent = dirname(path);
  try {
    for (let attempt = 0; attempt < DIRECTORY_STABILITY_ATTEMPTS; attempt += 1) {
      const [stats, canonical] = await deadline.run(() => Promise.all([
        lstat(parent, { bigint: true }),
        realpath(parent),
      ]));
      if (
        canonical !== parent
        || !stats.isDirectory()
        || stats.isSymbolicLink()
        || (stats.mode & 0o777n) !== 0o700n
        || (typeof process.getuid === 'function' && stats.uid !== BigInt(process.getuid()))
      ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
      await assertNoDarwinExtendedAcl(parent, deadline);
      const [after, canonicalAfter] = await deadline.run(() => Promise.all([
        lstat(parent, { bigint: true }),
        realpath(parent),
      ]));
      if (canonicalAfter === parent && sameMetadata(stats, after)) {
        if (expectedIdentity !== undefined && !sameIdentity(after, expectedIdentity)) {
          throw runtimeError('RUNTIME_CACHE_UNSAFE');
        }
        return Object.freeze({ dev: after.dev, ino: after.ino });
      }
    }
    throw runtimeError('RUNTIME_CACHE_UNSAFE');
  } catch (error) {
    preserveTimeout(error, 'RUNTIME_CACHE_UNSAFE');
  }
}

async function assertPinnedDirectoryIdentities(
  cacheRoot,
  parentIdentity,
  directoryPaths,
  directoryIdentities,
) {
  const parent = dirname(cacheRoot);
  let canonical;
  let stats;
  try {
    [canonical, ...stats] = await Promise.all([
      realpath(parent),
      lstat(parent, { bigint: true }),
      ...directoryPaths.map((path) => lstat(path, { bigint: true })),
    ]);
  } catch {
    throw runtimeError('RUNTIME_CACHE_UNSAFE');
  }
  const [parentStats, ...directoryStats] = stats;
  if (
    canonical !== parent
    || !parentStats.isDirectory()
    || parentStats.isSymbolicLink()
    || !sameIdentity(parentStats, parentIdentity)
    || (parentStats.mode & 0o777n) !== 0o700n
    || (typeof process.getuid === 'function'
      && parentStats.uid !== BigInt(process.getuid()))
    || directoryStats.length !== directoryIdentities.length
    || directoryStats.some((entry, index) => (
      !entry.isDirectory()
      || entry.isSymbolicLink()
      || !sameIdentity(entry, directoryIdentities[index])
      || (entry.mode & 0o777n) !== 0o700n
      || (typeof process.getuid === 'function'
        && entry.uid !== BigInt(process.getuid()))
    ))
  ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
}

function resultFor(cacheRoot, artifact) {
  return Object.freeze({
    artifactId: artifact.id,
    version: artifact.version,
    path: join(cacheRoot, 'objects', `${artifact.sha256}.bin`),
    bytes: artifact.bytes,
    sha256: artifact.sha256,
  });
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
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

function safeCacheFile(fileStats, pathStats, allowedLinks = Object.freeze([1n])) {
  return fileStats.isFile()
    && !pathStats.isSymbolicLink()
    && pathStats.isFile()
    && sameMetadata(fileStats, pathStats)
    && allowedLinks.includes(fileStats.nlink)
    && (fileStats.mode & 0o777n) === 0o600n
    && (typeof process.getuid !== 'function' || fileStats.uid === BigInt(process.getuid()));
}

async function hashOpenFile(file, size, deadline) {
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, Math.max(1, size)));
  let offset = 0;
  while (offset < size) {
    const length = Math.min(buffer.length, size - offset);
    const { bytesRead } = await deadline.run(() => file.read(buffer, 0, length, offset));
    if (bytesRead !== length) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    hash.update(buffer.subarray(0, bytesRead));
    offset += bytesRead;
  }
  return hash.digest();
}

async function inspectCache(path, artifact, deadline, allowedLinks = Object.freeze([1n])) {
  let file;
  let primary;
  let result;
  try {
    file = await openWithinDeadline(
      deadline,
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const before = await deadline.run(() => file.stat({ bigint: true }));
    const pathBefore = await deadline.run(() => lstat(path, { bigint: true }));
    if (!safeCacheFile(before, pathBefore, allowedLinks)) {
      throw runtimeError('RUNTIME_CACHE_UNSAFE');
    }
    await assertNoDarwinExtendedAcl(path, deadline);
    const aclBefore = await deadline.run(() => file.stat({ bigint: true }));
    const aclPathBefore = await deadline.run(() => lstat(path, { bigint: true }));
    if (
      !sameMetadata(before, aclBefore)
      || !sameMetadata(aclBefore, aclPathBefore)
    ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    if (before.size !== BigInt(artifact.bytes)) {
      const after = await deadline.run(() => file.stat({ bigint: true }));
      const pathAfter = await deadline.run(() => lstat(path, { bigint: true }));
      if (!sameMetadata(before, after) || !sameMetadata(after, pathAfter)) {
        throw runtimeError('RUNTIME_CACHE_UNSAFE');
      }
      result = { status: 'poison', identity: after };
    } else {
      const first = await hashOpenFile(file, artifact.bytes, deadline);
      await deadline.run(() => runCacheTestHook('afterCacheFirstRead', { path }));
      const middle = await deadline.run(() => file.stat({ bigint: true }));
      const second = await hashOpenFile(file, artifact.bytes, deadline);
      await assertNoDarwinExtendedAcl(path, deadline);
      const after = await deadline.run(() => file.stat({ bigint: true }));
      const pathAfter = await deadline.run(() => lstat(path, { bigint: true }));
      if (
        !sameMetadata(before, middle)
        || !sameMetadata(middle, after)
        || !sameMetadata(after, pathAfter)
        || !timingSafeEqual(first, second)
      ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
      const expected = Buffer.from(artifact.sha256, 'hex');
      result = {
        status: timingSafeEqual(second, expected) ? 'valid' : 'poison',
        identity: after,
      };
    }
  } catch (error) {
    if (!file && safeErrorCode(error) === 'ENOENT') {
      result = { status: 'missing' };
    } else {
      primary = internalErrorCode(error) === 'RUNTIME_ARTIFACT_TIMEOUT'
        ? error
        : internalErrorCode(error) === 'RUNTIME_CACHE_UNSAFE'
          ? error
          : runtimeError('RUNTIME_CACHE_UNSAFE');
    }
  } finally {
    if (file) {
      const cleanup = await deadline.cleanup(() => file.close());
      if (cleanup.status === 'timeout') {
        primary = runtimeError('RUNTIME_ARTIFACT_TIMEOUT');
      } else if (cleanup.status === 'failed') {
        primary = runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
      }
    }
  }
  if (primary) throw primary;
  return result;
}

async function removePoison(path, expected, deadline, assertPinned = NO_TEST_HOOK) {
  try {
    const observed = await deadline.run(() => lstat(path, { bigint: true }));
    if (!sameMetadata(observed, expected)) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    await deadline.run(assertPinned);
    await deadline.run(() => unlink(path));
  } catch (error) {
    if (internalErrorCode(error) === 'RUNTIME_ARTIFACT_TIMEOUT') throw error;
    if (internalErrorCode(error) === 'RUNTIME_CACHE_UNSAFE') throw error;
    throw runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
  }
}

function redirectUrl(current, location, seen, allowedOrigins) {
  if (
    typeof location !== 'string'
    || location.length === 0
    || location.length > 4_096
    || /[\x00-\x20\x7F]/u.test(location)
  ) throw runtimeError('RUNTIME_ARTIFACT_REDIRECT_INVALID');
  let next;
  try {
    next = new URL(location, current);
  } catch {
    throw runtimeError('RUNTIME_ARTIFACT_REDIRECT_INVALID');
  }
  if (
    next.protocol !== 'https:'
    || next.hostname.length === 0
    || next.username !== ''
    || next.password !== ''
    || next.port !== ''
    || next.hash !== ''
    || !allowedOrigins.has(next.origin)
    || seen.has(next.href)
  ) throw runtimeError('RUNTIME_ARTIFACT_REDIRECT_INVALID');
  return next.href;
}

async function syncDirectory(path, deadline) {
  let directory;
  let primary;
  try {
    directory = await openWithinDeadline(
      deadline,
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    await deadline.run(() => directory.sync());
  } catch (error) {
    primary = internalErrorCode(error) === 'RUNTIME_ARTIFACT_TIMEOUT'
      ? error
      : runtimeError('RUNTIME_CACHE_FAILED');
  } finally {
    if (directory) {
      const cleanup = await deadline.cleanup(() => directory.close());
      if (cleanup.status === 'timeout') {
        primary = runtimeError('RUNTIME_ARTIFACT_TIMEOUT');
      } else if (cleanup.status === 'failed') {
        primary = runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
      }
    }
  }
  if (primary) throw primary;
}

async function removeTemporary(path, expected, assertPinned = NO_TEST_HOOK) {
  let observed;
  try {
    observed = await lstat(path, { bigint: true });
  } catch (error) {
    if (safeErrorCode(error) === 'ENOENT') return;
    throw runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
  }
  if (
    !observed.isFile()
    || observed.isSymbolicLink()
    || !sameIdentity(observed, expected)
    || ![1n, 2n].includes(observed.nlink)
    || (observed.mode & 0o777n) !== 0o600n
    || (typeof process.getuid === 'function' && observed.uid !== BigInt(process.getuid()))
  ) throw runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
  try {
    await assertPinned();
    await unlink(path);
  } catch {
    throw runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
  }
  let directory;
  try {
    directory = await open(
      dirname(path),
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    await directory.sync();
  } catch {
    throw runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
  } finally {
    try { await directory?.close(); } catch {
      throw runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
    }
  }
}

async function publishTemporary(
  temporaryPath,
  destinationPath,
  identity,
  deadline,
  assertPinned = NO_TEST_HOOK,
) {
  const parent = join(destinationPath, '..');
  try {
    const before = await deadline.run(() => lstat(temporaryPath, { bigint: true }));
    if (
      !sameMetadata(before, identity)
      || !safeCacheFile(before, before)
    ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    await assertNoDarwinExtendedAcl(temporaryPath, deadline);
    const aclBefore = await deadline.run(() => lstat(temporaryPath, { bigint: true }));
    if (!sameMetadata(before, aclBefore)) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    await deadline.run(assertPinned);
    await deadline.run(() => link(temporaryPath, destinationPath));
    await deadline.run(() => runCacheTestHook('afterPublishLink', {
      path: destinationPath,
      temporaryPath,
    }));
    const temporary = await deadline.run(() => lstat(temporaryPath, { bigint: true }));
    const destination = await deadline.run(() => lstat(destinationPath, { bigint: true }));
    if (
      !sameIdentity(temporary, identity)
      || !sameIdentity(destination, identity)
      || temporary.nlink !== 2n
      || destination.nlink !== 2n
      || !safeCacheFile(temporary, destination, Object.freeze([2n]))
    ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    await assertNoDarwinExtendedAcl([temporaryPath, destinationPath], deadline);
    const aclTemporary = await deadline.run(() => lstat(temporaryPath, { bigint: true }));
    const aclDestination = await deadline.run(() => lstat(destinationPath, { bigint: true }));
    if (
      !sameMetadata(temporary, aclTemporary)
      || !sameMetadata(destination, aclDestination)
    ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    await deadline.run(assertPinned);
    await deadline.run(() => unlink(temporaryPath));
    const published = await deadline.run(() => lstat(destinationPath, { bigint: true }));
    if (
      !sameIdentity(published, identity)
      || published.nlink !== 1n
      || !safeCacheFile(published, published)
    ) {
      throw runtimeError('RUNTIME_CACHE_UNSAFE');
    }
    await assertNoDarwinExtendedAcl(destinationPath, deadline);
    const aclPublished = await deadline.run(() => lstat(destinationPath, { bigint: true }));
    if (!sameMetadata(published, aclPublished)) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    await syncDirectory(parent, deadline);
    return aclPublished;
  } catch (error) {
    if (internalErrorCode(error) === 'RUNTIME_CACHE_UNSAFE') throw error;
    if (internalErrorCode(error) === 'RUNTIME_CACHE_FAILED') throw error;
    if (internalErrorCode(error) === 'RUNTIME_ARTIFACT_TIMEOUT') throw error;
    throw runtimeError('RUNTIME_CACHE_UNSAFE');
  }
}

function canonicalLockRecord(record) {
  return `${JSON.stringify(record)}\n`;
}

function parseLockRecord(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
    || Object.getOwnPropertySymbols(value).length !== 0
  ) return undefined;
  const names = Object.getOwnPropertyNames(value);
  if (
    names.length !== LOCK_FIELDS.length
    || !LOCK_FIELDS.every((field, index) => names[index] === field)
  ) return undefined;
  for (const field of LOCK_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) return undefined;
  }
  if (
    value.schemaVersion !== 1
    || typeof value.owner !== 'string'
    || !LOCK_OWNER_PATTERN.test(value.owner)
    || !Number.isSafeInteger(value.pid)
    || value.pid <= 0
    || value.pid > 2_147_483_647
    || typeof value.createdAt !== 'string'
    || !CANONICAL_TIMESTAMP_PATTERN.test(value.createdAt)
    || Number.isNaN(Date.parse(value.createdAt))
    || new Date(value.createdAt).toISOString() !== value.createdAt
    || typeof value.artifactSha256 !== 'string'
    || !SHA256_PATTERN.test(value.artifactSha256)
    || typeof value.artifactPartName !== 'string'
    || value.artifactPartName
      !== `.${value.artifactSha256}.${value.owner}.part`
    || typeof value.lockPartName !== 'string'
    || value.lockPartName
      !== `.${value.artifactSha256}.${value.owner}.lock.part`
    || canonicalLockRecord(value) !== text
  ) return undefined;
  return Object.freeze({ ...value });
}

function safeLockEndpoint(stats, allowedLinks = Object.freeze([1n])) {
  return stats.isFile()
    && !stats.isSymbolicLink()
    && allowedLinks.includes(stats.nlink)
    && (stats.mode & 0o777n) === 0o600n
    && (typeof process.getuid !== 'function' || stats.uid === BigInt(process.getuid()));
}

function safeLockMetadata(fileStats, pathStats, allowedLinks = Object.freeze([1n])) {
  return safeLockEndpoint(fileStats, allowedLinks)
    && safeLockEndpoint(pathStats, allowedLinks)
    && sameMetadata(fileStats, pathStats);
}

function safeLockFile(fileStats, pathStats, allowedLinks = Object.freeze([1n])) {
  return safeLockMetadata(fileStats, pathStats, allowedLinks)
    && fileStats.size > 0n
    && fileStats.size <= BigInt(LOCK_RECORD_MAX_BYTES);
}

function safeLockLinkCompletion(before, fileAfter, pathAfter) {
  return before.nlink === 2n
    && fileAfter.nlink === 1n
    && sameIdentity(before, fileAfter)
    && sameIdentity(fileAfter, pathAfter)
    && safeLockFile(fileAfter, pathAfter)
    && before.size === fileAfter.size
    && before.mode === fileAfter.mode
    && before.uid === fileAfter.uid
    && before.gid === fileAfter.gid
    && before.mtimeNs === fileAfter.mtimeNs;
}

async function readExactOpenFile(file, size, deadline) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const result = await deadline.run(() => file.read(bytes, offset, size - offset, offset));
    if (result.bytesRead <= 0) return undefined;
    offset += result.bytesRead;
  }
  return bytes;
}

async function pathIsMissing(path, deadline) {
  try {
    await deadline.run(() => lstat(path, { bigint: true }));
    return false;
  } catch (error) {
    if (safeErrorCode(error) === 'ENOENT') return true;
    if (internalErrorCode(error) === 'RUNTIME_ARTIFACT_TIMEOUT') throw error;
    return false;
  }
}

async function readLockSnapshot(path, artifactSha256, deadline, allowedLinks) {
  let file;
  let primary;
  let result;
  try {
    file = await openWithinDeadline(
      deadline,
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const before = await deadline.run(() => file.stat({ bigint: true }));
    const pathBefore = await deadline.run(() => lstat(path, { bigint: true }));
    if (
      !safeLockFile(before, pathBefore, allowedLinks)
    ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    try {
      await assertNoDarwinExtendedAcl(path, deadline);
    } catch (error) {
      if (
        internalErrorCode(error) === 'RUNTIME_CACHE_UNSAFE'
        && await pathIsMissing(path, deadline)
      ) throw runtimeError('RUNTIME_CACHE_LOCK_RETRY');
      throw error;
    }
    const aclBefore = await deadline.run(() => file.stat({ bigint: true }));
    const aclPathBefore = await deadline.run(() => lstat(path, { bigint: true }));
    if (
      !sameMetadata(before, aclBefore)
      || !sameMetadata(aclBefore, aclPathBefore)
    ) {
      if (safeLockLinkCompletion(before, aclBefore, aclPathBefore)) {
        throw runtimeError('RUNTIME_CACHE_LOCK_RETRY');
      }
      throw runtimeError('RUNTIME_CACHE_UNSAFE');
    }
    const bytes = await readExactOpenFile(file, Number(before.size), deadline);
    try {
      await assertNoDarwinExtendedAcl(path, deadline);
    } catch (error) {
      if (
        internalErrorCode(error) === 'RUNTIME_CACHE_UNSAFE'
        && await pathIsMissing(path, deadline)
      ) throw runtimeError('RUNTIME_CACHE_LOCK_RETRY');
      throw error;
    }
    const after = await deadline.run(() => file.stat({ bigint: true }));
    const pathAfter = await deadline.run(() => lstat(path, { bigint: true }));
    if (
      bytes === undefined
      || !sameMetadata(before, after)
      || !sameMetadata(after, pathAfter)
    ) {
      if (bytes !== undefined && safeLockLinkCompletion(before, after, pathAfter)) {
        throw runtimeError('RUNTIME_CACHE_LOCK_RETRY');
      }
      throw runtimeError('RUNTIME_CACHE_UNSAFE');
    }
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      text = undefined;
    }
    const record = typeof text === 'string' ? parseLockRecord(text) : undefined;
    if (record === undefined || record.artifactSha256 !== artifactSha256) {
      throw runtimeError('RUNTIME_CACHE_UNSAFE');
    }
    result = Object.freeze({ status: 'valid', identity: after, record });
  } catch (error) {
    if (safeErrorCode(error) === 'ENOENT') {
      result = Object.freeze({ status: 'missing' });
    } else if (internalErrorCode(error) === 'RUNTIME_CACHE_LOCK_RETRY') {
      result = Object.freeze({ status: 'retry' });
    } else {
      primary = internalErrorCode(error) === 'RUNTIME_ARTIFACT_TIMEOUT'
        ? error
        : runtimeError('RUNTIME_CACHE_UNSAFE');
    }
  } finally {
    if (file) {
      const cleanup = await deadline.cleanup(() => file.close());
      if (cleanup.status === 'timeout') {
        primary = runtimeError('RUNTIME_ARTIFACT_TIMEOUT');
      } else if (cleanup.status === 'failed') {
        primary = runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
      }
    }
  }
  if (primary) throw primary;
  return result;
}

async function lockPublicationCompleted(lockPath, lockPartPath, snapshot, deadline) {
  let final;
  try {
    final = await deadline.run(() => lstat(lockPath, { bigint: true }));
    await deadline.run(() => lstat(lockPartPath, { bigint: true }));
    return false;
  } catch (error) {
    if (safeErrorCode(error) !== 'ENOENT') {
      if (internalErrorCode(error) === 'RUNTIME_ARTIFACT_TIMEOUT') throw error;
      return false;
    }
  }
  return final !== undefined
    && sameIdentity(final, snapshot.identity)
    && safeLockEndpoint(final)
    && final.size === snapshot.identity.size;
}

async function inspectCacheLock(lockPath, artifactSha256, deadline) {
  const snapshot = await readLockSnapshot(
    lockPath,
    artifactSha256,
    deadline,
    Object.freeze([1n, 2n]),
  );
  if (
    snapshot.status === 'missing'
    || snapshot.status === 'retry'
    || snapshot.identity.nlink === 1n
  ) return snapshot;

  const lockPartPath = join(dirname(lockPath), snapshot.record.lockPartName);
  let lockPart;
  try {
    lockPart = await deadline.run(() => lstat(lockPartPath, { bigint: true }));
  } catch (error) {
    if (
      safeErrorCode(error) === 'ENOENT'
      && await lockPublicationCompleted(lockPath, lockPartPath, snapshot, deadline)
    ) {
      return Object.freeze({ status: 'retry' });
    }
    preserveTimeout(error, 'RUNTIME_CACHE_UNSAFE');
  }
  if (
    !safeLockEndpoint(lockPart, Object.freeze([2n]))
    || !sameMetadata(lockPart, snapshot.identity)
  ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
  try {
    await assertNoDarwinExtendedAcl([lockPath, lockPartPath], deadline);
  } catch (error) {
    if (
      internalErrorCode(error) === 'RUNTIME_CACHE_UNSAFE'
      && await lockPublicationCompleted(lockPath, lockPartPath, snapshot, deadline)
    ) {
      return Object.freeze({ status: 'retry' });
    }
    throw error;
  }
  let finalAfter;
  let partAfter;
  try {
    [finalAfter, partAfter] = await deadline.run(() => Promise.all([
      lstat(lockPath, { bigint: true }),
      lstat(lockPartPath, { bigint: true }),
    ]));
  } catch (error) {
    if (
      safeErrorCode(error) === 'ENOENT'
      && await lockPublicationCompleted(lockPath, lockPartPath, snapshot, deadline)
    ) {
      return Object.freeze({ status: 'retry' });
    }
    preserveTimeout(error, 'RUNTIME_CACHE_UNSAFE');
  }
  if (
    !sameMetadata(finalAfter, snapshot.identity)
    || !sameMetadata(partAfter, snapshot.identity)
  ) {
    if (
      sameIdentity(finalAfter, snapshot.identity)
      && safeLockEndpoint(finalAfter)
      && finalAfter.size === snapshot.identity.size
    ) return Object.freeze({ status: 'retry' });
    throw runtimeError('RUNTIME_CACHE_UNSAFE');
  }
  return Object.freeze({ ...snapshot, lockPartPath });
}

function processIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    const code = safeErrorCode(error);
    if (code === 'EPERM') return true;
    if (code === 'ESRCH') return false;
    throw runtimeError('RUNTIME_CACHE_LOCKED');
  }
}

function safeCacheGate(stats) {
  return stats.isDirectory()
    && !stats.isSymbolicLink()
    && (stats.mode & 0o777n) === 0o700n
    && (typeof process.getuid !== 'function' || stats.uid === BigInt(process.getuid()));
}

async function inspectCacheGate(gatePath, deadline) {
  let before;
  try {
    before = await deadline.run(() => lstat(gatePath, { bigint: true }));
  } catch (error) {
    if (safeErrorCode(error) === 'ENOENT') return Object.freeze({ status: 'missing' });
    preserveTimeout(error, 'RUNTIME_CACHE_UNSAFE');
  }
  if (!safeCacheGate(before)) throw runtimeError('RUNTIME_CACHE_UNSAFE');
  try {
    await assertNoDarwinExtendedAcl(gatePath, deadline);
  } catch (error) {
    if (
      internalErrorCode(error) === 'RUNTIME_CACHE_UNSAFE'
      && await pathIsMissing(gatePath, deadline)
    ) return Object.freeze({ status: 'missing' });
    throw error;
  }
  let after;
  try {
    after = await deadline.run(() => lstat(gatePath, { bigint: true }));
  } catch (error) {
    if (safeErrorCode(error) === 'ENOENT') return Object.freeze({ status: 'missing' });
    preserveTimeout(error, 'RUNTIME_CACHE_UNSAFE');
  }
  if (!sameMetadata(before, after)) throw runtimeError('RUNTIME_CACHE_UNSAFE');
  return Object.freeze({ status: 'busy' });
}

async function releaseCacheGateRaw(gatePath, identity, assertPinned) {
  await assertPinned();
  const observed = await lstat(gatePath, { bigint: true });
  if (!safeCacheGate(observed) || !sameMetadata(observed, identity)) {
    throw runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
  }
  await rmdir(gatePath);
  let directory;
  try {
    directory = await open(
      dirname(gatePath),
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    await directory.sync();
  } finally {
    await directory?.close();
  }
}

async function tryCreateCacheGate(gatePath, deadline, assertPinned) {
  await deadline.run(assertPinned);
  try {
    await deadline.run(() => mkdir(gatePath, { mode: 0o700 }));
  } catch (error) {
    if (safeErrorCode(error) === 'EEXIST') return inspectCacheGate(gatePath, deadline);
    preserveTimeout(error, 'RUNTIME_CACHE_UNSAFE');
  }

  let identity;
  let primary;
  try {
    const before = await deadline.run(() => lstat(gatePath, { bigint: true }));
    if (!safeCacheGate(before)) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    await assertNoDarwinExtendedAcl(gatePath, deadline);
    const after = await deadline.run(() => lstat(gatePath, { bigint: true }));
    if (!sameMetadata(before, after)) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    identity = after;
    await syncDirectory(dirname(gatePath), deadline);
    await deadline.run(assertPinned);
    await deadline.run(() => runCacheTestHook('afterCacheRecoveryGateAcquired', {
      gatePath,
    }));
  } catch (error) {
    primary = internalErrorCode(error) === 'RUNTIME_ARTIFACT_TIMEOUT'
      ? error
      : internalErrorCode(error) === 'RUNTIME_CACHE_UNSAFE'
        ? error
        : runtimeError('RUNTIME_CACHE_UNSAFE');
  }
  if (primary) {
    if (identity !== undefined) {
      await deadline.cleanup(() => releaseCacheGateRaw(gatePath, identity, assertPinned));
    }
    throw primary;
  }
  return Object.freeze({ status: 'owned', identity });
}

async function removeExactPath(path, expected, deadline, assertPinned = NO_TEST_HOOK) {
  let observed;
  try {
    observed = await deadline.run(() => lstat(path, { bigint: true }));
  } catch (error) {
    if (safeErrorCode(error) === 'ENOENT') return false;
    if (internalErrorCode(error) === 'RUNTIME_ARTIFACT_TIMEOUT') throw error;
    throw runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
  }
  if (!sameMetadata(observed, expected)) return false;
  try {
    await deadline.run(assertPinned);
    await deadline.run(() => unlink(path));
  } catch (error) {
    if (safeErrorCode(error) === 'ENOENT') return false;
    if (internalErrorCode(error) === 'RUNTIME_ARTIFACT_TIMEOUT') throw error;
    throw runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
  }
  await syncDirectory(dirname(path), deadline);
  return true;
}

async function removeCreatedLockRaw(path, expected, assertPinned) {
  try { await removeTemporary(path, expected, assertPinned); } catch {}
}

async function tryCreateCacheLock(lockPath, artifact, deadline, assertPinned) {
  const owner = randomUUID();
  const artifactPartName = `.${artifact.sha256}.${owner}.part`;
  const lockPartName = `.${artifact.sha256}.${owner}.lock.part`;
  const lockPartPath = join(dirname(lockPath), lockPartName);
  const record = Object.freeze({
    schemaVersion: 1,
    owner,
    pid: process.pid,
    createdAt: new Date().toISOString(),
    artifactSha256: artifact.sha256,
    artifactPartName,
    lockPartName,
  });
  const content = Buffer.from(canonicalLockRecord(record), 'utf8');
  if (content.length > LOCK_RECORD_MAX_BYTES) throw runtimeError('RUNTIME_CACHE_UNSAFE');
  let file;
  let createdIdentity;
  let publishedIdentity;
  let primary;
  try {
    file = await openWithinDeadline(
      deadline,
      lockPartPath,
      constants.O_WRONLY
        | constants.O_CREAT
        | constants.O_EXCL
        | constants.O_NOFOLLOW
        | constants.O_NONBLOCK,
      0o600,
    );
  } catch (error) {
    if (internalErrorCode(error) === 'RUNTIME_ARTIFACT_TIMEOUT') throw error;
    throw runtimeError('RUNTIME_CACHE_UNSAFE');
  }

  try {
    createdIdentity = await deadline.run(() => file.stat({ bigint: true }));
    const pathBefore = await deadline.run(() => lstat(lockPartPath, { bigint: true }));
    if (
      !createdIdentity.isFile()
      || createdIdentity.isSymbolicLink()
      || !sameMetadata(createdIdentity, pathBefore)
      || createdIdentity.nlink !== 1n
      || createdIdentity.size !== 0n
      || (createdIdentity.mode & 0o777n) !== 0o600n
      || (typeof process.getuid === 'function'
        && createdIdentity.uid !== BigInt(process.getuid()))
    ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    await assertNoDarwinExtendedAcl(lockPartPath, deadline);
    const aclBefore = await deadline.run(() => lstat(lockPartPath, { bigint: true }));
    if (!sameMetadata(createdIdentity, aclBefore)) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    const write = await deadline.run(() => file.write(content, 0, content.length, 0));
    if (write.bytesWritten !== content.length) throw runtimeError('RUNTIME_CACHE_FAILED');
    await deadline.run(() => file.sync());
    const after = await deadline.run(() => file.stat({ bigint: true }));
    const pathAfter = await deadline.run(() => lstat(lockPartPath, { bigint: true }));
    if (
      !safeLockFile(after, pathAfter)
      || after.size !== BigInt(content.length)
    ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    createdIdentity = after;
  } catch (error) {
    primary = internalErrorCode(error) === 'RUNTIME_ARTIFACT_TIMEOUT'
      ? error
      : internalErrorCode(error) === 'RUNTIME_CACHE_UNSAFE'
        ? error
        : runtimeError('RUNTIME_CACHE_FAILED');
  } finally {
    const cleanup = await deadline.cleanup(() => file.close());
    if (cleanup.status === 'timeout') {
      primary = runtimeError('RUNTIME_ARTIFACT_TIMEOUT');
    } else if (cleanup.status === 'failed') {
      primary = runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
    }
  }

  if (!primary) {
    try {
      await syncDirectory(dirname(lockPath), deadline);
      await deadline.run(() => runCacheTestHook('afterLockTemporarySyncBeforePublish', {
        lockPath,
        lockPartPath,
      }));
      const beforePublish = await deadline.run(() => lstat(lockPartPath, { bigint: true }));
      if (!sameMetadata(beforePublish, createdIdentity)) {
        throw runtimeError('RUNTIME_CACHE_UNSAFE');
      }
      await assertNoDarwinExtendedAcl(lockPartPath, deadline);
      const aclBeforePublish = await deadline.run(() => lstat(lockPartPath, { bigint: true }));
      if (!sameMetadata(aclBeforePublish, createdIdentity)) {
        throw runtimeError('RUNTIME_CACHE_UNSAFE');
      }
      try {
        await deadline.run(assertPinned);
        await deadline.run(() => link(lockPartPath, lockPath));
      } catch (error) {
        if (safeErrorCode(error) === 'EEXIST') {
          await deadline.run(() => removeTemporary(
            lockPartPath,
            createdIdentity,
            assertPinned,
          ));
          await syncDirectory(dirname(lockPath), deadline);
          return undefined;
        }
        throw error;
      }
      const linkedPart = await deadline.run(() => lstat(lockPartPath, { bigint: true }));
      const linkedFinal = await deadline.run(() => lstat(lockPath, { bigint: true }));
      if (
        !safeLockMetadata(linkedPart, linkedFinal, Object.freeze([2n]))
        || !sameIdentity(linkedPart, createdIdentity)
      ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
      await assertNoDarwinExtendedAcl([lockPartPath, lockPath], deadline);
      const aclLinkedPart = await deadline.run(() => lstat(lockPartPath, { bigint: true }));
      const aclLinkedFinal = await deadline.run(() => lstat(lockPath, { bigint: true }));
      if (
        !sameMetadata(aclLinkedPart, linkedPart)
        || !sameMetadata(aclLinkedFinal, linkedFinal)
      ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
      publishedIdentity = aclLinkedFinal;
      await deadline.run(assertPinned);
      await deadline.run(() => unlink(lockPartPath));
      const final = await deadline.run(() => lstat(lockPath, { bigint: true }));
      if (
        !sameIdentity(final, publishedIdentity)
        || !safeLockEndpoint(final)
        || final.size !== BigInt(content.length)
      ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
      await assertNoDarwinExtendedAcl(lockPath, deadline);
      const aclFinal = await deadline.run(() => lstat(lockPath, { bigint: true }));
      if (!sameMetadata(final, aclFinal)) throw runtimeError('RUNTIME_CACHE_UNSAFE');
      publishedIdentity = aclFinal;
      await syncDirectory(dirname(lockPath), deadline);
    } catch (error) {
      primary = error;
    }
  }
  if (primary) {
    if (publishedIdentity) {
      await deadline.cleanup(() => removeCreatedLockRaw(
        lockPath,
        publishedIdentity,
        assertPinned,
      ));
    } else if (createdIdentity) {
      await deadline.cleanup(() => removeCreatedLockRaw(
        lockPath,
        createdIdentity,
        assertPinned,
      ));
    }
    if (createdIdentity) {
      await deadline.cleanup(() => removeCreatedLockRaw(
        lockPartPath,
        createdIdentity,
        assertPinned,
      ));
    }
    throw primary;
  }
  deadline.assertLive();
  return Object.freeze({ identity: publishedIdentity, record });
}

async function inspectCacheLockRaw(lockPath, artifactSha256) {
  let file;
  try {
    file = await open(
      lockPath,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const before = await file.stat({ bigint: true });
    const pathBefore = await lstat(lockPath, { bigint: true });
    if (!safeLockFile(before, pathBefore)) return undefined;
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const read = await file.read(bytes, offset, bytes.length - offset, offset);
      if (read.bytesRead <= 0) return undefined;
      offset += read.bytesRead;
    }
    const after = await file.stat({ bigint: true });
    const pathAfter = await lstat(lockPath, { bigint: true });
    if (!sameMetadata(before, after) || !sameMetadata(after, pathAfter)) return undefined;
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      return undefined;
    }
    const record = parseLockRecord(text);
    return record === undefined || record.artifactSha256 !== artifactSha256
      ? undefined
      : { record, identity: after };
  } catch {
    return undefined;
  } finally {
    try { await file?.close(); } catch {}
  }
}

async function releaseCacheLockRaw(lockPath, owned, assertPinned) {
  const snapshot = await inspectCacheLockRaw(lockPath, owned.record.artifactSha256);
  if (
    snapshot === undefined
    || snapshot.record.owner !== owned.record.owner
    || !sameMetadata(snapshot.identity, owned.identity)
  ) {
    throw runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
  }
  const observed = await lstat(lockPath, { bigint: true });
  if (!sameMetadata(observed, snapshot.identity)) {
    throw runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
  }
  await assertPinned();
  await unlink(lockPath);
  let directory;
  try {
    directory = await open(
      dirname(lockPath),
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    await directory.sync();
  } finally {
    await directory?.close();
  }
}

async function readBoundedDirectoryEntries(path, deadline) {
  let directory;
  const entries = [];
  let primary;
  try {
    directory = await opendirWithinDeadline(deadline, path);
    while (true) {
      const entry = await deadline.run(() => directory.read());
      if (entry === null) break;
      entries.push(entry.name);
      if (entries.length > ORPHAN_LIMIT) {
        await deadline.run(() => runCacheTestHook('orphanDirectoryLimitExceeded', {
          path,
          entriesRead: entries.length,
        }));
        throw runtimeError('RUNTIME_CACHE_UNSAFE');
      }
    }
  } catch (error) {
    primary = internalErrorCode(error) === 'RUNTIME_ARTIFACT_TIMEOUT'
      ? error
      : internalErrorCode(error) === 'RUNTIME_CACHE_UNSAFE'
        ? error
        : runtimeError('RUNTIME_CACHE_UNSAFE');
  } finally {
    if (directory) {
      const cleanup = await deadline.cleanup(() => directory.close());
      if (cleanup.status === 'timeout') {
        primary = runtimeError('RUNTIME_ARTIFACT_TIMEOUT');
      } else if (cleanup.status === 'failed') {
        primary = runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
      }
    }
  }
  if (primary) throw primary;
  return entries;
}

async function sweepDeadLockTemporaries(
  locksPath,
  artifact,
  deadline,
  assertPinned,
) {
  let entries;
  try {
    await deadline.run(assertPinned);
    entries = await readBoundedDirectoryEntries(locksPath, deadline);
  } catch (error) {
    preserveTimeout(error, 'RUNTIME_CACHE_UNSAFE');
  }
  const pattern = new RegExp(
    `^\\.${artifact.sha256}\\.[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.lock\\.part$`,
    'u',
  );
  for (const name of entries) {
    if (!pattern.test(name)) continue;
    const path = join(locksPath, name);
    let preliminary;
    try {
      preliminary = await deadline.run(() => lstat(path, { bigint: true }));
    } catch (error) {
      if (safeErrorCode(error) === 'ENOENT') continue;
      preserveTimeout(error, 'RUNTIME_CACHE_UNSAFE');
    }
    if (!safeLockEndpoint(preliminary, Object.freeze([1n, 2n]))) {
      throw runtimeError('RUNTIME_CACHE_UNSAFE');
    }
    await assertNoDarwinExtendedAcl(path, deadline);
    const stable = await deadline.run(() => lstat(path, { bigint: true }));
    if (!sameMetadata(preliminary, stable)) continue;
    if (stable.size === 0n || stable.size > BigInt(LOCK_RECORD_MAX_BYTES)) continue;

    let snapshot;
    try {
      snapshot = await readLockSnapshot(
        path,
        artifact.sha256,
        deadline,
        Object.freeze([1n, 2n]),
      );
    } catch (error) {
      if (internalErrorCode(error) === 'RUNTIME_ARTIFACT_TIMEOUT') throw error;
      await assertNoDarwinExtendedAcl(path, deadline);
      const unknown = await deadline.run(() => lstat(path, { bigint: true }));
      if (
        !sameIdentity(unknown, stable)
        || !safeLockEndpoint(unknown, Object.freeze([1n, 2n]))
      ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
      continue;
    }
    if (snapshot.status === 'missing' || snapshot.status === 'retry') continue;
    if (snapshot.record.lockPartName !== name) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    if (snapshot.identity.nlink === 2n) {
      const finalPath = join(locksPath, `${artifact.sha256}.lock`);
      const final = await deadline.run(() => lstat(finalPath, { bigint: true }));
      if (!sameMetadata(final, snapshot.identity)) throw runtimeError('RUNTIME_CACHE_UNSAFE');
      continue;
    }
    if (!processIsAlive(snapshot.record.pid)) {
      await removeExactPath(path, snapshot.identity, deadline, assertPinned);
    }
  }
}

async function recoverDeadArtifactPart(
  objectsPath,
  destinationPath,
  artifact,
  record,
  deadline,
  assertPinned,
) {
  const partPath = join(objectsPath, record.artifactPartName);
  let part;
  try {
    part = await deadline.run(() => lstat(partPath, { bigint: true }));
  } catch (error) {
    if (safeErrorCode(error) === 'ENOENT') return true;
    preserveTimeout(error, 'RUNTIME_CACHE_UNSAFE');
  }
  if (
    !part.isFile()
    || part.isSymbolicLink()
    || ![1n, 2n].includes(part.nlink)
    || (part.mode & 0o777n) !== 0o600n
    || (typeof process.getuid === 'function' && part.uid !== BigInt(process.getuid()))
  ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
  await assertNoDarwinExtendedAcl(partPath, deadline);
  const stablePart = await deadline.run(() => lstat(partPath, { bigint: true }));
  if (!sameMetadata(part, stablePart)) throw runtimeError('RUNTIME_CACHE_UNSAFE');

  if (stablePart.nlink === 1n) {
    return removeExactPath(partPath, stablePart, deadline, assertPinned);
  }

  let destination;
  try {
    destination = await deadline.run(() => lstat(destinationPath, { bigint: true }));
  } catch (error) {
    preserveTimeout(error, 'RUNTIME_CACHE_UNSAFE');
  }
  if (!sameMetadata(destination, stablePart)) {
    if (
      sameIdentity(destination, stablePart)
      && safeCacheFile(destination, destination)
    ) return false;
    throw runtimeError('RUNTIME_CACHE_UNSAFE');
  }
  const verified = await inspectCache(
    destinationPath,
    artifact,
    deadline,
    Object.freeze([2n]),
  );
  if (
    verified.status !== 'valid'
    || !sameMetadata(verified.identity, stablePart)
  ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
  let finalPart;
  let finalDestination;
  try {
    [finalPart, finalDestination] = await deadline.run(() => Promise.all([
      lstat(partPath, { bigint: true }),
      lstat(destinationPath, { bigint: true }),
    ]));
  } catch (error) {
    if (safeErrorCode(error) === 'ENOENT') return false;
    preserveTimeout(error, 'RUNTIME_CACHE_UNSAFE');
  }
  if (
    !sameMetadata(finalPart, verified.identity)
    || !sameMetadata(finalDestination, verified.identity)
  ) {
    if (
      sameIdentity(finalDestination, verified.identity)
      && safeCacheFile(finalDestination, finalDestination)
    ) return false;
    throw runtimeError('RUNTIME_CACHE_UNSAFE');
  }
  if (!await removeExactPath(
    partPath,
    verified.identity,
    deadline,
    assertPinned,
  )) return false;
  const reconciled = await deadline.run(() => lstat(destinationPath, { bigint: true }));
  if (
    !sameIdentity(reconciled, verified.identity)
    || !safeCacheFile(reconciled, reconciled)
  ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
  await assertNoDarwinExtendedAcl(destinationPath, deadline);
  const aclReconciled = await deadline.run(() => lstat(destinationPath, { bigint: true }));
  if (!sameMetadata(reconciled, aclReconciled)) throw runtimeError('RUNTIME_CACHE_UNSAFE');
  await syncDirectory(objectsPath, deadline);
  return true;
}

async function recoverDeadCacheLock(
  lockPath,
  objectsPath,
  destinationPath,
  artifact,
  snapshot,
  deadline,
  assertPinned,
) {
  if (!await recoverDeadArtifactPart(
    objectsPath,
    destinationPath,
    artifact,
    snapshot.record,
    deadline,
    assertPinned,
  )) return false;
  let finalIdentity = snapshot.identity;
  if (snapshot.lockPartPath !== undefined) {
    let lockPart;
    let final;
    try {
      [lockPart, final] = await deadline.run(() => Promise.all([
        lstat(snapshot.lockPartPath, { bigint: true }),
        lstat(lockPath, { bigint: true }),
      ]));
    } catch (error) {
      if (safeErrorCode(error) === 'ENOENT') return false;
      preserveTimeout(error, 'RUNTIME_CACHE_UNSAFE');
    }
    if (
      !sameMetadata(lockPart, snapshot.identity)
      || !sameMetadata(final, snapshot.identity)
    ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    if (!await removeExactPath(
      snapshot.lockPartPath,
      snapshot.identity,
      deadline,
      assertPinned,
    )) return false;
    try {
      finalIdentity = await deadline.run(() => lstat(lockPath, { bigint: true }));
    } catch (error) {
      if (safeErrorCode(error) === 'ENOENT') return false;
      preserveTimeout(error, 'RUNTIME_CACHE_UNSAFE');
    }
    if (
      !sameIdentity(finalIdentity, snapshot.identity)
      || !safeLockEndpoint(finalIdentity)
    ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    await assertNoDarwinExtendedAcl(lockPath, deadline);
    const aclFinal = await deadline.run(() => lstat(lockPath, { bigint: true }));
    if (!sameMetadata(finalIdentity, aclFinal)) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    finalIdentity = aclFinal;
  }
  return removeExactPath(lockPath, finalIdentity, deadline, assertPinned);
}

async function waitForCacheLock(deadline, timeoutCode = 'RUNTIME_ARTIFACT_TIMEOUT') {
  const delayMs = Math.min(LOCK_RETRY_DELAY_MS, deadline.remainingMs);
  if (delayMs <= 0) throw runtimeError(timeoutCode);
  try {
    await deadline.run(() => new Promise((resolveDelay) => {
      setTimeout(resolveDelay, delayMs);
    }));
  } catch (error) {
    if (internalErrorCode(error) === 'RUNTIME_ARTIFACT_TIMEOUT') {
      throw runtimeError(timeoutCode);
    }
    throw error;
  }
}

async function withCacheLock(
  lockPath,
  objectsPath,
  destinationPath,
  artifact,
  deadline,
  operation,
  assertPinned,
) {
  const gatePath = join(dirname(lockPath), `${artifact.sha256}.gate`);
  let observedContention = false;
  while (true) {
    let gate;
    try {
      gate = await tryCreateCacheGate(gatePath, deadline, assertPinned);
    } catch (error) {
      if (
        observedContention
        && internalErrorCode(error) === 'RUNTIME_ARTIFACT_TIMEOUT'
      ) {
        throw runtimeError('RUNTIME_CACHE_LOCKED');
      }
      throw error;
    }
    if (gate.status === 'missing') continue;
    if (gate.status === 'busy') {
      observedContention = true;
      await deadline.run(() => runCacheTestHook('afterCacheRecoveryGateBusy', {
        gatePath,
      }));
      await waitForCacheLock(deadline, 'RUNTIME_CACHE_LOCKED');
      continue;
    }

    let owned;
    let liveLock = false;
    let primary;
    try {
      while (true) {
        const observed = await inspectCacheLock(lockPath, artifact.sha256, deadline);
        if (observed.status === 'retry') continue;
        if (observed.status === 'valid') {
          if (processIsAlive(observed.record.pid)) {
            observedContention = true;
            liveLock = true;
            break;
          }
          observedContention = false;
          await recoverDeadCacheLock(
            lockPath,
            objectsPath,
            destinationPath,
            artifact,
            observed,
            deadline,
            assertPinned,
          );
          continue;
        }
        observedContention = false;
        owned = await tryCreateCacheLock(lockPath, artifact, deadline, assertPinned);
        if (owned !== undefined) break;
      }
    } catch (error) {
      primary = error;
    }

    const gateCleanup = await deadline.cleanup(() => releaseCacheGateRaw(
      gatePath,
      gate.identity,
      assertPinned,
    ));
    if (gateCleanup.status === 'timeout') {
      primary = runtimeError('RUNTIME_ARTIFACT_TIMEOUT');
    } else if (gateCleanup.status === 'failed' && primary === undefined) {
      primary = runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
    }
    if (
      observedContention
      && internalErrorCode(primary) === 'RUNTIME_ARTIFACT_TIMEOUT'
    ) primary = runtimeError('RUNTIME_CACHE_LOCKED');
    if (primary) {
      if (owned !== undefined) {
        await deadline.cleanup(() => releaseCacheLockRaw(lockPath, owned, assertPinned));
      }
      throw primary;
    }

    if (liveLock) {
      observedContention = true;
      await waitForCacheLock(deadline, 'RUNTIME_CACHE_LOCKED');
      continue;
    }
    if (owned !== undefined) {
      let value;
      let operationPrimary;
      try {
        await sweepDeadLockTemporaries(
          dirname(lockPath),
          artifact,
          deadline,
          assertPinned,
        );
        value = await operation(owned.record);
      } catch (error) {
        operationPrimary = error;
      }
      const cleanup = await deadline.cleanup(() => releaseCacheLockRaw(
        lockPath,
        owned,
        assertPinned,
      ));
      if (cleanup.status === 'timeout') {
        operationPrimary = runtimeError('RUNTIME_ARTIFACT_TIMEOUT');
      } else if (cleanup.status === 'failed' && operationPrimary === undefined) {
        operationPrimary = runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
      }
      if (operationPrimary) throw operationPrimary;
      deadline.assertLive();
      return value;
    }
    continue;
  }
}

const RESPONSE_STATUS_GETTER = Object.getOwnPropertyDescriptor(Response.prototype, 'status').get;
const RESPONSE_HEADERS_GETTER = Object.getOwnPropertyDescriptor(Response.prototype, 'headers').get;
const RESPONSE_BODY_GETTER = Object.getOwnPropertyDescriptor(Response.prototype, 'body').get;
const READABLE_STREAM_CANCEL = ReadableStream.prototype.cancel;
const READABLE_STREAM_GET_READER = ReadableStream.prototype.getReader;
const READER_READ = ReadableStreamDefaultReader.prototype.read;
const READER_CANCEL = ReadableStreamDefaultReader.prototype.cancel;

function responseCandidateForCancellation(value) {
  if (
    value === null
    || typeof value !== 'object'
    || isProxy(value)
  ) return undefined;
  try {
    RESPONSE_BODY_GETTER.call(value);
    return value;
  } catch {}
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, 'response');
    if (descriptor !== undefined && Object.hasOwn(descriptor, 'value')) {
      const candidate = descriptor.value;
      if (
        candidate !== null
        && typeof candidate === 'object'
        && !isProxy(candidate)
      ) {
        RESPONSE_BODY_GETTER.call(candidate);
        return candidate;
      }
    }
  } catch {}
  return undefined;
}

async function cancelAuthenticResponseBestEffort(value, deadline) {
  const response = responseCandidateForCancellation(value);
  if (response === undefined) return;
  let body;
  try {
    body = RESPONSE_BODY_GETTER.call(response);
  } catch {
    return;
  }
  if (body === null) return;
  await deadline.cleanup(() => READABLE_STREAM_CANCEL.call(body));
}

async function fetchWithinDeadline(fetch, url, options, deadline) {
  let pending;
  try {
    return await deadline.run(() => {
      pending = Promise.resolve(fetch(url, options));
      return pending;
    });
  } catch (error) {
    if (deadline.expired && pending !== undefined) {
      pending.then(
        (value) => { void cancelAuthenticResponseBestEffort(value, deadline); },
        () => {},
      );
    }
    throw error;
  }
}

function validateResponse(response) {
  if (
    response === null
    || typeof response !== 'object'
    || isProxy(response)
    || Object.getPrototypeOf(response) !== Response.prototype
    || Object.getOwnPropertyNames(response).length !== 0
  ) throw runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');
  let status;
  let headers;
  let body;
  try {
    status = RESPONSE_STATUS_GETTER.call(response);
    headers = RESPONSE_HEADERS_GETTER.call(response);
    body = RESPONSE_BODY_GETTER.call(response);
  } catch {
    throw runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');
  }
  if (
    !Number.isInteger(status)
    || status < 100
    || status > 599
    || headers === null
    || typeof headers !== 'object'
    || isProxy(headers)
    || Object.getPrototypeOf(headers) !== Headers.prototype
    || Object.getOwnPropertyNames(headers).length !== 0
    || (body !== null && (
      typeof body !== 'object'
      || isProxy(body)
      || Object.getPrototypeOf(body) !== ReadableStream.prototype
      || Object.getOwnPropertyNames(body).length !== 0
    ))
  ) throw runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');
  return { status, headers, body };
}

function header(headers, name) {
  try {
    return Headers.prototype.get.call(headers, name);
  } catch {
    throw runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');
  }
}

function safeChunkBytes(value, remainingBytes, deadline) {
  if (
    value === null
    || typeof value !== 'object'
    || isProxy(value)
  ) throw runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');
  let prototype;
  try {
    prototype = Object.getPrototypeOf(value);
  } catch {
    throw runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');
  }
  if (prototype !== Uint8Array.prototype && prototype !== BUFFER_PROTOTYPE) {
    throw runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');
  }
  for (const property of ['byteLength', 'byteOffset', 'buffer', 'length', 'constructor']) {
    const descriptor = Object.getOwnPropertyDescriptor(value, property);
    if (descriptor?.get !== undefined || descriptor?.set !== undefined) {
      throw runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');
    }
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    throw runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');
  }
  let length;
  let bytes;
  try {
    length = TYPED_ARRAY_BYTE_LENGTH_GETTER.call(value);
    if (!Number.isSafeInteger(length) || length <= 0) {
      throw runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');
    }
    if (length > remainingBytes) {
      throw runtimeError('RUNTIME_ARTIFACT_INTEGRITY_FAILED');
    }
    if (length > MAX_CHUNK_BYTES) {
      throw runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');
    }
    deadline.assertLive();
    bytes = Buffer.allocUnsafe(length);
    TYPED_ARRAY_SET.call(bytes, value, 0);
    deadline.assertLive();
  } catch (error) {
    if (internalErrorCode(error) !== undefined) throw error;
    throw runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');
  }
  return bytes;
}

async function acquire(
  path,
  artifact,
  maxRedirects,
  fetch,
  deadline,
  lockRecord,
  assertPinned,
) {
  const parent = join(path, '..');
  const temporaryPath = join(parent, lockRecord.artifactPartName);
  let file;
  let identity;
  let reader;
  let body;
  let primary;

  try {
    file = await openWithinDeadline(
      deadline,
      temporaryPath,
      constants.O_WRONLY
        | constants.O_CREAT
        | constants.O_EXCL
        | constants.O_NOFOLLOW
        | constants.O_NONBLOCK,
      0o600,
    );
    identity = await deadline.run(() => file.stat({ bigint: true }));
    const pathIdentity = await deadline.run(() => lstat(temporaryPath, { bigint: true }));
    if (
      !identity.isFile()
      || identity.isSymbolicLink()
      || !sameMetadata(identity, pathIdentity)
      || identity.nlink !== 1n
      || (identity.mode & 0o777n) !== 0o600n
      || (typeof process.getuid === 'function' && identity.uid !== BigInt(process.getuid()))
    ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    await assertNoDarwinExtendedAcl(temporaryPath, deadline);
    const aclIdentity = await deadline.run(() => lstat(temporaryPath, { bigint: true }));
    if (!sameMetadata(identity, aclIdentity)) throw runtimeError('RUNTIME_CACHE_UNSAFE');

    let current = artifact.url;
    const allowedOrigins = new Set([
      new URL(artifact.url).origin,
      ...artifact.redirectOrigins,
    ]);
    let redirects = 0;
    const seen = new Set([current]);
    let response;
    while (true) {
      const fetchedValue = await fetchWithinDeadline(fetch, current, {
        redirect: 'manual',
        signal: deadline.signal,
      }, deadline);
      let fetched;
      try {
        fetched = readExactRecord(
          fetchedValue,
          Object.freeze(['response']),
          'RUNTIME_ARTIFACT_ACQUISITION_FAILED',
        );
      } catch (error) {
        await cancelAuthenticResponseBestEffort(fetchedValue, deadline);
        throw error;
      }
      try {
        response = validateResponse(fetched.response);
      } catch (error) {
        await cancelAuthenticResponseBestEffort(fetched.response, deadline);
        throw error;
      }
      body = response.body;
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        if (redirects >= maxRedirects) {
          throw runtimeError('RUNTIME_ARTIFACT_REDIRECT_INVALID');
        }
        const next = redirectUrl(current, header(response.headers, 'location'), seen, allowedOrigins);
        seen.add(next);
        redirects += 1;
        current = next;
        if (body !== null) await deadline.run(() => READABLE_STREAM_CANCEL.call(body));
        body = undefined;
        continue;
      }
      if (response.status !== 200) throw runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');
      break;
    }

    const contentLength = header(response.headers, 'content-length');
    if (
      contentLength !== null
      && (!/^(?:0|[1-9][0-9]*)$/u.test(contentLength)
        || Number(contentLength) !== artifact.bytes)
    ) throw runtimeError('RUNTIME_ARTIFACT_INTEGRITY_FAILED');
    const contentEncoding = header(response.headers, 'content-encoding');
    if (contentEncoding !== null && contentEncoding.toLowerCase() !== 'identity') {
      throw runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');
    }
    if (
      body === null
    ) throw runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');

    const candidateReader = READABLE_STREAM_GET_READER.call(body);
    if (
      isProxy(candidateReader)
      || Object.getPrototypeOf(candidateReader) !== ReadableStreamDefaultReader.prototype
      || Object.getOwnPropertyNames(candidateReader).length !== 0
    ) throw runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');
    reader = candidateReader;
    const hash = createHash('sha256');
    let received = 0;
    while (true) {
      const chunk = readExactRecord(
        await deadline.run(() => READER_READ.call(reader)),
        Object.freeze(['value', 'done']),
        'RUNTIME_ARTIFACT_ACQUISITION_FAILED',
      );
      if (typeof chunk.done !== 'boolean') {
        throw runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');
      }
      if (chunk.done) {
        if (chunk.value !== undefined) throw runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');
        break;
      }
      const bytes = safeChunkBytes(chunk.value, artifact.bytes - received, deadline);
      const { bytesWritten } = await deadline.run(() => file.write(
        bytes,
        0,
        bytes.length,
        received,
      ));
      if (bytesWritten !== bytes.length) throw runtimeError('RUNTIME_CACHE_FAILED');
      hash.update(bytes);
      received += bytes.length;
    }
    if (
      received !== artifact.bytes
      || hash.digest('hex').toUpperCase() !== artifact.sha256
    ) throw runtimeError('RUNTIME_ARTIFACT_INTEGRITY_FAILED');
    await deadline.run(() => file.sync());
    await deadline.run(() => file.close());
    file = undefined;

    const verified = await inspectCache(temporaryPath, artifact, deadline);
    if (verified.status !== 'valid') throw runtimeError('RUNTIME_ARTIFACT_INTEGRITY_FAILED');
    identity = verified.identity;
    const published = await publishTemporary(
      temporaryPath,
      path,
      identity,
      deadline,
      assertPinned,
    );
    await deadline.run(() => runCacheTestHook('afterPublishBeforeFinalVerification', { path }));
    const final = await inspectCache(path, artifact, deadline);
    if (
      final.status !== 'valid'
      || !sameIdentity(final.identity, published)
    ) throw runtimeError('RUNTIME_CACHE_UNSAFE');
    deadline.assertLive();
  } catch (error) {
    const code = internalErrorCode(error);
    if (deadline.expired || code === 'RUNTIME_ARTIFACT_TIMEOUT') {
      primary = runtimeError('RUNTIME_ARTIFACT_TIMEOUT');
    } else if (
      typeof code === 'string'
      && /^RUNTIME_[A-Z0-9_]+$/u.test(code)
    ) {
      primary = runtimeError(code);
    } else {
      primary = runtimeError('RUNTIME_ARTIFACT_ACQUISITION_FAILED');
    }
  } finally {
    if (reader) {
      const cleanup = await deadline.cleanup(() => READER_CANCEL.call(reader));
      if (cleanup.status === 'timeout') {
        primary = runtimeError('RUNTIME_ARTIFACT_TIMEOUT');
      } else if (cleanup.status === 'failed' && primary === undefined) {
        primary = runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
      }
    } else if (body) {
      const cleanup = await deadline.cleanup(() => READABLE_STREAM_CANCEL.call(body));
      if (cleanup.status === 'timeout') {
        primary = runtimeError('RUNTIME_ARTIFACT_TIMEOUT');
      } else if (cleanup.status === 'failed' && primary === undefined) {
        primary = runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
      }
    }
    if (file) {
      const cleanup = await deadline.cleanup(() => file.close());
      if (cleanup.status === 'timeout') {
        primary = runtimeError('RUNTIME_ARTIFACT_TIMEOUT');
      } else if (cleanup.status === 'failed') {
        primary = runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
      }
    }
    if (identity) {
      const cleanup = await deadline.cleanup(() => removeTemporary(
        temporaryPath,
        identity,
        assertPinned,
      ));
      if (cleanup.status === 'timeout') {
        primary = runtimeError('RUNTIME_ARTIFACT_TIMEOUT');
      } else if (cleanup.status === 'failed') {
        primary = runtimeError('RUNTIME_CACHE_CLEANUP_FAILED');
      }
    }
  }
  if (primary) throw primary;
}

export async function acquireRuntimeArtifact(input) {
  const {
    cacheRoot,
    artifact,
    policy,
    fetch,
  } = validateInput(input);
  const deadline = createDeadline(policy.timeoutMs);
  const objects = join(cacheRoot, 'objects');
  const locks = join(cacheRoot, 'locks');
  const result = resultFor(cacheRoot, artifact);
  let value;
  let primary;

  try {
    const parentIdentity = await assertOwnerOnlyRealParent(cacheRoot, deadline);
    await ownerOnlyDirectory(cacheRoot, deadline);
    await ownerOnlyDirectory(objects, deadline);
    await ownerOnlyDirectory(locks, deadline);
    const directoryPaths = Object.freeze([cacheRoot, objects, locks]);
    const directoryIdentities = await assertOwnerOnlyDirectories(directoryPaths, deadline);
    const assertPinned = Object.freeze(() => assertPinnedDirectoryIdentities(
      cacheRoot,
      parentIdentity,
      directoryPaths,
      directoryIdentities,
    ));
    value = await withCacheLock(
      join(locks, `${artifact.sha256}.lock`),
      objects,
      result.path,
      artifact,
      deadline,
      async (lockRecord) => {
        const cached = await inspectCache(result.path, artifact, deadline);
        if (cached.status === 'poison') {
          await removePoison(result.path, cached.identity, deadline, assertPinned);
        }
        if (cached.status !== 'valid') {
          await acquire(
            result.path,
            artifact,
            policy.maxRedirects,
            fetch,
            deadline,
            lockRecord,
            assertPinned,
          );
        }
        const final = await inspectCache(result.path, artifact, deadline);
        if (final.status !== 'valid') throw runtimeError('RUNTIME_CACHE_UNSAFE');
        deadline.assertLive();
        return result;
      },
      assertPinned,
    );
    await assertOwnerOnlyRealParent(cacheRoot, deadline, parentIdentity);
    await assertOwnerOnlyDirectories(directoryPaths, deadline, directoryIdentities);
  } catch (error) {
    const code = internalErrorCode(error);
    if (typeof code === 'string' && /^RUNTIME_[A-Z0-9_]+$/u.test(code)) {
      primary = runtimeError(code);
    } else {
      primary = runtimeError('RUNTIME_CACHE_FAILED');
    }
  } finally {
    deadline.dispose();
  }
  if (primary) throw primary;
  return value;
}
