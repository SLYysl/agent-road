import { execFile as execFileCallback, spawn } from 'node:child_process';
import {
  createHash,
  randomBytes as cryptoRandomBytes,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
import { constants } from 'node:fs';
import {
  link,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
} from 'node:fs/promises';
import {
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from 'node:path';
import { promisify, TextDecoder } from 'node:util';
import { isProxy } from 'node:util/types';

import { RUNTIME_PLAN_TICKET_TTL_MS } from './runtime-plan-ticket-policy.mjs';

const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/u;
const PLAN_TICKET_ID_PATTERN = /^rpt_[a-f0-9]{64}$/u;
const OPERATION_ID_PATTERN = /^[a-f0-9]{32}$/u;
const SHA256_PATTERN = /^[A-F0-9]{64}$/u;
const ISO_TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const UUID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const DIRECTORY_MODE = 0o700;
const FILE_MODE = 0o600;
const MAX_PATH_BYTES = 4_096;
const MAX_RECORD_BYTES = 512 * 1_024;
const MAX_NAMESPACE_ENTRIES = 4_096;
const TEMPORARY_SUFFIX_BYTES = Buffer.byteLength(`.publish-${'0'.repeat(36)}.tmp`, 'utf8');
const LOCKF_WAIT_SECONDS = 1;
const LOCKF_WATCHDOG_GRACE_MS = 500;
const LOCKF_OUTPUT_LIMIT = 1_024;
const LOCKF_TEMPFAIL = 75;
const TICKET_DOMAIN = 'AgentRoad.RuntimePlanTicket.v1\0';
const CONSUMED_DOMAIN = 'AgentRoad.RuntimePlanConsumed.v1\0';
const execFile = promisify(execFileCallback);
const TICKET_INPUT_FIELDS = Object.freeze([
  'deviceId',
  'operationId',
  'createdAt',
  'state',
  'catalog',
  'inventory',
  'plan',
  'controller',
  'mutators',
  'baseline',
  'authorization',
  'authorizationDigest',
]);
const TICKET_FIELDS = Object.freeze([
  'schemaVersion',
  'recordType',
  'planTicketId',
  ...TICKET_INPUT_FIELDS,
  'expiresAt',
  'recordDigest',
]);
const CONSUME_INPUT_FIELDS = Object.freeze([
  'deviceId',
  'planTicketId',
  'ticketRecordDigest',
  'authorizationDigest',
]);
const CONSUMED_FIELDS = Object.freeze([
  'schemaVersion',
  'recordType',
  'planTicketId',
  'deviceId',
  'ticketRecordDigest',
  'authorizationDigest',
  'consumedAt',
  'recordDigest',
]);
const KNOWN_CODES = new Set([
  'RUNTIME_ALREADY_RUNNING',
  'RUNTIME_INPUT_INVALID',
  'RUNTIME_INTERNAL_ERROR',
  'RUNTIME_STATE_UNSUPPORTED',
]);

function runtimeError(code, Type = Error) {
  const error = new Type(code);
  error.code = code;
  return error;
}

function failInput() {
  throw runtimeError('RUNTIME_INPUT_INVALID', TypeError);
}

function failState() {
  throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
}

function exactObject(input, fields, failure = failInput) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) failure();
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== fields.length || !fields.every((field) => names.includes(field))) failure();
  const output = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      failure();
    }
    output[field] = descriptor.value;
  }
  return output;
}

function safeClone(input, state = { nodes: 0 }, depth = 0, failure = failInput) {
  state.nodes += 1;
  if (state.nodes > 16_384 || depth > 32) failure();
  if (input === null || typeof input === 'boolean') return input;
  if (typeof input === 'string') {
    if (Buffer.byteLength(input, 'utf8') > MAX_RECORD_BYTES) failure();
    return input;
  }
  if (typeof input === 'number') {
    if (!Number.isSafeInteger(input) || Object.is(input, -0)) failure();
    return input;
  }
  if (typeof input !== 'object' || isProxy(input)) failure();
  if (Array.isArray(input)) {
    if (
      Object.getPrototypeOf(input) !== Array.prototype
      || Object.getOwnPropertySymbols(input).length !== 0
      || input.length > 2_048
      || Object.getOwnPropertyNames(input).length !== input.length + 1
    ) failure();
    const output = [];
    for (let index = 0; index < input.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
        failure();
      }
      output.push(safeClone(descriptor.value, state, depth + 1, failure));
    }
    return output;
  }
  if (
    Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
    || Object.getOwnPropertyNames(input).length > 128
  ) failure();
  const output = {};
  for (const name of Object.getOwnPropertyNames(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      failure();
    }
    output[name] = safeClone(descriptor.value, state, depth + 1, failure);
  }
  return output;
}

function deepFreeze(value) {
  if (Array.isArray(value)) {
    for (const child of value) deepFreeze(child);
  } else if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return Object.freeze(value);
}

function canonicalTimestamp(value, failure = failInput) {
  if (typeof value !== 'string' || !ISO_TIMESTAMP_PATTERN.test(value)) failure();
  try {
    if (new Date(value).toISOString() !== value) failure();
  } catch {
    failure();
  }
  return value;
}

function canonicalNow(now) {
  let value;
  try {
    value = now();
    if (
      value === null
      || typeof value !== 'object'
      || isProxy(value)
      || Object.getPrototypeOf(value) !== Date.prototype
      || Object.getOwnPropertyNames(value).length !== 0
      || Object.getOwnPropertySymbols(value).length !== 0
    ) throw new TypeError('invalid clock');
    return Date.prototype.toISOString.call(value);
  } catch {
    throw runtimeError('RUNTIME_INTERNAL_ERROR');
  }
}

function validateRoot(value) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || Buffer.byteLength(value, 'utf8') > MAX_PATH_BYTES
    || !isAbsolute(value)
    || resolve(value) !== value
    || /[\r\n\x00-\x1f\x7f]/u.test(value)
  ) failInput();
  return value;
}

function authorizationPaths(root, deviceId, planTicketId = null) {
  if (
    typeof deviceId !== 'string'
    || deviceId.length > 64
    || !DEVICE_ID_PATTERN.test(deviceId)
    || (planTicketId !== null && !PLAN_TICKET_ID_PATTERN.test(planTicketId))
  ) failInput();
  const device = join(root, deviceId);
  const authorization = join(device, 'runtime-plan-authorizations');
  const tickets = join(authorization, 'tickets-v1');
  const consumed = join(authorization, 'consumed-v1');
  const paths = {
    device,
    authorization,
    tickets,
    consumed,
    lock: join(authorization, '.store.lock'),
    ticket: planTicketId === null ? null : join(tickets, `${planTicketId}.json`),
    consumedRecord: planTicketId === null ? null : join(consumed, `${planTicketId}.json`),
  };
  const longest = Math.max(...Object.values(paths)
    .filter((path) => typeof path === 'string')
    .map((path) => Buffer.byteLength(path, 'utf8')));
  if (longest + TEMPORARY_SUFFIX_BYTES > MAX_PATH_BYTES) failInput();
  return Object.freeze(paths);
}

function digestRecord(domain, value) {
  return createHash('sha256')
    .update(domain, 'utf8')
    .update(JSON.stringify(value), 'utf8')
    .digest('hex')
    .toUpperCase();
}

function ticketBase(value) {
  const { recordDigest, ...base } = value;
  void recordDigest;
  return base;
}

function canonicalTicket(input, failure = failState) {
  const value = exactObject(input, TICKET_FIELDS, failure);
  if (
    value.schemaVersion !== 1
    || value.recordType !== 'RUNTIME_PLAN_TICKET'
    || typeof value.planTicketId !== 'string'
    || !PLAN_TICKET_ID_PATTERN.test(value.planTicketId)
    || typeof value.deviceId !== 'string'
    || !DEVICE_ID_PATTERN.test(value.deviceId)
    || typeof value.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(value.operationId)
    || typeof value.authorizationDigest !== 'string'
    || !SHA256_PATTERN.test(value.authorizationDigest)
    || typeof value.recordDigest !== 'string'
    || !SHA256_PATTERN.test(value.recordDigest)
  ) failure();
  canonicalTimestamp(value.createdAt, failure);
  canonicalTimestamp(value.expiresAt, failure);
  if (
    Date.parse(value.expiresAt) - Date.parse(value.createdAt) !== RUNTIME_PLAN_TICKET_TTL_MS
    || value.plan === null
    || typeof value.plan !== 'object'
    || value.plan.operationId !== value.operationId
    || value.plan.createdAt !== value.createdAt
  ) failure();
  const record = {
    schemaVersion: 1,
    recordType: 'RUNTIME_PLAN_TICKET',
    planTicketId: value.planTicketId,
    deviceId: value.deviceId,
    operationId: value.operationId,
    createdAt: value.createdAt,
    state: safeClone(value.state, { nodes: 0 }, 0, failure),
    catalog: safeClone(value.catalog, { nodes: 0 }, 0, failure),
    inventory: safeClone(value.inventory, { nodes: 0 }, 0, failure),
    plan: safeClone(value.plan, { nodes: 0 }, 0, failure),
    controller: safeClone(value.controller, { nodes: 0 }, 0, failure),
    mutators: safeClone(value.mutators, { nodes: 0 }, 0, failure),
    baseline: safeClone(value.baseline, { nodes: 0 }, 0, failure),
    authorization: safeClone(value.authorization, { nodes: 0 }, 0, failure),
    authorizationDigest: value.authorizationDigest,
    expiresAt: value.expiresAt,
    recordDigest: value.recordDigest,
  };
  if (digestRecord(TICKET_DOMAIN, ticketBase(record)) !== record.recordDigest) failure();
  return deepFreeze(record);
}

function canonicalConsumed(input, failure = failState) {
  const value = exactObject(input, CONSUMED_FIELDS, failure);
  if (
    value.schemaVersion !== 1
    || value.recordType !== 'RUNTIME_PLAN_CONSUMED'
    || !PLAN_TICKET_ID_PATTERN.test(value.planTicketId ?? '')
    || !DEVICE_ID_PATTERN.test(value.deviceId ?? '')
    || !SHA256_PATTERN.test(value.ticketRecordDigest ?? '')
    || !SHA256_PATTERN.test(value.authorizationDigest ?? '')
    || !SHA256_PATTERN.test(value.recordDigest ?? '')
  ) failure();
  canonicalTimestamp(value.consumedAt, failure);
  const record = {
    schemaVersion: 1,
    recordType: 'RUNTIME_PLAN_CONSUMED',
    planTicketId: value.planTicketId,
    deviceId: value.deviceId,
    ticketRecordDigest: value.ticketRecordDigest,
    authorizationDigest: value.authorizationDigest,
    consumedAt: value.consumedAt,
    recordDigest: value.recordDigest,
  };
  if (digestRecord(CONSUMED_DOMAIN, ticketBase(record)) !== record.recordDigest) failure();
  return Object.freeze(record);
}

function sameIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function sameDirectoryEndpoint(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid;
}

function currentUid() {
  if (typeof process.geteuid !== 'function') failState();
  return BigInt(process.geteuid());
}

async function maybeLstat(path) {
  try {
    return await lstat(path, { bigint: true });
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

async function assertNoDarwinExtendedAcl(path) {
  if (process.platform !== 'darwin') return;
  let output;
  try {
    output = await execFile('/bin/ls', ['-lde', '--', path], {
      encoding: 'utf8',
      env: Object.freeze({
        LANG: 'C',
        LC_ALL: 'C',
        PATH: '/usr/bin:/bin',
      }),
      maxBuffer: 16 * 1_024,
      timeout: 2_000,
    });
  } catch {
    failState();
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
  ) failState();
}

async function assertTrustedDirectory(path, managed = false) {
  const before = await lstat(path, { bigint: true });
  if (
    !before.isDirectory()
    || before.isSymbolicLink()
    || before.uid !== currentUid()
    || (before.mode & 0o022n) !== 0n
    || (managed && (before.mode & 0o777n) !== BigInt(DIRECTORY_MODE))
  ) failState();
  const canonical = await realpath(path);
  if (canonical !== path) failState();
  await assertNoDarwinExtendedAcl(path);
  const after = await lstat(path, { bigint: true });
  if (!sameDirectoryEndpoint(before, after)) failState();
  return after;
}

async function nearestExistingDirectory(path) {
  let candidate = path;
  while (true) {
    const stats = await maybeLstat(candidate);
    if (stats !== null) return candidate;
    const parent = dirname(candidate);
    if (parent === candidate) failState();
    candidate = parent;
  }
}

function managedParts(root, target) {
  const suffix = relative(root, target);
  if (suffix.startsWith('..') || isAbsolute(suffix)) failState();
  if (suffix === '') return [];
  const parts = suffix.split(sep);
  if (parts.some((part) => part.length === 0 || part === '.' || part === '..')) failState();
  return parts;
}

async function syncDirectory(path) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try { await file.sync(); } finally { await file.close(); }
}

async function ensureManagedRoot(root) {
  const nearest = await nearestExistingDirectory(root);
  await assertTrustedDirectory(nearest, nearest === root);
  const suffix = relative(nearest, root);
  if (suffix === '') return;
  if (suffix.startsWith('..') || isAbsolute(suffix)) failState();
  let cursor = nearest;
  for (const part of suffix.split(sep)) {
    const parent = cursor;
    cursor = join(cursor, part);
    try { await mkdir(cursor, { mode: DIRECTORY_MODE }); } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
    }
    await assertTrustedDirectory(cursor, true);
    await syncDirectory(parent);
  }
}

async function ensureManagedChain(root, target) {
  await ensureManagedRoot(root);
  let cursor = root;
  await assertTrustedDirectory(cursor, true);
  for (const part of managedParts(root, target)) {
    const parent = cursor;
    cursor = join(cursor, part);
    try { await mkdir(cursor, { mode: DIRECTORY_MODE }); } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
    }
    await assertTrustedDirectory(cursor, true);
    await syncDirectory(parent);
  }
}

async function assertManagedChain(root, target) {
  let cursor = root;
  await assertTrustedDirectory(cursor, true);
  for (const part of managedParts(root, target)) {
    cursor = join(cursor, part);
    await assertTrustedDirectory(cursor, true);
  }
}

async function authorizationStoreAbsent(root, paths) {
  const nearest = await nearestExistingDirectory(root);
  const rootBefore = await assertTrustedDirectory(nearest, nearest === root);
  if (nearest !== root) {
    const rootAfter = await assertTrustedDirectory(nearest, false);
    if (!sameDirectoryEndpoint(rootBefore, rootAfter)) failState();
    return await maybeLstat(root) === null;
  }
  if (await maybeLstat(paths.device) === null) {
    const rootAfter = await assertTrustedDirectory(root, true);
    if (!sameDirectoryEndpoint(rootBefore, rootAfter)) failState();
    return await maybeLstat(paths.device) === null;
  }

  const deviceBefore = await assertTrustedDirectory(paths.device, true);
  if (await maybeLstat(paths.authorization) !== null) return false;
  const deviceAfter = await assertTrustedDirectory(paths.device, true);
  const rootAfter = await assertTrustedDirectory(root, true);
  if (
    !sameDirectoryEndpoint(deviceBefore, deviceAfter)
    || !sameDirectoryEndpoint(rootBefore, rootAfter)
  ) failState();
  return await maybeLstat(paths.authorization) === null;
}

function assertSafeLock(stats) {
  if (
    !stats.isFile()
    || stats.isSymbolicLink()
    || stats.uid !== currentUid()
    || (stats.mode & 0o777n) !== BigInt(FILE_MODE)
    || stats.nlink !== 1n
    || stats.size !== 0n
  ) failState();
}

async function assertStoreTopology(root, paths) {
  await assertManagedChain(root, paths.tickets);
  await assertManagedChain(root, paths.consumed);
  const names = (await readdir(paths.authorization)).sort();
  if (JSON.stringify(names) !== JSON.stringify(['.store.lock', 'consumed-v1', 'tickets-v1'])) {
    failState();
  }
}

async function openStoreLock(root, paths, create) {
  if (create) {
    await ensureManagedChain(root, paths.tickets);
    await ensureManagedChain(root, paths.consumed);
  } else {
    if (await authorizationStoreAbsent(root, paths)) failInput();
    await assertManagedChain(root, paths.consumed);
  }
  let file;
  if (create) {
    try {
      file = await open(
        paths.lock,
        constants.O_RDWR | constants.O_CREAT | constants.O_EXCL
          | constants.O_NOFOLLOW | constants.O_NONBLOCK,
        FILE_MODE,
      );
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
    }
  }
  if (!file) {
    file = await open(paths.lock, constants.O_RDWR | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  }
  try {
    const opened = await file.stat({ bigint: true });
    assertSafeLock(opened);
    const endpoint = await lstat(paths.lock, { bigint: true });
    assertSafeLock(endpoint);
    if (!sameIdentity(opened, endpoint)) failState();
    await assertNoDarwinExtendedAcl(paths.lock);
    const openedAfterAcl = await file.stat({ bigint: true });
    const endpointAfterAcl = await lstat(paths.lock, { bigint: true });
    assertSafeLock(openedAfterAcl);
    assertSafeLock(endpointAfterAcl);
    if (
      !sameIdentity(opened, openedAfterAcl)
      || !sameIdentity(openedAfterAcl, endpointAfterAcl)
    ) failState();
    await assertNoDarwinExtendedAcl(paths.lock);
    const openedFinal = await file.stat({ bigint: true });
    const endpointFinal = await lstat(paths.lock, { bigint: true });
    assertSafeLock(openedFinal);
    assertSafeLock(endpointFinal);
    if (
      !sameIdentity(openedAfterAcl, openedFinal)
      || !sameIdentity(openedFinal, endpointFinal)
    ) failState();
    await file.sync();
    await syncDirectory(paths.authorization);
    await assertStoreTopology(root, paths);
    return Object.freeze({ file, stats: openedFinal });
  } catch (error) {
    await file.close();
    throw error;
  }
}

async function acquireStoreLock(file) {
  if (process.platform !== 'darwin') failState();
  await new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    let outputLength = 0;
    let invalid = false;
    let timedOut = false;
    let timer;
    const child = spawn('/usr/bin/lockf', ['-s', '-t', String(LOCKF_WAIT_SECONDS), '3'], {
      env: Object.freeze({ LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' }),
      stdio: ['ignore', 'pipe', 'pipe', file.fd],
      windowsHide: true,
    });
    const settle = (error = null) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      if (error === null) resolvePromise();
      else rejectPromise(error);
    };
    const observe = (chunk) => {
      outputLength += chunk.length;
      if (outputLength > LOCKF_OUTPUT_LIMIT) {
        invalid = true;
        child.kill('SIGKILL');
      }
    };
    child.stdout.on('data', observe);
    child.stderr.on('data', observe);
    child.once('error', () => settle(runtimeError('RUNTIME_STATE_UNSUPPORTED')));
    child.once('close', (code, signal) => {
      if (timedOut || invalid || signal !== null || outputLength !== 0) {
        settle(runtimeError('RUNTIME_STATE_UNSUPPORTED'));
      } else if (code === LOCKF_TEMPFAIL) {
        settle(runtimeError('RUNTIME_ALREADY_RUNNING'));
      } else if (code !== 0) {
        settle(runtimeError('RUNTIME_STATE_UNSUPPORTED'));
      } else {
        settle();
      }
    });
    timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, (LOCKF_WAIT_SECONDS * 1_000) + LOCKF_WATCHDOG_GRACE_MS);
    timer.unref();
  });
}

async function withStoreLock(root, paths, create, operation) {
  const anchor = await openStoreLock(root, paths, create);
  let primary;
  let result;
  try {
    await acquireStoreLock(anchor.file);
    const current = await anchor.file.stat({ bigint: true });
    const endpoint = await lstat(paths.lock, { bigint: true });
    assertSafeLock(current);
    assertSafeLock(endpoint);
    if (!sameIdentity(anchor.stats, current) || !sameIdentity(current, endpoint)) failState();
    await assertStoreTopology(root, paths);
    result = await operation();
    await assertStoreTopology(root, paths);
  } catch (error) {
    primary = error;
  } finally {
    try { await anchor.file.close(); } catch (error) { primary ??= error; }
  }
  if (primary !== undefined) throw primary;
  return result;
}

function finalPattern(kind) {
  return kind === 'ticket'
    ? /^rpt_[a-f0-9]{64}\.json$/u
    : /^rpt_[a-f0-9]{64}\.json$/u;
}

function witnessPattern() {
  return /^(rpt_[a-f0-9]{64}\.json)\.publish-([a-f0-9-]{36})\.tmp$/u;
}

async function assertPublicationPair(final, witness) {
  const first = await lstat(final, { bigint: true });
  const second = await lstat(witness, { bigint: true });
  for (const stats of [first, second]) {
    if (
      !stats.isFile()
      || stats.isSymbolicLink()
      || stats.uid !== currentUid()
      || (stats.mode & 0o777n) !== BigInt(FILE_MODE)
      || stats.nlink !== 2n
      || stats.size < 1n
      || stats.size > BigInt(MAX_RECORD_BYTES)
    ) failState();
  }
  if (first.dev !== second.dev || first.ino !== second.ino) failState();
  await assertNoDarwinExtendedAcl(final);
  await assertNoDarwinExtendedAcl(witness);
  const finalAfter = await lstat(final, { bigint: true });
  const witnessAfter = await lstat(witness, { bigint: true });
  if (!sameIdentity(first, finalAfter) || !sameIdentity(second, witnessAfter)) failState();
  return first;
}

async function inspectNamespace(directory) {
  const names = await readdir(directory);
  if (names.length > MAX_NAMESPACE_ENTRIES) failState();
  const records = new Map();
  for (const name of names) {
    if (finalPattern().test(name)) {
      const value = records.get(name) ?? { final: false, witnesses: [] };
      if (value.final) failState();
      value.final = true;
      records.set(name, value);
      continue;
    }
    const match = witnessPattern().exec(name);
    if (match === null || !UUID_PATTERN.test(match[2])) failState();
    const value = records.get(match[1]) ?? { final: false, witnesses: [] };
    value.witnesses.push(name);
    records.set(match[1], value);
  }
  for (const [name, value] of records) {
    if (!value.final || value.witnesses.length !== 1) failState();
    await assertPublicationPair(join(directory, name), join(directory, value.witnesses[0]));
  }
  return records;
}

async function readStableRecord(path, witness, validator) {
  const expected = await assertPublicationPair(path, witness);
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = await file.stat({ bigint: true });
    if (!sameIdentity(expected, opened)) failState();
    const size = Number(opened.size);
    const first = Buffer.alloc(size);
    const second = Buffer.alloc(size);
    const firstRead = await file.read(first, 0, size, 0);
    const secondRead = await file.read(second, 0, size, 0);
    if (
      firstRead.bytesRead !== size
      || secondRead.bytesRead !== size
      || !timingSafeEqual(first, second)
    ) failState();
    const after = await file.stat({ bigint: true });
    const endpoint = await lstat(path, { bigint: true });
    if (!sameIdentity(opened, after) || !sameIdentity(after, endpoint)) failState();
    let text;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(first); } catch { failState(); }
    let parsed;
    try { parsed = JSON.parse(text); } catch { failState(); }
    const record = validator(parsed, failState);
    if (`${JSON.stringify(record, null, 2)}\n` !== text) failState();
    return record;
  } finally {
    await file.close();
  }
}

async function readExactFromNamespace(paths, kind, planTicketId, missingAllowed = false) {
  const directory = kind === 'ticket' ? paths.tickets : paths.consumed;
  const final = kind === 'ticket' ? paths.ticket : paths.consumedRecord;
  const records = await inspectNamespace(directory);
  const name = `${planTicketId}.json`;
  const publication = records.get(name);
  if (publication === undefined) {
    if (missingAllowed) return null;
    failInput();
  }
  const witness = join(directory, publication.witnesses[0]);
  const record = await readStableRecord(
    final,
    witness,
    kind === 'ticket' ? canonicalTicket : canonicalConsumed,
  );
  if (record.planTicketId !== planTicketId) failState();
  return record;
}

async function publishRecord(root, paths, kind, record) {
  const directory = kind === 'ticket' ? paths.tickets : paths.consumed;
  const final = kind === 'ticket' ? paths.ticket : paths.consumedRecord;
  await assertManagedChain(root, directory);
  const before = await inspectNamespace(directory);
  const finalName = `${record.planTicketId}.json`;
  if (before.has(finalName)) throw runtimeError('RUNTIME_ALREADY_RUNNING');
  const temporary = `${final}.publish-${randomUUID()}.tmp`;
  const bytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`, 'utf8');
  if (bytes.length < 1 || bytes.length > MAX_RECORD_BYTES) failInput();
  let file;
  let written;
  try {
    file = await open(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      FILE_MODE,
    );
    await file.writeFile(bytes);
    await file.sync();
    written = await file.stat({ bigint: true });
  } finally {
    await file?.close();
  }
  if (
    !written.isFile()
    || written.uid !== currentUid()
    || (written.mode & 0o777n) !== BigInt(FILE_MODE)
    || written.nlink !== 1n
    || written.size !== BigInt(bytes.length)
  ) failState();
  const staged = await lstat(temporary, { bigint: true });
  if (!sameIdentity(written, staged)) failState();
  await assertNoDarwinExtendedAcl(temporary);
  await assertManagedChain(root, directory);
  try { await link(temporary, final); } catch (error) {
    if (error?.code === 'EEXIST') throw runtimeError('RUNTIME_ALREADY_RUNNING');
    throw error;
  }
  await assertPublicationPair(final, temporary);
  await syncDirectory(directory);
  const after = await inspectNamespace(directory);
  const publication = after.get(finalName);
  if (publication === undefined || publication.witnesses[0] !== temporary.slice(directory.length + 1)) {
    failState();
  }
  return readStableRecord(
    final,
    temporary,
    kind === 'ticket' ? canonicalTicket : canonicalConsumed,
  );
}

function safeCode(error) {
  if (error === null || (typeof error !== 'object' && typeof error !== 'function') || isProxy(error)) {
    return null;
  }
  try {
    const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
    return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : null;
  } catch {
    return null;
  }
}

function mapFailure(error) {
  const code = safeCode(error);
  if (typeof code === 'string' && KNOWN_CODES.has(code)) {
    return runtimeError(code, code === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  }
  if (['ENOENT', 'ENOTDIR', 'ELOOP', 'EACCES', 'EPERM'].includes(code)) {
    return runtimeError('RUNTIME_STATE_UNSUPPORTED');
  }
  return runtimeError('RUNTIME_INTERNAL_ERROR');
}

async function mapped(operation) {
  try { return await operation(); } catch (error) { throw mapFailure(error); }
}

function storeOptions(input) {
  if (input === undefined) return { now: () => new Date(), randomBytes: cryptoRandomBytes };
  const value = exactObject(input, ['now', 'randomBytes']);
  if (
    typeof value.now !== 'function'
    || isProxy(value.now)
    || typeof value.randomBytes !== 'function'
    || isProxy(value.randomBytes)
  ) failInput();
  return value;
}

function ticketCreateInput(input) {
  const value = exactObject(input, TICKET_INPUT_FIELDS);
  if (
    typeof value.deviceId !== 'string'
    || value.deviceId.length > 64
    || !DEVICE_ID_PATTERN.test(value.deviceId)
    || typeof value.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(value.operationId)
    || typeof value.authorizationDigest !== 'string'
    || !SHA256_PATTERN.test(value.authorizationDigest)
  ) failInput();
  canonicalTimestamp(value.createdAt);
  const output = { ...value };
  for (const field of TICKET_INPUT_FIELDS.slice(3, -1)) output[field] = safeClone(value[field]);
  if (
    output.plan === null
    || typeof output.plan !== 'object'
    || output.plan.operationId !== output.operationId
    || output.plan.createdAt !== output.createdAt
  ) failInput();
  return output;
}

function randomTicketId(randomBytes) {
  let bytes;
  try { bytes = randomBytes(32); } catch { throw runtimeError('RUNTIME_INTERNAL_ERROR'); }
  if (
    bytes === null
    || typeof bytes !== 'object'
    || isProxy(bytes)
    || !Buffer.isBuffer(bytes)
    || Object.getPrototypeOf(bytes) !== Buffer.prototype
    || Object.getOwnPropertySymbols(bytes).length !== 0
    || bytes.length !== 32
    || Object.getOwnPropertyNames(bytes).length !== 32
  ) {
    throw runtimeError('RUNTIME_INTERNAL_ERROR');
  }
  for (let index = 0; index < 32; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(bytes, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
      throw runtimeError('RUNTIME_INTERNAL_ERROR');
    }
  }
  const snapshot = Buffer.from(bytes);
  return `rpt_${Buffer.prototype.toString.call(snapshot, 'hex')}`;
}

export class RuntimePlanTicketStore {
  #root;
  #now;
  #randomBytes;

  constructor(runtimeDevicesRoot, options) {
    this.#root = validateRoot(runtimeDevicesRoot);
    const selected = storeOptions(options);
    this.#now = selected.now;
    this.#randomBytes = selected.randomBytes;
    Object.freeze(this);
  }

  async createTicket(input) {
    let value;
    try { value = ticketCreateInput(input); } catch (error) { throw mapFailure(error); }
    return mapped(async () => {
      const now = canonicalNow(this.#now);
      if (now < value.createdAt) failState();
      const expiresAt = new Date(
        Date.parse(value.createdAt) + RUNTIME_PLAN_TICKET_TTL_MS,
      ).toISOString();
      if (now >= expiresAt) failInput();
      const planTicketId = randomTicketId(this.#randomBytes);
      const base = {
        schemaVersion: 1,
        recordType: 'RUNTIME_PLAN_TICKET',
        planTicketId,
        ...value,
        expiresAt,
      };
      const ticket = canonicalTicket({
        ...base,
        recordDigest: digestRecord(TICKET_DOMAIN, base),
      });
      const paths = authorizationPaths(this.#root, value.deviceId, planTicketId);
      return withStoreLock(
        this.#root,
        paths,
        true,
        () => publishRecord(this.#root, paths, 'ticket', ticket),
      );
    });
  }

  async readTicket(input) {
    let value;
    try {
      value = exactObject(input, ['deviceId', 'planTicketId']);
      authorizationPaths(this.#root, value.deviceId, value.planTicketId);
    } catch (error) { throw mapFailure(error); }
    return mapped(async () => {
      const paths = authorizationPaths(this.#root, value.deviceId, value.planTicketId);
      return withStoreLock(this.#root, paths, false, async () => {
        if (await readExactFromNamespace(paths, 'consumed', value.planTicketId, true)) failInput();
        const ticket = await readExactFromNamespace(paths, 'ticket', value.planTicketId);
        if (ticket.deviceId !== value.deviceId) failState();
        const now = canonicalNow(this.#now);
        if (now < ticket.createdAt) failState();
        if (now >= ticket.expiresAt) failInput();
        return ticket;
      });
    });
  }

  async consumeTicket(input) {
    let value;
    try {
      value = exactObject(input, CONSUME_INPUT_FIELDS);
      authorizationPaths(this.#root, value.deviceId, value.planTicketId);
      if (
        !SHA256_PATTERN.test(value.ticketRecordDigest ?? '')
        || !SHA256_PATTERN.test(value.authorizationDigest ?? '')
      ) failInput();
    } catch (error) { throw mapFailure(error); }
    return mapped(async () => {
      const paths = authorizationPaths(this.#root, value.deviceId, value.planTicketId);
      return withStoreLock(this.#root, paths, false, async () => {
        if (await readExactFromNamespace(paths, 'consumed', value.planTicketId, true)) failInput();
        const ticket = await readExactFromNamespace(paths, 'ticket', value.planTicketId);
        const now = canonicalNow(this.#now);
        if (
          ticket.deviceId !== value.deviceId
          || ticket.recordDigest !== value.ticketRecordDigest
          || ticket.authorizationDigest !== value.authorizationDigest
          || now >= ticket.expiresAt
        ) failInput();
        if (now < ticket.createdAt) failState();
        const base = {
          schemaVersion: 1,
          recordType: 'RUNTIME_PLAN_CONSUMED',
          planTicketId: value.planTicketId,
          deviceId: value.deviceId,
          ticketRecordDigest: ticket.recordDigest,
          authorizationDigest: ticket.authorizationDigest,
          consumedAt: now,
        };
        const consumed = canonicalConsumed({
          ...base,
          recordDigest: digestRecord(CONSUMED_DOMAIN, base),
        });
        return publishRecord(this.#root, paths, 'consumed', consumed);
      });
    });
  }
}
