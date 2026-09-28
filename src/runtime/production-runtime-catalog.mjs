import { execFile as execFileCallback } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import {
  lstat,
  open,
  realpath,
} from 'node:fs/promises';
import { dirname } from 'node:path';
import { TextDecoder, promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import { validateRuntimeCatalog } from './runtime-catalog.mjs';

const PRODUCTION_CATALOG_URL = new URL('../../config/runtime-catalog.json', import.meta.url);
const PRODUCTION_CATALOG_PATH = fileURLToPath(PRODUCTION_CATALOG_URL);
const PRODUCTION_CATALOG_DIRECTORY = dirname(PRODUCTION_CATALOG_PATH);
const MAX_CATALOG_BYTES = 64 * 1024;
const REVIEWED_CATALOG_SHA256 = '0F3D79110E3C286DCCFEE5941652F4B0A58647DC35D8BC39BA64535F8DCD47E9';
const execFile = promisify(execFileCallback);

function internalError() {
  const error = new Error('RUNTIME_INTERNAL_ERROR');
  error.code = 'RUNTIME_INTERNAL_ERROR';
  return error;
}

function sameFileState(left, right) {
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

function trustedOwner(stats) {
  if (typeof process.geteuid !== 'function') return true;
  const effectiveUid = BigInt(process.geteuid());
  return stats.uid === effectiveUid || stats.uid === 0n;
}

function safeRegularFile(handleStats, pathStats) {
  return handleStats.isFile()
    && !handleStats.isSymbolicLink()
    && pathStats.isFile()
    && !pathStats.isSymbolicLink()
    && handleStats.nlink === 1n
    && handleStats.size > 0n
    && handleStats.size <= BigInt(MAX_CATALOG_BYTES)
    && (handleStats.mode & 0o022n) === 0n
    && trustedOwner(handleStats)
    && sameFileState(handleStats, pathStats);
}

function safeCatalogDirectory(stats, canonicalPath) {
  return stats.isDirectory()
    && !stats.isSymbolicLink()
    && canonicalPath === PRODUCTION_CATALOG_DIRECTORY
    && (stats.mode & 0o022n) === 0n
    && trustedOwner(stats);
}

async function assertNoDarwinExtendedAcl(paths) {
  if (process.platform !== 'darwin') return;
  const { stdout, stderr } = await execFile('/bin/ls', [
    '-lde',
    '--',
    ...paths,
  ], {
    encoding: 'utf8',
    env: Object.freeze({
      LANG: 'C',
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
    }),
    maxBuffer: 32 * 1024,
  });
  if (
    typeof stdout !== 'string'
    || typeof stderr !== 'string'
    || stderr !== ''
    || stdout.length === 0
    || stdout.includes('\0')
    || /^\s+[0-9]+:\s/mu.test(stdout)
  ) throw internalError();
}

async function inspectCatalogDirectory(expected) {
  const initial = await lstat(PRODUCTION_CATALOG_DIRECTORY, { bigint: true });
  const initialCanonical = await realpath(PRODUCTION_CATALOG_DIRECTORY);
  if (!safeCatalogDirectory(initial, initialCanonical)) throw internalError();
  await assertNoDarwinExtendedAcl([PRODUCTION_CATALOG_DIRECTORY]);
  const final = await lstat(PRODUCTION_CATALOG_DIRECTORY, { bigint: true });
  const finalCanonical = await realpath(PRODUCTION_CATALOG_DIRECTORY);
  if (
    !safeCatalogDirectory(final, finalCanonical)
    || !sameFileState(initial, final)
    || (expected !== undefined && !sameFileState(expected, final))
  ) throw internalError();
  return final;
}

async function readExact(file, size) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const { bytesRead } = await file.read(bytes, offset, size - offset, offset);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  if (offset !== size) throw internalError();
  return bytes;
}

async function readStableCatalog() {
  let file;
  try {
    const directory = await inspectCatalogDirectory();
    file = await open(
      PRODUCTION_CATALOG_URL,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const initial = await file.stat({ bigint: true });
    const initialPath = await lstat(PRODUCTION_CATALOG_URL, { bigint: true });
    if (!safeRegularFile(initial, initialPath)) throw internalError();
    await assertNoDarwinExtendedAcl([PRODUCTION_CATALOG_PATH]);
    const aclChecked = await file.stat({ bigint: true });
    const aclCheckedPath = await lstat(PRODUCTION_CATALOG_URL, { bigint: true });
    if (!safeRegularFile(aclChecked, aclCheckedPath) || !sameFileState(initial, aclChecked)) {
      throw internalError();
    }

    const size = Number(initial.size);
    const first = await readExact(file, size);
    const middle = await file.stat({ bigint: true });
    const middlePath = await lstat(PRODUCTION_CATALOG_URL, { bigint: true });
    if (!safeRegularFile(middle, middlePath) || !sameFileState(initial, middle)) {
      throw internalError();
    }

    const second = await readExact(file, size);
    await assertNoDarwinExtendedAcl([PRODUCTION_CATALOG_PATH]);
    const final = await file.stat({ bigint: true });
    const finalPath = await lstat(PRODUCTION_CATALOG_URL, { bigint: true });
    if (
      !safeRegularFile(final, finalPath)
      || !sameFileState(middle, final)
      || !first.equals(second)
    ) throw internalError();
    await inspectCatalogDirectory(directory);
    return first;
  } finally {
    await file?.close();
  }
}

export async function loadProductionRuntimeCatalog() {
  try {
    const bytes = await readStableCatalog();
    const digest = createHash('sha256').update(bytes).digest('hex').toUpperCase();
    if (digest !== REVIEWED_CATALOG_SHA256) throw internalError();
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const parsed = JSON.parse(text);
    const catalog = validateRuntimeCatalog(parsed);
    const canonicalBytes = Buffer.from(`${JSON.stringify(catalog)}\n`, 'utf8');
    if (!bytes.equals(canonicalBytes)) throw internalError();
    return catalog;
  } catch {
    throw internalError();
  }
}
