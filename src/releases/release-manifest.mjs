import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { TextDecoder } from 'node:util';

const MAX_MANIFEST_BYTES = 64 * 1024;
const ROOT_KEYS = ['schemaVersion', 'tailscaleWindows'];
const WINDOWS_RELEASE_KEYS = ['version', 'url', 'sha256', 'authenticodeSubject'];
const VERSION_PATTERN = /^\d+\.\d+\.\d+$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const AUTHENTICODE_SUBJECT = 'CN=Tailscale Inc.';

function manifestError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function normalizePath(path) {
  let value = path;
  if (path instanceof URL) {
    if (path.protocol !== 'file:') {
      throw manifestError('RELEASE_MANIFEST_PATH_INVALID');
    }
    try {
      value = fileURLToPath(path);
    } catch {
      throw manifestError('RELEASE_MANIFEST_PATH_INVALID');
    }
  }
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    throw manifestError('RELEASE_MANIFEST_PATH_INVALID');
  }
  return resolve(value);
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

async function readExact(file, size) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const { bytesRead } = await file.read(bytes, offset, size - offset, offset);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  if (offset !== size) {
    throw manifestError('RELEASE_MANIFEST_UNSAFE_FILE');
  }
  return bytes;
}

async function readStableManifest(path) {
  let file;
  let primaryError;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const initial = await file.stat();
    if (!initial.isFile() || initial.nlink !== 1) {
      throw manifestError('RELEASE_MANIFEST_UNSAFE_FILE');
    }
    if (initial.size <= 0 || initial.size > MAX_MANIFEST_BYTES) {
      throw manifestError('RELEASE_MANIFEST_INVALID');
    }

    const first = await readExact(file, initial.size);
    const middle = await file.stat();
    if (!sameFileState(initial, middle)) {
      throw manifestError('RELEASE_MANIFEST_UNSAFE_FILE');
    }
    const second = await readExact(file, initial.size);
    const final = await file.stat();
    if (!sameFileState(middle, final) || !first.equals(second)) {
      throw manifestError('RELEASE_MANIFEST_UNSAFE_FILE');
    }
    return first;
  } catch (error) {
    if (error.code === 'ELOOP') {
      primaryError = manifestError('RELEASE_MANIFEST_UNSAFE_FILE');
      throw primaryError;
    }
    primaryError = error;
    throw error;
  } finally {
    try {
      await file?.close();
    } catch (error) {
      if (!primaryError) throw error;
    }
  }
}

function hasExactKeys(value, keys) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function validateManifest(value) {
  if (!hasExactKeys(value, ROOT_KEYS) || value.schemaVersion !== 1) {
    throw manifestError('RELEASE_MANIFEST_INVALID');
  }

  const release = value.tailscaleWindows;
  if (
    !hasExactKeys(release, WINDOWS_RELEASE_KEYS)
    || typeof release.version !== 'string'
    || !VERSION_PATTERN.test(release.version)
    || typeof release.url !== 'string'
    || release.url !== `https://pkgs.tailscale.com/stable/tailscale-setup-full-${release.version}.exe`
    || typeof release.sha256 !== 'string'
    || !SHA256_PATTERN.test(release.sha256)
    || release.authenticodeSubject !== AUTHENTICODE_SUBJECT
  ) {
    throw manifestError('RELEASE_MANIFEST_INVALID');
  }
}

function freezeDeep(value) {
  for (const child of Object.values(value)) {
    if (child !== null && typeof child === 'object') freezeDeep(child);
  }
  return Object.freeze(value);
}

export async function loadReleaseManifest(path) {
  const normalizedPath = normalizePath(path);
  const bytes = await readStableManifest(normalizedPath);
  let value;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw manifestError('RELEASE_MANIFEST_INVALID');
  }
  validateManifest(value);
  return freezeDeep(structuredClone(value));
}
