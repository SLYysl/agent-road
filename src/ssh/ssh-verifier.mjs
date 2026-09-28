import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  chmod,
  lstat,
  mkdtemp,
  open,
  readFile,
  rm,
} from 'node:fs/promises';
import { constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { runProcess as defaultRunProcess } from '../process/run-process.mjs';
import { withTrustedSshSession } from './trusted-ssh-session.mjs';

const MAX_PROBE_OUTPUT_BYTES = 16 * 1024;
const FILE_BYTES = 257;
const PROBE_FIELDS = new Set(['username', 'administrator', 'powershellVersion', 'nonce']);
const INPUT_FIELDS = new Set([
  'deviceId',
  'address',
  'sshHostKeys',
  'sshHostKeyFingerprints',
  'privateKeyPath',
  'knownHostsPath',
  'runProcess',
]);
const CAPABILITIES = Object.freeze(['ssh', 'sftp', 'admin-powershell']);

function verifierError(code = 'SSH_VERIFY_FAILED') {
  const error = new Error(code);
  error.code = code;
  return error;
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
  for (const required of [...INPUT_FIELDS].filter((field) => field !== 'runProcess')) {
    if (!Object.hasOwn(snapshot, required)) failInput();
  }
  if (!Object.hasOwn(snapshot, 'runProcess')) snapshot.runProcess = defaultRunProcess;
  return snapshot;
}

function runResult(result, { stderr = false } = {}) {
  return Boolean(
    result
    && result.exitCode === 0
    && result.signal === null
    && typeof result.stdout === 'string'
    && typeof result.stderr === 'string'
    && (stderr || result.stderr === ''),
  );
}

function powershellProbe(nonce) {
  const script = [
    "$ErrorActionPreference='Stop'",
    "$ProgressPreference='SilentlyContinue'",
    '$i=[Security.Principal.WindowsIdentity]::GetCurrent()',
    '$p=New-Object Security.Principal.WindowsPrincipal($i)',
    "[IO.Directory]::CreateDirectory('C:\\ProgramData\\AgentRoad\\probe')|Out-Null",
    `$o=[ordered]@{username=($i.Name -split '\\\\')[-1];administrator=$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);powershellVersion=$PSVersionTable.PSVersion.ToString();nonce='${nonce}'}`,
    '$o|ConvertTo-Json -Compress',
  ].join(';');
  return Buffer.from(script, 'utf16le').toString('base64');
}

function parseProbe(result, nonce) {
  if (!runResult(result) || Buffer.byteLength(result.stdout) > MAX_PROBE_OUTPUT_BYTES) throw verifierError();
  const text = result.stdout.endsWith('\r\n')
    ? result.stdout.slice(0, -2)
    : result.stdout.endsWith('\n')
      ? result.stdout.slice(0, -1)
      : result.stdout;
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw verifierError();
  }
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).length !== PROBE_FIELDS.size
    || !Object.keys(value).every((key) => PROBE_FIELDS.has(key))
    || value.username !== 'AgentRoad'
    || value.administrator !== true
    || typeof value.powershellVersion !== 'string'
    || value.powershellVersion.length === 0
    || value.powershellVersion.length > 32
    || !/^\d+(?:\.\d+){1,3}$/.test(value.powershellVersion)
    || value.nonce !== nonce
    || JSON.stringify(value) !== text
  ) throw verifierError();
  return value;
}

function remoteCleanupCommand(remotePath) {
  return [
    "$ProgressPreference='SilentlyContinue'",
    `$p='${remotePath}'`,
    'if(Test-Path -LiteralPath $p -ErrorAction Stop){Remove-Item -LiteralPath $p -Force -ErrorAction Stop}',
    "if(Test-Path -LiteralPath $p -ErrorAction Stop){throw 'REMOTE_CLEANUP_FAILED'}",
  ].join(';');
}

async function tryAddress(session, address) {
  const nonce = randomBytes(24).toString('base64url');
  const probe = await session.invokeSsh(address, [
    'powershell.exe',
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-EncodedCommand',
    powershellProbe(nonce),
  ]);
  parseProbe(probe, nonce);

  const directory = await mkdtemp(join(tmpdir(), 'agent-road-file-probe-'));
  await chmod(directory, 0o700);
  const sourcePath = join(directory, 'upload.bin');
  const downloadedPath = join(directory, 'download.bin');
  const remotePath = `C:/ProgramData/AgentRoad/probe/${nonce}.bin`;
  let primaryError;
  let fixtureStarted = false;
  try {
    const fixture = randomBytes(FILE_BYTES);
    const sourceFile = await open(
      sourcePath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    try {
      await sourceFile.writeFile(fixture);
      await sourceFile.sync();
    } finally {
      await sourceFile.close();
    }
    fixtureStarted = true;
    const upload = await session.invokeScp([
      sourcePath,
      session.remoteSpec(address, remotePath),
    ]);
    if (!runResult(upload)) throw verifierError();
    const download = await session.invokeScp([
      session.remoteSpec(address, remotePath),
      downloadedPath,
    ]);
    if (!runResult(download)) throw verifierError();
    const downloadedStats = await lstat(downloadedPath);
    if (
      !downloadedStats.isFile()
      || downloadedStats.isSymbolicLink()
      || downloadedStats.nlink !== 1
      || downloadedStats.size !== FILE_BYTES
    ) throw verifierError();
    const downloaded = await readFile(downloadedPath);
    if (!timingSafeEqual(
      createHash('sha256').update(fixture).digest(),
      createHash('sha256').update(downloaded).digest(),
    )) throw verifierError();
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    let cleanupError;
    if (fixtureStarted) {
      try {
        const cleanup = await session.invokeCleanup(address, [
          'powershell.exe',
          '-NoLogo',
          '-NoProfile',
          '-NonInteractive',
          '-EncodedCommand',
          Buffer.from(remoteCleanupCommand(remotePath), 'utf16le').toString('base64'),
        ]);
        if (!runResult(cleanup)) throw verifierError();
      } catch (error) {
        cleanupError = verifierError('SSH_VERIFY_REMOTE_CLEANUP_UNCERTAIN');
      }
    }
    let localCleanupError;
    try { await rm(directory, { recursive: true, force: true }); } catch (error) {
      localCleanupError = error;
    }
    if (cleanupError && primaryError?.code !== 'SSH_VERIFY_UNSAFE_PATH') throw cleanupError;
    if (localCleanupError && primaryError?.code !== 'SSH_VERIFY_UNSAFE_PATH') {
      throw cleanupFailure(primaryError);
    }
  }
}

async function verifySession(session) {
  for (const address of session.addresses) {
    try {
      await tryAddress(session, address);
      return Object.freeze({ address, capabilities: CAPABILITIES });
    } catch (error) {
      if (
        error.code === 'SSH_VERIFY_UNSAFE_PATH'
        || error.code === 'SSH_VERIFY_REMOTE_CLEANUP_UNCERTAIN'
        || error.code === 'SSH_VERIFY_CLEANUP_FAILED'
      ) throw error;
    }
  }
  throw verifierError();
}

export async function verifyWindowsSsh(input) {
  try {
    const config = snapshotInput(input);
    const addresses = typeof config.address === 'string' ? [config.address] : config.address;
    return await withTrustedSshSession({
      deviceId: config.deviceId,
      addresses,
      hostKeys: config.sshHostKeys,
      fingerprints: config.sshHostKeyFingerprints,
      privateKeyPath: config.privateKeyPath,
      knownHostsPath: config.knownHostsPath,
      runProcess: config.runProcess,
    }, verifySession);
  } catch (error) {
    if (
      error?.code === 'SSH_VERIFY_INPUT_INVALID'
      || error?.code === 'SSH_VERIFY_UNSAFE_PATH'
      || error?.code === 'SSH_VERIFY_CLEANUP_FAILED'
    ) throw error;
    throw verifierError();
  }
}
