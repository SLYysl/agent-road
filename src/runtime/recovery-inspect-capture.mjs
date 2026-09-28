import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { link, lstat, mkdir, open, readdir, unlink } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { createRecoveryInspectStageCapture, isRecoveryInspectStage } from './recovery-inspect-stage.mjs';

const MAX_OUTPUT_BYTES = 65_536;
const MAX_RECORD_BYTES = 2_048;
const ERRORS = new Set([
  'RUNTIME_ALREADY_RUNNING', 'RUNTIME_BOOT_IDENTITY_UNAVAILABLE',
  'RUNTIME_INPUT_INVALID', 'RUNTIME_INTERNAL_ERROR', 'RUNTIME_INVENTORY_FAILED',
  'RUNTIME_OPERATION_CONFLICT', 'RUNTIME_REBOOT_REQUIRED', 'RUNTIME_STATE_UNSUPPORTED',
]);
const STATUSES = Object.freeze({
  RECOVERY_READY: true,
  RECOVERY_PARENT_REQUIRED: false,
  RECOVERY_APPLY_REQUIRED: false,
});
const unknown = () => ({
  phase: 'recovery-inspect', outcome: 'STOP_UNKNOWN', code: 'INSPECT_INVOKED_RESULT_UNCERTAIN',
});
const blocked = () => ({
  phase: 'pre-inspection', outcome: 'BLOCKED', code: 'CAPTURE_START_FAILED',
});
const encode = (value) => `${JSON.stringify(value)}\n`;

function project(exitCode, stdout, stderr) {
  if (exitCode === 2) {
    const code = stderr.slice(0, -1);
    if (stdout !== '' || stderr !== `${code}\n` || !ERRORS.has(code)) throw new Error();
    return { phase: 'recovery-inspect', outcome: 'FINITE_STOP', code };
  }
  if (exitCode !== 0 || stderr !== '') throw new Error();
  const value = JSON.parse(stdout);
  if (!value || value.schemaVersion !== 1 || typeof value.status !== 'string'
    || !Object.hasOwn(STATUSES, value.status)
    || !['EMPTY_PRE_TRANSACTION', 'ALREADY_ABSENT'].includes(value.classification)
    || value.rebootRequired !== false || value.actionable !== STATUSES[value.status]) {
    throw new Error();
  }
  return {
    phase: 'recovery-inspect', outcome: 'FINITE_RESULT', status: value.status,
    classification: value.classification, rebootRequired: false, actionable: value.actionable,
  };
}

function canonicalProjection(value, schemaVersion = 1) {
  let expected;
  if (value?.outcome === 'STOP_UNKNOWN') expected = unknown();
  else if (value?.outcome === 'FINITE_STOP') expected = project(2, '', `${value.code}\n`);
  else if (value?.outcome === 'FINITE_RESULT') expected = project(0, JSON.stringify({
    schemaVersion: 1, status: value.status, classification: value.classification,
    rebootRequired: value.rebootRequired, actionable: value.actionable,
  }), '');
  else throw new Error();
  if (schemaVersion === 2) {
    if (!isRecoveryInspectStage(value.lastStage)) throw new Error();
    expected = { ...expected, lastStage: value.lastStage };
  }
  if (JSON.stringify(value) !== JSON.stringify(expected)) throw new Error();
  return expected;
}

async function assertDirectory(path, privateDirectory = true) {
  if (typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path) throw new Error();
  const parent = dirname(path);
  if (parent !== path) await assertDirectory(parent, false);
  const stats = await lstat(path);
  if (!stats.isDirectory() || stats.isSymbolicLink()) throw new Error();
  if (privateDirectory && (stats.uid !== process.getuid() || (stats.mode & 0o777) !== 0o700)) {
    throw new Error();
  }
}

async function syncDirectory(path) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { await file.sync(); } finally { await file.close(); }
}

async function writeExclusive(path, value) {
  const file = await open(path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    await file.writeFile(encode(value));
    await file.sync();
  } finally { await file.close(); }
}

async function readRecord(path) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stats = await file.stat();
    if (!stats.isFile() || stats.uid !== process.getuid() || (stats.mode & 0o777) !== 0o600
      || stats.nlink !== 1 || stats.size > MAX_RECORD_BYTES) throw new Error();
    const bytes = Buffer.alloc(MAX_RECORD_BYTES + 1);
    let length = 0;
    while (length < bytes.length) {
      const result = await file.read(bytes, length, bytes.length - length, null);
      if (!result.bytesRead) break;
      length += result.bytesRead;
    }
    if (length > MAX_RECORD_BYTES) throw new Error();
    const text = bytes.subarray(0, length).toString('utf8');
    const value = JSON.parse(text);
    if (encode(value) !== text) throw new Error();
    return value;
  } finally { await file.close(); }
}

// Trusted local harness API. No CLI import or production target selection.
export async function captureRecoveryInspect({ runDirectory, invoke, stdout = process.stdout, diagnostics = false }) {
  let runId;
  const schemaVersion = diagnostics === true ? 2 : 1;
  try {
    if (typeof diagnostics !== 'boolean' || typeof invoke !== 'function' || typeof runDirectory !== 'string'
      || !isAbsolute(runDirectory) || resolve(runDirectory) !== runDirectory) throw new Error();
    await assertDirectory(dirname(runDirectory));
    // A retained directory blocks every subsequent invocation, even without a marker.
    await mkdir(runDirectory, { mode: 0o700 });
    await assertDirectory(runDirectory);
    await syncDirectory(dirname(runDirectory));
    runId = randomUUID();
    await writeExclusive(join(runDirectory, 'started.json'), { schemaVersion, runId, phase: 'STARTED' });
    await syncDirectory(runDirectory);
  } catch {
    return blocked();
  }

  let rawStdout = '';
  let rawStderr = '';
  let capturedBytes = 0;
  let invalidOutput = false;
  function capture(channel, value) {
    if (typeof value !== 'string') {
      invalidOutput = true;
      throw new Error('CAPTURE_OUTPUT_INVALID');
    }
    capturedBytes += Buffer.byteLength(value);
    if (capturedBytes > MAX_OUTPUT_BYTES) {
      invalidOutput = true;
      throw new Error('CAPTURE_OUTPUT_LIMIT');
    }
    if (channel === 'stdout') rawStdout += value;
    else rawStderr += value;
    return true;
  }
  let projection;
  const invokeAndProject = async () => {
    try {
      const exitCode = await invoke({
        stdout: { write: (value) => capture('stdout', value) },
        stderr: { write: (value) => capture('stderr', value) },
      });
      if (invalidOutput) throw new Error();
      projection = project(exitCode, rawStdout, rawStderr);
    } catch {
      projection = unknown();
    } finally {
      rawStdout = '';
      rawStderr = '';
    }
  };
  if (diagnostics) {
    const stages = createRecoveryInspectStageCapture();
    await stages.run(invokeAndProject);
    projection = { ...projection, lastStage: stages.snapshot() };
  } else {
    await invokeAndProject();
  }

  try {
    await assertDirectory(runDirectory);
    await writeExclusive(join(runDirectory, 'terminal.tmp'), { schemaVersion, runId, projection });
    // No replacement: a conflicting endpoint or partial publication stops the run.
    await link(join(runDirectory, 'terminal.tmp'), join(runDirectory, 'terminal.json'));
    await unlink(join(runDirectory, 'terminal.tmp'));
    await syncDirectory(runDirectory);
  } catch {
    return unknown();
  }
  try { stdout.write(encode(projection)); } catch {
    // The durable receipt remains authoritative when the display sink is lost.
  }
  return projection;
}

export async function readRecoveryInspectCapture(runDirectory) {
  try {
    await assertDirectory(dirname(runDirectory));
    await assertDirectory(runDirectory);
    const names = (await readdir(runDirectory)).sort();
    if (JSON.stringify(names) !== JSON.stringify(['started.json', 'terminal.json'])) throw new Error();
    const started = await readRecord(join(runDirectory, 'started.json'));
    const schemaVersion = started.schemaVersion;
    if (![1, 2].includes(schemaVersion) || typeof started.runId !== 'string'
      || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u.test(started.runId)
      || encode(started) !== encode({ schemaVersion, runId: started.runId, phase: 'STARTED' })) {
      throw new Error();
    }
    const terminal = await readRecord(join(runDirectory, 'terminal.json'));
    const projection = canonicalProjection(terminal.projection, schemaVersion);
    if (encode(terminal) !== encode({ schemaVersion, runId: started.runId, projection })) throw new Error();
    return projection;
  } catch {
    return unknown();
  }
}
