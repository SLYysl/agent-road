import { constants } from 'node:fs';
import { lstat, open, readdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';

import { runtimeDeviceRecoveryPaths, statePaths } from '../core/paths.mjs';
import { validateRuntimeStateRecord } from './runtime-state-store.mjs';

// Observation only: never acquire a store lock, import the CLI, or contact a target.
async function inspectPath(path) {
  const parent = dirname(path);
  if (parent !== path) {
    const parentStats = await inspectPath(parent);
    if (parentStats === null) return null;
    if (!parentStats.isDirectory()) throw new Error();
  }
  try {
    const stats = await lstat(path);
    if (stats.isSymbolicLink()) throw new Error();
    return stats;
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

async function readJson(path, limit) {
  const stats = await inspectPath(path);
  if (!stats?.isFile() || stats.size > limit) throw new Error();
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (before.dev !== stats.dev || before.ino !== stats.ino) throw new Error();
    const buffer = Buffer.alloc(limit + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    const after = await handle.stat();
    if (length > limit || before.size !== after.size || before.mtimeMs !== after.mtimeMs) {
      throw new Error();
    }
    return JSON.parse(buffer.subarray(0, length).toString('utf8'));
  } finally {
    await handle.close();
  }
}

async function present(path, kind) {
  const stats = await inspectPath(path);
  if (stats === null) return false;
  if (!(kind === 'directory' ? stats.isDirectory() : stats.isFile())) throw new Error();
  return true;
}

async function countEntries(path) {
  if (!await present(path, 'directory')) return 0;
  const entries = await readdir(path, { withFileTypes: true });
  if (entries.some((entry) => !entry.isFile())) throw new Error();
  return entries.length;
}

export async function observeLocalRecoveryEvidence(env = process.env) {
  try {
    const paths = statePaths(env);
    const registry = await readJson(paths.devices, 1_048_576);
    const candidates = registry.devices.filter((device) => [
      'CONNECTED_SSH_ONLY', 'READY', 'DEGRADED_RECOVERY_AVAILABLE',
    ].includes(device.status));
    if (candidates.length !== 1) throw new Error();
    const deviceId = candidates[0].id;
    // Validate the ID before constructing any device path.
    const probe = runtimeDeviceRecoveryPaths(paths.runtimeDevices, deviceId, '0'.repeat(32));
    const statePath = join(probe.device, 'state.json');
    const state = validateRuntimeStateRecord(await readJson(statePath, 4_096));
    if (state.deviceId !== deviceId || state.runtimeStatus !== 'FAILED'
      || state.failureCode !== 'RUNTIME_COMPLETION_UNCERTAIN') throw new Error();
    const recovery = runtimeDeviceRecoveryPaths(paths.runtimeDevices, deviceId, state.operationId);
    const evidence = {
      operationDirectoryPresent: await present(recovery.operation, 'directory'),
      persistentLockFilePresent: await present(`${recovery.recoveryCommit}.lock`, 'file'),
      bootObservationFilePresent: await present(recovery.bootObservation, 'file'),
      recoveryCommitFilePresent: await present(recovery.recoveryCommit, 'file'),
      ticketEntries: await countEntries(recovery.tickets),
      legacyTicketEntries: await countEntries(recovery.legacyTickets),
      successorEntries: await countEntries(recovery.authorizationSuccessors),
      attemptEntries: await countEntries(recovery.authorizedDeleteAttempts),
      legacyAttemptEntries: await countEntries(recovery.legacyAuthorizedDeleteAttempts),
    };
    if (JSON.stringify(state) !== JSON.stringify(
      validateRuntimeStateRecord(await readJson(statePath, 4_096)),
    )) throw new Error();
    return {
      schemaVersion: 1,
      outcome: 'LOCAL_OBSERVATION_ONLY',
      runtimeStatus: 'FAILED',
      failureCode: 'RUNTIME_COMPLETION_UNCERTAIN',
      ...evidence,
      remoteOutcome: 'UNKNOWN',
      retryAuthorized: false,
    };
  } catch {
    return { schemaVersion: 1, outcome: 'LOCAL_EVIDENCE_UNAVAILABLE', retryAuthorized: false };
  }
}
