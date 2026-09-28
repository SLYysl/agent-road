import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { runtimeDeviceRecoveryPaths, statePaths } from '../src/core/paths.mjs';
import { observeLocalRecoveryEvidence } from '../src/runtime/local-recovery-evidence.mjs';

async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'local-evidence-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const env = { AGENT_ROAD_HOME: root };
  const paths = statePaths(env);
  const recovery = runtimeDeviceRecoveryPaths(paths.runtimeDevices, 'dev_fixture', 'a'.repeat(32));
  await mkdir(recovery.operation, { recursive: true });
  await writeFile(paths.devices, JSON.stringify({ devices: [
    { id: 'dev_fixture', status: 'CONNECTED_SSH_ONLY', secret: 'PRIVATE_SENTINEL' },
  ] }));
  const statePath = join(recovery.device, 'state.json');
  await writeFile(statePath, JSON.stringify({
    schemaVersion: 1, deviceId: 'dev_fixture', runtimeStatus: 'FAILED',
    requestedProfiles: ['core'], readyProfiles: [], operationId: 'a'.repeat(32),
    manifestDigest: 'D'.repeat(64), generationDigest: 'E'.repeat(64),
    failureCode: 'RUNTIME_COMPLETION_UNCERTAIN', updatedAt: '2026-07-30T10:00:00.000Z',
  }));
  return { root, env, paths, recovery, statePath };
}

test('local observation preserves bytes and paths, redacts identifiers, and never authorizes retry', async (t) => {
  const f = await fixture(t);
  await writeFile(`${f.recovery.recoveryCommit}.lock`, 'private lock content');
  const beforePaths = await readdir(f.root, { recursive: true });
  const beforeState = await readFile(f.statePath);
  const report = await observeLocalRecoveryEvidence(f.env);
  assert.equal(report.outcome, 'LOCAL_OBSERVATION_ONLY');
  assert.equal(report.persistentLockFilePresent, true);
  assert.equal(report.bootObservationFilePresent, false);
  assert.equal(report.ticketEntries, 0);
  assert.equal(report.retryAuthorized, false);
  assert.equal(report.remoteOutcome, 'UNKNOWN');
  assert.doesNotMatch(JSON.stringify(report), /PRIVATE_SENTINEL|dev_fixture|aaaa|DDDD|EEEE|private lock/);
  assert.deepEqual(await readdir(f.root, { recursive: true }), beforePaths);
  assert.deepEqual(await readFile(f.statePath), beforeState);
});

test('counts evidence files without treating their contents as valid recovery proof', async (t) => {
  const f = await fixture(t);
  await mkdir(f.recovery.tickets);
  await writeFile(join(f.recovery.tickets, 'not-a-valid-ticket'), 'PRIVATE_SENTINEL');
  const report = await observeLocalRecoveryEvidence(f.env);
  assert.equal(report.ticketEntries, 1);
  assert.equal(report.retryAuthorized, false);
});

for (const mode of ['missing', 'malformed', 'oversized', 'symlink', 'parent-symlink', 'multiple', 'wrong-device']) {
  test(`fails closed without raw diagnostics: ${mode}`, async (t) => {
    const f = await fixture(t);
    if (mode === 'missing') await rm(f.statePath);
    if (mode === 'malformed') await writeFile(f.statePath, 'PRIVATE_SENTINEL');
    if (mode === 'oversized') await writeFile(f.statePath, ' '.repeat(4_097));
    if (mode === 'symlink') {
      await rm(f.statePath);
      await symlink(f.paths.devices, f.statePath);
    }
    if (mode === 'parent-symlink') {
      const link = join(f.root, 'linked-root');
      await symlink(f.root, link);
      f.env.AGENT_ROAD_HOME = link;
    }
    if (mode === 'multiple') await writeFile(f.paths.devices, JSON.stringify({ devices: [
      { id: 'dev_fixture', status: 'READY' }, { id: 'dev_other', status: 'READY' },
    ] }));
    if (mode === 'wrong-device') {
      const state = JSON.parse(await readFile(f.statePath, 'utf8'));
      state.deviceId = 'dev_other';
      await writeFile(f.statePath, JSON.stringify(state));
    }
    assert.deepEqual(await observeLocalRecoveryEvidence(f.env), {
      schemaVersion: 1, outcome: 'LOCAL_EVIDENCE_UNAVAILABLE', retryAuthorized: false,
    });
  });
}
