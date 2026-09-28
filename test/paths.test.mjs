import assert from 'node:assert/strict';
import test from 'node:test';

import {
  runtimeDeviceRecoveryPaths,
  runtimeRecoveryAuthorizationSuccessorPath,
  runtimeDeviceStatePath,
  statePaths,
} from '../src/core/paths.mjs';

test('derives a runtime state file below the independent per-device root', () => {
  const paths = statePaths({ AGENT_ROAD_HOME: '/tmp/agent-road-state' });

  assert.equal(
    runtimeDeviceStatePath(paths.runtimeDevices, 'dev_abc123'),
    '/tmp/agent-road-state/runtime/devices/dev_abc123/state.json',
  );
});

test('derives one lowercase authorization-successor path from an uppercase parent digest', () => {
  const root = '/tmp/agent-road-state/runtime/devices';
  const digest = 'AB'.repeat(32);
  const recovery = runtimeDeviceRecoveryPaths(root, 'dev_abc123', 'a'.repeat(32));

  assert.equal(
    recovery.tickets,
    `/tmp/agent-road-state/runtime/devices/dev_abc123/recovery/operations/${'a'.repeat(32)}/tickets-v2`,
  );
  assert.equal(
    recovery.authorizedDeleteAttempts,
    `/tmp/agent-road-state/runtime/devices/dev_abc123/recovery/operations/${'a'.repeat(32)}/authorized-delete-attempts-v2`,
  );
  assert.equal(
    recovery.legacyTickets,
    `/tmp/agent-road-state/runtime/devices/dev_abc123/recovery/operations/${'a'.repeat(32)}/tickets`,
  );
  assert.equal(
    recovery.legacyAuthorizedDeleteAttempts,
    `/tmp/agent-road-state/runtime/devices/dev_abc123/recovery/operations/${'a'.repeat(32)}/authorized-delete-attempts`,
  );
  assert.equal(
    recovery.authorizationSuccessors,
    `/tmp/agent-road-state/runtime/devices/dev_abc123/recovery/operations/${'a'.repeat(32)}/authorization-successors`,
  );
  assert.equal(
    runtimeRecoveryAuthorizationSuccessorPath(
      root,
      'dev_abc123',
      'a'.repeat(32),
      digest,
    ),
    `${recovery.authorizationSuccessors}/${digest.toLowerCase()}.json`,
  );
  for (const invalid of [digest.toLowerCase(), 'A'.repeat(63), `${'A'.repeat(64)}A`]) {
    assert.throws(
      () => runtimeRecoveryAuthorizationSuccessorPath(
        root,
        'dev_abc123',
        'a'.repeat(32),
        invalid,
      ),
      (error) => error?.code === 'RUNTIME_INPUT_INVALID'
        && error.message === 'RUNTIME_INPUT_INVALID',
    );
  }
});

test('rejects noncanonical runtime roots and device ids without echoing them', () => {
  for (const [root, deviceId] of [
    ['relative/runtime/devices', 'dev_abc123'],
    ['/tmp/runtime/../devices', 'dev_abc123'],
    ['/tmp/runtime/devices/', 'dev_abc123'],
    ['/tmp/runtime/devices', '../escape'],
    ['/tmp/runtime/devices', 'DEV_ABC123'],
    ['/tmp/runtime/devices', `dev_${'a'.repeat(65)}`],
  ]) {
    assert.throws(
      () => runtimeDeviceStatePath(root, deviceId),
      (error) => {
        assert.equal(error?.code, 'RUNTIME_INPUT_INVALID');
        assert.equal(error.message, 'RUNTIME_INPUT_INVALID');
        assert.doesNotMatch(error.message, /escape|relative|DEV_/u);
        return true;
      },
    );
  }
});
