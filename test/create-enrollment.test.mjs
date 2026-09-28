import assert from 'node:assert/strict';
import test from 'node:test';

import { createEnrollment } from '../src/enrollment/create-enrollment.mjs';

test('creates an enrolling Windows device, issues a ten-minute token, and builds its command', async () => {
  const added = [];
  const issued = [];
  const now = new Date('2026-07-26T00:00:00.000Z');
  const result = await createEnrollment({
    controllerUrl: 'https://controller.example.test/enroll',
    displayName: 'Studio PC',
    now: () => now,
    createDeviceId: () => 'dev_abc123',
    registry: { add: async (device) => added.push(device) },
    tokenStore: {
      issue: async (input) => {
        issued.push(input);
        return { token: 'x'.repeat(32), expiresAt: '2026-07-26T00:10:00.000Z' };
      },
    },
  });

  assert.deepEqual(added, [{
    id: 'dev_abc123',
    displayName: 'Studio PC',
    controllerPlatform: 'darwin',
    targetPlatform: 'windows',
    status: 'ENROLLING',
    capabilities: [],
    createdAt: '2026-07-26T00:00:00.000Z',
    updatedAt: '2026-07-26T00:00:00.000Z',
  }]);
  assert.deepEqual(issued, [{ deviceId: 'dev_abc123', ttlMs: 600_000 }]);
  assert.equal(result.deviceId, 'dev_abc123');
  assert.equal(result.expiresAt, '2026-07-26T00:10:00.000Z');
  assert.match(result.command, /^powershell\.exe /);
});

test('uses an injected five-to-thirty-minute token lifetime', async () => {
  for (const tokenTtlMs of [300_000, 600_000, 1_800_000]) {
    let issued;
    await createEnrollment({
      controllerUrl: 'https://controller.example.test/enroll',
      displayName: 'Studio PC',
      createDeviceId: () => 'dev_abc123',
      tokenTtlMs,
      registry: { add: async () => {} },
      tokenStore: {
        issue: async (input) => { issued = input; return { token: 'x'.repeat(32), expiresAt: '2026-07-26T00:10:00.000Z' }; },
      },
    });
    assert.deepEqual(issued, { deviceId: 'dev_abc123', ttlMs: tokenTtlMs });
  }
});

test('rejects invalid token lifetimes before persistence', async () => {
  for (const tokenTtlMs of [299_999, 1_800_001, 600_000.5, '600000']) {
    let issued = 0;
    let added = 0;
    await assert.rejects(createEnrollment({
      controllerUrl: 'https://controller.example.test/enroll',
      displayName: 'Studio PC',
      createDeviceId: () => 'dev_abc123',
      tokenTtlMs,
      registry: { add: async () => { added += 1; } },
      tokenStore: { issue: async () => { issued += 1; } },
    }), /tokenTtlMs must be an integer from 300000 to 1800000/);
    assert.equal(issued, 0);
    assert.equal(added, 0);
  }
});

test('preflights and builds with an injected command builder and payload extras', async () => {
  const calls = [];
  const buildCommand = (payload) => {
    calls.push(payload);
    return payload.token === 'x'.repeat(32) ? 'real-command' : 'preflight-command';
  };
  const result = await createEnrollment({
    displayName: 'Studio PC',
    createDeviceId: () => 'dev_abc123',
    registry: { add: async () => {} },
    tokenStore: {
      issue: async () => ({ token: 'x'.repeat(32), expiresAt: '2026-07-26T00:10:00.000Z' }),
      revoke: async () => true,
    },
    buildCommand,
    commandPayload: Object.freeze({
      controllerBaseUrl: 'https://mac.tail123.ts.net/agent-road/v1/dev_abc123',
      releaseManifest: Object.freeze({ schemaVersion: 1 }),
    }),
  });

  assert.equal(calls.length, 2);
  assert.equal(calls[0].deviceId, 'dev_abc123');
  assert.equal(calls[0].token, 'A'.repeat(43));
  assert.equal(calls[1].token, 'x'.repeat(32));
  assert.equal(result.command, 'real-command');
  assert.equal(typeof result.revoke, 'function');
  assert.equal(await result.revoke(), true);
});

test('rejects accessor payloads and multiline commands before persistence', async () => {
  for (const options of [
    {
      commandPayload: Object.defineProperty({}, 'controllerBaseUrl', {
        enumerable: true,
        get() { throw new Error('secret getter'); },
      }),
      buildCommand: () => 'one-line',
    },
    { commandPayload: {}, buildCommand: () => 'first\nsecond' },
  ]) {
    let issued = 0;
    let added = 0;
    await assert.rejects(createEnrollment({
      displayName: 'Studio PC',
      createDeviceId: () => 'dev_abc123',
      registry: { add: async () => { added += 1; } },
      tokenStore: { issue: async () => { issued += 1; } },
      ...options,
    }));
    assert.equal(issued, 0);
    assert.equal(added, 0);
  }
});

test('preflights invalid controller URL, device id, and name before writing either store', async () => {
  for (const overrides of [
    { controllerUrl: 'http://controller.example.test/enroll' },
    { createDeviceId: () => 'invalid' },
    { displayName: '   ' },
  ]) {
    let added = 0;
    let issued = 0;
    await assert.rejects(createEnrollment({
      controllerUrl: 'https://controller.example.test/enroll',
      displayName: 'Studio PC',
      createDeviceId: () => 'dev_abc123',
      registry: { add: async () => { added += 1; } },
      tokenStore: { issue: async () => { issued += 1; } },
      ...overrides,
    }));
    assert.equal(added, 0);
    assert.equal(issued, 0);
  }
});

test('does not add a device when issuing its token fails', async () => {
  let added = 0;
  const issueError = new Error('token issue failed');

  await assert.rejects(createEnrollment({
    controllerUrl: 'https://controller.example.test/enroll',
    displayName: 'Studio PC',
    createDeviceId: () => 'dev_abc123',
    registry: { add: async () => { added += 1; } },
    tokenStore: { issue: async () => { throw issueError; } },
  }), issueError);

  assert.equal(added, 0);
});

test('keeps the token and succeeds when add throws after persisting the intended device', async () => {
  const timestamp = '2026-07-26T00:00:00.000Z';
  const device = {
    id: 'dev_abc123',
    displayName: 'Studio PC',
    controllerPlatform: 'darwin',
    targetPlatform: 'windows',
    status: 'ENROLLING',
    capabilities: [],
    createdAt: timestamp,
    updatedAt: timestamp,
  };
  const revoked = [];
  const result = await createEnrollment({
    controllerUrl: 'https://controller.example.test/enroll',
    displayName: 'Studio PC',
    now: () => new Date(timestamp),
    createDeviceId: () => 'dev_abc123',
    registry: {
      add: async () => { throw new Error('directory sync failed'); },
      get: async () => device,
    },
    tokenStore: {
      issue: async () => ({ token: 'x'.repeat(32), expiresAt: '2026-07-26T00:10:00.000Z' }),
      revoke: async (token) => { revoked.push(token); return true; },
    },
  });

  assert.equal(result.deviceId, 'dev_abc123');
  assert.deepEqual(revoked, []);
});

test('revokes an issued token when adding the device fails before persistence', async () => {
  const addError = new Error('registry add failed');
  const revoked = [];

  await assert.rejects(createEnrollment({
    controllerUrl: 'https://controller.example.test/enroll',
    displayName: 'Studio PC',
    createDeviceId: () => 'dev_abc123',
    registry: {
      add: async () => { throw addError; },
      get: async () => null,
    },
    tokenStore: {
      issue: async () => ({ token: 'x'.repeat(32), expiresAt: '2026-07-26T00:10:00.000Z' }),
      revoke: async (token) => { revoked.push(token); return true; },
    },
  }), addError);

  assert.deepEqual(revoked, ['x'.repeat(32)]);
});

test('revokes an issued token when reconciliation finds a conflicting device', async () => {
  const addError = new Error('registry add failed');
  const revoked = [];

  await assert.rejects(createEnrollment({
    controllerUrl: 'https://controller.example.test/enroll',
    displayName: 'Studio PC',
    createDeviceId: () => 'dev_abc123',
    registry: {
      add: async () => { throw addError; },
      get: async () => ({
        id: 'dev_abc123',
        displayName: 'Other PC',
        controllerPlatform: 'darwin',
        targetPlatform: 'windows',
        status: 'ENROLLING',
        capabilities: [],
        createdAt: '2026-07-26T00:00:00.000Z',
        updatedAt: '2026-07-26T00:00:00.000Z',
      }),
    },
    tokenStore: {
      issue: async () => ({ token: 'x'.repeat(32), expiresAt: '2026-07-26T00:10:00.000Z' }),
      revoke: async (token) => { revoked.push(token); return true; },
    },
  }), addError);

  assert.deepEqual(revoked, ['x'.repeat(32)]);
});

test('preserves the token when reconciliation cannot determine the add outcome', async () => {
  const addError = new Error('registry add failed');
  const readError = new Error('registry read failed');
  const revoked = [];

  await assert.rejects(createEnrollment({
    controllerUrl: 'https://controller.example.test/enroll',
    displayName: 'Studio PC',
    createDeviceId: () => 'dev_abc123',
    registry: {
      add: async () => { throw addError; },
      get: async () => { throw readError; },
    },
    tokenStore: {
      issue: async () => ({ token: 'x'.repeat(32), expiresAt: '2026-07-26T00:10:00.000Z' }),
      revoke: async (token) => { revoked.push(token); return true; },
    },
  }), (error) => (
    error instanceof AggregateError
    && /ambiguous enrollment persistence/.test(error.message)
    && error.errors[0] === addError
    && error.errors[1] === readError
  ));

  assert.deepEqual(revoked, []);
});

test('surfaces both registry and revoke failures', async () => {
  const addError = new Error('registry add failed');
  const revokeError = new Error('token revoke failed');

  await assert.rejects(createEnrollment({
    controllerUrl: 'https://controller.example.test/enroll',
    displayName: 'Studio PC',
    createDeviceId: () => 'dev_abc123',
    registry: {
      add: async () => { throw addError; },
      get: async () => null,
    },
    tokenStore: {
      issue: async () => ({ token: 'x'.repeat(32), expiresAt: '2026-07-26T00:10:00.000Z' }),
      revoke: async () => { throw revokeError; },
    },
  }), (error) => (
    error instanceof AggregateError
    && error.errors[0] === addError
    && error.errors[1] === revokeError
  ));
});
