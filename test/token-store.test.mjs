import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { EnrollmentTokenStore } from '../src/enrollment/token-store.mjs';

test('issues a non-persisted token which may be consumed only once', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-token-store-'));
  const path = join(directory, 'tokens.json');
  const now = new Date('2026-07-26T00:00:00.000Z');
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new EnrollmentTokenStore(path, {
    now: () => now,
    randomBytes: () => Buffer.alloc(32, 7),
  });

  const issued = await store.issue({ deviceId: 'dev_abc123', ttlMs: 10 * 60 * 1000 });

  assert.equal(issued.expiresAt, '2026-07-26T00:10:00.000Z');
  assert.doesNotMatch(await readFile(path, 'utf8'), new RegExp(issued.token, 'u'));
  assert.deepEqual(await store.consume(issued.token), {
    deviceId: 'dev_abc123',
    expiresAt: '2026-07-26T00:10:00.000Z',
  });
  await assert.rejects(store.consume(issued.token), new Error('enrollment token already consumed'));
});

test('rejects a token once its expiration time is reached', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-token-store-'));
  const path = join(directory, 'tokens.json');
  let now = new Date('2026-07-26T00:00:00.000Z');
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new EnrollmentTokenStore(path, {
    now: () => now,
    randomBytes: () => Buffer.alloc(32, 7),
  });

  const { token } = await store.issue({ deviceId: 'dev_abc123', ttlMs: 1000 });
  now = new Date('2026-07-26T00:00:02.000Z');

  await assert.rejects(store.consume(token), new Error('enrollment token expired'));
});

test('retains every concurrently issued enrollment token', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-token-store-'));
  const path = join(directory, 'tokens.json');
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new EnrollmentTokenStore(path);

  await Promise.all(Array.from({ length: 8 }, (_, index) => (
    store.issue({ deviceId: `dev_${index}`, ttlMs: 1000 })
  )));

  assert.equal(JSON.parse(await readFile(path, 'utf8')).tokens.length, 8);
});

test('allows exactly one concurrent consumption of an enrollment token', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-token-store-'));
  const path = join(directory, 'tokens.json');
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new EnrollmentTokenStore(path);
  const { token } = await store.issue({ deviceId: 'dev_abc123', ttlMs: 1000 });

  const results = await Promise.allSettled(Array.from({ length: 8 }, () => store.consume(token)));

  assert.equal(results.filter(({ status }) => status === 'fulfilled').length, 1);
  assert.deepEqual(
    results.filter(({ status }) => status === 'rejected').map(({ reason }) => reason.message),
    Array(7).fill('enrollment token already consumed'),
  );
});

test('fails closed when a stored token has a malformed expiry', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-token-store-'));
  const path = join(directory, 'tokens.json');
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new EnrollmentTokenStore(path, { randomBytes: () => Buffer.alloc(32, 7) });
  const { token } = await store.issue({ deviceId: 'dev_abc123', ttlMs: 1000 });
  const data = JSON.parse(await readFile(path, 'utf8'));
  data.tokens[0].expiresAt = 'not a timestamp';
  await writeFile(path, `${JSON.stringify(data)}\n`);

  await assert.rejects(store.consume(token), /invalid enrollment token store/);
});

test('captures the clock once while consuming a valid token', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-token-store-'));
  const path = join(directory, 'tokens.json');
  let calls = 0;
  const now = () => {
    calls += 1;
    return new Date('2026-07-26T00:00:00.000Z');
  };
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new EnrollmentTokenStore(path, { now, randomBytes: () => Buffer.alloc(32, 7) });
  const { token } = await store.issue({ deviceId: 'dev_abc123', ttlMs: 1000 });
  calls = 0;

  await store.consume(token);

  assert.equal(calls, 1);
});

test('fails closed without writing when the consume clock predates issuance', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-token-store-'));
  const path = join(directory, 'tokens.json');
  let now = new Date('2026-07-26T00:00:00.000Z');
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new EnrollmentTokenStore(path, {
    now: () => now,
    randomBytes: () => Buffer.alloc(32, 7),
  });
  const { token } = await store.issue({ deviceId: 'dev_abc123', ttlMs: 1000 });
  now = new Date('2026-07-25T23:59:59.000Z');

  await assert.rejects(store.consume(token), /invalid enrollment token store/);
  assert.equal(JSON.parse(await readFile(path, 'utf8')).tokens[0].consumedAt, null);
});

test('revokes exactly one matching token record, including a consumed token', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-token-store-'));
  const path = join(directory, 'tokens.json');
  t.after(() => rm(directory, { recursive: true, force: true }));
  let tokenByte = 7;
  const store = new EnrollmentTokenStore(path, {
    randomBytes: () => Buffer.alloc(32, tokenByte++),
  });
  const first = await store.issue({ deviceId: 'dev_abc123', ttlMs: 1000 });
  const second = await store.issue({ deviceId: 'dev_def456', ttlMs: 1000 });
  await store.consume(first.token);

  assert.equal(await store.revoke(first.token), true);
  assert.equal(await store.revoke(first.token), false);
  assert.equal(await store.revoke('missing-token'), false);
  assert.deepEqual(
    JSON.parse(await readFile(path, 'utf8')).tokens.map(({ deviceId }) => deviceId),
    ['dev_def456'],
  );
  assert.deepEqual(await store.consume(second.token), {
    deviceId: 'dev_def456',
    expiresAt: second.expiresAt,
  });
});
