import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import test from 'node:test';

import { CompletionTicketStore } from '../src/enrollment/completion-ticket-store.mjs';

test('issues a canonical 32-byte ticket while retaining only its SHA-256 hash', async () => {
  const now = new Date('2026-07-26T00:00:00.000Z');
  const store = new CompletionTicketStore({
    now: () => now,
    randomBytes: () => Buffer.alloc(32, 7),
  });

  const ticket = await store.issue('dev_abc123', 10 * 60 * 1000);

  assert.equal(ticket, Buffer.alloc(32, 7).toString('base64url'));
  assert.equal(Buffer.from(ticket, 'base64url').length, 32);
  assert.doesNotMatch(inspect(store, { showHidden: true }), new RegExp(ticket, 'u'));
  assert.deepEqual(Object.keys(store), []);
});

test('consumes a ticket once for its bound device', async () => {
  const store = new CompletionTicketStore({ randomBytes: () => Buffer.alloc(32, 3) });
  const ticket = await store.issue('dev_abc123', 600_000);

  assert.deepEqual(await store.consume(ticket, 'dev_abc123'), { deviceId: 'dev_abc123' });
  await assert.rejects(store.consume(ticket, 'dev_abc123'), /invalid completion ticket/);
});

test('wrong-device consumption fails without burning the valid ticket', async () => {
  const store = new CompletionTicketStore({ randomBytes: () => Buffer.alloc(32, 4) });
  const ticket = await store.issue('dev_abc123', 600_000);

  await assert.rejects(store.consume(ticket, 'dev_other'), /invalid completion ticket/);
  assert.deepEqual(await store.consume(ticket, 'dev_abc123'), { deviceId: 'dev_abc123' });
});

test('rejects expiry and clock rollback without consuming the ticket', async () => {
  let now = new Date('2026-07-26T00:00:00.000Z');
  let entropyByte = 5;
  const store = new CompletionTicketStore({
    now: () => now,
    randomBytes: () => Buffer.alloc(32, entropyByte++),
  });
  const expired = await store.issue('dev_expired', 1000);
  now = new Date('2026-07-26T00:00:01.000Z');
  await assert.rejects(store.consume(expired, 'dev_expired'), /invalid completion ticket/);

  now = new Date('2026-07-26T00:01:00.000Z');
  const rolledBack = await store.issue('dev_rollback', 1000);
  now = new Date('2026-07-26T00:00:59.999Z');
  await assert.rejects(store.consume(rolledBack, 'dev_rollback'), /invalid completion ticket/);
  now = new Date('2026-07-26T00:01:00.500Z');
  assert.deepEqual(await store.consume(rolledBack, 'dev_rollback'), { deviceId: 'dev_rollback' });
});

test('serializes concurrent consumption so exactly one caller succeeds', async () => {
  const store = new CompletionTicketStore({ randomBytes: () => Buffer.alloc(32, 6) });
  const ticket = await store.issue('dev_abc123', 600_000);

  const results = await Promise.allSettled(
    Array.from({ length: 12 }, () => store.consume(ticket, 'dev_abc123')),
  );

  assert.equal(results.filter(({ status }) => status === 'fulfilled').length, 1);
  assert.equal(results.filter(({ status }) => status === 'rejected').length, 11);
  assert.ok(results.filter(({ status }) => status === 'rejected').every(
    ({ reason }) => reason.message === 'invalid completion ticket',
  ));
});

test('validates issue dependencies, device IDs, lifetimes, and random output', async () => {
  assert.throws(() => new CompletionTicketStore({ now: null }), /invalid completion ticket dependency/);
  const store = new CompletionTicketStore({ randomBytes: () => Buffer.alloc(31) });
  await assert.rejects(store.issue('dev_abc123', 1000), /invalid completion ticket entropy/);

  const valid = new CompletionTicketStore();
  await assert.rejects(valid.issue('bad/device', 1000), /invalid completion ticket request/);
  await assert.rejects(valid.issue('dev_abc123', 0), /invalid completion ticket request/);
  await assert.rejects(valid.consume('not-a-ticket', 'dev_abc123'), /invalid completion ticket/);
});

test('accepts a 64-character device ID and rejects a 65-character device ID', async () => {
  const store = new CompletionTicketStore();
  const maximum = `dev_${'a'.repeat(60)}`;
  const oversized = `dev_${'a'.repeat(61)}`;

  assert.equal((await store.issue(maximum, 1000)).length, 43);
  await assert.rejects(store.issue(oversized, 1000), /invalid completion ticket request/);
});
