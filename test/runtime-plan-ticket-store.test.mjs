import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import {
  chmod,
  link,
  lstat,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

const storeModule = await import('../src/runtime/runtime-plan-ticket-store.mjs').catch(() => null);

const DEVICE_ID = 'dev_abc123';
const PLAN_TICKET_ID = `rpt_${'07'.repeat(32)}`;
const AUTHORIZATION_DIGEST = 'A'.repeat(64);
const CREATED_AT = '2026-07-30T00:00:00.000Z';
const EXPIRES_AT = '2026-07-30T00:10:00.000Z';
const execFile = promisify(execFileCallback);

async function sandbox(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-runtime-plan-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function ticketInput() {
  return {
    deviceId: DEVICE_ID,
    operationId: 'b'.repeat(32),
    createdAt: CREATED_AT,
    state: { exact: 'state-snapshot' },
    catalog: { exact: 'catalog-snapshot' },
    inventory: { exact: 'second-inventory', freeBytes: 50_000_000_000 },
    plan: { exact: 'full-plan', operationId: 'b'.repeat(32), createdAt: CREATED_AT },
    controller: {
      controllerKeyId: 'C'.repeat(64),
      controllerPublicKey: { algorithm: 'RSA-SHA256', snapshot: 'public-key' },
      firstTrustPinningRequired: true,
    },
    mutators: {
      inventoryScriptSha256: 'C'.repeat(64),
      inventorySha256: 'D'.repeat(64),
      provisionSha256: 'E'.repeat(64),
      recoverySha256: 'F'.repeat(64),
    },
    baseline: {
      baselineId: `rbl_${'1'.repeat(64)}`,
      schemaVersion: 1,
      protocolRevision: 1,
      captureAggregateMac: '2'.repeat(64),
      recordDigest: '3'.repeat(64),
      capturedAt: '2026-07-29T00:00:00.000Z',
      expiresAt: '2026-07-31T00:00:00.000Z',
    },
    authorization: { exact: 'full-stable-authorization-projection' },
    authorizationDigest: AUTHORIZATION_DIGEST,
  };
}

async function rejectsCode(pending, code) {
  await assert.rejects(pending, (error) => {
    assert.equal(error?.code, code);
    assert.equal(error?.message, code);
    return true;
  });
}

test('publishes an owner-only exact ticket with retained witness and consumes it once', async (t) => {
  assert.ok(storeModule, 'runtime plan ticket store module must exist');
  const root = await sandbox(t);
  let now = CREATED_AT;
  const randomCalls = [];
  const store = new storeModule.RuntimePlanTicketStore(root, {
    now: () => new Date(now),
    randomBytes: (size) => {
      randomCalls.push(size);
      return Buffer.alloc(size, 7);
    },
  });

  const ticket = await store.createTicket(ticketInput());
  assert.deepEqual(randomCalls, [32]);
  assert.equal(ticket.planTicketId, PLAN_TICKET_ID);
  assert.equal(ticket.createdAt, CREATED_AT);
  assert.equal(ticket.expiresAt, EXPIRES_AT);
  assert.equal(ticket.authorizationDigest, AUTHORIZATION_DIGEST);
  assert.match(ticket.recordDigest, /^[A-F0-9]{64}$/u);
  assert.equal(Object.isFrozen(ticket), true);

  const authorizationRoot = join(root, DEVICE_ID, 'runtime-plan-authorizations');
  const tickets = join(authorizationRoot, 'tickets-v1');
  const consumed = join(authorizationRoot, 'consumed-v1');
  assert.deepEqual((await readdir(authorizationRoot)).sort(), [
    '.store.lock',
    'consumed-v1',
    'tickets-v1',
  ]);
  assert.equal((await lstat(join(authorizationRoot, '.store.lock'))).mode & 0o777, 0o600);
  assert.deepEqual(await readdir(consumed), []);
  const ticketNames = await readdir(tickets);
  assert.equal(ticketNames.length, 2);
  assert.equal(ticketNames.includes(`${PLAN_TICKET_ID}.json`), true);
  assert.equal(ticketNames.some((name) => (
    name.startsWith(`${PLAN_TICKET_ID}.json.publish-`) && name.endsWith('.tmp')
  )), true);
  for (const name of ticketNames) {
    const stats = await lstat(join(tickets, name));
    assert.equal(stats.mode & 0o777, 0o600);
    assert.equal(stats.nlink, 2);
  }
  const rawTicket = await readFile(join(tickets, `${PLAN_TICKET_ID}.json`), 'utf8');
  assert.equal(rawTicket, `${JSON.stringify(ticket, null, 2)}\n`);
  assert.doesNotMatch(rawTicket, /hmac|surfaces/iu);

  assert.deepEqual(await store.readTicket({
    deviceId: DEVICE_ID,
    planTicketId: PLAN_TICKET_ID,
  }), ticket);

  now = '2026-07-30T00:01:00.000Z';
  const consumedRecord = await store.consumeTicket({
    deviceId: DEVICE_ID,
    planTicketId: PLAN_TICKET_ID,
    ticketRecordDigest: ticket.recordDigest,
    authorizationDigest: AUTHORIZATION_DIGEST,
  });
  assert.equal(consumedRecord.planTicketId, PLAN_TICKET_ID);
  assert.equal(consumedRecord.ticketRecordDigest, ticket.recordDigest);
  assert.equal(consumedRecord.authorizationDigest, AUTHORIZATION_DIGEST);
  assert.equal(consumedRecord.consumedAt, now);
  assert.match(consumedRecord.recordDigest, /^[A-F0-9]{64}$/u);
  assert.equal((await readdir(tickets)).length, 2, 'ticket and witness are retained');
  assert.equal((await readdir(consumed)).length, 2, 'consumed record retains its witness');

  await rejectsCode(store.readTicket({
    deviceId: DEVICE_ID,
    planTicketId: PLAN_TICKET_ID,
  }), 'RUNTIME_INPUT_INVALID');
  await rejectsCode(store.consumeTicket({
    deviceId: DEVICE_ID,
    planTicketId: PLAN_TICKET_ID,
    ticketRecordDigest: ticket.recordDigest,
    authorizationDigest: AUTHORIZATION_DIGEST,
  }), 'RUNTIME_INPUT_INVALID');
});

test('maps exact missing and expired tickets to input failure without selecting another record', async (t) => {
  assert.ok(storeModule, 'runtime plan ticket store module must exist');
  const root = await sandbox(t);
  let now = CREATED_AT;
  const store = new storeModule.RuntimePlanTicketStore(root, {
    now: () => new Date(now),
    randomBytes: () => Buffer.alloc(32, 7),
  });
  const ticket = await store.createTicket(ticketInput());

  await rejectsCode(store.readTicket({
    deviceId: DEVICE_ID,
    planTicketId: `rpt_${'8'.repeat(64)}`,
  }), 'RUNTIME_INPUT_INVALID');
  now = EXPIRES_AT;
  await rejectsCode(store.readTicket({
    deviceId: DEVICE_ID,
    planTicketId: ticket.planTicketId,
  }), 'RUNTIME_INPUT_INVALID');
  await rejectsCode(store.consumeTicket({
    deviceId: DEVICE_ID,
    planTicketId: ticket.planTicketId,
    ticketRecordDigest: ticket.recordDigest,
    authorizationDigest: AUTHORIZATION_DIGEST,
  }), 'RUNTIME_INPUT_INVALID');
});

test('maps a wholly absent authorization store to input failure without creating it', async (t) => {
  assert.ok(storeModule, 'runtime plan ticket store module must exist');
  const root = await sandbox(t);
  const store = new storeModule.RuntimePlanTicketStore(root, {
    now: () => new Date(CREATED_AT),
    randomBytes: () => Buffer.alloc(32, 7),
  });

  await rejectsCode(store.readTicket({
    deviceId: DEVICE_ID,
    planTicketId: PLAN_TICKET_ID,
  }), 'RUNTIME_INPUT_INVALID');
  await rejectsCode(store.consumeTicket({
    deviceId: DEVICE_ID,
    planTicketId: PLAN_TICKET_ID,
    ticketRecordDigest: '9'.repeat(64),
    authorizationDigest: AUTHORIZATION_DIGEST,
  }), 'RUNTIME_INPUT_INVALID');
  assert.deepEqual(await readdir(root), []);
});

test('maps a wholly absent runtime devices root to input failure without creating it', async (t) => {
  assert.ok(storeModule, 'runtime plan ticket store module must exist');
  const parent = await sandbox(t);
  const root = join(parent, 'runtime-devices');
  const store = new storeModule.RuntimePlanTicketStore(root, {
    now: () => new Date(CREATED_AT),
    randomBytes: () => Buffer.alloc(32, 7),
  });

  await rejectsCode(store.readTicket({
    deviceId: DEVICE_ID,
    planTicketId: PLAN_TICKET_ID,
  }), 'RUNTIME_INPUT_INVALID');
  await rejectsCode(store.consumeTicket({
    deviceId: DEVICE_ID,
    planTicketId: PLAN_TICKET_ID,
    ticketRecordDigest: '9'.repeat(64),
    authorizationDigest: AUTHORIZATION_DIGEST,
  }), 'RUNTIME_INPUT_INVALID');
  assert.deepEqual(await readdir(parent), []);
});

test('refuses to publish a ticket whose ten-minute lifetime is already exhausted', async (t) => {
  const root = await sandbox(t);
  const store = new storeModule.RuntimePlanTicketStore(root, {
    now: () => new Date(EXPIRES_AT),
    randomBytes: () => Buffer.alloc(32, 7),
  });
  await rejectsCode(store.createTicket(ticketInput()), 'RUNTIME_INPUT_INVALID');
  assert.deepEqual(await readdir(root), []);
});

test('rejects a decorated random buffer without invoking instance hooks', async (t) => {
  const root = await sandbox(t);
  let getterReads = 0;
  const bytes = Buffer.alloc(32, 7);
  Object.defineProperty(bytes, 'toString', {
    get() {
      getterReads += 1;
      throw new Error('hostile toString accessor');
    },
  });
  const store = new storeModule.RuntimePlanTicketStore(root, {
    now: () => new Date(CREATED_AT),
    randomBytes: () => bytes,
  });
  await rejectsCode(store.createTicket(ticketInput()), 'RUNTIME_INTERNAL_ERROR');
  assert.equal(getterReads, 0);
  assert.deepEqual(await readdir(root), []);
});

test('fails closed for unsafe directory topology and missing or substituted witnesses', async (t) => {
  assert.ok(storeModule, 'runtime plan ticket store module must exist');

  await t.test('partial namespace', async (t) => {
    const root = await sandbox(t);
    const store = new storeModule.RuntimePlanTicketStore(root, {
      now: () => new Date(CREATED_AT),
      randomBytes: () => Buffer.alloc(32, 7),
    });
    await mkdir(join(root, DEVICE_ID, 'runtime-plan-authorizations'), {
      recursive: true,
      mode: 0o700,
    });
    await rejectsCode(store.readTicket({
      deviceId: DEVICE_ID,
      planTicketId: PLAN_TICKET_ID,
    }), 'RUNTIME_STATE_UNSUPPORTED');
  });

  await t.test('unsafe mode', async (t) => {
    const root = await sandbox(t);
    const store = new storeModule.RuntimePlanTicketStore(root, {
      now: () => new Date(CREATED_AT),
      randomBytes: () => Buffer.alloc(32, 7),
    });
    const ticket = await store.createTicket(ticketInput());
    const authorizationRoot = join(root, DEVICE_ID, 'runtime-plan-authorizations');
    await chmod(authorizationRoot, 0o777);
    await rejectsCode(store.readTicket({
      deviceId: DEVICE_ID,
      planTicketId: ticket.planTicketId,
    }), 'RUNTIME_STATE_UNSUPPORTED');
  });

  await t.test('symlinked namespace', async (t) => {
    const root = await sandbox(t);
    const store = new storeModule.RuntimePlanTicketStore(root, {
      now: () => new Date(CREATED_AT),
      randomBytes: () => Buffer.alloc(32, 7),
    });
    const ticket = await store.createTicket(ticketInput());
    const authorizationRoot = join(root, DEVICE_ID, 'runtime-plan-authorizations');
    const consumed = join(authorizationRoot, 'consumed-v1');
    await rm(consumed, { recursive: true });
    await symlink(join(authorizationRoot, 'tickets-v1'), consumed);
    await rejectsCode(store.readTicket({
      deviceId: DEVICE_ID,
      planTicketId: ticket.planTicketId,
    }), 'RUNTIME_STATE_UNSUPPORTED');
  });

  for (const substituted of [false, true]) {
    await t.test(substituted ? 'substituted witness' : 'missing witness', async (t) => {
      const root = await sandbox(t);
      const store = new storeModule.RuntimePlanTicketStore(root, {
        now: () => new Date(CREATED_AT),
        randomBytes: () => Buffer.alloc(32, 7),
      });
      const ticket = await store.createTicket(ticketInput());
      const tickets = join(root, DEVICE_ID, 'runtime-plan-authorizations', 'tickets-v1');
      const witnessName = (await readdir(tickets)).find((name) => name.endsWith('.tmp'));
      const witness = join(tickets, witnessName);
      await unlink(witness);
      if (substituted) {
        const decoy = join(root, 'decoy');
        await writeFile(decoy, 'x', { mode: 0o600 });
        await link(decoy, witness);
      }
      await rejectsCode(store.readTicket({
        deviceId: DEVICE_ID,
        planTicketId: ticket.planTicketId,
      }), 'RUNTIME_STATE_UNSUPPORTED');
    });
  }
});

test('rejects Darwin extended ACLs on the owner-only ticket namespace', async (t) => {
  if (process.platform !== 'darwin') {
    t.skip('Darwin ACL semantics are unavailable');
    return;
  }
  const root = await sandbox(t);
  const store = new storeModule.RuntimePlanTicketStore(root, {
    now: () => new Date(CREATED_AT),
    randomBytes: () => Buffer.alloc(32, 7),
  });
  const ticket = await store.createTicket(ticketInput());
  const directory = dirname(join(
    root,
    DEVICE_ID,
    'runtime-plan-authorizations',
    'tickets-v1',
    `${ticket.planTicketId}.json`,
  ));
  await execFile('/bin/chmod', ['+a', 'everyone allow read', directory]);
  t.after(async () => {
    try { await execFile('/bin/chmod', ['-N', directory]); } catch {}
  });
  await rejectsCode(store.readTicket({
    deviceId: DEVICE_ID,
    planTicketId: ticket.planTicketId,
  }), 'RUNTIME_STATE_UNSUPPORTED');
});

test('rejects a Darwin extended ACL on the permanent store lock', async (t) => {
  if (process.platform !== 'darwin') {
    t.skip('Darwin ACL semantics are unavailable');
    return;
  }
  const root = await sandbox(t);
  const store = new storeModule.RuntimePlanTicketStore(root, {
    now: () => new Date(CREATED_AT),
    randomBytes: () => Buffer.alloc(32, 7),
  });
  const ticket = await store.createTicket(ticketInput());
  const lock = join(root, DEVICE_ID, 'runtime-plan-authorizations', '.store.lock');
  await execFile('/bin/chmod', ['+a', 'everyone allow write', lock]);
  t.after(async () => {
    try { await execFile('/bin/chmod', ['-N', lock]); } catch {}
  });

  await rejectsCode(store.readTicket({
    deviceId: DEVICE_ID,
    planTicketId: ticket.planTicketId,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.match((await execFile('/bin/ls', ['-lde', '--', lock])).stdout, /^\s+[0-9]+:\s/mu);
});

test('rejects wrong digests and backward clocks and linearizes concurrent consume', async (t) => {
  assert.ok(storeModule, 'runtime plan ticket store module must exist');
  const root = await sandbox(t);
  let now = CREATED_AT;
  const store = new storeModule.RuntimePlanTicketStore(root, {
    now: () => new Date(now),
    randomBytes: () => Buffer.alloc(32, 7),
  });
  const ticket = await store.createTicket(ticketInput());

  await rejectsCode(store.consumeTicket({
    deviceId: DEVICE_ID,
    planTicketId: ticket.planTicketId,
    ticketRecordDigest: '9'.repeat(64),
    authorizationDigest: ticket.authorizationDigest,
  }), 'RUNTIME_INPUT_INVALID');
  await rejectsCode(store.consumeTicket({
    deviceId: DEVICE_ID,
    planTicketId: ticket.planTicketId,
    ticketRecordDigest: ticket.recordDigest,
    authorizationDigest: '9'.repeat(64),
  }), 'RUNTIME_INPUT_INVALID');

  now = '2026-07-29T23:59:59.999Z';
  await rejectsCode(store.createTicket(ticketInput()), 'RUNTIME_STATE_UNSUPPORTED');
  await rejectsCode(store.readTicket({
    deviceId: DEVICE_ID,
    planTicketId: ticket.planTicketId,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  await rejectsCode(store.consumeTicket({
    deviceId: DEVICE_ID,
    planTicketId: ticket.planTicketId,
    ticketRecordDigest: ticket.recordDigest,
    authorizationDigest: ticket.authorizationDigest,
  }), 'RUNTIME_STATE_UNSUPPORTED');
  now = '2026-07-30T00:01:00.000Z';

  const input = {
    deviceId: DEVICE_ID,
    planTicketId: ticket.planTicketId,
    ticketRecordDigest: ticket.recordDigest,
    authorizationDigest: ticket.authorizationDigest,
  };
  const settled = await Promise.allSettled([
    store.consumeTicket(input),
    store.consumeTicket(input),
  ]);
  assert.equal(settled.filter(({ status }) => status === 'fulfilled').length, 1);
  const rejected = settled.find(({ status }) => status === 'rejected');
  assert.equal(rejected.reason.code, 'RUNTIME_INPUT_INVALID');
});
