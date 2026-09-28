import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { connect } from 'node:net';
import { inspect } from 'node:util';
import test from 'node:test';

import { CompletionTicketStore } from '../src/enrollment/completion-ticket-store.mjs';
import { startEnrollmentReceiver } from '../src/enrollment/enrollment-receiver.mjs';

const DEVICE_ID = 'dev_abc123';
const SSH_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBsAFEQvB0i0RoR9qkqCHDw5BDzQPE+4wP3ScuwRjJCm agent-road:dev_abc123';
const STAGE_BYTES = Buffer.from("Write-Output 'OK'\n");
const STAGE_BASE64 = STAGE_BYTES.toString('base64');
const STAGE_SHA = '75b9bc87820d6e075e3d9d87a4ba97cc4617663f80a6c174a074c68417f8b520';
const SIGNATURE = 'c2lnbmF0dXJl';

function validCompletion(ticket) {
  return {
    protocolVersion: 1,
    deviceId: DEVICE_ID,
    completionTicket: ticket,
    target: {
      version: '10.0.19045',
      build: 19045,
      edition: 'Professional',
      architecture: 'AMD64',
    },
    tailscaleAddresses: ['100.64.0.10'],
    sshHostKeys: [SSH_KEY],
    sshHostKeyFingerprints: ['SHA256:3vIF45tPRtGVuJ3VsSRd0MvFQ87Y38vAnRqfFdNcsYM'],
    checkpoints: ['preflight', 'tailscale', 'openssh', 'account', 'firewall'],
  };
}

function postJson(port, path, body, headers = {}) {
  const bytes = Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
  return postBytes(port, path, bytes, headers);
}

function postBytes(port, path, bytes, headers = {}) {
  return new Promise((resolve, reject) => {
    const request = httpRequest({
      host: '127.0.0.1',
      port,
      path,
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': bytes.length,
        ...headers,
      },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({
        statusCode: response.statusCode,
        headers: response.headers,
        text: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    request.on('error', reject);
    request.end(bytes);
  });
}

function rawRequest(port, lines, body = '') {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port });
    const chunks = [];
    socket.setEncoding('utf8');
    socket.on('connect', () => socket.end(`${lines.join('\r\n')}\r\n\r\n${body}`));
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('end', () => resolve(chunks.join('')));
    socket.on('error', reject);
  });
}

async function fixture(t, overrides = {}) {
  let tokenConsumed = false;
  let signCalls = 0;
  const tokenStore = overrides.tokenStore ?? {
    consume: async (token) => {
      assert.equal(token, 'raw-one-use-token');
      if (tokenConsumed) throw new Error(`secret:${token}`);
      tokenConsumed = true;
      return { deviceId: DEVICE_ID, expiresAt: '2026-07-26T00:10:00.000Z' };
    },
  };
  const completionTickets = overrides.completionTickets ?? new CompletionTicketStore({
    randomBytes: () => Buffer.alloc(32, 0xb5),
  });
  const receiver = await startEnrollmentReceiver({
    tokenStore,
    completionTickets,
    deviceId: DEVICE_ID,
    sshPublicKey: SSH_KEY,
    stageOneBytes: STAGE_BYTES,
    signer: {
      sign: async (bytes) => {
        signCalls += 1;
        assert.deepEqual(bytes, STAGE_BYTES);
        return SIGNATURE;
      },
    },
    host: '127.0.0.1',
    port: 0,
    ...overrides.options,
  });
  t.after(() => receiver.close());
  return {
    receiver,
    completionTickets,
    get tokenConsumed() { return tokenConsumed; },
    get signCalls() { return signCalls; },
  };
}

test('exchanges one enrollment token for the exact signed bootstrap response', async (t) => {
  const state = await fixture(t, {
    completionTickets: {
      issue: async (deviceId, ttlMs) => {
        assert.equal(state.tokenConsumed, true);
        assert.equal(deviceId, DEVICE_ID);
        assert.equal(ttlMs, 600_000);
        return 't'.repeat(43);
      },
      consume: async () => {},
    },
  });

  const response = await postJson(
    state.receiver.port,
    '/exchange',
    { protocolVersion: 1, deviceId: DEVICE_ID, token: 'raw-one-use-token' },
  );

  assert.equal(response.statusCode, 200);
  assert.equal(response.headers['content-type'], 'application/json');
  assert.deepEqual(JSON.parse(response.text), {
    protocolVersion: 1,
    deviceId: DEVICE_ID,
    sshPublicKey: SSH_KEY,
    stageOneBase64: STAGE_BASE64,
    stageOneSha256: STAGE_SHA,
    stageOneSignatureBase64: SIGNATURE,
    completionTicket: 't'.repeat(43),
  });
  assert.equal(state.tokenConsumed, true);
  assert.equal(state.signCalls, 1);
});

test('uses a snapshotted bounded completion-ticket lifetime without a body override', async (t) => {
  for (const [name, completionTtlMs] of [
    ['five minutes', 5 * 60 * 1000],
    ['thirty minutes', 30 * 60 * 1000],
  ]) {
    await t.test(name, async (t) => {
      let ttlReads = 0;
      let issuedTtl;
      const options = {
        get completionTtlMs() {
          ttlReads += 1;
          return completionTtlMs;
        },
      };
      const state = await fixture(t, {
        completionTickets: {
          issue: async (_deviceId, ttlMs) => {
            issuedTtl = ttlMs;
            return 't'.repeat(43);
          },
          consume: async () => ({ deviceId: DEVICE_ID }),
        },
        options,
      });

      const response = await postJson(state.receiver.port, `/exchange`, {
        protocolVersion: 1,
        deviceId: DEVICE_ID,
        token: 'raw-one-use-token',
      });

      assert.equal(response.statusCode, 200);
      assert.equal(issuedTtl, completionTtlMs);
      assert.equal(ttlReads, 1);
    });
  }

  let issues = 0;
  const state = await fixture(t, {
    completionTickets: {
      issue: async () => { issues += 1; return 't'.repeat(43); },
      consume: async () => ({ deviceId: DEVICE_ID }),
    },
    options: { completionTtlMs: 5 * 60 * 1000 },
  });
  const override = await postJson(state.receiver.port, `/exchange`, {
    protocolVersion: 1,
    deviceId: DEVICE_ID,
    token: 'raw-one-use-token',
    completionTtlMs: 30 * 60 * 1000,
  });
  assert.equal(override.statusCode, 400);
  assert.equal(override.text, '{"error":"invalid enrollment request"}');
  assert.equal(issues, 0);
});

test('accepts one exact completion and resolves a deeply frozen snapshot', async (t) => {
  const state = await fixture(t);
  const exchange = await postJson(state.receiver.port, `/exchange`, {
    protocolVersion: 1,
    deviceId: DEVICE_ID,
    token: 'raw-one-use-token',
  });
  const ticket = JSON.parse(exchange.text).completionTicket;
  const waiting = state.receiver.waitForCompletion({ timeoutMs: 1000 });

  const response = await postJson(
    state.receiver.port,
    `/complete`,
    validCompletion(ticket),
  );
  const completion = await waiting;

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.text), { protocolVersion: 1, deviceId: DEVICE_ID, accepted: true });
  assert.deepEqual(completion, {
    protocolVersion: 1,
    deviceId: DEVICE_ID,
    target: validCompletion(ticket).target,
    tailscaleAddresses: ['100.64.0.10'],
    sshHostKeys: [SSH_KEY],
    sshHostKeyFingerprints: ['SHA256:3vIF45tPRtGVuJ3VsSRd0MvFQ87Y38vAnRqfFdNcsYM'],
    checkpoints: ['preflight', 'tailscale', 'openssh', 'account', 'firewall'],
  });
  assert.equal(Object.isFrozen(completion), true);
  assert.equal(Object.isFrozen(completion.target), true);
  assert.equal(Object.isFrozen(completion.checkpoints), true);
  assert.doesNotMatch(JSON.stringify(completion), new RegExp(ticket, 'u'));
  assert.strictEqual(await state.receiver.waitForCompletion({ timeoutMs: 1000 }), completion);
});

test('allows only one concurrent completion request to consume a ticket', async (t) => {
  let attempts = 0;
  let releaseAttempts;
  let allEntered;
  const entered = new Promise((resolve) => { allEntered = resolve; });
  const blocked = new Promise((resolve) => { releaseAttempts = resolve; });
  const state = await fixture(t, {
    completionTickets: {
      issue: async () => 't'.repeat(43),
      consume: async () => {
        const attempt = attempts;
        attempts += 1;
        if (attempts === 8) allEntered();
        await blocked;
        if (attempt !== 0) throw new Error('already consumed');
        return { deviceId: DEVICE_ID };
      },
    },
  });
  const responsesPending = Promise.all(Array.from({ length: 8 }, () => postJson(
    state.receiver.port,
    `/complete`,
    validCompletion('t'.repeat(43)),
  )));
  await entered;
  releaseAttempts();
  const responses = await responsesPending;

  assert.equal(responses.filter(({ statusCode }) => statusCode === 200).length, 1);
  assert.equal(responses.filter(({ statusCode }) => statusCode === 400).length, 7);
  for (const response of responses.filter(({ statusCode }) => statusCode === 400)) {
    assert.equal(response.text, '{"error":"invalid completion request"}');
  }
  assert.equal(attempts, 8);
});

test('rejects non-exact methods, paths, media types, and schemas with fixed redacted errors', async (t) => {
  const state = await fixture(t);
  const validExchange = { protocolVersion: 1, deviceId: DEVICE_ID, token: 'raw-one-use-token' };
  const cases = [
    ['wrong path', `/exchange/`, validExchange, {}, 404, '{"error":"not found"}'],
    ['wrong device path', '/agent-road/v1/dev_other/exchange', validExchange, {}, 404, '{"error":"not found"}'],
    ['media type parameters', `/exchange`, validExchange, { 'content-type': 'application/json; charset=utf-8' }, 400, '{"error":"invalid enrollment request"}'],
    ['extra key', `/exchange`, { ...validExchange, extra: 'raw-one-use-token' }, {}, 400, '{"error":"invalid enrollment request"}'],
    ['wrong protocol', `/exchange`, { ...validExchange, protocolVersion: 2 }, {}, 400, '{"error":"invalid enrollment request"}'],
    ['malformed JSON', `/exchange`, '{"token":"secret-fragment"', {}, 400, '{"error":"invalid enrollment request"}'],
  ];

  for (const [name, path, body, headers, status, text] of cases) {
    await t.test(name, async () => {
      const response = await postJson(state.receiver.port, path, body, headers);
      assert.equal(response.statusCode, status);
      assert.equal(response.text, text);
      assert.doesNotMatch(response.text, /raw-one-use-token|secret-fragment|signature/u);
    });
  }

  const getResponse = await new Promise((resolve, reject) => {
    const request = httpRequest({ host: '127.0.0.1', port: state.receiver.port, path: `/exchange`, method: 'GET' }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ statusCode: response.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
    });
    request.on('error', reject);
    request.end();
  });
  assert.deepEqual(getResponse, { statusCode: 405, text: '{"error":"method not allowed"}' });
});

test('rejects malformed completion facts before consuming a ticket', async (t) => {
  let consumes = 0;
  const state = await fixture(t, {
    completionTickets: {
      issue: async () => 't'.repeat(43),
      consume: async () => { consumes += 1; },
    },
  });
  const base = validCompletion('t'.repeat(43));
  const invalid = [
    { ...base, extra: true },
    { ...base, deviceId: 'dev_other' },
    { ...base, target: { ...base.target, build: 100_000 } },
    { ...base, target: { ...base.target, extra: true } },
    { ...base, tailscaleAddresses: ['010.064.000.010'] },
    { ...base, tailscaleAddresses: ['2001:0db8::1'] },
    { ...base, tailscaleAddresses: Array(9).fill('100.64.0.10') },
    { ...base, sshHostKeys: ['ssh-ed25519 not-base64 secret'] },
    { ...base, sshHostKeyFingerprints: ['SHA256:not-a-fingerprint'] },
    { ...base, sshHostKeyFingerprints: ['SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'] },
    {
      ...base,
      sshHostKeyFingerprints: [
        ...base.sshHostKeyFingerprints,
        'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      ],
    },
    { ...base, checkpoints: ['preflight', 'preflight'] },
    { ...base, checkpoints: ['preflight', 'tailscale', 'openssh', 'account', 'unknown'] },
  ];

  for (const body of invalid) {
    const response = await postJson(state.receiver.port, `/complete`, body);
    assert.equal(response.statusCode, 400);
    assert.equal(response.text, '{"error":"invalid completion request"}');
  }
  assert.equal(consumes, 0);
});

test('rejects duplicate JSON keys and invalid UTF-8 before token consumption', async (t) => {
  let consumes = 0;
  const state = await fixture(t, {
    tokenStore: { consume: async () => { consumes += 1; return { deviceId: DEVICE_ID }; } },
  });
  const duplicate = `{"protocolVersion":1,"deviceId":"${DEVICE_ID}","token":"first-secret","token":"second-secret"}`;
  const duplicateResponse = await postJson(
    state.receiver.port,
    `/exchange`,
    duplicate,
  );
  const invalidUtf8 = Buffer.concat([
    Buffer.from(`{"protocolVersion":1,"deviceId":"${DEVICE_ID}","token":"`),
    Buffer.from([0xc3, 0x28]),
    Buffer.from('"}'),
  ]);
  const utf8Response = await postBytes(
    state.receiver.port,
    `/exchange`,
    invalidUtf8,
  );

  assert.equal(duplicateResponse.statusCode, 400);
  assert.equal(duplicateResponse.text, '{"error":"invalid enrollment request"}');
  assert.equal(utf8Response.statusCode, 400);
  assert.equal(utf8Response.text, '{"error":"invalid enrollment request"}');
  assert.equal(consumes, 0);
});

test('fails closed when injected ticket stores return invalid or mismatched values', async (t) => {
  await t.test('invalid issued ticket', async (t) => {
    const state = await fixture(t, {
      completionTickets: { issue: async () => 'leaked-ticket', consume: async () => ({ deviceId: DEVICE_ID }) },
    });
    const response = await postJson(state.receiver.port, `/exchange`, {
      protocolVersion: 1, deviceId: DEVICE_ID, token: 'raw-one-use-token',
    });
    assert.equal(response.statusCode, 400);
    assert.equal(response.text, '{"error":"invalid enrollment request"}');
    assert.doesNotMatch(response.text, /leaked-ticket/u);
  });

  await t.test('mismatched consumed ticket', async (t) => {
    const state = await fixture(t, {
      completionTickets: {
        issue: async () => 't'.repeat(43),
        consume: async () => ({ deviceId: 'dev_other' }),
      },
    });
    const response = await postJson(
      state.receiver.port,
      `/complete`,
      validCompletion('t'.repeat(43)),
    );
    assert.equal(response.statusCode, 400);
    assert.equal(response.text, '{"error":"invalid completion request"}');
  });
});

test('enforces exact Content-Length, forbids transfer encoding, and bounds bodies', async (t) => {
  const state = await fixture(t);
  const body = JSON.stringify({ protocolVersion: 1, deviceId: DEVICE_ID, token: 'raw-one-use-token' });
  const common = [
    'POST /exchange HTTP/1.1',
    'Host: 127.0.0.1',
    'Content-Type: application/json',
    'Connection: close',
  ];
  const rawCases = [
    [...common],
    [...common, 'Content-Type: application/json', `Content-Length: ${Buffer.byteLength(body)}`],
    [...common, `Content-Length: ${Buffer.byteLength(body)}`, `Content-Length: ${Buffer.byteLength(body)}`],
    [...common, 'Transfer-Encoding: chunked'],
    [...common, `Content-Length: ${Buffer.byteLength(body)}`, 'Transfer-Encoding: chunked'],
  ];

  for (const lines of rawCases) {
    const response = await rawRequest(state.receiver.port, lines, body);
    assert.match(response, /HTTP\/1\.1 400 /u);
    assert.doesNotMatch(response, /raw-one-use-token/u);
  }

  const oversized = await postJson(
    state.receiver.port,
    `/exchange`,
    JSON.stringify({ value: 'x'.repeat(65_536) }),
  );
  assert.equal(oversized.statusCode, 413);
  assert.equal(oversized.text, '{"error":"request body too large"}');
});

test('enforces one absolute ten-second connection deadline which trickle bytes cannot reset', async (t) => {
  let deadlineCallback;
  let scheduledDelay;
  let timerSets = 0;
  let tokenConsumes = 0;
  const state = await fixture(t, {
    tokenStore: {
      consume: async () => {
        tokenConsumes += 1;
        return { deviceId: DEVICE_ID };
      },
    },
    options: {
      setRequestDeadline: (callback, delay) => {
        timerSets += 1;
        deadlineCallback = callback;
        scheduledDelay = delay;
        return { deadline: true };
      },
      clearRequestDeadline: () => {},
    },
  });
  const fullBody = Buffer.from(JSON.stringify({
    protocolVersion: 1,
    deviceId: DEVICE_ID,
    token: 'raw-one-use-token',
  }));
  let request;
  const outcome = new Promise((resolve) => {
    request = httpRequest({
      host: '127.0.0.1',
      port: state.receiver.port,
      path: `/exchange`,
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': fullBody.length,
      },
    }, (response) => {
      response.resume();
      response.on('end', () => resolve({ type: 'response', statusCode: response.statusCode }));
    });
    request.on('error', () => resolve({ type: 'error' }));
    request.write(fullBody.subarray(0, 1));
  });
  await Promise.race([
    (async () => {
      while (!deadlineCallback) await new Promise((resolve) => setImmediate(resolve));
    })(),
    new Promise((_, reject) => setTimeout(() => reject(new Error('absolute deadline was not scheduled')), 100)),
  ]);
  request.write(fullBody.subarray(1, 2));

  assert.equal(timerSets, 1);
  assert.equal(scheduledDelay, 10_000);
  deadlineCallback();
  const result = await outcome;

  assert.notDeepEqual(result, { type: 'response', statusCode: 200 });
  assert.equal(tokenConsumes, 0);
});

test('starts the absolute deadline at TCP acceptance and closes partial headers before consumption', async (t) => {
  let deadlineCallback;
  let scheduledDelay;
  let tokenConsumes = 0;
  const state = await fixture(t, {
    tokenStore: {
      consume: async () => {
        tokenConsumes += 1;
        return { deviceId: DEVICE_ID };
      },
    },
    options: {
      setRequestDeadline: (callback, delay) => {
        deadlineCallback = callback;
        scheduledDelay = delay;
        return { deadline: true };
      },
      clearRequestDeadline: () => {},
    },
  });
  let socket;
  const closed = new Promise((resolve, reject) => {
    socket = connect({ host: '127.0.0.1', port: state.receiver.port });
    socket.on('connect', () => {
      socket.write(`POST /exchange HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Ty`);
    });
    socket.on('end', resolve);
    socket.on('close', resolve);
    socket.on('error', (error) => {
      if (error.code === 'ECONNRESET') resolve();
      else reject(error);
    });
  });
  await Promise.race([
    (async () => {
      while (!deadlineCallback) await new Promise((resolve) => setImmediate(resolve));
    })(),
    new Promise((_, reject) => setTimeout(() => reject(new Error('connection deadline was not scheduled')), 100)),
  ]);

  assert.equal(scheduledDelay, 10_000);
  deadlineCallback();
  await closed;
  assert.equal(tokenConsumes, 0);
  assert.equal(socket.destroyed, true);
});

test('deadline expiry during delayed token consumption prevents ticket issue and success', async (t) => {
  let monotonicTime = 0;
  let enterConsume;
  let releaseConsume;
  let ticketIssues = 0;
  const entered = new Promise((resolve) => { enterConsume = resolve; });
  const blocked = new Promise((resolve) => { releaseConsume = resolve; });
  const state = await fixture(t, {
    tokenStore: {
      consume: async () => {
        enterConsume();
        await blocked;
        return { deviceId: DEVICE_ID };
      },
    },
    completionTickets: {
      issue: async () => { ticketIssues += 1; return 't'.repeat(43); },
      consume: async () => ({ deviceId: DEVICE_ID }),
    },
    options: {
      monotonicNow: () => monotonicTime,
      setRequestDeadline: () => ({ deadline: true }),
      clearRequestDeadline: () => {},
    },
  });
  const response = postJson(state.receiver.port, `/exchange`, {
    protocolVersion: 1,
    deviceId: DEVICE_ID,
    token: 'raw-one-use-token',
  }).catch(() => null);
  await entered;

  monotonicTime = 10_001;
  releaseConsume();
  const result = await response;
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(ticketIssues, 0);
  assert.notEqual(result?.statusCode, 200);
});

test('deadline expiry during delayed completion consumption prevents publication', async (t) => {
  let deadlineCallback;
  let enterConsume;
  let releaseConsume;
  const entered = new Promise((resolve) => { enterConsume = resolve; });
  const blocked = new Promise((resolve) => { releaseConsume = resolve; });
  const state = await fixture(t, {
    completionTickets: {
      issue: async () => 't'.repeat(43),
      consume: async () => {
        enterConsume();
        await blocked;
        return { deviceId: DEVICE_ID };
      },
    },
    options: {
      setRequestDeadline: (callback) => {
        deadlineCallback = callback;
        return { deadline: true };
      },
      clearRequestDeadline: () => {},
    },
  });
  const response = postJson(
    state.receiver.port,
    `/complete`,
    validCompletion('t'.repeat(43)),
  ).catch(() => null);
  await entered;

  deadlineCallback();
  releaseConsume();
  const result = await response;
  assert.notEqual(result?.statusCode, 200);
  await assert.rejects(
    state.receiver.waitForCompletion({ timeoutMs: 10 }),
    (error) => error.code === 'ENROLLMENT_TIMEOUT',
  );
});

test('completion publication is the commit point and cannot be reversed by a later clock read', async (t) => {
  let afterConsume = false;
  let readsAfterConsume = 0;
  const state = await fixture(t, {
    completionTickets: {
      issue: async () => 't'.repeat(43),
      consume: async () => {
        afterConsume = true;
        return { deviceId: DEVICE_ID };
      },
    },
    options: {
      monotonicNow: () => {
        if (!afterConsume) return 0;
        readsAfterConsume += 1;
        return readsAfterConsume === 1 ? 0 : 10_001;
      },
      setRequestDeadline: () => ({ deadline: true }),
      clearRequestDeadline: () => {},
    },
  });
  const waiting = state.receiver.waitForCompletion({ timeoutMs: 1000 });

  const response = await postJson(
    state.receiver.port,
    `/complete`,
    validCompletion('t'.repeat(43)),
  ).catch(() => null);
  const completion = await waiting;

  assert.equal(response?.statusCode, 200);
  assert.deepEqual(response && JSON.parse(response.text), {
    protocolVersion: 1,
    deviceId: DEVICE_ID,
    accepted: true,
  });
  assert.equal(completion.deviceId, DEVICE_ID);
  assert.equal(readsAfterConsume, 1);
});

test('reconciles an exact sequential completion retry after the committed response socket is lost', async (t) => {
  let consumeCalls = 0;
  let enterConsume;
  let releaseConsume;
  const entered = new Promise((resolve) => { enterConsume = resolve; });
  const blocked = new Promise((resolve) => { releaseConsume = resolve; });
  const state = await fixture(t, {
    completionTickets: {
      issue: async () => 't'.repeat(43),
      consume: async (_ticket, deviceId) => {
        consumeCalls += 1;
        assert.equal(deviceId, DEVICE_ID);
        enterConsume();
        await blocked;
        return { deviceId: DEVICE_ID };
      },
    },
  });
  const requestBody = validCompletion('t'.repeat(43));
  const waiting = state.receiver.waitForCompletion({ timeoutMs: 1000 });
  const bytes = Buffer.from(JSON.stringify(requestBody));
  let firstRequest;
  const firstOutcome = new Promise((resolve) => {
    firstRequest = httpRequest({
      host: '127.0.0.1',
      port: state.receiver.port,
      path: `/complete`,
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': bytes.length },
    }, (response) => {
      response.resume();
      response.on('end', () => resolve({ statusCode: response.statusCode }));
    });
    firstRequest.on('error', () => resolve(null));
    firstRequest.end(bytes);
  });
  await entered;
  firstRequest.destroy();
  await firstOutcome;
  releaseConsume();
  const committed = await waiting;
  await new Promise((resolve) => setImmediate(resolve));

  const replay = await postJson(
    state.receiver.port,
    `/complete`,
    requestBody,
  );

  assert.equal(replay.statusCode, 200);
  assert.deepEqual(JSON.parse(replay.text), { protocolVersion: 1, deviceId: DEVICE_ID, accepted: true });
  assert.equal(consumeCalls, 1);
  assert.strictEqual(await state.receiver.waitForCompletion({ timeoutMs: 100 }), committed);
  assert.doesNotMatch(inspect(state.receiver, { showHidden: true }), /tttttttttttttttt/u);
});

test('rejects altered completion replays without consuming or republishing', async (t) => {
  let consumeCalls = 0;
  const state = await fixture(t, {
    completionTickets: {
      issue: async () => 't'.repeat(43),
      consume: async () => {
        consumeCalls += 1;
        return { deviceId: DEVICE_ID };
      },
    },
  });
  const original = validCompletion('t'.repeat(43));
  const first = await postJson(state.receiver.port, `/complete`, original);
  assert.equal(first.statusCode, 200);
  await new Promise((resolve) => setImmediate(resolve));

  const altered = [
    { ...original, completionTicket: 's'.repeat(43) },
    { ...original, target: { ...original.target, edition: 'Home' } },
    { ...original, deviceId: 'dev_other' },
  ];
  for (const body of altered) {
    const response = await postJson(state.receiver.port, `/complete`, body);
    assert.equal(response.statusCode, 400);
    assert.equal(response.text, '{"error":"invalid completion request"}');
    assert.doesNotMatch(response.text, /tttttttt|ssssssss|Professional|Home/u);
  }
  assert.equal(consumeCalls, 1);
});

test('rejects an exact completion from a socket accepted before the first response settled', async (t) => {
  let consumeCalls = 0;
  const state = await fixture(t, {
    completionTickets: {
      issue: async () => 't'.repeat(43),
      consume: async () => {
        consumeCalls += 1;
        return { deviceId: DEVICE_ID };
      },
    },
  });
  let earlySocket;
  const earlyResponse = new Promise((resolve, reject) => {
    const chunks = [];
    earlySocket = connect({ host: '127.0.0.1', port: state.receiver.port });
    earlySocket.setEncoding('utf8');
    earlySocket.on('data', (chunk) => chunks.push(chunk));
    earlySocket.on('end', () => resolve(chunks.join('')));
    earlySocket.on('error', reject);
  });
  await new Promise((resolve) => earlySocket.once('connect', resolve));

  const original = validCompletion('t'.repeat(43));
  const first = await postJson(state.receiver.port, `/complete`, original);
  assert.equal(first.statusCode, 200);
  await new Promise((resolve) => setImmediate(resolve));
  const bytes = Buffer.from(JSON.stringify(original));
  earlySocket.end([
    `POST /complete HTTP/1.1`,
    'Host: 127.0.0.1',
    'Content-Type: application/json',
    `Content-Length: ${bytes.length}`,
    'Connection: close',
    '',
    bytes.toString('utf8'),
  ].join('\r\n'));

  const replay = await earlyResponse;
  assert.match(replay, /HTTP\/1\.1 400 /u);
  assert.doesNotMatch(replay, /tttttttttttt/u);
  assert.equal(consumeCalls, 1);
});

test('close prevents a delayed exchange from issuing or returning a completion ticket', async (t) => {
  let enterConsume;
  let releaseConsume;
  let ticketIssues = 0;
  const entered = new Promise((resolve) => { enterConsume = resolve; });
  const blocked = new Promise((resolve) => { releaseConsume = resolve; });
  const state = await fixture(t, {
    tokenStore: {
      consume: async () => {
        enterConsume();
        await blocked;
        return { deviceId: DEVICE_ID };
      },
    },
    completionTickets: {
      issue: async () => { ticketIssues += 1; return 't'.repeat(43); },
      consume: async () => ({ deviceId: DEVICE_ID }),
    },
  });
  const response = postJson(state.receiver.port, `/exchange`, {
    protocolVersion: 1,
    deviceId: DEVICE_ID,
    token: 'raw-one-use-token',
  }).catch(() => null);
  await entered;

  const closing = state.receiver.close();
  releaseConsume();
  await closing;
  const result = await response;
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(ticketIssues, 0);
  assert.notEqual(result?.statusCode, 200);
  await assert.rejects(
    state.receiver.waitForCompletion({ timeoutMs: 10 }),
    (error) => error.code === 'ENROLLMENT_CLOSED',
  );
});

test('close prevents a delayed completion consume from publishing success', async (t) => {
  let enterConsume;
  let releaseConsume;
  const entered = new Promise((resolve) => { enterConsume = resolve; });
  const blocked = new Promise((resolve) => { releaseConsume = resolve; });
  const state = await fixture(t, {
    completionTickets: {
      issue: async () => 't'.repeat(43),
      consume: async () => {
        enterConsume();
        await blocked;
        return { deviceId: DEVICE_ID };
      },
    },
  });
  const waiting = state.receiver.waitForCompletion({ timeoutMs: 1000 });
  const response = postJson(
    state.receiver.port,
    `/complete`,
    validCompletion('t'.repeat(43)),
  ).catch(() => null);
  await entered;

  const closing = state.receiver.close();
  await assert.rejects(waiting, (error) => error.code === 'ENROLLMENT_CLOSED');
  releaseConsume();
  await closing;
  const result = await response;
  await new Promise((resolve) => setImmediate(resolve));

  assert.notEqual(result?.statusCode, 200);
  await assert.rejects(
    state.receiver.waitForCompletion({ timeoutMs: 10 }),
    (error) => error.code === 'ENROLLMENT_CLOSED',
  );
});

test('requires localhost binding, computes stage material once, times out waiters, and closes idempotently', async (t) => {
  await assert.rejects(fixture(t, { options: { host: '0.0.0.0' } }), /ENROLLMENT_LOCALHOST_REQUIRED/);
  const state = await fixture(t);
  assert.equal(state.signCalls, 1);

  await assert.rejects(
    state.receiver.waitForCompletion({ timeoutMs: 10 }),
    (error) => error.code === 'ENROLLMENT_TIMEOUT' && error.message === 'ENROLLMENT_TIMEOUT',
  );
  await state.receiver.close();
  await state.receiver.close();
  await assert.rejects(
    state.receiver.waitForCompletion({ timeoutMs: 10 }),
    (error) => error.code === 'ENROLLMENT_CLOSED',
  );
});

test('validates stage bytes and the device-specific SSH key before signing or listening', async () => {
  let signCalls = 0;
  const common = {
    tokenStore: { consume: async () => ({ deviceId: DEVICE_ID }) },
    completionTickets: { issue: async () => 't'.repeat(43), consume: async () => ({ deviceId: DEVICE_ID }) },
    deviceId: DEVICE_ID,
    sshPublicKey: SSH_KEY,
    stageOneBytes: STAGE_BYTES,
    signer: { sign: async () => { signCalls += 1; return SIGNATURE; } },
  };
  await assert.rejects(startEnrollmentReceiver({ ...common, stageOneBytes: 'not bytes' }), /invalid enrollment receiver options/);
  await assert.rejects(startEnrollmentReceiver({
    ...common,
    sshPublicKey: SSH_KEY.replace(`agent-road:${DEVICE_ID}`, 'agent-road:dev_other'),
  }), /invalid enrollment receiver options/);
  for (const completionTtlMs of [
    5 * 60 * 1000 - 1,
    30 * 60 * 1000 + 1,
    300_000.5,
    '600000',
    Number.NaN,
  ]) {
    await assert.rejects(
      startEnrollmentReceiver({ ...common, completionTtlMs }),
      /invalid enrollment receiver options/,
    );
  }
  assert.equal(signCalls, 0);
  const maximumDeviceId = `dev_${'a'.repeat(60)}`;
  const accepted = await startEnrollmentReceiver({
    ...common,
    deviceId: maximumDeviceId,
    sshPublicKey: SSH_KEY.replace(`agent-road:${DEVICE_ID}`, `agent-road:${maximumDeviceId}`),
  });
  await accepted.close();
  const oversizedDeviceId = `dev_${'a'.repeat(61)}`;
  await assert.rejects(startEnrollmentReceiver({
    ...common,
    deviceId: oversizedDeviceId,
    sshPublicKey: SSH_KEY.replace(`agent-road:${DEVICE_ID}`, `agent-road:${oversizedDeviceId}`),
  }), /invalid enrollment receiver options/);
  assert.equal(signCalls, 1);
});


test('native receiver releases only data, refuses v1 before consumption, and completes once', async t => {
  const state = await fixture(t, {options:{protocolVersion:2, signer:undefined, stageOneBytes:undefined}});
  const rejected = await postJson(state.receiver.port, '/exchange', {protocolVersion:1, deviceId:DEVICE_ID, token:'raw-one-use-token'});
  assert.equal(rejected.statusCode, 400);
  assert.equal(state.tokenConsumed, false);
  const exchange = await postJson(state.receiver.port, '/exchange', {protocolVersion:2, deviceId:DEVICE_ID, token:'raw-one-use-token'});
  assert.equal(exchange.statusCode, 200);
  const body = JSON.parse(exchange.text);
  assert.deepEqual(Object.keys(body).sort(), ['completionTicket','deviceId','protocolVersion','sshPublicKey']);
  assert.equal(body.protocolVersion, 2);
  assert.equal(state.signCalls, 0);
  const replay = await postJson(state.receiver.port, '/exchange', {protocolVersion:2, deviceId:DEVICE_ID, token:'raw-one-use-token'});
  assert.equal(replay.statusCode, 400);
  const completion = {...validCompletion(body.completionTicket), protocolVersion:2};
  assert.equal((await postJson(state.receiver.port, '/complete', {...completion, protocolVersion:1})).statusCode, 400);
  const accepted = await postJson(state.receiver.port, '/complete', completion);
  assert.deepEqual(JSON.parse(accepted.text), {protocolVersion:2, deviceId:DEVICE_ID, accepted:true});
  const snapshot = await state.receiver.waitForCompletion({timeoutMs:1000});
  // The internal verified snapshot contract is unchanged; wire versions cannot mix.
  assert.equal(snapshot.protocolVersion, 1);
  assert.equal(snapshot.deviceId, DEVICE_ID);
});

test('native receiver refuses executable options and unknown protocol versions', async t => {
  await assert.rejects(fixture(t, {options:{protocolVersion:2}}), /refuses executable/);
  await assert.rejects(fixture(t, {options:{protocolVersion:3}}), /invalid enrollment receiver/);
});


test('default receiver refuses native exchange without consuming its token', async t => {
  const state = await fixture(t);
  const rejected = await postJson(state.receiver.port, '/exchange', {protocolVersion:2, deviceId:DEVICE_ID, token:'raw-one-use-token'});
  assert.equal(rejected.statusCode, 400);
  assert.equal(state.tokenConsumed, false);
});
