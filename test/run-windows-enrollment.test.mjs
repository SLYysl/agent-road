import assert from 'node:assert/strict';
import test from 'node:test';

import { runWindowsEnrollment } from '../src/enrollment/run-windows-enrollment.mjs';

const DEVICE_ID = 'dev_abc123';
const SSH_PUBLIC_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBsAFEQvB0i0RoR9qkqCHDw5BDzQPE+4wP3ScuwRjJCm agent-road:dev_abc123';
const HOST_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBsAFEQvB0i0RoR9qkqCHDw5BDzQPE+4wP3ScuwRjJCm';
const FINGERPRINT = 'SHA256:3vIF45tPRtGVuJ3VsSRd0MvFQ87Y38vAnRqfFdNcsYM';

function fixture(overrides = {}) {
  const events = [];
  let exchanged = false;
  let receiverStartOptions;
  let tokenIssueInput;
  const record = {
    id: DEVICE_ID,
    displayName: 'Studio PC',
    controllerPlatform: 'darwin',
    targetPlatform: 'windows',
    status: 'ENROLLING',
    capabilities: [],
    createdAt: '2026-07-27T00:00:00.000Z',
    updatedAt: '2026-07-27T00:00:00.000Z',
  };
  const completion = {
    protocolVersion: 1,
    deviceId: DEVICE_ID,
    target: { version: '10.0.19045', build: 19045, edition: 'Professional', architecture: 'AMD64' },
    tailscaleAddresses: ['100.64.0.10'],
    sshHostKeys: [HOST_KEY],
    sshHostKeyFingerprints: [FINGERPRINT],
    checkpoints: ['preflight', 'tailscale', 'openssh', 'account', 'firewall'],
  };
  const receiver = {
    port: 43210,
    waitForCompletion: async () => { events.push('receiver.waitForCompletion'); return completion; },
    close: async () => { events.push('receiver.close'); },
  };
  const dependencies = {
    tailscale: {
      status: async () => { events.push('tailscale.status'); return { backendState: 'Running', dnsName: 'mac.tail123.ts.net', tailscaleIPs: ['100.64.0.1'] }; },
      serve: async (input) => {
        events.push(`tailscale.serve:${input.deviceId}:${input.localPort}`);
        return {
          baseUrl: `https://mac.tail123.ts.net/agent-road/v1/${input.deviceId}`,
          close: async () => { events.push('serve.close'); },
        };
      },
    },
    signer: {
      getOrCreate: async () => { events.push('signer.getOrCreate'); return { algorithm: 'RSA-SHA256', modulusBase64Url: 'abc', exponentBase64Url: 'AQAB' }; },
      sign: async () => 'c2ln',
    },
    sshIdentity: {
      getOrCreate: async () => { events.push('sshIdentity.getOrCreate'); return { privateKeyPath: `/safe/${DEVICE_ID}/id_ed25519`, publicKey: SSH_PUBLIC_KEY }; },
    },
    startReceiver: async (options) => {
      receiverStartOptions = options;
      const { tokenStore } = options;
      events.push('receiver.start');
      receiver.consume = async () => { exchanged = true; return tokenStore.consume('token'); };
      return receiver;
    },
    tokenStore: {
      issue: async (input) => { tokenIssueInput = input; events.push('token.issue'); return { token: 'x'.repeat(32), expiresAt: '2026-07-27T00:10:00.000Z' }; },
      consume: async () => { exchanged = true; return { deviceId: DEVICE_ID }; },
      revoke: async () => { events.push('token.revoke'); return true; },
    },
    completionTickets: {},
    registry: {
      add: async () => { events.push('registry.add'); },
      replace: async (value) => { events.push(`registry.replace:${value.status}`); return value; },
    },
    releaseManifest: { schemaVersion: 1 },
    stageOneBytes: Buffer.from('stage one'),
    buildCommand: ({ token }) => token === 'x'.repeat(32) ? 'powershell.exe REAL' : 'powershell.exe PREFLIGHT',
    verifySsh: async () => { events.push('ssh.verify'); return { address: '100.64.0.10', capabilities: ['ssh', 'sftp', 'admin-powershell'] }; },
    knownHostsPath: (deviceId) => `/safe/agent-road-known-hosts-${deviceId}`,
    now: () => new Date('2026-07-27T00:00:00.000Z'),
    createDeviceId: () => DEVICE_ID,
    ...overrides,
  };
  return {
    dependencies,
    events,
    receiver,
    completion,
    record,
    get exchanged() { return exchanged; },
    get receiverStartOptions() { return receiverStartOptions; },
    get tokenIssueInput() { return tokenIssueInput; },
  };
}

test('orchestrates preflight, one command, completion, strict SSH verification, persistence, and reverse cleanup', async () => {
  const state = fixture();
  const commands = [];
  const result = await runWindowsEnrollment({
    displayName: 'Studio PC',
    timeoutMs: 600_000,
    onCommand(command) { state.events.push('command.print'); commands.push(command); },
    onCommitStart() { state.events.push('commit.start'); },
    dependencies: state.dependencies,
  });

  assert.deepEqual(commands, ['powershell.exe REAL']);
  assert.equal(state.receiverStartOptions.completionTtlMs, 600_000);
  assert.deepEqual(state.tokenIssueInput, { deviceId: DEVICE_ID, ttlMs: 600_000 });
  assert.equal(result.status, 'CONNECTED_SSH_ONLY');
  assert.deepEqual(result.capabilities, ['ssh', 'sftp', 'admin-powershell']);
  assert.deepEqual(result.target, state.completion.target);
  assert.deepEqual(result.transport, {
    tailscaleAddresses: ['100.64.0.10'],
    sshUsername: 'AgentRoad',
    sshHostKeys: [HOST_KEY],
    sshHostKeyFingerprints: [FINGERPRINT],
  });
  assert.deepEqual(state.events, [
    'tailscale.status',
    'signer.getOrCreate',
    'sshIdentity.getOrCreate',
    'receiver.start',
    `tailscale.serve:${DEVICE_ID}:43210`,
    'token.issue',
    'registry.add',
    'command.print',
    'receiver.waitForCompletion',
    'ssh.verify',
    'serve.close',
    'receiver.close',
    'commit.start',
    'registry.replace:CONNECTED_SSH_ONLY',
  ]);
});

test('aligns receiver, token, and completion wait lifetimes at five and thirty minutes', async () => {
  for (const timeoutMs of [300_000, 1_800_000]) {
    const state = fixture();
    let waited;
    state.receiver.waitForCompletion = async ({ timeoutMs: value }) => {
      waited = value;
      return state.completion;
    };
    await runWindowsEnrollment({
      displayName: 'Studio PC', timeoutMs, onCommand() {}, dependencies: state.dependencies,
    });
    assert.equal(state.receiverStartOptions.completionTtlMs, timeoutMs);
    assert.equal(state.tokenIssueInput.ttlMs, timeoutMs);
    assert.equal(waited, timeoutMs);
  }
});

test('rejects out-of-session-range orchestrator timeouts before side effects', async () => {
  for (const timeoutMs of [299_999, 1_800_001]) {
    const state = fixture();
    await assert.rejects(runWindowsEnrollment({
      displayName: 'Studio PC', timeoutMs, onCommand() {}, dependencies: state.dependencies,
    }), /invalid Windows enrollment options/);
    assert.deepEqual(state.events, []);
  }
});

test('revokes before exchange and cleans Serve then receiver when waiting fails', async () => {
  const state = fixture();
  state.receiver.waitForCompletion = async () => { state.events.push('receiver.waitForCompletion'); throw Object.assign(new Error('secret timeout detail'), { code: 'ENROLLMENT_TIMEOUT' }); };

  await assert.rejects(runWindowsEnrollment({
    displayName: 'Studio PC', timeoutMs: 300_000, onCommand: () => state.events.push('command.print'), dependencies: state.dependencies,
  }), (error) => error.code === 'BOOTSTRAP_FAILED' && error.message === 'BOOTSTRAP_FAILED');

  assert.deepEqual(state.events.slice(-4), ['token.revoke', 'registry.replace:BOOTSTRAP_FAILED', 'serve.close', 'receiver.close']);
});

test('never revokes an exchanged token and records SSH verification failure', async () => {
  let failedRecord;
  const state = fixture({
    verifySsh: async () => { state.events.push('ssh.verify'); throw new Error('private path'); },
  });
  state.dependencies.registry.replace = async (value) => {
    state.events.push(`registry.replace:${value.status}`);
    failedRecord = value;
    return value;
  };
  state.receiver.waitForCompletion = async () => {
    state.events.push('receiver.waitForCompletion');
    await state.receiver.consume();
    return state.completion;
  };

  await assert.rejects(runWindowsEnrollment({
    displayName: 'Studio PC', timeoutMs: 300_000, onCommand: () => state.events.push('command.print'), dependencies: state.dependencies,
  }), (error) => error.code === 'SSH_VERIFY_FAILED' && error.message === 'SSH_VERIFY_FAILED');

  assert.equal(state.events.includes('token.revoke'), false);
  assert.deepEqual(state.events.slice(-3), ['registry.replace:SSH_VERIFY_FAILED', 'serve.close', 'receiver.close']);
  assert.deepEqual(failedRecord, {
    id: DEVICE_ID,
    displayName: 'Studio PC',
    controllerPlatform: 'darwin',
    targetPlatform: 'windows',
    status: 'SSH_VERIFY_FAILED',
    capabilities: [],
    createdAt: '2026-07-27T00:00:00.000Z',
    updatedAt: '2026-07-27T00:00:00.000Z',
    target: state.completion.target,
    transport: {
      tailscaleAddresses: ['100.64.0.10'],
      sshUsername: 'AgentRoad',
      sshHostKeys: [HOST_KEY],
      sshHostKeyFingerprints: [FINGERPRINT],
    },
  });
  assert.equal(JSON.stringify(failedRecord).includes('completionTicket'), false);
  assert.equal(JSON.stringify(failedRecord).includes('token'), false);
});

test('preserves SSH_VERIFY_FAILED when its metadata replacement also fails', async () => {
  const attemptedStatuses = [];
  const state = fixture({
    verifySsh: async () => { throw new Error('private verifier detail'); },
  });
  state.receiver.waitForCompletion = async () => {
    await state.receiver.consume();
    return state.completion;
  };
  state.dependencies.registry.replace = async (value) => {
    attemptedStatuses.push(value.status);
    throw new Error('/private/devices.json');
  };

  await assert.rejects(runWindowsEnrollment({
    displayName: 'Studio PC', timeoutMs: 300_000, onCommand: () => {}, dependencies: state.dependencies,
  }), { code: 'SSH_VERIFY_FAILED', message: 'SSH_VERIFY_FAILED' });
  assert.deepEqual(attemptedStatuses, ['SSH_VERIFY_FAILED']);
  assert.equal(attemptedStatuses.includes('CONNECTED_SSH_ONLY'), false);
});

test('preserves the core SSH failure while attempting both failing cleanups', async () => {
  const state = fixture({
    verifySsh: async () => { throw new Error('private verifier detail'); },
  });
  state.receiver.waitForCompletion = async () => {
    await state.receiver.consume();
    return state.completion;
  };
  state.dependencies.tailscale.serve = async ({ deviceId }) => ({
    baseUrl: `https://mac.tail123.ts.net/agent-road/v1/${deviceId}`,
    close: async () => { state.events.push('serve.close'); throw new Error('serve secret'); },
  });
  state.receiver.close = async () => { state.events.push('receiver.close'); throw new Error('receiver secret'); };

  await assert.rejects(runWindowsEnrollment({
    displayName: 'Studio PC', timeoutMs: 300_000, onCommand: () => {}, dependencies: state.dependencies,
  }), { code: 'SSH_VERIFY_FAILED', message: 'SSH_VERIFY_FAILED' });
  assert.deepEqual(state.events.slice(-2), ['serve.close', 'receiver.close']);
});

test('maps Serve consent failure without issuing a token and closes only the receiver', async () => {
  const state = fixture();
  state.dependencies.tailscale.serve = async () => {
    state.events.push('tailscale.serve');
    throw Object.assign(new Error('https://login.tailscale.com/a'), { code: 'TAILSCALE_SERVE_AUTH_REQUIRED', details: 'https://login.tailscale.com/a' });
  };
  await assert.rejects(runWindowsEnrollment({
    displayName: 'Studio PC', timeoutMs: 300_000, onCommand: () => {}, dependencies: state.dependencies,
  }), (error) => error.code === 'TAILSCALE_SERVE_AUTH_REQUIRED' && error.details === 'https://login.tailscale.com/a');
  assert.equal(state.events.includes('token.issue'), false);
  assert.equal(state.events.at(-1), 'receiver.close');
});

test('redacts controller identity failures as BOOTSTRAP_FAILED before persistence', async () => {
  const state = fixture();
  state.dependencies.signer.getOrCreate = async () => {
    state.events.push('signer.getOrCreate');
    throw Object.assign(new Error('/Users/private/bootstrap-signing-private.pem'), { code: 'BOOTSTRAP_SIGNING_KEY_PRIVATE_INVALID' });
  };
  await assert.rejects(runWindowsEnrollment({
    displayName: 'Studio PC', timeoutMs: 300_000, onCommand: () => {}, dependencies: state.dependencies,
  }), { code: 'BOOTSTRAP_FAILED', message: 'BOOTSTRAP_FAILED' });
  assert.deepEqual(state.events, ['tailscale.status', 'signer.getOrCreate']);
});

test('never persists CONNECTED when Serve, receiver, or both cleanup operations fail', async (t) => {
  for (const failure of ['serve', 'receiver', 'both']) {
    await t.test(failure, async () => {
      const statuses = [];
      const state = fixture();
      state.dependencies.registry.replace = async (value) => {
        statuses.push(value.status);
        return value;
      };
      state.dependencies.tailscale.serve = async ({ deviceId, localPort }) => ({
        baseUrl: `https://mac.tail123.ts.net/agent-road/v1/${deviceId}`,
        localPort,
        close: async () => {
          state.events.push('serve.close');
          if (failure === 'serve' || failure === 'both') throw new Error('secret Serve cleanup path');
        },
      });
      state.receiver.close = async () => {
        state.events.push('receiver.close');
        if (failure === 'receiver' || failure === 'both') throw new Error('secret receiver cleanup path');
      };

      await assert.rejects(runWindowsEnrollment({
        displayName: 'Studio PC', timeoutMs: 300_000, onCommand: () => state.events.push('command.print'), dependencies: state.dependencies,
      }), { code: 'BOOTSTRAP_FAILED', message: 'BOOTSTRAP_FAILED' });
      assert.deepEqual(state.events.slice(-2), ['serve.close', 'receiver.close']);
      assert.deepEqual(statuses, ['BOOTSTRAP_FAILED']);
      assert.equal(statuses.includes('CONNECTED_SSH_ONLY'), false);
    });
  }
});

test('aborting the completion wait performs reverse cleanup and never persists CONNECTED', async () => {
  const controller = new AbortController();
  const statuses = [];
  const state = fixture();
  let waiting;
  const waitStarted = new Promise((resolve) => { waiting = resolve; });
  state.receiver.waitForCompletion = async () => {
    state.events.push('receiver.waitForCompletion');
    waiting();
    return new Promise(() => {});
  };
  state.dependencies.registry.replace = async (value) => {
    statuses.push(value.status);
    return value;
  };

  const running = runWindowsEnrollment({
    displayName: 'Studio PC',
    timeoutMs: 300_000,
    onCommand: () => state.events.push('command.print'),
    dependencies: state.dependencies,
    signal: controller.signal,
  });
  await waitStarted;
  controller.abort();
  await assert.rejects(running, { code: 'BOOTSTRAP_FAILED', message: 'BOOTSTRAP_FAILED' });
  assert.deepEqual(state.events.slice(-2), ['serve.close', 'receiver.close']);
  assert.equal(statuses.includes('CONNECTED_SSH_ONLY'), false);
  assert.deepEqual(statuses, ['BOOTSTRAP_FAILED']);
});

test('rejects an invalid cancellation signal before side effects', async () => {
  const state = fixture();
  await assert.rejects(runWindowsEnrollment({
    displayName: 'Studio PC', timeoutMs: 300_000, onCommand() {}, dependencies: state.dependencies, signal: {},
  }), /invalid Windows enrollment options/);
  assert.deepEqual(state.events, []);
});

test('an abort immediately before the publication barrier fails without CONNECTED', async () => {
  const controller = new AbortController();
  const statuses = [];
  const state = fixture();
  state.receiver.close = async () => {
    state.events.push('receiver.close');
    controller.abort();
  };
  state.dependencies.registry.replace = async (value) => { statuses.push(value.status); return value; };

  await assert.rejects(runWindowsEnrollment({
    displayName: 'Studio PC', timeoutMs: 300_000, onCommand() {}, dependencies: state.dependencies, signal: controller.signal,
  }), { code: 'BOOTSTRAP_FAILED', message: 'BOOTSTRAP_FAILED' });
  assert.deepEqual(statuses, ['BOOTSTRAP_FAILED']);
  assert.equal(statuses.includes('CONNECTED_SSH_ONLY'), false);
});

test('direct API ignores abort after entering the final publication barrier', async () => {
  const controller = new AbortController();
  const statuses = [];
  const state = fixture();
  state.dependencies.registry.replace = async (value) => {
    statuses.push(value.status);
    controller.abort();
    await new Promise((resolve) => setImmediate(resolve));
    return value;
  };

  const result = await runWindowsEnrollment({
    displayName: 'Studio PC', timeoutMs: 300_000, onCommand() {}, dependencies: state.dependencies, signal: controller.signal,
  });
  assert.equal(controller.signal.aborted, true);
  assert.equal(result.status, 'CONNECTED_SSH_ONLY');
  assert.deepEqual(statuses, ['CONNECTED_SSH_ONLY']);
});
