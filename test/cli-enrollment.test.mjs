import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import test from 'node:test';

import { main } from '../src/cli.mjs';

const GENERATION_DIGEST = 'A'.repeat(64);
const RUNTIME_AUTHORIZATION_NOTICE = 'NOTICE: Pasting the generated Windows command authorizes Agent Road to install its private core runtime under C:\\ProgramData\\AgentRoad after pinned SSH verification.\n';

function readyState(deviceId = 'dev_abc123') {
  return {
    schemaVersion: 1,
    deviceId,
    runtimeStatus: 'READY',
    requestedProfiles: ['core'],
    readyProfiles: ['core'],
    operationId: null,
    manifestDigest: null,
    generationDigest: GENERATION_DIGEST,
    failureCode: null,
    updatedAt: '2026-07-30T00:00:00.000Z',
  };
}

function runtimeHandoff(deviceId = 'dev_abc123', inspect = () => {}) {
  const runtimeDependencyFactory = () => assert.fail('CLI must delegate dependency creation');
  return {
    runtimeDependencyFactory,
    ensureRuntime: async (input) => {
      inspect(input);
      assert.equal(input.deviceId, deviceId);
      assert.deepEqual(input.requestedProfiles, ['core']);
      assert.equal(input.dependencyFactory, runtimeDependencyFactory);
      return readyState(deviceId);
    },
  };
}

function run(args, env) {
  return spawnSync(process.execPath, ['src/cli.mjs', ...args], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env,
  });
}

test('enroll prints exactly one command to stdout and progress plus fixed success to stderr', async () => {
  let stdout = '';
  let stderr = '';
  const marker = Object.freeze({ production: 'dependencies' });
  let factoryCalls = 0;
  let handoffCalls = 0;
  const exitCode = await main(['enroll', '--name', 'Studio PC'], {}, {
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
    dependencyFactory: async () => { factoryCalls += 1; return marker; },
    runEnrollment: async (options) => {
      assert.equal(options.displayName, 'Studio PC');
      assert.equal(options.timeoutMs, 600_000);
      assert.equal(options.dependencies, marker);
      options.onCommand('powershell.exe -NoProfile -EncodedCommand QQ==');
      return { id: 'dev_abc123', status: 'CONNECTED_SSH_ONLY' };
    },
    ...runtimeHandoff('dev_abc123', () => { handoffCalls += 1; }),
  });

  assert.equal(exitCode, 0);
  assert.equal(factoryCalls, 1);
  assert.equal(handoffCalls, 1);
  assert.equal(stdout, 'powershell.exe -NoProfile -EncodedCommand QQ==\n');
  assert.equal(stderr, `ENROLLING\n${RUNTIME_AUTHORIZATION_NOTICE}CONNECTED_SSH_ONLY\nRUNTIME_READY\n`);
});

test('prints the fixed runtime authorization notice before the generated command', async () => {
  const events = [];
  const exitCode = await main(['enroll'], {}, {
    stdout: { write(value) { events.push(['stdout', value]); } },
    stderr: { write(value) { events.push(['stderr', value]); } },
    dependencyFactory: async () => ({}),
    signalSource: new EventEmitter(),
    runEnrollment: async (options) => {
      options.onCommand('one-line');
      return { id: 'dev_abc123', status: 'CONNECTED_SSH_ONLY' };
    },
    ...runtimeHandoff(),
  });

  assert.equal(exitCode, 0);
  assert.deepEqual(events.slice(0, 3), [
    ['stderr', 'ENROLLING\n'],
    ['stderr', RUNTIME_AUTHORIZATION_NOTICE],
    ['stdout', 'one-line\n'],
  ]);
});

test('enroll accepts only integer timeout minutes from 5 through 30 and has no controller URL', async () => {
  for (const value of ['4', '31', '5.5', '05', 'ten']) {
    await assert.rejects(main(['enroll', '--timeout-minutes', value], {}, {
      stdout: { write() {} }, stderr: { write() {} }, dependencyFactory: async () => assert.fail('factory called'),
    }), /--timeout-minutes must be an integer from 5 to 30/);
  }
  await assert.rejects(main(['enroll', '--controller-url', 'https://example.test'], {}, {
    stdout: { write() {} }, stderr: { write() {} }, dependencyFactory: async () => assert.fail('factory called'),
  }), /Unknown option/);

  for (const value of ['5', '20', '30']) {
    let timeoutMs;
    await main(['enroll', '--timeout-minutes', value], {}, {
      stdout: { write() {} }, stderr: { write() {} }, dependencyFactory: async () => ({}),
      runEnrollment: async (options) => { timeoutMs = options.timeoutMs; options.onCommand('one-line'); return { id: 'dev_x', status: 'CONNECTED_SSH_ONLY' }; },
      ...runtimeHandoff('dev_x'),
    });
    assert.equal(timeoutMs, Number(value) * 60_000);
  }
});

test('redacts dependency factory failures to fixed stderr with empty stdout', async () => {
  let stdout = '';
  let stderr = '';
  const signalSource = new EventEmitter();
  const exitCode = await main(['enroll'], {}, {
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
    dependencyFactory: async () => {
      throw Object.assign(new Error('ENOENT /Users/private/token-file'), { code: 'ENOENT' });
    },
    signalSource,
  });
  assert.equal(exitCode, 2);
  assert.equal(stdout, '');
  assert.equal(stderr, 'BOOTSTRAP_FAILED\n');
  assert.equal(signalSource.listenerCount('SIGINT'), 0);
  assert.equal(signalSource.listenerCount('SIGTERM'), 0);
});

test('prints only a strictly validated Tailscale consent URL after its stable code', async () => {
  const validUrl = 'https://login.tailscale.com/a/abc_123';
  for (const [details, expectedSuffix] of [
    [validUrl, `TAILSCALE_SERVE_AUTH_REQUIRED\n${validUrl}\n`],
    ['https://evil.example/a/abc', 'TAILSCALE_SERVE_AUTH_REQUIRED\n'],
    ['https://user:pass@login.tailscale.com/a/abc', 'TAILSCALE_SERVE_AUTH_REQUIRED\n'],
    ['https://login.tailscale.com:444/a/abc', 'TAILSCALE_SERVE_AUTH_REQUIRED\n'],
  ]) {
    let stdout = '';
    let stderr = '';
    const error = Object.assign(new Error('TAILSCALE_SERVE_AUTH_REQUIRED'), {
      code: 'TAILSCALE_SERVE_AUTH_REQUIRED',
      details,
    });
    const exitCode = await main(['enroll'], {}, {
      stdout: { write: (value) => { stdout += value; } },
      stderr: { write: (value) => { stderr += value; } },
      dependencyFactory: async () => ({}),
      runEnrollment: async () => { throw error; },
      signalSource: new EventEmitter(),
    });
    assert.equal(exitCode, 2);
    assert.equal(stdout, '');
    assert.equal(stderr, `ENROLLING\n${expectedSuffix}`);
  }
});

test('SIGINT aborts enrollment, waits for rejection, and removes both signal listeners', async () => {
  const signalSource = new EventEmitter();
  let seenSignal;
  let stderr = '';
  const running = main(['enroll'], {}, {
    stdout: { write() {} },
    stderr: { write: (value) => { stderr += value; } },
    dependencyFactory: async () => ({}),
    signalSource,
    runEnrollment: ({ signal }) => {
      seenSignal = signal;
      return new Promise((resolve, reject) => {
        signal.addEventListener('abort', () => reject(Object.assign(new Error('cancel path'), { code: 'BOOTSTRAP_FAILED' })), { once: true });
      });
    },
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(signalSource.listenerCount('SIGINT'), 1);
  assert.equal(signalSource.listenerCount('SIGTERM'), 1);
  signalSource.emit('SIGINT');
  assert.equal(await running, 2);
  assert.equal(seenSignal.aborted, true);
  assert.equal(stderr, 'ENROLLING\nBOOTSTRAP_FAILED\n');
  assert.equal(signalSource.listenerCount('SIGINT'), 0);
  assert.equal(signalSource.listenerCount('SIGTERM'), 0);
});

test('SIGTERM during the final publication barrier is absorbed until CONNECTED completes', async () => {
  const signalSource = new EventEmitter();
  let publicationStarted;
  let releasePublication;
  const atPublication = new Promise((resolve) => { publicationStarted = resolve; });
  const publicationGate = new Promise((resolve) => { releasePublication = resolve; });
  let enrollmentSignal;
  let stderr = '';
  const running = main(['enroll'], {}, {
    stdout: { write() {} },
    stderr: { write: (value) => { stderr += value; } },
    dependencyFactory: async () => ({}),
    signalSource,
    runEnrollment: async ({ signal, onCommitStart }) => {
      enrollmentSignal = signal;
      onCommitStart();
      publicationStarted();
      await publicationGate;
      return { id: 'dev_abc123', status: 'CONNECTED_SSH_ONLY' };
    },
    ...runtimeHandoff('dev_abc123', () => {
      assert.equal(signalSource.listenerCount('SIGINT'), 1);
      assert.equal(signalSource.listenerCount('SIGTERM'), 1);
      signalSource.emit('SIGINT');
      signalSource.emit('SIGTERM');
    }),
  });
  await atPublication;
  signalSource.emit('SIGTERM');
  assert.equal(enrollmentSignal.aborted, false);
  releasePublication();
  const exitCode = await running;
  assert.equal(exitCode, 0);
  assert.equal(stderr, 'ENROLLING\nCONNECTED_SSH_ONLY\nRUNTIME_READY\n');
  assert.equal(signalSource.listenerCount('SIGINT'), 0);
  assert.equal(signalSource.listenerCount('SIGTERM'), 0);
});

test('post-CONNECTED signals are absorbed until runtime handoff settles', async () => {
  const signalSource = new EventEmitter();
  let runtimeStarted;
  let releaseRuntime;
  const atRuntime = new Promise((resolve) => { runtimeStarted = resolve; });
  const runtimeGate = new Promise((resolve) => { releaseRuntime = resolve; });
  let settled = false;
  const running = main(['enroll'], {}, {
    stdout: { write() {} },
    stderr: { write() {} },
    dependencyFactory: async () => ({}),
    signalSource,
    runEnrollment: async () => ({ id: 'dev_abc123', status: 'CONNECTED_SSH_ONLY' }),
    runtimeDependencyFactory: () => ({}),
    ensureRuntime: async () => {
      assert.equal(signalSource.listenerCount('SIGINT'), 1);
      assert.equal(signalSource.listenerCount('SIGTERM'), 1);
      runtimeStarted();
      await runtimeGate;
      return readyState();
    },
  }).finally(() => { settled = true; });

  await atRuntime;
  signalSource.emit('SIGINT');
  signalSource.emit('SIGTERM');
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(settled, false);
  releaseRuntime();
  assert.equal(await running, 0);
  assert.equal(signalSource.listenerCount('SIGINT'), 0);
  assert.equal(signalSource.listenerCount('SIGTERM'), 0);
});

test('runtime handoff failure preserves CONNECTED and never falls back to BOOTSTRAP_FAILED', async () => {
  let stderr = '';
  let factoryCalls = 0;
  const runtimeDependencyFactory = () => { factoryCalls += 1; };
  const exitCode = await main(['enroll'], {}, {
    stdout: { write() {} },
    stderr: { write(value) { stderr += value; } },
    dependencyFactory: async () => ({}),
    signalSource: new EventEmitter(),
    runEnrollment: async () => ({ id: 'dev_abc123', status: 'CONNECTED_SSH_ONLY' }),
    runtimeDependencyFactory,
    ensureRuntime: async ({ dependencyFactory }) => {
      assert.equal(dependencyFactory, runtimeDependencyFactory);
      throw Object.assign(new Error('/Users/private/runtime-cache'), {
        code: 'RUNTIME_DISK_INSUFFICIENT',
      });
    },
  });

  assert.equal(exitCode, 2);
  assert.equal(factoryCalls, 0);
  assert.equal(stderr, 'ENROLLING\nCONNECTED_SSH_ONLY\nRUNTIME_DISK_INSUFFICIENT\n');
  assert.doesNotMatch(stderr, /BOOTSTRAP_FAILED|private/u);
});

test('enrollment result requires safe own id and status before runtime handoff', async () => {
  let getterCalls = 0;
  const getterResult = { id: 'dev_abc123' };
  Object.defineProperty(getterResult, 'status', {
    get() {
      getterCalls += 1;
      return 'CONNECTED_SSH_ONLY';
    },
  });
  const inherited = Object.create({ id: 'dev_abc123', status: 'CONNECTED_SSH_ONLY' });
  const symbolic = { id: 'dev_abc123', status: 'CONNECTED_SSH_ONLY', [Symbol('hostile')]: true };
  const proxied = new Proxy({ id: 'dev_abc123', status: 'CONNECTED_SSH_ONLY' }, {
    getOwnPropertyDescriptor() { throw new Error('proxy trap'); },
  });

  for (const result of [getterResult, inherited, symbolic, proxied]) {
    let stderr = '';
    let ensureCalls = 0;
    const exitCode = await main(['enroll'], {}, {
      stdout: { write() {} },
      stderr: { write(value) { stderr += value; } },
      dependencyFactory: async () => ({}),
      signalSource: new EventEmitter(),
      runEnrollment: async () => result,
      runtimeDependencyFactory: () => assert.fail('runtime dependency factory called'),
      ensureRuntime: async () => { ensureCalls += 1; },
    });
    assert.equal(exitCode, 2);
    assert.equal(stderr, 'ENROLLING\nBOOTSTRAP_FAILED\n');
    assert.equal(ensureCalls, 0);
  }
  assert.equal(getterCalls, 0);
});

test('enrollment rejects hostile thenables without invoking then accessors', async () => {
  let thenReads = 0;
  const thenable = {};
  Object.defineProperty(thenable, 'then', {
    get() {
      thenReads += 1;
      throw new Error('then getter');
    },
  });
  let stderr = '';
  const exitCode = await main(['enroll'], {}, {
    stdout: { write() {} },
    stderr: { write(value) { stderr += value; } },
    dependencyFactory: () => ({}),
    signalSource: new EventEmitter(),
    runEnrollment: () => thenable,
    ...runtimeHandoff(),
  });

  assert.equal(exitCode, 2);
  assert.equal(stderr, 'ENROLLING\nBOOTSTRAP_FAILED\n');
  assert.equal(thenReads, 0);
});

test('hostile runtime handoff hooks stay in the post-CONNECTED runtime error domain', async () => {
  let getterReads = 0;
  let stderr = '';
  const runtime = {
    stdout: { write() {} },
    stderr: { write(value) { stderr += value; } },
    dependencyFactory: async () => ({}),
    signalSource: new EventEmitter(),
    runEnrollment: async () => ({ id: 'dev_abc123', status: 'CONNECTED_SSH_ONLY' }),
    runtimeDependencyFactory: () => assert.fail('runtime dependency factory called'),
  };
  Object.defineProperty(runtime, 'ensureRuntime', {
    get() {
      getterReads += 1;
      return async () => readyState();
    },
  });

  const exitCode = await main(['enroll'], {}, runtime);

  assert.equal(exitCode, 2);
  assert.equal(getterReads, 0);
  assert.equal(stderr, 'ENROLLING\nCONNECTED_SSH_ONLY\nRUNTIME_INPUT_INVALID\n');
  assert.doesNotMatch(stderr, /BOOTSTRAP_FAILED/u);
});

test('inherited runtime handoff hooks are rejected only after transport is connected', async () => {
  let inheritedCalls = 0;
  let stderr = '';
  const runtime = Object.assign(Object.create({
    ensureRuntime() {
      inheritedCalls += 1;
      return readyState();
    },
  }), {
    stdout: { write() {} },
    stderr: { write(value) { stderr += value; } },
    dependencyFactory: async () => ({}),
    signalSource: new EventEmitter(),
    runEnrollment: async () => ({ id: 'dev_abc123', status: 'CONNECTED_SSH_ONLY' }),
    runtimeDependencyFactory: () => assert.fail('runtime dependency factory called'),
  });

  const exitCode = await main(['enroll'], {}, runtime);

  assert.equal(exitCode, 2);
  assert.equal(inheritedCalls, 0);
  assert.equal(stderr, 'ENROLLING\nCONNECTED_SSH_ONLY\nRUNTIME_INPUT_INVALID\n');
});

test('an explicitly undefined runtime hook cannot fall back to production behavior', async () => {
  let stderr = '';
  let factoryCalls = 0;
  const exitCode = await main(['enroll'], {}, {
    stdout: { write() {} },
    stderr: { write(value) { stderr += value; } },
    dependencyFactory: async () => ({}),
    signalSource: new EventEmitter(),
    runEnrollment: async () => ({ id: 'dev_abc123', status: 'CONNECTED_SSH_ONLY' }),
    runtimeDependencyFactory: () => { factoryCalls += 1; },
    ensureRuntime: undefined,
  });

  assert.equal(exitCode, 2);
  assert.equal(factoryCalls, 0);
  assert.equal(stderr, 'ENROLLING\nCONNECTED_SSH_ONLY\nRUNTIME_INPUT_INVALID\n');
});

test('prints help when a help flag follows enroll', () => {
  for (const flag of ['--help', '-h']) {
    const result = run(['enroll', flag], process.env);

    assert.equal(result.status, 0);
    assert.match(result.stdout, /agent-road enroll/);
    assert.equal(result.stderr, '');
  }
});
