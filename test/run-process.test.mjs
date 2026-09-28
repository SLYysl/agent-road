import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import { inspect } from 'node:util';

import { runProcess } from '../src/process/run-process.mjs';

class FakeChild extends EventEmitter {
  constructor() {
    super();
    this.stdin = new EventEmitter();
    this.stdin.endCalls = [];
    this.stdin.end = (value) => {
      this.stdin.endCalls.push(value);
    };
    this.stdout = new EventEmitter();
    this.stderr = new EventEmitter();
    this.killCalls = [];
  }

  kill(signal) {
    this.killCalls.push(signal);
    return true;
  }
}

function fakeSpawner(child, calls) {
  return (command, args, options) => {
    calls.push({ command, args, options });
    return child;
  };
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

test('preserves literal argv and invokes spawn without a shell', async () => {
  const child = new FakeChild();
  const calls = [];
  const operation = runProcess('/usr/bin/example', ['literal;not-shell'], {
    spawnProcess: fakeSpawner(child, calls),
    env: { PATH: '/usr/bin' },
  });

  assert.deepEqual(calls, [{
    command: '/usr/bin/example',
    args: ['literal;not-shell'],
    options: {
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: '/usr/bin' },
    },
  }]);
  child.stdout.emit('data', Buffer.from('ok\n'));
  child.emit('close', 0, null);

  assert.deepEqual(await operation, {
    command: '/usr/bin/example',
    args: ['literal;not-shell'],
    exitCode: 0,
    signal: null,
    stdout: 'ok\n',
    stderr: '',
  });
});

test('writes one snapshotted ASCII stdin value after every listener is installed', async () => {
  const child = new FakeChild();
  const calls = [];
  child.stdin.end = (value) => {
    assert.equal(child.listenerCount('error'), 1);
    assert.equal(child.stdin.listenerCount('error'), 1);
    assert.equal(child.stdout.listenerCount('error'), 1);
    assert.equal(child.stderr.listenerCount('error'), 1);
    child.stdin.endCalls.push(value);
  };
  const options = {
    spawnProcess: fakeSpawner(child, calls),
    stdinText: 'Write-Output ok\r\n',
    maxOutputBytes: 1,
  };
  const operation = runProcess('/usr/bin/example', [], options);
  options.stdinText = 'mutated-secret';

  child.stdout.emit('data', Buffer.from('x'));
  child.emit('close', 0, null);

  const result = await operation;
  assert.equal(calls[0].options.stdio[0], 'pipe');
  assert.deepEqual(child.stdin.endCalls, ['Write-Output ok\r\n']);
  assert.deepEqual(result, {
    command: '/usr/bin/example',
    args: [],
    exitCode: 0,
    signal: null,
    stdout: 'x',
    stderr: '',
  });
});

test('rejects invalid, accessor, and unknown stdin options before spawning', async () => {
  let getterCalls = 0;
  const accessor = {};
  Object.defineProperty(accessor, 'stdinText', {
    enumerable: true,
    get() {
      getterCalls += 1;
      throw new Error('stdin getter secret');
    },
  });
  const invalidOptions = [
    { stdinText: '' },
    { stdinText: 'nul\0byte' },
    { stdinText: '你好' },
    { stdinText: Buffer.from('buffer') },
    { stdinText: 'x'.repeat((64 * 1024) + 1) },
    { unknown: true },
    accessor,
  ];

  for (const options of invalidOptions) {
    const child = new FakeChild();
    let spawnCalls = 0;
    const invocationOptions = {};
    Object.defineProperties(invocationOptions, Object.getOwnPropertyDescriptors(options));
    Object.defineProperty(invocationOptions, 'spawnProcess', {
      configurable: true,
      enumerable: true,
      value() {
        spawnCalls += 1;
        queueMicrotask(() => child.emit('close', 0, null));
        return child;
      },
    });
    await assert.rejects(
      runProcess('/usr/bin/example', [], invocationOptions),
      (error) => error instanceof TypeError && !inspect(error, { depth: null }).includes('secret'),
    );
    assert.equal(spawnCalls, 0);
  }
  assert.equal(getterCalls, 0);
});

test('maps synchronous stdin end and emitted EPIPE failures to one redacted code', async () => {
  const syncChild = new FakeChild();
  syncChild.stdin.end = () => { throw new Error('sync stdin secret'); };
  const syncOperation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(syncChild, []),
    stdinText: 'exit 0\r\n',
  });
  queueMicrotask(() => syncChild.emit('close', null, 'SIGTERM'));
  await assert.rejects(syncOperation, (error) => (
    error.code === 'PROCESS_STDIN_FAILED'
    && error.message === 'process stdin failed'
    && !inspect(error, { depth: null }).includes('sync stdin secret')
  ));
  assert.deepEqual(syncChild.killCalls, ['SIGTERM']);

  const emittedChild = new FakeChild();
  const emittedOperation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(emittedChild, []),
    stdinText: 'exit 0\r\n',
  });
  let unhandled;
  try {
    emittedChild.stdin.emit('error', Object.assign(new Error('EPIPE stdin secret'), { code: 'EPIPE' }));
  } catch (error) {
    unhandled = error;
    emittedChild.emit('close', 0, null);
  }
  assert.equal(unhandled, undefined);
  await assert.rejects(emittedOperation, (error) => (
    error.code === 'PROCESS_STDIN_FAILED'
    && error.message === 'process stdin failed'
    && !inspect(error, { depth: null }).includes('EPIPE stdin secret')
  ));
  assert.deepEqual(emittedChild.killCalls, ['SIGTERM']);
});

test('keeps timeout primary while consuming late stdin errors without leaking input', async () => {
  const child = new FakeChild();
  const secretInput = 'Write-Output hidden-stdin-secret\r\n';
  const operation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(child, []),
    stdinText: secretInput,
    timeoutMs: 5,
  });
  const rejection = assert.rejects(operation, (error) => (
    error.code === 'PROCESS_TIMEOUT'
    && !inspect(error, { depth: null }).includes(secretInput)
  ));

  await delay(20);
  const stdinErrorListeners = child.stdin.listenerCount('error');
  if (stdinErrorListeners > 0) child.stdin.emit('error', new Error('late stdin secret'));
  child.emit('close', null, 'SIGTERM');
  await rejection;
  assert.equal(stdinErrorListeners, 1);
  assert.deepEqual(child.killCalls, ['SIGTERM']);
});

test('accepts exactly 64 KiB of ASCII stdin without charging the output cap', async () => {
  const child = new FakeChild();
  const stdinText = 'x'.repeat(64 * 1024);
  const operation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(child, []),
    stdinText,
    maxOutputBytes: 1,
  });
  child.stdout.emit('data', Buffer.from('y'));
  child.emit('close', 0, null);
  const result = await operation;
  assert.equal(result.stdout, 'y');
  assert.equal(child.stdin.endCalls.length, 1);
  assert.equal(child.stdin.endCalls[0], stdinText);
});

test('captures stdout and stderr split across Buffer chunks', async () => {
  const child = new FakeChild();
  const operation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(child, []),
  });

  child.stdout.emit('data', Buffer.from('hel'));
  child.stderr.emit('data', Buffer.from('warn'));
  child.stdout.emit('data', Buffer.from('lo'));
  child.stderr.emit('data', Buffer.from('ing'));
  child.emit('close', 0, null);

  const result = await operation;
  assert.equal(result.stdout, 'hello');
  assert.equal(result.stderr, 'warning');
});

test('observes stdout and stderr chunks while the process is still running', async () => {
  const child = new FakeChild();
  const observed = [];
  const operation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(child, []),
    onOutput(stream, chunk) {
      observed.push({ stream, chunk: Buffer.from(chunk).toString('utf8') });
    },
  });

  child.stdout.emit('data', Buffer.from('consent-'));
  child.stderr.emit('data', Buffer.from('url'));
  assert.deepEqual(observed, [
    { stream: 'stdout', chunk: 'consent-' },
    { stream: 'stderr', chunk: 'url' },
  ]);
  child.emit('close', 0, null);
  await operation;
});

test('returns nonzero exit codes and signals as process data', async () => {
  const nonzeroChild = new FakeChild();
  const nonzero = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(nonzeroChild, []),
  });
  nonzeroChild.emit('close', 7, null);
  assert.equal((await nonzero).exitCode, 7);

  const signalChild = new FakeChild();
  const signalled = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(signalChild, []),
  });
  signalChild.emit('close', null, 'SIGTERM');
  assert.deepEqual(await signalled, {
    command: '/usr/bin/example',
    args: [],
    exitCode: null,
    signal: 'SIGTERM',
    stdout: '',
    stderr: '',
  });
});

test('rejects synchronous and emitted spawn failures', async () => {
  const spawnFailure = new Error('spawn unavailable');
  await assert.rejects(
    runProcess('/usr/bin/example', [], { spawnProcess: () => { throw spawnFailure; } }),
    (error) => error.code === 'PROCESS_SPAWN_FAILED' && error.cause === undefined,
  );

  const child = new FakeChild();
  const emittedFailure = new Error('spawn emitted failure');
  const operation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(child, []),
  });
  child.emit('error', emittedFailure);
  await assert.rejects(operation, (error) => error.code === 'PROCESS_SPAWN_FAILED' && error.cause === undefined);
});

test('terminates once and rejects with PROCESS_TIMEOUT', async () => {
  const child = new FakeChild();
  const operation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(child, []),
    timeoutMs: 5,
  });
  const rejection = assert.rejects(operation, (error) => error.code === 'PROCESS_TIMEOUT');

  await delay(20);
  assert.deepEqual(child.killCalls, ['SIGTERM']);
  child.emit('close', null, 'SIGTERM');

  await rejection;
});

test('enforces one total raw-byte output cap across stdout and stderr', async () => {
  const child = new FakeChild();
  const operation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(child, []),
    maxOutputBytes: 3,
  });

  child.stdout.emit('data', Buffer.from('ab'));
  child.stderr.emit('data', Buffer.from('cd'));
  child.stdout.emit('data', Buffer.from('top-secret-output'));
  assert.deepEqual(child.killCalls, ['SIGTERM']);
  child.emit('close', null, 'SIGTERM');

  await assert.rejects(operation, (error) => (
    error.code === 'PROCESS_OUTPUT_LIMIT'
    && !error.message.includes('top-secret-output')
  ));
});

test('validates process input and environment mappings', async () => {
  const invalidCalls = [
    () => runProcess('', []),
    () => runProcess('/usr/bin/example', ['ok', 1]),
    () => runProcess('/usr/bin/example', [], { timeoutMs: 0 }),
    () => runProcess('/usr/bin/example', [], { maxOutputBytes: Number.MAX_SAFE_INTEGER + 1 }),
    () => runProcess('/usr/bin/example', [], { onOutput: true }),
    () => runProcess('/usr/bin/example', [], { env: { PATH: 1 } }),
    () => runProcess('/usr/bin/example', [], { env: Object.create({ PATH: '/usr/bin' }) }),
  ];

  for (const invoke of invalidCalls) {
    await assert.rejects(invoke());
  }
});

test('snapshots argv and environment before process events can observe mutations', async () => {
  const child = new FakeChild();
  const calls = [];
  const args = ['literal;not-shell'];
  const env = { PATH: '/usr/bin', API_TOKEN: 'original-secret' };
  const operation = runProcess('/usr/bin/example', args, {
    spawnProcess: fakeSpawner(child, calls),
    env,
  });
  args[0] = 'changed';
  env.API_TOKEN = 'changed-secret';

  assert.deepEqual(calls[0].args, ['literal;not-shell']);
  assert.equal(calls[0].options.env.API_TOKEN, 'original-secret');
  child.emit('close', 0, null);

  assert.deepEqual((await operation).args, ['literal;not-shell']);
});

test('keeps the primary timeout error through an error-close race without unhandled events', async () => {
  const child = new FakeChild();
  const operation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(child, []),
    timeoutMs: 5,
  });
  const rejection = assert.rejects(operation, (error) => (
    error.code === 'PROCESS_TIMEOUT'
    && !error.message.includes('secret-value')
  ));

  await delay(20);
  child.emit('error', new Error('late failure containing secret-value'));
  child.emit('close', null, 'SIGTERM');

  await rejection;
  assert.deepEqual(child.killCalls, ['SIGTERM']);
});

test('rejects a timeout promptly when SIGTERM throws and no close arrives', async () => {
  const child = new FakeChild();
  child.kill = (signal) => {
    child.killCalls.push(signal);
    throw new Error('kill failure containing secret-value');
  };
  const operation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(child, []),
    timeoutMs: 5,
  });

  await assert.rejects(Promise.race([
    operation,
    delay(30).then(() => { throw new Error('runner remained pending'); }),
  ]), (error) => (
    error.code === 'PROCESS_TIMEOUT'
    && !error.message.includes('secret-value')
  ));
  assert.deepEqual(child.killCalls, ['SIGTERM']);
  child.emit('error', new Error('late failure must not be unhandled'));
});

test('rejects an output limit promptly when SIGTERM throws and no close arrives', async () => {
  const child = new FakeChild();
  child.kill = (signal) => {
    child.killCalls.push(signal);
    throw new Error('kill failure containing secret-value');
  };
  const operation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(child, []),
    maxOutputBytes: 1,
  });
  child.stdout.emit('data', Buffer.from('too much'));

  await assert.rejects(Promise.race([
    operation,
    delay(30).then(() => { throw new Error('runner remained pending'); }),
  ]), (error) => (
    error.code === 'PROCESS_OUTPUT_LIMIT'
    && !error.message.includes('secret-value')
  ));
  assert.deepEqual(child.killCalls, ['SIGTERM']);
  child.emit('error', new Error('late failure must not be unhandled'));
});

test('rejects NUL-bearing command, argv, and environment without spawning', async () => {
  const calls = [];
  const spawnProcess = fakeSpawner(new FakeChild(), calls);
  const nulKeyEnv = {};
  Object.defineProperty(nulKeyEnv, 'API\0TOKEN', { enumerable: true, value: 'safe' });

  for (const invoke of [
    () => runProcess('/usr/bin/\0example', [], { spawnProcess }),
    () => runProcess('/usr/bin/example', ['literal\0argument'], { spawnProcess }),
    () => runProcess('/usr/bin/example', [], { spawnProcess, env: nulKeyEnv }),
    () => runProcess('/usr/bin/example', [], { spawnProcess, env: { API_TOKEN: 'secret\0value' } }),
  ]) {
    await assert.rejects(invoke(), (error) => (
      error instanceof TypeError
      && !error.message.includes('secret')
      && !error.message.includes('\0')
    ));
  }
  assert.deepEqual(calls, []);
});

test('rejects accessor environments without invoking secret-bearing getters', async () => {
  let reads = 0;
  const env = { PATH: '/usr/bin' };
  Object.defineProperty(env, 'API_TOKEN', {
    enumerable: true,
    get() {
      reads += 1;
      throw new Error('getter secret must not escape');
    },
  });

  await assert.rejects(
    runProcess('/usr/bin/example', [], { spawnProcess: () => new FakeChild(), env }),
    (error) => error instanceof TypeError && !error.message.includes('getter secret'),
  );
  assert.equal(reads, 0);
});

test('sanitizes synchronous and emitted spawn errors', async () => {
  const syncSecret = new Error('sync secret with /usr/bin/example and literal;not-shell');
  await assert.rejects(
    runProcess('/usr/bin/example', ['literal;not-shell'], {
      env: { API_TOKEN: 'secret-value' },
      spawnProcess: () => { throw syncSecret; },
    }),
    (error) => (
      error.code === 'PROCESS_SPAWN_FAILED'
      && error.message === 'process spawn failed'
      && !error.message.includes('secret-value')
      && !error.message.includes('literal;not-shell')
      && !inspect(error, { depth: null }).includes(syncSecret.message)
    ),
  );

  const child = new FakeChild();
  const operation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(child, []),
  });
  child.emit('error', new Error('emitted secret-value'));
  await assert.rejects(operation, (error) => (
    error.code === 'PROCESS_SPAWN_FAILED'
    && error.message === 'process spawn failed'
    && !error.message.includes('secret-value')
    && !inspect(error, { depth: null }).includes('emitted secret-value')
  ));
});

test('isolates result args from mutations made by an injected spawner', async () => {
  const child = new FakeChild();
  const originalArgs = ['literal;not-shell'];
  const originalEnv = { PATH: '/usr/bin', API_TOKEN: 'original-secret' };
  const operation = runProcess('/usr/bin/example', originalArgs, {
    env: originalEnv,
    spawnProcess: (command, args, options) => {
      assert.equal(command, '/usr/bin/example');
      args[0] = 'spawner-mutated';
      options.env.API_TOKEN = 'spawner-mutated-secret';
      return child;
    },
  });
  child.emit('close', 0, null);

  assert.deepEqual((await operation).args, ['literal;not-shell']);
  assert.deepEqual(originalArgs, ['literal;not-shell']);
  assert.deepEqual(originalEnv, { PATH: '/usr/bin', API_TOKEN: 'original-secret' });
});

test('escalates a close-free timeout from SIGTERM to SIGKILL after the grace period', async () => {
  const child = new FakeChild();
  const operation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(child, []),
    timeoutMs: 5,
  });

  await assert.rejects(operation, (error) => error.code === 'PROCESS_TIMEOUT');
  assert.deepEqual(child.killCalls, ['SIGTERM']);
  await delay(1_100);
  assert.deepEqual(child.killCalls, ['SIGTERM', 'SIGKILL']);
  assert.equal(child.listenerCount('close'), 1);
  assert.equal(child.listenerCount('error'), 1);
  assert.equal(child.stdout.listenerCount('data'), 0);
  assert.equal(child.stdout.listenerCount('error'), 1);
  assert.equal(child.stderr.listenerCount('data'), 0);
  assert.equal(child.stderr.listenerCount('error'), 1);
  child.emit('error', new Error('late-child-secret'));
  child.stdout.emit('error', new Error('late-stdout-secret'));
  child.stderr.emit('error', new Error('late-stderr-secret'));
});

test('clears the SIGKILL escalation when a timed-out child closes during grace', async () => {
  const child = new FakeChild();
  const operation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(child, []),
    timeoutMs: 5,
  });
  const rejection = assert.rejects(operation, (error) => error.code === 'PROCESS_TIMEOUT');

  await delay(20);
  child.emit('close', null, 'SIGTERM');
  await rejection;
  await delay(1_100);
  assert.deepEqual(child.killCalls, ['SIGTERM']);
  assert.equal(child.listenerCount('close'), 0);
  assert.equal(child.listenerCount('error'), 0);
  assert.equal(child.stdout.listenerCount('data'), 0);
  assert.equal(child.stdout.listenerCount('error'), 0);
  assert.equal(child.stderr.listenerCount('data'), 0);
  assert.equal(child.stderr.listenerCount('error'), 0);
});

test('redacts stdout and stderr errors before close and preserves a fixed stream error', async () => {
  const child = new FakeChild();
  const operation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(child, []),
  });
  const rejection = assert.rejects(operation, (error) => (
    error.code === 'PROCESS_STREAM_FAILED'
    && error.message === 'process stream failed'
    && !inspect(error, { depth: null }).includes('stdout-secret')
    && !inspect(error, { depth: null }).includes('stderr-secret')
  ));

  child.stdout.emit('error', new Error('stdout-secret'));
  child.stderr.emit('error', new Error('stderr-secret'));
  child.emit('close', null, 'SIGTERM');

  await rejection;
  assert.deepEqual(child.killCalls, ['SIGTERM']);
});

test('consumes secret stream errors after timeout and output-limit settlement', async () => {
  const timeoutChild = new FakeChild();
  const timeoutOperation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(timeoutChild, []),
    timeoutMs: 5,
  });
  const timeoutRejection = assert.rejects(timeoutOperation, (error) => (
    error.code === 'PROCESS_TIMEOUT'
    && !inspect(error, { depth: null }).includes('late-timeout-secret')
  ));

  await delay(20);
  timeoutChild.stdout.emit('error', new Error('late-timeout-secret-stdout'));
  timeoutChild.stderr.emit('error', new Error('late-timeout-secret-stderr'));
  timeoutChild.emit('close', null, 'SIGTERM');
  await timeoutRejection;

  const limitChild = new FakeChild();
  const limitOperation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(limitChild, []),
    maxOutputBytes: 1,
  });
  const limitRejection = assert.rejects(limitOperation, (error) => (
    error.code === 'PROCESS_OUTPUT_LIMIT'
    && !inspect(error, { depth: null }).includes('late-limit-secret')
  ));

  limitChild.stdout.emit('data', Buffer.from('too much'));
  limitChild.stdout.emit('error', new Error('late-limit-secret-stdout'));
  limitChild.stderr.emit('error', new Error('late-limit-secret-stderr'));
  limitChild.emit('close', null, 'SIGTERM');
  await limitRejection;
});

test('keeps primary timeout and output-limit failures through re-entrant SIGTERM errors', async () => {
  const createReentrantChild = () => {
    const child = new FakeChild();
    child.kill = (signal) => {
      child.killCalls.push(signal);
      if (signal === 'SIGTERM') {
        child.emit('error', new Error('re-entrant-secret'));
      }
      return true;
    };
    return child;
  };

  const timeoutChild = createReentrantChild();
  const timeoutOperation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(timeoutChild, []),
    timeoutMs: 5,
  });
  const limitChild = createReentrantChild();
  const limitOperation = runProcess('/usr/bin/example', [], {
    spawnProcess: fakeSpawner(limitChild, []),
    maxOutputBytes: 1,
  });
  const timeoutRejection = assert.rejects(timeoutOperation, (error) => (
    error.code === 'PROCESS_TIMEOUT'
    && !inspect(error, { depth: null }).includes('re-entrant-secret')
  ));
  const limitRejection = assert.rejects(limitOperation, (error) => (
    error.code === 'PROCESS_OUTPUT_LIMIT'
    && !inspect(error, { depth: null }).includes('re-entrant-secret')
  ));

  limitChild.stdout.emit('data', Buffer.from('too much'));
  await Promise.all([timeoutRejection, limitRejection]);
  await delay(1_100);

  for (const child of [timeoutChild, limitChild]) {
    assert.deepEqual(child.killCalls, ['SIGTERM', 'SIGKILL']);
    assert.equal(child.listenerCount('close'), 1);
    assert.equal(child.listenerCount('error'), 1);
    assert.equal(child.stdout.listenerCount('error'), 1);
    assert.equal(child.stderr.listenerCount('error'), 1);
  }
});
