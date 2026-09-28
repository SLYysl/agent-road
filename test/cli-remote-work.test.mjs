import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import * as cli from '../src/cli.mjs';
import { SshIdentityStore } from '../src/identity/ssh-identity-store.mjs';
import { DeviceRegistry } from '../src/storage/device-registry.mjs';

const EXEC_RESULT = Object.freeze({
  schemaVersion: 1,
  operation: 'exec',
  deviceId: 'dev_abc123',
  address: '100.64.0.1',
  exitCode: 0,
  stdout: 'done\n',
  stderr: '',
  startedAt: '2026-07-28T00:00:00.000Z',
  finishedAt: '2026-07-28T00:00:01.000Z',
});
const PUT_RESULT = Object.freeze({
  schemaVersion: 1,
  operation: 'put',
  deviceId: 'dev_abc123',
  address: '100.64.0.1',
  bytes: 4,
  sha256: 'A'.repeat(64),
  destination: 'D:\\work\\a.txt',
  startedAt: '2026-07-28T00:00:00.000Z',
  finishedAt: '2026-07-28T00:00:01.000Z',
});
const GET_RESULT = Object.freeze({
  schemaVersion: 1,
  operation: 'get',
  deviceId: 'dev_abc123',
  address: '100.64.0.1',
  bytes: 4,
  sha256: 'B'.repeat(64),
  source: 'D:\\work\\a.txt',
  destination: '/tmp/a.txt',
  startedAt: '2026-07-28T00:00:00.000Z',
  finishedAt: '2026-07-28T00:00:01.000Z',
});

function captureIo() {
  const stdoutWrites = [];
  const stderrWrites = [];
  return {
    stdout: { write(value) { stdoutWrites.push(value); } },
    stderr: { write(value) { stderrWrites.push(value); } },
    stdoutValue: () => stdoutWrites.join(''),
    stderrValue: () => stderrWrites.join(''),
    stdoutWrites,
    stderrWrites,
  };
}

function fixture() {
  const target = Object.freeze({ marker: 'target' });
  const registry = {
    marker: 'registry',
    async get(deviceId) {
      assert.equal(this, registry);
      return `registry:${deviceId}`;
    },
  };
  const sshIdentity = {
    marker: 'identity',
    async getExisting(deviceId) {
      assert.equal(this, sshIdentity);
      return `identity:${deviceId}`;
    },
  };
  Object.freeze(registry);
  Object.freeze(sshIdentity);
  const knownHostsPath = () => '/state/known-hosts/dev_abc123';
  const runProcess = async () => assert.fail('runProcess called');
  const clock = () => new Date('2026-07-28T00:00:00.000Z');
  const operationId = () => 'a'.repeat(32);
  const factoryValue = Object.freeze({
    registry,
    sshIdentity,
    knownHostsPath,
    runProcess,
    clock,
    operationId,
  });
  const operationDependencies = Object.freeze({ runProcess, clock, operationId });
  return {
    target,
    factoryValue,
    knownHostsPath,
    operationDependencies,
  };
}

function successfulRuntime({ operationName, result, inspectOperation }) {
  const values = fixture();
  let factoryCalls = 0;
  let targetCalls = 0;
  let operationCalls = 0;
  return {
    values,
    counts: () => ({ factoryCalls, targetCalls, operationCalls }),
    runtime: {
      dependencyFactory: async () => assert.fail('enrollment dependency factory called'),
      createRemoteDependencies: async () => {
        factoryCalls += 1;
        return values.factoryValue;
      },
      loadRemoteTarget: async (deviceId, dependencies) => {
        targetCalls += 1;
        assert.equal(deviceId, 'dev_abc123');
        assert.deepEqual(Object.keys(dependencies), ['registry', 'sshIdentity', 'knownHostsPath']);
        assert.equal(Object.getPrototypeOf(dependencies.registry), null);
        assert.equal(Object.getPrototypeOf(dependencies.sshIdentity), null);
        assert.equal(Object.isFrozen(dependencies.registry), true);
        assert.equal(Object.isFrozen(dependencies.sshIdentity), true);
        assert.equal(await dependencies.registry.get(deviceId), `registry:${deviceId}`);
        assert.equal(
          await dependencies.sshIdentity.getExisting(deviceId),
          `identity:${deviceId}`,
        );
        assert.equal(dependencies.knownHostsPath(deviceId), values.knownHostsPath(deviceId));
        return values.target;
      },
      [operationName]: async (input) => {
        operationCalls += 1;
        inspectOperation(input, values);
        return result;
      },
    },
  };
}

test('createRemoteDependencies builds and freezes only the existing remote-work dependencies', () => {
  const directory = mkdtempSync(join(tmpdir(), 'agent-road-cli-'));
  try {
    assert.equal(typeof cli.createRemoteDependencies, 'function');
    const dependencies = cli.createRemoteDependencies({ AGENT_ROAD_HOME: directory });
    assert.equal(Object.isFrozen(dependencies), true);
    assert.deepEqual(Object.keys(dependencies).sort(), [
      'clock',
      'knownHostsPath',
      'operationId',
      'registry',
      'runProcess',
      'sshIdentity',
    ]);
    assert.equal(dependencies.registry instanceof DeviceRegistry, true);
    assert.equal(dependencies.sshIdentity instanceof SshIdentityStore, true);
    assert.equal(dependencies.knownHostsPath('dev_abc123'), join(directory, 'known-hosts', 'agent-road-known-hosts-dev_abc123'));
    assert.equal(typeof dependencies.runProcess, 'function');
    assert.equal(dependencies.clock() instanceof Date, true);
    assert.match(dependencies.operationId(), /^[a-f0-9]{32}$/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('exec loads one target, uses exact dependencies and the default timeout, then writes one JSON line', async () => {
  const io = captureIo();
  const setup = successfulRuntime({
    operationName: 'executeRemoteScript',
    result: EXEC_RESULT,
    inspectOperation(input, values) {
      assert.deepEqual(input, {
        target: values.target,
        scriptPath: '/tmp/task.ps1',
        timeoutMs: 300_000,
        dependencies: values.operationDependencies,
      });
    },
  });
  const exitCode = await cli.main(['exec', 'dev_abc123', '--script', '/tmp/task.ps1'], {}, {
    ...setup.runtime,
    ...io,
  });

  assert.equal(exitCode, 0);
  assert.deepEqual(setup.counts(), { factoryCalls: 1, targetCalls: 1, operationCalls: 1 });
  assert.deepEqual(io.stdoutWrites, [`${JSON.stringify(EXEC_RESULT)}\n`]);
  assert.equal(io.stderrValue(), '');
});

test('exec converts an explicit timeout and maps a completed remote nonzero exit to CLI 1', async () => {
  const io = captureIo();
  const result = { ...EXEC_RESULT, exitCode: 7 };
  const setup = successfulRuntime({
    operationName: 'executeRemoteScript',
    result,
    inspectOperation(input, values) {
      assert.deepEqual(input, {
        target: values.target,
        scriptPath: '/tmp/task.ps1',
        timeoutMs: 1_800_000,
        dependencies: values.operationDependencies,
      });
    },
  });
  const exitCode = await cli.main([
    'exec',
    'dev_abc123',
    '--script',
    '/tmp/task.ps1',
    '--timeout-seconds',
    '1800',
  ], {}, { ...setup.runtime, ...io });

  assert.equal(exitCode, 1);
  assert.deepEqual(JSON.parse(io.stdoutValue()), result);
  assert.equal(io.stderrValue(), '');
});

test('put maps positionals and default overwrite false exactly', async () => {
  const io = captureIo();
  const setup = successfulRuntime({
    operationName: 'putRemoteFile',
    result: PUT_RESULT,
    inspectOperation(input, values) {
      assert.deepEqual(input, {
        target: values.target,
        localPath: '/tmp/a.txt',
        remotePath: 'D:\\work\\a.txt',
        overwrite: false,
        dependencies: values.operationDependencies,
      });
    },
  });
  const exitCode = await cli.main([
    'put',
    'dev_abc123',
    '/tmp/a.txt',
    'D:\\work\\a.txt',
  ], {}, { ...setup.runtime, ...io });

  assert.equal(exitCode, 0);
  assert.deepEqual(setup.counts(), { factoryCalls: 1, targetCalls: 1, operationCalls: 1 });
  assert.deepEqual(io.stdoutWrites, [`${JSON.stringify(PUT_RESULT)}\n`]);
  assert.equal(io.stderrValue(), '');
});

test('get maps positionals and overwrite true exactly', async () => {
  const io = captureIo();
  const setup = successfulRuntime({
    operationName: 'getRemoteFile',
    result: GET_RESULT,
    inspectOperation(input, values) {
      assert.deepEqual(input, {
        target: values.target,
        remotePath: 'D:\\work\\a.txt',
        localPath: '/tmp/a.txt',
        overwrite: true,
        dependencies: values.operationDependencies,
      });
    },
  });
  const exitCode = await cli.main([
    'get',
    'dev_abc123',
    'D:\\work\\a.txt',
    '/tmp/a.txt',
    '--overwrite',
  ], {}, { ...setup.runtime, ...io });

  assert.equal(exitCode, 0);
  assert.deepEqual(setup.counts(), { factoryCalls: 1, targetCalls: 1, operationCalls: 1 });
  assert.deepEqual(io.stdoutWrites, [`${JSON.stringify(GET_RESULT)}\n`]);
  assert.equal(io.stderrValue(), '');
});

test('remote commands reject malformed positionals, flags, duplicates and timeout values before dependencies', async () => {
  const cases = [
    ['exec'],
    ['exec', 'dev_abc123'],
    ['exec', 'dev_abc123', 'extra', '--script', '/tmp/task.ps1'],
    ['exec', 'dev_abc123', '--script', '/tmp/a.ps1', '--script', '/tmp/b.ps1'],
    ['exec', 'dev_abc123', '--script', '/tmp/a.ps1', '--timeout-seconds', '1', '--timeout-seconds', '2'],
    ['exec', 'dev_abc123', '--script', '/tmp/a.ps1', '--unknown'],
    ['exec', 'dev_abc123', '--script', '/tmp/a.ps1', '--timeout-seconds', '0'],
    ['exec', 'dev_abc123', '--script', '/tmp/a.ps1', '--timeout-seconds', '1801'],
    ['exec', 'dev_abc123', '--script', '/tmp/a.ps1', '--timeout-seconds', '1.5'],
    ['exec', 'dev_abc123', '--script', '/tmp/a.ps1', '--timeout-seconds', '01'],
    ['put', 'dev_abc123', '/tmp/a.txt'],
    ['put', 'dev_abc123', '/tmp/a.txt', 'D:\\a.txt', 'extra'],
    ['put', 'dev_abc123', '/tmp/a.txt', 'D:\\a.txt', '--overwrite', '--overwrite'],
    ['put', 'dev_abc123', '/tmp/a.txt', 'D:\\a.txt', '--unknown'],
    ['get', 'dev_abc123', 'D:\\a.txt'],
    ['get', 'dev_abc123', 'D:\\a.txt', '/tmp/a.txt', 'extra'],
    ['get', 'dev_abc123', 'D:\\a.txt', '/tmp/a.txt', '--overwrite', '--overwrite'],
    ['get', 'dev_abc123', 'D:\\a.txt', '/tmp/a.txt', '--unknown'],
  ];

  for (const args of cases) {
    const io = captureIo();
    let factoryCalls = 0;
    const exitCode = await cli.main(args, {}, {
      ...io,
      createRemoteDependencies: async () => {
        factoryCalls += 1;
        return fixture().factoryValue;
      },
    });
    assert.equal(exitCode, 2, args.join(' '));
    assert.equal(factoryCalls, 0, args.join(' '));
    assert.equal(io.stdoutValue(), '', args.join(' '));
    assert.equal(io.stderrValue(), 'REMOTE_INPUT_INVALID\n', args.join(' '));
  }
});

test('redacts factory, target and operation failures to stable codes with no stdout', async () => {
  const failures = [
    {
      expected: 'REMOTE_INPUT_INVALID',
      runtime: {
        createRemoteDependencies: async () => {
          throw Object.assign(new Error('/Users/private/key leaked'), { code: 'ENOENT', path: '/Users/private/key' });
        },
      },
    },
    {
      expected: 'DEVICE_NOT_FOUND',
      runtime: {
        createRemoteDependencies: async () => fixture().factoryValue,
        loadRemoteTarget: async () => {
          throw Object.assign(new Error('private registry data'), { code: 'DEVICE_NOT_FOUND' });
        },
      },
    },
    {
      expected: 'FILE_TRANSFER_FAILED',
      runtime: {
        createRemoteDependencies: async () => fixture().factoryValue,
        loadRemoteTarget: async () => fixture().target,
        putRemoteFile: async () => {
          throw Object.assign(new Error('/private/source leaked'), { code: 'FILE_TRANSFER_FAILED' });
        },
      },
    },
  ];

  for (const { runtime, expected } of failures) {
    const io = captureIo();
    const exitCode = await cli.main([
      'put',
      'dev_abc123',
      '/tmp/a.txt',
      'D:\\work\\a.txt',
    ], {}, { ...runtime, ...io });
    assert.equal(exitCode, 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), `${expected}\n`);
  }
});

test('preserves a valid stable primary and cleanup code chain in descriptor order', async () => {
  const io = captureIo();
  const error = new Error('private transport detail');
  Object.defineProperties(error, {
    primaryCode: { value: 'REMOTE_EXECUTION_UNCERTAIN:REMOTE_CLEANUP_UNCERTAIN', enumerable: true },
    code: { value: 'LOCAL_CLEANUP_FAILED', enumerable: true },
  });
  const exitCode = await cli.main(['exec', 'dev_abc123', '--script', '/tmp/a.ps1'], {}, {
    ...io,
    createRemoteDependencies: async () => fixture().factoryValue,
    loadRemoteTarget: async () => fixture().target,
    executeRemoteScript: async () => { throw error; },
  });

  assert.equal(exitCode, 2);
  assert.equal(io.stdoutValue(), '');
  assert.equal(io.stderrValue(), 'REMOTE_EXECUTION_UNCERTAIN:REMOTE_CLEANUP_UNCERTAIN:LOCAL_CLEANUP_FAILED\n');
});

test('rejects unknown composite segments and never reads hostile getters, proxies or messages', async () => {
  let getterReads = 0;
  let proxyTraps = 0;
  const getterError = new Error('DEVICE_NOT_FOUND');
  Object.defineProperty(getterError, 'code', {
    get() {
      getterReads += 1;
      throw new Error('getter leaked');
    },
  });
  const proxyError = new Proxy(new Error('FILE_TRANSFER_FAILED'), {
    getOwnPropertyDescriptor() {
      proxyTraps += 1;
      throw new Error('proxy trap leaked');
    },
  });
  const cases = [
    getterError,
    proxyError,
    Object.assign(new Error('DEVICE_NOT_READY'), { path: '/private/path', args: ['secret'] }),
    Object.assign(new Error('private'), { code: 'FILE_TRANSFER_FAILED:NOT_PUBLIC' }),
  ];

  for (const failure of cases) {
    const io = captureIo();
    const exitCode = await cli.main(['exec', 'dev_abc123', '--script', '/tmp/a.ps1'], {}, {
      ...io,
      createRemoteDependencies: async () => fixture().factoryValue,
      loadRemoteTarget: async () => fixture().target,
      executeRemoteScript: async () => { throw failure; },
    });
    assert.equal(exitCode, 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), 'REMOTE_INPUT_INVALID\n');
  }
  assert.equal(getterReads, 0);
  assert.equal(proxyTraps, 0);
});

test('serialization and stdout write failures are redacted without a partial JSON object', async () => {
  for (const { result, stdout } of [
    { result: { ...EXEC_RESULT, unsafe: 1n }, stdout: { write: () => assert.fail('stdout called') } },
    { result: EXEC_RESULT, stdout: { write: () => { throw new Error('stdout sink path leaked'); } } },
  ]) {
    let stderr = '';
    const exitCode = await cli.main(['exec', 'dev_abc123', '--script', '/tmp/a.ps1'], {}, {
      stdout,
      stderr: { write(value) { stderr += value; } },
      createRemoteDependencies: async () => fixture().factoryValue,
      loadRemoteTarget: async () => fixture().target,
      executeRemoteScript: async () => result,
    });
    assert.equal(exitCode, 2);
    assert.equal(stderr, 'REMOTE_INPUT_INVALID\n');
  }
});

test('put rejects a successful operation value that cannot produce one JSON object', async () => {
  for (const result of [undefined, [], { toJSON: () => 'not-an-object' }]) {
    const io = captureIo();
    const exitCode = await cli.main([
      'put',
      'dev_abc123',
      '/tmp/a.txt',
      'D:\\work\\a.txt',
    ], {}, {
      ...io,
      createRemoteDependencies: async () => fixture().factoryValue,
      loadRemoteTarget: async () => fixture().target,
      putRemoteFile: () => result,
    });
    assert.equal(exitCode, 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), 'REMOTE_INPUT_INVALID\n');
  }
});

test('success output snapshots exact own data fields without invoking toJSON, getters or Proxy traps', async () => {
  let toJsonCalls = 0;
  let getterCalls = 0;
  let proxyTraps = 0;
  const withToJson = {
    ...PUT_RESULT,
    toJSON() {
      toJsonCalls += 1;
      return { secret: '/private/source' };
    },
  };
  const withGetter = { ...PUT_RESULT };
  Object.defineProperty(withGetter, 'destination', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 'D:\\work\\a.txt';
    },
  });
  const proxied = new Proxy({ ...PUT_RESULT }, {
    getOwnPropertyDescriptor() {
      proxyTraps += 1;
      throw new Error('result proxy trap');
    },
    get() {
      proxyTraps += 1;
      throw new Error('result proxy get');
    },
  });

  for (const result of [withToJson, withGetter, proxied]) {
    const io = captureIo();
    const exitCode = await cli.main(['put', 'dev_abc123', '/tmp/a', 'D:\\work\\a.txt'], {}, {
      ...io,
      createRemoteDependencies: async () => fixture().factoryValue,
      loadRemoteTarget: async () => fixture().target,
      putRemoteFile: () => result,
    });
    assert.equal(exitCode, 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), 'REMOTE_INPUT_INVALID\n');
  }
  assert.equal(toJsonCalls, 0);
  assert.equal(getterCalls, 0);
  assert.equal(proxyTraps, 0);
});

test('success output rejects symbols, extra or missing fields and invalid scalar values', async () => {
  const withSymbol = { ...PUT_RESULT };
  withSymbol[Symbol('secret')] = '/private/source';
  const { address: _missingAddress, ...missingField } = PUT_RESULT;
  const invalidResults = [
    withSymbol,
    { ...PUT_RESULT, extra: 'secret' },
    missingField,
    { ...PUT_RESULT, destination: undefined },
    { ...PUT_RESULT, destination: () => 'D:\\work\\a.txt' },
    { ...PUT_RESULT, operation: 'get' },
    { ...PUT_RESULT, schemaVersion: 2 },
    { ...PUT_RESULT, deviceId: 'not-a-device' },
    { ...PUT_RESULT, address: 'not-an-ip' },
    { ...PUT_RESULT, bytes: -1 },
    { ...PUT_RESULT, sha256: 'not-a-hash' },
    { ...PUT_RESULT, finishedAt: 'not-a-time' },
  ];

  for (const result of invalidResults) {
    const io = captureIo();
    const exitCode = await cli.main(['put', 'dev_abc123', '/tmp/a', 'D:\\work\\a.txt'], {}, {
      ...io,
      createRemoteDependencies: async () => fixture().factoryValue,
      loadRemoteTarget: async () => fixture().target,
      putRemoteFile: async () => result,
    });
    assert.equal(exitCode, 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), 'REMOTE_INPUT_INVALID\n');
  }
});

test('exec and get enforce their exact result schemas and bounded scalar values', async () => {
  const cases = [
    {
      command: ['exec', 'dev_abc123', '--script', '/tmp/a.ps1'],
      hook: 'executeRemoteScript',
      result: { ...EXEC_RESULT, stdout: 'x'.repeat(4 * 1024 * 1024 + 1) },
    },
    {
      command: ['exec', 'dev_abc123', '--script', '/tmp/a.ps1'],
      hook: 'executeRemoteScript',
      result: { ...EXEC_RESULT, exitCode: 256 },
    },
    {
      command: ['get', 'dev_abc123', 'D:\\work\\a.txt', '/tmp/a.txt'],
      hook: 'getRemoteFile',
      result: { ...GET_RESULT, source: undefined },
    },
    {
      command: ['get', 'dev_abc123', 'D:\\work\\a.txt', '/tmp/a.txt'],
      hook: 'getRemoteFile',
      result: { ...GET_RESULT, operation: 'put' },
    },
  ];
  for (const { command, hook, result } of cases) {
    const io = captureIo();
    const exitCode = await cli.main(command, {}, {
      ...io,
      createRemoteDependencies: async () => fixture().factoryValue,
      loadRemoteTarget: async () => fixture().target,
      [hook]: async () => result,
    });
    assert.equal(exitCode, 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), 'REMOTE_INPUT_INVALID\n');
  }
});

test('remote dispatch never reads enrollment-only runtime getters', async () => {
  const io = captureIo();
  const setup = successfulRuntime({
    operationName: 'executeRemoteScript',
    result: EXEC_RESULT,
    inspectOperation() {},
  });
  let enrollmentReads = 0;
  const runtime = { ...setup.runtime, ...io };
  Object.defineProperties(runtime, {
    dependencyFactory: {
      enumerable: true,
      get() {
        enrollmentReads += 1;
        throw new Error('enrollment factory read');
      },
    },
    runEnrollment: {
      enumerable: true,
      get() {
        enrollmentReads += 1;
        throw new Error('enrollment operation read');
      },
    },
    signalSource: {
      enumerable: true,
      get() {
        enrollmentReads += 1;
        throw new Error('signal source read');
      },
    },
  });

  const exitCode = await cli.main(['exec', 'dev_abc123', '--script', '/tmp/a.ps1'], {}, runtime);
  assert.equal(exitCode, 0);
  assert.equal(enrollmentReads, 0);
  assert.equal(io.stderrValue(), '');
});

test('remote runtime hooks reject accessors, proxies and symbols without invoking traps', async () => {
  let getterCalls = 0;
  let proxyTraps = 0;
  const cases = [];

  const getterRuntime = {
    ...captureIo(),
    loadRemoteTarget: async () => fixture().target,
    executeRemoteScript: async () => EXEC_RESULT,
  };
  Object.defineProperty(getterRuntime, 'createRemoteDependencies', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return async () => fixture().factoryValue;
    },
  });
  cases.push(getterRuntime);

  const proxyHook = new Proxy(async () => fixture().factoryValue, {
    apply() {
      proxyTraps += 1;
      return fixture().factoryValue;
    },
  });
  cases.push({
    ...captureIo(),
    createRemoteDependencies: proxyHook,
    loadRemoteTarget: async () => fixture().target,
    executeRemoteScript: async () => EXEC_RESULT,
  });

  const symbolRuntime = {
    ...captureIo(),
    createRemoteDependencies: async () => fixture().factoryValue,
    loadRemoteTarget: async () => fixture().target,
    executeRemoteScript: async () => EXEC_RESULT,
    [Symbol('secret')]: '/private/path',
  };
  cases.push(symbolRuntime);

  for (const runtime of cases) {
    const exitCode = await cli.main(['exec', 'dev_abc123', '--script', '/tmp/a.ps1'], {}, runtime);
    assert.equal(exitCode, 2);
    assert.equal(runtime.stdoutValue(), '');
    assert.equal(runtime.stderrValue(), 'REMOTE_INPUT_INVALID\n');
  }
  assert.equal(getterCalls, 0);
  assert.equal(proxyTraps, 0);
});

test('remote dependency snapshots reject getters and proxies without invoking traps', async () => {
  let getterCalls = 0;
  let proxyTraps = 0;
  const getterDependencies = { ...fixture().factoryValue };
  Object.defineProperty(getterDependencies, 'registry', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return fixture().factoryValue.registry;
    },
  });
  const proxyDependencies = new Proxy(fixture().factoryValue, {
    get() {
      proxyTraps += 1;
      throw new Error('dependency proxy get');
    },
    getOwnPropertyDescriptor() {
      proxyTraps += 1;
      throw new Error('dependency proxy descriptor');
    },
  });

  for (const dependencies of [getterDependencies, proxyDependencies]) {
    const io = captureIo();
    const exitCode = await cli.main(['exec', 'dev_abc123', '--script', '/tmp/a.ps1'], {}, {
      ...io,
      createRemoteDependencies: () => dependencies,
      loadRemoteTarget: async () => assert.fail('target loader called'),
      executeRemoteScript: async () => assert.fail('operation called'),
    });
    assert.equal(exitCode, 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), 'REMOTE_INPUT_INVALID\n');
  }
  assert.equal(getterCalls, 0);
  assert.equal(proxyTraps, 0);
});

test('rejects duplicate, reordered or multi-primary stable error chains', async () => {
  const chains = [
    { primaryCode: 'REMOTE_EXECUTION_UNCERTAIN:REMOTE_CLEANUP_UNCERTAIN', code: 'REMOTE_CLEANUP_UNCERTAIN' },
    { primaryCode: 'LOCAL_CLEANUP_FAILED', code: 'REMOTE_CLEANUP_UNCERTAIN' },
    { primaryCode: 'REMOTE_CLEANUP_UNCERTAIN', code: 'FILE_TRANSFER_FAILED' },
    { primaryCode: 'REMOTE_CONNECTION_FAILED:FILE_TRANSFER_FAILED', code: 'REMOTE_CLEANUP_UNCERTAIN' },
    { code: 'FILE_TRANSFER_FAILED:REMOTE_CLEANUP_UNCERTAIN' },
  ];
  for (const chain of chains) {
    const io = captureIo();
    const error = Object.assign(new Error('private'), chain);
    const exitCode = await cli.main(['exec', 'dev_abc123', '--script', '/tmp/a.ps1'], {}, {
      ...io,
      createRemoteDependencies: async () => fixture().factoryValue,
      loadRemoteTarget: async () => fixture().target,
      executeRemoteScript: async () => { throw error; },
    });
    assert.equal(exitCode, 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), 'REMOTE_INPUT_INVALID\n');
  }
});

test('preserves canonical operation-generated primary and cleanup chains', async () => {
  const chains = [
    { code: 'FILE_TRANSFER_FAILED', expected: 'FILE_TRANSFER_FAILED' },
    { primaryCode: 'FILE_TRANSFER_FAILED', code: 'REMOTE_CLEANUP_UNCERTAIN', expected: 'FILE_TRANSFER_FAILED:REMOTE_CLEANUP_UNCERTAIN' },
    { primaryCode: 'FILE_TRANSFER_FAILED:REMOTE_CLEANUP_UNCERTAIN', code: 'LOCAL_CLEANUP_FAILED', expected: 'FILE_TRANSFER_FAILED:REMOTE_CLEANUP_UNCERTAIN:LOCAL_CLEANUP_FAILED' },
    { primaryCode: 'FILE_TRANSFER_FAILED', code: 'LOCAL_CLEANUP_FAILED', expected: 'FILE_TRANSFER_FAILED:LOCAL_CLEANUP_FAILED' },
    { primaryCode: 'REMOTE_CLEANUP_UNCERTAIN', code: 'LOCAL_CLEANUP_FAILED', expected: 'REMOTE_CLEANUP_UNCERTAIN:LOCAL_CLEANUP_FAILED' },
  ];
  for (const { expected, ...chain } of chains) {
    const io = captureIo();
    const error = Object.assign(new Error('private'), chain);
    const exitCode = await cli.main(['exec', 'dev_abc123', '--script', '/tmp/a.ps1'], {}, {
      ...io,
      createRemoteDependencies: async () => fixture().factoryValue,
      loadRemoteTarget: async () => fixture().target,
      executeRemoteScript: async () => { throw error; },
    });
    assert.equal(exitCode, 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), `${expected}\n`);
  }
});

test('get preserves operation-generated local-before-remote cleanup chains', async () => {
  const chains = [
    {
      primaryCode: 'LOCAL_CLEANUP_FAILED',
      code: 'REMOTE_CLEANUP_UNCERTAIN',
      expected: 'LOCAL_CLEANUP_FAILED:REMOTE_CLEANUP_UNCERTAIN',
    },
    {
      primaryCode: 'FILE_TRANSFER_FAILED:LOCAL_CLEANUP_FAILED',
      code: 'REMOTE_CLEANUP_UNCERTAIN',
      expected: 'FILE_TRANSFER_FAILED:LOCAL_CLEANUP_FAILED:REMOTE_CLEANUP_UNCERTAIN',
    },
  ];
  for (const { expected, ...chain } of chains) {
    const io = captureIo();
    const error = Object.assign(new Error('private'), chain);
    const exitCode = await cli.main(['get', 'dev_abc123', 'D:\\a.txt', '/tmp/a'], {}, {
      ...io,
      createRemoteDependencies: async () => fixture().factoryValue,
      loadRemoteTarget: async () => fixture().target,
      getRemoteFile: async () => { throw error; },
    });
    assert.equal(exitCode, 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), `${expected}\n`);
  }
});

test('rejects non-Proxy thenable hook returns without invoking their then accessors', async () => {
  for (const phase of ['dependencies', 'target', 'operation']) {
    let thenReads = 0;
    const thenable = phase === 'dependencies'
      ? { ...fixture().factoryValue }
      : phase === 'target'
        ? { marker: 'target' }
        : { ...EXEC_RESULT };
    Object.defineProperty(thenable, 'then', {
      enumerable: false,
      get() {
        thenReads += 1;
        return undefined;
      },
    });
    const io = captureIo();
    const exitCode = await cli.main(['exec', 'dev_abc123', '--script', '/tmp/a.ps1'], {}, {
      ...io,
      createRemoteDependencies: phase === 'dependencies'
        ? () => thenable
        : async () => fixture().factoryValue,
      loadRemoteTarget: phase === 'target'
        ? () => thenable
        : async () => fixture().target,
      executeRemoteScript: phase === 'operation'
        ? () => thenable
        : async () => EXEC_RESULT,
    });
    assert.equal(exitCode, 2, phase);
    assert.equal(io.stdoutValue(), '', phase);
    assert.equal(io.stderrValue(), 'REMOTE_INPUT_INVALID\n', phase);
    assert.equal(thenReads, 0, phase);
  }
});

test('rejects native Promise hook results with own constructor accessors without invoking them', async () => {
  for (const phase of ['dependencies', 'target', 'operation']) {
    let constructorReads = 0;
    const value = phase === 'dependencies'
      ? fixture().factoryValue
      : phase === 'target'
        ? fixture().target
        : EXEC_RESULT;
    const promise = Promise.resolve(value);
    Object.defineProperty(promise, 'constructor', {
      configurable: true,
      get() {
        constructorReads += 1;
        return Promise;
      },
    });
    const io = captureIo();
    const exitCode = await cli.main(['exec', 'dev_abc123', '--script', '/tmp/a.ps1'], {}, {
      ...io,
      createRemoteDependencies: phase === 'dependencies'
        ? () => promise
        : async () => fixture().factoryValue,
      loadRemoteTarget: phase === 'target'
        ? () => promise
        : async () => fixture().target,
      executeRemoteScript: phase === 'operation'
        ? () => promise
        : async () => EXEC_RESULT,
    });
    assert.equal(exitCode, 2, phase);
    assert.equal(io.stdoutValue(), '', phase);
    assert.equal(io.stderrValue(), 'REMOTE_INPUT_INVALID\n', phase);
    assert.equal(constructorReads, 0, phase);
  }
});

test('rejects hostile registry and SSH identity methods before property access', async () => {
  for (const dependency of ['registry', 'sshIdentity']) {
    const method = dependency === 'registry' ? 'get' : 'getExisting';
    for (const attack of ['own-getter', 'prototype-getter', 'proxy-prototype']) {
      let reads = 0;
      let value;
      if (attack === 'own-getter') {
        value = {};
        Object.defineProperty(value, method, {
          get() {
            reads += 1;
            return async () => null;
          },
        });
      } else if (attack === 'prototype-getter') {
        const prototype = {};
        Object.defineProperty(prototype, method, {
          get() {
            reads += 1;
            return async () => null;
          },
        });
        value = Object.create(prototype);
      } else {
        const prototype = new Proxy({ [method]: async () => null }, {
          get(target, property, receiver) {
            reads += 1;
            return Reflect.get(target, property, receiver);
          },
        });
        value = Object.create(prototype);
      }
      const dependencies = Object.freeze({
        ...fixture().factoryValue,
        [dependency]: value,
      });
      const io = captureIo();
      const exitCode = await cli.main(['exec', 'dev_abc123', '--script', '/tmp/a.ps1'], {}, {
        ...io,
        createRemoteDependencies: () => dependencies,
        loadRemoteTarget: async (deviceId, nested) => {
          await nested[dependency][method](deviceId);
          return fixture().target;
        },
        executeRemoteScript: async () => EXEC_RESULT,
      });
      assert.equal(exitCode, 2, `${dependency}:${attack}`);
      assert.equal(io.stdoutValue(), '', `${dependency}:${attack}`);
      assert.equal(io.stderrValue(), 'REMOTE_INPUT_INVALID\n', `${dependency}:${attack}`);
      assert.equal(reads, 0, `${dependency}:${attack}`);
    }
  }
});

test('rejects missing, ambiguous, symbolic, and Proxy dependency methods before target loading', async () => {
  const method = async () => null;
  const ambiguous = Object.create({ get: method });
  ambiguous.get = method;
  const symbolic = { get: method, [Symbol('hostile')]: true };
  const proxyMethod = new Proxy(method, { apply: () => null });
  const invalidRegistries = [{}, ambiguous, symbolic, { get: proxyMethod }];

  for (const registry of invalidRegistries) {
    let targetCalls = 0;
    const io = captureIo();
    const exitCode = await cli.main(['exec', 'dev_abc123', '--script', '/tmp/a.ps1'], {}, {
      ...io,
      createRemoteDependencies: () => Object.freeze({
        ...fixture().factoryValue,
        registry,
      }),
      loadRemoteTarget: async () => {
        targetCalls += 1;
        return fixture().target;
      },
      executeRemoteScript: async () => EXEC_RESULT,
    });
    assert.equal(exitCode, 2);
    assert.equal(targetCalls, 0);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), 'REMOTE_INPUT_INVALID\n');
  }
});

test('production registry and SSH identity methods survive fixed dependency wrappers', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'agent-road-cli-dependencies-'));
  try {
    const dependencies = cli.createRemoteDependencies({ AGENT_ROAD_HOME: directory });
    const io = captureIo();
    const exitCode = await cli.main(['exec', 'dev_abc123', '--script', '/tmp/a.ps1'], {}, {
      ...io,
      createRemoteDependencies: () => dependencies,
      loadRemoteTarget: async (deviceId, nested) => {
        assert.equal(Object.getPrototypeOf(nested.registry), null);
        assert.equal(Object.getPrototypeOf(nested.sshIdentity), null);
        assert.equal(Object.isFrozen(nested.registry), true);
        assert.equal(Object.isFrozen(nested.sshIdentity), true);
        assert.equal(await nested.registry.get('dev_missing'), null);
        await assert.rejects(
          nested.sshIdentity.getExisting(deviceId),
          (error) => error.code === 'SSH_IDENTITY_NOT_FOUND',
        );
        return fixture().target;
      },
      executeRemoteScript: async () => EXEC_RESULT,
    });
    assert.equal(exitCode, 0);
    assert.equal(io.stderrValue(), '');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('accepts only command-realistic standalone remote error codes', async () => {
  const shared = [
    'DEVICE_NOT_FOUND',
    'DEVICE_NOT_READY',
    'DEVICE_BUSY',
    'REMOTE_INPUT_INVALID',
    'REMOTE_CONNECTION_FAILED',
    'REMOTE_OUTPUT_LIMIT',
    'REMOTE_CLEANUP_UNCERTAIN',
    'FILE_TRANSFER_FAILED',
    'FILE_INTEGRITY_FAILED',
    'LOCAL_CLEANUP_FAILED',
  ];
  const cases = {
    exec: { valid: [...shared, 'REMOTE_EXECUTION_UNCERTAIN'], invalid: 'FILE_TRANSFER_UNCERTAIN' },
    put: { valid: [...shared, 'FILE_TRANSFER_UNCERTAIN'], invalid: 'REMOTE_EXECUTION_UNCERTAIN' },
    get: { valid: [...shared, 'FILE_TRANSFER_UNCERTAIN'], invalid: 'REMOTE_EXECUTION_UNCERTAIN' },
  };
  const args = {
    exec: ['exec', 'dev_abc123', '--script', '/tmp/a.ps1'],
    put: ['put', 'dev_abc123', '/tmp/a', 'D:\\a.txt'],
    get: ['get', 'dev_abc123', 'D:\\a.txt', '/tmp/a'],
  };
  const operationName = {
    exec: 'executeRemoteScript',
    put: 'putRemoteFile',
    get: 'getRemoteFile',
  };

  for (const [command, { valid, invalid }] of Object.entries(cases)) {
    for (const code of [...valid, invalid]) {
      const io = captureIo();
      const error = Object.assign(new Error('private'), { code });
      const exitCode = await cli.main(args[command], {}, {
        ...io,
        createRemoteDependencies: async () => fixture().factoryValue,
        loadRemoteTarget: async () => fixture().target,
        [operationName[command]]: async () => { throw error; },
      });
      assert.equal(exitCode, 2, `${command}:${code}`);
      assert.equal(io.stdoutValue(), '', `${command}:${code}`);
      assert.equal(
        io.stderrValue(),
        `${code === invalid ? 'REMOTE_INPUT_INVALID' : code}\n`,
        `${command}:${code}`,
      );
    }
  }
});

for (const operation of ['put','get']) {
 test(`CLI accepts a verified zero-byte ${operation} result`, async () => {
  const io=captureIo();
  const result={...(operation==='put'?PUT_RESULT:GET_RESULT),bytes:0,sha256:'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855'};
  const args=operation==='put'?['put','dev_abc123','/tmp/a','D:\\work\\a.txt']:['get','dev_abc123','D:\\work\\a.txt','/tmp/a.txt'];
  const code=await cli.main(args,{}, {...io,createRemoteDependencies:async()=>fixture().factoryValue,loadRemoteTarget:async()=>fixture().target,[operation+'RemoteFile']:async()=>result});
  assert.equal(code,0);assert.equal(JSON.parse(io.stdoutValue()).bytes,0);assert.equal(io.stderrValue(),'');
 });
}
