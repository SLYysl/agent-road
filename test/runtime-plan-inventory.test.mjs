import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { gunzipSync } from 'node:zlib';

const inventoryModule = await import('../src/runtime/runtime-plan-inventory.mjs').catch(() => null);

const DEVICE_ID = 'dev_abc123';
const ADDRESS = '100.64.0.10';

function inventory() {
  return {
    schemaVersion: 1,
    platform: {
      os: 'windows',
      version: '10.0.26200',
      build: 26_200,
      edition: 'Microsoft Windows 11 Home',
      architecture: 'x64',
      windowsPowerShellVersion: '5.1.26100.8655',
      elevated: true,
    },
    freeBytes: 50_000_000_000,
    pendingReboot: false,
    interactiveSession: false,
    runtime: {
      schemaVersion: null,
      catalogRevision: null,
      catalogDigest: null,
      generationDigest: null,
      generationVerified: false,
      pendingOperationId: null,
      restartRequired: false,
    },
    managedArtifacts: [],
  };
}

function observation(controllerTrust = { state: 'unpinned', controllerKeyId: null }) {
  return {
    schemaVersion: 1,
    inventory: inventory(),
    controllerTrust,
  };
}

function processResult(stdout) {
  return {
    command: '/usr/bin/ssh',
    args: [],
    exitCode: 0,
    signal: null,
    stdout,
    stderr: '',
  };
}

test('reads hashes and gzips the checked-in inventory once for two identical pinned-SSH observations', async () => {
  assert.ok(inventoryModule, 'runtime plan inventory module must exist');
  const source = await readFile(inventoryModule.RUNTIME_PLAN_INVENTORY_SCRIPT_PATH);
  const expectedSha256 = createHash('sha256').update(source).digest('hex').toUpperCase();
  const target = Object.freeze({ device: Object.freeze({ id: DEVICE_ID }) });
  const trust = Object.freeze({ deviceId: DEVICE_ID, pinned: true });
  const calls = [];
  const invocations = [];
  const runProcess = () => assert.fail('the trusted session owns process execution');
  const session = Object.freeze({
    invokeSsh: async (address, argv, options) => {
      invocations.push({ address, argv, options });
      return processResult(JSON.stringify(observation()));
    },
  });
  const result = await inventoryModule.readRuntimePlanInventoryPair({
    target,
    dependencies: {
      readInventoryScript: async () => {
        calls.push('readInventoryScript');
        return Buffer.from(source);
      },
      trustedInput: (inputTarget, inputRunProcess) => {
        calls.push('trustedInput');
        assert.equal(inputTarget, target);
        assert.equal(inputRunProcess, runProcess);
        return trust;
      },
      withTrustedSshSession: async (inputTrust, operation, options) => {
        calls.push('withTrustedSshSession');
        assert.equal(inputTrust, trust);
        assert.deepEqual(options, { lockTimeoutMs: 900_000 });
        return operation(session);
      },
      selectAddress: async (inputSession) => {
        calls.push('selectAddress');
        assert.equal(inputSession, session);
        return ADDRESS;
      },
      isTrustedSshSessionLockError: () => false,
      runProcess,
    },
  });

  assert.deepEqual(calls, [
    'readInventoryScript',
    'trustedInput',
    'withTrustedSshSession',
    'selectAddress',
  ]);
  assert.equal(invocations.length, 2);
  assert.equal(invocations[0].address, ADDRESS);
  assert.equal(invocations[1].address, ADDRESS);
  assert.deepEqual(invocations[0].argv, invocations[1].argv);
  assert.deepEqual(invocations[0].options, invocations[1].options);
  assert.equal(invocations[0].options.timeoutMs, 120_000);
  assert.equal(invocations[0].options.maxOutputBytes, 65_536);
  assert.equal(Buffer.byteLength(invocations[0].options.stdinText, 'ascii') < 65_536, true);
  assert.equal(invocations[0].options.stdinText.includes('Get-AgentRoadRuntimeStateSnapshot'), false);
  assert.deepEqual(gunzipSync(Buffer.from(invocations[0].options.stdinText, 'base64')), source);

  const argv = invocations[0].argv;
  assert.deepEqual(argv.slice(0, 7), [
    'powershell.exe',
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-EncodedCommand',
  ]);
  assert.equal(argv.length, 8);
  assert.equal(Buffer.byteLength(argv.join(' '), 'utf8') < 7_000, true);
  const loader = Buffer.from(argv[7], 'base64').toString('utf16le');
  const compressed = Buffer.from(invocations[0].options.stdinText, 'base64');
  const compressedSha256 = createHash('sha256').update(compressed).digest('hex').toUpperCase();
  assert.match(loader, new RegExp(expectedSha256, 'u'));
  assert.match(loader, new RegExp(compressedSha256, 'u'));
  assert.match(loader, /ComputeHash\(\$z\)/u);
  assert.match(loader, /GZipStream/u);
  assert.match(loader, /CompressionMode\]::Decompress/u);
  assert.match(loader, /UTF8Encoding\(\$false,\$true\)/u);
  assert.match(loader, /-PlanningObservation/u);
  assert.match(loader, /65536/u);
  assert.match(loader, /\$d=131072/u);
  assert.match(loader, /\$q\.Length\+\$r -gt \$d/u);
  assert.match(loader, new RegExp(String(source.length), 'u'));
  assert.doesNotMatch(loader, /StreamReader|ReadToEnd|ReadByte|\.ps1|ProgramData|scp|sftp/iu);
  assert.equal(source.length <= 128 * 1_024, true);

  const trailing = Buffer.concat([compressed, Buffer.alloc(8)]);
  assert.deepEqual(gunzipSync(trailing), source, 'gzip alone accepts ignorable trailing data');
  assert.notEqual(
    createHash('sha256').update(trailing).digest('hex').toUpperCase(),
    compressedSha256,
    'the loader-bound compressed digest rejects the same trailing data',
  );

  assert.deepEqual(result, {
    schemaVersion: 1,
    firstInventory: inventory(),
    firstControllerTrust: { state: 'unpinned', controllerKeyId: null },
    secondInventory: inventory(),
    secondControllerTrust: { state: 'unpinned', controllerKeyId: null },
    scriptSha256: expectedSha256,
  });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.firstInventory), true);
  assert.equal(Object.isFrozen(result.firstControllerTrust), true);
});

test('planning observation is an explicit switch while normal doctor output remains the existing inventory shape', async () => {
  assert.ok(inventoryModule, 'runtime plan inventory module must exist');
  const source = await readFile(inventoryModule.RUNTIME_PLAN_INVENTORY_SCRIPT_PATH, 'utf8');
  assert.match(source, /param\(\[switch\]\$PlanningObservation\)/u);
  assert.match(source, /if \(\$PlanningObservation\.IsPresent\)/u);
  assert.match(source, /controllerTrust/u);
  assert.match(source, /state = if \(\$null -eq \$script:PinnedKeyId\) \{ 'unpinned' \} else \{ 'pinned' \}/u);
});

test('rejects an accessor session invoker without reading it or selecting an address', async () => {
  let getterReads = 0;
  let selectCalls = 0;
  const session = {};
  Object.defineProperty(session, 'invokeSsh', {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error('hostile accessor');
    },
  });
  Object.freeze(session);
  await assert.rejects(inventoryModule.readRuntimePlanInventoryPair({
    target: Object.freeze({}),
    dependencies: {
      readInventoryScript: async () => Buffer.from('inventory fixture', 'utf8'),
      trustedInput: () => Object.freeze({}),
      withTrustedSshSession: async (_trust, operation) => operation(session),
      selectAddress: async () => { selectCalls += 1; return ADDRESS; },
      isTrustedSshSessionLockError: () => false,
      runProcess: () => assert.fail('unused'),
    },
  }), { code: 'RUNTIME_INVENTORY_FAILED' });
  assert.equal(getterReads, 0);
  assert.equal(selectCalls, 0);
});

test('maps hostile thrown error objects without invoking code traps', async () => {
  for (const kind of ['accessor', 'proxy']) {
    let traps = 0;
    let error;
    if (kind === 'accessor') {
      error = {};
      Object.defineProperty(error, 'code', {
        get() {
          traps += 1;
          throw new Error('hostile code accessor');
        },
      });
    } else {
      error = new Proxy({}, {
        get() {
          traps += 1;
          throw new Error('hostile proxy');
        },
      });
    }
    await assert.rejects(inventoryModule.readRuntimePlanInventoryPair({
      target: Object.freeze({}),
      dependencies: {
        readInventoryScript: async () => Buffer.from('inventory fixture', 'utf8'),
        trustedInput: () => Object.freeze({}),
        withTrustedSshSession: async () => { throw error; },
        selectAddress: async () => assert.fail('unused'),
        isTrustedSshSessionLockError: () => false,
        runProcess: () => assert.fail('unused'),
      },
    }), { code: 'RUNTIME_INVENTORY_FAILED' }, kind);
    assert.equal(traps, 0, kind);
  }
});
