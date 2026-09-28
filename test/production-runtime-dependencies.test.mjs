import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmod,
  lstat,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import * as productionRuntime from '../src/runtime/production-runtime-dependencies.mjs';
import { RUNTIME_ACQUISITION_POLICY } from '../src/runtime/runtime-acquisition-policy.mjs';
import { RUNTIME_BASELINE_SCRIPT_PATH } from '../src/runtime/runtime-baseline.mjs';
import { RUNTIME_PLAN_INVENTORY_SCRIPT_PATH } from '../src/runtime/runtime-plan-inventory.mjs';
import { RUNTIME_PROVISION_SCRIPT_PATH } from '../src/runtime/runtime-provision.mjs';

const {
  createProductionRuntimeDependencies,
  createProductionApprovedRuntimeDependencies,
  createProductionRuntimeBaselineDependencies,
  createProductionRuntimePlanDependencies,
  createProductionRuntimeRecoveryDependencies,
  createProductionRuntimeProvisionInput,
  digestRuntimeInventoryRevision,
  digestRuntimeProvisionRevision,
  digestRuntimeRecoveryRevision,
  executeProductionRuntimeBaselineScript,
  PRODUCTION_RUNTIME_ACQUISITION_POLICY,
} = productionRuntime;

const DEVICE_ID = 'dev_abc123';
const DEPENDENCY_FIELDS = [
  'loadTarget',
  'readState',
  'transitionState',
  'readInventory',
  'loadCatalog',
  'getSigningPublicKey',
  'sign',
  'acquireArtifact',
  'provision',
  'operationId',
  'clock',
];
const RECOVERY_DEPENDENCY_FIELDS = [
  'loadTarget',
  'readState',
  'transitionState',
  'withRecoveryOperation',
  'inspectRemote',
  'applyRemote',
  'clock',
];
const BASELINE_DEPENDENCY_FIELDS = [
  'executeBaselineScript',
  'createBaseline',
  'readBaseline',
  'createComparison',
  'randomBytes',
];
const BASELINE_EXECUTION_DEPENDENCY_FIELDS = [
  'readBaselineScript',
  'loadTarget',
  'trustedInput',
  'withTrustedSshSession',
  'selectAddress',
  'isTrustedSshSessionLockError',
  'runProcess',
  'clock',
];
const PLAN_DEPENDENCY_FIELDS = [
  'loadTarget',
  'readState',
  'readInventoryPair',
  'loadCatalog',
  'readBaselineBinding',
  'getSigningPublicKey',
  'readMutatorRevisions',
  'createPlanTicket',
  'operationId',
  'clock',
];
const APPROVED_DEPENDENCY_FIELDS = [
  'loadTarget',
  'readState',
  'transitionState',
  'readInventoryPair',
  'loadCatalog',
  'readBaselineBinding',
  'getSigningPublicKey',
  'readMutatorRevisions',
  'readPlanTicket',
  'consumePlanTicket',
  'sign',
  'acquireArtifact',
  'provision',
];
const ADDRESS = '100.64.0.10';
const BASELINE_INPUT = JSON.stringify({
  schemaVersion: 1,
  protocolRevision: 1,
  hmacKeyBase64: Buffer.alloc(32, 7).toString('base64'),
});

async function runtimeHome(t) {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-runtime-production-')));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

test('binds the exact frozen production runtime dependency surface and policy', async (t) => {
  const home = await runtimeHome(t);
  const dependencies = createProductionRuntimeDependencies({ AGENT_ROAD_HOME: home });

  assert.deepEqual(Object.keys(dependencies), DEPENDENCY_FIELDS);
  assert.equal(Object.isFrozen(dependencies), true);
  for (const field of DEPENDENCY_FIELDS) assert.equal(typeof dependencies[field], 'function');
  assert.deepEqual(PRODUCTION_RUNTIME_ACQUISITION_POLICY, {
    timeoutMs: 1_800_000,
    maxRedirects: 5,
  });
  assert.equal(Object.isFrozen(PRODUCTION_RUNTIME_ACQUISITION_POLICY), true);
  assert.equal(PRODUCTION_RUNTIME_ACQUISITION_POLICY, RUNTIME_ACQUISITION_POLICY);

  const operationId = dependencies.operationId();
  assert.match(operationId, /^[a-f0-9]{32}$/u);
  assert.equal(dependencies.clock() instanceof Date, true);
});

test('approved acquisition requires the exact policy values bound into authorization', async (t) => {
  const home = await runtimeHome(t);
  const approved = createProductionApprovedRuntimeDependencies({ AGENT_ROAD_HOME: home });
  for (const policy of [
    undefined,
    { ...RUNTIME_ACQUISITION_POLICY, timeoutMs: RUNTIME_ACQUISITION_POLICY.timeoutMs + 1 },
    { ...RUNTIME_ACQUISITION_POLICY, maxRedirects: RUNTIME_ACQUISITION_POLICY.maxRedirects + 1 },
  ]) {
    assert.throws(
      () => approved.acquireArtifact(Object.freeze({}), policy),
      { code: 'RUNTIME_INPUT_INVALID' },
    );
  }
});

test('binds separate exact plan and approved dependency surfaces to checked-in mutator revisions', async (t) => {
  const home = await runtimeHome(t);
  assert.equal(typeof createProductionRuntimePlanDependencies, 'function');
  assert.equal(typeof createProductionApprovedRuntimeDependencies, 'function');
  const planning = createProductionRuntimePlanDependencies({ AGENT_ROAD_HOME: home });
  const approved = createProductionApprovedRuntimeDependencies({ AGENT_ROAD_HOME: home });

  assert.deepEqual(Object.keys(planning), PLAN_DEPENDENCY_FIELDS);
  assert.deepEqual(Object.keys(approved), APPROVED_DEPENDENCY_FIELDS);
  assert.equal(Object.isFrozen(planning), true);
  assert.equal(Object.isFrozen(approved), true);
  for (const field of PLAN_DEPENDENCY_FIELDS) assert.equal(typeof planning[field], 'function');
  for (const field of APPROVED_DEPENDENCY_FIELDS) assert.equal(typeof approved[field], 'function');
  for (const forbidden of ['transitionState', 'sign', 'acquireArtifact', 'provision']) {
    assert.equal(Object.hasOwn(planning, forbidden), false);
  }
  for (const forbidden of ['operationId', 'clock']) {
    assert.equal(Object.hasOwn(approved, forbidden), false);
  }

  const recoveryPath = fileURLToPath(
    new URL('../src/runtime/runtime-recovery-remote.mjs', import.meta.url),
  );
  const windowsRemotePath = fileURLToPath(
    new URL('../src/remote/windows-remote.mjs', import.meta.url),
  );
  const remoteExecPath = fileURLToPath(
    new URL('../src/remote/remote-exec.mjs', import.meta.url),
  );
  const runtimePlanInventoryPath = fileURLToPath(
    new URL('../src/runtime/runtime-plan-inventory.mjs', import.meta.url),
  );
  const provisionUploadPath = fileURLToPath(
    new URL('../src/runtime/provision-upload.mjs', import.meta.url),
  );
  const runtimeProvisionPath = fileURLToPath(
    new URL('../src/runtime/runtime-provision.mjs', import.meta.url),
  );
  const ensureRuntimePath = fileURLToPath(
    new URL('../src/runtime/ensure-runtime.mjs', import.meta.url),
  );
  const runtimeManifestPath = fileURLToPath(
    new URL('../src/runtime/runtime-manifest.mjs', import.meta.url),
  );
  const inventoryScriptBytes = await readFile(RUNTIME_PLAN_INVENTORY_SCRIPT_PATH);
  const expected = {};
  expected.inventoryScriptSha256 = createHash('sha256')
    .update(inventoryScriptBytes)
    .digest('hex')
    .toUpperCase();
  expected.inventorySha256 = digestRuntimeInventoryRevision(
    inventoryScriptBytes,
    await readFile(runtimePlanInventoryPath),
  );
  expected.provisionSha256 = digestRuntimeProvisionRevision(
    await readFile(RUNTIME_PROVISION_SCRIPT_PATH),
    await readFile(remoteExecPath),
    await readFile(provisionUploadPath),
    await readFile(runtimeProvisionPath),
    await readFile(windowsRemotePath),
    await readFile(ensureRuntimePath),
    await readFile(runtimeManifestPath),
  );
  expected.recoverySha256 = digestRuntimeRecoveryRevision(
    await readFile(recoveryPath),
    await readFile(windowsRemotePath),
  );
  assert.deepEqual(await planning.readMutatorRevisions(), expected);
  assert.deepEqual(await approved.readMutatorRevisions(), expected);

  const factorySource = await readFile(
    new URL('../src/runtime/production-runtime-dependencies.mjs', import.meta.url),
    'utf8',
  );
  assert.match(factorySource, /provisionBytes: Buffer\.from\(provision\)/u);
  assert.match(factorySource, /recoveryBytes: Buffer\.from\(recovery\)/u);
  assert.match(factorySource, /runtimeProvisionFromAuthorizedSources/u);
  assert.match(factorySource, /const sources = await context\.sourceManifest\(\)/u);
});

test('recovery revision binds ordered adapter and wrapper bytes without boundary ambiguity', () => {
  const adapter = Buffer.from('adapter-v1');
  const wrapper = Buffer.from('wrapper-v1');
  const digest = digestRuntimeRecoveryRevision(adapter, wrapper);

  assert.match(digest, /^[A-F0-9]{64}$/u);
  assert.notEqual(digestRuntimeRecoveryRevision(Buffer.from('adapter-v2'), wrapper), digest);
  assert.notEqual(digestRuntimeRecoveryRevision(adapter, Buffer.from('wrapper-v2')), digest);
  assert.notEqual(digestRuntimeRecoveryRevision(wrapper, adapter), digest);
  assert.notEqual(
    digestRuntimeRecoveryRevision(Buffer.from('ab'), Buffer.from('c')),
    digestRuntimeRecoveryRevision(Buffer.from('a'), Buffer.from('bc')),
  );
});

test('inventory revision binds script and planning loader bytes without boundary ambiguity', () => {
  const script = Buffer.from('inventory-script-v1');
  const loader = Buffer.from('inventory-loader-v1');
  const digest = digestRuntimeInventoryRevision(script, loader);

  assert.match(digest, /^[A-F0-9]{64}$/u);
  assert.notEqual(digestRuntimeInventoryRevision(Buffer.from('inventory-script-v2'), loader), digest);
  assert.notEqual(digestRuntimeInventoryRevision(script, Buffer.from('inventory-loader-v2')), digest);
  assert.notEqual(digestRuntimeInventoryRevision(loader, script), digest);
  assert.notEqual(
    digestRuntimeInventoryRevision(Buffer.from('ab'), Buffer.from('c')),
    digestRuntimeInventoryRevision(Buffer.from('a'), Buffer.from('bc')),
  );
});

test('provision revision binds script and transport bytes without order or boundary ambiguity', () => {
  const components = [
    Buffer.from('provision-v1'),
    Buffer.from('remote-exec-v1'),
    Buffer.from('provision-upload-v1'),
    Buffer.from('runtime-provision-v1'),
    Buffer.from('windows-remote-v1'),
    Buffer.from('ensure-runtime-v1'),
    Buffer.from('runtime-manifest-v1'),
  ];
  const digest = digestRuntimeProvisionRevision(...components);

  assert.match(digest, /^[A-F0-9]{64}$/u);
  for (const [index, component] of components.entries()) {
    const changed = components.map((value) => Buffer.from(value));
    changed[index] = Buffer.concat([component, Buffer.from([0])]);
    assert.notEqual(digestRuntimeProvisionRevision(...changed), digest, `component ${index}`);
  }
  const reordered = components.map((value) => Buffer.from(value));
  [reordered[0], reordered[1]] = [reordered[1], reordered[0]];
  assert.notEqual(digestRuntimeProvisionRevision(...reordered), digest);
  assert.notEqual(
    digestRuntimeProvisionRevision(
      Buffer.from('ab'),
      Buffer.from('c'),
      Buffer.alloc(0),
      Buffer.alloc(0),
      Buffer.alloc(0),
      Buffer.alloc(0),
      Buffer.alloc(0),
    ),
    digestRuntimeProvisionRevision(
      Buffer.from('a'),
      Buffer.from('bc'),
      Buffer.alloc(0),
      Buffer.alloc(0),
      Buffer.alloc(0),
      Buffer.alloc(0),
      Buffer.alloc(0),
    ),
  );
});

test('approved production signing is existing-only and never creates or repairs identity files', async (t) => {
  const missingHome = await runtimeHome(t);
  const missingApproved = createProductionApprovedRuntimeDependencies({
    AGENT_ROAD_HOME: missingHome,
  });
  await assert.rejects(
    missingApproved.getSigningPublicKey(),
    (error) => error.code === 'BOOTSTRAP_SIGNING_KEY_PARTIAL',
  );
  assert.deepEqual(await readdir(missingHome), []);

  const home = await runtimeHome(t);
  const planning = createProductionRuntimePlanDependencies({ AGENT_ROAD_HOME: home });
  const expected = await planning.getSigningPublicKey();
  const identityDirectory = join(home, 'identity');
  const beforeNames = (await readdir(identityDirectory)).sort();
  const approved = createProductionApprovedRuntimeDependencies({ AGENT_ROAD_HOME: home });
  assert.deepEqual(await approved.getSigningPublicKey(), expected);
  const signature = await approved.sign(Buffer.from('approved existing-only signature'));
  assert.equal(typeof signature, 'string');
  assert.equal(signature.length > 0, true);
  assert.deepEqual((await readdir(identityDirectory)).sort(), beforeNames);

  await chmod(identityDirectory, 0o777);
  await assert.rejects(
    approved.getSigningPublicKey(),
    (error) => error.code === 'BOOTSTRAP_SIGNING_KEY_PERMISSIONS',
  );
  assert.equal((await lstat(identityDirectory)).mode & 0o777, 0o777);
});

test('binds a separate exact frozen recovery dependency surface without provisioning authority', async (t) => {
  const home = await runtimeHome(t);
  const dependencies = createProductionRuntimeRecoveryDependencies({ AGENT_ROAD_HOME: home });

  assert.deepEqual(Object.keys(dependencies), RECOVERY_DEPENDENCY_FIELDS);
  assert.equal(Object.isFrozen(dependencies), true);
  for (const field of RECOVERY_DEPENDENCY_FIELDS) {
    assert.equal(typeof dependencies[field], 'function');
  }
  for (const forbidden of [
    'readInventory',
    'loadCatalog',
    'getSigningPublicKey',
    'sign',
    'acquireArtifact',
    'provision',
    'operationId',
  ]) assert.equal(Object.hasOwn(dependencies, forbidden), false);

  const state = await dependencies.readState(DEVICE_ID);
  assert.equal(state.runtimeStatus, 'UNPROVISIONED');
  assert.equal(state.deviceId, DEVICE_ID);
  assert.equal(dependencies.clock() instanceof Date, true);
});

test('binds a separate exact frozen baseline dependency surface without mutation authority', async (t) => {
  const home = await runtimeHome(t);
  assert.equal(typeof createProductionRuntimeBaselineDependencies, 'function');
  const dependencies = createProductionRuntimeBaselineDependencies({ AGENT_ROAD_HOME: home });

  assert.deepEqual(Object.keys(dependencies), BASELINE_DEPENDENCY_FIELDS);
  assert.equal(Object.isFrozen(dependencies), true);
  for (const field of BASELINE_DEPENDENCY_FIELDS) {
    assert.equal(typeof dependencies[field], 'function');
  }
  for (const forbidden of [
    'readState',
    'transitionState',
    'readInventory',
    'loadCatalog',
    'getSigningPublicKey',
    'sign',
    'acquireArtifact',
    'provision',
    'inspectRemote',
    'applyRemote',
    'operationId',
  ]) assert.equal(Object.hasOwn(dependencies, forbidden), false);
});

test('baseline transport executes the checked-in bytes from memory over pinned SSH with the HMAC input only on stdin', async () => {
  assert.equal(typeof executeProductionRuntimeBaselineScript, 'function');
  const scriptBytes = await readFile(RUNTIME_BASELINE_SCRIPT_PATH);
  const scriptSha256 = createHash('sha256').update(scriptBytes).digest('hex').toUpperCase();
  const target = Object.freeze({ target: 'pinned-device' });
  const trust = Object.freeze({ trust: 'pinned-known-hosts' });
  const runProcess = () => assert.fail('session owns process execution');
  const session = Object.freeze({
    addresses: Object.freeze([ADDRESS]),
    invokeSsh: async (address, argv, options) => {
      assert.equal(address, ADDRESS);
      assert.deepEqual(argv.slice(0, 5), [
        'powershell.exe',
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
      ]);
      assert.deepEqual(argv.slice(5, 8), ['Bypass', '-EncodedCommand', argv[7]]);
      assert.equal(argv.length, 8);
      assert.ok(Buffer.byteLength(argv.join(' '), 'utf8') < 7_000);
      assert.equal(argv.join(' ').includes(JSON.parse(BASELINE_INPUT).hmacKeyBase64), false);
      assert.deepEqual(options, {
        timeoutMs: 120_000,
        maxOutputBytes: 8_192,
        stdinText: `${scriptBytes.toString('ascii')}${BASELINE_INPUT}`,
      });

      const loader = Buffer.from(argv[7], 'base64').toString('utf16le');
      assert.match(loader, new RegExp(scriptSha256, 'u'));
      assert.match(loader, new RegExp(String(scriptBytes.length), 'u'));
      assert.match(loader, /\[Console\]::OpenStandardInput\(\)/u);
      assert.match(loader, /\.Read\(/u);
      assert.doesNotMatch(loader, /StreamReader|ReadToEnd/u);
      for (const preference of [
        'ProgressPreference',
        'VerbosePreference',
        'DebugPreference',
        'InformationPreference',
        'WarningPreference',
      ]) assert.match(loader, new RegExp(`\\$${preference}='SilentlyContinue'`, 'u'));
      assert.doesNotMatch(loader, new RegExp(JSON.parse(BASELINE_INPUT).hmacKeyBase64, 'u'));
      const framed = Buffer.from(options.stdinText, 'ascii');
      assert.deepEqual(framed.subarray(0, scriptBytes.length), scriptBytes);
      assert.equal(framed.subarray(scriptBytes.length).toString('ascii'), BASELINE_INPUT);
      return {
        command: '/usr/bin/ssh',
        args: [],
        exitCode: 0,
        signal: null,
        stdout: '{"schemaVersion":1,"protocolRevision":1,"surfaces":[]}',
        stderr: '',
      };
    },
  });
  const clocks = [
    new Date('2026-07-30T10:00:00.000Z'),
    new Date('2026-07-30T10:00:01.000Z'),
  ];
  const calls = [];
  const dependencies = {
    readBaselineScript: async () => Buffer.from(scriptBytes),
    loadTarget: async (deviceId) => {
      calls.push(['loadTarget', deviceId]);
      return target;
    },
    trustedInput: (inputTarget, inputRunProcess) => {
      calls.push(['trustedInput', inputTarget, inputRunProcess]);
      return trust;
    },
    withTrustedSshSession: async (inputTrust, operation, options) => {
      calls.push(['withTrustedSshSession', inputTrust, options]);
      return operation(session);
    },
    selectAddress: async (inputSession) => {
      calls.push(['selectAddress', inputSession]);
      return ADDRESS;
    },
    isTrustedSshSessionLockError: () => false,
    runProcess,
    clock: () => clocks.shift(),
  };

  const result = await executeProductionRuntimeBaselineScript({
    deviceId: DEVICE_ID,
    scriptPath: RUNTIME_BASELINE_SCRIPT_PATH,
    scriptSha256,
    timeoutMs: 120_000,
    maxOutputBytes: 8_192,
    stdinText: BASELINE_INPUT,
  }, dependencies);

  assert.deepEqual(result, {
    schemaVersion: 1,
    operation: 'exec',
    deviceId: DEVICE_ID,
    address: ADDRESS,
    exitCode: 0,
    stdout: '{"schemaVersion":1,"protocolRevision":1,"surfaces":[]}',
    stderr: '',
    startedAt: '2026-07-30T10:00:00.000Z',
    finishedAt: '2026-07-30T10:00:01.000Z',
  });
  assert.deepEqual(calls, [
    ['loadTarget', DEVICE_ID],
    ['trustedInput', target, runProcess],
    ['withTrustedSshSession', trust, { lockTimeoutMs: 900_000 }],
    ['selectAddress', session],
  ]);
});

test('baseline transport maps only trusted-session contention and rejects hostile expanded inputs before traps', async () => {
  assert.equal(typeof executeProductionRuntimeBaselineScript, 'function');
  const scriptBytes = await readFile(RUNTIME_BASELINE_SCRIPT_PATH);
  const scriptSha256 = createHash('sha256').update(scriptBytes).digest('hex').toUpperCase();
  const lockError = new Error('private lock path');
  const baseDependencies = {
    readBaselineScript: async () => scriptBytes,
    loadTarget: async () => Object.freeze({}),
    trustedInput: () => Object.freeze({}),
    withTrustedSshSession: async () => { throw lockError; },
    selectAddress: async () => ADDRESS,
    isTrustedSshSessionLockError: (error) => error === lockError,
    runProcess: () => {},
    clock: () => new Date('2026-07-30T10:00:00.000Z'),
  };
  const input = {
    deviceId: DEVICE_ID,
    scriptPath: RUNTIME_BASELINE_SCRIPT_PATH,
    scriptSha256,
    timeoutMs: 120_000,
    maxOutputBytes: 8_192,
    stdinText: BASELINE_INPUT,
  };
  await assert.rejects(
    executeProductionRuntimeBaselineScript(input, baseDependencies),
    (error) => error?.code === 'RUNTIME_ALREADY_RUNNING'
      && error.message === 'RUNTIME_ALREADY_RUNNING'
      && !/private|path/u.test(error.message),
  );

  let accessorReads = 0;
  const accessor = {};
  for (const field of Object.keys(input)) {
    Object.defineProperty(accessor, field, {
      enumerable: true,
      get() {
        accessorReads += 1;
        throw new Error('private accessor');
      },
    });
  }
  assert.throws(
    () => executeProductionRuntimeBaselineScript(accessor, baseDependencies),
    { code: 'RUNTIME_INPUT_INVALID' },
  );
  assert.equal(accessorReads, 0);
  assert.throws(
    () => executeProductionRuntimeBaselineScript(
      input,
      { ...baseDependencies, provision: () => {} },
    ),
    { code: 'RUNTIME_INPUT_INVALID' },
  );

  const protocol = JSON.parse(BASELINE_INPUT);
  protocol.hmacKeyBase64 = `${protocol.hmacKeyBase64.slice(0, -2)}d=`;
  assert.equal(
    Buffer.from(protocol.hmacKeyBase64, 'base64').toString('base64'),
    JSON.parse(BASELINE_INPUT).hmacKeyBase64,
  );
  assert.throws(
    () => executeProductionRuntimeBaselineScript(
      { ...input, stdinText: JSON.stringify(protocol) },
      baseDependencies,
    ),
    { code: 'RUNTIME_INPUT_INVALID' },
  );

  let reorderedSideEffects = 0;
  const reorderedInput = JSON.stringify({
    protocolRevision: 1,
    hmacKeyBase64: JSON.parse(BASELINE_INPUT).hmacKeyBase64,
    schemaVersion: 1,
  });
  const reorderedDependencies = Object.fromEntries(
    Object.entries(baseDependencies).map(([field, operation]) => [
      field,
      (...args) => {
        reorderedSideEffects += 1;
        return operation(...args);
      },
    ]),
  );
  assert.throws(
    () => executeProductionRuntimeBaselineScript(
      { ...input, stdinText: reorderedInput },
      reorderedDependencies,
    ),
    { code: 'RUNTIME_INPUT_INVALID' },
  );
  assert.equal(reorderedSideEffects, 0);

  let proxyTraps = 0;
  const proxied = new Proxy(input, {
    getPrototypeOf() {
      proxyTraps += 1;
      throw new Error('private proxy');
    },
    getOwnPropertyDescriptor() {
      proxyTraps += 1;
      throw new Error('private proxy');
    },
  });
  assert.throws(
    () => executeProductionRuntimeBaselineScript(proxied, baseDependencies),
    { code: 'RUNTIME_INPUT_INVALID' },
  );
  assert.equal(proxyTraps, 0);
  assert.deepEqual(Object.keys(baseDependencies), BASELINE_EXECUTION_DEPENDENCY_FIELDS);
});

test('recovery transport adapters reject accessors and extra authority before remote execution', async (t) => {
  const home = await runtimeHome(t);
  const dependencies = createProductionRuntimeRecoveryDependencies({ AGENT_ROAD_HOME: home });
  let reads = 0;
  const hostileInspect = {};
  for (const field of [
    'target',
    'operationId',
    'beforeBootMarker',
    'priorAuthorizedAttempt',
  ]) {
    Object.defineProperty(hostileInspect, field, {
      enumerable: true,
      get() {
        reads += 1;
        throw new Error('private accessor trap');
      },
    });
  }

  assert.throws(
    () => dependencies.inspectRemote(hostileInspect),
    { code: 'RUNTIME_INPUT_INVALID' },
  );
  assert.equal(reads, 0);
  assert.throws(
    () => dependencies.applyRemote({
      target: null,
      proof: null,
      authorizedAttempt: null,
      provision: () => {},
    }),
    { code: 'RUNTIME_INPUT_INVALID' },
  );
});

test('loads only the fixed production catalog and independent local runtime state', async (t) => {
  const home = await runtimeHome(t);
  const dependencies = createProductionRuntimeDependencies({ AGENT_ROAD_HOME: home });

  const catalog = await dependencies.loadCatalog();
  assert.equal(catalog.catalogRevision, 1);
  assert.deepEqual(catalog.profiles.map(({ id }) => id), ['core', 'base']);
  assert.equal(catalog.artifacts[0].id, 'powershell-7');
  assert.deepEqual(catalog.artifacts[0].redirectOrigins, [
    'https://release-assets.githubusercontent.com',
  ]);

  const state = await dependencies.readState(DEVICE_ID);
  assert.equal(state.runtimeStatus, 'UNPROVISIONED');
  assert.equal(state.deviceId, DEVICE_ID);
  assert.equal(Object.isFrozen(state), true);
});

test('the production provision adapter enforces the exact snapshot field set and rejects accessors without invoking them', async (t) => {
  const home = await runtimeHome(t);
  const dependencies = createProductionRuntimeDependencies({ AGENT_ROAD_HOME: home });
  let reads = 0;
  const input = {};
  for (const field of ['target', 'plan', 'capsule', 'inventorySnapshot', 'artifactFiles']) {
    Object.defineProperty(input, field, {
      get() {
        reads += 1;
        throw new Error('private accessor trap');
      },
      enumerable: true,
    });
  }

  await assert.rejects(dependencies.provision(input), { code: 'RUNTIME_INPUT_INVALID' });
  assert.equal(reads, 0);

  const extraInput = {};
  for (const [field, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(input))) {
    Object.defineProperty(extraInput, field, descriptor);
  }
  Object.defineProperty(extraInput, 'privateDetail', {
    value: 'must-not-cross-adapter',
    enumerable: true,
  });
  await assert.rejects(dependencies.provision(extraInput), { code: 'RUNTIME_INPUT_INVALID' });
  assert.equal(reads, 0);

  await assert.rejects(dependencies.provision({
    target: null,
    plan: null,
    capsule: null,
    artifactFiles: null,
  }), { code: 'RUNTIME_INPUT_INVALID' });
});

test('the production provision adapter forwards the exact inventory snapshot through its pure controller seam', () => {
  assert.equal(typeof createProductionRuntimeProvisionInput, 'function');
  const input = {
    target: Object.freeze({ target: true }),
    plan: Object.freeze({ plan: true }),
    capsule: Object.freeze({ capsule: true }),
    inventorySnapshot: Object.freeze({ inventory: true }),
    artifactFiles: Object.freeze([]),
  };
  const dependencies = Object.freeze({ runProcess: () => {} });

  const result = createProductionRuntimeProvisionInput(input, dependencies);

  assert.deepEqual(Object.keys(result), [
    'target',
    'plan',
    'capsule',
    'inventorySnapshot',
    'artifactFiles',
    'dependencies',
  ]);
  for (const field of Object.keys(input)) assert.equal(result[field], input[field]);
  assert.equal(result.dependencies, dependencies);
  assert.equal(Object.isFrozen(result), true);
});
