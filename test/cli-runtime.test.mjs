import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { main } from '../src/cli.mjs';
import { RUNTIME_BASELINE_SCRIPT_PATH } from '../src/runtime/runtime-baseline.mjs';

const SHA_A = 'A'.repeat(64);
const TICKET_ID = `rct_${'b'.repeat(64)}`;
const PRIOR_TICKET_ID = `rct_${'c'.repeat(64)}`;
const PLAN_TICKET_ID = `rpt_${'d'.repeat(64)}`;
const BASELINE_ID = `rbl_${'1'.repeat(64)}`;
const OTHER_BASELINE_ID = `rbl_${'2'.repeat(64)}`;
const COMPARISON_ID = `rbc_${'3'.repeat(64)}`;
const BASELINE_CAPTURED_AT = '2026-07-30T00:00:00.000Z';
const BASELINE_EXPIRES_AT = '2026-07-31T00:00:00.000Z';
const BASELINE_SURFACE_IDS = Object.freeze([
  'account-environment',
  'account-profile-identity',
  'command-resolution',
  'external-sentinel-acls',
  'firewall-profiles',
  'firewall-rules',
  'machine-environment',
  'scheduled-tasks',
  'service-definitions',
]);

function baselineCapture(overrides = {}) {
  return {
    baselineId: BASELINE_ID,
    capturedAt: BASELINE_CAPTURED_AT,
    expiresAt: BASELINE_EXPIRES_AT,
    ...overrides,
  };
}

function baselineComparison(overrides = {}) {
  return {
    baselineId: BASELINE_ID,
    comparisonId: COMPARISON_ID,
    status: 'UNCHANGED',
    changedSurfaces: [],
    ...overrides,
  };
}

function baselineObservation() {
  return {
    schemaVersion: 1,
    protocolRevision: 1,
    surfaces: BASELINE_SURFACE_IDS.map((id, index) => ({
      id,
      count: id === 'firewall-profiles' ? 3 : index,
      mac: String(index).repeat(64),
    })),
  };
}

function baselineAggregateMac(hmacKeyBase64, surfaces) {
  const hmac = createHmac('sha256', Buffer.from(hmacKeyBase64, 'base64'));
  hmac.update(Buffer.from('AgentRoad.RuntimeBaseline.Aggregate.v1\0', 'ascii'));
  for (const surface of surfaces) {
    for (const value of [surface.id, String(surface.count), surface.mac]) {
      const bytes = Buffer.from(value, 'utf8');
      const length = Buffer.alloc(4);
      length.writeUInt32BE(bytes.length);
      hmac.update(length);
      hmac.update(bytes);
    }
  }
  return hmac.digest('hex').toUpperCase();
}

function baselineRecord(input) {
  const base = {
    schemaVersion: 1,
    recordType: 'RUNTIME_BASELINE',
    baselineId: BASELINE_ID,
    deviceId: 'dev_abc123',
    protocolRevision: 1,
    scriptSha256: input.scriptSha256,
    hmacKeyBase64: input.hmacKeyBase64,
    surfaces: input.surfaces,
    captureAggregateMac: input.captureAggregateMac,
    capturedAt: BASELINE_CAPTURED_AT,
    expiresAt: BASELINE_EXPIRES_AT,
  };
  return {
    ...base,
    recordDigest: createHash('sha256')
      .update('AgentRoad.RuntimeBaseline.Record.v1\0', 'ascii')
      .update(JSON.stringify(base), 'utf8')
      .digest('hex')
      .toUpperCase(),
  };
}

function baselineComparisonRecord(baseline, surfaces) {
  const base = {
    schemaVersion: 1,
    recordType: 'RUNTIME_BASELINE_COMPARISON',
    comparisonId: COMPARISON_ID,
    deviceId: 'dev_abc123',
    baselineId: BASELINE_ID,
    baselineRecordDigest: baseline.recordDigest,
    protocolRevision: 1,
    scriptSha256: baseline.scriptSha256,
    observedSurfaces: surfaces,
    observedAggregateMac: baselineAggregateMac(baseline.hmacKeyBase64, surfaces),
    status: 'UNCHANGED',
    changedSurfaces: [],
    comparedAt: '2026-07-30T00:00:01.000Z',
  };
  return {
    ...base,
    recordDigest: createHash('sha256')
      .update('AgentRoad.RuntimeBaseline.Comparison.v1\0', 'ascii')
      .update(JSON.stringify(base), 'utf8')
      .digest('hex')
      .toUpperCase(),
  };
}

function recoveryReady(overrides = {}) {
  return {
    schemaVersion: 1,
    status: 'RECOVERY_READY',
    deviceId: 'dev_abc123',
    displayName: 'Home Windows PC',
    targetFingerprint: 'A1B2C3D4E5F6',
    classification: 'EMPTY_PRE_TRANSACTION',
    rebootRequired: false,
    actionable: true,
    ticketId: TICKET_ID,
    ticketFingerprint: 'B1C2D3E4F5A6',
    expiresAt: '2026-07-30T00:10:00.000Z',
    ...overrides,
  };
}

function recoveryParentRequired(overrides = {}) {
  return {
    ...recoveryReady({
      status: 'RECOVERY_PARENT_REQUIRED',
      actionable: false,
    }),
    eligibleAfter: null,
    ...overrides,
  };
}

function recoveryApplyRequired(overrides = {}) {
  return recoveryReady({
    status: 'RECOVERY_APPLY_REQUIRED',
    actionable: false,
    ...overrides,
  });
}

function recovered(overrides = {}) {
  return {
    schemaVersion: 1,
    status: 'RECOVERED',
    deviceId: 'dev_abc123',
    displayName: 'Home Windows PC',
    targetFingerprint: 'A1B2C3D4E5F6',
    classification: 'EMPTY_PRE_TRANSACTION',
    ticketFingerprint: 'B1C2D3E4F5A6',
    disposition: 'REMOVED',
    ...overrides,
  };
}

const INVENTORY = {
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

function readyState(deviceId = 'dev_abc123', profiles = ['core']) {
  return {
    schemaVersion: 1,
    deviceId,
    runtimeStatus: 'READY',
    requestedProfiles: profiles,
    readyProfiles: profiles,
    operationId: null,
    manifestDigest: null,
    generationDigest: SHA_A,
    failureCode: null,
    updatedAt: '2026-07-30T00:00:00.000Z',
  };
}

function planReview() {
  return {
    schemaVersion: 1,
    status: 'PLAN_REVIEW_READY',
    planTicketId: PLAN_TICKET_ID,
    plan: {
      status: 'actionable',
      blockers: [],
      requestedProfiles: ['core'],
      resolvedProfiles: ['core'],
      acquisition: 'mac-relay',
      transactionMode: 'new',
      requiredFreeBytes: 268_436_603,
      artifacts: [],
    },
    controller: {
      controllerKeyId: SHA_A,
      firstTrustPinningRequired: true,
    },
    mutators: {
      inventoryRevision: 'A'.repeat(12),
      provisionRevision: 'B'.repeat(12),
      recoveryRevision: 'C'.repeat(12),
    },
    mutationScope: {
      runtimeRoot: 'C:\\ProgramData\\AgentRoad\\runtime',
      allowedDescendants: [
        'staging/<operationId>',
        'trust/controller-key.json',
        'versions/<manifestDigest>',
        'versions/.rollback-<manifestDigest>',
        'versions/.retired-<manifestDigest>',
        'state/journal.json',
        'state/active.json',
        'state/previous.json',
      ],
    },
    transportScope: {
      transportRoot: 'C:\\ProgramData\\AgentRoad\\tasks',
      allowedDescendants: [
        '<transportOperationId>.ps1',
        '<transportOperationId>.result.json',
        '<transportOperationId>.result.json.tmp',
      ],
      operationSets: {
        noOp: 0,
        actionableMaximum: 2,
        roles: ['inventory', 'provision'],
        identifier: 'fresh-lowercase-hex-32-per-set',
        distinct: true,
      },
      lifecycle: {
        create: 'root-if-absent-and-operation-files-as-needed',
        verify: 'root-acl-and-script-bytes-before-execute',
        execute: 'verified-operation-script-without-retry',
        result: 'temporary-write-atomic-publish-then-read',
        cleanup: 'attempt-all-three-operation-files-after-staging',
      },
      temporariness: {
        transportRoot: 'may-create-and-retain',
        normal: 'cleanup-attempted-for-all-three-operation-files',
        uncertain: 'bounded-operation-file-residue-may-remain',
      },
    },
    nonMutationClaims: {
      pathEnvironment: 'not-mutated',
      registryRegistration: 'not-mutated',
      services: 'not-mutated',
      scheduledTasks: 'not-mutated',
      firewall: 'not-mutated',
      userProfiles: 'not-mutated',
      unrelatedAcls: 'not-mutated',
    },
  };
}

function captureIo() {
  let stdout = '';
  let stderr = '';
  return {
    stdout: { write(value) { stdout += value; } },
    stderr: { write(value) { stderr += value; } },
    stdoutValue: () => stdout,
    stderrValue: () => stderr,
  };
}

test('help documents runtime recovery and baseline commands without removing existing commands', async () => {
  const io = captureIo();
  assert.equal(await main(['--help'], {}, io), 0);
  for (const expected of [
    'agent-road enroll',
    'agent-road list',
    'agent-road status <device-id>',
    'agent-road exec <device-id>',
    'agent-road put <device-id>',
    'agent-road get <device-id>',
    'agent-road doctor <device-id>',
    'agent-road runtime-plan <device-id> --profile <core|base> --baseline <baseline-id>',
    'agent-road prepare <device-id> --profile <core|base> --approved <plan-ticket-id>',
    'agent-road runtime-status <device-id>',
    'agent-road runtime-recover <device-id> --inspect [--prior-ticket <ticket-id>]',
    'agent-road runtime-recover <device-id> --apply --ticket <ticket-id>',
    'agent-road runtime-baseline <device-id> --capture',
    'agent-road runtime-baseline <device-id> --compare --baseline <baseline-id>',
  ]) assert.equal(io.stdoutValue().includes(expected), true);
  assert.equal(io.stderrValue(), '');
});

test('runtime-baseline delegates immutable exact capture and compare controller inputs to its separate factory', async () => {
  const runtimeBaselineDependencyFactory = () => assert.fail('controller owns dependency creation');
  const calls = [];
  const runtime = {
    runtimeBaselineDependencyFactory,
    captureRuntimeBaseline: async (input) => {
      calls.push(['capture', input]);
      return baselineCapture();
    },
    compareRuntimeBaseline: async (input) => {
      calls.push(['compare', input]);
      return baselineComparison();
    },
  };

  for (const [args, expectedKind, expectedResult] of [
    [
      ['runtime-baseline', 'dev_abc123', '--capture'],
      'capture',
      baselineCapture(),
    ],
    [
      ['runtime-baseline', 'dev_abc123', '--compare', '--baseline', BASELINE_ID],
      'compare',
      baselineComparison(),
    ],
  ]) {
    const io = captureIo();
    assert.equal(await main(args, {}, { ...runtime, stdout: io.stdout, stderr: io.stderr }), 0);
    assert.equal(io.stdoutValue(), `${JSON.stringify(expectedResult)}\n`);
    assert.equal(io.stderrValue(), '');
    const [kind, input] = calls.shift();
    assert.equal(kind, expectedKind);
    assert.equal(input.deviceId, 'dev_abc123');
    assert.equal(input.dependencyFactory, runtimeBaselineDependencyFactory);
    assert.equal(Object.isFrozen(input), true);
    if (kind === 'capture') {
      assert.deepEqual(Object.keys(input).sort(), ['dependencyFactory', 'deviceId']);
    } else {
      assert.deepEqual(Object.keys(input).sort(), ['baselineId', 'dependencyFactory', 'deviceId']);
      assert.equal(input.baselineId, BASELINE_ID);
    }
  }
});

test('runtime-baseline default controllers project the union factory to each exact dependency schema', async () => {
  const scriptBytes = await readFile(RUNTIME_BASELINE_SCRIPT_PATH);
  const scriptSha256 = createHash('sha256').update(scriptBytes).digest('hex').toUpperCase();
  const observation = baselineObservation();
  const key = Buffer.alloc(32, 7).toString('base64');
  const storedBaseline = baselineRecord({
    scriptSha256,
    hmacKeyBase64: key,
    surfaces: observation.surfaces,
    captureAggregateMac: baselineAggregateMac(key, observation.surfaces),
  });
  const calls = [];
  const dependencies = {
    executeBaselineScript: async (input) => {
      calls.push(['execute', input]);
      return {
        schemaVersion: 1,
        operation: 'exec',
        deviceId: 'dev_abc123',
        address: '100.64.0.10',
        exitCode: 0,
        stdout: JSON.stringify(observation),
        stderr: '',
        startedAt: '2026-07-30T00:00:00.000Z',
        finishedAt: '2026-07-30T00:00:01.000Z',
      };
    },
    createBaseline: async (input) => {
      calls.push(['createBaseline', input]);
      return baselineRecord(input);
    },
    readBaseline: async (input) => {
      calls.push(['readBaseline', input]);
      return storedBaseline;
    },
    createComparison: async (input) => {
      calls.push(['createComparison', input]);
      return baselineComparisonRecord(storedBaseline, input.observedSurfaces);
    },
    randomBytes: () => {
      calls.push(['randomBytes']);
      return Buffer.alloc(32, 7);
    },
  };
  const runtimeBaselineDependencyFactory = () => Object.freeze(dependencies);

  const captureOutput = captureIo();
  assert.equal(await main(['runtime-baseline', 'dev_abc123', '--capture'], {}, {
    stdout: captureOutput.stdout,
    stderr: captureOutput.stderr,
    runtimeBaselineDependencyFactory,
  }), 0);
  assert.equal(captureOutput.stdoutValue(), `${JSON.stringify(baselineCapture())}\n`);
  assert.equal(captureOutput.stderrValue(), '');
  assert.deepEqual(calls.map(([name]) => name), [
    'randomBytes',
    'execute',
    'createBaseline',
  ]);

  calls.length = 0;
  const compareIo = captureIo();
  assert.equal(await main(
    ['runtime-baseline', 'dev_abc123', '--compare', '--baseline', BASELINE_ID],
    {},
    {
      stdout: compareIo.stdout,
      stderr: compareIo.stderr,
      runtimeBaselineDependencyFactory,
    },
  ), 0);
  assert.equal(compareIo.stdoutValue(), `${JSON.stringify(baselineComparison())}\n`);
  assert.equal(compareIo.stderrValue(), '');
  assert.deepEqual(calls.map(([name]) => name), [
    'readBaseline',
    'execute',
    'createComparison',
  ]);
});

test('runtime-baseline default controllers reject hostile union factories without invoking traps', async () => {
  let accessorReads = 0;
  const accessor = {};
  for (const field of [
    'executeBaselineScript',
    'createBaseline',
    'readBaseline',
    'createComparison',
    'randomBytes',
  ]) {
    Object.defineProperty(accessor, field, {
      enumerable: true,
      get() {
        accessorReads += 1;
        throw new Error('private accessor');
      },
    });
  }
  const accessorIo = captureIo();
  assert.equal(await main(['runtime-baseline', 'dev_abc123', '--capture'], {}, {
    stdout: accessorIo.stdout,
    stderr: accessorIo.stderr,
    runtimeBaselineDependencyFactory: () => accessor,
  }), 2);
  assert.equal(accessorReads, 0);
  assert.equal(accessorIo.stdoutValue(), '');
  assert.equal(accessorIo.stderrValue(), 'RUNTIME_INPUT_INVALID\n');

  let proxyTraps = 0;
  const proxied = new Proxy({}, {
    getPrototypeOf() {
      proxyTraps += 1;
      throw new Error('private proxy');
    },
    ownKeys() {
      proxyTraps += 1;
      throw new Error('private proxy');
    },
  });
  const proxyIo = captureIo();
  assert.equal(await main(['runtime-baseline', 'dev_abc123', '--capture'], {}, {
    stdout: proxyIo.stdout,
    stderr: proxyIo.stderr,
    runtimeBaselineDependencyFactory: () => proxied,
  }), 2);
  assert.equal(proxyTraps, 0);
  assert.equal(proxyIo.stdoutValue(), '');
  assert.equal(proxyIo.stderrValue(), 'RUNTIME_INPUT_INVALID\n');
});

test('runtime-baseline rejects ambiguous repeated malformed or non-exact IDs before hooks', async () => {
  const invalid = [
    ['runtime-baseline'],
    ['runtime-baseline', 'dev_abc123'],
    ['runtime-baseline', 'dev_abc123', '--capture', '--compare', '--baseline', BASELINE_ID],
    ['runtime-baseline', 'dev_abc123', '--capture', '--baseline', BASELINE_ID],
    ['runtime-baseline', 'dev_abc123', '--compare'],
    ['runtime-baseline', 'dev_abc123', '--compare', '--baseline', BASELINE_ID, '--capture'],
    ['runtime-baseline', 'dev_abc123', '--capture', '--capture'],
    ['runtime-baseline', 'dev_abc123', '--compare', '--compare', '--baseline', BASELINE_ID],
    ['runtime-baseline', 'dev_abc123', '--compare', '--baseline', BASELINE_ID, '--baseline', BASELINE_ID],
    ['runtime-baseline', 'dev_abc123', '--compare', '--baseline', 'latest'],
    ['runtime-baseline', 'dev_abc123', '--compare', '--baseline', `rbl_${'A'.repeat(64)}`],
    ['runtime-baseline', 'dev_abc123', '--compare', '--baseline', 'rbl_short'],
    ['runtime-baseline', 'dev_abc123', 'extra', '--capture'],
    ['runtime-baseline', 'INVALID', '--capture'],
  ];
  for (const args of invalid) {
    const io = captureIo();
    let factoryCalls = 0;
    let hookCalls = 0;
    assert.equal(await main(args, {}, {
      stdout: io.stdout,
      stderr: io.stderr,
      runtimeBaselineDependencyFactory: () => { factoryCalls += 1; },
      captureRuntimeBaseline: () => { hookCalls += 1; },
      compareRuntimeBaseline: () => { hookCalls += 1; },
    }), 2, args.join(' '));
    assert.equal(io.stdoutValue(), '', args.join(' '));
    assert.equal(io.stderrValue(), 'RUNTIME_INPUT_INVALID\n', args.join(' '));
    assert.equal(factoryCalls, 0, args.join(' '));
    assert.equal(hookCalls, 0, args.join(' '));
  }
});

test('runtime-baseline validates only canonical controller results and rejects hostile results without traps', async () => {
  const invalidCaptures = [
    baselineCapture({ baselineId: `rbl_${'A'.repeat(64)}` }),
    baselineCapture({ capturedAt: 'not-a-timestamp' }),
    baselineCapture({ expiresAt: BASELINE_CAPTURED_AT }),
    baselineCapture({ hmacKeyBase64: Buffer.alloc(32, 7).toString('base64') }),
  ];
  for (const result of invalidCaptures) {
    const io = captureIo();
    assert.equal(await main(['runtime-baseline', 'dev_abc123', '--capture'], {}, {
      stdout: io.stdout,
      stderr: io.stderr,
      runtimeBaselineDependencyFactory: () => {},
      captureRuntimeBaseline: () => result,
    }), 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), 'RUNTIME_INPUT_INVALID\n');
  }

  const invalidComparisons = [
    baselineComparison({ baselineId: OTHER_BASELINE_ID }),
    baselineComparison({ comparisonId: `rbc_${'A'.repeat(64)}` }),
    baselineComparison({ status: 'CHANGED' }),
    baselineComparison({ changedSurfaces: [{
      id: BASELINE_SURFACE_IDS[0],
      countChanged: false,
      macChanged: true,
    }] }),
    baselineComparison({ status: 'CHANGED', changedSurfaces: [{
      id: BASELINE_SURFACE_IDS[0],
      countChanged: false,
      macChanged: false,
    }] }),
    baselineComparison({ status: 'CHANGED', changedSurfaces: [
      { id: BASELINE_SURFACE_IDS[1], countChanged: true, macChanged: false },
      { id: BASELINE_SURFACE_IDS[0], countChanged: true, macChanged: false },
    ] }),
    baselineComparison({ address: '100.64.0.10' }),
  ];
  for (const result of invalidComparisons) {
    const io = captureIo();
    assert.equal(await main(
      ['runtime-baseline', 'dev_abc123', '--compare', '--baseline', BASELINE_ID],
      {},
      {
        stdout: io.stdout,
        stderr: io.stderr,
        runtimeBaselineDependencyFactory: () => {},
        compareRuntimeBaseline: () => result,
      },
    ), 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), 'RUNTIME_INPUT_INVALID\n');
  }

  const changed = baselineComparison({
    status: 'CHANGED',
    changedSurfaces: [{
      id: BASELINE_SURFACE_IDS[7],
      countChanged: true,
      macChanged: false,
    }],
  });
  const changedIo = captureIo();
  assert.equal(await main(
    ['runtime-baseline', 'dev_abc123', '--compare', '--baseline', BASELINE_ID],
    {},
    {
      stdout: changedIo.stdout,
      stderr: changedIo.stderr,
      runtimeBaselineDependencyFactory: () => {},
      compareRuntimeBaseline: () => changed,
    },
  ), 0);
  assert.equal(changedIo.stdoutValue(), `${JSON.stringify(changed)}\n`);
  assert.doesNotMatch(changedIo.stdoutValue(), /hmacKey|"surfaces":|100[.]64|ProgramData/u);

  let accessorReads = 0;
  const accessor = baselineCapture();
  Object.defineProperty(accessor, 'baselineId', {
    enumerable: true,
    get() {
      accessorReads += 1;
      return BASELINE_ID;
    },
  });
  const accessorIo = captureIo();
  assert.equal(await main(['runtime-baseline', 'dev_abc123', '--capture'], {}, {
    stdout: accessorIo.stdout,
    stderr: accessorIo.stderr,
    runtimeBaselineDependencyFactory: () => {},
    captureRuntimeBaseline: () => accessor,
  }), 2);
  assert.equal(accessorReads, 0);
  assert.equal(accessorIo.stdoutValue(), '');
  assert.equal(accessorIo.stderrValue(), 'RUNTIME_INPUT_INVALID\n');

  let proxyTraps = 0;
  const proxied = new Proxy(baselineComparison(), {
    getPrototypeOf() {
      proxyTraps += 1;
      throw new Error('private proxy');
    },
    getOwnPropertyDescriptor() {
      proxyTraps += 1;
      throw new Error('private proxy');
    },
  });
  const proxyIo = captureIo();
  assert.equal(await main(
    ['runtime-baseline', 'dev_abc123', '--compare', '--baseline', BASELINE_ID],
    {},
    {
      stdout: proxyIo.stdout,
      stderr: proxyIo.stderr,
      runtimeBaselineDependencyFactory: () => {},
      compareRuntimeBaseline: () => proxied,
    },
  ), 2);
  assert.equal(proxyTraps, 0);
  assert.equal(proxyIo.stdoutValue(), '');
  assert.equal(proxyIo.stderrValue(), 'RUNTIME_INPUT_INVALID\n');
});

test('runtime-baseline exposes only its finite read-only error set', async () => {
  for (const [code, expected] of [
    ['RUNTIME_ALREADY_RUNNING', 'RUNTIME_ALREADY_RUNNING'],
    ['RUNTIME_INVENTORY_FAILED', 'RUNTIME_INVENTORY_FAILED'],
    ['RUNTIME_STATE_UNSUPPORTED', 'RUNTIME_STATE_UNSUPPORTED'],
    ['RUNTIME_COMPLETION_UNCERTAIN', 'RUNTIME_INTERNAL_ERROR'],
    ['RUNTIME_ARTIFACT_INTEGRITY_FAILED', 'RUNTIME_INTERNAL_ERROR'],
    ['PRIVATE_SECRET_PATH', 'RUNTIME_INTERNAL_ERROR'],
  ]) {
    const io = captureIo();
    assert.equal(await main(['runtime-baseline', 'dev_abc123', '--capture'], {}, {
      stdout: io.stdout,
      stderr: io.stderr,
      runtimeBaselineDependencyFactory: () => {},
      captureRuntimeBaseline: () => {
        throw Object.assign(new Error('/Users/private/key'), { code });
      },
    }), 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), `${expected}\n`);
    assert.doesNotMatch(io.stderrValue(), /private|key/u);
  }
});

test('runtime-recover delegates exact inspect and apply inputs to the separate recovery factory', async () => {
  const runtimeRecoveryDependencyFactory = () => assert.fail('controller owns dependency creation');
  const calls = [];
  const runtime = {
    runtimeRecoveryDependencyFactory,
    inspectRuntimeRecovery: async (input) => {
      calls.push(['inspect', input]);
      return recoveryReady();
    },
    applyRuntimeRecovery: async (input) => {
      calls.push(['apply', input]);
      return recovered();
    },
  };

  for (const [args, expectedKind, expectedResult] of [
    [
      ['runtime-recover', 'dev_abc123', '--inspect'],
      'inspect',
      recoveryReady(),
    ],
    [
      ['runtime-recover', 'dev_abc123', '--inspect', '--prior-ticket', PRIOR_TICKET_ID],
      'inspect',
      recoveryReady(),
    ],
    [
      ['runtime-recover', 'dev_abc123', '--apply', '--ticket', TICKET_ID],
      'apply',
      recovered(),
    ],
  ]) {
    const io = captureIo();
    assert.equal(await main(args, {}, { ...runtime, stdout: io.stdout, stderr: io.stderr }), 0);
    assert.equal(io.stdoutValue(), `${JSON.stringify(expectedResult)}\n`);
    assert.equal(io.stderrValue(), '');
    const [kind, input] = calls.shift();
    assert.equal(kind, expectedKind);
    assert.equal(input.deviceId, 'dev_abc123');
    assert.equal(input.dependencyFactory, runtimeRecoveryDependencyFactory);
    if (kind === 'apply') {
      assert.deepEqual(Object.keys(input).sort(), ['dependencyFactory', 'deviceId', 'ticketId']);
      assert.equal(input.ticketId, TICKET_ID);
    } else {
      assert.deepEqual(Object.keys(input).sort(), ['dependencyFactory', 'deviceId', 'priorTicketId']);
      assert.equal(
        input.priorTicketId,
        args.includes('--prior-ticket') ? PRIOR_TICKET_ID : null,
      );
    }
  }
});

test('runtime-recover emits exact structured inspect handoffs without widening authority', async () => {
  for (const result of [
    recoveryParentRequired(),
    recoveryParentRequired({ eligibleAfter: '2026-07-30T00:10:00.000Z' }),
    recoveryApplyRequired(),
  ]) {
    const io = captureIo();
    assert.equal(await main(['runtime-recover', 'dev_abc123', '--inspect'], {}, {
      stdout: io.stdout,
      stderr: io.stderr,
      runtimeRecoveryDependencyFactory: () => {},
      inspectRuntimeRecovery: () => result,
    }), 0);
    assert.equal(io.stdoutValue(), `${JSON.stringify(result)}\n`);
    assert.equal(io.stderrValue(), '');
    assert.doesNotMatch(
      io.stdoutValue(),
      /authorizationParent|operationId|proofDigest|manifestDigest|generationDigest/u,
    );
  }
});

test('runtime-recover rejects ambiguous, repeated, malformed, or cross-mode tickets before hooks', async () => {
  const invalid = [
    ['runtime-recover', 'dev_abc123'],
    ['runtime-recover', 'dev_abc123', '--inspect', '--apply', '--ticket', TICKET_ID],
    ['runtime-recover', 'dev_abc123', '--inspect', '--ticket', TICKET_ID],
    ['runtime-recover', 'dev_abc123', '--apply'],
    ['runtime-recover', 'dev_abc123', '--apply', '--ticket', TICKET_ID, '--prior-ticket', PRIOR_TICKET_ID],
    ['runtime-recover', 'dev_abc123', '--inspect', '--inspect'],
    ['runtime-recover', 'dev_abc123', '--apply', '--apply', '--ticket', TICKET_ID],
    ['runtime-recover', 'dev_abc123', '--apply', '--ticket', TICKET_ID, '--ticket', TICKET_ID],
    ['runtime-recover', 'dev_abc123', '--inspect', '--prior-ticket', PRIOR_TICKET_ID, '--prior-ticket', PRIOR_TICKET_ID],
    ['runtime-recover', 'dev_abc123', '--apply', '--ticket', 'latest'],
    ['runtime-recover', 'dev_abc123', '--apply', '--ticket', `rct_${'A'.repeat(64)}`],
    ['runtime-recover', 'dev_abc123', '--inspect', '--prior-ticket', 'rct_short'],
    ['runtime-recover', 'dev_abc123', 'extra', '--inspect'],
  ];
  for (const args of invalid) {
    const io = captureIo();
    let factoryCalls = 0;
    let hookCalls = 0;
    assert.equal(await main(args, {}, {
      stdout: io.stdout,
      stderr: io.stderr,
      runtimeRecoveryDependencyFactory: () => { factoryCalls += 1; },
      inspectRuntimeRecovery: () => { hookCalls += 1; },
      applyRuntimeRecovery: () => { hookCalls += 1; },
    }), 2, args.join(' '));
    assert.equal(io.stdoutValue(), '', args.join(' '));
    assert.equal(io.stderrValue(), 'RUNTIME_INPUT_INVALID\n', args.join(' '));
    assert.equal(factoryCalls, 0, args.join(' '));
    assert.equal(hookCalls, 0, args.join(' '));
  }
});

test('runtime-recover validates canonical redacted results and admits boot identity failure', async () => {
  const boundedNameResult = recovered({ displayName: 'x'.repeat(300) });
  const boundedNameIo = captureIo();
  assert.equal(await main(
    ['runtime-recover', 'dev_abc123', '--apply', '--ticket', TICKET_ID],
    {},
    {
      stdout: boundedNameIo.stdout,
      stderr: boundedNameIo.stderr,
      runtimeRecoveryDependencyFactory: () => {},
      applyRuntimeRecovery: () => boundedNameResult,
    },
  ), 0);
  assert.equal(boundedNameIo.stdoutValue(), `${JSON.stringify(boundedNameResult)}\n`);
  assert.equal(boundedNameIo.stderrValue(), '');

  for (const result of [
    recoveryReady({ deviceId: 'dev_other' }),
    recoveryReady({ address: '100.64.0.1' }),
    recoveryReady({ targetFingerprint: SHA_A }),
    recoveryReady({ ticketId: 'latest' }),
    recoveryReady({ actionable: false }),
    recoveryReady({ eligibleAfter: null }),
    recoveryReady({ displayName: 'x'.repeat(513) }),
    recoveryParentRequired({ actionable: true }),
    recoveryParentRequired({ eligibleAfter: 'not-a-timestamp' }),
    recoveryParentRequired({ eligibleAfter: '2026-07-30T00:09:59.000Z' }),
    (() => {
      const result = recoveryParentRequired();
      delete result.eligibleAfter;
      return result;
    })(),
    recoveryApplyRequired({ actionable: true }),
    recoveryApplyRequired({ eligibleAfter: null }),
    recoveryApplyRequired({ rebootRequired: true }),
    recoveryApplyRequired({ ticketId: 'latest' }),
    recoveryApplyRequired({ expiresAt: 'not-a-timestamp' }),
    recovered({ disposition: 'ALREADY_ABSENT' }),
    recovered({ operationId: 'a'.repeat(32) }),
  ]) {
    const io = captureIo();
    const apply = result.status === 'RECOVERED';
    assert.equal(await main(
      apply
        ? ['runtime-recover', 'dev_abc123', '--apply', '--ticket', TICKET_ID]
        : ['runtime-recover', 'dev_abc123', '--inspect'],
      {},
      {
        stdout: io.stdout,
        stderr: io.stderr,
        runtimeRecoveryDependencyFactory: () => {},
        inspectRuntimeRecovery: () => result,
        applyRuntimeRecovery: () => result,
      },
    ), 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), 'RUNTIME_INPUT_INVALID\n');
  }

  const io = captureIo();
  assert.equal(await main(['runtime-recover', 'dev_abc123', '--inspect'], {}, {
    stdout: io.stdout,
    stderr: io.stderr,
    runtimeRecoveryDependencyFactory: () => {},
    inspectRuntimeRecovery: () => {
      throw Object.assign(new Error('private boot detail'), {
        code: 'RUNTIME_BOOT_IDENTITY_UNAVAILABLE',
      });
    },
  }), 2);
  assert.equal(io.stdoutValue(), '');
  assert.equal(io.stderrValue(), 'RUNTIME_BOOT_IDENTITY_UNAVAILABLE\n');
});

test('runtime-recover rejects cross-mode and hostile handoff results without invoking traps', async () => {
  for (const [args, result] of [
    [
      ['runtime-recover', 'dev_abc123', '--inspect'],
      recovered(),
    ],
    [
      ['runtime-recover', 'dev_abc123', '--apply', '--ticket', TICKET_ID],
      recoveryParentRequired(),
    ],
    [
      ['runtime-recover', 'dev_abc123', '--apply', '--ticket', TICKET_ID],
      recoveryApplyRequired(),
    ],
  ]) {
    const io = captureIo();
    assert.equal(await main(args, {}, {
      stdout: io.stdout,
      stderr: io.stderr,
      runtimeRecoveryDependencyFactory: () => {},
      inspectRuntimeRecovery: () => result,
      applyRuntimeRecovery: () => result,
    }), 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), 'RUNTIME_INPUT_INVALID\n');
  }

  let accessorReads = 0;
  const accessor = recoveryApplyRequired();
  Object.defineProperty(accessor, 'status', {
    enumerable: true,
    get() {
      accessorReads += 1;
      return 'RECOVERY_APPLY_REQUIRED';
    },
  });
  const accessorIo = captureIo();
  assert.equal(await main(['runtime-recover', 'dev_abc123', '--inspect'], {}, {
    stdout: accessorIo.stdout,
    stderr: accessorIo.stderr,
    runtimeRecoveryDependencyFactory: () => {},
    inspectRuntimeRecovery: () => accessor,
  }), 2);
  assert.equal(accessorReads, 0);
  assert.equal(accessorIo.stdoutValue(), '');
  assert.equal(accessorIo.stderrValue(), 'RUNTIME_INPUT_INVALID\n');

  let proxyTraps = 0;
  const proxied = new Proxy(recoveryApplyRequired(), {
    getPrototypeOf() {
      proxyTraps += 1;
      throw new Error('PROXY_TRAP');
    },
    getOwnPropertyDescriptor() {
      proxyTraps += 1;
      throw new Error('PROXY_TRAP');
    },
  });
  const proxyIo = captureIo();
  assert.equal(await main(['runtime-recover', 'dev_abc123', '--inspect'], {}, {
    stdout: proxyIo.stdout,
    stderr: proxyIo.stderr,
    runtimeRecoveryDependencyFactory: () => {},
    inspectRuntimeRecovery: () => proxied,
  }), 2);
  assert.equal(proxyTraps, 0);
  assert.equal(proxyIo.stdoutValue(), '');
  assert.equal(proxyIo.stderrValue(), 'RUNTIME_INPUT_INVALID\n');
});

test('runtime-recover error codes remain exact to inspect and apply authority', async () => {
  for (const [args, code, expected] of [
    [
      ['runtime-recover', 'dev_abc123', '--inspect'],
      'RUNTIME_COMPLETION_UNCERTAIN',
      'RUNTIME_INTERNAL_ERROR',
    ],
    [
      ['runtime-recover', 'dev_abc123', '--inspect'],
      'RUNTIME_ARTIFACT_INTEGRITY_FAILED',
      'RUNTIME_INTERNAL_ERROR',
    ],
    [
      ['runtime-recover', 'dev_abc123', '--apply', '--ticket', TICKET_ID],
      'RUNTIME_COMPLETION_UNCERTAIN',
      'RUNTIME_COMPLETION_UNCERTAIN',
    ],
  ]) {
    const io = captureIo();
    const operation = () => { throw Object.assign(new Error('private detail'), { code }); };
    assert.equal(await main(args, {}, {
      stdout: io.stdout,
      stderr: io.stderr,
      runtimeRecoveryDependencyFactory: () => {},
      inspectRuntimeRecovery: operation,
      applyRuntimeRecovery: operation,
    }), 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), `${expected}\n`);
  }

  const legacyIo = captureIo();
  assert.equal(await main(['runtime-status', 'dev_abc123'], {}, {
    stdout: legacyIo.stdout,
    stderr: legacyIo.stderr,
    runtimeDependencyFactory: () => {},
    runtimeStatus: () => {
      throw Object.assign(new Error('private detail'), {
        code: 'RUNTIME_BOOT_IDENTITY_UNAVAILABLE',
      });
    },
  }), 2);
  assert.equal(legacyIo.stdoutValue(), '');
  assert.equal(legacyIo.stderrValue(), 'RUNTIME_INTERNAL_ERROR\n');
});

test('doctor runtime-plan approved prepare and runtime-status delegate separate exact inputs', async () => {
  const runtimeDependencyFactory = () => assert.fail('CLI must delegate dependency creation');
  const runtimePlanDependencyFactory = () => assert.fail('plan controller owns dependency creation');
  const approvedRuntimeDependencyFactory = () => assert.fail('approved controller owns dependency creation');
  const calls = [];
  const runtime = {
    runtimeDependencyFactory,
    runtimePlanDependencyFactory,
    approvedRuntimeDependencyFactory,
    doctorRuntime: async (input) => {
      calls.push(['doctor', input]);
      return structuredClone(INVENTORY);
    },
    reviewRuntimePlan: (input) => {
      calls.push(['plan', input]);
      return planReview();
    },
    prepareApprovedRuntime: (input) => {
      calls.push(['prepare', input]);
      return readyState(input.deviceId, input.requestedProfiles);
    },
    runtimeStatus: async (input) => {
      calls.push(['status', input]);
      return readyState(input.deviceId);
    },
  };

  for (const [args, kind, expected] of [
    [['doctor', 'dev_abc123'], 'doctor', INVENTORY],
    [[
      'runtime-plan', 'dev_abc123', '--profile', 'core', '--baseline', BASELINE_ID,
    ], 'plan', planReview()],
    [[
      'prepare', 'dev_abc123', '--profile', 'core', '--approved', PLAN_TICKET_ID,
    ], 'prepare', readyState()],
    [['runtime-status', 'dev_abc123'], 'status', readyState()],
  ]) {
    const io = captureIo();
    const exitCode = await main(args, {}, { ...runtime, stdout: io.stdout, stderr: io.stderr });
    assert.equal(exitCode, 0);
    assert.equal(io.stdoutValue(), `${JSON.stringify(expected)}\n`);
    assert.equal(io.stderrValue(), '');
    const [observedKind, input] = calls.shift();
    assert.equal(observedKind, kind);
    assert.equal(input.deviceId, 'dev_abc123');
    if (kind === 'plan') {
      assert.equal(input.dependencyFactory, runtimePlanDependencyFactory);
      assert.equal(input.baselineId, BASELINE_ID);
      assert.deepEqual(input.requestedProfiles, ['core']);
    } else if (kind === 'prepare') {
      assert.equal(input.dependencyFactory, approvedRuntimeDependencyFactory);
      assert.equal(input.planTicketId, PLAN_TICKET_ID);
      assert.deepEqual(input.requestedProfiles, ['core']);
    } else {
      assert.equal(input.dependencyFactory, runtimeDependencyFactory);
      assert.deepEqual(Object.keys(input).sort(), ['dependencyFactory', 'deviceId']);
    }
  }
});

test('runtime commands reject malformed syntax before any runtime hook or factory call', async () => {
  const invalid = [
    ['doctor'],
    ['doctor', 'dev_abc123', 'extra'],
    ['doctor', 'dev_abc123', '--profile', 'core'],
    ['runtime-status'],
    ['runtime-status', 'dev_abc123', 'extra'],
    ['prepare', 'dev_abc123'],
    ['prepare', 'dev_abc123', '--profile', 'core'],
    ['prepare', 'dev_abc123', '--profile', 'core', '--approved', 'latest'],
    ['prepare', 'dev_abc123', '--profile', 'core', '--approved', `rpt_${'a'.repeat(63)}`],
    ['prepare', 'dev_abc123', '--profile', 'core', '--approved', `${PLAN_TICKET_ID}0`],
    ['prepare', 'dev_abc123', '--profile', 'core', '--approved', `rpt_${'D'.repeat(64)}`],
    ['prepare', 'dev_abc123', '--profile', 'core', '--approved', PLAN_TICKET_ID, '--approved', PLAN_TICKET_ID],
    ['prepare', 'dev_abc123', '--profile', 'core', '--profile', 'core'],
    ['prepare', 'dev_abc123', '--profile', 'web'],
    ['prepare', 'dev_abc123', '--unknown', 'core'],
    ['prepare', 'INVALID', '--profile', 'core'],
    ['runtime-plan', 'dev_abc123', '--profile', 'core'],
    ['runtime-plan', 'dev_abc123', '--profile', 'core', '--baseline', 'latest'],
    ['runtime-plan', 'dev_abc123', '--profile', 'core', '--baseline', BASELINE_ID, '--baseline', BASELINE_ID],
    ['runtime-status', `dev_${'a'.repeat(61)}`],
  ];
  for (const args of invalid) {
    const io = captureIo();
    let factoryCalls = 0;
    let hookCalls = 0;
    const exitCode = await main(args, {}, {
      stdout: io.stdout,
      stderr: io.stderr,
      runtimeDependencyFactory: () => { factoryCalls += 1; },
      runtimePlanDependencyFactory: () => { factoryCalls += 1; },
      approvedRuntimeDependencyFactory: () => { factoryCalls += 1; },
      doctorRuntime: () => { hookCalls += 1; },
      reviewRuntimePlan: () => { hookCalls += 1; },
      prepareApprovedRuntime: () => { hookCalls += 1; },
      runtimeStatus: () => { hookCalls += 1; },
    });
    assert.equal(exitCode, 2, args.join(' '));
    assert.equal(io.stdoutValue(), '', args.join(' '));
    assert.equal(io.stderrValue(), 'RUNTIME_INPUT_INVALID\n', args.join(' '));
    assert.equal(factoryCalls, 0, args.join(' '));
    assert.equal(hookCalls, 0, args.join(' '));
  }
});

test('approved prepare accepts base syntax and delegates availability gating before factory creation', async () => {
  const io = captureIo();
  let factoryCalls = 0;
  const approvedRuntimeDependencyFactory = () => { factoryCalls += 1; };
  const exitCode = await main([
    'prepare', 'dev_abc123', '--profile', 'base', '--approved', PLAN_TICKET_ID,
  ], {}, {
    stdout: io.stdout,
    stderr: io.stderr,
    approvedRuntimeDependencyFactory,
    prepareApprovedRuntime: ({ requestedProfiles, planTicketId, dependencyFactory }) => {
      assert.deepEqual(requestedProfiles, ['base']);
      assert.equal(planTicketId, PLAN_TICKET_ID);
      assert.equal(dependencyFactory, approvedRuntimeDependencyFactory);
      throw Object.assign(new Error('base is not shipped'), { code: 'RUNTIME_PROFILE_UNAVAILABLE' });
    },
  });

  assert.equal(exitCode, 2);
  assert.equal(factoryCalls, 0);
  assert.equal(io.stdoutValue(), '');
  assert.equal(io.stderrValue(), 'RUNTIME_PROFILE_UNAVAILABLE\n');
});

test('runtime failures expose only finite stable codes and never raw messages', async () => {
  for (const [code, expected] of [
    ['RUNTIME_DISK_INSUFFICIENT', 'RUNTIME_DISK_INSUFFICIENT'],
    ['RUNTIME_FAKE_SECRET', 'RUNTIME_INTERNAL_ERROR'],
    ['ENOENT', 'RUNTIME_INTERNAL_ERROR'],
  ]) {
    const io = captureIo();
    const error = Object.assign(new Error('/Users/private/key'), { code });
    const exitCode = await main(['runtime-status', 'dev_abc123'], {}, {
      stdout: io.stdout,
      stderr: io.stderr,
      runtimeDependencyFactory: () => {},
      runtimeStatus: () => { throw error; },
    });
    assert.equal(exitCode, 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), `${expected}\n`);
    assert.doesNotMatch(io.stderrValue(), /private|key/u);
  }
});

test('runtime-plan exposes only its finite read-only error set', async () => {
  for (const [code, expected] of [
    ['RUNTIME_INVENTORY_FAILED', 'RUNTIME_INVENTORY_FAILED'],
    ['RUNTIME_COMPLETION_UNCERTAIN', 'RUNTIME_INTERNAL_ERROR'],
    ['RUNTIME_ARTIFACT_TIMEOUT', 'RUNTIME_INTERNAL_ERROR'],
  ]) {
    const io = captureIo();
    const exitCode = await main([
      'runtime-plan', 'dev_abc123', '--profile', 'core', '--baseline', BASELINE_ID,
    ], {}, {
      stdout: io.stdout,
      stderr: io.stderr,
      runtimePlanDependencyFactory: () => assert.fail('controller owns factory creation'),
      reviewRuntimePlan: () => {
        throw Object.assign(new Error('private mutation detail'), { code });
      },
    });
    assert.equal(exitCode, 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), `${expected}\n`);
  }
});

test('runtime result validators reject wrong device, non-ready prepare, and uncovered profile', async () => {
  for (const result of [
    readyState('dev_other'),
    { ...readyState(), runtimeStatus: 'FAILED', readyProfiles: [], failureCode: 'RUNTIME_VERIFY_FAILED' },
    { ...readyState(), requestedProfiles: ['core'], readyProfiles: [] },
  ]) {
    const io = captureIo();
    const exitCode = await main([
      'prepare', 'dev_abc123', '--profile', 'core', '--approved', PLAN_TICKET_ID,
    ], {}, {
      stdout: io.stdout,
      stderr: io.stderr,
      approvedRuntimeDependencyFactory: () => {},
      prepareApprovedRuntime: () => result,
    });
    assert.equal(exitCode, 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), 'RUNTIME_INPUT_INVALID\n');
  }
});

test('runtime hooks and results reject accessors proxies symbols inheritance and hostile thenables', async () => {
  let getterReads = 0;
  let thenReads = 0;
  const getterResult = { ...readyState() };
  Object.defineProperty(getterResult, 'runtimeStatus', {
    enumerable: true,
    get() {
      getterReads += 1;
      return 'READY';
    },
  });
  const thenable = {};
  Object.defineProperty(thenable, 'then', {
    get() {
      thenReads += 1;
      throw new Error('then getter');
    },
  });
  const inherited = Object.assign(Object.create({ inherited: true }), readyState());
  const symbolic = { ...readyState(), [Symbol('hostile')]: true };
  const proxied = new Proxy(readyState(), { getPrototypeOf() { throw new Error('proxy'); } });

  for (const result of [getterResult, thenable, inherited, symbolic, proxied]) {
    const io = captureIo();
    const exitCode = await main(['runtime-status', 'dev_abc123'], {}, {
      stdout: io.stdout,
      stderr: io.stderr,
      runtimeDependencyFactory: () => {},
      runtimeStatus: () => result,
    });
    assert.equal(exitCode, 2);
    assert.equal(io.stdoutValue(), '');
    assert.equal(io.stderrValue(), 'RUNTIME_INPUT_INVALID\n');
  }

  const io = captureIo();
  const runtime = { stdout: io.stdout, stderr: io.stderr };
  Object.defineProperty(runtime, 'runtimeStatus', {
    get() {
      getterReads += 1;
      return () => readyState();
    },
  });
  assert.equal(await main(['runtime-status', 'dev_abc123'], {}, runtime), 2);
  assert.equal(io.stderrValue(), 'RUNTIME_INPUT_INVALID\n');
  assert.equal(getterReads, 0);
  assert.equal(thenReads, 0);
});

test('runtime output sink failures cannot leak internal details or emit partial JSON', async () => {
  let stderr = '';
  const exitCode = await main(['runtime-status', 'dev_abc123'], {}, {
    stdout: { write() { throw new Error('/Users/private/output'); } },
    stderr: { write(value) { stderr += value; } },
    runtimeDependencyFactory: () => {},
    runtimeStatus: () => readyState(),
  });
  assert.equal(exitCode, 2);
  assert.equal(stderr, 'RUNTIME_INTERNAL_ERROR\n');
  assert.doesNotMatch(stderr, /private|output/u);
});
