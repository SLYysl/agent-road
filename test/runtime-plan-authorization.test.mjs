import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign as cryptoSign,
} from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { createProductionRuntimePlanDependencies } from '../src/runtime/production-runtime-dependencies.mjs';
import { RUNTIME_ACQUISITION_POLICY } from '../src/runtime/runtime-acquisition-policy.mjs';
import {
  readRuntimePlanInventoryPair,
  RUNTIME_PLAN_INVENTORY_SCRIPT_PATH,
} from '../src/runtime/runtime-plan-inventory.mjs';
import { RUNTIME_PLAN_TICKET_TTL_MS } from '../src/runtime/runtime-plan-ticket-policy.mjs';
import { validateRuntimeInventory } from '../src/runtime/runtime-inventory.mjs';

const authorizationModule = await import(
  '../src/runtime/runtime-plan-authorization.mjs'
).catch(() => null);

const PLAN_TICKET_ID = `rpt_${'a'.repeat(64)}`;
const CONTROLLER_KEY_ID = 'B'.repeat(64);
const { privateKey: controllerPrivateKey, publicKey: controllerPublicKey } = generateKeyPairSync(
  'rsa',
  { modulusLength: 3072, publicExponent: 0x10001 },
);
const controllerJwk = controllerPublicKey.export({ format: 'jwk' });
const CONTROLLER_PUBLIC_KEY = Object.freeze({
  algorithm: 'RSA-SHA256',
  modulusBase64Url: controllerJwk.n,
  exponentBase64Url: 'AQAB',
});

function authorizationProjection() {
  return {
    schemaVersion: 1,
    target: {
      deviceId: 'dev_abc123',
      sshHostKeyFingerprints: [
        'SHA256:QdPGpp8sQwLyi6Qe18XpEi5eJQk+lxry0yNyb27T4lM',
      ],
    },
    state: {
      schemaVersion: 1,
      deviceId: 'dev_abc123',
      runtimeStatus: 'UNPROVISIONED',
      requestedProfiles: [],
      readyProfiles: [],
      operationId: null,
      manifestDigest: null,
      generationDigest: null,
      failureCode: null,
      updatedAt: null,
    },
    catalog: {
      schemaVersion: 1,
      catalogRevision: 1,
      platform: { os: 'windows', architecture: 'x64', minimumBuild: 17_763 },
      artifacts: [{
        id: 'powershell-7',
        version: '7.6.4',
        url: 'https://example.com/PowerShell-7.6.4-win-x64.zip',
        redirectOrigins: ['https://downloads.example.com'],
        bytes: 123,
        maximumExpandedBytes: 1_024,
        sha256: 'C'.repeat(64),
        packaging: 'zip',
        signerRule: 'microsoft-corporation',
        verificationCommandId: 'powershell-json-roundtrip',
      }],
      profiles: [
        { id: 'core', artifacts: ['powershell-7'], dependencies: [] },
        { id: 'base', artifacts: ['powershell-7'], dependencies: ['core'] },
      ],
    },
    inventory: {
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
      requiredFreeBytes: 268_436_603,
      freeSpaceSufficient: true,
    },
    plan: {
      schemaVersion: 1,
      deviceId: 'dev_abc123',
      catalogDigest: 'D'.repeat(64),
      requestedProfiles: ['core'],
      profiles: ['core'],
      acquisition: 'mac-relay',
      transactionMode: 'new',
      status: 'actionable',
      blockedReasons: [],
      requiredFreeBytes: 268_436_603,
      items: [{
        artifactId: 'powershell-7',
        action: 'install',
        reason: 'managed-artifact-missing',
        desired: {
          version: '7.6.4',
          bytes: 123,
          maximumExpandedBytes: 1_024,
          sha256: 'C'.repeat(64),
        },
        current: null,
        rollbackVersion: null,
      }],
    },
    acquisitionPolicy: { ...RUNTIME_ACQUISITION_POLICY },
    controller: {
      controllerKeyId: CONTROLLER_KEY_ID,
      controllerPublicKey: {
        algorithm: 'RSA-SHA256',
        modulusBase64Url: 'secret-public-modulus-snapshot',
        exponentBase64Url: 'AQAB',
      },
      firstTrustPinningRequired: true,
    },
    mutators: {
      inventoryScriptSha256: 'D'.repeat(64),
      inventorySha256: 'E'.repeat(64),
      provisionSha256: 'F'.repeat(64),
      recoverySha256: '1'.repeat(64),
    },
    baseline: {
      baselineId: `rbl_${'2'.repeat(64)}`,
      schemaVersion: 1,
      protocolRevision: 1,
      captureAggregateMac: '3'.repeat(64),
      recordDigest: '4'.repeat(64),
      capturedAt: '2026-07-30T00:00:00.000Z',
      expiresAt: '2026-07-31T00:00:00.000Z',
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

function fullAuthorizationInput() {
  const projected = authorizationProjection();
  const inventorySnapshot = structuredClone(projected.inventory);
  delete inventorySnapshot.requiredFreeBytes;
  delete inventorySnapshot.freeSpaceSufficient;
  inventorySnapshot.freeBytes = 50_000_000_000;
  const plan = {
    schemaVersion: 1,
    operationId: '5'.repeat(32),
    createdAt: '2026-07-30T01:00:00.000Z',
    deviceId: projected.plan.deviceId,
    inventoryDigest: '6'.repeat(64),
    catalogDigest: projected.plan.catalogDigest,
    requestedProfiles: projected.plan.requestedProfiles,
    profiles: projected.plan.profiles,
    acquisition: projected.plan.acquisition,
    transactionMode: projected.plan.transactionMode,
    status: projected.plan.status,
    blockedReasons: projected.plan.blockedReasons,
    requiredFreeBytes: projected.plan.requiredFreeBytes,
    items: projected.plan.items,
  };
  return {
    target: projected.target,
    state: projected.state,
    catalog: projected.catalog,
    inventory: inventorySnapshot,
    plan,
    acquisitionPolicy: projected.acquisitionPolicy,
    controller: projected.controller,
    mutators: projected.mutators,
    baseline: projected.baseline,
  };
}

test('projects one exact redacted PLAN_REVIEW_READY result with the full ticket ID', () => {
  assert.ok(authorizationModule, 'runtime plan authorization module must exist');
  const result = authorizationModule.createRuntimePlanReviewResult({
    planTicketId: PLAN_TICKET_ID,
    authorization: authorizationProjection(),
  });

  assert.deepEqual(result, {
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
      artifacts: [{
        artifactId: 'powershell-7',
        action: 'install',
        reason: 'managed-artifact-missing',
        desiredVersion: '7.6.4',
        downloadBytes: 123,
        maximumExpandedBytes: 1_024,
        rollbackVersion: null,
        sourceOrigins: ['https://downloads.example.com', 'https://example.com'],
        signerRule: 'microsoft-corporation',
        verifierId: 'powershell-json-roundtrip',
        fingerprint: 'CCCCCCCCCCCC',
      }],
    },
    controller: {
      controllerKeyId: CONTROLLER_KEY_ID,
      firstTrustPinningRequired: true,
    },
    mutators: {
      inventoryRevision: 'EEEEEEEEEEEE',
      provisionRevision: 'FFFFFFFFFFFF',
      recoveryRevision: '111111111111',
    },
    mutationScope: authorizationProjection().mutationScope,
    transportScope: authorizationProjection().transportScope,
    nonMutationClaims: authorizationProjection().nonMutationClaims,
  });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(`${JSON.stringify(result)}\n`.split('\n').length, 2);

  const publicJson = JSON.stringify(result);
  for (const secret of [
    'dev_abc123',
    '2026-07-30T00:00:00.000Z',
    '2026-07-31T00:00:00.000Z',
    'secret-public-modulus-snapshot',
    'https://example.com/PowerShell-7.6.4-win-x64.zip',
    'CCCCCCCCCCCCCCCC',
    'DDDDDDDDDDDDDDDD',
    'rbl_',
  ]) assert.equal(publicJson.includes(secret), false, secret);
});

test('accepts the canonical verified no-op present item with its null reason', () => {
  const authorization = authorizationProjection();
  authorization.plan.items[0].action = 'present';
  authorization.plan.items[0].reason = null;
  const result = authorizationModule.createRuntimePlanReviewResult({
    planTicketId: PLAN_TICKET_ID,
    authorization,
  });
  assert.equal(result.plan.artifacts[0].action, 'present');
  assert.equal(result.plan.artifacts[0].reason, null);
});

test('builds a stable full authorization projection and binds every mutation category', () => {
  assert.ok(authorizationModule, 'runtime plan authorization module must exist');
  const firstInput = fullAuthorizationInput();
  const first = authorizationModule.createRuntimePlanAuthorizationProjection(firstInput);
  assert.deepEqual(first, authorizationProjection());
  assert.equal(Object.isFrozen(first), true);
  const digest = authorizationModule.digestRuntimePlanAuthorization(first);
  assert.match(digest, /^[A-F0-9]{64}$/u);

  const volatile = fullAuthorizationInput();
  volatile.inventory.freeBytes += 1_000_000;
  volatile.plan.inventoryDigest = '7'.repeat(64);
  volatile.plan.operationId = '8'.repeat(32);
  volatile.plan.createdAt = '2026-07-30T02:00:00.000Z';
  const same = authorizationModule.createRuntimePlanAuthorizationProjection(volatile);
  assert.equal(authorizationModule.digestRuntimePlanAuthorization(same), digest);

  const mutations = [
    (value) => { value.target.sshHostKeyFingerprints[0] = `SHA256:${'A'.repeat(43)}`; },
    (value) => { value.state.updatedAt = '2026-07-29T00:00:00.000Z'; },
    (value) => { value.catalog.catalogRevision += 1; },
    (value) => { value.catalog.artifacts[0].url = 'https://mirror.example.com/PowerShell-7.6.4-win-x64.zip'; },
    (value) => { value.catalog.artifacts[0].redirectOrigins[0] = 'https://redirect.example.com'; },
    (value) => { value.catalog.artifacts[0].bytes += 1; },
    (value) => { value.catalog.artifacts[0].maximumExpandedBytes += 1; },
    (value) => { value.catalog.artifacts[0].sha256 = '7'.repeat(64); },
    (value) => { value.catalog.artifacts[0].packaging = 'changed'; },
    (value) => { value.catalog.artifacts[0].signerRule = 'changed'; },
    (value) => { value.catalog.artifacts[0].verificationCommandId = 'changed'; },
    (value) => { value.inventory.platform.build += 1; },
    (value) => { value.inventory.pendingReboot = true; },
    (value) => { value.inventory.freeSpaceSufficient = false; },
    (value) => { value.inventory.requiredFreeBytes += 1; },
    (value) => { value.plan.transactionMode = 'reconcile'; },
    (value) => { value.plan.items[0].action = 'repair'; },
    (value) => { value.acquisitionPolicy.timeoutMs += 1; },
    (value) => { value.acquisitionPolicy.maxRedirects += 1; },
    (value) => { value.controller.controllerKeyId = '8'.repeat(64); },
    (value) => { value.controller.controllerPublicKey.modulusBase64Url = 'changed'; },
    (value) => { value.controller.firstTrustPinningRequired = false; },
    (value) => { value.mutators.inventoryScriptSha256 = '8'.repeat(64); },
    (value) => { value.mutators.inventorySha256 = '8'.repeat(64); },
    (value) => { value.mutators.provisionSha256 = '8'.repeat(64); },
    (value) => { value.mutators.recoverySha256 = '8'.repeat(64); },
    (value) => { value.baseline.baselineId = `rbl_${'8'.repeat(64)}`; },
    (value) => { value.baseline.schemaVersion += 1; },
    (value) => { value.baseline.protocolRevision += 1; },
    (value) => { value.baseline.captureAggregateMac = '8'.repeat(64); },
    (value) => { value.baseline.recordDigest = '8'.repeat(64); },
    (value) => { value.baseline.capturedAt = '2026-07-29T00:00:00.000Z'; },
    (value) => { value.baseline.expiresAt = '2026-08-01T00:00:00.000Z'; },
    (value) => { value.mutationScope.allowedDescendants[0] = 'changed'; },
    (value) => { value.mutationScope.allowedDescendants[3] = 'versions/.rollback-changed'; },
    (value) => { value.mutationScope.allowedDescendants[4] = 'versions/.retired-changed'; },
    (value) => { value.transportScope.transportRoot = 'C:\\changed'; },
    (value) => { value.transportScope.allowedDescendants[0] = '<transportOperationId>.changed'; },
    (value) => { value.transportScope.operationSets.actionableMaximum += 1; },
    (value) => { value.transportScope.operationSets.roles[0] = 'changed'; },
    (value) => { value.transportScope.lifecycle.cleanup = 'changed'; },
    (value) => { value.transportScope.temporariness.uncertain = 'changed'; },
    (value) => { value.nonMutationClaims.firewall = 'changed'; },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(first);
    mutate(changed);
    assert.notEqual(
      authorizationModule.digestRuntimePlanAuthorization(changed),
      digest,
      mutate.toString(),
    );
  }
});

function controllerTarget() {
  return Object.freeze({
    device: Object.freeze({
      id: 'dev_abc123',
      transport: Object.freeze({
        sshHostKeyFingerprints: Object.freeze([
          'SHA256:QdPGpp8sQwLyi6Qe18XpEi5eJQk+lxry0yNyb27T4lM',
        ]),
      }),
    }),
    identity: Object.freeze({
      privateKeyPath: '/tmp/agent-road/identity/devices/dev_abc123/id_ed25519',
      publicKeyPath: '/tmp/agent-road/identity/devices/dev_abc123/id_ed25519.pub',
      publicKey: 'ssh-ed25519 fixture',
    }),
    knownHostsPath: '/tmp/agent-road/known-hosts/agent-road-known-hosts-dev_abc123',
  });
}

function controllerState() {
  return {
    schemaVersion: 1,
    deviceId: 'dev_abc123',
    runtimeStatus: 'UNPROVISIONED',
    requestedProfiles: [],
    readyProfiles: [],
    operationId: null,
    manifestDigest: null,
    generationDigest: null,
    failureCode: null,
    updatedAt: null,
  };
}

function controllerCatalog() {
  return structuredClone(authorizationProjection().catalog);
}

function controllerInventory(freeBytes = 50_000_000_000) {
  const value = structuredClone(fullAuthorizationInput().inventory);
  value.freeBytes = freeBytes;
  return value;
}

function controllerBaseline() {
  return structuredClone(authorizationProjection().baseline);
}

function freezeDeep(value) {
  if (Array.isArray(value)) {
    for (const child of value) freezeDeep(child);
  } else if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) freezeDeep(child);
  }
  return Object.freeze(value);
}

function planControllerFixture(overrides = {}) {
  const calls = [];
  let ticket;
  const pair = {
    schemaVersion: 1,
    firstInventory: controllerInventory(),
    firstControllerTrust: { state: 'unpinned', controllerKeyId: null },
    secondInventory: controllerInventory(),
    secondControllerTrust: { state: 'unpinned', controllerKeyId: null },
    scriptSha256: 'D'.repeat(64),
  };
  const dependencies = {
    loadTarget: async () => { calls.push('loadTarget'); return controllerTarget(); },
    readState: async () => { calls.push('readState'); return controllerState(); },
    readInventoryPair: async () => { calls.push('readInventoryPair'); return pair; },
    loadCatalog: async () => { calls.push('loadCatalog'); return controllerCatalog(); },
    readBaselineBinding: async () => { calls.push('readBaselineBinding'); return controllerBaseline(); },
    getSigningPublicKey: async () => {
      calls.push('getSigningPublicKey');
      return CONTROLLER_PUBLIC_KEY;
    },
    readMutatorRevisions: async () => {
      calls.push('readMutatorRevisions');
      return {
        inventoryScriptSha256: 'D'.repeat(64),
        inventorySha256: 'E'.repeat(64),
        provisionSha256: 'F'.repeat(64),
        recoverySha256: '1'.repeat(64),
      };
    },
    createPlanTicket: async (input) => {
      calls.push('createPlanTicket');
      const base = {
        schemaVersion: 1,
        recordType: 'RUNTIME_PLAN_TICKET',
        planTicketId: PLAN_TICKET_ID,
        ...structuredClone(input),
        expiresAt: '2026-07-30T01:10:00.000Z',
      };
      ticket = freezeDeep({
        ...base,
        recordDigest: createHash('sha256')
          .update('AgentRoad.RuntimePlanTicket.v1\0', 'utf8')
          .update(JSON.stringify(base), 'utf8')
          .digest('hex')
          .toUpperCase(),
      });
      return ticket;
    },
    operationId: () => { calls.push('operationId'); return '5'.repeat(32); },
    clock: () => { calls.push('clock'); return new Date('2026-07-30T01:00:00.000Z'); },
    ...overrides.dependencies,
  };
  return {
    calls,
    pair,
    dependencies,
    dependencyFactory: () => dependencies,
    get ticket() { return ticket; },
  };
}

function approvedPreflightFixture(planned, overrides = {}) {
  let authorityCalls = 0;
  const dependencies = {
    loadTarget: async () => controllerTarget(),
    readState: async () => controllerState(),
    transitionState: async () => { authorityCalls += 1; assert.fail('no state mutation'); },
    readInventoryPair: async () => planned.pair,
    loadCatalog: async () => controllerCatalog(),
    readBaselineBinding: async () => controllerBaseline(),
    getSigningPublicKey: async () => CONTROLLER_PUBLIC_KEY,
    readMutatorRevisions: async () => structuredClone(planned.ticket.mutators),
    readPlanTicket: async () => planned.ticket,
    consumePlanTicket: async () => { authorityCalls += 1; assert.fail('no consume'); },
    sign: async () => { authorityCalls += 1; assert.fail('no signing'); },
    acquireArtifact: async () => { authorityCalls += 1; assert.fail('no acquisition'); },
    provision: async () => { authorityCalls += 1; assert.fail('no provision'); },
    ...overrides,
  };
  return {
    dependencies,
    dependencyFactory: () => dependencies,
    authorityCalls: () => authorityCalls,
  };
}

function consumedPlanRecord(ticket, overrides = {}) {
  const base = {
    schemaVersion: 1,
    recordType: 'RUNTIME_PLAN_CONSUMED',
    planTicketId: ticket.planTicketId,
    deviceId: ticket.deviceId,
    ticketRecordDigest: ticket.recordDigest,
    authorizationDigest: ticket.authorizationDigest,
    consumedAt: '2026-07-30T01:05:00.000Z',
    ...overrides,
  };
  return freezeDeep({
    ...base,
    recordDigest: createHash('sha256')
      .update('AgentRoad.RuntimePlanConsumed.v1\0', 'utf8')
      .update(JSON.stringify(base), 'utf8')
      .digest('hex')
      .toUpperCase(),
  });
}

function ticketWithBaselineExpiry(ticket, expiresAt) {
  const snapshot = structuredClone(ticket);
  snapshot.baseline.expiresAt = expiresAt;
  snapshot.authorization.baseline.expiresAt = expiresAt;
  snapshot.authorizationDigest = authorizationModule.digestRuntimePlanAuthorization(
    snapshot.authorization,
  );
  delete snapshot.recordDigest;
  snapshot.recordDigest = createHash('sha256')
    .update('AgentRoad.RuntimePlanTicket.v1\0', 'utf8')
    .update(JSON.stringify(snapshot), 'utf8')
    .digest('hex')
    .toUpperCase();
  return freezeDeep(snapshot);
}

test('review creates a full immutable ticket and returns only the redacted plan projection', async () => {
  const fixture = planControllerFixture();
  const result = await authorizationModule.reviewRuntimePlan({
    deviceId: 'dev_abc123',
    requestedProfiles: ['core'],
    baselineId: `rbl_${'2'.repeat(64)}`,
    dependencyFactory: fixture.dependencyFactory,
  });

  assert.equal(result.status, 'PLAN_REVIEW_READY');
  assert.equal(result.planTicketId, PLAN_TICKET_ID);
  assert.equal(result.plan.status, 'actionable');
  assert.deepEqual(fixture.calls, [
    'loadTarget',
    'readState',
    'operationId',
    'clock',
    'loadCatalog',
    'readBaselineBinding',
    'getSigningPublicKey',
    'readMutatorRevisions',
    'readInventoryPair',
    'createPlanTicket',
  ]);
  assert.equal(fixture.ticket.operationId, '5'.repeat(32));
  assert.equal(fixture.ticket.createdAt, '2026-07-30T01:00:00.000Z');
  assert.equal(fixture.ticket.plan.operationId, fixture.ticket.operationId);
  assert.equal(fixture.ticket.plan.createdAt, fixture.ticket.createdAt);
  assert.equal(fixture.ticket.inventory.freeBytes, 50_000_000_000);
  assert.equal(fixture.ticket.authorizationDigest.length, 64);
  assert.deepEqual(fixture.ticket.authorization.acquisitionPolicy, RUNTIME_ACQUISITION_POLICY);
  assert.equal(fixture.ticket.baseline.baselineId, `rbl_${'2'.repeat(64)}`);
  assert.equal('hmacKeyBase64' in fixture.ticket.baseline, false);
  assert.equal('surfaces' in fixture.ticket.baseline, false);
  const publicJson = JSON.stringify(result);
  assert.equal(publicJson.includes('dev_abc123'), false);
  assert.equal(publicJson.includes('2026-07-30'), false);
  assert.equal(publicJson.includes('/tmp/'), false);
});

test('production inventory runner binds its raw script hash beside the composite code revision', async () => {
  const source = await readFile(RUNTIME_PLAN_INVENTORY_SCRIPT_PATH);
  const target = Object.freeze({ device: Object.freeze({ id: 'dev_abc123' }) });
  const trust = Object.freeze({ deviceId: 'dev_abc123', pinned: true });
  const observation = JSON.stringify({
    schemaVersion: 1,
    inventory: validateRuntimeInventory(controllerInventory()),
    controllerTrust: { state: 'unpinned', controllerKeyId: null },
  });
  const session = Object.freeze({
    invokeSsh: async () => ({
      command: '/usr/bin/ssh',
      args: [],
      exitCode: 0,
      signal: null,
      stdout: observation,
      stderr: '',
    }),
  });
  const pair = await readRuntimePlanInventoryPair({
    target,
    dependencies: {
      readInventoryScript: async () => Buffer.from(source),
      trustedInput: () => trust,
      withTrustedSshSession: async (inputTrust, operation) => {
        assert.equal(inputTrust, trust);
        return operation(session);
      },
      selectAddress: async () => '100.64.0.10',
      isTrustedSshSessionLockError: () => false,
      runProcess: () => assert.fail('the trusted session owns process execution'),
    },
  });
  const production = createProductionRuntimePlanDependencies({
    AGENT_ROAD_HOME: '/tmp/agent-road-runtime-plan-revision-test',
  });
  const mutators = await production.readMutatorRevisions();
  assert.notEqual(pair.scriptSha256, mutators.inventorySha256);

  const fixture = planControllerFixture({
    dependencies: {
      readInventoryPair: async () => pair,
      readMutatorRevisions: async () => mutators,
    },
  });
  await authorizationModule.reviewRuntimePlan({
    deviceId: 'dev_abc123',
    requestedProfiles: ['core'],
    baselineId: `rbl_${'2'.repeat(64)}`,
    dependencyFactory: fixture.dependencyFactory,
  });
  assert.equal(fixture.ticket.mutators.inventoryScriptSha256, pair.scriptSha256);
  assert.notEqual(
    fixture.ticket.mutators.inventoryScriptSha256,
    fixture.ticket.mutators.inventorySha256,
  );
});

test('review requires baseline validity to contain the complete plan-ticket lifetime', async () => {
  const operationTime = Date.parse('2026-07-30T01:00:00.000Z');
  const exactExpiry = new Date(operationTime + RUNTIME_PLAN_TICKET_TTL_MS).toISOString();
  const shortExpiry = new Date(operationTime + RUNTIME_PLAN_TICKET_TTL_MS - 1).toISOString();
  const exact = planControllerFixture({
    dependencies: {
      readBaselineBinding: async () => ({
        ...controllerBaseline(),
        expiresAt: exactExpiry,
      }),
    },
  });
  await authorizationModule.reviewRuntimePlan({
    deviceId: 'dev_abc123',
    requestedProfiles: ['core'],
    baselineId: `rbl_${'2'.repeat(64)}`,
    dependencyFactory: exact.dependencyFactory,
  });
  assert.ok(exact.calls.includes('createPlanTicket'));

  const short = planControllerFixture({
    dependencies: {
      readBaselineBinding: async () => ({
        ...controllerBaseline(),
        expiresAt: shortExpiry,
      }),
    },
  });
  await assert.rejects(authorizationModule.reviewRuntimePlan({
    deviceId: 'dev_abc123',
    requestedProfiles: ['core'],
    baselineId: `rbl_${'2'.repeat(64)}`,
    dependencyFactory: short.dependencyFactory,
  }), { code: 'RUNTIME_STATE_UNSUPPORTED' });
  for (const forbidden of [
    'getSigningPublicKey',
    'readMutatorRevisions',
    'readInventoryPair',
    'createPlanTicket',
  ]) assert.equal(short.calls.includes(forbidden), false, forbidden);
});

test('approved prepare replays the ticket operation and consumes before transition sign acquire or provision', async () => {
  const planned = planControllerFixture();
  await authorizationModule.reviewRuntimePlan({
    deviceId: 'dev_abc123',
    requestedProfiles: ['core'],
    baselineId: `rbl_${'2'.repeat(64)}`,
    dependencyFactory: planned.dependencyFactory,
  });
  const ticket = planned.ticket;
  const calls = [];
  let current = freezeDeep(controllerState());
  const approvedDependencies = {
    loadTarget: async () => { calls.push('loadTarget'); return controllerTarget(); },
    readState: async () => { calls.push('readState'); return current; },
    transitionState: async (expected, next) => {
      calls.push(`transition:${next.runtimeStatus}`);
      assert.deepEqual(expected, current);
      current = freezeDeep(structuredClone(next));
      return current;
    },
    readInventoryPair: async () => {
      calls.push('readInventoryPair');
      return planned.pair;
    },
    loadCatalog: async () => { calls.push('loadCatalog'); return controllerCatalog(); },
    readBaselineBinding: async () => {
      calls.push('readBaselineBinding');
      return controllerBaseline();
    },
    getSigningPublicKey: async () => {
      calls.push('getSigningPublicKey');
      return CONTROLLER_PUBLIC_KEY;
    },
    readMutatorRevisions: async () => {
      calls.push('readMutatorRevisions');
      return structuredClone(ticket.mutators);
    },
    readPlanTicket: async () => { calls.push('readPlanTicket'); return ticket; },
    consumePlanTicket: async (input) => {
      calls.push('consumePlanTicket');
      assert.equal(input.planTicketId, PLAN_TICKET_ID);
      assert.equal(input.ticketRecordDigest, ticket.recordDigest);
      assert.equal(input.authorizationDigest, ticket.authorizationDigest);
      return consumedPlanRecord(ticket);
    },
    sign: async (bytes) => {
      calls.push('sign');
      return cryptoSign('RSA-SHA256', bytes, controllerPrivateKey).toString('base64');
    },
    acquireArtifact: async (artifact, acquisitionPolicy) => {
      calls.push('acquireArtifact');
      assert.deepEqual(acquisitionPolicy, ticket.authorization.acquisitionPolicy);
      assert.equal(Object.isFrozen(acquisitionPolicy), true);
      return freezeDeep({
        artifactId: artifact.id,
        version: artifact.version,
        path: `/tmp/${artifact.sha256}.zip`,
        bytes: artifact.bytes,
        sha256: artifact.sha256,
      });
    },
    provision: async (input) => {
      calls.push('provision');
      assert.equal(input.plan.operationId, ticket.operationId);
      assert.equal(input.plan.createdAt, ticket.createdAt);
      return freezeDeep({
        schemaVersion: 1,
        status: 'committed',
        deviceId: 'dev_abc123',
        address: '100.64.0.10',
        operationId: ticket.operationId,
        manifestDigest: input.capsule.manifestDigest,
        generationDigest: input.capsule.generationDigest,
        restartRequired: false,
        failureCode: null,
      });
    },
  };

  const result = await authorizationModule.prepareApprovedRuntime({
    deviceId: 'dev_abc123',
    requestedProfiles: ['core'],
    planTicketId: PLAN_TICKET_ID,
    dependencyFactory: () => approvedDependencies,
  });

  assert.equal(result.runtimeStatus, 'READY');
  assert.equal(result.operationId, ticket.operationId);
  assert.ok(calls.indexOf('readPlanTicket') < calls.indexOf('loadTarget'));
  const consumeIndex = calls.indexOf('consumePlanTicket');
  assert.ok(consumeIndex > calls.indexOf('readInventoryPair'));
  for (const authority of [
    'transition:INVENTORY_READY',
    'sign',
    'acquireArtifact',
    'provision',
  ]) assert.ok(calls.indexOf(authority) > consumeIndex, authority);
  assert.equal(calls.includes('operationId'), false);
});

test('approved prepare rejects a missing or expired exact ticket before target and state hooks', async () => {
  for (const reason of ['missing', 'expired']) {
    const planned = planControllerFixture();
    await authorizationModule.reviewRuntimePlan({
      deviceId: 'dev_abc123',
      requestedProfiles: ['core'],
      baselineId: `rbl_${'2'.repeat(64)}`,
      dependencyFactory: planned.dependencyFactory,
    });
    let ticketReads = 0;
    let laterCalls = 0;
    const approved = approvedPreflightFixture(planned, {
      readPlanTicket: async (input) => {
        ticketReads += 1;
        assert.deepEqual(input, {
          deviceId: 'dev_abc123',
          planTicketId: PLAN_TICKET_ID,
        });
        throw Object.assign(new TypeError(reason), { code: 'RUNTIME_INPUT_INVALID' });
      },
      loadTarget: async () => { laterCalls += 1; return controllerTarget(); },
      readState: async () => { laterCalls += 1; return controllerState(); },
      readInventoryPair: async () => { laterCalls += 1; return planned.pair; },
      getSigningPublicKey: async () => { laterCalls += 1; return CONTROLLER_PUBLIC_KEY; },
    });

    await assert.rejects(authorizationModule.prepareApprovedRuntime({
      deviceId: 'dev_abc123',
      requestedProfiles: ['core'],
      planTicketId: PLAN_TICKET_ID,
      dependencyFactory: approved.dependencyFactory,
    }), { code: 'RUNTIME_INPUT_INVALID' }, reason);
    assert.equal(ticketReads, 1, reason);
    assert.equal(laterCalls, 0, reason);
    assert.equal(approved.authorityCalls(), 0, reason);
  }
});

test('approved prepare rejects a re-digested ticket whose baseline expires before the ticket', async () => {
  const planned = planControllerFixture();
  await authorizationModule.reviewRuntimePlan({
    deviceId: 'dev_abc123',
    requestedProfiles: ['core'],
    baselineId: `rbl_${'2'.repeat(64)}`,
    dependencyFactory: planned.dependencyFactory,
  });
  const ticket = ticketWithBaselineExpiry(
    planned.ticket,
    new Date(Date.parse(planned.ticket.expiresAt) - 1).toISOString(),
  );
  let laterCalls = 0;
  const approved = approvedPreflightFixture(planned, {
    readPlanTicket: async () => ticket,
    loadTarget: async () => { laterCalls += 1; return controllerTarget(); },
    readState: async () => { laterCalls += 1; return controllerState(); },
  });

  await assert.rejects(authorizationModule.prepareApprovedRuntime({
    deviceId: 'dev_abc123',
    requestedProfiles: ['core'],
    planTicketId: PLAN_TICKET_ID,
    dependencyFactory: approved.dependencyFactory,
  }), { code: 'RUNTIME_INPUT_INVALID' });
  assert.equal(laterCalls, 0);
  assert.equal(approved.authorityCalls(), 0);
});

test('blocked reviews remain auditable but approved prepare rejects before consuming', async () => {
  const planned = planControllerFixture();
  planned.pair.firstInventory.pendingReboot = true;
  planned.pair.secondInventory.pendingReboot = true;
  const review = await authorizationModule.reviewRuntimePlan({
    deviceId: 'dev_abc123',
    requestedProfiles: ['core'],
    baselineId: `rbl_${'2'.repeat(64)}`,
    dependencyFactory: planned.dependencyFactory,
  });
  assert.equal(review.plan.status, 'blocked');
  assert.deepEqual(review.plan.blockers, ['pending-reboot']);
  assert.ok(planned.ticket);

  const approved = approvedPreflightFixture(planned);
  await assert.rejects(authorizationModule.prepareApprovedRuntime({
    deviceId: 'dev_abc123',
    requestedProfiles: ['core'],
    planTicketId: PLAN_TICKET_ID,
    dependencyFactory: approved.dependencyFactory,
  }), { code: 'RUNTIME_REBOOT_REQUIRED' });
  assert.equal(approved.authorityCalls(), 0);
});

test('approved prepare rejects changed state and changed inventory before consuming', async () => {
  for (const drift of ['state', 'inventory']) {
    const planned = planControllerFixture();
    await authorizationModule.reviewRuntimePlan({
      deviceId: 'dev_abc123',
      requestedProfiles: ['core'],
      baselineId: `rbl_${'2'.repeat(64)}`,
      dependencyFactory: planned.dependencyFactory,
    });
    const overrides = drift === 'state'
      ? {
          readState: async () => ({
            schemaVersion: 1,
            deviceId: 'dev_abc123',
            runtimeStatus: 'READY',
            requestedProfiles: ['core'],
            readyProfiles: ['core'],
            operationId: '7'.repeat(32),
            manifestDigest: '8'.repeat(64),
            generationDigest: '9'.repeat(64),
            failureCode: null,
            updatedAt: '2026-07-30T00:59:59.000Z',
          }),
        }
      : {
          readInventoryPair: async () => {
            const pair = structuredClone(planned.pair);
            pair.firstInventory.platform.build += 1;
            pair.secondInventory.platform.build += 1;
            return pair;
          },
        };
    const approved = approvedPreflightFixture(planned, overrides);
    await assert.rejects(authorizationModule.prepareApprovedRuntime({
      deviceId: 'dev_abc123',
      requestedProfiles: ['core'],
      planTicketId: PLAN_TICKET_ID,
      dependencyFactory: approved.dependencyFactory,
    }), { code: 'RUNTIME_INVENTORY_CHANGED' }, drift);
    assert.equal(approved.authorityCalls(), 0, drift);
  }
});

test('planning target validation rejects proxies and shallow-frozen nested transport without traps', async () => {
  let proxyTraps = 0;
  const proxiedTarget = new Proxy({}, {
    getOwnPropertyDescriptor() {
      proxyTraps += 1;
      throw new Error('must not inspect a proxy target');
    },
    isExtensible() {
      proxyTraps += 1;
      throw new Error('must not freeze-check a proxy target');
    },
  });
  const proxied = planControllerFixture({
    dependencies: { loadTarget: async () => proxiedTarget },
  });
  await assert.rejects(authorizationModule.reviewRuntimePlan({
    deviceId: 'dev_abc123',
    requestedProfiles: ['core'],
    baselineId: `rbl_${'2'.repeat(64)}`,
    dependencyFactory: proxied.dependencyFactory,
  }), { code: 'RUNTIME_INVENTORY_FAILED' });
  assert.equal(proxyTraps, 0);
  assert.deepEqual(proxied.calls, []);

  const stableIdentity = controllerTarget().identity;
  const knownHostsPath = controllerTarget().knownHostsPath;
  const fingerprint = 'SHA256:QdPGpp8sQwLyi6Qe18XpEi5eJQk+lxry0yNyb27T4lM';
  const mutableTransport = {
    sshHostKeyFingerprints: Object.freeze([fingerprint]),
  };
  const mutableFingerprints = [fingerprint];
  const shallowTargets = [
    Object.freeze({
      device: Object.freeze({ id: 'dev_abc123', transport: mutableTransport }),
      identity: stableIdentity,
      knownHostsPath,
    }),
    Object.freeze({
      device: Object.freeze({
        id: 'dev_abc123',
        transport: Object.freeze({ sshHostKeyFingerprints: mutableFingerprints }),
      }),
      identity: stableIdentity,
      knownHostsPath,
    }),
  ];
  for (const target of shallowTargets) {
    let laterCalls = 0;
    const fixture = planControllerFixture({
      dependencies: {
        loadTarget: async () => target,
        readState: async () => { laterCalls += 1; return controllerState(); },
      },
    });
    await assert.rejects(authorizationModule.reviewRuntimePlan({
      deviceId: 'dev_abc123',
      requestedProfiles: ['core'],
      baselineId: `rbl_${'2'.repeat(64)}`,
      dependencyFactory: fixture.dependencyFactory,
    }), { code: 'RUNTIME_INVENTORY_FAILED' });
    assert.equal(laterCalls, 0);
  }
});

test('read-only review maps uncertain runtime state to state unsupported', async () => {
  for (const failureCode of [
    'RUNTIME_COMPLETION_UNCERTAIN',
    'RUNTIME_ROLLBACK_INCOMPLETE',
  ]) {
    const fixture = planControllerFixture({
      dependencies: {
        readState: async () => ({
          ...controllerState(),
          runtimeStatus: 'FAILED',
          requestedProfiles: ['core'],
          operationId: '7'.repeat(32),
          manifestDigest: '8'.repeat(64),
          generationDigest: '9'.repeat(64),
          failureCode,
          updatedAt: '2026-07-30T00:59:59.000Z',
        }),
      },
    });
    await assert.rejects(authorizationModule.reviewRuntimePlan({
      deviceId: 'dev_abc123',
      requestedProfiles: ['core'],
      baselineId: `rbl_${'2'.repeat(64)}`,
      dependencyFactory: fixture.dependencyFactory,
    }), { code: 'RUNTIME_STATE_UNSUPPORTED' }, failureCode);
  }
});

test('approved prepare maps signing-key and remote-trust drift to inventory changed before consume', async () => {
  const { publicKey: changedPublicKey } = generateKeyPairSync(
    'rsa',
    { modulusLength: 3072, publicExponent: 0x10001 },
  );
  const changedJwk = changedPublicKey.export({ format: 'jwk' });
  const changedControllerPublicKey = Object.freeze({
    algorithm: 'RSA-SHA256',
    modulusBase64Url: changedJwk.n,
    exponentBase64Url: 'AQAB',
  });

  for (const drift of ['signing-key', 'remote-trust']) {
    const planned = planControllerFixture();
    await authorizationModule.reviewRuntimePlan({
      deviceId: 'dev_abc123',
      requestedProfiles: ['core'],
      baselineId: `rbl_${'2'.repeat(64)}`,
      dependencyFactory: planned.dependencyFactory,
    });
    const pair = structuredClone(planned.pair);
    const pinnedId = drift === 'signing-key'
      ? planned.ticket.controller.controllerKeyId
      : '9'.repeat(64);
    pair.firstControllerTrust = { state: 'pinned', controllerKeyId: pinnedId };
    pair.secondControllerTrust = { state: 'pinned', controllerKeyId: pinnedId };
    const approved = approvedPreflightFixture(planned, {
      readInventoryPair: async () => pair,
      getSigningPublicKey: async () => (
        drift === 'signing-key' ? changedControllerPublicKey : CONTROLLER_PUBLIC_KEY
      ),
    });
    await assert.rejects(authorizationModule.prepareApprovedRuntime({
      deviceId: 'dev_abc123',
      requestedProfiles: ['core'],
      planTicketId: PLAN_TICKET_ID,
      dependencyFactory: approved.dependencyFactory,
    }), { code: 'RUNTIME_INVENTORY_CHANGED' }, drift);
    assert.equal(approved.authorityCalls(), 0, drift);
  }
});

test('approved prepare maps existing-only signer failures by drift safety and internal class', async () => {
  const expectedByCode = new Map([
    ['BOOTSTRAP_SIGNING_KEY_PARTIAL', 'RUNTIME_INVENTORY_CHANGED'],
    ['BOOTSTRAP_SIGNING_KEY_MISMATCH', 'RUNTIME_INVENTORY_CHANGED'],
    ['BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE', 'RUNTIME_STATE_UNSUPPORTED'],
    ['BOOTSTRAP_SIGNING_KEY_PERMISSIONS', 'RUNTIME_STATE_UNSUPPORTED'],
    ['BOOTSTRAP_SIGNING_KEY_PRIVATE_INVALID', 'RUNTIME_STATE_UNSUPPORTED'],
    ['BOOTSTRAP_SIGNING_KEY_PUBLIC_INVALID', 'RUNTIME_STATE_UNSUPPORTED'],
    ['ENOENT', 'RUNTIME_INTERNAL_ERROR'],
  ]);
  for (const [signerCode, expectedCode] of expectedByCode) {
    const planned = planControllerFixture();
    await authorizationModule.reviewRuntimePlan({
      deviceId: 'dev_abc123',
      requestedProfiles: ['core'],
      baselineId: `rbl_${'2'.repeat(64)}`,
      dependencyFactory: planned.dependencyFactory,
    });
    const approved = approvedPreflightFixture(planned, {
      getSigningPublicKey: async () => {
        throw Object.assign(new Error('private signer detail'), { code: signerCode });
      },
    });
    await assert.rejects(authorizationModule.prepareApprovedRuntime({
      deviceId: 'dev_abc123',
      requestedProfiles: ['core'],
      planTicketId: PLAN_TICKET_ID,
      dependencyFactory: approved.dependencyFactory,
    }), { code: expectedCode }, signerCode);
    assert.equal(approved.authorityCalls(), 0, signerCode);
  }
});

test('approved prepare refuses a missing or forged consume acknowledgement before apply', async () => {
  for (const acknowledgement of [undefined, Object.freeze({ consumed: true })]) {
    const planned = planControllerFixture();
    await authorizationModule.reviewRuntimePlan({
      deviceId: 'dev_abc123',
      requestedProfiles: ['core'],
      baselineId: `rbl_${'2'.repeat(64)}`,
      dependencyFactory: planned.dependencyFactory,
    });
    let applyCalls = 0;
    const approved = approvedPreflightFixture(planned, {
      consumePlanTicket: async () => acknowledgement,
      transitionState: async () => { applyCalls += 1; },
      sign: async () => { applyCalls += 1; },
      acquireArtifact: async () => { applyCalls += 1; },
      provision: async () => { applyCalls += 1; },
    });
    await assert.rejects(authorizationModule.prepareApprovedRuntime({
      deviceId: 'dev_abc123',
      requestedProfiles: ['core'],
      planTicketId: PLAN_TICKET_ID,
      dependencyFactory: approved.dependencyFactory,
    }), { code: 'RUNTIME_STATE_UNSUPPORTED' });
    assert.equal(applyCalls, 0);
  }
});
