import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { assessStagedRetirement, decodeStagedRetirementObservation } from '../src/runtime/staged-retirement-assessment.mjs';
import { createSignedRuntimeManifest } from '../src/runtime/runtime-manifest.mjs';
import { createRuntimePlan } from '../src/runtime/runtime-plan.mjs';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 });
const jwk = publicKey.export({ format: 'jwk' });
const controllerPublicKey = { algorithm: 'RSA-SHA256', modulusBase64Url: jwk.n, exponentBase64Url: jwk.e };
const catalog = JSON.parse(await readFile(new URL('../config/runtime-catalog.json', import.meta.url)));
const deviceId = 'dev_retirementfixture';
const operationId = '1'.repeat(32);
const oldInventory = {
  schemaVersion: 1,
  platform: { os: 'windows', version: '10.0.26200', build: 26200, edition: 'Microsoft Windows 11 家庭中文版',
    architecture: 'x64', windowsPowerShellVersion: '5.1.26100.1', elevated: true },
  freeBytes: 50_000_000_000, pendingReboot: false, interactiveSession: false,
  runtime: { schemaVersion: null, catalogRevision: null, catalogDigest: null, generationDigest: null,
    generationVerified: false, pendingOperationId: null, restartRequired: false },
  managedArtifacts: [],
};
const plan = createRuntimePlan({ catalog, inventory: oldInventory, requestedProfiles: ['core'],
  deviceId, operationId, createdAt: '2026-09-18T10:00:00.000Z' });
const capsule = await createSignedRuntimeManifest({ catalog, inventory: oldInventory, plan,
  dependencies: { getSigningPublicKey: async () => controllerPublicKey,
    sign: async (bytes) => sign('RSA-SHA256', bytes, privateKey).toString('base64') } });
const capsuleJson = JSON.stringify(capsule);
const digest = (value) => createHash('sha256').update(value).digest('hex').toUpperCase();
const current = structuredClone(oldInventory);
current.platform.windowsPowerShellVersion = '5.1.26100.2';
current.runtime.pendingOperationId = operationId;
function fixture() {
  return structuredClone({
    failedState: { schemaVersion: 1, deviceId, runtimeStatus: 'FAILED', requestedProfiles: ['core'], readyProfiles: [],
      operationId, manifestDigest: capsule.manifestDigest, generationDigest: capsule.generationDigest,
      failureCode: 'RUNTIME_COMPLETION_UNCERTAIN', updatedAt: '2026-09-18T10:01:00.000Z' },
    controllerPublicKey, capsuleJson, firstInventory: current, secondInventory: current,
    staged: { operationId, manifestDigest: capsule.manifestDigest, generationDigest: capsule.generationDigest,
      capsuleSha256: digest(capsuleJson), archiveBytes: catalog.artifacts[0].bytes,
      archiveSha256: catalog.artifacts[0].sha256, hasWork: false, hasTemporary: false, onlyExpectedTransaction: true },
  });
}

test('recognizes the signed obsolete stage without issuing recovery authority or mutating inputs', () => {
  const input = fixture();
  const before = structuredClone(input);
  const result = assessStagedRetirement(input);
  assert.equal(result.classification, 'OBSOLETE_STAGED_TRANSACTION');
  assert.equal(result.actionable, false);
  assert.equal(result.authority, 'OBSERVATION_ONLY');
  assert.equal(result.operationId, operationId);
  assert.equal(Object.isFrozen(result), true);
  assert.deepEqual(input, before);
});

for (const [name, mutate] of [
  ['different failed operation', (v) => { v.failedState.operationId = '2'.repeat(32); }],
  ['different failed generation', (v) => { v.failedState.generationDigest = 'A'.repeat(64); }],
  ['capsule byte mismatch', (v) => { v.staged.capsuleSha256 = 'A'.repeat(64); }],
  ['archive corruption', (v) => { v.staged.archiveSha256 = 'A'.repeat(64); }],
  ['archive length mismatch', (v) => { v.staged.archiveBytes++; }],
  ['work already started', (v) => { v.staged.hasWork = true; }],
  ['upload incomplete', (v) => { v.staged.hasTemporary = true; }],
  ['unexpected topology', (v) => { v.staged.onlyExpectedTransaction = false; }],
  ['fresh capsule', (v) => { v.firstInventory.platform.windowsPowerShellVersion = oldInventory.platform.windowsPowerShellVersion; v.secondInventory = structuredClone(v.firstInventory); }],
  ['unrelated platform drift', (v) => { v.firstInventory.platform.edition = 'different'; v.secondInventory = structuredClone(v.firstInventory); }],
  ['inventory changed', (v) => { v.secondInventory.pendingReboot = true; }],
  ['reboot pending', (v) => { v.firstInventory.pendingReboot = true; v.secondInventory.pendingReboot = true; }],
  ['interactive session', (v) => { v.firstInventory.interactiveSession = true; v.secondInventory.interactiveSession = true; }],
  ['disk insufficient', (v) => { v.firstInventory.freeBytes = 0; v.secondInventory.freeBytes = 0; }],
  ['different pending operation', (v) => { v.firstInventory.runtime.pendingOperationId = '2'.repeat(32); v.secondInventory = structuredClone(v.firstInventory); }],
  ['noncanonical capsule JSON', (v) => { v.capsuleJson += '\n'; }],
  ['duplicate JSON field', (v) => { v.capsuleJson = v.capsuleJson.replace('{', '{"schemaVersion":1,'); }],
  ['unknown outer fields', (v) => { v.extra = true; }],
]) {
  test(`rejects ${name}`, () => {
    const input = fixture();
    mutate(input);
    assert.throws(() => assessStagedRetirement(input));
  });
}

test('rejects an altered signature and a foreign controller key', () => {
  const input = fixture();
  const changed = JSON.parse(input.capsuleJson);
  changed.signatureBase64 = (changed.signatureBase64[0] === 'A' ? 'B' : 'A') + changed.signatureBase64.slice(1);
  input.capsuleJson = JSON.stringify(changed);
  assert.throws(() => assessStagedRetirement(input), { code: 'RUNTIME_SIGNATURE_INVALID' });
  const other = generateKeyPairSync('rsa', { modulusLength: 3072 }).publicKey.export({ format: 'jwk' });
  const foreign = fixture();
  foreign.controllerPublicKey.modulusBase64Url = other.n;
  assert.throws(() => assessStagedRetirement(foreign), { code: 'RUNTIME_SIGNATURE_INVALID' });
});

test('rejects accessors and proxies without executing caller code', () => {
  const input = fixture();
  let invoked = false;
  Object.defineProperty(input, 'staged', { enumerable: true, get() { invoked = true; throw new Error(); } });
  assert.throws(() => assessStagedRetirement(input));
  assert.equal(invoked, false);
  assert.throws(() => assessStagedRetirement(new Proxy(fixture(), {})));
});


test('transports non-ASCII signed capsule bytes losslessly and rejects malformed wire encoding', () => {
  const input = fixture();
  const wire = { schemaVersion: 1, capsuleBase64: Buffer.from(input.capsuleJson).toString('base64'), staged: input.staged };
  const decoded = decodeStagedRetirementObservation(JSON.stringify(wire));
  assert.equal(decoded.capsuleJson, input.capsuleJson);
  assert.equal(assessStagedRetirement({ ...input, ...decoded }).classification, 'OBSOLETE_STAGED_TRANSACTION');
  for (const bad of ['!', '/w==', wire.capsuleBase64 + ' ', 'A'.repeat(174_768)]) {
    assert.throws(() => decodeStagedRetirementObservation(JSON.stringify({ ...wire, capsuleBase64: bad })));
  }
  assert.throws(() => decodeStagedRetirementObservation(JSON.stringify(wire).replace('{', '{"schemaVersion":1,')));
});

test('reports a stable reboot requirement separately from changing inventory', () => {
  const input = fixture();
  input.firstInventory.pendingReboot = true;
  input.secondInventory.pendingReboot = true;
  assert.throws(() => assessStagedRetirement(input), { code: 'RUNTIME_REBOOT_REQUIRED' });
});

test('unsupported staged contents take priority over incidental reboot requirements', () => {
  const input = fixture();
  input.staged.archiveSha256 = 'A'.repeat(64);
  input.firstInventory.pendingReboot = true;
  input.secondInventory.pendingReboot = true;
  assert.throws(() => assessStagedRetirement(input), { code: 'RUNTIME_STATE_UNSUPPORTED' });
});

test('console replacement of signed non-ASCII text is rejected rather than repaired', () => {
  const input = fixture();
  const damaged = JSON.parse(input.capsuleJson);
  damaged.manifestJson = damaged.manifestJson.replace('家庭中文版', '?????');
  input.capsuleJson = JSON.stringify(damaged);
  assert.throws(() => assessStagedRetirement(input), { code: 'RUNTIME_SIGNATURE_INVALID' });
});

test('observation source builder refuses ineligible failure before transport', async () => {
  const { buildStagedRetirementObservationScript } = await import('../src/runtime/staged-retirement-observation.mjs');
  const input = fixture();
  input.failedState.failureCode = 'RUNTIME_ROLLBACK_INCOMPLETE';
  await assert.rejects(buildStagedRetirementObservationScript(input.failedState, input.controllerPublicKey), {
    code: 'RUNTIME_STATE_UNSUPPORTED',
  });
});
