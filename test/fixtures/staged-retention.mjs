import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createSignedRuntimeManifest } from '../../src/runtime/runtime-manifest.mjs';
import { createRuntimePlan } from '../../src/runtime/runtime-plan.mjs';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 });
const jwk = publicKey.export({ format: 'jwk' });
const controllerPublicKey = { algorithm: 'RSA-SHA256', modulusBase64Url: jwk.n, exponentBase64Url: jwk.e };
const catalog = JSON.parse(await readFile(new URL('../../config/runtime-catalog.json', import.meta.url)));
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
export function assessmentFixture() {
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

export const now = '2026-09-18T10:02:00.000Z';
export function retentionFixture() {
 const names = ['programData', 'agentRoad', 'runtime', 'staging', 'operation', 'transaction', 'files', 'capsule', 'archive'];
 return { assessmentInput: assessmentFixture(), targetBindingDigest: 'D'.repeat(64), executorDigest: 'E'.repeat(64),
   sourceIdentity: Object.fromEntries(names.map((name, i) => [name, 'A'.repeat(16) + ':' + (i + 1).toString(16).toUpperCase().padStart(32, '0')])),
   sourceAclSha256: Object.fromEntries(names.map(name => [name, 'F'.repeat(64)])),
   destination: { rootIdentity: null, operationIdentity: null, transactionAbsent: true } };
}
export function postObservation(proposal) {
 const input = proposal.evidence;
 const ids = input.sourceIdentity;
 const staged = input.assessmentInput.staged;
 return { targetBindingDigest: input.targetBindingDigest, executorDigest: input.executorDigest, source: null, retained: { transaction: ids.transaction, files: ids.files, capsule: ids.capsule, archive: ids.archive,
   capsuleSha256: staged.capsuleSha256, archiveSha256: staged.archiveSha256, archiveBytes: staged.archiveBytes,
   transactionAclSha256: input.sourceAclSha256.transaction, filesAclSha256: input.sourceAclSha256.files, capsuleAclSha256: input.sourceAclSha256.capsule, archiveAclSha256: input.sourceAclSha256.archive },
   parents: Object.fromEntries(['programData','agentRoad','runtime','staging','operation'].map(k => [k, ids[k]])),
   destination: { rootIdentity: 'A'.repeat(16) + ':' + 'B'.repeat(32), operationIdentity: 'A'.repeat(16) + ':' + 'C'.repeat(32) },
   parentAclSha256: Object.fromEntries(['programData','agentRoad','runtime','staging','operation'].map(k => [k, input.sourceAclSha256[k]])),
   runtimeOnlyStaging: true, stagingOnlyExpectedOperation: true, sourceOperationEmpty: true, retainedOnlyExpectedTransaction: true };
}
