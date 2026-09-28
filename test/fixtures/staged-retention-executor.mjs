import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { retentionFixture } from './staged-retention.mjs';
import { createRuntimePlan } from '../../src/runtime/runtime-plan.mjs';
import { createSignedRuntimeManifest } from '../../src/runtime/runtime-manifest.mjs';
import { loadStagedRetentionWindowsBundle } from '../../src/runtime/staged-retention-windows.mjs';

export async function buildRetentionExecutorFixture() {
  const fixture = retentionFixture();
  const archive = Buffer.from('isolated archive bytes');
  const catalog = JSON.parse(await readFile(new URL('../../config/runtime-catalog.json', import.meta.url)));
  catalog.artifacts[0].bytes = archive.length;
  catalog.artifacts[0].sha256 = createHash('sha256').update(archive).digest('hex').toUpperCase();
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 });
  const jwk = publicKey.export({ format: 'jwk' });
  const key = { algorithm: 'RSA-SHA256', modulusBase64Url: jwk.n, exponentBase64Url: jwk.e };
  const old = structuredClone(fixture.assessmentInput.firstInventory);
  old.runtime.pendingOperationId = null;
  old.platform.windowsPowerShellVersion = '5.1.26100.1';
  const state = fixture.assessmentInput.failedState;
  const plan = createRuntimePlan({ catalog, inventory: old, deviceId: state.deviceId, operationId: state.operationId,
    requestedProfiles: ['core'], createdAt: '2026-09-18T10:00:00.000Z' });
  const capsule = await createSignedRuntimeManifest({ catalog, inventory: old, plan,
    dependencies: { getSigningPublicKey: async () => key,
      sign: async bytes => sign('RSA-SHA256', bytes, privateKey).toString('base64') } });
  fixture.assessmentInput.controllerPublicKey = key;
  fixture.assessmentInput.capsuleJson = JSON.stringify(capsule);
  Object.assign(state, { manifestDigest: capsule.manifestDigest, generationDigest: capsule.generationDigest });
  Object.assign(fixture.assessmentInput.staged, { manifestDigest: capsule.manifestDigest, generationDigest: capsule.generationDigest,
    capsuleSha256: createHash('sha256').update(JSON.stringify(capsule)).digest('hex').toUpperCase(),
    archiveSha256: catalog.artifacts[0].sha256, archiveBytes: archive.length });
  const bundle = await loadStagedRetentionWindowsBundle();
  fixture.executorDigest = bundle.executorDigest;
  const encoded = Buffer.from(JSON.stringify({ fixture, archiveBase64: archive.toString('base64'), keyJson: JSON.stringify(key) })).toString('base64');
  const tail = await readFile(new URL('../windows/staged-retention-executor-fixture.ps1', import.meta.url), 'utf8');
  // Test-only fault injection. Production source has no caller-controlled hook.
  const source = bundle.source.replace('  [AgentRoadRetention.Native]::Rename($context.handles.transaction,$target)',
    '  Invoke-RetentionFixtureHook $context $target "before"\n  [AgentRoadRetention.Native]::Rename($context.handles.transaction,$target)\n  Invoke-RetentionFixtureHook $context $target "after"');
  return source.replaceAll('Global\\AgentRoadRuntimeMutation', 'Global\\AgentRoadRetentionFixtureMutation')
    + `\n$fixtureData=$script:Utf8.GetString([Convert]::FromBase64String('${encoded}'))|ConvertFrom-Json\n${tail}`;
}
