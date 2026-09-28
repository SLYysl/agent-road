import assert from 'node:assert/strict';
import test from 'node:test';
import { loadStagedRetentionWindowsBundle, buildStagedRetentionScript } from '../src/runtime/staged-retention-windows.mjs';
import { createStagedRetentionProposal, createStagedRetentionAttempt } from '../src/runtime/staged-retention-protocol.mjs';
import { retentionFixture, now } from './fixtures/staged-retention.mjs';

test('retention source binds the exact bundle and fixed production path', async () => {
  const bundle = await loadStagedRetentionWindowsBundle();
  const fixture = retentionFixture();
  fixture.executorDigest = bundle.executorDigest;
  const proposal = createStagedRetentionProposal(fixture, now);
  const attempt = createStagedRetentionAttempt(proposal, fixture, now);
  const config = { mode: 'apply', failedState: fixture.assessmentInput.failedState,
    controllerPublicKey: fixture.assessmentInput.controllerPublicKey, proposal, attempt };
  const script = buildStagedRetentionScript(bundle, config);
  assert.ok(script.includes("Invoke-StagedRetention $payload 'C:\\ProgramData\\AgentRoad'"));
  assert.throws(() => buildStagedRetentionScript({ ...bundle, source: bundle.source + '\n' }, config));
  assert.throws(() => buildStagedRetentionScript(bundle, { ...config, attempt: null }));
  assert.throws(() => buildStagedRetentionScript(bundle, { ...config, mode: 'delete' }));
  assert.throws(() => buildStagedRetentionScript(bundle, { ...config,
    failedState: { ...config.failedState, operationId: '2'.repeat(32) } }));
  assert.throws(() => buildStagedRetentionScript(bundle, { ...config, mode: 'observe' }));
  assert.ok(buildStagedRetentionScript(bundle, { ...config, mode: 'observe', proposal: null, attempt: null }));
});
