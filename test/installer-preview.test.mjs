import test from 'node:test';
import assert from 'node:assert/strict';
import { previewInstaller, simulateInstaller } from '../src/installer/preview.mjs';
import { mkdtemp, writeFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
const input = { schemaVersion: 1, purpose: 'agent-road-offline-preview', requestId: 'a'.repeat(32),
  origin: 'https://pair.example', createdAt: 1000, expiresAt: 601000, profile: 'core' };
const context = { expectedOrigin: input.origin, now: 2000 };
const preview = (value = input, env = context) => previewInstaller(JSON.stringify(value), env);

test('preview grants no authority and digest ignores JSON key order', () => {
  const plan = preview();
  assert.equal(plan.executable, false);
  assert.equal(plan.authorized, false);
  assert.ok(Object.isFrozen(plan.phases));
  assert.equal(plan.configSha256, preview(Object.fromEntries(Object.entries(input).reverse())).configSha256);
  assert.notEqual(plan.configSha256, preview({ ...input, requestId: 'b'.repeat(32) }).configSha256);
});
test('executable fields, credentials and unknown fields are rejected', () => {
  for (const key of ['command', 'script', 'encodedCommand', 'authKey', 'path', '__proto__']) {
    assert.throws(() => preview({ ...input, [key]: 'sensitive value' }), { code: 'PREVIEW_INPUT_INVALID' });
  }
  for (const key of Object.keys(input)) {
    const incomplete = { ...input }; delete incomplete[key];
    assert.throws(() => preview(incomplete), { code: 'PREVIEW_INPUT_INVALID' });
  }
});
test('wrong origin and version cannot select a legacy fallback', () => {
  assert.throws(() => preview({ ...input, origin: 'https://other.example' }), { code: 'PREVIEW_ORIGIN_MISMATCH' });
  assert.throws(() => preview({ ...input, schemaVersion: 2 }), { code: 'PREVIEW_VERSION_UNSUPPORTED' });
  for (const origin of ['https://user:secret@pair.example', 'https://pair.example/path', 'http://pair.example']) {
    assert.throws(() => preview({ ...input, origin }), { code: 'PREVIEW_INPUT_INVALID' });
  }
});
test('expiry, future issuance and invalid lifetimes fail closed', () => {
  for (const now of [999, 601000]) assert.throws(() => preview(input, { ...context, now }), { code: 'PREVIEW_EXPIRED' });
  for (const expiresAt of [1000, 601001, NaN]) assert.throws(() => preview({ ...input, expiresAt }), { code: 'PREVIEW_TIME_INVALID' });
});
test('malformed and oversized input expose only finite errors', () => {
  for (const text of ['null', '[]', '{secret', ' '.repeat(4097)]) {
    assert.throws(() => previewInstaller(text, context), { code: 'PREVIEW_INPUT_INVALID' });
  }
});
test('unknown acknowledgement or failure stops before subsequent phases', () => {
  for (const outcome of ['UNKNOWN', 'FAIL']) {
    const result = simulateInstaller(preview(), ['PASS', outcome, 'PASS']);
    assert.equal(result.executed, false);
    assert.equal(result.receipts.length, 2);
    assert.ok(result.receipts.every(receipt => receipt.simulation));
    assert.equal(result.receipts.at(-1).outcome, outcome);
  }
  assert.equal(simulateInstaller(preview()).receipts.length, 1);
});
test('all-pass simulation still cannot report installed or runtime READY', () => {
  const result = simulateInstaller(preview(), Array(5).fill('PASS'));
  assert.equal(result.state, 'SIMULATED_COMPLETE');
  assert.equal(result.executed, false);
  assert.throws(() => simulateInstaller(preview(), ['RETRY']), { code: 'PREVIEW_SIMULATION_INVALID' });
});
test('local CLI previews data without execution and rejects symlinks or malformed files', async t => {
  const root = await mkdtemp(join(tmpdir(), 'installer-preview-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, 'input.json');
  const now = Date.now();
  await writeFile(path, JSON.stringify({ ...input, createdAt: now, expiresAt: now + 600000 }), { mode: 0o600 });
  const run = file => spawnSync(process.execPath, ['tools/installer-preview.mjs', file, input.origin], { encoding: 'utf8' });
  const valid = run(path);
  assert.equal(valid.status, 0, valid.stderr);
  assert.equal(JSON.parse(valid.stdout).plan.executable, false);
  assert.equal(JSON.parse(valid.stdout).simulation.state, 'SIMULATED_RECONCILIATION_REQUIRED');
  const link = join(root, 'link.json'); await symlink(path, link);
  assert.equal(run(link).status, 2);
  await writeFile(path, 'sensitive malformed data');
  const invalid = run(path);
  assert.equal(invalid.status, 2);
  assert.equal(invalid.stdout, '');
  assert.equal(invalid.stderr, 'PREVIEW_INPUT_INVALID\n');
});
