import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyReadiness, observeReadiness } from '../src/runtime/runtime-readiness.mjs';
import { main } from '../src/cli.mjs';
const sample = (extra = {}) => ({ inventory: { freeBytes: 123, pendingReboot: false, runtime: { pendingOperationId: null }, ...extra }, servicingActive: false });
test('readiness distinguishes reboot, servicing, pending operation and drift', () => {
  assert.equal(classifyReadiness(sample(), sample({ freeBytes: 456 })), 'READY_FOR_PLAN');
  assert.equal(classifyReadiness(sample(), sample({ pendingReboot: true })), 'REBOOT_REQUIRED');
  assert.equal(classifyReadiness(sample(), { ...sample(), servicingActive: true }), 'SERVICING_ACTIVE');
  assert.equal(classifyReadiness(sample(), sample({ runtime: { pendingOperationId: 'pending' } })), 'RECOVERY_REQUIRED');
  assert.equal(classifyReadiness(sample(), sample({ platform: { version: 'changed' } })), 'INVENTORY_CHANGED');
  assert.equal(classifyReadiness({ ...sample(), servicingActive: true }, sample({ pendingReboot: true })), 'REBOOT_REQUIRED');
});
test('readiness performs two read-only samples and never retries failed reads', async () => {
  const calls = []; const d = { loadTarget: async () => ({}), readInventory: async () => { calls.push('inventory'); return sample().inventory; },
    servicing: async () => { calls.push('servicing'); return false; }, wait: async ms => { calls.push(ms); } };
  assert.equal((await observeReadiness('dev_test', 60, {}, d)).status, 'READY_FOR_PLAN');
  assert.deepEqual(calls, ['inventory', 'servicing', 60000, 'inventory', 'servicing']);
  let count = 0;
  await assert.rejects(observeReadiness('dev_test', 60, {}, { ...d, readInventory: async () => { count++; throw Error('failure'); } }));
  assert.equal(count, 1);
  const blocked = await observeReadiness('dev_test', 60, {}, { ...d,
    readInventory: async () => sample({ pendingReboot: true }).inventory, wait: async () => assert.fail('must not wait on a known blocker') });
  assert.equal(blocked.status, 'REBOOT_REQUIRED'); assert.equal(blocked.samples, 1);
});
test('new CLI commands reject invalid selectors before remote dependencies', async () => {
  for (const args of [['runtime-readiness', 'dev_test', '--interval-seconds', '0'], ['runtime-retain-empty-stage', 'dev_test', '--apply', '--inspect'],
    ['runtime-readiness', 'latest'], ['runtime-retain-empty-stage', 'dev_test']]) {
    let error = ''; const io = { stdout: { write() { assert.fail('unexpected output'); } }, stderr: { write(s) { error += s; } } };
    assert.equal(await main(args, {}, io), 2); assert.equal(error, 'RUNTIME_INPUT_INVALID\n');
  }
});
