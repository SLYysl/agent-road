import test from 'node:test';
import assert from 'node:assert/strict';
import { observePairDelivery } from '../src/pairing/delivery-observation.mjs';

test('approval is not delivery; consumption is not execution', async () => {
  let requests = 0;
  const result = await observePairDelivery({ signal: new AbortController().signal,
    request: async () => ({ state: ++requests === 1 ? 'APPROVED' : 'CONSUMED' }), wait: async () => {} });
  assert.equal(requests, 2);
  assert.deepEqual(result, { state: 'DELIVERED', executionConfirmed: false });
});
test('missing delivery is bounded and not labelled a failed execution', async () => {
  let time = 0, requests = 0;
  const result = await observePairDelivery({ signal: new AbortController().signal,
    now: () => time, wait: async () => { time += 30_000; },
    request: async () => { requests++; return { state: 'APPROVED' }; } });
  assert.equal(requests, 4);
  assert.deepEqual(result, { state: 'DELIVERY_UNCONFIRMED', code: 'PAIR_DELIVERY_OBSERVATION_TIMEOUT' });
});
test('status failure records only a finite code, without retry', async () => {
  let requests = 0;
  const result = await observePairDelivery({ signal: new AbortController().signal,
    request: async () => { requests++; throw Object.assign(new Error('secret'), { code: 'secret' }); } });
  assert.equal(requests, 1);
  assert.deepEqual(result, { state: 'DELIVERY_UNCONFIRMED', code: 'PAIR_STATUS_UNAVAILABLE' });
});
test('enrollment completion interrupts observation without overriding its result', async () => {
  const controller = new AbortController();
  const result = await observePairDelivery({ signal: controller.signal,
    request: async () => ({ state: 'APPROVED' }),
    wait: async () => { controller.abort(); throw new Error('aborted'); } });
  assert.deepEqual(result, { state: 'OBSERVATION_STOPPED' });
});
test('cancelled or malformed state is not delivery', async () => {
  for (const state of ['CANCELLED', 'CLAIMED', undefined]) {
    const result = await observePairDelivery({ signal: new AbortController().signal, request: async () => ({ state }) });
    assert.equal(result.code, 'PAIR_STATUS_UNEXPECTED');
  }
});
