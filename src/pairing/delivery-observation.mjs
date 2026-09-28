import { setTimeout as delay } from 'node:timers/promises';

// A consumed envelope proves retrieval, never execution or successful enrollment.
// Observation failure must not cancel a bootstrap that may already be running.
export async function observePairDelivery({ request, signal, now = Date.now,
  wait = () => delay(2000, undefined, { signal }) }) {
  const deadline = now() + 120_000;
  while (!signal.aborted && now() < deadline) {
    let status;
    try { status = await request(); }
    catch (error) {
      if (signal.aborted) return { state: 'OBSERVATION_STOPPED' };
      const code = ['PAIR_EXPIRED', 'PAIR_UNAVAILABLE', 'PAIR_UNAUTHORIZED'].includes(error.code)
        ? error.code : 'PAIR_STATUS_UNAVAILABLE';
      return { state: 'DELIVERY_UNCONFIRMED', code };
    }
    if (status?.state === 'CONSUMED') return { state: 'DELIVERED', executionConfirmed: false };
    if (status?.state !== 'APPROVED') return { state: 'DELIVERY_UNCONFIRMED', code: 'PAIR_STATUS_UNEXPECTED' };
    try { await wait(); }
    catch { return { state: signal.aborted ? 'OBSERVATION_STOPPED' : 'DELIVERY_UNCONFIRMED' }; }
  }
  return signal.aborted ? { state: 'OBSERVATION_STOPPED' }
    : { state: 'DELIVERY_UNCONFIRMED', code: 'PAIR_DELIVERY_OBSERVATION_TIMEOUT' };
}
