import { createHash } from 'node:crypto';

const FIELDS = ['schemaVersion', 'purpose', 'requestId', 'origin', 'createdAt', 'expiresAt', 'profile'];
const PHASES = ['OWNER_CONSENT', 'TRUSTED_INSTALLER', 'PAIR_VERIFICATION', 'SSH_IDENTITY', 'CORE_READINESS'];
function fail(code) { throw Object.assign(new Error(code), { code }); }
function origin(value) {
  if (typeof value !== 'string' || !/^https:\/\/[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(value)) return false;
  try { return new URL(value).origin === value; } catch { return false; }
}

// Experimental offline contract. It grants no authority and accepts no executable
// material, credentials, artifact URLs, installation paths or callback addresses.
export function previewInstaller(text, { expectedOrigin, now = Date.now() } = {}) {
  if (!origin(expectedOrigin) || !Number.isSafeInteger(now) || now < 0) fail('PREVIEW_CONTEXT_INVALID');
  if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > 4096) fail('PREVIEW_INPUT_INVALID');
  let input;
  try { input = JSON.parse(text); } catch { fail('PREVIEW_INPUT_INVALID'); }
  if (!input || Array.isArray(input) || typeof input !== 'object'
    || Object.keys(input).length !== FIELDS.length || FIELDS.some(key => !Object.hasOwn(input, key))) fail('PREVIEW_INPUT_INVALID');
  if (input.schemaVersion !== 1 || input.purpose !== 'agent-road-offline-preview') fail('PREVIEW_VERSION_UNSUPPORTED');
  if (!/^[a-f0-9]{32}$/.test(input.requestId ?? '') || typeof input.requestId !== 'string'
    || input.profile !== 'core' || !origin(input.origin)) fail('PREVIEW_INPUT_INVALID');
  if (input.origin !== expectedOrigin) fail('PREVIEW_ORIGIN_MISMATCH');
  if (!Number.isSafeInteger(input.createdAt) || !Number.isSafeInteger(input.expiresAt)
    || input.createdAt < 0 || input.expiresAt <= input.createdAt
    || input.expiresAt - input.createdAt > 600_000) fail('PREVIEW_TIME_INVALID');
  if (now < input.createdAt || now >= input.expiresAt) fail('PREVIEW_EXPIRED');
  const canonical = Object.fromEntries(FIELDS.map(key => [key, input[key]]));
  return Object.freeze({ schemaVersion: 1, mode: 'OFFLINE_PREVIEW', requestId: input.requestId,
    configSha256: createHash('sha256').update(JSON.stringify(canonical)).digest('hex'),
    expiresAt: input.expiresAt, executable: false, authorized: false,
    releaseBlockers: Object.freeze(['SIGNED_INSTALLER_REQUIRED', 'NATIVE_INSTALLER_INTEGRATION_REQUIRED', 'FRESH_WINDOWS_ACCEPTANCE_REQUIRED']),
    phases: Object.freeze([...PHASES]) });
}

// Simulated receipts are deliberately incompatible with runtime/install receipts.
// A missing acknowledgement stops the simulation; it never means retry the action.
export function simulateInstaller(plan, outcomes = []) {
  if (!plan || plan.mode !== 'OFFLINE_PREVIEW' || plan.executable !== false || plan.authorized !== false
    || !/^[a-f0-9]{64}$/.test(plan.configSha256 ?? '') || !Array.isArray(plan.phases)
    || JSON.stringify(plan.phases) !== JSON.stringify(PHASES)
    || !Array.isArray(outcomes) || outcomes.length > PHASES.length
    || outcomes.some(value => !['PASS', 'FAIL', 'UNKNOWN'].includes(value))) fail('PREVIEW_SIMULATION_INVALID');
  const receipts = [];
  for (let index = 0; index < PHASES.length; index++) {
    const outcome = outcomes[index] ?? 'UNKNOWN';
    receipts.push(Object.freeze({ simulation: true, configSha256: plan.configSha256, phase: PHASES[index], outcome }));
    if (outcome !== 'PASS') return Object.freeze({ mode: 'OFFLINE_SIMULATION', executed: false,
      state: outcome === 'FAIL' ? 'SIMULATED_FAILURE' : 'SIMULATED_RECONCILIATION_REQUIRED', receipts: Object.freeze(receipts) });
  }
  return Object.freeze({ mode: 'OFFLINE_SIMULATION', executed: false, state: 'SIMULATED_COMPLETE', receipts: Object.freeze(receipts) });
}
