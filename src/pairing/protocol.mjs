// The HTTPS rendezvous is a trusted bootstrap distributor, not an SSH relay.
export const PAIR_TTL_MS = 10 * 60_000;
export const MAX_BOOTSTRAP_BYTES = 32_767;
const CODE = /^[A-HJ-NP-Z2-9]{12}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const BOOTSTRAP = /^powershell\.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand [A-Za-z0-9+/]+={0,2}$/;
export function pairingError(code, status = 400) { return Object.assign(new Error(code), { code, status }); }
export function normalizePairCode(value) {
  if (typeof value !== 'string' || value.length > 16) throw pairingError('PAIR_INPUT_INVALID');
  const code = value.toUpperCase().replaceAll('-', '');
  if (!CODE.test(code)) throw pairingError('PAIR_INPUT_INVALID');
  return code;
}
export function validateBootstrap(command) {
  if (typeof command !== 'string' || new TextEncoder().encode(command).length > MAX_BOOTSTRAP_BYTES
    || !BOOTSTRAP.test(command)) throw pairingError('PAIR_BOOTSTRAP_INVALID');
  return command;
}
export async function digestToken(token) {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) throw pairingError('PAIR_UNAUTHORIZED', 401);
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return Array.from(new Uint8Array(bytes), (x) => x.toString(16).padStart(2, '0')).join('');
}
export function createPairRecord({ ownerHash, now }) {
  if (!DIGEST.test(ownerHash) || !Number.isSafeInteger(now) || now < 0) throw pairingError('PAIR_INPUT_INVALID');
  return { version: 1, state: 'WAITING', ownerHash, createdAt: now, expiresAt: now + PAIR_TTL_MS, claim: null, envelope: null };
}
export function pairTransition(record, action, input, now) {
  if (!record) throw pairingError('PAIR_UNAVAILABLE', 404);
  if (!Number.isSafeInteger(now) || now < record.createdAt || now >= record.expiresAt) throw pairingError('PAIR_EXPIRED', 410);
  const next = structuredClone(record);
  const owner = () => { if (!DIGEST.test(input.ownerHash ?? '') || input.ownerHash !== record.ownerHash) throw pairingError('PAIR_UNAUTHORIZED', 401); };
  const claimant = () => { if (!DIGEST.test(input.clientHash ?? '') || input.clientHash !== record.claim?.clientHash) throw pairingError('PAIR_UNAUTHORIZED', 401); };
  const terminal = ['CONSUMED', 'CANCELLED'].includes(record.state);
  if (action === 'status') {
    owner();
    return { record: next, response: { state: next.state, expiresAt: next.expiresAt,
      claim: next.claim ? { id: next.claim.clientHash, verification: next.claim.verification } : null } };
  }
  if (action === 'cancel') {
    owner();
    if (record.state === 'CONSUMED') throw pairingError('PAIR_ALREADY_DELIVERED', 409);
    next.state = 'CANCELLED'; next.envelope = null;
    return { record: next, response: { state: next.state } };
  }
  if (terminal) throw pairingError('PAIR_UNAVAILABLE', 410);
  if (action === 'claim') {
    if (record.state !== 'WAITING') throw pairingError('PAIR_ALREADY_CLAIMED', 409);
    if (!DIGEST.test(input.clientHash ?? '') || !/^[0-9]{8}$/.test(input.verification ?? '')) throw pairingError('PAIR_INPUT_INVALID');
    next.claim = { clientHash: input.clientHash, verification: input.verification };
    next.state = 'CLAIMED';
    return { record: next, response: { state: next.state, verification: input.verification, expiresAt: next.expiresAt } };
  }
  if (action === 'approve') {
    owner();
    if (record.state !== 'CLAIMED' || input.claimId !== record.claim.clientHash) throw pairingError('PAIR_CLAIM_CHANGED', 409);
    if (typeof input.envelope !== 'string' || input.envelope.length < 1 || input.envelope.length > 50_000) throw pairingError('PAIR_INPUT_INVALID');
    next.envelope = input.envelope; next.state = 'APPROVED';
    return { record: next, response: { state: next.state } };
  }
  if (action === 'receive') {
    claimant();
    if (record.state === 'CLAIMED') return { record: next, response: { state: 'PENDING' } };
    if (record.state !== 'APPROVED') throw pairingError('PAIR_UNAVAILABLE', 409);
    const envelope = next.envelope;
    next.envelope = null; next.state = 'CONSUMED';
    return { record: next, response: { state: 'DELIVERED', envelope } };
  }
  throw pairingError('PAIR_INPUT_INVALID');
}
