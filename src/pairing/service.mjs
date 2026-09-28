import { validateNativeConfiguration } from '../installer/configuration.mjs';
import { cliSession, activeCliSession } from '../auth/service.mjs';
import { createPairRecord, digestToken, normalizePairCode, pairingError, pairTransition, validateBootstrap } from './protocol.mjs';
const ACTIONS = new Set(['create', 'claim', 'status', 'approve', 'receive', 'cancel']);
const FIELDS = { create: ['code', 'ownerToken'], claim: ['code', 'clientToken'], status: ['code', 'ownerToken'], approve: ['code', 'ownerToken', 'claimId', 'command'], receive: ['code', 'clientToken'], cancel: ['code', 'ownerToken'] };
export function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
}
async function bodyJson(request) {
  if (!(request.headers.get('content-type') ?? '').startsWith('application/json')) throw pairingError('PAIR_INPUT_INVALID');
  const reader = request.body?.getReader();
  if (!reader) throw pairingError('PAIR_INPUT_INVALID');
  let size = 0; const chunks = [];
  while (true) {
    const { value, done } = await reader.read(); if (done) break;
    size += value.length;
    if (size > 40_000) { await reader.cancel(); throw pairingError('PAIR_INPUT_TOO_LARGE', 413); }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { throw pairingError('PAIR_INPUT_INVALID'); }
}
function base64(bytes) { return btoa(String.fromCharCode(...bytes)); }
function unbase64(value) { return Uint8Array.from(atob(value), (c) => c.charCodeAt(0)); }
async function storageKey(secret) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(secret ?? '')) throw pairingError('PAIR_SERVICE_UNCONFIGURED', 503);
  const raw = unbase64(secret.replaceAll('-', '+').replaceAll('_', '/') + '=');
  if (raw.length !== 32) throw pairingError('PAIR_SERVICE_UNCONFIGURED', 503);
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function cryptEnvelope(secret, context, value, encrypt) {
  const key = await storageKey(secret);
  const iv = encrypt ? crypto.getRandomValues(new Uint8Array(12)) : unbase64(value.split('.')[0]);
  const params = { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(context) };
  if (encrypt) {
    const bytes = await crypto.subtle.encrypt(params, key, new TextEncoder().encode(value));
    return `${base64(iv)}.${base64(new Uint8Array(bytes))}`;
  }
  const bytes = await crypto.subtle.decrypt(params, key, unbase64(value.split('.')[1]));
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}
async function keyForCode(code) {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(code));
  return 'pair:' + Array.from(new Uint8Array(bytes), (x) => x.toString(16).padStart(2, '0')).join('');
}

// Must be called within one serialized/transactional storage operation.
export async function serviceRequest(request, env, storage, now = Date.now()) {
  try {
    const url = new URL(request.url), action = url.pathname.split('/').at(-1);
    const version = url.pathname.startsWith('/v2/') ? 2 : 1;
    if (version === 2 && env.PAIR_NATIVE_V2_ENABLED !== 'true') return jsonResponse({ code: 'PAIR_PROTOCOL_UNSUPPORTED' }, 404);
    if (request.method !== 'POST' || url.search || url.pathname !== `/v${version}/${action}` || !ACTIONS.has(action)) return jsonResponse({ code: 'PAIR_NOT_FOUND' }, 404);
    // Global bounded rate for this private controller service, not per-visitor identity.
    const bucket = Math.floor(now / 60_000), rate = await storage.get('rate');
    const count = rate?.bucket === bucket ? rate.count + 1 : 1;
    if (count > 180) return jsonResponse({ code: 'PAIR_RATE_LIMITED' }, 429);
    await storage.put('rate', { bucket, count });
    const body = await bodyJson(request);
    const fields = version === 2 && action === 'approve' ? ['code', 'ownerToken', 'claimId', 'configuration'] : FIELDS[action];
    if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).length !== fields.length || fields.some((key) => !Object.hasOwn(body, key))) throw pairingError('PAIR_INPUT_INVALID');
    const code = normalizePairCode(body.code), key = await keyForCode(code);
    const records = await storage.list({ prefix: 'pair:' });
    for (const [name, value] of records) if (now >= value.expiresAt) { await storage.delete(name); records.delete(name); }
    if (action === 'create') {
      const credential = (request.headers.get('authorization') ?? '').replace(/^Bearer /, '');
      let controller = null;
      if (credential.startsWith('ar1.')) {
        try { controller = await cliSession(credential, storage, now); } catch { throw pairingError('PAIR_UNAUTHORIZED', 401); }
      } else {
        const expected = await digestToken(env.PAIR_ADMIN_TOKEN);
        const actual = await digestToken(credential);
        if (actual !== expected) throw pairingError('PAIR_UNAUTHORIZED', 401);
      }
      await storageKey(env.PAIR_STORAGE_KEY); // Refuse creation when payload protection is unavailable.
      if (records.has(key)) throw pairingError('PAIR_CODE_IN_USE', 409);
      if (records.size >= 32) throw pairingError('PAIR_CAPACITY', 429);
      const record = createPairRecord({ ownerHash: await digestToken(body.ownerToken), now });
      record.version = version;
      if (controller) { record.controllerId = controller.id; record.controllerGeneration = controller.generation; record.account = controller.account; }
      await storage.put(key, record);
      await storage.setAlarm(Math.min(...[...records.values()].map((r) => r.expiresAt), record.expiresAt));
      return jsonResponse({ state: record.state, expiresAt: record.expiresAt, ...(version === 1 ? { codeInJoinUrl: true } : { protocolVersion: 2, deliveryKind: 'configuration' }) });
    }
    const record = records.get(key);
    if (record && record.version !== version) throw pairingError('PAIR_PROTOCOL_MISMATCH', 409);
    if (record?.controllerId) {
      const controller = await activeCliSession(record.controllerId, storage, now);
      if (!controller || controller.generation !== record.controllerGeneration || controller.account !== record.account) throw pairingError('PAIR_UNAUTHORIZED', 401);
      if (['status', 'approve', 'cancel'].includes(action)) {
        let session;
        try { session = await cliSession((request.headers.get('authorization') ?? '').replace(/^Bearer /, ''), storage, now); } catch { throw pairingError('PAIR_UNAUTHORIZED', 401); }
        if (session.id !== record.controllerId) throw pairingError('PAIR_UNAUTHORIZED', 401);
      }
    }
    const input = {};
    if (body.ownerToken !== undefined) input.ownerHash = await digestToken(body.ownerToken);
    if (body.clientToken !== undefined) input.clientHash = await digestToken(body.clientToken);
    if (action === 'claim') input.verification = String(crypto.getRandomValues(new Uint32Array(1))[0] % 100_000_000).padStart(8, '0');
    const context = `${version === 2 ? 'v2:' : ''}${code}:${record?.ownerHash}:${record?.claim?.clientHash}`;
    const configurationContext = { origin: env.PUBLIC_ORIGIN, now, expiresAt: record?.expiresAt };
    if (action === 'approve') {
      input.claimId = body.claimId;
      pairTransition(record, action, { ...input, envelope: 'preflight' }, now);
      const payload = version === 2 ? JSON.stringify(validateNativeConfiguration(body.configuration, configurationContext)) : validateBootstrap(body.command);
      input.envelope = await cryptEnvelope(env.PAIR_STORAGE_KEY, context, payload, true);
    }
    const result = pairTransition(record, action, input, now);
    if (action === 'receive' && result.response.state === 'DELIVERED') {
      const payload = await cryptEnvelope(env.PAIR_STORAGE_KEY, context, result.response.envelope, false);
      result.response = version === 2
        ? { state: 'DELIVERED', protocolVersion: 2, configuration: validateNativeConfiguration(JSON.parse(payload), configurationContext) }
        : { state: 'DELIVERED', command: validateBootstrap(payload) };
    }
    // Persist consumption before returning any bootstrap or configuration bytes.
    await storage.put(key, result.record);
    return jsonResponse(result.response);
  } catch (error) {
    const recognized = /^PAIR_[A-Z_]+$/.test(error?.code ?? '');
    return jsonResponse({ code: recognized ? error.code : 'PAIR_SERVICE_FAILED' }, recognized ? error.status : 500);
  }
}
export async function expirePairs(storage, now = Date.now()) {
  const records = await storage.list({ prefix: 'pair:' }); let next = Infinity;
  for (const [key, record] of records) {
    if (now >= record.expiresAt) await storage.delete(key); else next = Math.min(next, record.expiresAt);
  }
  if (Number.isFinite(next)) await storage.setAlarm(next);
  else { await storage.delete('rate'); await storage.deleteAlarm(); }
}
