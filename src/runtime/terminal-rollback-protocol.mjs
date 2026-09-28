import {createHash, createPublicKey, verify} from 'node:crypto';
import {isProxy} from 'node:util/types';
import {deriveRuntimeControllerKeyIdentity} from './runtime-manifest.mjs';
import {validateRuntimeStateRecord} from './runtime-state-store.mjs';

const SHA = /^[A-F0-9]{64}$/u;
const CAPSULE = ['schemaVersion','manifestJson','manifestDigest','generationDigest','signatureAlgorithm','signatureBase64','controllerKeyId','controllerPublicKeyJson'];
const JOURNAL = ['schemaVersion','revision','operationId','manifestDigest','generationDigest','catalogDigest','inventoryDigest','controllerKeyId','requestedProfiles','status','phase','completedPhases','changes','snapshot','restartRequired','failureCode','rollbackStatus'];
const OBSERVATION = ['schemaVersion','capsuleJson','journalJson','activeAbsent','previousAbsent','generationAbsent','tombstoneAbsent','archiveBytes','archiveSha256'];
function fail() { const e = new Error('RUNTIME_STATE_UNSUPPORTED'); e.code = e.message; throw e; }
function snapshot(v, depth = 0) {
  if (v === null || typeof v === 'string' || typeof v === 'boolean') return v;
  if (typeof v === 'number' && Number.isSafeInteger(v)) return v;
  if (depth > 20 || typeof v !== 'object' || isProxy(v) || Object.getOwnPropertySymbols(v).length) fail();
  const array = Array.isArray(v);
  if (Object.getPrototypeOf(v) !== (array ? Array.prototype : Object.prototype)) fail();
  const names = Object.getOwnPropertyNames(v).filter(k => !array || k !== 'length');
  if (names.length > 100 || (array && (names.length !== v.length || names.some((k,i) => k !== String(i))))) fail();
  const out = array ? [] : {};
  for (const k of names) {
    const d = Object.getOwnPropertyDescriptor(v,k);
    if (!d.enumerable || !Object.hasOwn(d,'value') || k === '__proto__') fail();
    out[k] = snapshot(d.value,depth+1);
  }
  return Object.freeze(out);
}
function exact(v, fields) {
  if (v === null || Array.isArray(v) || typeof v !== 'object' || Object.keys(v).length !== fields.length
    || fields.some(k => !Object.hasOwn(v,k))) fail();
  return v;
}
function json(s, max) {
  if (typeof s !== 'string' || Buffer.byteLength(s) > max) fail();
  let v; try { v = JSON.parse(s); } catch { fail(); }
  if (JSON.stringify(v) !== s) fail();
  return v;
}
function same(a,b) { return JSON.stringify(a) === JSON.stringify(b); }
export function terminalRollbackDigest(v) {
  return createHash('sha256').update('AGENT_ROAD_TERMINAL_ROLLBACK_V1\0').update(JSON.stringify(v)).digest('hex').toUpperCase();
}
export function assertTerminalRollbackStatePair(expectedInput,nextInput) {
  const expected = validateRuntimeStateRecord(expectedInput), next = validateRuntimeStateRecord(nextInput);
  if (expected.schemaVersion !== 1 || expected.runtimeStatus !== 'FAILED'
    || expected.failureCode !== 'RUNTIME_COMPLETION_UNCERTAIN'
    || !same(expected.requestedProfiles,['core']) || expected.readyProfiles.length !== 0
    || next.failureCode !== 'RUNTIME_INSTALL_FAILED' || next.updatedAt <= expected.updatedAt
    || !same({...next,failureCode:expected.failureCode,updatedAt:expected.updatedAt},expected)) fail();
  return {expected,next};
}
export function validateTerminalRollbackEvidence(input) {
  const v = exact(snapshot(input),['failedState','controllerPublicKey','targetBindingDigest','executorDigest','observation']);
  const state = validateRuntimeStateRecord(v.failedState);
  if (state.schemaVersion !== 1 || state.runtimeStatus !== 'FAILED' || state.failureCode !== 'RUNTIME_COMPLETION_UNCERTAIN'
    || !same(state.requestedProfiles,['core']) || state.readyProfiles.length !== 0) fail();
  for (const k of ['targetBindingDigest','executorDigest']) if (typeof v[k] !== 'string' || !SHA.test(v[k])) fail();
  const o = exact(v.observation,OBSERVATION);
  if (o.schemaVersion !== 1 || ['activeAbsent','previousAbsent','generationAbsent','tombstoneAbsent'].some(k => o[k] !== true)) fail();
  const c = exact(json(o.capsuleJson,8192),CAPSULE), m = json(c.manifestJson,6144), j = exact(json(o.journalJson,4096),JOURNAL);
  const key = deriveRuntimeControllerKeyIdentity(v.controllerPublicKey);
  if (c.schemaVersion !== 1 || c.signatureAlgorithm !== 'RSA-SHA256' || c.controllerKeyId !== key.controllerKeyId
    || c.controllerPublicKeyJson !== key.controllerPublicKeyJson || typeof c.signatureBase64 !== 'string'
    || !/^[A-Za-z0-9+/]{512}$/u.test(c.signatureBase64)) fail();
  const pub = createPublicKey({format:'jwk',key:{kty:'RSA',n:key.controllerPublicKey.modulusBase64Url,e:key.controllerPublicKey.exponentBase64Url}});
  if (!verify('RSA-SHA256',Buffer.concat([Buffer.from('AGENT_ROAD_RUNTIME_V1\0'),Buffer.from(c.manifestJson)]),pub,Buffer.from(c.signatureBase64,'base64'))) fail();
  if (m.schemaVersion !== 1 || m.deviceId !== state.deviceId || m.operationId !== state.operationId
    || c.manifestDigest !== state.manifestDigest || c.generationDigest !== state.generationDigest
    || m.generationDigest !== state.generationDigest
    || createHash('sha256').update(c.manifestJson).digest('hex').toUpperCase() !== state.manifestDigest
    || !same(m.requestedProfiles,['core']) || !same(m.profiles,['core'])
    || !Array.isArray(m.components) || m.components.length !== 1 || m.components[0].id !== 'powershell-7'
    || !Number.isSafeInteger(o.archiveBytes) || o.archiveBytes < 1 || o.archiveBytes !== m.components[0].bytes
    || typeof o.archiveSha256 !== 'string' || !SHA.test(o.archiveSha256) || o.archiveSha256 !== m.components[0].sha256) fail();
  if (j.schemaVersion !== 1 || !Number.isSafeInteger(j.revision) || j.revision < 1
    || j.operationId !== state.operationId || j.manifestDigest !== state.manifestDigest || j.generationDigest !== state.generationDigest
    || j.catalogDigest !== m.catalogDigest || j.inventoryDigest !== m.inventoryDigest || j.controllerKeyId !== c.controllerKeyId
    || j.status !== 'rolled-back' || j.phase !== 'rollback' || j.rollbackStatus !== 'succeeded'
    || j.failureCode !== 'RUNTIME_INTERNAL_ERROR' || j.restartRequired !== false || !same(j.requestedProfiles,['core'])
    || !same(j.completedPhases,['discover','verify-manifest','verify-artifacts','snapshot'])
    || !same(j.changes,['work-created']) || !same(j.snapshot,{active:null,previous:null})) fail();
  return v;
}
export function createTerminalRollbackCommit(input, secondObservation, now) {
  const evidence = validateTerminalRollbackEvidence(input);
  if (!same(evidence.observation,snapshot(secondObservation)) || typeof now !== 'string'
    || !Number.isFinite(Date.parse(now)) || new Date(now).toISOString() !== now || now <= evidence.failedState.updatedAt) fail();
  const nextState = validateRuntimeStateRecord({...evidence.failedState,failureCode:'RUNTIME_INSTALL_FAILED',updatedAt:now});
  assertTerminalRollbackStatePair(evidence.failedState,nextState);
  const fields = {schemaVersion:1,kind:'INITIAL_CORE_ROLLBACK_CONFIRMED',evidence,nextState,confirmedAt:now};
  return snapshot({...fields,commitDigest:terminalRollbackDigest(fields)});
}
export function validateTerminalRollbackCommit(input) {
  const v = exact(snapshot(input),['schemaVersion','kind','evidence','nextState','confirmedAt','commitDigest']);
  const expected = createTerminalRollbackCommit(v.evidence,v.evidence.observation,v.confirmedAt);
  if (!same(v,expected)) fail();
  return expected;
}
