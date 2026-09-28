import { validateWindowsFilePath } from '../remote/remote-files.mjs';

const TOOLS = Object.freeze(['git', 'node', 'python', 'rg']);
const validated = new WeakSet();
function invalid() { throw Object.assign(new Error('EXISTING_BASE_INVALID'), {code: 'EXISTING_BASE_INVALID'}); }
function exact(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== fields.length || !fields.every(key => Object.hasOwn(value, key))) invalid();
}

// Accept bounded JSON text, not arbitrary caller objects with getters/proxies.
export function parseExistingBase(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 65536) invalid();
  let report;
  try { report = JSON.parse(text); } catch { invalid(); }
  exact(report, ['schemaVersion', 'candidates']);
  if (report.schemaVersion !== 1 || !Array.isArray(report.candidates) || report.candidates.length > 32) invalid();
  const paths = new Set();
  const candidates = report.candidates.map(candidate => {
    exact(candidate, ['tool', 'path', 'source', 'status', 'version', 'sha256', 'environmentModules', 'reason']);
    if (!TOOLS.includes(candidate.tool) || !['path', 'machine', 'user-profile'].includes(candidate.source)
      || !['verified', 'unavailable', 'store-alias'].includes(candidate.status)
      || typeof candidate.environmentModules !== 'boolean') invalid();
    try { validateWindowsFilePath(candidate.path); } catch { invalid(); }
    if (!candidate.path.toLowerCase().endsWith('.exe') || paths.has(candidate.path.toLowerCase())) invalid();
    paths.add(candidate.path.toLowerCase());
    if (candidate.status === 'verified') {
      if (candidate.reason !== null) invalid();
      if (typeof candidate.version !== 'string' || !/^\d{1,3}\.\d{1,3}\.\d{1,3}(?:\.windows\.\d{1,3})?$/.test(candidate.version)
        || typeof candidate.sha256 !== 'string' || !/^[A-F0-9]{64}$/.test(candidate.sha256)
        || /\\WindowsApps\\/i.test(candidate.path)) invalid();
    } else {
      if (candidate.version !== null || candidate.sha256 !== null || candidate.environmentModules) invalid();
      if (candidate.status === 'store-alias' ? candidate.reason !== 'STORE_ALIAS'
        : !['PROBE_FAILED', 'REPARSE', 'TIMEOUT', 'OUTPUT', 'PROBE', 'VERSION', 'PLATFORM', 'CHANGED'].includes(candidate.reason)) invalid();
    }
    if (candidate.tool !== 'python' && candidate.environmentModules) invalid();
    return Object.freeze({...candidate});
  });
  const result = Object.freeze({schemaVersion: 1, candidates: Object.freeze(candidates)});
  validated.add(result);
  return result;
}

// This is capability assessment only: never publish a runtime READY transition.
export function assessExistingBase(report) {
  if (!validated.has(report)) invalid();
  return Object.freeze({
    schemaVersion: 1, managedBaseReady: false,
    tools: Object.freeze(TOOLS.map(tool => {
      const candidates = report.candidates.filter(candidate => candidate.tool === tool);
      const usable = candidates.filter(candidate => candidate.status === 'verified'
        && (tool !== 'python' || candidate.environmentModules));
      const action = usable.length > 1 ? 'select' : usable.length === 1 ? 'reuse'
        : candidates.length ? 'review' : 'not-found';
      return Object.freeze({tool, action, candidates: Object.freeze(candidates)});
    })),
  });
}
