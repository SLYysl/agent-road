import { createHash } from 'node:crypto';
import { lstat, mkdir, open, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { statePaths, runtimeDeviceRecoveryPaths } from '../core/paths.mjs';
import { trustedInput } from '../remote/remote-target.mjs';
import { selectAddress } from '../remote/windows-remote.mjs';
import { withTrustedSshSession } from '../ssh/trusted-ssh-session.mjs';
import { runProcess } from '../process/run-process.mjs';
import { createProductionRuntimeRecoveryDependencies } from './production-runtime-dependencies.mjs';
import { runtimeRecoveryTargetBindingDigest } from './runtime-recovery-remote.mjs';
import { loadStagedRetentionWindowsBundle } from './staged-retention-windows.mjs';
import { retentionScriptInvocation } from './staged-retention-remote.mjs';
import { validateRuntimeStateRecord } from './runtime-state-store.mjs';

const NAMES = ['programData', 'agentRoad', 'runtime', 'staging', 'operation', 'transaction', 'files'];
function fail(code = 'RUNTIME_STATE_UNSUPPORTED') { const e = new Error(code); e.code = code; throw e; }
function exact(v, keys) {
  if (!v || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).length !== keys.length
    || keys.some(k => !Object.hasOwn(v, k))) fail();
}
export function validateEmptyStageProof(v) {
  exact(v, ['tree', 'bootUtc', 'destinationAbsent']); exact(v.tree, ['identities', 'acls']);
  if (v.destinationAbsent !== true || typeof v.bootUtc !== 'string' || !Number.isFinite(Date.parse(v.bootUtc))) fail();
  exact(v.tree.identities, NAMES); exact(v.tree.acls, NAMES);
  const ids = Object.values(v.tree.identities);
  if (ids.some(id => typeof id !== 'string' || !/^[A-F0-9]{16}:[A-F0-9]{32}$/u.test(id))
    || new Set(ids).size !== NAMES.length || ids.some(id => id.slice(0, 16) !== ids[0].slice(0, 16))
    || Object.values(v.tree.acls).some(s => typeof s !== 'string' || !/^[A-F0-9]{64}$/u.test(s))) fail();
  return v;
}
export function eligibleEmptyStageState(input, deviceId) {
  const s = validateRuntimeStateRecord(input);
  if (s.deviceId !== deviceId || s.runtimeStatus !== 'FAILED' || s.failureCode !== 'RUNTIME_COMPLETION_UNCERTAIN'
    || s.requestedProfiles.length !== 1 || s.requestedProfiles[0] !== 'core' || s.readyProfiles.length
    || !/^[a-f0-9]{32}$/u.test(s.operationId ?? '') || !/^[A-F0-9]{64}$/u.test(s.manifestDigest ?? '')) fail();
  return s;
}
export async function emptyStageBundle() {
  const base = await loadStagedRetentionWindowsBundle();
  const driver = await readFile(new URL('../../windows/empty-stage-retention.ps1', import.meta.url), 'utf8');
  const source = `${base.source}\n${driver}`;
  return { source, digest: createHash('sha256').update(source).digest('hex').toUpperCase() };
}
export function emptyStageScript(bundle, payload, root = 'C:\\ProgramData\\AgentRoad') {
  // Custom root is reserved for isolated Windows filesystem fixtures.
  if (!/^C:\\[A-Za-z0-9\\_-]+$/u.test(root)) fail('RUNTIME_INPUT_INVALID');
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64');
  return bundle.source + `\n$p=$script:Utf8.GetString([Convert]::FromBase64String('${encoded}'))|ConvertFrom-Json\n`
    + `try {$r=Invoke-EmptyStageRetention $p '${root}';[Console]::Out.Write(($r|ConvertTo-Json -Compress -Depth 12))}`
    + "catch {$c=[string]$_.Exception.Message;if($c -cnotin @('RUNTIME_STATE_UNSUPPORTED','RUNTIME_INPUT_INVALID','RUNTIME_INVENTORY_CHANGED','RUNTIME_COMPLETION_UNCERTAIN','RUNTIME_ALREADY_RUNNING')){$c='RUNTIME_STATE_UNSUPPORTED'};[Console]::Out.Write((@{error=$c}|ConvertTo-Json -Compress));exit 73}";
}
async function privateNode(path, directory) {
  const s = await lstat(path);
  if (s.isSymbolicLink() || (directory ? !s.isDirectory() : !s.isFile() || s.nlink !== 1)
    || s.uid !== process.getuid() || (s.mode & 0o077)) fail();
}
async function save(dir, name, value) {
  const f = await open(join(dir, name), 'wx', 0o600);
  try { await f.writeFile(JSON.stringify(value) + '\n'); await f.sync(); } finally { await f.close(); }
  const d = await open(dir, 'r'); try { await d.sync(); } finally { await d.close(); }
}
async function load(dir, name) {
  const path = join(dir, name); await privateNode(path, false); return JSON.parse(await readFile(path, 'utf8'));
}

// Maintenance-only entry point. It retains bytes/topology and never transitions
// runtime state. Existing reboot-fenced recovery still owns that transition.
export async function retainEmptyStage(mode, deviceId, env = process.env) {
  if (!['inspect', 'apply', 'reconcile'].includes(mode)) fail('RUNTIME_INPUT_INVALID');
  const d = createProductionRuntimeRecoveryDependencies(env);
  const state = eligibleEmptyStageState(await d.readState(deviceId), deviceId);
  return d.withRecoveryOperation({ deviceId, operationId: state.operationId }, async () => {
    const target = await d.loadTarget(deviceId);
    const targetDigest = runtimeRecoveryTargetBindingDigest(target);
    const bundle = await emptyStageBundle();
    const paths = runtimeDeviceRecoveryPaths(statePaths(env).runtimeDevices, deviceId, state.operationId);
    const dir = join(paths.operation, 'empty-stage-retention-v1');
    try { await mkdir(dir, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
    await privateNode(dir, true);
    return runLocked();
    async function runLocked() {
      const assertCurrent = async () => {
        if (JSON.stringify(await d.readState(deviceId)) !== JSON.stringify(state)
          || runtimeRecoveryTargetBindingDigest(await d.loadTarget(deviceId)) !== targetDigest) fail('RUNTIME_INVENTORY_CHANGED');
      };
      const invoke = async (remoteMode, proof = null, expiresAt = null) => {
        await assertCurrent();
        const invocation = retentionScriptInvocation(emptyStageScript(bundle, {
          mode: remoteMode, state, controllerPublicKeyJson: '', proof, expiresAt,
        }));
        const result = await withTrustedSshSession(trustedInput(target, runProcess), async session => {
          const address = await selectAddress(session);
          await save(dir, `${remoteMode}-invoked.json`, { at: new Date().toISOString() });
          return session.invokeSsh(address, invocation.argv, { stdinText: invocation.stdin, timeoutMs: 120_000, maxOutputBytes: 32768 });
        });
        await save(dir, `${remoteMode}-result.json`, result);
        await assertCurrent();
        if (result.exitCode !== 0 || result.signal !== null || result.stderr !== '') fail('RUNTIME_COMPLETION_UNCERTAIN');
        return JSON.parse(result.stdout);
      };
      if (mode === 'inspect') {
        const proof = validateEmptyStageProof(await invoke('observe'));
        const record = { state, targetDigest, executorDigest: bundle.digest, proof,
          expiresAt: new Date(Date.now() + 15 * 60_000).toISOString() };
        await save(dir, 'proposal.json', record);
        return { status: 'EMPTY_STAGE_REVIEW_READY', mutation: 'retain exact empty transaction directory', runtimeRecovered: false };
      }
      const p = await load(dir, 'proposal.json');
      exact(p, ['state', 'targetDigest', 'executorDigest', 'proof', 'expiresAt']);
      validateEmptyStageProof(p.proof);
      if (JSON.stringify(p.state) !== JSON.stringify(state) || p.targetDigest !== targetDigest || p.executorDigest !== bundle.digest) fail();
      if (mode === 'apply') {
        if (!Number.isFinite(Date.parse(p.expiresAt)) || Date.now() >= Date.parse(p.expiresAt)) fail('RUNTIME_INVENTORY_CHANGED');
        // Exclusive, fsynced attempt before any dispatch. Never automatically retry.
        await save(dir, 'consumed.json', { executorDigest: bundle.digest, at: new Date().toISOString() });
      } else { await load(dir, 'consumed.json'); }
      const result = await invoke(mode, p.proof, p.expiresAt);
      exact(result, ['status', 'runtimeRecovered', 'nextStep']);
      if (result.status !== 'RETAINED' || result.runtimeRecovered !== false || result.nextStep !== 'EMPTY_OPERATION_RECOVERY') fail();
      return result;
    }
  });
}
