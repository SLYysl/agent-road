import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { deriveRuntimeControllerKeyIdentity } from './runtime-manifest.mjs';
import { validateRuntimeStateRecord } from './runtime-state-store.mjs';
import { validateStagedRetentionProposal, validateStagedRetentionAttempt } from './staged-retention-protocol.mjs';

function fail() { const error = new Error('RUNTIME_STATE_UNSUPPORTED'); error.code = error.message; throw error; }
function sliceOnce(source, start, end) {
  const offset = source.indexOf(start);
  const limit = source.indexOf(end, offset + start.length);
  if (offset < 0 || limit < 0 || source.indexOf(start, offset + 1) >= 0) fail();
  return source.slice(offset, limit);
}

// Exact executor bytes are captured once; a controller must carry this bundle
// through observation, durable consumption, dispatch and reconciliation.
export async function loadStagedRetentionWindowsBundle() {
  const [inventory, provision, native, driver] = await Promise.all([
    'runtime-inventory.ps1', 'runtime-provision-core.ps1', 'staged-retention-native.cs', 'staged-retention.ps1',
  ].map(name => readFile(new URL(`../../windows/${name}`, import.meta.url), 'utf8')));
  const marker = "\ntry {\n $runtimeRoot = 'C:\\ProgramData\\AgentRoad\\runtime'";
  const offset = inventory.indexOf(marker);
  if (offset < 0 || inventory.indexOf(marker, offset + 1) >= 0) fail();
  const environment = sliceOnce(inventory, marker, ' if ($PlanningObservation.IsPresent) {').slice('\ntry {\n'.length);
  const mutex = sliceOnce(provision, 'function Enter-AgentRoadMutationLock {', 'function Assert-AgentRoadDirectoryNode {');
  const source = `${inventory.slice(0, offset)}\n${mutex}\nAdd-Type -TypeDefinition @'\n${native}'@\n`
    + `function Read-RetentionInventory {\n${environment}\n return $result\n}\n${driver}`;
  if (Buffer.byteLength(source) > 120_000 || /[^\x00-\x7f]/u.test(source)) fail();
  return Object.freeze({ source, executorDigest: createHash('sha256').update(source).digest('hex').toUpperCase() });
}

export function buildStagedRetentionScript(bundle, input) {
  if (bundle.executorDigest !== createHash('sha256').update(bundle.source).digest('hex').toUpperCase()) fail();
  const { mode, failedState, controllerPublicKey, proposal = null, attempt = null } = input;
  const state = validateRuntimeStateRecord(failedState);
  if (state.runtimeStatus !== 'FAILED' || state.failureCode !== 'RUNTIME_COMPLETION_UNCERTAIN'
    || !/^[a-f0-9]{32}$/u.test(state.operationId ?? '') || !/^[A-F0-9]{64}$/u.test(state.manifestDigest ?? '')
    || !['observe', 'apply', 'reconcile'].includes(mode)) fail();
  const identity = deriveRuntimeControllerKeyIdentity(controllerPublicKey);
  let validatedProposal = null;
  let validatedAttempt = null;
  if (mode !== 'observe') {
    validatedProposal = validateStagedRetentionProposal(proposal);
    validatedAttempt = validateStagedRetentionAttempt(attempt, validatedProposal);
    const evidence = validatedProposal.evidence;
    if (evidence.executorDigest !== bundle.executorDigest
      || JSON.stringify(validateRuntimeStateRecord(evidence.assessmentInput.failedState)) !== JSON.stringify(state)
      || deriveRuntimeControllerKeyIdentity(evidence.assessmentInput.controllerPublicKey).controllerKeyId !== identity.controllerKeyId) fail();
  } else if (proposal !== null || attempt !== null) fail();
  const payload = { mode, state, controllerPublicKeyJson: identity.controllerPublicKeyJson,
    proposal: validatedProposal, attempt: validatedAttempt };
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64');
  return bundle.source + `\n$payload=$script:Utf8.GetString([Convert]::FromBase64String('${encoded}'))|ConvertFrom-Json\n`
    + "try {$result=Invoke-StagedRetention $payload 'C:\\ProgramData\\AgentRoad';[Console]::OutputEncoding=$script:Utf8;[Console]::Out.Write(($result|ConvertTo-Json -Compress -Depth 16))}"
    + "catch {$code=[string]$_.Exception.Message;if($code -cnotin @('RUNTIME_INPUT_INVALID','RUNTIME_STATE_UNSUPPORTED','RUNTIME_REBOOT_REQUIRED','RUNTIME_INVENTORY_CHANGED','RUNTIME_ALREADY_RUNNING','RUNTIME_COMPLETION_UNCERTAIN')){$code='RUNTIME_STATE_UNSUPPORTED'};[Console]::Out.Write((@{error=$code}|ConvertTo-Json -Compress));exit 73}";
}
