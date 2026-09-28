import { readFile } from 'node:fs/promises';
import { deriveRuntimeControllerKeyIdentity } from './runtime-manifest.mjs';
import { validateRuntimeStateRecord } from './runtime-state-store.mjs';

function unsupported() {
  const error = new Error('RUNTIME_STATE_UNSUPPORTED');
  error.code = 'RUNTIME_STATE_UNSUPPORTED';
  throw error;
}

// A source builder only: callers retain pinned SSH, deadlines and private output
// handling. The resulting script has no mutation or recovery-authority surface.
export async function buildStagedRetirementObservationScript(failedState, controllerPublicKey) {
  const state = validateRuntimeStateRecord(failedState);
  if (state.runtimeStatus !== 'FAILED' || state.failureCode !== 'RUNTIME_COMPLETION_UNCERTAIN'
    || JSON.stringify(state.requestedProfiles) !== '["core"]'
    || !/^[A-F0-9]{64}$/u.test(state.manifestDigest ?? '')
    || !/^[A-F0-9]{64}$/u.test(state.generationDigest ?? '')
    || !/^[a-f0-9]{32}$/u.test(state.operationId ?? '')) {
    unsupported();
  }
  const identity = deriveRuntimeControllerKeyIdentity(controllerPublicKey);
  const source = await readFile(new URL('../../windows/runtime-inventory.ps1', import.meta.url), 'utf8');
  const tail = await readFile(new URL('../../windows/staged-retirement-observation.ps1', import.meta.url), 'utf8');
  const marker = "\ntry {\n $runtimeRoot = 'C:\\ProgramData\\AgentRoad\\runtime'";
  const offset = source.indexOf(marker);
  if (offset < 0 || source.indexOf(marker, offset + 1) >= 0) unsupported();
  const keyBase64 = Buffer.from(identity.controllerPublicKeyJson).toString('base64');
  return `${source.slice(0, offset)}\n$retirementOperationId='${state.operationId}'\n`
    + `$retirementControllerKeyJson=$script:Utf8.GetString([Convert]::FromBase64String('${keyBase64}'))\n${tail}`;
}
