import { AsyncLocalStorage } from 'node:async_hooks';

const context = new AsyncLocalStorage();
export const WINDOWS_INSPECT_STAGES = Object.freeze([
  'WINDOWS_INPUT', 'WINDOWS_NATIVE', 'WINDOWS_VALIDATION', 'WINDOWS_ADMIN',
  'WINDOWS_STATE', 'WINDOWS_DIRECTORY_OPEN', 'WINDOWS_IDENTITY', 'WINDOWS_ACL',
  'WINDOWS_CHILDREN', 'WINDOWS_BOOT', 'WINDOWS_STABILITY', 'WINDOWS_OUTPUT',
]);

export function isWindowsInspectStage(value) {
  return typeof value === 'string' && WINDOWS_INSPECT_STAGES.includes(value);
}

const STAGES = new Set([
  ...WINDOWS_INSPECT_STAGES,
  'NOT_REPORTED', 'INPUT_VALIDATION', 'DEPENDENCIES', 'STATE_READ',
  'TARGET_LOAD', 'RECOVERY_LOCK', 'RECOVERY_SCOPE', 'STATE_RECHECK',
  'BOOT_OBSERVATION_READ', 'COMMIT_READ', 'RECOVERY_RECORDS',
  'REMOTE_INSPECT', 'REMOTE_RESULT_VALIDATION', 'BOOT_OBSERVATION_PUBLISH',
  'TICKET_PUBLISH',
]);

export function isRecoveryInspectStage(value) {
  return typeof value === 'string' && STAGES.has(value);
}

// Only fixed labels are accepted; no diagnostic callbacks run in controller code.
export function markRecoveryInspectStage(stage) {
  const current = context.getStore();
  if (current?.active && isRecoveryInspectStage(stage)) current.stage = stage;
}

export function createRecoveryInspectStageCapture() {
  const current = { stage: 'NOT_REPORTED', active: true };
  return Object.freeze({
    async run(operation) {
      try { return await context.run(current, operation); }
      finally { current.active = false; }
    },
    snapshot() { return current.stage; },
  });
}
