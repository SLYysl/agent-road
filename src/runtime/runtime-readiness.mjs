import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { createProductionRuntimeDependencies } from './production-runtime-dependencies.mjs';
import { executeRemoteScript } from '../remote/remote-exec.mjs';
import { runProcess } from '../process/run-process.mjs';

export function classifyReadiness(first, second) {
  const samples = [first, second];
  if (samples.some(s => s.inventory.runtime.pendingOperationId !== null)) return 'RECOVERY_REQUIRED';
  if (samples.some(s => s.inventory.pendingReboot)) return 'REBOOT_REQUIRED';
  if (samples.some(s => s.servicingActive)) return 'SERVICING_ACTIVE';
  const stable = sample => JSON.stringify({ ...sample.inventory, freeBytes: 0 });
  return stable(first) === stable(second) ? 'READY_FOR_PLAN' : 'INVENTORY_CHANGED';
}
export async function observeReadiness(deviceId, intervalSeconds = 60, env = process.env, injected) {
  if (!/^dev_[a-z0-9]+$/u.test(deviceId) || !Number.isInteger(intervalSeconds) || intervalSeconds < 30 || intervalSeconds > 120) {
    throw new Error('RUNTIME_INPUT_INVALID');
  }
  const production = createProductionRuntimeDependencies(env);
  const d = injected ?? {
    loadTarget: production.loadTarget,
    readInventory: production.readInventory,
    wait: delay,
    async servicing(target) {
      const result = await executeRemoteScript({ target,
        scriptPath: fileURLToPath(new URL('../../windows/runtime-servicing.ps1', import.meta.url)), timeoutMs: 60_000,
        dependencies: { runProcess, operationId: () => randomUUID().replaceAll('-', ''), clock: () => new Date() } });
      if (result.exitCode !== 0 || result.stderr !== '') throw new Error('RUNTIME_INVENTORY_FAILED');
      const value = JSON.parse(result.stdout);
      if (Object.keys(value).length !== 1 || typeof value.servicingActive !== 'boolean') throw new Error('RUNTIME_INVENTORY_INVALID');
      return value.servicingActive;
    },
  };
  const target = await d.loadTarget(deviceId);
  const sample = async () => ({ inventory: await d.readInventory(target), servicingActive: await d.servicing(target) });
  const first = await sample();
  const initial = classifyReadiness(first, first);
  if (initial !== 'READY_FOR_PLAN') return { schemaVersion: 1, status: initial, samples: 1, intervalSeconds,
    observationOnly: true, planRevalidationRequired: true };
  await d.wait(intervalSeconds * 1000);
  const second = await sample();
  return { schemaVersion: 1, status: classifyReadiness(first, second), samples: 2, intervalSeconds,
    observationOnly: true, planRevalidationRequired: true };
}
