// Bounded, explicit diagnostics; never retries a failed observation.
import { randomUUID } from 'node:crypto';
import { mkdtemp, open } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { statePaths } from '../src/core/paths.mjs';
import { runProcess } from '../src/process/run-process.mjs';
import { executeRemoteScript } from '../src/remote/remote-exec.mjs';
import { createProductionRuntimeDependencies } from '../src/runtime/production-runtime-dependencies.mjs';
import { readRuntimeInventory } from '../src/runtime/runtime-doctor.mjs';

const [deviceId, countText = '1', ...extra] = process.argv.slice(2);
if (!/^dev_[a-z0-9]{1,60}$/.test(deviceId ?? '') || !/^[1-6]$/.test(countText) || extra.length) {
  process.stderr.write('Usage: node tools/diagnose-runtime-doctor.mjs <device-id> [1-6]\n');
  process.exitCode = 2;
} else {
  // mkdtemp creates a private, unique directory. Raw receipts never go to stdout.
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-doctor-'));
  process.stdout.write(JSON.stringify({ capture: basename(directory) }) + '\n');
  const save = async (name, value) => {
    const file = await open(join(directory, name), 'wx', 0o600);
    try { await file.writeFile(JSON.stringify(value) + '\n'); await file.sync(); }
    finally { await file.close(); }
  };
  const safeCode = error => {
    const code = Object.getOwnPropertyDescriptor(error ?? {}, 'code')?.value;
    return typeof code === 'string' && /^(?:RUNTIME|REMOTE|FILE|LOCAL|PROCESS|DEVICE|SSH_IDENTITY)_[A-Z_]+$/.test(code)
      ? code : 'DIAGNOSTIC_UNCLASSIFIED';
  };
  await save('context.json', { deviceId, controllerRoot: statePaths().root, count: Number(countText) });
  let step = 0;
  let boundary = 'target';
  const runner = async (command, args, options) => {
    const index = ++step;
    await save(`${index}-started.json`, { startedAt: new Date().toISOString(), command: basename(command), timeoutMs: options.timeoutMs });
    const chunks = { stdout: [], stderr: [] };
    try {
      const result = await runProcess(command, args, {
        ...options,
        onOutput: (stream, bytes) => {
          chunks[stream].push(bytes);
          options.onOutput?.(stream, bytes);
        },
      });
      await save(`${index}-result.json`, { finishedAt: new Date().toISOString(), exitCode: result.exitCode, signal: result.signal, stdout: result.stdout, stderr: result.stderr });
      return result;
    } catch (error) {
      await save(`${index}-failed.json`, { finishedAt: new Date().toISOString(), code: safeCode(error), stdout: Buffer.concat(chunks.stdout).toString('utf8'), stderr: Buffer.concat(chunks.stderr).toString('utf8') });
      throw error;
    }
  };
  try {
    const dependencies = createProductionRuntimeDependencies();
    const target = await dependencies.loadTarget(deviceId);
    boundary = 'state-read';
    const before = await dependencies.readState(deviceId);
    await save('state-before.json', before);
    for (let attempt = 1; attempt <= Number(countText); attempt++) {
      boundary = 'inventory-transport';
      const inventory = await readRuntimeInventory({
        target,
        dependencies: {
          executeRemoteScript: async options => {
            const result = await executeRemoteScript(options);
            await save(`attempt-${attempt}-execution.json`, result);
            boundary = result.exitCode !== 0 ? 'inventory-script-exit'
              : result.stderr !== '' ? 'inventory-script-stderr' : 'inventory-parse';
            return result;
          },
          runProcess: runner,
          operationId: () => randomUUID().replaceAll('-', ''),
          clock: () => new Date(),
        },
      });
      await save(`attempt-${attempt}-inventory.json`, inventory);
      process.stdout.write(JSON.stringify({ attempt, status: 'INVENTORY_VALID', generationVerified: inventory.runtime.generationVerified }) + '\n');
    }
    boundary = 'state-readback';
    const after = await dependencies.readState(deviceId);
    await save('state-after.json', after);
    const stateUnchanged = JSON.stringify(before) === JSON.stringify(after);
    process.stdout.write(JSON.stringify({ stateUnchanged }) + '\n');
    if (!stateUnchanged) throw Object.assign(new Error(), { code: 'RUNTIME_OPERATION_CONFLICT' });
  } catch (error) {
    const code = safeCode(error);
    await save('stopped.json', { code, step, boundary });
    process.stderr.write(JSON.stringify({ code, boundary }) + '\n');
    process.exitCode = 2;
  }
}
