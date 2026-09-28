// Explicit lightweight remote benchmark; does not retry failed or uncertain work.
import { randomUUID } from 'node:crypto';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { performance } from 'node:perf_hooks';

import { runProcess } from '../process/run-process.mjs';
import { executeRemoteScript } from '../remote/remote-exec.mjs';
import { createProductionRuntimeDependencies } from '../runtime/production-runtime-dependencies.mjs';

export async function run(argv, env = process.env, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  let exitCode = 0;
  const [deviceId, countText = '10', ...extra] = argv;
  const marker = 'AGENT_ROAD_LATENCY_OK';
  const publicCode = (error) => /^[A-Z][A-Z_]+$/.test(error?.code ?? '') ? error.code : 'LATENCY_CHECK_FAILED';
  try {
    if (!/^dev_[a-z0-9]{1,60}$/.test(deviceId ?? '') || !/^(?:[1-9]|1[0-9]|20)$/.test(countText) || extra.length) {
      throw Object.assign(new Error(), { code: 'LATENCY_INPUT_INVALID' });
    }
    const directory = await mkdtemp(join(tmpdir(), 'agent-road-latency-'));
    const scriptPath = join(directory, 'noop.ps1');
    await writeFile(scriptPath, `[Console]::Write('${marker}')\n`, { mode: 0o600 });
    const records = [];
    for (let n = 0; n < Number(countText); n += 1) {
      const start = performance.now();
      const steps = [];
      let targetMs = null;
      let failure;
      try {
        const target = await createProductionRuntimeDependencies(env).loadTarget(deviceId);
        targetMs = performance.now() - start;
        const measured = async (command, args, options) => {
          const stepStart = performance.now();
          try {
            const result = await runProcess(command, args, options);
            steps.push({ command: basename(command), ms: performance.now() - stepStart, exitCode: result.exitCode });
            return result;
          } catch (error) {
            steps.push({ command: basename(command), ms: performance.now() - stepStart, error: publicCode(error) });
            throw error;
          }
        };
        const result = await executeRemoteScript({
          target, scriptPath, timeoutMs: 10_000,
          dependencies: { runProcess: measured, operationId: () => randomUUID().replaceAll('-', ''), clock: () => new Date() },
        });
        if (result.exitCode !== 0 || result.stdout !== marker || result.stderr !== '') throw new Error();
      } catch (error) {
        failure = publicCode(error);
      }
      const record = { n, totalMs: performance.now() - start, targetMs, steps, passed: failure === undefined };
      if (failure) record.error = failure;
      records.push(record);
      await writeFile(join(directory, 'results.json'), JSON.stringify(records, null, 2), { mode: 0o600 });
      stdout.write(`${JSON.stringify(record)}\n`);
      if (failure) { exitCode = 2; break; }
    }
    const passed = records.filter((record) => record.passed).map((record) => record.totalMs).sort((a, b) => a - b);
    const percentile = (p) => passed.length ? passed[Math.ceil(passed.length * p) - 1] : null;
    stdout.write(`${JSON.stringify({ capture: basename(directory), completed: records.length, failures: records.length - passed.length, p50Ms: percentile(0.5), p95Ms: percentile(0.95) })}\n`);
  } catch (error) {
    stderr.write(`${publicCode(error)}\n`);
    exitCode = 2;
  }
  return exitCode;
}
