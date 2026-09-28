// Explicit observation; no install, runtime transition, selection persistence or retry.
import {randomUUID} from 'node:crypto';
import {mkdtemp, open} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {basename, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runProcess} from '../process/run-process.mjs';
import {executeRemoteScript} from '../remote/remote-exec.mjs';
import {createProductionRuntimeDependencies} from '../runtime/production-runtime-dependencies.mjs';
import {parseExistingBase, assessExistingBase} from '../runtime/existing-base.mjs';

export async function run(argv, env = process.env, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  let exitCode = 0;
  const [deviceId, ...extra] = argv;
  if (!/^dev_[a-z0-9]{1,60}$/.test(deviceId ?? '') || extra.length) {
    stderr.write('Usage: node tools/inspect-existing-base.mjs <device-id>\n');
    exitCode = 2;
  } else {
    const directory = await mkdtemp(join(tmpdir(), 'agent-road-existing-base-'));
    const save = async (name, value) => {
      const file = await open(join(directory, name), 'wx', 0o600);
      try { await file.writeFile(JSON.stringify(value) + '\n'); await file.sync(); }
      finally { await file.close(); }
    };
    const safeCode = error => /^(?:EXISTING_BASE|RUNTIME|REMOTE|FILE|LOCAL|PROCESS|DEVICE|SSH_IDENTITY)_[A-Z_]+$/.test(error?.code ?? '')
      ? error.code : 'EXISTING_BASE_INSPECTION_FAILED';
    let step = 0;
    const runner = async (command, args, options) => {
      const index = ++step;
      await save(`${index}-started.json`, {command: basename(command), timeoutMs: options.timeoutMs});
      try {
        const result = await runProcess(command, args, options);
        await save(`${index}-result.json`, {exitCode: result.exitCode, signal: result.signal, stdout: result.stdout, stderr: result.stderr});
        return result;
      } catch (error) { await save(`${index}-failed.json`, {code: safeCode(error)}); throw error; }
    };
    stdout.write(JSON.stringify({capture: basename(directory)}) + '\n');
    try {
      const dependencies = createProductionRuntimeDependencies(env);
      const target = await dependencies.loadTarget(deviceId);
      const before = await dependencies.readState(deviceId);
      await save('context.json', {deviceId, stateBefore: before});
      const result = await executeRemoteScript({
        target,
        scriptPath: fileURLToPath(new URL('../../windows/existing-base.ps1', import.meta.url)),
        timeoutMs: 240000,
        dependencies: {runProcess: runner, operationId: () => randomUUID().replaceAll('-', ''), clock: () => new Date()},
      });
      await save('execution.json', result);
      if (result.exitCode !== 0 || result.stderr !== '') throw new Error('EXISTING_BASE_INSPECTION_FAILED');
      const assessment = assessExistingBase(parseExistingBase(result.stdout));
      await save('assessment.json', assessment);
      const after = await dependencies.readState(deviceId);
      const stateUnchanged = JSON.stringify(before) === JSON.stringify(after);
      await save('state-after.json', after);
      if (!stateUnchanged) throw Object.assign(new Error(), {code: 'RUNTIME_OPERATION_CONFLICT'});
      stdout.write(JSON.stringify({
        stateUnchanged, managedBaseReady: false,
        tools: assessment.tools.map(({tool, action, candidates}) => ({
          tool, action, candidates: candidates.map(({source, status, version, environmentModules, reason}) => ({source, status, version, environmentModules, reason})),
        })),
      }) + '\n');
    } catch (error) {
      const code = safeCode(error);
      await save('stopped.json', {code, step});
      stderr.write(code + '\n');
      exitCode = 2;
    }
  }
  return exitCode;
}
