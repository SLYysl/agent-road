// A bounded, explicit batch of scripts sharing one pinned SSH connection.
import { randomUUID } from 'node:crypto';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, isAbsolute, join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { runProcess } from '../process/run-process.mjs';
import { executePreparedRemoteScriptInSession, withPreparedRemoteScript } from '../remote/remote-exec.mjs';
import { trustedInput } from '../remote/remote-target.mjs';
import { selectAddress } from '../remote/windows-remote.mjs';
import { createProductionRuntimeDependencies } from '../runtime/production-runtime-dependencies.mjs';
import { withTrustedSshSession } from '../ssh/trusted-ssh-session.mjs';

export async function run(argv, env = process.env, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  let exitCode = 0;
  const [deviceId, ...paths] = argv;
  let directory;
  const results = [];
  const codeFor = (error) => /^[A-Z][A-Z_]+$/.test(error?.code ?? '') ? error.code : 'SESSION_FAILED';
  try {
    if (!/^dev_[a-z0-9]{1,60}$/.test(deviceId ?? '') || paths.length < 1 || paths.length > 20
      || paths.some((path) => !isAbsolute(path))) throw Object.assign(new Error(), { code: 'SESSION_INPUT_INVALID' });
    directory = await mkdtemp(join(tmpdir(), 'agent-road-session-'));
    const requests = paths.map((scriptPath) => ({ scriptPath, operationId: randomUUID().replaceAll('-', '') }));
    await writeFile(join(directory, 'request.json'), JSON.stringify({ deviceId, requests }), { mode: 0o600 });
    stdout.write(`${JSON.stringify({ capture: basename(directory), scripts: paths.length })}\n`);
    const target = await createProductionRuntimeDependencies(env).loadTarget(deviceId);
    const prepared = [];
    const started = performance.now();
    // Snapshot every source before any remote mutation. Retain snapshots until the
    // whole session closes; each prepared capability can execute at most once.
    const prepare = async (index) => {
      if (index < requests.length) {
        const request = requests[index];
        return withPreparedRemoteScript({
          target, scriptPath: request.scriptPath, timeoutMs: 300_000,
          dependencies: { runProcess, operationId: () => request.operationId, clock: () => new Date() },
        }, async (value) => { prepared.push(value); return prepare(index + 1); });
      }
      return withTrustedSshSession(trustedInput(target, runProcess), async (session) => {
        const address = await selectAddress(session);
        for (let i = 0; i < prepared.length; i += 1) {
          const start = performance.now();
          const result = await executePreparedRemoteScriptInSession(prepared[i], session, address);
          results.push(result);
          await writeFile(join(directory, 'results.json'), JSON.stringify(results), { mode: 0o600 });
          stdout.write(`${JSON.stringify({ index: i, exitCode: result.exitCode, elapsedMs: performance.now() - start })}\n`);
          if (result.exitCode !== 0) {
            throw Object.assign(new Error(), { code: 'SESSION_SCRIPT_FAILED' });
          }
        }
      }, { reuseConnection: true });
    };
    await prepare(0);
    stdout.write(`${JSON.stringify({ completed: results.length, elapsedMs: performance.now() - started, closed: true })}\n`);
  } catch (error) {
    const code = codeFor(error);
    if (directory) await writeFile(join(directory, 'stopped.json'), JSON.stringify({ code, completed: results.length }), { mode: 0o600 });
    stderr.write(`${code}\n`);
    exitCode = 2;
  }
  return exitCode;
}
