import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';

import { main } from '../src/inspect-cli.mjs';
import { readRecoveryInspectCapture } from '../src/runtime/recovery-inspect-capture.mjs';

const result = {
  schemaVersion: 1, status: 'RECOVERY_READY', classification: 'EMPTY_PRE_TRANSACTION',
  rebootRequired: false, actionable: true, ticketId: 'PRIVATE_SENTINEL',
};
async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'inspect-cli-')));
  await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, run: join(root, 'run') };
}
function output() {
  const lines = [];
  return { lines, io: { stdout: { write(value) { lines.push(value); return true; } } } };
}

test('awaits the one exact CLI invocation, forwards env, and emits only after receipt publication', async (t) => {
  const { run } = await fixture(t);
  const env = { AGENT_ROAD_HOME: 'PRIVATE_SENTINEL' };
  let loads = 0, calls = 0, finished = false;
  const out = output();
  const code = await main(['inspect', 'dev_fixture', '--run-directory', run], env, out.io, async () => {
    loads++;
    assert.equal(JSON.parse(await readFile(join(run, 'started.json'), 'utf8')).phase, 'STARTED');
    return async (argv, forwardedEnv, io) => {
      calls++;
      assert.deepEqual(argv, ['runtime-recover', 'dev_fixture', '--inspect']);
      assert.equal(forwardedEnv, env);
      assert.deepEqual(Object.keys(io).sort(), ['stderr', 'stdout']);
      assert.notEqual(io.stdout, out.io.stdout);
      await new Promise((resolve) => setImmediate(resolve));
      io.stdout.write(JSON.stringify(result));
      finished = true;
      return 0;
    };
  });
  assert.equal(code, 0);
  assert.equal(finished, true);
  assert.equal(loads, 1);
  assert.equal(calls, 1);
  assert.equal(out.lines.length, 1);
  assert.doesNotMatch(out.lines[0], /dev_fixture|PRIVATE_SENTINEL/);
  assert.deepEqual(JSON.parse(out.lines[0]), await readRecoveryInspectCapture(run));
  const second = output();
  assert.equal(await main(['inspect', 'dev_fixture', '--run-directory', run], env, second.io,
    () => { loads++; throw new Error(); }), 3);
  assert.equal(loads, 1);
});

for (const mode of ['finite-stop', 'throw', 'loader-throw', 'malformed', 'overflow']) {
  test(`finite mapping and redaction: ${mode}`, async (t) => {
    const { run } = await fixture(t);
    const out = output();
    const code = await main(['inspect', 'dev_fixture', '--run-directory', run], {}, out.io, async () => {
      if (mode === 'loader-throw') throw new Error('PRIVATE_SENTINEL');
      return async (_argv, _env, io) => {
        if (mode === 'throw') throw new Error('PRIVATE_SENTINEL');
        if (mode === 'finite-stop') { io.stderr.write('RUNTIME_REBOOT_REQUIRED\n'); return 2; }
        io.stdout.write(mode === 'overflow' ? 'PRIVATE_SENTINEL'.repeat(10_000) : 'PRIVATE_SENTINEL');
        return 0;
      };
    });
    assert.equal(code, mode === 'finite-stop' ? 2 : 4);
    assert.equal(out.lines.length, 1);
    assert.doesNotMatch(out.lines[0], /PRIVATE_SENTINEL/);
    assert.deepEqual(JSON.parse(out.lines[0]), await readRecoveryInspectCapture(run));
    const readback = output();
    let readbackLoads = 0;
    assert.equal(await main(['readback', '--run-directory', run], {}, readback.io,
      () => { readbackLoads++; }), code);
    assert.equal(readbackLoads, 0);
    assert.deepEqual(readback.lines, out.lines);
  });
}

test('rejects invalid selectors and options before loading CLI or creating a run', async (t) => {
  const { root, run } = await fixture(t);
  for (const argv of [
    [], ['prepare', 'dev_fixture', '--run-directory', run],
    ['inspect', '--run-directory', run], ['inspect', 'latest', '--run-directory', run],
    ['inspect', 'dev_fixture', '--run-directory', 'relative'],
    ['inspect', 'dev_fixture', '--run-directory', run, '--run-directory', run],
    ['inspect', 'dev_fixture', '--run-directory', run, '--apply'],
    ['inspect', 'dev_fixture', '--run-directory', run, '--prior-ticket', 'PRIVATE_SENTINEL'],
    ['readback', 'dev_fixture', '--run-directory', run],
  ]) {
    const out = output();
    let loads = 0;
    assert.equal(await main(argv, {}, out.io, () => { loads++; }), 3);
    assert.equal(loads, 0);
    assert.equal(JSON.parse(out.lines[0]).outcome, 'BLOCKED');
    assert.doesNotMatch(out.lines[0], /dev_fixture|PRIVATE_SENTINEL/);
  }
  assert.deepEqual(await readdir(root), []);
});

test('readback never loads CLI and missing records return exit 4 without writes', async (t) => {
  const { root, run } = await fixture(t);
  const out = output();
  let loads = 0;
  assert.equal(await main(['readback', '--run-directory', run], {}, out.io, () => { loads++; }), 4);
  assert.equal(loads, 0);
  assert.deepEqual(await readdir(root), []);
});

test('lost display is recoverable through the executable readback route', async (t) => {
  const { run } = await fixture(t);
  assert.equal(await main(['inspect', 'dev_fixture', '--run-directory', run], {},
    { stdout: { write() { throw new Error('PRIVATE_SENTINEL'); } } },
    async () => async (_argv, _env, io) => { io.stdout.write(JSON.stringify(result)); return 0; }), 0);
  const cliPath = fileURLToPath(new URL('../src/inspect-cli.mjs', import.meta.url));
  const { stdout, stderr } = await promisify(execFile)(process.execPath,
    [cliPath, 'readback', '--run-directory', run], { env: { ...process.env, AGENT_ROAD_HOME: '/nonexistent' } });
  assert.equal(stderr, '');
  assert.deepEqual(JSON.parse(stdout), await readRecoveryInspectCapture(run));
  assert.doesNotMatch(stdout, /PRIVATE_SENTINEL/);
});

test('help does not create local state or load production CLI', async (t) => {
  const { root } = await fixture(t);
  const out = output();
  let loads = 0;
  assert.equal(await main(['--help'], {}, out.io, () => { loads++; }), 0);
  assert.equal(loads, 0);
  assert.match(out.lines[0], /readback/);
  assert.deepEqual(await readdir(root), []);
});

test('failed terminal publication emits one unknown result and never retries CLI', async (t) => {
  const { run } = await fixture(t);
  const out = output();
  let calls = 0;
  const code = await main(['inspect', 'dev_fixture', '--run-directory', run], {}, out.io,
    async () => async (_argv, _env, io) => {
      calls++;
      await writeFile(join(run, 'terminal.tmp'), 'partial', { mode: 0o600 });
      io.stdout.write(JSON.stringify(result));
      return 0;
    });
  assert.equal(code, 4);
  assert.equal(calls, 1);
  assert.equal(out.lines.length, 1);
  assert.equal(JSON.parse(out.lines[0]).outcome, 'STOP_UNKNOWN');
  assert.equal((await readRecoveryInspectCapture(run)).outcome, 'STOP_UNKNOWN');
});
