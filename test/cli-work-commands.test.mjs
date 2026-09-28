import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { main } from '../src/cli.mjs';
import { isWorkCommand, runWorkCommand } from '../src/work/commands.mjs';

function capture() {
  let out = '', err = '';
  return {
    stdout: { write: (value) => { out += value; } },
    stderr: { write: (value) => { err += value; } },
    out: () => out, err: () => err,
  };
}

test('capability discovery is local, JSON, and distinguishes experiments from interfaces', async () => {
  const io = capture();
  const hostileEnv = new Proxy({}, { get() { assert.fail('discovery read environment'); } });
  assert.equal(await main(['capabilities'], hostileEnv, io), 0);
  const result = JSON.parse(io.out());
  assert.equal(result.deviceProbed, false);
  assert.equal(result.automaticReplay, false);
  assert.equal(result.commands.find((x) => x.name === 'session').sharedShell, false);
  assert(result.experimentalEvidenceOnly.includes('desktop-user-agent-handoff'));
  assert.equal(io.err(), '');
  assert.equal(await main(['capabilities', 'unexpected'], hostileEnv, io), 2);
  assert.match(io.err(), /WORK_INPUT_INVALID/);
});

const routes = [
  ['session', 'run-session', ['invalid-device']],
  ['job', 'background-task', ['start', 'invalid-device']],
  ['base-inspect', 'inspect-existing-base', ['invalid-device']],
  ['base-exec', 'run-existing-task', ['invalid-device']],
  ['measure-exec', 'measure-remote-exec', ['invalid-device']],
];
for (const [command, tool, args] of routes) {
  test(`${command}: canonical and legacy entry points retain rejection/exit semantics`, async () => {
    const io = capture();
    const argv = Object.freeze([command, ...args]);
    const previousExit = process.exitCode;
    assert.equal(await main(argv, {}, io), 2);
    assert.equal(process.exitCode, previousExit, 'library call must not mutate global exit status');
    assert.equal(io.out(), '');
    const old = spawnSync(process.execPath, [fileURLToPath(new URL(`../tools/${tool}.mjs`, import.meta.url)), ...args], { encoding: 'utf8', timeout: 10000 });
    assert.equal(old.status, 2);
    assert.equal(old.stdout, io.out());
    assert.equal(old.stderr, io.err());
    const help = capture();
    assert.equal(await main([command, '--help'], {}, help), 0);
    assert.match(help.out(), new RegExp(`agent-road ${command}`));
    assert.equal(help.err(), '');
  });
}

test('command names cannot become arbitrary module paths or inherited properties', async () => {
  for (const command of ['../cli', '__proto__', 'constructor', 'toString']) {
    assert.equal(isWorkCommand(command), false);
    await assert.rejects(runWorkCommand(command, [], {}, capture()), /WORK_COMMAND_INVALID/);
  }
});

test('job rejects extra arguments before accepting a job identity or dispatching', async () => {
  const io = capture();
  assert.equal(await main(['job', 'status', 'dev_abc123', 'job_' + 'a'.repeat(32), 'extra'], {}, io), 2);
  assert.equal(io.out(), '');
  assert.equal(io.err(), 'JOB_INPUT_INVALID\n');
});

test('session uses caller environment and retains a finite failure capture without dispatch', async (t) => {
  const home = await mkdtemp(join(tmpdir(), 'agent-road-interface-test-'));
  t.after(() => rm(home, { recursive: true, force: true }));
  const io = capture();
  let readHome = false;
  const env = { get AGENT_ROAD_HOME() { readHome = true; return home; } };
  assert.equal(await main(['session', 'dev_abc123', join(home, 'unused.ps1')], env, io), 2);
  assert.equal(readHome, true);
  const { capture: name } = JSON.parse(io.out());
  assert.match(name, /^agent-road-session-[a-zA-Z0-9]+$/);
  const directory = join(tmpdir(), name);
  t.after(() => rm(directory, { recursive: true, force: true }));
  const stopped = JSON.parse(await readFile(join(directory, 'stopped.json'), 'utf8'));
  assert.equal(stopped.completed, 0);
  assert.equal(io.err(), `${stopped.code}\n`);
  const request = JSON.parse(await readFile(join(directory, 'request.json'), 'utf8'));
  assert.equal(request.requests.length, 1);
  assert.match(request.requests[0].operationId, /^[a-f0-9]{32}$/);
});

test('logs output option reaches target lookup using isolated local state', async (t) => {
  const home = await mkdtemp(join(tmpdir(), 'agent-road-log-option-'));
  t.after(() => rm(home, { recursive: true, force: true }));
  const io = capture();
  const jobId = 'job_' + 'a'.repeat(32);
  assert.equal(await main(['job', 'logs', 'dev_abc123', jobId, '--include-output'], { AGENT_ROAD_HOME: home }, io), 2);
  const first = JSON.parse(io.out());
  assert.equal(first.jobId, jobId);
  const directory = join(tmpdir(), first.capture);
  t.after(() => rm(directory, { recursive: true, force: true }));
  const request = JSON.parse(await readFile(join(directory, 'request.json'), 'utf8'));
  assert.equal(request.action, 'logs');
  assert.equal(request.jobId, jobId);
  assert.equal(io.err(), 'DEVICE_NOT_FOUND\n');
});
