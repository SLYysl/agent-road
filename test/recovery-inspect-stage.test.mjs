import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

import { captureRecoveryInspect, readRecoveryInspectCapture } from '../src/runtime/recovery-inspect-capture.mjs';
import { createRecoveryInspectStageCapture, markRecoveryInspectStage } from '../src/runtime/recovery-inspect-stage.mjs';

async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'inspect-stage-')));
  await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test('simultaneous captures isolate last stage and ignore unknown labels', async () => {
  const a = createRecoveryInspectStageCapture();
  const b = createRecoveryInspectStageCapture();
  await Promise.all([
    a.run(async () => {
      markRecoveryInspectStage('STATE_READ');
      await new Promise((resolve) => setImmediate(resolve));
      markRecoveryInspectStage('PRIVATE_SENTINEL');
      markRecoveryInspectStage(['REMOTE_INSPECT']);
    }),
    b.run(async () => {
      markRecoveryInspectStage('REMOTE_INSPECT');
      await new Promise((resolve) => setImmediate(resolve));
    }),
  ]);
  assert.equal(a.snapshot(), 'STATE_READ');
  assert.equal(b.snapshot(), 'REMOTE_INSPECT');
});

test('late asynchronous callbacks cannot rewrite a completed capture', async () => {
  const capture = createRecoveryInspectStageCapture();
  let late;
  await capture.run(async () => {
    markRecoveryInspectStage('RECOVERY_LOCK');
    late = new Promise((resolve) => setImmediate(() => {
      markRecoveryInspectStage('REMOTE_INSPECT'); resolve();
    }));
  });
  await late;
  assert.equal(capture.snapshot(), 'RECOVERY_LOCK');
});

test('v2 receipt persists only internal stage and remains readable after lost display', async (t) => {
  const root = await fixture(t);
  const runDirectory = join(root, 'run');
  const result = await captureRecoveryInspect({ runDirectory, diagnostics: true,
    stdout: { write() { throw new Error('PRIVATE_SENTINEL'); } },
    invoke: async ({ stderr }) => {
      markRecoveryInspectStage('REMOTE_INSPECT');
      stderr.write('RUNTIME_STATE_UNSUPPORTED\n'); return 2;
    },
  });
  assert.equal(result.lastStage, 'REMOTE_INSPECT');
  assert.equal(result.code, 'RUNTIME_STATE_UNSUPPORTED');
  assert.deepEqual(await readRecoveryInspectCapture(runDirectory), result);
  const record = JSON.parse(await readFile(join(runDirectory, 'terminal.json'), 'utf8'));
  assert.equal(record.schemaVersion, 2);
  assert.doesNotMatch(JSON.stringify(record), /PRIVATE_SENTINEL/);
});

test('raw remote fields cannot supply a diagnostic stage', async (t) => {
  const root = await fixture(t);
  const result = await captureRecoveryInspect({ runDirectory: join(root, 'run'), diagnostics: true,
    stdout: { write() {} }, invoke: async ({ stdout }) => {
      stdout.write(JSON.stringify({ schemaVersion: 1, status: 'RECOVERY_READY',
        classification: 'EMPTY_PRE_TRANSACTION', rebootRequired: false, actionable: true,
        lastStage: 'REMOTE_INSPECT', secret: 'PRIVATE_SENTINEL' }));
      return 0;
    },
  });
  assert.equal(result.lastStage, 'NOT_REPORTED');
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_SENTINEL/);
});

for (const mode of ['unknown-stage', 'array-stage', 'missing-stage', 'schema-mismatch', 'extra-field']) {
  test(`v2 readback rejects ${mode}`, async (t) => {
    const root = await fixture(t);
    const runDirectory = join(root, 'run');
    await captureRecoveryInspect({ runDirectory, diagnostics: true, stdout: { write() {} },
      invoke: async () => { throw new Error(); },
    });
    const path = join(runDirectory, 'terminal.json');
    const record = JSON.parse(await readFile(path, 'utf8'));
    if (mode === 'unknown-stage') record.projection.lastStage = 'PRIVATE_SENTINEL';
    if (mode === 'array-stage') record.projection.lastStage = ['STATE_READ'];
    if (mode === 'missing-stage') delete record.projection.lastStage;
    if (mode === 'schema-mismatch') record.schemaVersion = 1;
    if (mode === 'extra-field') record.projection.detail = 'PRIVATE_SENTINEL';
    await writeFile(path, `${JSON.stringify(record)}\n`);
    assert.deepEqual(await readRecoveryInspectCapture(runDirectory), {
      phase: 'recovery-inspect', outcome: 'STOP_UNKNOWN', code: 'INSPECT_INVOKED_RESULT_UNCERTAIN',
    });
  });
}

test('v1 readback stays unchanged and rejects a backfilled stage', async (t) => {
  const root = await fixture(t);
  const runDirectory = join(root, 'run');
  const result = await captureRecoveryInspect({ runDirectory, stdout: { write() {} },
    invoke: async ({ stderr }) => { stderr.write('RUNTIME_STATE_UNSUPPORTED\n'); return 2; },
  });
  assert.equal(Object.hasOwn(result, 'lastStage'), false);
  assert.deepEqual(await readRecoveryInspectCapture(runDirectory), result);
  const path = join(runDirectory, 'terminal.json');
  const record = JSON.parse(await readFile(path, 'utf8'));
  record.projection.lastStage = 'STATE_READ';
  await writeFile(path, `${JSON.stringify(record)}\n`);
  assert.equal((await readRecoveryInspectCapture(runDirectory)).outcome, 'STOP_UNKNOWN');
});

test('v2 process exit before terminal publication does not invent a persisted stage', async (t) => {
  const root = await fixture(t);
  const run = join(root, 'run');
  const captureUrl = new URL('../src/runtime/recovery-inspect-capture.mjs', import.meta.url).href;
  const stageUrl = new URL('../src/runtime/recovery-inspect-stage.mjs', import.meta.url).href;
  const program = `import {captureRecoveryInspect} from ${JSON.stringify(captureUrl)};
    import {markRecoveryInspectStage} from ${JSON.stringify(stageUrl)};
    await captureRecoveryInspect({runDirectory:process.argv[1],diagnostics:true,invoke(){
      markRecoveryInspectStage('REMOTE_INSPECT');process.exit(23);
    }});`;
  await assert.rejects(promisify(execFile)(process.execPath,
    ['--input-type=module', '-e', program, run]), (error) => error.code === 23);
  assert.equal(JSON.parse(await readFile(join(run, 'started.json'), 'utf8')).schemaVersion, 2);
  assert.deepEqual(await readRecoveryInspectCapture(run), {
    phase: 'recovery-inspect', outcome: 'STOP_UNKNOWN', code: 'INSPECT_INVOKED_RESULT_UNCERTAIN',
  });
});
