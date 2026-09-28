import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, mkdtemp, readFile, readdir, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';

import { captureRecoveryInspect, readRecoveryInspectCapture } from '../src/runtime/recovery-inspect-capture.mjs';

const success = {
  schemaVersion: 1, status: 'RECOVERY_READY', classification: 'EMPTY_PRE_TRANSACTION',
  rebootRequired: false, actionable: true, ticketId: 'PRIVATE_SENTINEL',
};
const expected = {
  phase: 'recovery-inspect', outcome: 'FINITE_RESULT', status: 'RECOVERY_READY',
  classification: 'EMPTY_PRE_TRANSACTION', rebootRequired: false, actionable: true,
};
async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'inspect-capture-')));
  await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, runDirectory: join(root, 'run') };
}
const invokeSuccess = async ({ stdout }) => { stdout.write(JSON.stringify(success)); return 0; };

test('publishes redacted receipt before stdout; readback does not invoke or write', async (t) => {
  const { runDirectory } = await fixture(t);
  let receiptAtOutput;
  let output;
  const result = await captureRecoveryInspect({ runDirectory, invoke: async (io) => {
    const marker = JSON.parse(await readFile(join(runDirectory, 'started.json'), 'utf8'));
    assert.equal(marker.phase, 'STARTED');
    assert.equal((await stat(runDirectory)).mode & 0o777, 0o700);
    assert.equal((await stat(join(runDirectory, 'started.json'))).mode & 0o777, 0o600);
    return invokeSuccess(io);
  }, stdout: { write(value) {
    output = value;
    receiptAtOutput = readRecoveryInspectCapture(runDirectory);
  } } });
  assert.deepEqual(result, expected);
  assert.deepEqual(await receiptAtOutput, expected);
  assert.equal(output, `${JSON.stringify(expected)}\n`);
  const before = await readFile(join(runDirectory, 'terminal.json'), 'utf8');
  assert.doesNotMatch(before, /PRIVATE_SENTINEL/);
  assert.equal((await stat(join(runDirectory, 'terminal.json'))).mode & 0o777, 0o600);
  assert.deepEqual(await readRecoveryInspectCapture(runDirectory), expected);
  assert.equal(await readFile(join(runDirectory, 'terminal.json'), 'utf8'), before);
});

test('lost stdout preserves a readable terminal receipt', async (t) => {
  const { runDirectory } = await fixture(t);
  assert.deepEqual(await captureRecoveryInspect({ runDirectory, invoke: invokeSuccess,
    stdout: { write() { throw new Error('PRIVATE_SENTINEL'); } },
  }), expected);
  assert.deepEqual(await readRecoveryInspectCapture(runDirectory), expected);
});

test('simultaneous and later duplicate calls invoke exactly once', async (t) => {
  const { runDirectory } = await fixture(t);
  let calls = 0;
  const options = { runDirectory, stdout: { write() {} }, invoke: async (io) => {
    calls += 1;
    return invokeSuccess(io);
  } };
  const results = await Promise.all([captureRecoveryInspect(options), captureRecoveryInspect(options)]);
  assert.equal(results.filter((r) => r.outcome === 'FINITE_RESULT').length, 1);
  assert.equal(results.filter((r) => r.outcome === 'BLOCKED').length, 1);
  assert.equal((await captureRecoveryInspect(options)).outcome, 'BLOCKED');
  assert.equal(calls, 1);
});

for (const mode of ['throw', 'overflow-caught', 'non-string', 'invalid-json', 'invalid-exit', 'stderr', 'bad-semantics']) {
  test(`persists only uncertainty for ${mode}`, async (t) => {
    const { runDirectory } = await fixture(t);
    const result = await captureRecoveryInspect({ runDirectory, stdout: { write() {} }, invoke: async (io) => {
      if (mode === 'throw') throw new Error('PRIVATE_SENTINEL');
      if (mode === 'overflow-caught') {
        try { io.stdout.write('PRIVATE_SENTINEL'.repeat(10_000)); } catch {}
      }
      if (mode === 'non-string') io.stdout.write({ secret: 'PRIVATE_SENTINEL' });
      if (mode === 'invalid-json') { io.stdout.write('PRIVATE_SENTINEL'); return 0; }
      if (mode === 'invalid-exit') return 23;
      if (mode === 'stderr') io.stderr.write('PRIVATE_SENTINEL');
      if (mode === 'bad-semantics') {
        io.stdout.write(JSON.stringify({ ...success, actionable: false })); return 0;
      }
      return invokeSuccess(io);
    } });
    assert.equal(result.outcome, 'STOP_UNKNOWN');
    assert.deepEqual(await readRecoveryInspectCapture(runDirectory), result);
    assert.doesNotMatch(await readFile(join(runDirectory, 'terminal.json'), 'utf8'), /PRIVATE_SENTINEL/);
  });
}

test('finite error is persisted and unknown error text is rejected', async (t) => {
  const { root, runDirectory } = await fixture(t);
  const result = await captureRecoveryInspect({ runDirectory, stdout: { write() {} }, invoke: async ({ stderr }) => {
    stderr.write('RUNTIME_REBOOT_REQUIRED\n'); return 2;
  } });
  assert.deepEqual(result, { phase: 'recovery-inspect', outcome: 'FINITE_STOP', code: 'RUNTIME_REBOOT_REQUIRED' });
  assert.deepEqual(await readRecoveryInspectCapture(runDirectory), result);
  const rejected = await captureRecoveryInspect({ runDirectory: join(root, 'other'), stdout: { write() {} },
    invoke: async ({ stderr }) => { stderr.write('PRIVATE_SENTINEL\n'); return 2; },
  });
  assert.equal(rejected.outcome, 'STOP_UNKNOWN');
});

test('publication residue blocks success output and reinvocation', async (t) => {
  const { runDirectory } = await fixture(t);
  let outputs = 0;
  const result = await captureRecoveryInspect({ runDirectory, stdout: { write() { outputs += 1; } },
    invoke: async (io) => {
      await writeFile(join(runDirectory, 'terminal.tmp'), 'partial', { mode: 0o600 });
      return invokeSuccess(io);
    },
  });
  assert.equal(result.outcome, 'STOP_UNKNOWN');
  assert.equal(outputs, 0);
  assert.equal((await readRecoveryInspectCapture(runDirectory)).outcome, 'STOP_UNKNOWN');
  assert.equal((await captureRecoveryInspect({ runDirectory, invoke() { assert.fail('must not invoke'); } })).outcome, 'BLOCKED');
});

test('actual process exit after started marker leaves uncertainty and cannot resume', async (t) => {
  const { runDirectory } = await fixture(t);
  const moduleUrl = new URL('../src/runtime/recovery-inspect-capture.mjs', import.meta.url).href;
  const program = `import { captureRecoveryInspect } from ${JSON.stringify(moduleUrl)};
    await captureRecoveryInspect({runDirectory: process.argv[1], invoke() { process.exit(23); }});`;
  await assert.rejects(promisify(execFile)(process.execPath, ['--input-type=module', '-e', program, runDirectory]),
    (error) => error.code === 23);
  assert.deepEqual(await readdir(runDirectory), ['started.json']);
  assert.equal((await readRecoveryInspectCapture(runDirectory)).outcome, 'STOP_UNKNOWN');
  assert.equal((await captureRecoveryInspect({ runDirectory, invoke() { assert.fail('must not resume'); } })).outcome, 'BLOCKED');
});

for (const mode of ['corrupt', 'extra-field', 'mismatched-run', 'partial', 'permissions', 'symlink']) {
  test(`readback rejects ${mode} receipt`, async (t) => {
    const { root, runDirectory } = await fixture(t);
    await captureRecoveryInspect({ runDirectory, invoke: invokeSuccess, stdout: { write() {} } });
    const path = join(runDirectory, 'terminal.json');
    const record = JSON.parse(await readFile(path, 'utf8'));
    if (mode === 'corrupt') await writeFile(path, 'PRIVATE_SENTINEL');
    if (mode === 'extra-field') {
      record.projection.secret = 'PRIVATE_SENTINEL';
      await writeFile(path, `${JSON.stringify(record)}\n`);
    }
    if (mode === 'mismatched-run') {
      record.runId = '00000000-0000-4000-8000-000000000000';
      await writeFile(path, `${JSON.stringify(record)}\n`);
    }
    if (mode === 'partial') await writeFile(join(runDirectory, 'terminal.tmp'), 'partial');
    if (mode === 'permissions') await chmod(path, 0o644);
    if (mode === 'symlink') {
      const other = join(root, 'other.json');
      await writeFile(other, `${JSON.stringify(record)}\n`, { mode: 0o600 });
      await rm(path);
      await symlink(other, path);
    }
    assert.equal((await readRecoveryInspectCapture(runDirectory)).outcome, 'STOP_UNKNOWN');
  });
}

test('unsafe or missing parent blocks before invoking', async (t) => {
  const { root, runDirectory } = await fixture(t);
  await chmod(root, 0o755);
  const invoke = () => assert.fail('must not invoke');
  assert.equal((await captureRecoveryInspect({ runDirectory, invoke })).outcome, 'BLOCKED');
  assert.equal((await captureRecoveryInspect({ runDirectory: join(root, 'missing', 'run'), invoke })).outcome, 'BLOCKED');
  assert.equal((await readRecoveryInspectCapture(runDirectory)).outcome, 'STOP_UNKNOWN');
});

test('all permitted result statuses and classifications round trip', async (t) => {
  const { root } = await fixture(t);
  for (const status of ['RECOVERY_READY', 'RECOVERY_PARENT_REQUIRED', 'RECOVERY_APPLY_REQUIRED']) {
    for (const classification of ['EMPTY_PRE_TRANSACTION', 'ALREADY_ABSENT']) {
      const runDirectory = join(root, `${status}-${classification}`);
      const result = await captureRecoveryInspect({ runDirectory, stdout: { write() {} },
        invoke: async ({ stdout }) => {
          stdout.write(JSON.stringify({ ...success, status, classification, actionable: status === 'RECOVERY_READY' }));
          return 0;
        },
      });
      assert.equal(result.outcome, 'FINITE_RESULT');
      assert.equal(result.status, status);
      assert.equal(result.classification, classification);
      assert.deepEqual(await readRecoveryInspectCapture(runDirectory), result);
    }
  }
});

test('conflicting terminal is never replaced or accepted as this invocation result', async (t) => {
  const { runDirectory } = await fixture(t);
  let outputs = 0;
  const result = await captureRecoveryInspect({ runDirectory, stdout: { write() { outputs += 1; } },
    invoke: async (io) => {
      await writeFile(join(runDirectory, 'terminal.json'), 'conflict', { mode: 0o600 });
      return invokeSuccess(io);
    },
  });
  assert.equal(result.outcome, 'STOP_UNKNOWN');
  assert.equal(outputs, 0);
  assert.equal(await readFile(join(runDirectory, 'terminal.json'), 'utf8'), 'conflict');
  assert.equal((await readRecoveryInspectCapture(runDirectory)).outcome, 'STOP_UNKNOWN');
});

test('symlink parent is rejected before invocation', async (t) => {
  const { root } = await fixture(t);
  const alias = join(root, 'alias');
  await symlink(root, alias);
  const result = await captureRecoveryInspect({ runDirectory: join(alias, 'run'),
    invoke() { assert.fail('must not invoke'); },
  });
  assert.equal(result.outcome, 'BLOCKED');
  assert.deepEqual(await readdir(root), ['alias']);
});

test('terminal without started marker cannot establish a result', async (t) => {
  const { runDirectory } = await fixture(t);
  await captureRecoveryInspect({ runDirectory, invoke: invokeSuccess, stdout: { write() {} } });
  await rm(join(runDirectory, 'started.json'));
  assert.equal((await readRecoveryInspectCapture(runDirectory)).outcome, 'STOP_UNKNOWN');
  assert.equal((await captureRecoveryInspect({ runDirectory, invoke() { assert.fail('must not invoke'); } })).outcome, 'BLOCKED');
});

test('rejects coercible non-string status in both CLI output and persisted receipt', async (t) => {
  const { root, runDirectory } = await fixture(t);
  const result = await captureRecoveryInspect({ runDirectory, stdout: { write() {} },
    invoke: async ({ stdout }) => {
      stdout.write(JSON.stringify({ ...success, status: ['RECOVERY_READY'] }));
      return 0;
    },
  });
  assert.equal(result.outcome, 'STOP_UNKNOWN');
  const other = join(root, 'other');
  await captureRecoveryInspect({ runDirectory: other, invoke: invokeSuccess, stdout: { write() {} } });
  const terminalPath = join(other, 'terminal.json');
  const terminal = JSON.parse(await readFile(terminalPath, 'utf8'));
  terminal.projection.status = ['RECOVERY_READY'];
  await writeFile(terminalPath, `${JSON.stringify(terminal)}\n`);
  assert.equal((await readRecoveryInspectCapture(other)).outcome, 'STOP_UNKNOWN');
});

// Patch native filesystem calls only inside a disposable child, not the API under test.
for (const fault of ['sync-1', 'sync-2', 'sync-3', 'sync-4', 'sync-5', 'write-1', 'write-2', 'link', 'unlink']) {
  test(`filesystem failure remains finite and cannot reinvoke: ${fault}`, async (t) => {
    const { runDirectory } = await fixture(t);
    const moduleUrl = new URL('../src/runtime/recovery-inspect-capture.mjs', import.meta.url).href;
    const program = `
      import fs from 'node:fs/promises';
      import { syncBuiltinESMExports } from 'node:module';
      const [runDirectory, fault] = process.argv.slice(1);
      let syncs = 0, writes = 0, calls = 0, outputs = 0, triggered = false;
      const fail = () => { triggered = true; throw new Error('PRIVATE_SENTINEL'); };
      const originalOpen = fs.open;
      fs.open = async (...args) => {
        const handle = await originalOpen(...args);
        const originalSync = handle.sync.bind(handle);
        handle.sync = async () => {
          if (fault === 'sync-' + (++syncs)) fail();
          return originalSync();
        };
        const originalWrite = handle.writeFile.bind(handle);
        handle.writeFile = async (data) => {
          if (fault === 'write-' + (++writes)) {
            await originalWrite(data.slice(0, 12));
            fail();
          }
          return originalWrite(data);
        };
        return handle;
      };
      for (const name of ['link', 'unlink']) {
        const original = fs[name];
        fs[name] = async (...args) => { if (fault === name) fail(); return original(...args); };
      }
      syncBuiltinESMExports();
      const { captureRecoveryInspect } = await import(${JSON.stringify(moduleUrl)});
      const options = { runDirectory, stdout: { write() { outputs++; } }, invoke: async ({stdout}) => {
        calls++;
        stdout.write(${JSON.stringify(JSON.stringify(success))});
        return 0;
      } };
      const result = await captureRecoveryInspect(options);
      const duplicate = await captureRecoveryInspect(options);
      process.stdout.write(JSON.stringify({ result, duplicate, calls, outputs, triggered }));
    `;
    const { stdout, stderr } = await promisify(execFile)(process.execPath,
      ['--input-type=module', '-e', program, runDirectory, fault]);
    assert.equal(stderr, '');
    assert.doesNotMatch(stdout, /PRIVATE_SENTINEL/);
    const report = JSON.parse(stdout);
    const beforeInvoke = ['sync-1', 'sync-2', 'sync-3', 'write-1'].includes(fault);
    assert.equal(report.triggered, true);
    assert.equal(report.calls, beforeInvoke ? 0 : 1);
    assert.equal(report.outputs, 0);
    assert.equal(report.result.outcome, beforeInvoke ? 'BLOCKED' : 'STOP_UNKNOWN');
    assert.equal(report.duplicate.outcome, 'BLOCKED');
    // A complete visible receipt after final-directory fsync failure can be read,
    // but that does not establish power-loss durability or authorize another call.
    assert.equal((await readRecoveryInspectCapture(runDirectory)).outcome,
      fault === 'sync-5' ? 'FINITE_RESULT' : 'STOP_UNKNOWN');
  });
}

test('process exit during display leaves a receipt readable by a different process', async (t) => {
  const { runDirectory } = await fixture(t);
  const moduleUrl = new URL('../src/runtime/recovery-inspect-capture.mjs', import.meta.url).href;
  const program = `
    import { captureRecoveryInspect } from ${JSON.stringify(moduleUrl)};
    await captureRecoveryInspect({ runDirectory: process.argv[1],
      invoke: async ({stdout}) => { stdout.write(${JSON.stringify(JSON.stringify(success))}); return 0; },
      stdout: { write() { process.exit(23); } }
    });
  `;
  await assert.rejects(promisify(execFile)(process.execPath,
    ['--input-type=module', '-e', program, runDirectory]), (error) => error.code === 23);
  const readProgram = `import { readRecoveryInspectCapture } from ${JSON.stringify(moduleUrl)};
    process.stdout.write(JSON.stringify(await readRecoveryInspectCapture(process.argv[1])));`;
  const { stdout, stderr } = await promisify(execFile)(process.execPath,
    ['--input-type=module', '-e', readProgram, runDirectory]);
  assert.equal(stderr, '');
  assert.deepEqual(JSON.parse(stdout), expected);
});

test('UTF-8 byte ceiling accepts exactly 64 KiB and rejects one byte more', async (t) => {
  const { root } = await fixture(t);
  const base = JSON.stringify({ ...success, privatePadding: '' });
  const remaining = 65_536 - Buffer.byteLength(base);
  const text = JSON.stringify({ ...success,
    privatePadding: '界'.repeat(Math.floor(remaining / 3)) + 'x'.repeat(remaining % 3),
  });
  assert.equal(Buffer.byteLength(text), 65_536);
  for (const extra of ['', ' ']) {
    const runDirectory = join(root, extra ? 'over' : 'exact');
    const result = await captureRecoveryInspect({ runDirectory, stdout: { write() {} },
      invoke: async ({ stdout }) => { stdout.write(text + extra); return 0; },
    });
    assert.equal(result.outcome, extra ? 'STOP_UNKNOWN' : 'FINITE_RESULT');
    assert.doesNotMatch(await readFile(join(runDirectory, 'terminal.json'), 'utf8'), /界|privatePadding/);
  }
});
