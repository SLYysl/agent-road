import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { runProcess } from '../src/process/run-process.mjs';
import { buildNativeStdinFixture } from './fixtures/native-stdin.mjs';

test('native stdin validates fragmented open pipes and rejects corrupt frames', {
  skip: process.platform !== 'win32',
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-native-stdin-'));
  try {
    const path = join(directory, 'fixture.ps1');
    await writeFile(path, buildNativeStdinFixture());
    const result = await runProcess('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', path], {
      timeoutMs: 150000, maxOutputBytes: 4096,
    });
    assert.equal(result.exitCode, 0);
    assert.equal(result.stderr, '');
    const report = JSON.parse(result.stdout);
    assert.equal(report.cases.length, 6);
    assert.equal(report.passed, true);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
