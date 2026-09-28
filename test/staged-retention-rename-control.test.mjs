import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { runProcess } from '../src/process/run-process.mjs';

test('Windows isolated retained-directory rename controls', { skip: process.platform !== 'win32' }, async () => {
  const source = await readFile(new URL('./windows/staged-retention-rename-control.ps1', import.meta.url), 'utf8');
  const encoded = Buffer.from(source, 'utf16le').toString('base64');
  const result = await runProcess('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
    timeoutMs: 30_000,
    maxOutputBytes: 8192,
  });
  assert.equal(result.exitCode, 0);
  assert.equal(result.signal, null);
  assert.equal(result.stderr, '');
  assert.deepEqual(JSON.parse(result.stdout), {
    isolated: true,
    allPassed: true,
    cases: {
      'closed-child': true,
      'destination-conflict': true,
      'source-replacement': true,
      'changed-child': true,
    },
  });
});
