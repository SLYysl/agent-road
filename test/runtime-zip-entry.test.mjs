import assert from 'node:assert/strict';
import test from 'node:test';
import {runProcess} from '../src/process/run-process.mjs';
import {retentionScriptInvocation} from '../src/runtime/staged-retention-remote.mjs';
import {buildRuntimeZipEntryFixture} from './fixtures/runtime-zip-entry.mjs';

test('Windows ZIP validation accepts the first entry and rejects a case collision', {
  skip: process.platform !== 'win32',
}, async () => {
  const call = retentionScriptInvocation(await buildRuntimeZipEntryFixture());
  const result = await runProcess(call.argv[0], call.argv.slice(1), {
    stdinText: call.stdin, timeoutMs: 20_000, maxOutputBytes: 4096,
  });
  assert.equal(result.exitCode, 0);
  assert.equal(result.signal, null);
  assert.equal(result.stderr, '');
  assert.deepEqual(JSON.parse(result.stdout), {firstEntryAccepted: true, caseCollisionRejected: true});
});
