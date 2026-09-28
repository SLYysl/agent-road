import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

test('inspection command rejects missing, malformed and extra arguments before connecting', () => {
  for (const args of [[], ['secret/path'], ['dev_test', 'extra']]) {
    const result = spawnSync(process.execPath, ['tools/inspect-existing-base.mjs', ...args], {encoding: 'utf8'});
    assert.equal(result.status, 2);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, 'Usage: node tools/inspect-existing-base.mjs <device-id>\n');
    assert.equal(result.stderr.includes('secret/path'), false);
  }
});
