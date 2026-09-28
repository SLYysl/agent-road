import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

for (const args of [[], ['latest'], ['dev_fixture', '0'], ['dev_fixture', '7'], ['dev_fixture', '1', '--retry']]) {
  test(`doctor diagnostic rejects unsupported invocation ${JSON.stringify(args)}`, () => {
    const result = spawnSync(process.execPath, ['tools/diagnose-runtime-doctor.mjs', ...args], {
      cwd: new URL('..', import.meta.url), encoding: 'utf8',
    });
    assert.equal(result.status, 2);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /^Usage: node tools\/diagnose-runtime-doctor\.mjs/);
  });
}
