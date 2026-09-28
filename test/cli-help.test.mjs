import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

test('prints controller commands for --help', () => {
  const result = spawnSync(process.execPath, ['src/cli.mjs', '--help'], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });

  assert.equal(result.status, 0);
  assert.match(result.stdout, /agent-road enroll/);
  assert.match(result.stdout, /agent-road list/);
  assert.match(result.stdout, /agent-road status/);
  assert.match(result.stdout, /agent-road runtime-confirm-rollback <device-id>/);
  assert.match(result.stdout, /agent-road runtime-readiness <device-id>/);
  assert.match(result.stdout, /agent-road runtime-retain-empty-stage <device-id>/);
  assert.match(result.stdout, /agent-road exec <device-id> --script <local\.ps1>/);
  assert.match(result.stdout, /--timeout-seconds <1-1800>/);
  assert.match(result.stdout, /agent-road put <device-id> <local-file> <absolute-windows-path>/);
  assert.match(result.stdout, /agent-road get <device-id> <absolute-windows-path> <local-file>/);
  assert.match(result.stdout, /--overwrite/);
  assert.equal(result.stderr, '');
});

test('prints help when invoked through a symlinked entrypoint', () => {
  const directory = mkdtempSync(join(tmpdir(), 'agent-road-'));
  const entrypoint = join(directory, 'agent-road');
  symlinkSync(join(process.cwd(), 'src/cli.mjs'), entrypoint);

  try {
    const result = spawnSync(process.execPath, [entrypoint, '--help'], {
      cwd: process.cwd(),
      encoding: 'utf8',
    });

    assert.equal(result.status, 0);
    assert.match(result.stdout, /agent-road enroll/);
    assert.equal(result.stderr, '');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('can be imported without an entry script', () => {
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', "import('./src/cli.mjs')"], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });

  assert.equal(result.status, 0);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
});
