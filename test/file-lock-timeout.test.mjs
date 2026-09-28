import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { isFileLockTimeout, withFileLock } from '../src/storage/file-lock.mjs';

test('timeout marker distinguishes actual acquisition timeout from lookalike failures', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-lock-marker-'));
  try {
    const path = join(directory, 'resource');
    await withFileLock(path, async () => {
      await assert.rejects(
        withFileLock(path, async () => assert.fail('entered held lock'), { timeoutMs: 10 }),
        (error) => isFileLockTimeout(error),
      );
    });
    assert.equal(isFileLockTimeout(new Error('file is locked: private (owner)')), false);
    assert.equal(isFileLockTimeout({ code: 'FILE_LOCK_TIMEOUT' }), false);
    const inner = new Error('operation failed');
    await assert.rejects(
      withFileLock(path, async () => { throw inner; }),
      (error) => error === inner && !isFileLockTimeout(error),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
