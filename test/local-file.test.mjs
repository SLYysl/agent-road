import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  access,
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  truncate,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';

import {
  createLocalDestination,
  snapshotBytes,
  snapshotLocalFile,
} from '../src/remote/local-file.mjs';

const LOCAL_FILE_TEST_HOOK = Symbol.for('agent-road.local-file.test-hook');
const RECOVERY_PHASE = 'overwrite-replace-pending';
const DEAD_OWNER_PID = 2_147_483_647;
const OWNER_TOKEN = 'a'.repeat(32);
const OWNER_CREATED_AT = '2026-07-28T00:00:00.000Z';

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex').toUpperCase();
}

async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-local-file-')));
  await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function rejectsCode(operation, code) {
  return assert.rejects(operation, (error) => (
    error?.code === code
    && error.message === code
    && error.cause === undefined
  ));
}

function installLocalFileHook(t, hook) {
  Object.defineProperty(globalThis, LOCAL_FILE_TEST_HOOK, {
    configurable: true,
    value: hook,
    writable: false,
  });
  t.after(() => {
    delete globalThis[LOCAL_FILE_TEST_HOOK];
  });
}

function recoveryPaths(destinationPath) {
  const targetId = createHash('sha256').update(destinationPath, 'utf8').digest('hex');
  const prefix = join(dirname(destinationPath), `.agent-road-overwrite-${targetId}`);
  return {
    backupPath: `${prefix}.backup`,
    journalPath: `${prefix}.journal`,
  };
}

async function plantRecoveryJournal(destinationPath, oldStats, publishedBytes, overrides = {}) {
  const { journalPath } = recoveryPaths(destinationPath);
  const record = {
    schemaVersion: 1,
    phase: RECOVERY_PHASE,
    targetPathSha256: digest(Buffer.from(destinationPath, 'utf8')),
    destinationBytes: publishedBytes.length,
    destinationSha256: digest(publishedBytes),
    oldDev: String(oldStats.dev),
    oldIno: String(oldStats.ino),
    ownerToken: OWNER_TOKEN,
    ownerPid: DEAD_OWNER_PID,
    createdAt: OWNER_CREATED_AT,
    ...overrides,
  };
  await writeFile(journalPath, `${JSON.stringify(record)}\n`, { flag: 'wx', mode: 0o600 });
  return recoveryPaths(destinationPath);
}

test('snapshots one stable regular file into an immutable owner-only fixture', async (t) => {
  const root = await fixture(t);
  const source = join(root, 'source.bin');
  const original = Buffer.from('hello');
  await writeFile(source, original, { mode: 0o640 });

  const snapshot = await snapshotLocalFile(source, { maximumBytes: 1024 });
  assert.equal(Object.isFrozen(snapshot), true);
  assert.deepEqual(Object.keys(snapshot).sort(), ['bytes', 'close', 'path', 'sha256']);
  assert.notEqual(snapshot.path, source);
  assert.equal(snapshot.bytes, original.length);
  assert.equal(snapshot.sha256, digest(original));
  assert.match(snapshot.sha256, /^[A-F0-9]{64}$/u);
  assert.equal((await lstat(snapshot.path)).mode & 0o777, 0o600);
  assert.deepEqual(await readFile(snapshot.path), original);

  await writeFile(source, 'changed');
  assert.deepEqual(await readFile(snapshot.path), original);
  const firstClose = snapshot.close();
  assert.equal(snapshot.close(), firstClose);
  await firstClose;
  await assert.rejects(access(snapshot.path), { code: 'ENOENT' });
});

test('snapshots copied bytes with exact size bounds and idempotent cleanup', async (t) => {
  await fixture(t);
  const source = Buffer.from([0, 1, 2, 3]);
  const snapshot = await snapshotBytes(source, { minimumBytes: 4, maximumBytes: 4 });
  source.fill(9);
  assert.equal(snapshot.bytes, 4);
  assert.equal(snapshot.sha256, digest(Buffer.from([0, 1, 2, 3])));
  assert.deepEqual(await readFile(snapshot.path), Buffer.from([0, 1, 2, 3]));
  await Promise.all([snapshot.close(), snapshot.close()]);
});

test('rejects unsafe paths, links, directories, zero bytes, and oversized files', async (t) => {
  const root = await fixture(t);
  const source = join(root, 'source.bin');
  const hardlink = join(root, 'hardlink.bin');
  const symbolic = join(root, 'symbolic.bin');
  const directory = join(root, 'directory');
  await writeFile(source, 'hello');
  await link(source, hardlink);
  await symlink(source, symbolic);
  await mkdir(directory);

  for (const candidate of [source, hardlink, symbolic, directory]) {
    await rejectsCode(snapshotLocalFile(candidate, { maximumBytes: 1024 }), 'REMOTE_INPUT_INVALID');
  }

  const zero = join(root, 'zero.bin');
  const large = join(root, 'large.bin');
  await writeFile(zero, Buffer.alloc(0));
  await writeFile(large, Buffer.alloc(5));
  await rejectsCode(snapshotLocalFile(zero, { maximumBytes: 1024 }), 'REMOTE_INPUT_INVALID');
  await rejectsCode(snapshotLocalFile(large, { maximumBytes: 4 }), 'REMOTE_INPUT_INVALID');
  await rejectsCode(snapshotLocalFile('relative.bin', { maximumBytes: 4 }), 'REMOTE_INPUT_INVALID');
  await rejectsCode(
    snapshotLocalFile(`${root}/directory/../large.bin`, { maximumBytes: 8 }),
    'REMOTE_INPUT_INVALID',
  );
  await rejectsCode(snapshotLocalFile(`${root}/bad\0name`, { maximumBytes: 8 }), 'REMOTE_INPUT_INVALID');
});

test('rejects a source whose path or metadata changes during the snapshot', async (t) => {
  const root = await fixture(t);
  const source = join(root, 'changing.bin');
  const replacement = join(root, 'replacement.bin');
  await writeFile(source, Buffer.alloc(1));
  await truncate(source, 32 * 1024 * 1024);
  await writeFile(replacement, Buffer.alloc(1024, 7));

  const pending = snapshotLocalFile(source, { maximumBytes: 64 * 1024 * 1024 });
  await new Promise((resolve) => setImmediate(resolve));
  await rename(replacement, source);
  await rejectsCode(pending, 'REMOTE_INPUT_INVALID');
});

test('rejects deterministic same-inode mutation between the two source reads', async (t) => {
  const root = await fixture(t);
  const source = join(root, 'same-inode.bin');
  const original = Buffer.alloc(1024 * 1024, 1);
  await writeFile(source, original);
  const inode = (await lstat(source)).ino;
  let mutated = false;
  installLocalFileHook(t, async (event, context) => {
    if (event === 'afterStableFirstRead' && context.path === source && !mutated) {
      mutated = true;
      await writeFile(source, Buffer.alloc(original.length, 2));
      assert.equal((await lstat(source)).ino, inode);
    }
  });

  await rejectsCode(
    snapshotLocalFile(source, { maximumBytes: 2 * 1024 * 1024 }),
    'REMOTE_INPUT_INVALID',
  );
  assert.equal(mutated, true);
});

test('rejects hostile and non-exact snapshot inputs before creating a temporary file', async () => {
  const accessor = {};
  Object.defineProperty(accessor, 'maximumBytes', {
    enumerable: true,
    get() { throw new Error('accessor executed'); },
  });
  const withSymbol = { maximumBytes: 4 };
  withSymbol[Symbol('secret')] = true;

  for (const options of [
    accessor,
    withSymbol,
    new Proxy({ maximumBytes: 4 }, {}),
    { maximumBytes: 4, unknown: true },
    { maximumBytes: 0 },
    { minimumBytes: 5, maximumBytes: 4 },
    { minimumBytes: 1, maximumBytes: 256 * 1024 * 1024 + 1 },
  ]) {
    await rejectsCode(snapshotBytes(Buffer.alloc(4), options), 'REMOTE_INPUT_INVALID');
  }

  await rejectsCode(snapshotBytes(Buffer.alloc(0), { maximumBytes: 4 }), 'REMOTE_INPUT_INVALID');
  await rejectsCode(snapshotBytes(Buffer.alloc(5), { maximumBytes: 4 }), 'REMOTE_INPUT_INVALID');
  await rejectsCode(snapshotBytes('bytes', { maximumBytes: 8 }), 'REMOTE_INPUT_INVALID');
  await rejectsCode(
    snapshotBytes(new Proxy(Buffer.from('safe'), {}), { maximumBytes: 8 }),
    'REMOTE_INPUT_INVALID',
  );
});

test('publishes one verified local download atomically and keeps cleanup idempotent', async (t) => {
  const root = await fixture(t);
  const destinationPath = join(root, 'download.bin');
  const downloaded = Buffer.from('downloaded bytes');
  const destination = await createLocalDestination(destinationPath, {
    overwrite: false,
    expectedBytes: downloaded.length,
    expectedSha256: digest(downloaded),
  });

  assert.equal(Object.isFrozen(destination), true);
  assert.deepEqual(Object.keys(destination).sort(), ['close', 'publish', 'temporaryPath']);
  assert.equal((await lstat(destination.temporaryPath)).mode & 0o777, 0o600);
  await writeFile(destination.temporaryPath, downloaded);
  const publication = destination.publish();
  assert.equal(destination.publish(), publication);
  await publication;
  assert.deepEqual(await readFile(destinationPath), downloaded);
  assert.equal((await lstat(destinationPath)).mode & 0o777, 0o600);
  await Promise.all([destination.close(), destination.close()]);
});

for (const overwrite of [false, true]) {
  test(`syncs and revalidates temp content before ${overwrite ? 'rename' : 'link'} publication`, async (t) => {
    const root = await fixture(t);
    const destinationPath = join(root, 'download.bin');
    const original = Buffer.from('original bytes');
    const downloaded = Buffer.from('downloaded bytes');
    if (overwrite) await writeFile(destinationPath, original, { mode: 0o600 });
    const { backupPath, journalPath } = recoveryPaths(destinationPath);
    const destination = await createLocalDestination(destinationPath, {
      overwrite,
      expectedBytes: downloaded.length,
      expectedSha256: digest(downloaded),
    });
    await writeFile(destination.temporaryPath, downloaded);
    const observed = [];
    installLocalFileHook(t, async (event, context) => {
      if (
        ['beforeDownloadedFileSync', 'afterDownloadedFileSync'].includes(event)
        && context.path === destination.temporaryPath
      ) {
        observed.push(event);
        if (overwrite) {
          assert.deepEqual(await readFile(destinationPath), original);
        } else {
          await assert.rejects(access(destinationPath), { code: 'ENOENT' });
        }
        await assert.rejects(access(backupPath), { code: 'ENOENT' });
        await assert.rejects(access(journalPath), { code: 'ENOENT' });
      }
    });

    await destination.publish();

    assert.deepEqual(observed, ['beforeDownloadedFileSync', 'afterDownloadedFileSync']);
    assert.deepEqual(await readFile(destinationPath), downloaded);
    await destination.close();
  });
}

test('does not publish when syncing verified temp content fails', async (t) => {
  const root = await fixture(t);
  const destinationPath = join(root, 'download.bin');
  const downloaded = Buffer.from('downloaded bytes');
  const destination = await createLocalDestination(destinationPath, {
    overwrite: false,
    expectedBytes: downloaded.length,
    expectedSha256: digest(downloaded),
  });
  await writeFile(destination.temporaryPath, downloaded);
  let injected = false;
  installLocalFileHook(t, async (event, context) => {
    if (event === 'beforeDownloadedFileSync' && context.path === destination.temporaryPath) {
      injected = true;
      throw new Error('injected temp sync failure');
    }
  });

  await rejectsCode(destination.publish(), 'FILE_INTEGRITY_FAILED');
  assert.equal(injected, true);
  await assert.rejects(access(destinationPath), { code: 'ENOENT' });
  assert.deepEqual(await readFile(destination.temporaryPath), downloaded);
  await destination.close();
  await assert.rejects(access(destination.temporaryPath), { code: 'ENOENT' });
});

test('fails closed when the temp path changes inode after content sync', async (t) => {
  const root = await fixture(t);
  const destinationPath = join(root, 'download.bin');
  const downloaded = Buffer.from('downloaded bytes');
  const destination = await createLocalDestination(destinationPath, {
    overwrite: false,
    expectedBytes: downloaded.length,
    expectedSha256: digest(downloaded),
  });
  await writeFile(destination.temporaryPath, downloaded);
  let replaced = false;
  installLocalFileHook(t, async (event, context) => {
    if (event === 'afterDownloadedFileSync' && context.path === destination.temporaryPath) {
      const replacement = join(root, 'replacement.bin');
      await writeFile(replacement, downloaded, { mode: 0o600 });
      await rename(replacement, destination.temporaryPath);
      replaced = true;
    }
  });

  await rejectsCode(destination.publish(), 'FILE_INTEGRITY_FAILED');
  assert.equal(replaced, true);
  await assert.rejects(access(destinationPath), { code: 'ENOENT' });
  await unlink(destination.temporaryPath);
  await destination.close();
});

test('preserves an existing destination when integrity verification fails', async (t) => {
  const root = await fixture(t);
  const destinationPath = join(root, 'download.bin');
  const original = Buffer.from('original');
  const expected = Buffer.from('expected');
  await writeFile(destinationPath, original, { mode: 0o600 });
  const destination = await createLocalDestination(destinationPath, {
    overwrite: true,
    expectedBytes: expected.length,
    expectedSha256: digest(expected),
  });
  await writeFile(destination.temporaryPath, Buffer.from('corrupt!'));

  await rejectsCode(destination.publish(), 'FILE_INTEGRITY_FAILED');
  assert.deepEqual(await readFile(destinationPath), original);
  await destination.close();
  await assert.rejects(access(destination.temporaryPath), { code: 'ENOENT' });
});

test('maps every invalid download temporary to FILE_INTEGRITY_FAILED', async (t) => {
  const root = await fixture(t);
  const expected = Buffer.from('expected');
  const fixtures = [
    ['short', Buffer.from('short'), null],
    ['long', Buffer.from('too-long-value'), null],
    ['missing', null, 'missing'],
    ['replaced', Buffer.from('replaced'), 'replace'],
  ];

  for (const [name, bytes, action] of fixtures) {
    const destination = await createLocalDestination(join(root, `${name}.bin`), {
      overwrite: false,
      expectedBytes: expected.length,
      expectedSha256: digest(expected),
    });
    if (action === 'missing') {
      await unlink(destination.temporaryPath);
    } else if (action === 'replace') {
      const replacement = join(root, `${name}-source.bin`);
      await writeFile(replacement, bytes, { mode: 0o600 });
      await rename(replacement, destination.temporaryPath);
    } else {
      await writeFile(destination.temporaryPath, bytes);
    }
    await rejectsCode(destination.publish(), 'FILE_INTEGRITY_FAILED');
    await destination.close().catch(() => {});
  }
});

test('keeps the old overwrite target visible through every pre-rename hook', async (t) => {
  const root = await fixture(t);
  const destinationPath = join(root, 'target.bin');
  const oldBytes = Buffer.from('old-target');
  const newBytes = Buffer.from('new-target');
  await writeFile(destinationPath, oldBytes, { mode: 0o600 });
  const destination = await createLocalDestination(destinationPath, {
    overwrite: true,
    expectedBytes: newBytes.length,
    expectedSha256: digest(newBytes),
  });
  await writeFile(destination.temporaryPath, newBytes);
  const observed = [];
  installLocalFileHook(t, async (event) => {
    if ([
      'afterOverwriteBackupLink',
      'afterOverwriteBackupSync',
      'beforeOverwriteFinalCheck',
    ].includes(event)) {
      observed.push(event);
      assert.deepEqual(await readFile(destinationPath), oldBytes);
    }
  });

  await destination.publish();
  assert.deepEqual(observed, [
    'afterOverwriteBackupLink',
    'afterOverwriteBackupSync',
    'beforeOverwriteFinalCheck',
  ]);
  assert.deepEqual(await readFile(destinationPath), newBytes);
  await destination.close();
});

test('fails closed when overwrite target changes before the final inode check', async (t) => {
  const root = await fixture(t);
  const destinationPath = join(root, 'target.bin');
  const concurrentPath = join(root, 'concurrent.bin');
  const oldBytes = Buffer.from('old-target');
  const newBytes = Buffer.from('new-target');
  const concurrentBytes = Buffer.from('concurrent');
  await writeFile(destinationPath, oldBytes, { mode: 0o600 });
  await writeFile(concurrentPath, concurrentBytes, { mode: 0o600 });
  const destination = await createLocalDestination(destinationPath, {
    overwrite: true,
    expectedBytes: newBytes.length,
    expectedSha256: digest(newBytes),
  });
  await writeFile(destination.temporaryPath, newBytes);
  let replaced = false;
  installLocalFileHook(t, async (event) => {
    if (event === 'beforeOverwriteFinalCheck' && !replaced) {
      replaced = true;
      await rename(concurrentPath, destinationPath);
    }
  });

  await rejectsCode(destination.publish(), 'FILE_TRANSFER_FAILED');
  assert.equal(replaced, true);
  assert.deepEqual(await readFile(destinationPath), concurrentBytes);
  await destination.close();
});

for (const mutation of ['symlink', 'hardlink', 'directory']) {
  test(`maps a publish-time ${mutation} destination mutation to FILE_TRANSFER_FAILED`, async (t) => {
    const root = await fixture(t);
    const destinationPath = join(root, 'target.bin');
    const original = Buffer.from('original');
    const expected = Buffer.from('expected');
    await writeFile(destinationPath, original, { mode: 0o600 });
    const destination = await createLocalDestination(destinationPath, {
      overwrite: true,
      expectedBytes: expected.length,
      expectedSha256: digest(expected),
    });
    await writeFile(destination.temporaryPath, expected);

    if (mutation === 'symlink') {
      const replacement = join(root, 'replacement.bin');
      await writeFile(replacement, original, { mode: 0o600 });
      await unlink(destinationPath);
      await symlink(replacement, destinationPath);
    } else if (mutation === 'hardlink') {
      await link(destinationPath, join(root, 'second-link.bin'));
    } else {
      await unlink(destinationPath);
      await mkdir(destinationPath);
    }

    await rejectsCode(destination.publish(), 'FILE_TRANSFER_FAILED');
    await destination.close();
  });
}

test('preserves publish-time FILE_TRANSFER_FAILED when unsafe validation cleanup also fails', async (t) => {
  const root = await fixture(t);
  const destinationPath = join(root, 'target.bin');
  const expected = Buffer.from('expected');
  await writeFile(destinationPath, 'original', { mode: 0o600 });
  const destination = await createLocalDestination(destinationPath, {
    overwrite: true,
    expectedBytes: expected.length,
    expectedSha256: digest(expected),
  });
  await writeFile(destination.temporaryPath, expected);
  await unlink(destinationPath);
  await mkdir(destinationPath);
  let injected = false;
  installLocalFileHook(t, async (event, context) => {
    if (
      event === 'afterFileHandleClose'
      && context.fallbackCode === 'REMOTE_INPUT_INVALID'
      && context.primaryCode === 'REMOTE_INPUT_INVALID'
      && !injected
    ) {
      injected = true;
      throw new Error('injected validation close failure');
    }
  });

  await assert.rejects(destination.publish(), (error) => (
    error?.code === 'LOCAL_CLEANUP_FAILED'
    && error.primaryCode === 'FILE_TRANSFER_FAILED'
    && error.message === 'LOCAL_CLEANUP_FAILED'
  ));
  assert.equal(injected, true);
  await destination.close();
});

for (const publishedBytes of [Buffer.from('published-target'), Buffer.alloc(0)]) {
  for (const crashPoint of [
    'marker-only',
    'backup-before-rename',
    'after-rename-before-unlink',
    'after-unlink-before-directory-sync',
    'destination-missing',
  ]) {
    test(`reconciles the exact ${crashPoint} ${publishedBytes.length}-byte overwrite recovery state`, async (t) => {
      const root = await fixture(t);
      const destinationPath = join(root, 'target.bin');
      const oldBytes = Buffer.from('old-target');
      const nextBytes = Buffer.from('next-target');
      await writeFile(destinationPath, oldBytes, { mode: 0o600 });
      const oldStats = await lstat(destinationPath, { bigint: true });
      const { backupPath, journalPath } = await plantRecoveryJournal(
        destinationPath,
        oldStats,
        publishedBytes,
      );

      if (['backup-before-rename', 'after-rename-before-unlink', 'destination-missing'].includes(crashPoint)) {
        await link(destinationPath, backupPath);
      }
      if (['after-rename-before-unlink', 'after-unlink-before-directory-sync'].includes(crashPoint)) {
        const replacement = join(root, 'published.bin');
        await writeFile(replacement, publishedBytes, { mode: 0o600 });
        await rename(replacement, destinationPath);
      }
      if (crashPoint === 'destination-missing') await unlink(destinationPath);

      const destination = await createLocalDestination(destinationPath, {
        overwrite: true,
        expectedBytes: nextBytes.length,
        expectedSha256: digest(nextBytes),
      });

      const expectedBytes = ['after-rename-before-unlink', 'after-unlink-before-directory-sync']
        .includes(crashPoint) ? publishedBytes : oldBytes;
      assert.deepEqual(await readFile(destinationPath), expectedBytes);
      await assert.rejects(access(journalPath), { code: 'ENOENT' });
      await assert.rejects(access(backupPath), { code: 'ENOENT' });
      await destination.close();
    });
  }
}

test('keeps a trusted live same-process overwrite journal locked', async (t) => {
  const root = await fixture(t);
  const destinationPath = join(root, 'target.bin');
  const oldBytes = Buffer.from('old-target');
  const publishedBytes = Buffer.from('published-target');
  await writeFile(destinationPath, oldBytes, { mode: 0o600 });
  const oldStats = await lstat(destinationPath, { bigint: true });
  const { journalPath, backupPath } = await plantRecoveryJournal(
    destinationPath,
    oldStats,
    publishedBytes,
    { ownerPid: process.pid },
  );
  const journalBytes = await readFile(journalPath);

  await rejectsCode(createLocalDestination(destinationPath, {
    overwrite: true,
    expectedBytes: 1,
    expectedSha256: digest(Buffer.from('x')),
  }), 'FILE_TRANSFER_FAILED');

  assert.deepEqual(await readFile(destinationPath), oldBytes);
  assert.deepEqual(await readFile(journalPath), journalBytes);
  await assert.rejects(access(backupPath), { code: 'ENOENT' });
});

for (const [name, overrides] of [
  ['owner token', { ownerToken: 'invalid' }],
  ['owner pid', { ownerPid: 0 }],
  ['owner timestamp', { createdAt: 'not-a-timestamp' }],
]) {
  test(`fails closed without deleting a journal with an invalid ${name}`, async (t) => {
    const root = await fixture(t);
    const destinationPath = join(root, 'target.bin');
    const oldBytes = Buffer.from('old-target');
    const publishedBytes = Buffer.from('published-target');
    await writeFile(destinationPath, oldBytes, { mode: 0o600 });
    const oldStats = await lstat(destinationPath, { bigint: true });
    const { journalPath } = await plantRecoveryJournal(
      destinationPath,
      oldStats,
      publishedBytes,
      overrides,
    );
    const journalBytes = await readFile(journalPath);

    await rejectsCode(createLocalDestination(destinationPath, {
      overwrite: true,
      expectedBytes: 1,
      expectedSha256: digest(Buffer.from('x')),
    }), 'LOCAL_CLEANUP_FAILED');

    assert.deepEqual(await readFile(destinationPath), oldBytes);
    assert.deepEqual(await readFile(journalPath), journalBytes);
  });
}

test('fails closed without deleting a hostile preplanted recovery journal', async (t) => {
  const root = await fixture(t);
  const destinationPath = join(root, 'target.bin');
  const destinationBytes = Buffer.from('original');
  const { journalPath, backupPath } = recoveryPaths(destinationPath);
  const hostile = Buffer.from('{"schemaVersion":1,"phase":"hostile"}\n');
  await writeFile(destinationPath, destinationBytes, { mode: 0o600 });
  await writeFile(journalPath, hostile, { flag: 'wx', mode: 0o600 });

  await rejectsCode(createLocalDestination(destinationPath, {
    overwrite: true,
    expectedBytes: 1,
    expectedSha256: digest(Buffer.from('x')),
  }), 'LOCAL_CLEANUP_FAILED');

  assert.deepEqual(await readFile(destinationPath), destinationBytes);
  assert.deepEqual(await readFile(journalPath), hostile);
  await assert.rejects(access(backupPath), { code: 'ENOENT' });
});

test('durably removes the overwrite backup and journal before publish succeeds', async (t) => {
  const root = await fixture(t);
  const destinationPath = join(root, 'target.bin');
  const oldBytes = Buffer.from('old-target');
  const newBytes = Buffer.from('new-target');
  const { backupPath, journalPath } = recoveryPaths(destinationPath);
  await writeFile(destinationPath, oldBytes, { mode: 0o600 });
  const destination = await createLocalDestination(destinationPath, {
    overwrite: true,
    expectedBytes: newBytes.length,
    expectedSha256: digest(newBytes),
  });
  await writeFile(destination.temporaryPath, newBytes);
  const syncPhases = [];
  installLocalFileHook(t, async (event, context) => {
    if (event === 'beforeDirectorySync' && context.path === destinationPath) {
      syncPhases.push(context.phase);
      if (context.phase === 'overwrite-journal-created') {
        const journal = JSON.parse(await readFile(journalPath, 'utf8'));
        assert.match(journal.ownerToken, /^[a-f0-9]{32}$/u);
        assert.equal(journal.ownerPid, process.pid);
        assert.equal(new Date(journal.createdAt).toISOString(), journal.createdAt);
      }
      if (context.phase === 'overwrite-backup-removed') {
        await assert.rejects(access(backupPath), { code: 'ENOENT' });
        await access(journalPath);
      }
      if (context.phase === 'overwrite-journal-removed') {
        await assert.rejects(access(journalPath), { code: 'ENOENT' });
      }
    }
  });

  await destination.publish();

  assert.deepEqual(syncPhases, [
    'overwrite-journal-created',
    'overwrite-backup-created',
    'published',
    'overwrite-backup-removed',
    'overwrite-journal-removed',
  ]);
  assert.deepEqual(await readFile(destinationPath), newBytes);
  await destination.close();
});

test('maps a successful file close failure without publishing uncertain bytes', async (t) => {
  const root = await fixture(t);
  const destinationPath = join(root, 'target.bin');
  const expected = Buffer.from('expected');
  const destination = await createLocalDestination(destinationPath, {
    overwrite: false,
    expectedBytes: expected.length,
    expectedSha256: digest(expected),
  });
  await writeFile(destination.temporaryPath, expected);
  let armed = false;
  let closeFailures = 0;
  installLocalFileHook(t, async (event, context) => {
    if (event === 'afterStableFirstRead' && context.path === destination.temporaryPath) {
      armed = true;
    }
    if (event === 'afterFileHandleClose' && armed) {
      armed = false;
      closeFailures += 1;
      throw new Error('injected close failure');
    }
  });

  await rejectsCode(destination.publish(), 'LOCAL_CLEANUP_FAILED');

  assert.equal(closeFailures, 1);
  await assert.rejects(access(destinationPath), { code: 'ENOENT' });
  await destination.close();
});

test('preserves the primary integrity code when closing the checked file also fails', async (t) => {
  const root = await fixture(t);
  const destinationPath = join(root, 'target.bin');
  const expected = Buffer.from('expected');
  const destination = await createLocalDestination(destinationPath, {
    overwrite: false,
    expectedBytes: expected.length,
    expectedSha256: digest(expected),
  });
  await writeFile(destination.temporaryPath, Buffer.from('corrupt!'));
  let armed = false;
  let closeFailures = 0;
  installLocalFileHook(t, async (event, context) => {
    if (event === 'afterStableFirstRead' && context.path === destination.temporaryPath) {
      armed = true;
    }
    if (event === 'afterFileHandleClose' && armed) {
      armed = false;
      closeFailures += 1;
      throw new Error('injected close failure');
    }
  });

  await assert.rejects(destination.publish(), (error) => (
    error?.code === 'LOCAL_CLEANUP_FAILED'
    && error.primaryCode === 'FILE_INTEGRITY_FAILED'
    && error.message === 'LOCAL_CLEANUP_FAILED'
  ));

  assert.equal(closeFailures, 1);
  await destination.close();
});

for (const failurePoint of ['directory sync', 'post-integrity']) {
  test(`restores the old overwrite target after injected ${failurePoint} failure`, async (t) => {
    const root = await fixture(t);
    const destinationPath = join(root, 'target.bin');
    const oldBytes = Buffer.from('old-target');
    const newBytes = Buffer.from('new-target');
    await writeFile(destinationPath, oldBytes, { mode: 0o600 });
    const { backupPath } = recoveryPaths(destinationPath);
    const destination = await createLocalDestination(destinationPath, {
      overwrite: true,
      expectedBytes: newBytes.length,
      expectedSha256: digest(newBytes),
    });
    await writeFile(destination.temporaryPath, newBytes);
    let injected = false;
    installLocalFileHook(t, async (event, context) => {
      if (failurePoint === 'directory sync'
          && event === 'beforeDirectorySync'
          && context.phase === 'published'
          && !injected) {
        injected = true;
        assert.deepEqual(await readFile(destinationPath), newBytes);
        assert.deepEqual(await readFile(backupPath), oldBytes);
        throw new Error('injected directory sync failure');
      }
      if (failurePoint === 'post-integrity' && event === 'beforePostIntegrity' && !injected) {
        injected = true;
        await writeFile(destinationPath, Buffer.alloc(newBytes.length, 9));
      }
    });

    await rejectsCode(destination.publish(), failurePoint === 'post-integrity'
      ? 'FILE_INTEGRITY_FAILED'
      : 'FILE_TRANSFER_FAILED');
    assert.equal(injected, true);
    assert.deepEqual(await readFile(destinationPath), oldBytes);
    await destination.close();
  });
}

test('retains primary and rollback boundary when overwrite restoration fails', async (t) => {
  const root = await fixture(t);
  const destinationPath = join(root, 'target.bin');
  const oldBytes = Buffer.from('old-target');
  const newBytes = Buffer.from('new-target');
  await writeFile(destinationPath, oldBytes, { mode: 0o600 });
  const { backupPath } = recoveryPaths(destinationPath);
  const destination = await createLocalDestination(destinationPath, {
    overwrite: true,
    expectedBytes: newBytes.length,
    expectedSha256: digest(newBytes),
  });
  await writeFile(destination.temporaryPath, newBytes);
  installLocalFileHook(t, async (event, context) => {
    if (event === 'beforeDirectorySync' && context.phase === 'published') {
      throw new Error('injected publication failure');
    }
    if (event === 'beforeRollbackRestore') {
      throw new Error('injected rollback failure');
    }
  });

  await assert.rejects(destination.publish(), (error) => (
    error?.code === 'LOCAL_CLEANUP_FAILED'
    && error.primaryCode === 'FILE_TRANSFER_FAILED'
    && error.message === 'LOCAL_CLEANUP_FAILED'
  ));
  assert.deepEqual(await readFile(destinationPath), newBytes);
  assert.deepEqual(await readFile(backupPath), oldBytes);
});

test('requires explicit overwrite and rejects unsafe overwrite targets', async (t) => {
  const root = await fixture(t);
  const existing = join(root, 'existing.bin');
  await writeFile(existing, 'existing', { mode: 0o600 });

  await rejectsCode(createLocalDestination(existing, {
    overwrite: false,
    expectedBytes: 1,
    expectedSha256: digest(Buffer.from('x')),
  }), 'REMOTE_INPUT_INVALID');

  const hardlinkPath = join(root, 'hardlink.bin');
  await link(existing, hardlinkPath);
  await rejectsCode(createLocalDestination(existing, {
    overwrite: true,
    expectedBytes: 1,
    expectedSha256: digest(Buffer.from('x')),
  }), 'REMOTE_INPUT_INVALID');

  const symbolic = join(root, 'symbolic.bin');
  await symlink(existing, symbolic);
  await rejectsCode(createLocalDestination(symbolic, {
    overwrite: true,
    expectedBytes: 1,
    expectedSha256: digest(Buffer.from('x')),
  }), 'REMOTE_INPUT_INVALID');

  const directory = join(root, 'directory');
  await mkdir(directory);
  await rejectsCode(createLocalDestination(directory, {
    overwrite: true,
    expectedBytes: 1,
    expectedSha256: digest(Buffer.from('x')),
  }), 'REMOTE_INPUT_INVALID');
});

test('allows overwrite of an existing empty regular file', async (t) => {
  const root = await fixture(t);
  const destinationPath = join(root, 'empty.bin');
  const downloaded = Buffer.from('replacement');
  await writeFile(destinationPath, Buffer.alloc(0), { mode: 0o600 });
  const destination = await createLocalDestination(destinationPath, {
    overwrite: true,
    expectedBytes: downloaded.length,
    expectedSha256: digest(downloaded),
  });
  await writeFile(destination.temporaryPath, downloaded);
  await destination.publish();
  assert.deepEqual(await readFile(destinationPath), downloaded);
  await destination.close();
});

test('validates an exact destination contract without invoking accessors', async (t) => {
  const root = await fixture(t);
  const destinationPath = join(root, 'download.bin');
  const accessor = {
    overwrite: false,
    expectedBytes: 1,
  };
  Object.defineProperty(accessor, 'expectedSha256', {
    enumerable: true,
    get() { throw new Error('accessor executed'); },
  });

  for (const options of [
    accessor,
    { overwrite: 0, expectedBytes: 1, expectedSha256: digest(Buffer.from('x')) },
    { overwrite: false, expectedBytes: -1, expectedSha256: digest(Buffer.from('x')) },
    { overwrite: false, expectedBytes: 1, expectedSha256: digest(Buffer.from('x')).toLowerCase() },
    { overwrite: false, expectedBytes: 1, expectedSha256: digest(Buffer.from('x')), extra: true },
  ]) {
    await rejectsCode(createLocalDestination(destinationPath, options), 'REMOTE_INPUT_INVALID');
  }
});

test('explicit zero-byte snapshots and download publication preserve empty-file integrity', async (t) => {
  const root = await fixture(t);
  const source = join(root, 'empty-source');
  await writeFile(source, '');
  const snapshot = await snapshotLocalFile(source, {minimumBytes: 0, maximumBytes: 1024});
  assert.equal(snapshot.bytes, 0);
  assert.equal(snapshot.sha256, digest(Buffer.alloc(0)));
  await snapshot.close();
  for (const overwrite of [false, true]) {
    const target = join(root, 'empty-target');
    if (overwrite) await writeFile(target, 'previous content');
    const destination = await createLocalDestination(target, {overwrite, expectedBytes: 0, expectedSha256: digest(Buffer.alloc(0))});
    await destination.publish();
    await destination.close();
    assert.equal((await readFile(target)).length, 0);
  }
});
