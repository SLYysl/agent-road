import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { mkdtemp, open, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { readJson, writeJsonAtomic } from '../src/storage/json-file.mjs';

test('writes a pretty registry atomically and reads it back', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-json-file-'));
  const registryPath = join(directory, 'registry.json');
  const value = { devices: [{ id: 'dev_a' }] };
  t.after(() => rm(directory, { recursive: true, force: true }));

  await writeJsonAtomic(registryPath, value);

  assert.deepEqual(await readJson(registryPath, { devices: [] }), value);
  assert.equal(
    await readFile(registryPath, 'utf8'),
    '{\n  "devices": [\n    {\n      "id": "dev_a"\n    }\n  ]\n}\n',
  );
  assert.deepEqual(await readdir(directory), ['registry.json']);
});

test('returns a clone of the fallback when the registry is absent', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-json-file-'));
  const registryPath = join(directory, 'registry.json');
  const fallback = { devices: [] };
  t.after(() => rm(directory, { recursive: true, force: true }));

  const result = await readJson(registryPath, fallback);

  assert.deepEqual(result, fallback);
  assert.notEqual(result, fallback);
});

test('creates state files and directories with owner-only permissions', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'agent-road-json-file-'));
  const directory = join(root, 'state');
  const registryPath = join(directory, 'registry.json');
  t.after(() => rm(root, { recursive: true, force: true }));

  await writeJsonAtomic(registryPath, { devices: [] });

  assert.equal((await stat(directory)).mode & 0o777, 0o700);
  assert.equal((await stat(registryPath)).mode & 0o777, 0o600);
});

test('replaces an existing registry without leaving a temporary file', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-json-file-'));
  const registryPath = join(directory, 'registry.json');
  t.after(() => rm(directory, { recursive: true, force: true }));

  await writeJsonAtomic(registryPath, { devices: [{ id: 'dev_a' }] });
  await writeJsonAtomic(registryPath, { devices: [{ id: 'dev_b' }] });

  assert.deepEqual(await readJson(registryPath, { devices: [] }), { devices: [{ id: 'dev_b' }] });
  assert.deepEqual(await readdir(directory), ['registry.json']);
});

test('creates the random temporary file exclusively without following links', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-json-file-'));
  const registryPath = join(directory, 'registry.json');
  let temporaryFlags;
  t.after(() => rm(directory, { recursive: true, force: true }));

  await writeJsonAtomic(registryPath, { devices: [] }, {
    openFile: async (path, flags, mode) => {
      temporaryFlags ??= flags;
      return open(path, flags, mode);
    },
  });

  assert.equal(temporaryFlags & constants.O_EXCL, constants.O_EXCL);
  assert.equal(temporaryFlags & constants.O_NOFOLLOW, constants.O_NOFOLLOW);
});

test('rejects unsupported top-level values before creating state files', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'agent-road-json-file-'));
  const registryPath = join(root, 'state', 'registry.json');
  t.after(() => rm(root, { recursive: true, force: true }));

  await assert.rejects(writeJsonAtomic(registryPath, undefined), TypeError);
  assert.deepEqual(await readdir(root), []);
});

test('propagates malformed JSON errors', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-json-file-'));
  const registryPath = join(directory, 'registry.json');
  t.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(registryPath, '{ malformed');

  await assert.rejects(readJson(registryPath, { devices: [] }), SyntaxError);
});

test('preserves a temporary-file write failure when close also fails', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-json-file-'));
  const registryPath = join(directory, 'registry.json');
  const writeError = new Error('write failed');
  const closeError = new Error('close failed');
  t.after(() => rm(directory, { recursive: true, force: true }));

  await assert.rejects(
    writeJsonAtomic(registryPath, { devices: [] }, {
      openFile: async () => ({
        writeFile: async () => { throw writeError; },
        close: async () => { throw closeError; },
      }),
    }),
    (error) => error === writeError,
  );
});

test('preserves a directory sync failure when directory close also fails', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-road-json-file-'));
  const registryPath = join(directory, 'registry.json');
  const syncError = new Error('directory sync failed');
  const closeError = new Error('directory close failed');
  let openCount = 0;
  t.after(() => rm(directory, { recursive: true, force: true }));

  await assert.rejects(
    writeJsonAtomic(registryPath, { devices: [] }, {
      openFile: async (path) => {
        openCount += 1;
        if (openCount === 1) {
          return {
            writeFile: (content) => writeFile(path, content, { mode: 0o600 }),
            sync: async () => {},
            close: async () => {},
          };
        }
        return {
          sync: async () => { throw syncError; },
          close: async () => { throw closeError; },
        };
      },
    }),
    (error) => error === syncError,
  );
});
