import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readdir, readFile, stat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { captureProvisionFailure, markProvisionFailure, provisionFailureStage } from '../src/runtime/provision-diagnostic.mjs';

test('failure capture contains only finite stage and time, stored privately', async t => {
  const root = await mkdtemp(join(tmpdir(), 'ar-provision-diagnostic-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const error = new Error('secret private exception /machine/path');
  markProvisionFailure(error, 'upload');
  await captureProvisionFailure({ AGENT_ROAD_HOME: root }, error);
  const dir = join(root, 'provision-diagnostics');
  const files = await readdir(dir); assert.equal(files.length, 1);
  const file = join(dir, files[0]); const body = await readFile(file, 'utf8');
  assert.doesNotMatch(body, /secret|private|machine|path/u);
  const value = JSON.parse(body);
  assert.deepEqual(Object.keys(value).sort(), ['observedAt', 'schemaVersion', 'stage']);
  assert.equal(value.stage, 'upload');
  assert.equal((await stat(file)).mode & 0o077, 0);
  assert.equal((await stat(dir)).mode & 0o077, 0);
});
test('unrecognized stage cannot become a diagnostic or enumerable error field', () => {
  const error = markProvisionFailure(new Error('private'), 'arbitrary private data');
  assert.equal(provisionFailureStage(error), null);
  assert.deepEqual(Object.keys(error), []);
});
