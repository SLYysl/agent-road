import { randomUUID } from 'node:crypto';
import { lstat, mkdir, open } from 'node:fs/promises';
import { join } from 'node:path';
import { statePaths } from '../core/paths.mjs';

const STAGES = new Set(['initialize', 'inspect', 'upload', 'cleanup', 'finalize']);
const failures = new WeakMap();
export function markProvisionFailure(error, stage) {
  if (error instanceof Error && STAGES.has(stage)) failures.set(error, stage);
  return error;
}
export function provisionFailureStage(error) { return failures.get(error) ?? null; }
export async function captureProvisionFailure(env, error) {
  const stage = provisionFailureStage(error);
  if (stage === null) return;
  const root = statePaths(env).root;
  const dir = join(root, 'provision-diagnostics');
  try { await mkdir(dir, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
  const stat = await lstat(dir);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077)) throw new Error('UNSAFE_DIAGNOSTIC_DIRECTORY');
  const file = await open(join(dir, `${randomUUID()}.json`), 'wx', 0o600);
  try {
    // No command, address, identifier, exception text, payload or credential.
    await file.writeFile(JSON.stringify({ schemaVersion: 1, stage, observedAt: new Date().toISOString() }) + '\n');
    await file.sync();
  } finally { await file.close(); }
  const parent = await open(dir, 'r'); try { await parent.sync(); } finally { await parent.close(); }
}
