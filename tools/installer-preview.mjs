#!/usr/bin/env node
import { open, constants } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { previewInstaller, simulateInstaller } from '../src/installer/preview.mjs';

let file;
try {
  const [path, expectedOrigin, ...extra] = process.argv.slice(2);
  if (!path || !isAbsolute(path) || extra.length) throw new Error('PREVIEW_USAGE');
  file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  const info = await file.stat();
  if (!info.isFile() || info.size > 4096) throw new Error('PREVIEW_INPUT_INVALID');
  const buffer = Buffer.alloc(4097);
  const { bytesRead } = await file.read(buffer, 0, buffer.length, 0);
  if (bytesRead > 4096) throw new Error('PREVIEW_INPUT_INVALID');
  const plan = previewInstaller(buffer.subarray(0, bytesRead).toString('utf8'), { expectedOrigin });
  process.stdout.write(JSON.stringify({ plan, simulation: simulateInstaller(plan) }, null, 2) + '\n');
} catch (error) {
  const allowed = ['PREVIEW_USAGE', 'PREVIEW_CONTEXT_INVALID', 'PREVIEW_INPUT_INVALID', 'PREVIEW_VERSION_UNSUPPORTED',
    'PREVIEW_ORIGIN_MISMATCH', 'PREVIEW_TIME_INVALID', 'PREVIEW_EXPIRED'];
  process.stderr.write((allowed.includes(error.message) ? error.message : 'PREVIEW_READ_FAILED') + '\n');
  process.exitCode = 2;
} finally { await file?.close(); }
