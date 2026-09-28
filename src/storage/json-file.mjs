import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import { dirname } from 'node:path';

async function withFile(openFile, path, flags, mode, operation) {
  const file = await openFile(path, flags, mode);
  let primaryError;

  try {
    return await operation(file);
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    try {
      await file.close();
    } catch (error) {
      if (!primaryError) {
        throw error;
      }
    }
  }
}

export async function readJson(path, fallback) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') {
      return structuredClone(fallback);
    }
    throw error;
  }
}

export async function writeJsonAtomic(path, value, { openFile = open } = {}) {
  const serialized = JSON.stringify(value, null, 2);
  if (typeof serialized !== 'string') {
    throw new TypeError('State value must serialize to JSON');
  }

  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporaryPath = `${path}.${randomUUID()}.tmp`;
  let primaryError;

  try {
    await withFile(
      openFile,
      temporaryPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
      async (temporaryFile) => {
        await temporaryFile.writeFile(`${serialized}\n`);
        await temporaryFile.sync();
      },
    );

    await rename(temporaryPath, path);
    await withFile(
      openFile,
      dirname(path),
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      undefined,
      (directory) => directory.sync(),
    );
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    try {
      await rm(temporaryPath, { force: true });
    } catch (error) {
      if (!primaryError) {
        throw error;
      }
    }
  }
}
