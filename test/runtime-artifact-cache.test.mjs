import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

import { acquireRuntimeArtifact } from '../src/runtime/artifact-cache.mjs';

const BYTES = Buffer.from('pinned runtime artifact');
const execFile = promisify(execFileCallback);
const CACHE_TEST_HOOK = Symbol.for('agent-road.artifact-cache.test-hook');
const LOCK_OWNER = '01234567-89ab-4cde-8fab-0123456789ab';
const ARTIFACT_CACHE_MODULE_URL = new URL('../src/runtime/artifact-cache.mjs', import.meta.url).href;
const ARTIFACT_CACHE_WORKER_SOURCE = String.raw`
import { access, appendFile, writeFile } from 'node:fs/promises';

const payload = JSON.parse(process.argv[1]);
const { acquireRuntimeArtifact } = await import(payload.moduleUrl);
const bytes = Buffer.from(payload.bytesBase64, 'base64');
if (payload.holdGate || payload.waitingPath) {
  globalThis[Symbol.for('agent-road.artifact-cache.test-hook')] = async (event) => {
    if (event === 'afterCacheRecoveryGateBusy' && payload.waitingPath) {
      try {
        await writeFile(payload.waitingPath, 'waiting', { flag: 'wx', mode: 0o600 });
      } catch (error) {
        if (error?.code !== 'EEXIST') throw error;
      }
      return;
    }
    if (event === 'afterCacheRecoveryGateAcquired' && payload.holdGate) {
      await writeFile(payload.readyPath, 'ready', { flag: 'wx', mode: 0o600 });
      while (true) {
        try {
          await access(payload.releasePath);
          break;
        } catch {
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
      }
    }
  };
}

try {
  const result = await acquireRuntimeArtifact({
    cacheRoot: payload.cacheRoot,
    artifact: {
      id: 'powershell-7',
      version: '7.5.2',
      url: 'https://example.com/releases/7.5.2/powershell.zip',
      redirectOrigins: [],
      bytes: bytes.length,
      sha256: payload.sha256,
    },
    policy: { timeoutMs: payload.timeoutMs, maxRedirects: 0 },
    dependencies: {
      fetch: async () => {
        await appendFile(payload.fetchLogPath, String(process.pid) + '\n', {
          flag: 'a',
          mode: 0o600,
        });
        return { response: new Response(bytes, { status: 200 }) };
      },
    },
  });
  process.stdout.write(JSON.stringify({ status: 'fulfilled', result }));
} catch (error) {
  process.stdout.write(JSON.stringify({
    status: 'rejected',
    code: error?.code,
    message: error?.message,
  }));
}
`;

function sha256(bytes = BYTES) {
  return createHash('sha256').update(bytes).digest('hex').toUpperCase();
}

function lockNames(owner = LOCK_OWNER) {
  return {
    artifactPartName: `.${sha256()}.${owner}.part`,
    lockPartName: `.${sha256()}.${owner}.lock.part`,
  };
}

function lockRecord(pid, overrides = {}) {
  const owner = overrides.owner ?? LOCK_OWNER;
  const names = lockNames(owner);
  return `${JSON.stringify({
    schemaVersion: 1,
    owner,
    pid,
    createdAt: '2026-07-29T10:00:00.000Z',
    artifactSha256: sha256(),
    artifactPartName: names.artifactPartName,
    lockPartName: names.lockPartName,
    ...overrides,
  })}\n`;
}

async function exitedChildPid() {
  const child = execFileCallback(process.execPath, ['-e', 'process.exit(0)']);
  const pid = child.pid;
  await new Promise((resolve, reject) => {
    child.once('exit', resolve);
    child.once('error', reject);
  });
  return pid;
}

function artifact(overrides = {}) {
  return {
    id: 'powershell-7',
    version: '7.5.2',
    url: 'https://example.com/releases/7.5.2/powershell.zip',
    redirectOrigins: [],
    bytes: BYTES.length,
    sha256: sha256(),
    ...overrides,
  };
}

async function fixture(t, overrides = {}) {
  const parent = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-artifact-cache-test-')));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const calls = [];
  const fetch = overrides.fetch ?? (async (url, options) => {
    calls.push({ url, options });
    return {
      response: new Response(BYTES, {
        status: 200,
        headers: { 'content-length': String(BYTES.length) },
      }),
    };
  });
  return {
    parent,
    cacheRoot: join(parent, 'cache'),
    calls,
    input: {
      cacheRoot: join(parent, 'cache'),
      artifact: artifact(overrides.artifact),
      policy: {
        timeoutMs: 1_000,
        maxRedirects: 3,
      },
      dependencies: { fetch },
    },
  };
}

async function rejectsCode(promise, code, forbidden = []) {
  let observed;
  try {
    await promise;
  } catch (error) {
    observed = error;
  }
  assert.ok(observed, `expected ${code}`);
  assert.equal(observed.code, code);
  assert.equal(observed.message, code);
  assert.equal(Object.hasOwn(observed, 'cause'), false);
  for (const value of forbidden) assert.equal(observed.message.includes(value), false);
}

async function prepareCache(f) {
  await mkdir(join(f.cacheRoot, 'objects'), { recursive: true, mode: 0o700 });
  await mkdir(join(f.cacheRoot, 'locks'), { mode: 0o700 });
  return join(f.cacheRoot, 'objects', `${sha256()}.bin`);
}

async function waitForPath(path, timeoutMs = 2_000) {
  const expiresAt = Date.now() + timeoutMs;
  while (Date.now() < expiresAt) {
    try {
      await lstat(path);
      return;
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail(`timed out waiting for ${path}`);
}

async function runArtifactCacheWorker(payload) {
  const { stdout, stderr } = await execFile(process.execPath, [
    '--input-type=module',
    '--eval',
    ARTIFACT_CACHE_WORKER_SOURCE,
    JSON.stringify({
      ...payload,
      moduleUrl: ARTIFACT_CACHE_MODULE_URL,
      bytesBase64: BYTES.toString('base64'),
      sha256: sha256(),
    }),
  ], {
    env: { ...process.env, NODE_TEST_CONTEXT: '1' },
    maxBuffer: 64 * 1024,
    timeout: 15_000,
  });
  assert.equal(stderr, '');
  return JSON.parse(stdout);
}

async function addExtendedAcl(t, path) {
  await execFile('/bin/chmod', ['+a', 'everyone allow read', path]);
  t.after(async () => {
    try {
      await execFile('/bin/chmod', ['-N', path]);
    } catch {}
  });
}

test('acquires one exact artifact into an owner-only cache and reuses the verified hit', async (t) => {
  const f = await fixture(t);
  const first = await acquireRuntimeArtifact(f.input);
  const second = await acquireRuntimeArtifact(f.input);

  assert.deepEqual(first, {
    artifactId: 'powershell-7',
    version: '7.5.2',
    path: join(f.cacheRoot, 'objects', `${sha256()}.bin`),
    bytes: BYTES.length,
    sha256: sha256(),
  });
  assert.deepEqual(second, first);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].url, artifact().url);
  assert.equal(f.calls[0].options.redirect, 'manual');
  assert.equal(f.calls[0].options.signal instanceof AbortSignal, true);
  assert.deepEqual(await readFile(first.path), BYTES);

  for (const path of [f.cacheRoot, join(f.cacheRoot, 'objects'), join(f.cacheRoot, 'locks')]) {
    const stats = await lstat(path);
    assert.equal(stats.isDirectory(), true);
    assert.equal(stats.isSymbolicLink(), false);
    assert.equal(stats.mode & 0o777, 0o700);
    if (typeof process.getuid === 'function') assert.equal(stats.uid, process.getuid());
  }
  const fileStats = await lstat(first.path);
  assert.equal(fileStats.isFile(), true);
  assert.equal(fileStats.isSymbolicLink(), false);
  assert.equal(fileStats.nlink, 1);
  assert.equal(fileStats.mode & 0o777, 0o600);
  assert.deepEqual(
    (await readdir(join(f.cacheRoot, 'objects'))).sort(),
    [`${sha256()}.bin`],
  );
});

test('rejects non-exact hostile input without invoking getters, proxies or fetch', async (t) => {
  const f = await fixture(t);
  let getterReads = 0;
  let proxyTraps = 0;
  let fetchCalls = 0;
  const fetch = async () => {
    fetchCalls += 1;
    return { response: new Response(BYTES) };
  };

  const getterInput = { ...f.input };
  Object.defineProperty(getterInput, 'artifact', {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error('private getter value');
    },
  });
  const proxyInput = new Proxy(f.input, {
    ownKeys() {
      proxyTraps += 1;
      throw new Error('private proxy value');
    },
  });
  const missingRedirectOrigins = { ...f.input.artifact };
  delete missingRedirectOrigins.redirectOrigins;
  const invalid = [
    null,
    { ...f.input, extra: true },
    getterInput,
    proxyInput,
    { ...f.input, cacheRoot: 'relative/cache' },
    { ...f.input, artifact: missingRedirectOrigins },
    { ...f.input, artifact: { ...f.input.artifact, extra: true } },
    { ...f.input, artifact: { ...f.input.artifact, id: '../escape' } },
    { ...f.input, artifact: { ...f.input.artifact, version: 'latest' } },
    { ...f.input, artifact: { ...f.input.artifact, version: `${'1'.repeat(65)}.2.3` } },
    { ...f.input, artifact: { ...f.input.artifact, url: 'http://example.com/7.5.2/x.zip' } },
    { ...f.input, artifact: { ...f.input.artifact, redirectOrigins: ['https://example.com'] } },
    { ...f.input, artifact: { ...f.input.artifact, redirectOrigins: ['http://cdn.example'] } },
    { ...f.input, artifact: { ...f.input.artifact, redirectOrigins: ['https://cdn.example/'] } },
    { ...f.input, artifact: { ...f.input.artifact, redirectOrigins: ['https://cdn.example:444'] } },
    { ...f.input, artifact: { ...f.input.artifact, redirectOrigins: [
      'https://cdn.example',
      'https://cdn.example',
    ] } },
    { ...f.input, artifact: { ...f.input.artifact, redirectOrigins: Array.from(
      { length: 5 },
      (_, index) => `https://cdn-${index}.example`,
    ) } },
    { ...f.input, artifact: { ...f.input.artifact, bytes: 0 } },
    { ...f.input, artifact: { ...f.input.artifact, bytes: 256 * 1024 ** 2 + 1 } },
    { ...f.input, artifact: { ...f.input.artifact, sha256: sha256().toLowerCase() } },
    { ...f.input, policy: { ...f.input.policy, timeoutMs: 0 } },
    { ...f.input, policy: { ...f.input.policy, maxRedirects: 6 } },
    { ...f.input, dependencies: { fetch, extra: true } },
    { ...f.input, dependencies: { fetch: 'not-a-function' } },
    { ...f.input, dependencies: { fetch: new Proxy(fetch, {}) } },
  ];

  for (const input of invalid) {
    await rejectsCode(
      acquireRuntimeArtifact(input),
      'RUNTIME_INPUT_INVALID',
      ['private getter value', 'private proxy value'],
    );
  }
  assert.equal(getterReads, 0);
  assert.equal(proxyTraps, 0);
  assert.equal(fetchCalls, 0);
});

test('rejects hostile redirect-origin arrays without invoking accessors or proxy traps', async (t) => {
  const f = await fixture(t);
  let getterReads = 0;
  const getterOrigins = ['https://cdn.example'];
  Object.defineProperty(getterOrigins, 0, {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error('private redirect getter');
    },
  });
  await rejectsCode(acquireRuntimeArtifact({
    ...f.input,
    artifact: { ...f.input.artifact, redirectOrigins: getterOrigins },
  }), 'RUNTIME_INPUT_INVALID', ['private redirect getter']);
  assert.equal(getterReads, 0);

  let proxyTraps = 0;
  const proxyOrigins = new Proxy(['https://cdn.example'], {
    ownKeys() {
      proxyTraps += 1;
      throw new Error('private redirect proxy');
    },
  });
  await rejectsCode(acquireRuntimeArtifact({
    ...f.input,
    artifact: { ...f.input.artifact, redirectOrigins: proxyOrigins },
  }), 'RUNTIME_INPUT_INVALID', ['private redirect proxy']);
  assert.equal(proxyTraps, 0);
  assert.equal(f.calls.length, 0);
});

test('accepts acquisition deadlines through thirty minutes and rejects larger values', async (t) => {
  const accepted = await fixture(t);
  accepted.input.policy.timeoutMs = 30 * 60 * 1_000;
  await acquireRuntimeArtifact(accepted.input);
  assert.equal(accepted.calls.length, 1);

  const rejected = await fixture(t);
  rejected.input.policy.timeoutMs = 30 * 60 * 1_000 + 1;
  await rejectsCode(acquireRuntimeArtifact(rejected.input), 'RUNTIME_INPUT_INVALID');
  assert.equal(rejected.calls.length, 0);
});

test('fails closed on cache roots or internal directories that are not owner-only real directories', async (t) => {
  const cases = [];

  {
    const f = await fixture(t);
    await mkdir(f.cacheRoot, { mode: 0o755 });
    await chmod(f.cacheRoot, 0o755);
    cases.push(f);
  }
  {
    const f = await fixture(t);
    const target = join(f.parent, 'target');
    await mkdir(target, { mode: 0o700 });
    await symlink(target, f.cacheRoot);
    cases.push(f);
  }
  {
    const f = await fixture(t);
    await mkdir(f.cacheRoot, { mode: 0o700 });
    await symlink(f.parent, join(f.cacheRoot, 'objects'));
    cases.push(f);
  }
  {
    const f = await fixture(t);
    await writeFile(f.cacheRoot, 'not a directory', { mode: 0o600 });
    cases.push(f);
  }
  {
    const f = await fixture(t);
    const target = join(f.parent, 'parent-target');
    const alias = join(f.parent, 'parent-alias');
    await mkdir(target, { mode: 0o700 });
    await symlink(target, alias);
    f.input.cacheRoot = join(alias, 'cache');
    cases.push(f);
  }

  for (const f of cases) {
    await rejectsCode(
      acquireRuntimeArtifact(f.input),
      'RUNTIME_CACHE_UNSAFE',
      [f.parent, 'EEXIST', 'EACCES'],
    );
    assert.equal(f.calls.length, 0);
  }
});

test('rejects Darwin extended ACLs on cache roots, internal directories, files, locks and parts', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  const cases = [];

  {
    const f = await fixture(t);
    await addExtendedAcl(t, f.parent);
    cases.push({ f, path: f.parent });
  }
  {
    const f = await fixture(t);
    await mkdir(f.cacheRoot, { mode: 0o700 });
    await addExtendedAcl(t, f.cacheRoot);
    cases.push({ f, path: f.cacheRoot });
  }
  {
    const f = await fixture(t);
    await prepareCache(f);
    const path = join(f.cacheRoot, 'objects');
    await addExtendedAcl(t, path);
    cases.push({ f, path });
  }
  {
    const f = await fixture(t);
    await prepareCache(f);
    const deadPid = await exitedChildPid();
    const names = lockNames();
    const path = join(f.cacheRoot, 'locks', names.lockPartName);
    await writeFile(path, lockRecord(deadPid), { mode: 0o600 });
    await addExtendedAcl(t, path);
    cases.push({ f, path });
  }
  {
    const f = await fixture(t);
    const path = await prepareCache(f);
    await writeFile(path, BYTES, { mode: 0o600 });
    await addExtendedAcl(t, path);
    cases.push({ f, path });
  }
  {
    const f = await fixture(t);
    await prepareCache(f);
    const path = join(f.cacheRoot, 'locks', `${sha256()}.lock`);
    await writeFile(path, lockRecord(process.pid), { mode: 0o600 });
    await addExtendedAcl(t, path);
    cases.push({ f, path });
  }
  {
    const f = await fixture(t);
    await prepareCache(f);
    const deadPid = await exitedChildPid();
    const names = lockNames();
    const lockPath = join(f.cacheRoot, 'locks', `${sha256()}.lock`);
    const path = join(f.cacheRoot, 'objects', names.artifactPartName);
    await writeFile(lockPath, lockRecord(deadPid), { mode: 0o600 });
    await writeFile(path, BYTES.subarray(0, 5), { mode: 0o600 });
    await addExtendedAcl(t, path);
    cases.push({ f, path });
  }

  for (const { f, path } of cases) {
    await rejectsCode(acquireRuntimeArtifact(f.input), 'RUNTIME_CACHE_UNSAFE');
    assert.equal(f.calls.length, 0);
    assert.equal((await lstat(path)).isSymbolicLink(), false);
  }
});

test('rejects a Darwin directory ACL introduced after the ACL probe', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  const f = await fixture(t);
  let hookCalls = 0;
  globalThis[CACHE_TEST_HOOK] = async (event, context) => {
    if (
      event !== 'afterDirectoryAclCheck'
      || hookCalls !== 0
      || !context.paths.includes(join(f.cacheRoot, 'objects'))
    ) return;
    hookCalls += 1;
    await addExtendedAcl(t, join(f.cacheRoot, 'objects'));
  };
  t.after(() => { delete globalThis[CACHE_TEST_HOOK]; });

  await rejectsCode(acquireRuntimeArtifact(f.input), 'RUNTIME_CACHE_UNSAFE');
  assert.equal(hookCalls, 1);
  assert.equal(f.calls.length, 0);
});

test('rejects a cache parent replaced after initial directory validation', async (t) => {
  const f = await fixture(t);
  const movedParent = `${f.parent}-moved`;
  let swapped = false;
  t.after(() => rm(movedParent, { recursive: true, force: true }));
  globalThis[CACHE_TEST_HOOK] = async (event, context) => {
    if (
      event !== 'afterDirectoryAclCheck'
      || swapped
      || !context.paths.includes(f.cacheRoot)
    ) return;
    swapped = true;
    await rename(f.parent, movedParent);
    await symlink(movedParent, f.parent);
  };
  t.after(() => { delete globalThis[CACHE_TEST_HOOK]; });

  await rejectsCode(acquireRuntimeArtifact(f.input), 'RUNTIME_CACHE_UNSAFE');
  assert.equal(swapped, true);
});

test('rechecks the pinned parent before publishing a verified temporary artifact', async (t) => {
  const f = await fixture(t);
  const movedParent = `${f.parent}-moved-before-publish`;
  const publishedPath = join(
    movedParent,
    'cache',
    'objects',
    `${sha256()}.bin`,
  );
  let swapped = false;
  t.after(() => rm(movedParent, { recursive: true, force: true }));
  globalThis[CACHE_TEST_HOOK] = async (event, context) => {
    if (
      event !== 'afterCacheFirstRead'
      || swapped
      || !context.path.endsWith('.part')
    ) return;
    swapped = true;
    await rename(f.parent, movedParent);
    await symlink(movedParent, f.parent);
  };
  t.after(() => { delete globalThis[CACHE_TEST_HOOK]; });

  await rejectsCode(acquireRuntimeArtifact(f.input), 'RUNTIME_CACHE_CLEANUP_FAILED');
  assert.equal(swapped, true);
  await assert.rejects(lstat(publishedPath), { code: 'ENOENT' });
  const residue = await readdir(join(movedParent, 'cache', 'objects'));
  assert.equal(residue.length, 1);
  assert.equal(residue[0].endsWith('.part'), true);
});

test('repairs only a stable owner-only regular cache poison', async (t) => {
  const f = await fixture(t);
  const cachePath = await prepareCache(f);
  await writeFile(cachePath, Buffer.alloc(BYTES.length, 0x58), { mode: 0o600 });

  const result = await acquireRuntimeArtifact(f.input);

  assert.equal(result.path, cachePath);
  assert.equal(f.calls.length, 1);
  assert.deepEqual(await readFile(cachePath), BYTES);
  const stats = await lstat(cachePath);
  assert.equal(stats.nlink, 1);
  assert.equal(stats.mode & 0o777, 0o600);
});

test('rejects symlink, hardlink, FIFO and permissive cache entries without fetching or unlinking them', async (t) => {
  const cases = [];

  {
    const f = await fixture(t);
    const cachePath = await prepareCache(f);
    const target = join(f.parent, 'symlink-target');
    await writeFile(target, BYTES, { mode: 0o600 });
    await symlink(target, cachePath);
    cases.push({ f, cachePath, kind: 'symlink' });
  }
  {
    const f = await fixture(t);
    const cachePath = await prepareCache(f);
    const target = join(f.parent, 'hardlink-target');
    await writeFile(target, BYTES, { mode: 0o600 });
    await link(target, cachePath);
    cases.push({ f, cachePath, kind: 'hardlink' });
  }
  {
    const f = await fixture(t);
    const cachePath = await prepareCache(f);
    await execFile('mkfifo', [cachePath]);
    cases.push({ f, cachePath, kind: 'fifo' });
  }
  {
    const f = await fixture(t);
    const cachePath = await prepareCache(f);
    await writeFile(cachePath, BYTES, { mode: 0o644 });
    await chmod(cachePath, 0o644);
    cases.push({ f, cachePath, kind: 'permissive' });
  }

  for (const { f, cachePath, kind } of cases) {
    await rejectsCode(acquireRuntimeArtifact(f.input), 'RUNTIME_CACHE_UNSAFE', [kind, f.parent]);
    assert.equal(f.calls.length, 0);
    const stats = await lstat(cachePath);
    if (kind === 'symlink') assert.equal(stats.isSymbolicLink(), true);
    if (kind === 'hardlink') assert.equal(stats.nlink, 2);
    if (kind === 'fifo') assert.equal(stats.isFIFO(), true);
    if (kind === 'permissive') assert.equal(stats.mode & 0o777, 0o644);
  }
});

test('rejects a cache file that changes between stable verification reads', async (t) => {
  const f = await fixture(t);
  const cachePath = await prepareCache(f);
  await writeFile(cachePath, BYTES, { mode: 0o600 });
  let hookCalls = 0;
  globalThis[CACHE_TEST_HOOK] = async (event, context) => {
    if (event === 'afterCacheFirstRead' && context.path === cachePath) {
      hookCalls += 1;
      await writeFile(cachePath, Buffer.alloc(BYTES.length, 0x59));
    }
  };
  t.after(() => { delete globalThis[CACHE_TEST_HOOK]; });

  await rejectsCode(acquireRuntimeArtifact(f.input), 'RUNTIME_CACHE_UNSAFE');
  assert.equal(hookCalls, 1);
  assert.equal(f.calls.length, 0);
});

test('follows bounded HTTPS manual redirects only through listed origins', async (t) => {
  const calls = [];
  const f = await fixture(t, {
    artifact: {
      version: '7.6.4',
      url: 'https://github.com/PowerShell/PowerShell/releases/download/v7.6.4/PowerShell-7.6.4-win-x64.zip',
      redirectOrigins: ['https://release-assets.githubusercontent.com'],
    },
    fetch: async (url, options) => {
      calls.push({ url, options });
      if (calls.length === 1) {
        return {
          response: new Response(null, {
            status: 302,
            headers: {
              location: 'https://release-assets.githubusercontent.com/PowerShell-7.6.4-win-x64.zip?sig=temporary',
            },
          }),
        };
      }
      return {
        response: new Response(BYTES, {
          status: 200,
          headers: { 'content-length': String(BYTES.length) },
        }),
      };
    },
  });

  await acquireRuntimeArtifact(f.input);

  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, f.input.artifact.url);
  assert.equal(
    calls[1].url,
    'https://release-assets.githubusercontent.com/PowerShell-7.6.4-win-x64.zip?sig=temporary',
  );
  assert.equal(calls.every(({ options }) => options.redirect === 'manual'), true);
  assert.equal(calls[0].options.signal, calls[1].options.signal);
});

test('does not start another redirect fetch after cancellation crosses the deadline', async (t) => {
  let fetchCalls = 0;
  const f = await fixture(t, {
    fetch: async () => {
      fetchCalls += 1;
      if (fetchCalls !== 1) {
        return { response: new Response(BYTES, { status: 200 }) };
      }
      const body = new ReadableStream({
        pull() {},
        cancel() {
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 600);
        },
      });
      return {
        response: new Response(body, {
          status: 302,
          headers: { location: '/releases/7.5.2/redirected.zip' },
        }),
      };
    },
  });
  f.input.policy.timeoutMs = 500;

  await rejectsCode(acquireRuntimeArtifact(f.input), 'RUNTIME_ARTIFACT_TIMEOUT');
  assert.equal(fetchCalls, 1);
});

test('rejects invalid, looping and over-limit redirects without exposing their locations', async (t) => {
  const cases = [
    { location: 'http://private.example/secret', maxRedirects: 3 },
    { location: 'https://user:password@example.com/secret', maxRedirects: 3 },
    { location: 'https://example.com/secret#fragment', maxRedirects: 3 },
    { location: artifact().url, maxRedirects: 3 },
    { location: '/next', maxRedirects: 0 },
    { location: null, maxRedirects: 3 },
  ];

  for (const { location, maxRedirects } of cases) {
    const f = await fixture(t, {
      fetch: async () => ({
        response: new Response(null, {
          status: 302,
          headers: location === null ? {} : { location },
        }),
      }),
    });
    f.input.policy.maxRedirects = maxRedirects;
    await rejectsCode(
      acquireRuntimeArtifact(f.input),
      'RUNTIME_ARTIFACT_REDIRECT_INVALID',
      ['private.example', 'password', 'secret'],
    );
    assert.deepEqual(await readdir(join(f.cacheRoot, 'objects')), []);
  }
});

test('rejects cross-origin redirects before contacting the redirected origin', async (t) => {
  let calls = 0;
  const f = await fixture(t, {
    fetch: async () => {
      calls += 1;
      return {
        response: new Response(null, {
          status: 302,
          headers: { location: 'https://private.example/assets/powershell.zip' },
        }),
      };
    },
  });

  await rejectsCode(
    acquireRuntimeArtifact(f.input),
    'RUNTIME_ARTIFACT_REDIRECT_INVALID',
    ['private.example'],
  );
  assert.equal(calls, 1);
});

test('rejects an unlisted second-hop origin before contacting it', async (t) => {
  const calls = [];
  const f = await fixture(t, {
    artifact: { redirectOrigins: ['https://listed.example'] },
    fetch: async (url) => {
      calls.push(url);
      return {
        response: new Response(null, {
          status: 302,
          headers: {
            location: calls.length === 1
              ? 'https://listed.example/first-hop'
              : 'https://unlisted.example/second-hop',
          },
        }),
      };
    },
  });

  await rejectsCode(
    acquireRuntimeArtifact(f.input),
    'RUNTIME_ARTIFACT_REDIRECT_INVALID',
    ['unlisted.example'],
  );
  assert.deepEqual(calls, [
    artifact().url,
    'https://listed.example/first-hop',
  ]);
});

test('rejects hostile fetch responses without invoking attacker getters or proxy traps', async (t) => {
  let getterReads = 0;
  let proxyTraps = 0;
  const getterResponse = new Response(BYTES, { status: 200 });
  Object.defineProperty(getterResponse, 'status', {
    get() {
      getterReads += 1;
      throw new Error('private response getter');
    },
  });
  const bodyGetterResponse = new Response(BYTES, { status: 200 });
  Object.defineProperty(bodyGetterResponse, 'body', {
    get() {
      getterReads += 1;
      throw new Error('private body getter');
    },
  });
  const proxyResponse = new Proxy(new Response(BYTES, { status: 200 }), {
    get() {
      proxyTraps += 1;
      throw new Error('private response proxy');
    },
  });
  const proxyChunk = new Proxy(new Uint8Array(BYTES), {
    get() {
      proxyTraps += 1;
      throw new Error('private chunk proxy');
    },
    getPrototypeOf() {
      proxyTraps += 1;
      throw new Error('private chunk proxy');
    },
  });
  const proxyChunkResponse = new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(proxyChunk);
      controller.close();
    },
  }), { status: 200 });

  for (const response of [
    getterResponse,
    bodyGetterResponse,
    proxyResponse,
    proxyChunkResponse,
  ]) {
    const f = await fixture(t, { fetch: async () => ({ response }) });
    await rejectsCode(
      acquireRuntimeArtifact(f.input),
      'RUNTIME_ARTIFACT_ACQUISITION_FAILED',
      [
        'private response getter',
        'private body getter',
        'private response proxy',
        'private chunk proxy',
      ],
    );
  }
  assert.equal(getterReads, 0);
  assert.equal(proxyTraps, 0);
});

test('enforces timeout, status, exact content length, byte ceiling and hash with redacted errors', async (t) => {
  {
    let fetchStarted;
    const started = new Promise((resolve) => { fetchStarted = resolve; });
    const f = await fixture(t, {
      fetch: async (_url, { signal }) => {
        fetchStarted();
        return new Promise((resolve, reject) => {
          signal.addEventListener('abort', () => reject(new Error('private timeout detail')), {
            once: true,
          });
        });
      },
    });
    f.input.policy.timeoutMs = 1_000;
    const acquisition = acquireRuntimeArtifact(f.input);
    const reachedFetch = await Promise.race([
      started.then(() => true),
      acquisition.then(() => false, () => false),
    ]);
    assert.equal(reachedFetch, true);
    await rejectsCode(
      acquisition,
      'RUNTIME_ARTIFACT_TIMEOUT',
      ['private timeout detail'],
    );
  }

  const cases = [
    {
      code: 'RUNTIME_ARTIFACT_ACQUISITION_FAILED',
      fetch: async () => { throw new Error('private fetch failure'); },
    },
    {
      code: 'RUNTIME_ARTIFACT_ACQUISITION_FAILED',
      fetch: async () => {
        throw Object.assign(new Error('private forged runtime error'), {
          code: 'RUNTIME_CACHE_UNSAFE',
        });
      },
    },
    {
      code: 'RUNTIME_ARTIFACT_ACQUISITION_FAILED',
      fetch: async () => ({ response: new Response('private response', { status: 404 }) }),
    },
    {
      code: 'RUNTIME_ARTIFACT_INTEGRITY_FAILED',
      fetch: async () => ({
        response: new Response(BYTES, {
          status: 200,
          headers: { 'content-length': String(BYTES.length + 1) },
        }),
      }),
    },
    {
      code: 'RUNTIME_ARTIFACT_INTEGRITY_FAILED',
      fetch: async () => ({
        response: new Response(Buffer.concat([BYTES, Buffer.from('x')]), { status: 200 }),
      }),
    },
    {
      code: 'RUNTIME_ARTIFACT_INTEGRITY_FAILED',
      fetch: async () => ({
        response: new Response(Buffer.alloc(BYTES.length, 0x58), { status: 200 }),
      }),
    },
  ];

  for (const entry of cases) {
    const f = await fixture(t, { fetch: entry.fetch });
    await rejectsCode(
      acquireRuntimeArtifact(f.input),
      entry.code,
      ['private fetch failure', 'private forged runtime error', 'private response'],
    );
    assert.deepEqual(await readdir(join(f.cacheRoot, 'objects')), []);
  }
});

test('bounds reader cancellation by the same acquisition deadline', async (t) => {
  let cancelCalls = 0;
  let cancelStarted;
  const cancelStart = new Promise((resolve) => { cancelStarted = resolve; });
  let releaseCancel;
  const cancelGate = new Promise((resolve) => { releaseCancel = resolve; });
  const stream = new ReadableStream({
    pull() {
      return new Promise(() => {});
    },
    cancel() {
      cancelCalls += 1;
      cancelStarted();
      return cancelGate;
    },
  });
  const f = await fixture(t, {
    fetch: async () => ({ response: new Response(stream, { status: 200 }) }),
  });
  f.input.policy.timeoutMs = 1_000;

  const observed = acquireRuntimeArtifact(f.input).then(
    (value) => ({ value }),
    (error) => ({ error }),
  );
  const outcome = await Promise.race([
    observed,
    new Promise((resolve) => setTimeout(() => resolve('hung'), 1_500)),
  ]);
  if (outcome === 'hung') {
    releaseCancel();
    await observed;
  }

  assert.notEqual(outcome, 'hung');
  assert.equal(outcome.error?.code, 'RUNTIME_ARTIFACT_TIMEOUT');
  await cancelStart;
  assert.equal(cancelCalls, 1);
  releaseCancel();
});

test('never publishes success after the acquisition deadline expires during verification', async (t) => {
  const f = await fixture(t);
  f.input.policy.timeoutMs = 1_000;
  globalThis[CACHE_TEST_HOOK] = async (event, context) => {
    if (event === 'afterCacheFirstRead' && context.path.endsWith('.part')) {
      await new Promise((resolve) => setTimeout(resolve, 1_200));
    }
  };
  t.after(() => { delete globalThis[CACHE_TEST_HOOK]; });

  await rejectsCode(acquireRuntimeArtifact(f.input), 'RUNTIME_ARTIFACT_TIMEOUT');
  assert.equal(
    (await readdir(join(f.cacheRoot, 'objects'))).includes(`${sha256()}.bin`),
    false,
  );
});

test('uses the same absolute deadline while verifying a cache hit', async (t) => {
  const f = await fixture(t);
  const cachePath = await prepareCache(f);
  await writeFile(cachePath, BYTES, { mode: 0o600 });
  f.input.policy.timeoutMs = 1_000;
  globalThis[CACHE_TEST_HOOK] = async (event, context) => {
    if (event === 'afterCacheFirstRead' && context.path === cachePath) {
      await new Promise((resolve) => setTimeout(resolve, 1_200));
    }
  };
  t.after(() => { delete globalThis[CACHE_TEST_HOOK]; });

  await rejectsCode(acquireRuntimeArtifact(f.input), 'RUNTIME_ARTIFACT_TIMEOUT');
  assert.equal(f.calls.length, 0);
});

test('cancels a response body when validation fails before a reader is acquired', async (t) => {
  let cancelCalls = 0;
  const body = new ReadableStream({
    pull() {},
    cancel() {
      cancelCalls += 1;
    },
  });
  const f = await fixture(t, {
    fetch: async () => ({
      response: new Response(body, {
        status: 200,
        headers: { 'content-length': String(BYTES.length + 1) },
      }),
    }),
  });

  await rejectsCode(
    acquireRuntimeArtifact(f.input),
    'RUNTIME_ARTIFACT_INTEGRITY_FAILED',
  );
  assert.equal(cancelCalls, 1);
});

test('cancels authentic response bodies when envelope or Response structure validation fails', async (t) => {
  for (const failure of ['envelope', 'response-structure']) {
    let cancelCalls = 0;
    const body = new ReadableStream({
      pull() {},
      cancel() {
        cancelCalls += 1;
      },
    });
    const response = new Response(body, { status: 200 });
    if (failure === 'response-structure') {
      Object.defineProperty(response, 'unexpected', {
        enumerable: true,
        value: 'private response detail',
      });
    }
    const f = await fixture(t, {
      fetch: async () => failure === 'envelope'
        ? { response, unexpected: 'private envelope detail' }
        : { response },
    });

    await rejectsCode(
      acquireRuntimeArtifact(f.input),
      'RUNTIME_ARTIFACT_ACQUISITION_FAILED',
      ['private envelope detail', 'private response detail'],
    );
    assert.equal(cancelCalls, 1);
  }
});

test('cancels a late authentic response without waiting for cancellation completion', async (t) => {
  let resolveFetch;
  let fetchStarted;
  const fetchStart = new Promise((resolve) => { fetchStarted = resolve; });
  let cancelCalls = 0;
  const f = await fixture(t, {
    fetch: async () => {
      fetchStarted();
      return new Promise((resolve) => { resolveFetch = resolve; });
    },
  });
  f.input.policy.timeoutMs = 1_000;

  const acquisition = acquireRuntimeArtifact(f.input);
  const reachedFetch = await Promise.race([
    fetchStart.then(() => true),
    acquisition.then(() => false, () => false),
  ]);
  assert.equal(reachedFetch, true);
  await rejectsCode(acquisition, 'RUNTIME_ARTIFACT_TIMEOUT');

  const body = new ReadableStream({
    pull() {},
    cancel() {
      cancelCalls += 1;
      return new Promise(() => {});
    },
  });
  resolveFetch({ response: new Response(body, { status: 200 }) });
  for (let attempt = 0; attempt < 20 && cancelCalls === 0; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.equal(cancelCalls, 1);
});

test('rejects hostile Uint8Array accessors and prototypes without invoking them', async (t) => {
  let getterReads = 0;
  const ownAccessor = new Uint8Array(BYTES);
  Object.defineProperty(ownAccessor, 'byteLength', {
    configurable: true,
    get() {
      getterReads += 1;
      throw new Error('private typed array getter');
    },
  });
  const inheritedAccessor = new Uint8Array(BYTES);
  Object.setPrototypeOf(inheritedAccessor, Object.create(Uint8Array.prototype, {
    byteLength: {
      configurable: true,
      get() {
        getterReads += 1;
        throw new Error('private typed array prototype getter');
      },
    },
  }));

  for (const value of [ownAccessor, inheritedAccessor]) {
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(value);
        controller.close();
      },
    });
    const f = await fixture(t, {
      fetch: async () => ({ response: new Response(stream, { status: 200 }) }),
    });
    await rejectsCode(
      acquireRuntimeArtifact(f.input),
      'RUNTIME_ARTIFACT_ACQUISITION_FAILED',
      ['private typed array getter', 'private typed array prototype getter'],
    );
  }
  assert.equal(getterReads, 0);
});

test('rejects an oversized response chunk before copying or extending the deadline', async (t) => {
  const bytes = new Uint8Array(1024 * 1024 + 1);
  const f = await fixture(t, {
    artifact: {
      bytes: bytes.byteLength,
      sha256: sha256(bytes),
    },
    fetch: async () => ({
      response: new Response(new ReadableStream({
        start(controller) {
          controller.enqueue(bytes);
          controller.close();
        },
      }), { status: 200 }),
    }),
  });

  await rejectsCode(
    acquireRuntimeArtifact(f.input),
    'RUNTIME_ARTIFACT_ACQUISITION_FAILED',
  );
});

test('reconciles only an exact verified hardlink publication orphan pair', async (t) => {
  {
    const f = await fixture(t);
    const cachePath = await prepareCache(f);
    const deadPid = await exitedChildPid();
    const names = lockNames();
    const orphan = join(f.cacheRoot, 'objects', names.artifactPartName);
    const lockPath = join(f.cacheRoot, 'locks', `${sha256()}.lock`);
    await writeFile(orphan, BYTES, { mode: 0o600 });
    await link(orphan, cachePath);
    await writeFile(lockPath, lockRecord(deadPid), { mode: 0o600 });

    const result = await acquireRuntimeArtifact(f.input);

    assert.equal(result.path, cachePath);
    assert.equal(f.calls.length, 0);
    assert.deepEqual(await readdir(join(f.cacheRoot, 'objects')), [`${sha256()}.bin`]);
    assert.equal((await lstat(cachePath)).nlink, 1);
    assert.deepEqual(await readFile(cachePath), BYTES);
  }

  {
    const f = await fixture(t);
    const cachePath = await prepareCache(f);
    const deadPid = await exitedChildPid();
    const names = lockNames();
    const first = join(f.cacheRoot, 'objects', names.artifactPartName);
    const second = join(
      f.cacheRoot,
      'objects',
      `.${sha256()}.fedcba98-7654-4cba-8fed-ba9876543210.part`,
    );
    const lockPath = join(f.cacheRoot, 'locks', `${sha256()}.lock`);
    await writeFile(first, BYTES, { mode: 0o600 });
    await link(first, cachePath);
    await link(first, second);
    await writeFile(lockPath, lockRecord(deadPid), { mode: 0o600 });

    await rejectsCode(acquireRuntimeArtifact(f.input), 'RUNTIME_CACHE_UNSAFE');
    assert.equal(f.calls.length, 0);
    assert.deepEqual(
      (await readdir(join(f.cacheRoot, 'objects'))).sort(),
      [first, second, cachePath].map((path) => path.split('/').at(-1)).sort(),
    );
  }
});

test('revalidates final published metadata and content before reporting success', async (t) => {
  for (const mutation of ['content', 'mode']) {
    const f = await fixture(t);
    globalThis[CACHE_TEST_HOOK] = async (event, context) => {
      if (event !== 'afterPublishBeforeFinalVerification') return;
      if (mutation === 'content') {
        await writeFile(context.path, Buffer.alloc(BYTES.length, 0x5A));
      } else {
        await chmod(context.path, 0o644);
      }
    };
    try {
      await rejectsCode(acquireRuntimeArtifact(f.input), 'RUNTIME_CACHE_UNSAFE');
      assert.equal(f.calls.length, 1);
    } finally {
      delete globalThis[CACHE_TEST_HOOK];
    }
  }
});

test('publishes a complete cache lock atomically without exposing a partial final lock', async (t) => {
  const f = await fixture(t);
  let releaseHook;
  const hookGate = new Promise((resolve) => { releaseHook = resolve; });
  let enterHook;
  const hookEntered = new Promise((resolve) => { enterHook = resolve; });
  globalThis[CACHE_TEST_HOOK] = async (event, context) => {
    if (event !== 'afterLockTemporarySyncBeforePublish') return;
    enterHook(context);
    await hookGate;
  };
  t.after(() => { delete globalThis[CACHE_TEST_HOOK]; });

  const acquisition = acquireRuntimeArtifact(f.input);
  const context = await Promise.race([
    hookEntered,
    new Promise((resolve) => setTimeout(() => resolve('hook-missing'), 200)),
  ]);
  if (context === 'hook-missing') {
    await acquisition;
    assert.fail('atomic lock publication hook was not reached');
  }

  await assert.rejects(lstat(context.lockPath), { code: 'ENOENT' });
  const temporary = await lstat(context.lockPartPath);
  assert.equal(temporary.isFile(), true);
  assert.equal(temporary.nlink, 1);
  assert.equal(temporary.mode & 0o777, 0o600);
  assert.ok(temporary.size > 0);
  const content = await readFile(context.lockPartPath, 'utf8');
  const record = JSON.parse(content);
  assert.deepEqual(Object.keys(record), [
    'schemaVersion',
    'owner',
    'pid',
    'createdAt',
    'artifactSha256',
    'artifactPartName',
    'lockPartName',
  ]);
  assert.equal(content, `${JSON.stringify(record)}\n`);
  assert.equal(record.artifactSha256, sha256());
  assert.equal(record.artifactPartName, `.${sha256()}.${record.owner}.part`);
  assert.equal(record.lockPartName, `.${sha256()}.${record.owner}.lock.part`);
  releaseHook();
  await acquisition;
});

test('recovers only the dead lock owner\'s exact single-link artifact part', async (t) => {
  const f = await fixture(t);
  await prepareCache(f);
  const deadPid = await exitedChildPid();
  const names = lockNames();
  const lockPath = join(f.cacheRoot, 'locks', `${sha256()}.lock`);
  const ownedPart = join(f.cacheRoot, 'objects', names.artifactPartName);
  const unknownPart = join(
    f.cacheRoot,
    'objects',
    `.${sha256()}.fedcba98-7654-4cba-8fed-ba9876543210.part`,
  );
  await writeFile(lockPath, lockRecord(deadPid), { mode: 0o600 });
  await writeFile(ownedPart, BYTES.subarray(0, 5), { mode: 0o600 });
  await writeFile(unknownPart, Buffer.from('unknown residue'), { mode: 0o600 });

  await acquireRuntimeArtifact(f.input);

  assert.deepEqual(
    (await readdir(join(f.cacheRoot, 'objects'))).sort(),
    [`${sha256()}.bin`, unknownPart.split('/').at(-1)].sort(),
  );
  assert.equal(f.calls.length, 1);
});

test('recovers dead atomic lock temporaries and exact lock hardlink publication pairs', async (t) => {
  for (const state of ['temporary-only', 'published-pair']) {
    const f = await fixture(t);
    await prepareCache(f);
    const deadPid = await exitedChildPid();
    const names = lockNames();
    const lockPath = join(f.cacheRoot, 'locks', `${sha256()}.lock`);
    const lockPartPath = join(f.cacheRoot, 'locks', names.lockPartName);
    await writeFile(lockPartPath, lockRecord(deadPid), { mode: 0o600 });
    if (state === 'published-pair') await link(lockPartPath, lockPath);

    await acquireRuntimeArtifact(f.input);

    assert.deepEqual(await readdir(join(f.cacheRoot, 'locks')), []);
    assert.equal(f.calls.length, 1);
  }
});

test('removes an interrupted partial download and leaves no published cache entry', async (t) => {
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(BYTES.subarray(0, 5));
      controller.error(new Error('private interrupted stream'));
    },
  });
  const f = await fixture(t, {
    fetch: async () => ({ response: new Response(stream, { status: 200 }) }),
  });

  await rejectsCode(
    acquireRuntimeArtifact(f.input),
    'RUNTIME_ARTIFACT_ACQUISITION_FAILED',
    ['private interrupted stream'],
  );
  assert.deepEqual(await readdir(join(f.cacheRoot, 'objects')), []);
});

test('serializes concurrent acquisition and never publishes a partial destination', async (t) => {
  let fetchCalls = 0;
  let releaseBody;
  const bodyGate = new Promise((resolve) => { releaseBody = resolve; });
  let bodyStarted;
  const started = new Promise((resolve) => { bodyStarted = resolve; });
  const f = await fixture(t, {
    fetch: async () => {
      fetchCalls += 1;
      return {
        response: new Response(new ReadableStream({
          async start(controller) {
            controller.enqueue(BYTES.subarray(0, 5));
            bodyStarted();
            await bodyGate;
            controller.enqueue(BYTES.subarray(5));
            controller.close();
          },
        }), { status: 200 }),
      };
    },
  });

  const first = acquireRuntimeArtifact(f.input);
  const second = acquireRuntimeArtifact(f.input);
  await started;
  const during = await readdir(join(f.cacheRoot, 'objects'));
  assert.equal(during.some((name) => name === `${sha256()}.bin`), false);
  assert.equal(during.filter((name) => name.endsWith('.part')).length, 1);
  releaseBody();

  const [firstResult, secondResult] = await Promise.all([first, second]);
  assert.deepEqual(secondResult, firstResult);
  assert.equal(fetchCalls, 1);
  assert.deepEqual(await readdir(join(f.cacheRoot, 'objects')), [`${sha256()}.bin`]);
  assert.deepEqual(await readdir(join(f.cacheRoot, 'locks')), []);
});

test('bounds contention only after observing a live lock and redacts its metadata', async (t) => {
  let fetchStarted;
  const started = new Promise((resolve) => { fetchStarted = resolve; });
  let releaseFetch;
  const fetchGate = new Promise((resolve) => { releaseFetch = resolve; });
  let fetchCalls = 0;
  const f = await fixture(t, {
    fetch: async () => {
      fetchCalls += 1;
      fetchStarted();
      await fetchGate;
      return { response: new Response(BYTES, { status: 200 }) };
    },
  });
  f.input.policy.timeoutMs = 5_000;
  const first = acquireRuntimeArtifact(f.input);
  await started;
  const contender = {
    ...f.input,
    policy: { ...f.input.policy, timeoutMs: 1_000 },
  };

  await rejectsCode(
    acquireRuntimeArtifact(contender),
    'RUNTIME_CACHE_LOCKED',
    ['01234567-89ab-4cde-8fab-0123456789ab', f.cacheRoot, String(process.pid)],
  );
  releaseFetch();
  await first;
  assert.equal(fetchCalls, 1);
});

test('preserves artifact timeout when creating this caller\'s own cache lock expires', async (t) => {
  const f = await fixture(t);
  f.input.policy.timeoutMs = 500;
  globalThis[CACHE_TEST_HOOK] = async (event) => {
    if (event !== 'afterLockTemporarySyncBeforePublish') return;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 600);
  };
  t.after(() => { delete globalThis[CACHE_TEST_HOOK]; });

  await rejectsCode(acquireRuntimeArtifact(f.input), 'RUNTIME_ARTIFACT_TIMEOUT');
  assert.equal(f.calls.length, 0);
  const names = await readdir(join(f.cacheRoot, 'locks'));
  assert.equal(names.includes(`${sha256()}.lock`), false);
});

test('recovers a strictly validated lock whose owner process is dead', async (t) => {
  const f = await fixture(t);
  await prepareCache(f);
  const lockPath = join(f.cacheRoot, 'locks', `${sha256()}.lock`);
  const child = execFileCallback(process.execPath, ['-e', 'process.exit(0)']);
  const deadPid = child.pid;
  await new Promise((resolve, reject) => {
    child.once('exit', resolve);
    child.once('error', reject);
  });
  await writeFile(lockPath, lockRecord(deadPid), { mode: 0o600 });

  const result = await acquireRuntimeArtifact(f.input);

  assert.equal(result.path.endsWith(`${sha256()}.bin`), true);
  assert.equal(f.calls.length, 1);
  assert.deepEqual(await readdir(join(f.cacheRoot, 'locks')), []);
});

test('serializes concurrent dead-lock recovery without deleting a replacement lock', async (t) => {
  const deadPid = await exitedChildPid();
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const f = await fixture(t);
    await prepareCache(f);
    const lockPath = join(f.cacheRoot, 'locks', `${sha256()}.lock`);
    await writeFile(lockPath, lockRecord(deadPid), { mode: 0o600 });

    const outcomes = await Promise.allSettled([
      acquireRuntimeArtifact(f.input),
      acquireRuntimeArtifact(f.input),
    ]);

    assert.deepEqual(
      outcomes.map((outcome) => (
        outcome.status === 'fulfilled' ? outcome.status : outcome.reason?.code
      )),
      ['fulfilled', 'fulfilled'],
    );
    assert.deepEqual(outcomes[1].value, outcomes[0].value);
    assert.equal(f.calls.length, 1);
    assert.deepEqual(await readdir(join(f.cacheRoot, 'locks')), []);
  }
});

test('serializes dead-lock recovery and lock creation across real processes', async (t) => {
  const f = await fixture(t);
  await prepareCache(f);
  const deadPid = await exitedChildPid();
  const lockPath = join(f.cacheRoot, 'locks', `${sha256()}.lock`);
  const readyPath = join(f.parent, 'gate-ready');
  const waitingPath = join(f.parent, 'gate-waiting');
  const releasePath = join(f.parent, 'gate-release');
  const fetchLogPath = join(f.parent, 'fetch-log');
  await writeFile(lockPath, lockRecord(deadPid), { mode: 0o600 });
  const workers = [];
  try {
    const first = runArtifactCacheWorker({
      cacheRoot: f.cacheRoot,
      fetchLogPath,
      holdGate: true,
      readyPath,
      releasePath,
      timeoutMs: 5_000,
    });
    workers.push(first);
    await waitForPath(readyPath);
    const second = runArtifactCacheWorker({
      cacheRoot: f.cacheRoot,
      fetchLogPath,
      holdGate: false,
      readyPath,
      releasePath,
      waitingPath,
      timeoutMs: 5_000,
    });
    workers.push(second);

    await waitForPath(waitingPath);
    await assert.rejects(readFile(fetchLogPath), { code: 'ENOENT' });
    await writeFile(releasePath, 'release', { mode: 0o600 });
    const outcomes = await Promise.all(workers);

    assert.deepEqual(outcomes.map(({ status }) => status), ['fulfilled', 'fulfilled']);
    assert.deepEqual(outcomes[1].result, outcomes[0].result);
    const fetchers = (await readFile(fetchLogPath, 'utf8')).trim().split('\n');
    assert.equal(fetchers.length, 1);
    assert.deepEqual(await readdir(join(f.cacheRoot, 'locks')), []);
  } finally {
    try { await writeFile(releasePath, 'release', { mode: 0o600 }); } catch {}
    await Promise.allSettled(workers);
  }
});

test('fails closed without deleting an abandoned cross-process recovery gate', async (t) => {
  const f = await fixture(t);
  await prepareCache(f);
  const gatePath = join(f.cacheRoot, 'locks', `${sha256()}.gate`);
  const fetchLogPath = join(f.parent, 'fetch-log');
  await mkdir(gatePath, { mode: 0o700 });

  const outcome = await runArtifactCacheWorker({
    cacheRoot: f.cacheRoot,
    fetchLogPath,
    holdGate: false,
    readyPath: join(f.parent, 'unused-ready'),
    releasePath: join(f.parent, 'unused-release'),
    timeoutMs: 1_500,
  });

  assert.deepEqual(outcome, {
    status: 'rejected',
    code: 'RUNTIME_CACHE_LOCKED',
    message: 'RUNTIME_CACHE_LOCKED',
  });
  await assert.rejects(readFile(fetchLogPath), { code: 'ENOENT' });
  const gate = await lstat(gatePath);
  assert.equal(gate.isDirectory(), true);
  assert.equal(gate.mode & 0o777, 0o700);
});

test('stops streamed orphan enumeration at the 4097th directory entry', async (t) => {
  const f = await fixture(t);
  await prepareCache(f);
  const locksPath = join(f.cacheRoot, 'locks');
  for (let start = 0; start < 4_096; start += 256) {
    await Promise.all(Array.from({ length: 256 }, (_, offset) => writeFile(
      join(locksPath, `unrelated-${start + offset}`),
      '',
      { mode: 0o600 },
    )));
  }
  f.input.policy.timeoutMs = 10_000;
  let observedCount;
  globalThis[CACHE_TEST_HOOK] = async (event, context) => {
    if (event === 'orphanDirectoryLimitExceeded') observedCount = context.entriesRead;
  };
  t.after(() => { delete globalThis[CACHE_TEST_HOOK]; });

  await rejectsCode(acquireRuntimeArtifact(f.input), 'RUNTIME_CACHE_UNSAFE');
  assert.equal(observedCount, 4_097);
  assert.equal(f.calls.length, 0);
});

test('fails bounded on unsafe lock residue without reading or deleting its target', async (t) => {
  const cases = [];

  {
    const f = await fixture(t);
    await prepareCache(f);
    const target = join(f.parent, 'private-symlink-lock-target');
    await writeFile(target, lockRecord(process.pid).replace('01234567', 'private!'), {
      mode: 0o600,
    });
    const lockPath = join(f.cacheRoot, 'locks', `${sha256()}.lock`);
    await symlink(target, lockPath);
    cases.push({ f, lockPath, target, kind: 'symlink' });
  }
  {
    const f = await fixture(t);
    await prepareCache(f);
    const target = join(f.parent, 'private-hardlink-lock-target');
    await writeFile(target, lockRecord(process.pid), { mode: 0o600 });
    const lockPath = join(f.cacheRoot, 'locks', `${sha256()}.lock`);
    await link(target, lockPath);
    cases.push({ f, lockPath, target, kind: 'hardlink' });
  }
  {
    const f = await fixture(t);
    await prepareCache(f);
    const lockPath = join(f.cacheRoot, 'locks', `${sha256()}.lock`);
    await execFile('mkfifo', [lockPath]);
    cases.push({ f, lockPath, target: null, kind: 'fifo' });
  }
  {
    const f = await fixture(t);
    await prepareCache(f);
    const lockPath = join(f.cacheRoot, 'locks', `${sha256()}.lock`);
    await writeFile(lockPath, lockRecord(process.pid), { mode: 0o644 });
    await chmod(lockPath, 0o644);
    cases.push({ f, lockPath, target: null, kind: 'permissive' });
  }

  for (const { f, lockPath, target, kind } of cases) {
    f.input.policy.timeoutMs = 1_000;
    const observed = acquireRuntimeArtifact(f.input).then(
      (value) => ({ value }),
      (error) => ({ error }),
    );
    const outcome = await Promise.race([
      observed,
      new Promise((resolve) => setTimeout(() => resolve('hung'), 2_000)),
    ]);
    assert.notEqual(outcome, 'hung');
    assert.equal(outcome.error?.code, 'RUNTIME_CACHE_UNSAFE');
    assert.equal(outcome.error?.message, 'RUNTIME_CACHE_UNSAFE');
    assert.equal(f.calls.length, 0);
    const stats = await lstat(lockPath);
    if (kind === 'symlink') assert.equal(stats.isSymbolicLink(), true);
    if (kind === 'hardlink') assert.equal(stats.nlink, 2);
    if (kind === 'fifo') assert.equal(stats.isFIFO(), true);
    if (kind === 'permissive') assert.equal(stats.mode & 0o777, 0o644);
    if (target !== null) assert.equal((await lstat(target)).isFile(), true);
  }
});
