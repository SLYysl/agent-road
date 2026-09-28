import assert from 'node:assert/strict';
import { chmod, lstat, rename, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { dirname } from 'node:path';
import test from 'node:test';
import { createConnectionReuse } from '../src/ssh/connection-reuse.mjs';

const ADDRESS = '100.64.0.10';
const OPTIONS = ['-F', 'none', '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'ProxyCommand=none'];
async function fixture(t, { closeFails = false } = {}) {
  let socket;
  let server;
  let closes = 0;
  let calls = 0;
  const pool = await createConnectionReuse({ addresses: [ADDRESS], runProcess: async (_command, args) => {
    closes += 1;
    assert.equal(args.includes('ProxyCommand=/usr/bin/false'), true);
    if (closeFails) return { exitCode: 255, signal: null };
    await new Promise((resolve) => server.close(resolve));
    return { exitCode: 0, signal: null };
  } }, async () => {});
  t.after(async () => {
    if (server?.listening) await new Promise((resolve) => server.close(resolve));
    if (socket) await rm(dirname(socket), { recursive: true, force: true });
  });
  const invoke = async (options) => {
    calls += 1;
    const path = options.find((value) => value.startsWith('ControlPath=')).slice(12);
    if (!socket) {
      socket = path;
      server = createServer();
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socket, resolve); });
      await chmod(socket, 0o600);
    } else {
      assert.equal(path, socket);
      assert.equal(options.includes('ControlMaster=no'), true);
      assert.equal(options.includes('ProxyCommand=/usr/bin/false'), true);
    }
    return { exitCode: 0, signal: null, stdout: 'ok', stderr: '' };
  };
  return { pool, invoke, socket: () => socket, calls: () => calls, closes: () => closes,
    stop: () => new Promise((resolve) => server.close(resolve)) };
}

test('missing master fails before dispatch rather than reconnecting or replaying', async (t) => {
  const f = await fixture(t);
  await f.pool.run(ADDRESS, OPTIONS, f.invoke);
  await f.stop();
  await assert.rejects(f.pool.run(ADDRESS, OPTIONS, f.invoke), { code: 'SSH_VERIFY_FAILED' });
  assert.equal(f.calls(), 1);
  await assert.rejects(f.pool.close(), { code: 'SSH_VERIFY_CLEANUP_FAILED' });
  assert.equal(f.closes(), 0);
});

test('socket replacement is rejected for both commands and shutdown', async (t) => {
  const f = await fixture(t);
  await f.pool.run(ADDRESS, OPTIONS, f.invoke);
  await rename(f.socket(), `${f.socket()}.held`);
  await writeFile(f.socket(), 'foreign endpoint', { mode: 0o600 });
  await assert.rejects(f.pool.run(ADDRESS, OPTIONS, f.invoke), { code: 'SSH_VERIFY_UNSAFE_PATH' });
  await assert.rejects(f.pool.close(), { code: 'SSH_VERIFY_CLEANUP_FAILED' });
  assert.equal(f.calls(), 1);
  assert.equal(f.closes(), 0);
});

test('shutdown failure is visible and retains the private endpoint directory', async (t) => {
  const f = await fixture(t, { closeFails: true });
  await f.pool.run(ADDRESS, OPTIONS, f.invoke);
  await assert.rejects(f.pool.close(), { code: 'SSH_VERIFY_CLEANUP_FAILED' });
  assert.equal((await lstat(dirname(f.socket()))).mode & 0o777, 0o700);
});

test('operation failure is not replayed and the master still closes', async (t) => {
  const f = await fixture(t);
  const error = new Error('uncertain operation');
  await assert.rejects(f.pool.run(ADDRESS, OPTIONS, async (options) => {
    await f.invoke(options);
    throw error;
  }), (value) => value === error);
  await f.pool.close();
  assert.equal(f.calls(), 1);
  assert.equal(f.closes(), 1);
});

test('overlapping calls are rejected and close waits for the active invocation', async (t) => {
  const f = await fixture(t);
  let release;
  let started;
  const ready = new Promise((resolve) => { started = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });
  const pending = f.pool.run(ADDRESS, OPTIONS, async (options) => {
    const result = await f.invoke(options);
    started(); await gate; return result;
  });
  await ready;
  await assert.rejects(f.pool.run(ADDRESS, OPTIONS, f.invoke), { code: 'SSH_VERIFY_INPUT_INVALID' });
  const closing = f.pool.close();
  release(); await pending; await closing;
  assert.equal(f.calls(), 1);
  assert.equal(f.closes(), 1);
});
