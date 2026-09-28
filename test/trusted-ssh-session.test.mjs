import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';

import { withTrustedSshSession } from '../src/ssh/trusted-ssh-session.mjs';

function sshString(bytes) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

const BLOB = Buffer.concat([
  sshString(Buffer.from('ssh-ed25519')),
  sshString(Buffer.alloc(32, 17)),
]);
const HOST_KEY = `ssh-ed25519 ${BLOB.toString('base64')} windows-host`;
const FINGERPRINT = `SHA256:${createHash('sha256').update(BLOB).digest('base64').replace(/=+$/u, '')}`;
const ADDRESS = '100.64.0.10';
const SECOND_ADDRESS = '100.64.0.11';
const MAX_SESSION_PROCESS_TIMEOUT_MS = 31 * 60 * 1_000;

async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-trusted-ssh-')));
  const identityDirectory = join(root, 'identities', 'dev_abc123');
  const privateKeyPath = join(identityDirectory, 'id_ed25519');
  const knownHostsPath = join(root, 'known-hosts', 'agent-road-known-hosts-dev_abc123');
  await mkdir(identityDirectory, { recursive: true, mode: 0o700 });
  await chmod(join(root, 'identities'), 0o700);
  await chmod(identityDirectory, 0o700);
  await writeFile(privateKeyPath, 'PRIVATE FIXTURE NEVER RETURN\n', { mode: 0o600 });
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, privateKeyPath, knownHostsPath };
}

function input(paths, addresses, runProcess) {
  return {
    deviceId: 'dev_abc123',
    addresses,
    hostKeys: [HOST_KEY],
    fingerprints: [FINGERPRINT],
    privateKeyPath: paths.privateKeyPath,
    knownHostsPath: paths.knownHostsPath,
    runProcess,
  };
}

function successfulRunner(calls) {
  return async (command, args, options) => {
    calls.push({ command, args: [...args], options });
    if (command === '/usr/bin/ssh-keygen') {
      assert.deepEqual(args.slice(0, 1), ['-lf']);
      assert.equal((await lstat(args[1])).mode & 0o777, 0o600);
      return { exitCode: 0, signal: null, stdout: `256 ${FINGERPRINT} windows-host (ED25519)\n`, stderr: '' };
    }
    return { exitCode: 0, signal: null, stdout: '', stderr: '' };
  };
}

function exactOptions(args, command) {
  const knownHostsPath = args.find((arg) => arg.startsWith('UserKnownHostsFile='))
    ?.slice('UserKnownHostsFile='.length);
  const privateKeyPath = args[args.indexOf('-i') + 1];
  const portFlag = command === '/usr/bin/scp' ? '-P' : '-p';
  return [
    '-F', 'none',
    '-o', 'GlobalKnownHostsFile=/dev/null',
    '-o', 'KnownHostsCommand=none',
    '-o', 'VerifyHostKeyDNS=no',
    '-o', 'ProxyCommand=none',
    '-o', 'ProxyJump=none',
    '-o', 'IdentityAgent=none',
    '-o', 'UpdateHostKeys=no',
    '-o', 'ControlMaster=no',
    '-o', 'ControlPath=none',
    '-o', 'WarnWeakCrypto=no',
    '-o', 'BatchMode=yes',
    '-o', 'PasswordAuthentication=no',
    '-o', 'KbdInteractiveAuthentication=no',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', `UserKnownHostsFile=${knownHostsPath}`,
    '-o', 'IdentitiesOnly=yes',
    '-i', privateKeyPath,
    portFlag, '22',
  ];
}

test('provides only a frozen session over copied addresses and strict SSH clients', async (t) => {
  const paths = await fixture(t);
  const calls = [];
  const addresses = [ADDRESS];
  const pending = withTrustedSshSession(
    input(paths, addresses, successfulRunner(calls)),
    async (session) => {
      assert.equal(Object.isFrozen(session), true);
      assert.equal(Object.isFrozen(session.addresses), true);
      assert.deepEqual(session.addresses, [ADDRESS]);
      assert.notEqual(session.addresses, addresses);
      assert.deepEqual(Object.keys(session).sort(), [
        'addresses',
        'invokeCleanup',
        'invokeScp',
        'invokeSsh',
        'remoteSpec',
      ]);

      await session.invokeSsh(ADDRESS, ['powershell.exe', '-NoProfile'], {
        timeoutMs: 1_234,
        maxOutputBytes: 5_678,
        stdinText: 'exit 0\r\n',
      });
      await session.invokeScp([
        paths.privateKeyPath,
        session.remoteSpec(ADDRESS, 'C:/ProgramData/AgentRoad/probe/test.bin'),
      ]);
      return 'operation-result';
    },
  );
  addresses[0] = '100.64.0.99';

  assert.equal(await pending, 'operation-result');
  assert.equal(
    await readFile(paths.knownHostsPath, 'utf8'),
    `${ADDRESS} ${HOST_KEY}\n`,
  );
  const commands = calls.filter(({ command }) => command !== '/usr/bin/ssh-keygen');
  assert.deepEqual(commands.map(({ command }) => command), ['/usr/bin/ssh', '/usr/bin/scp']);
  for (const call of commands) {
    const options = exactOptions(call.args, call.command);
    assert.deepEqual(call.args.slice(0, options.length), options);
    assert.match(call.args[call.args.indexOf('-i') + 1], /\/\.verify-dev_abc123-[^/]+\/id_ed25519$/);
    assert.match(
      call.args.find((arg) => arg.startsWith('UserKnownHostsFile=')),
      /\/\.verify-dev_abc123-[^/]+\/known_hosts$/,
    );
  }
  assert.deepEqual(commands[0].args.slice(exactOptions(commands[0].args, commands[0].command).length), [
    `AgentRoad@${ADDRESS}`,
    'powershell.exe',
    '-NoProfile',
  ]);
  assert.deepEqual(commands[0].options, {
    timeoutMs: 1_234,
    maxOutputBytes: 5_678,
    stdinText: 'exit 0\r\n',
  });
  assert.deepEqual(commands[1].options, { timeoutMs: 20_000, maxOutputBytes: 16 * 1024 });
});

test('bounds an explicit trust-lock wait before any SSH process starts', async (t) => {
  const paths = await fixture(t);
  const calls = [];
  await writeFile(`${paths.privateKeyPath}.lock`, `${JSON.stringify({
    owner: 'occupied-by-test',
    pid: process.pid,
    createdAt: new Date().toISOString(),
  })}\n`, { mode: 0o600 });

  const started = Date.now();
  await assert.rejects(
    withTrustedSshSession(
      input(paths, [ADDRESS], successfulRunner(calls)),
      async () => 'must-not-run',
      { lockTimeoutMs: 1_000 },
    ),
    (error) => (
      error?.code === 'TRUSTED_SSH_SESSION_LOCKED'
      && error.message === 'TRUSTED_SSH_SESSION_LOCKED'
      && !error.message.includes(paths.privateKeyPath)
    ),
  );

  assert.ok(Date.now() - started < 3_000);
  assert.deepEqual(calls, []);
});

test('does not normalize an operation-thrown lock lookalike', async (t) => {
  const paths = await fixture(t);
  const calls = [];
  const lookalike = Object.assign(
    new Error(`Trusted SSH session dev_abc123 is locked: ${paths.privateKeyPath} (occupied)`),
    { code: 'TRUSTED_SSH_SESSION_LOCKED' },
  );

  await assert.rejects(
    withTrustedSshSession(
      input(paths, [ADDRESS], successfulRunner(calls)),
      async () => { throw lookalike; },
      { lockTimeoutMs: 1_000 },
    ),
    (error) => error === lookalike,
  );
});

test('strictly rejects invalid trust-session options before any SSH process starts', async (t) => {
  const paths = await fixture(t);
  const calls = [];
  let getterCalls = 0;
  const accessor = {};
  Object.defineProperty(accessor, 'lockTimeoutMs', {
    enumerable: true,
    get() { getterCalls += 1; return 1_000; },
  });

  for (const options of [
    { lockTimeoutMs: 999 },
    { lockTimeoutMs: 900_001 },
    { lockTimeoutMs: 1.5 },
    { lockTimeoutMs: 1_000, extra: true },
    [],
    new Proxy({ lockTimeoutMs: 1_000 }, {}),
    accessor,
  ]) {
    await assert.rejects(
      withTrustedSshSession(
        input(paths, [ADDRESS], successfulRunner(calls)),
        async () => 'must-not-run',
        options,
      ),
      { code: 'SSH_VERIFY_INPUT_INVALID' },
    );
  }

  assert.equal(getterCalls, 0);
  assert.deepEqual(calls, []);
});

test('rejects trust mutation around invocation while cleanup uses immutable session trust', async (t) => {
  const paths = await fixture(t);
  const calls = [];
  const replacement = `${paths.privateKeyPath}.replacement`;
  await writeFile(replacement, 'REPLACED PRIVATE FIXTURE\n', { mode: 0o600 });
  const baseRunner = successfulRunner(calls);
  let replaced = false;
  const runner = async (command, args, options) => {
    const result = await baseRunner(command, args, options);
    if (!replaced && command === '/usr/bin/ssh') {
      replaced = true;
      await rename(paths.privateKeyPath, `${paths.privateKeyPath}.original`);
      await rename(replacement, paths.privateKeyPath);
    }
    return result;
  };

  await assert.rejects(
    withTrustedSshSession(input(paths, [ADDRESS], runner), async (session) => {
      await assert.rejects(
        session.invokeSsh(ADDRESS, ['powershell.exe', '-NoProfile'], { stdinText: 'exit 73\r\n' }),
        { code: 'SSH_VERIFY_UNSAFE_PATH' },
      );
      await session.invokeCleanup(
        ADDRESS,
        ['powershell.exe', '-NoProfile'],
        { stdinText: 'exit 0\r\n' },
      );
    }),
    { code: 'SSH_VERIFY_UNSAFE_PATH' },
  );
  assert.deepEqual(
    calls.filter(({ command }) => command === '/usr/bin/ssh').map(({ command }) => command),
    ['/usr/bin/ssh', '/usr/bin/ssh'],
  );
  const cleanup = calls.at(-1);
  assert.equal(cleanup.command, '/usr/bin/ssh');
  const cleanupKnownHostsPath = cleanup.args.find((arg) => arg.startsWith('UserKnownHostsFile='))
    .slice('UserKnownHostsFile='.length);
  assert.equal(dirname(cleanupKnownHostsPath), dirname(cleanup.args[cleanup.args.indexOf('-i') + 1]));
});

test('allows the full thirty-minute exec window plus bounded transport margin', async (t) => {
  const paths = await fixture(t);
  const calls = [];

  await withTrustedSshSession(
    input(paths, [ADDRESS], successfulRunner(calls)),
    async (session) => {
      await session.invokeSsh(ADDRESS, ['powershell.exe', '-NoProfile'], {
        timeoutMs: MAX_SESSION_PROCESS_TIMEOUT_MS,
      });
      await assert.rejects(
        async () => session.invokeSsh(ADDRESS, ['powershell.exe', '-NoProfile'], {
          timeoutMs: MAX_SESSION_PROCESS_TIMEOUT_MS + 1,
        }),
        { code: 'SSH_VERIFY_INPUT_INVALID' },
      );
    },
  );

  const sshCalls = calls.filter(({ command }) => command === '/usr/bin/ssh');
  assert.equal(sshCalls.length, 1);
  assert.deepEqual(sshCalls[0].options, {
    timeoutMs: MAX_SESSION_PROCESS_TIMEOUT_MS,
    maxOutputBytes: 16 * 1024,
  });
});

test('rejects SCP operands with a wrong host, multiple remotes, or option-like input', async (t) => {
  const paths = await fixture(t);
  const calls = [];

  await withTrustedSshSession(
    input(paths, [ADDRESS, SECOND_ADDRESS], successfulRunner(calls)),
    async (session) => {
      const remote = session.remoteSpec(ADDRESS, 'C:/ProgramData/AgentRoad/probe/test.bin');
      const secondRemote = session.remoteSpec(SECOND_ADDRESS, 'C:/ProgramData/AgentRoad/probe/test.bin');
      const rejectedCode = async (args) => {
        try {
          await session.invokeScp(args);
          return null;
        } catch (error) {
          return error.code;
        }
      };
      assert.deepEqual(await Promise.all([
        rejectedCode([paths.privateKeyPath, 'AgentRoad@100.64.0.99:C:/ProgramData/AgentRoad/probe/test.bin']),
        rejectedCode([remote, secondRemote]),
        rejectedCode(['-v', remote]),
      ]), [
        'SSH_VERIFY_INPUT_INVALID',
        'SSH_VERIFY_INPUT_INVALID',
        'SSH_VERIFY_INPUT_INVALID',
      ]);
    },
  );

  assert.equal(calls.some(({ command }) => command === '/usr/bin/scp'), false);
});

test('snapshots bounded ASCII stdin for SSH and cleanup while SCP rejects it', async (t) => {
  const paths = await fixture(t);
  const calls = [];
  const runner = successfulRunner(calls);

  await withTrustedSshSession(input(paths, [ADDRESS], runner), async (session) => {
    const options = { stdinText: 'exit 73\r\n' };
    const pending = session.invokeSsh(ADDRESS, ['powershell.exe', '-File', '-'], options);
    options.stdinText = 'mutated secret';
    await pending;
    await session.invokeCleanup(
      ADDRESS,
      ['powershell.exe', '-File', '-'],
      { stdinText: 'x'.repeat(64 * 1024) },
    );

    const remote = session.remoteSpec(ADDRESS, 'C:/ProgramData/AgentRoad/probe/test.bin');
    await assert.rejects(
      async () => session.invokeScp(
        [paths.privateKeyPath, remote],
        { stdinText: 'exit 0\r\n' },
      ),
      { code: 'SSH_VERIFY_INPUT_INVALID' },
    );

    let getterCalls = 0;
    const accessor = {};
    Object.defineProperty(accessor, 'stdinText', {
      enumerable: true,
      get() { getterCalls += 1; throw new Error('stdin getter secret'); },
    });
    for (const processOptions of [
      { stdinText: '' },
      { stdinText: 'nul\0byte' },
      { stdinText: '你好' },
      { stdinText: Buffer.from('buffer') },
      { stdinText: 'x'.repeat((64 * 1024) + 1) },
      { unknown: true },
      accessor,
    ]) {
      await assert.rejects(
        async () => session.invokeSsh(
          ADDRESS,
          ['powershell.exe', '-File', '-'],
          processOptions,
        ),
        { code: 'SSH_VERIFY_INPUT_INVALID' },
      );
    }
    assert.equal(getterCalls, 0);
  });

  const sshCalls = calls.filter(({ command }) => command === '/usr/bin/ssh');
  assert.equal(sshCalls.length, 2);
  assert.equal(sshCalls[0].options.stdinText, 'exit 73\r\n');
  assert.equal(sshCalls[1].options.stdinText.length, 64 * 1024);
  assert.equal(calls.some(({ command }) => command === '/usr/bin/scp'), false);
});

test('connection reuse validates options without evaluating an accessor', async (t) => {
  const paths = await fixture(t);
  const calls = [];
  const getter = {};
  Object.defineProperty(getter, 'reuseConnection', { get() { assert.fail('getter invoked'); } });
  for (const options of [{ reuseConnection: 1 }, { reuseConnection: 'true' }, getter]) {
    await assert.rejects(withTrustedSshSession(input(paths, [ADDRESS], successfulRunner(calls)),
      async () => assert.fail('callback invoked'), options), { code: 'SSH_VERIFY_INPUT_INVALID' });
  }
  assert.equal(calls.length, 0);
});

test('reuses a private socket for SSH and SCP, disables fallback, and closes it', async (t) => {
  const { createServer } = await import('node:net');
  const paths = await fixture(t);
  const calls = [];
  const normal = successfulRunner(calls);
  let server;
  let socketPath;
  let saved;
  t.after(async () => { if (server?.listening) await new Promise((resolve) => server.close(resolve)); });
  const runner = async (command, args, options) => {
    if (command === '/usr/bin/ssh-keygen') return normal(command, args, options);
    calls.push({ command, args, options });
    const socket = args.find((arg) => arg.startsWith('ControlPath='))?.slice(12);
    if (args.includes('ControlMaster=yes')) {
      assert.equal(socketPath, undefined);
      assert.equal(args.includes('ControlPersist=30'), true);
      assert.equal((await lstat(dirname(socket))).mode & 0o777, 0o700);
      assert.equal(Buffer.byteLength(socket) <= 80, true);
      socketPath = socket;
      server = createServer();
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socket, resolve); });
      await chmod(socket, 0o600);
    } else {
      assert.equal(socket, socketPath);
      assert.equal(args.includes('ProxyCommand=/usr/bin/false'), true);
      if (args.includes('-O')) await new Promise((resolve) => server.close(resolve));
    }
    return { exitCode: 0, signal: null, stdout: '', stderr: '' };
  };
  await withTrustedSshSession(input(paths, [ADDRESS], runner), async (session) => {
    saved = session;
    await session.invokeSsh(ADDRESS, ['probe']);
    await session.invokeSsh(ADDRESS, ['second']);
    await session.invokeScp([join(paths.root, 'source'), session.remoteSpec(ADDRESS, 'C:/target')]);
  }, { reuseConnection: true });
  assert.equal(calls.filter(({ args }) => args.includes('ControlMaster=yes')).length, 1);
  assert.equal(calls.filter(({ args }) => args.includes('-O')).length, 1);
  await assert.rejects(lstat(dirname(socketPath)), { code: 'ENOENT' });
  await assert.rejects(saved.invokeSsh(ADDRESS, ['late']), { code: 'SSH_VERIFY_INPUT_INVALID' });
});
