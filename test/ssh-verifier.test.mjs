import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
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
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';

import { verifyWindowsSsh } from '../src/ssh/ssh-verifier.mjs';
import { withFileLock } from '../src/storage/file-lock.mjs';

function sshString(bytes) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

const BLOB = Buffer.concat([
  sshString(Buffer.from('ssh-ed25519')),
  sshString(Buffer.alloc(32, 13)),
]);
const HOST_KEY = `ssh-ed25519 ${BLOB.toString('base64')} windows-host`;
const FINGERPRINT = `SHA256:${createHash('sha256').update(BLOB).digest('base64').replace(/=+$/u, '')}`;
const CAPABILITIES = ['ssh', 'sftp', 'admin-powershell'];
const CLEANUP_PREFIX = "$ProgressPreference='SilentlyContinue';$p=";

async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-ssh-verifier-')));
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

function decodedProbe(args) {
  const marker = args.indexOf('-EncodedCommand');
  assert.notEqual(marker, -1);
  return Buffer.from(args[marker + 1], 'base64').toString('utf16le');
}

function successRunner(calls, { failAddress, wrongProbe = {}, corruptDownload = false } = {}) {
  let uploaded;
  return async (command, args, options) => {
    calls.push({ command, args: [...args], options });
    if (command === '/usr/bin/ssh-keygen') {
      assert.deepEqual(args.slice(0, 1), ['-lf']);
      assert.equal((await lstat(args[1])).mode & 0o777, 0o600);
      return { exitCode: 0, signal: null, stdout: `256 ${FINGERPRINT} windows-host (ED25519)\n`, stderr: '' };
    }
    const joined = args.join(' ');
    if (failAddress && joined.includes(`AgentRoad@${failAddress}`)) {
      return { exitCode: 255, signal: null, stdout: '', stderr: 'unreachable' };
    }
    const identityPath = args[args.indexOf('-i') + 1];
    const knownHostsPath = args.find((arg) => arg.startsWith('UserKnownHostsFile='))
      ?.slice('UserKnownHostsFile='.length);
    assert.equal((await lstat(identityPath)).mode & 0o777, 0o600);
    assert.equal((await lstat(knownHostsPath)).mode & 0o777, 0o600);
    assert.equal((await lstat(dirname(identityPath))).mode & 0o777, 0o700);
    if (command === '/usr/bin/ssh') {
      const script = decodedProbe(args);
      if (script.includes('ConvertTo-Json')) {
        const nonce = /nonce='([A-Za-z0-9_-]+)'/.exec(script)?.[1];
        return {
          exitCode: 0,
          signal: null,
          stdout: JSON.stringify({
            username: 'AgentRoad',
            administrator: true,
            powershellVersion: '5.1.19041.1',
            nonce,
            ...wrongProbe,
          }),
          stderr: '',
        };
      }
      assert.match(script, /^\$ProgressPreference='SilentlyContinue';\$p='C:\/ProgramData\/AgentRoad\/probe\/[A-Za-z0-9_-]+\.bin';/);
      return { exitCode: 0, signal: null, stdout: '', stderr: '' };
    }
    assert.equal(command, '/usr/bin/scp');
    if (args.at(-1).includes('C:/ProgramData/AgentRoad/probe/')) {
      uploaded = await readFile(args.at(-2));
    } else {
      await writeFile(args.at(-1), corruptDownload ? Buffer.from('wrong') : uploaded, { mode: 0o600 });
    }
    return { exitCode: 0, signal: null, stdout: '', stderr: '' };
  };
}

function verifierInput(paths, runProcess, address = '100.64.0.10') {
  return {
    deviceId: 'dev_abc123',
    address,
    sshHostKeys: [HOST_KEY],
    sshHostKeyFingerprints: [FINGERPRINT],
    privateKeyPath: paths.privateKeyPath,
    knownHostsPath: paths.knownHostsPath,
    runProcess,
  };
}

function commandOptions(command, sshOptions) {
  if (command !== '/usr/bin/scp') return sshOptions;
  return [...sshOptions.slice(0, -2), '-P', '22'];
}

test('the fixed macOS OpenSSH clients accept every isolation option', () => {
  const isolation = [
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
    '-o', 'UserKnownHostsFile=/dev/null',
    '-o', 'IdentitiesOnly=yes',
    '-i', '/dev/null',
  ];
  const ssh = spawnSync('/usr/bin/ssh', ['-G', ...isolation, '-p', '22', 'AgentRoad@100.64.0.10'], {
    encoding: 'utf8',
  });
  assert.equal(ssh.status, 0, ssh.stderr);
  assert.match(ssh.stdout, /^batchmode yes$/m);
  assert.match(ssh.stdout, /^globalknownhostsfile \/dev\/null$/m);
  assert.match(ssh.stdout, /^userknownhostsfile \/dev\/null$/m);
  assert.match(ssh.stdout, /^identityagent none$/m);
  assert.match(ssh.stdout, /^updatehostkeys false$/m);
  assert.match(ssh.stdout, /^controlmaster false$/m);

  const scp = spawnSync('/usr/bin/scp', [...isolation, '-P', '22'], { encoding: 'utf8' });
  assert.equal(scp.status, 1);
  assert.match(scp.stderr, /^usage: scp /m);
  assert.doesNotMatch(scp.stderr, /illegal option|Bad configuration option|Unsupported option/i);
});

test('pins host keys and completes exact command and bidirectional file probes', async (t) => {
  const paths = await fixture(t);
  const calls = [];
  const result = await verifyWindowsSsh(verifierInput(paths, successRunner(calls)));

  assert.deepEqual(result, { address: '100.64.0.10', capabilities: CAPABILITIES });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.capabilities), true);
  assert.equal(await readFile(paths.knownHostsPath, 'utf8'), `100.64.0.10 ${HOST_KEY}\n`);
  assert.equal((await lstat(paths.knownHostsPath)).mode & 0o777, 0o600);
  const commands = calls.filter(({ command }) => command !== '/usr/bin/ssh-keygen');
  assert.deepEqual(commands.map(({ command }) => command), [
    '/usr/bin/ssh', '/usr/bin/scp', '/usr/bin/scp', '/usr/bin/ssh',
  ]);
  const observedKnownHosts = commands[0].args.find((arg) => arg.startsWith('UserKnownHostsFile='))
    .slice('UserKnownHostsFile='.length);
  const observedIdentity = commands[0].args[commands[0].args.indexOf('-i') + 1];
  assert.match(observedKnownHosts, /\/\.verify-dev_abc123-[^/]+\/known_hosts$/);
  assert.match(observedIdentity, /\/\.verify-dev_abc123-[^/]+\/id_ed25519$/);
  assert.equal(dirname(observedKnownHosts), dirname(observedIdentity));
  const exactOptions = [
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
    '-o', `UserKnownHostsFile=${observedKnownHosts}`,
    '-o', 'IdentitiesOnly=yes',
    '-i', observedIdentity,
    '-p', '22',
  ];
  for (const call of commands) {
    const wantedOptions = commandOptions(call.command, exactOptions);
    assert.deepEqual(call.args.slice(0, wantedOptions.length), wantedOptions);
    assert.deepEqual(call.options, { timeoutMs: 20_000, maxOutputBytes: 16 * 1024 });
  }
  assert.equal(commands[0].args[exactOptions.length], 'AgentRoad@100.64.0.10');
  assert.match(decodedProbe(commands[0].args), /WindowsPrincipal/);
  assert.match(decodedProbe(commands[0].args), /\$ProgressPreference='SilentlyContinue'/);
  assert.match(decodedProbe(commands[0].args), /CreateDirectory\('C:\\ProgramData\\AgentRoad\\probe'\)/);
  assert.match(decodedProbe(commands[0].args), /ConvertTo-Json -Compress/);
  await assert.rejects(access(dirname(observedIdentity)), { code: 'ENOENT' });
  await assert.rejects(access(`${paths.privateKeyPath}.lock`), { code: 'ENOENT' });
});

test('serializes the complete same-device verification and rejects a pre-SSH path replacement', async (t) => {
  const paths = await fixture(t);
  const calls = [];
  let releaseFirstSsh;
  let firstSshReached;
  const firstSsh = new Promise((resolve) => { firstSshReached = resolve; });
  const release = new Promise((resolve) => { releaseFirstSsh = resolve; });
  const runner = successRunner(calls);
  const blockingRunner = async (command, args, options) => {
    if (command === '/usr/bin/ssh' && decodedProbe(args).includes('ConvertTo-Json')) {
      firstSshReached();
      await release;
    }
    return runner(command, args, options);
  };
  const first = verifyWindowsSsh(verifierInput(paths, blockingRunner));
  await firstSsh;
  const countAtLock = calls.length;
  let secondSettled = false;
  const second = verifyWindowsSsh(verifierInput(paths, successRunner(calls)))
    .finally(() => { secondSettled = true; });
  await new Promise((resolve) => setTimeout(resolve, 40));
  assert.equal(secondSettled, false);
  assert.equal(calls.length, countAtLock);
  releaseFirstSsh();
  await Promise.all([first, second]);

  const replacement = `${paths.privateKeyPath}.replacement`;
  await writeFile(replacement, 'REPLACED PRIVATE FIXTURE\n', { mode: 0o600 });
  const raceCalls = [];
  const replacingRunner = async (command, args, options) => {
    const result = await successRunner(raceCalls)(command, args, options);
    if (command === '/usr/bin/ssh-keygen') {
      await rename(paths.privateKeyPath, `${paths.privateKeyPath}.original`);
      await rename(replacement, paths.privateKeyPath);
    }
    return result;
  };
  await assert.rejects(
    verifyWindowsSsh(verifierInput(paths, replacingRunner)),
    { code: 'SSH_VERIFY_UNSAFE_PATH' },
  );
  assert.equal(raceCalls.some(({ command }) => command === '/usr/bin/ssh'), false);
});

test('tries validated addresses in order and formats IPv6 scp destinations', async (t) => {
  const paths = await fixture(t);
  const calls = [];
  const addresses = ['100.64.0.11', 'fd7a:115c:a1e0::12'];
  const result = await verifyWindowsSsh(verifierInput(
    paths,
    successRunner(calls, { failAddress: addresses[0] }),
    addresses,
  ));

  assert.equal(result.address, addresses[1]);
  assert.equal(
    await readFile(paths.knownHostsPath, 'utf8'),
    `${addresses[0]} ${HOST_KEY}\n${addresses[1]} ${HOST_KEY}\n`,
  );
  const scp = calls.filter(({ command }) => command === '/usr/bin/scp');
  assert.equal(scp.length, 2);
  assert.equal(scp.some(({ args }) => args.some((arg) => arg.startsWith(`AgentRoad@[${addresses[1]}]:C:/`))), true);
});

test('aborts address fallback when remote cleanup is uncertain', async (t) => {
  const paths = await fixture(t);
  const calls = [];
  const addresses = ['100.64.0.11', 'fd7a:115c:a1e0::12'];
  const baseRunner = successRunner(calls);
  const runner = async (command, args, options) => {
    const result = await baseRunner(command, args, options);
    if (
      command === '/usr/bin/ssh'
      && args.includes(`AgentRoad@${addresses[0]}`)
      && decodedProbe(args).startsWith(CLEANUP_PREFIX)
    ) return { exitCode: 1, signal: null, stdout: '', stderr: 'delete uncertain' };
    return result;
  };
  await assert.rejects(
    verifyWindowsSsh(verifierInput(paths, runner, addresses)),
    { code: 'SSH_VERIFY_FAILED', message: 'SSH_VERIFY_FAILED' },
  );
  assert.equal(calls.some(({ args }) => args.some((arg) => arg.includes(addresses[1]))), false);
});

test('rejects mismatched reported fingerprints before writing known_hosts or invoking ssh', async (t) => {
  const paths = await fixture(t);
  const calls = [];
  const input = verifierInput(paths, successRunner(calls));
  input.sshHostKeyFingerprints = ['SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'];
  await assert.rejects(verifyWindowsSsh(input), { code: 'SSH_VERIFY_FAILED', message: 'SSH_VERIFY_FAILED' });
  await assert.rejects(access(paths.knownHostsPath), { code: 'ENOENT' });
  assert.deepEqual(calls.map(({ command }) => command), ['/usr/bin/ssh-keygen']);
});

test('rejects malformed or untrusted probe data and still avoids file transfer', async (t) => {
  for (const wrongProbe of [
    { username: 'Administrator' },
    { administrator: false },
    { nonce: 'wrong' },
    { powershellVersion: 'secret\n5.1' },
    { extra: true },
  ]) {
    const paths = await fixture(t);
    const calls = [];
    await assert.rejects(
      verifyWindowsSsh(verifierInput(paths, successRunner(calls, { wrongProbe }))),
      { code: 'SSH_VERIFY_FAILED' },
    );
    assert.equal(calls.some(({ command }) => command === '/usr/bin/scp'), false);
  }
});

test('always requests remote cleanup and removes local fixtures when transfer verification fails', async (t) => {
  const paths = await fixture(t);
  const calls = [];
  await assert.rejects(
    verifyWindowsSsh(verifierInput(paths, successRunner(calls, { corruptDownload: true }))),
    { code: 'SSH_VERIFY_FAILED' },
  );
  const cleanup = calls.at(-1);
  assert.equal(cleanup.command, '/usr/bin/ssh');
  const cleanupScript = decodedProbe(cleanup.args);
  assert.match(cleanupScript, /^\$ProgressPreference='SilentlyContinue';\$p='C:\/ProgramData\/AgentRoad\/probe\/[A-Za-z0-9_-]+\.bin';/);
  assert.match(cleanupScript, /if\(Test-Path -LiteralPath \$p -ErrorAction Stop\)\{Remove-Item -LiteralPath \$p -Force -ErrorAction Stop\}/);
  assert.match(cleanupScript, /if\(Test-Path -LiteralPath \$p -ErrorAction Stop\)\{throw 'REMOTE_CLEANUP_FAILED'\}$/);
  assert.doesNotMatch(cleanupScript, /-ErrorAction SilentlyContinue|Remove-Item[^;]+['"]C:/);
  for (const call of calls.filter(({ command }) => command === '/usr/bin/scp')) {
    for (const arg of call.args) {
      if (arg.includes('agent-road-file-probe-') && !arg.includes(':')) {
        await assert.rejects(access(arg), { code: 'ENOENT' });
      }
    }
  }
});

test('uses immutable session trust for cleanup after persistent paths are replaced post-upload', async (t) => {
  const paths = await fixture(t);
  const calls = [];
  const baseRunner = successRunner(calls);
  let replaced = false;
  const runner = async (command, args, options) => {
    const result = await baseRunner(command, args, options);
    if (command === '/usr/bin/ssh' && decodedProbe(args).startsWith(CLEANUP_PREFIX)) {
      return { exitCode: 1, signal: null, stdout: '', stderr: 'cleanup failed' };
    }
    if (
      !replaced
      && command === '/usr/bin/scp'
      && args.at(-1).includes('C:/ProgramData/AgentRoad/probe/')
    ) {
      replaced = true;
      const privateReplacement = `${paths.privateKeyPath}.replacement`;
      const knownHostsReplacement = `${paths.knownHostsPath}.replacement`;
      await writeFile(privateReplacement, 'REPLACED PRIVATE FIXTURE\n', { mode: 0o600 });
      await writeFile(knownHostsReplacement, `${HOST_KEY}\n`, { mode: 0o600 });
      await rename(paths.privateKeyPath, `${paths.privateKeyPath}.original`);
      await rename(privateReplacement, paths.privateKeyPath);
      await rename(paths.knownHostsPath, `${paths.knownHostsPath}.original`);
      await rename(knownHostsReplacement, paths.knownHostsPath);
    }
    return result;
  };

  await assert.rejects(
    verifyWindowsSsh(verifierInput(paths, runner)),
    { code: 'SSH_VERIFY_UNSAFE_PATH' },
  );
  const sshCalls = calls.filter(({ command }) => command === '/usr/bin/ssh');
  assert.equal(sshCalls.length, 2);
  assert.match(decodedProbe(sshCalls.at(-1).args), /^\$ProgressPreference='SilentlyContinue';\$p='C:\/ProgramData\/AgentRoad\/probe\//);
  const cleanupKnownHosts = sshCalls.at(-1).args
    .find((arg) => arg.startsWith('UserKnownHostsFile='))
    .slice('UserKnownHostsFile='.length);
  const cleanupIdentity = sshCalls.at(-1).args[sshCalls.at(-1).args.indexOf('-i') + 1];
  assert.match(cleanupKnownHosts, /\/\.verify-dev_abc123-[^/]+\/known_hosts$/);
  assert.equal(dirname(cleanupKnownHosts), dirname(cleanupIdentity));
});

test('surfaces a stable cleanup failure when both probes otherwise succeeded', async (t) => {
  const paths = await fixture(t);
  const calls = [];
  const baseRunner = successRunner(calls);
  const runner = async (command, args, options) => {
    const result = await baseRunner(command, args, options);
    if (command === '/usr/bin/ssh' && decodedProbe(args).startsWith(CLEANUP_PREFIX)) {
      return { exitCode: 1, signal: null, stdout: '', stderr: 'sensitive cleanup details' };
    }
    return result;
  };
  await assert.rejects(
    verifyWindowsSsh(verifierInput(paths, runner)),
    { code: 'SSH_VERIFY_FAILED', message: 'SSH_VERIFY_FAILED' },
  );
  assert.equal(calls.filter(({ command }) => command === '/usr/bin/ssh').length, 2);
});

test('reports sensitive local snapshot cleanup failure even when another failure exists', async (t) => {
  const paths = await fixture(t);
  const calls = [];
  const knownHostsDirectory = dirname(paths.knownHostsPath);
  const baseRunner = successRunner(calls, { corruptDownload: true });
  const runner = async (command, args, options) => {
    const result = await baseRunner(command, args, options);
    if (command === '/usr/bin/ssh' && decodedProbe(args).startsWith(CLEANUP_PREFIX)) {
      await chmod(knownHostsDirectory, 0o500);
    }
    return result;
  };
  try {
    await assert.rejects(
      verifyWindowsSsh(verifierInput(paths, runner)),
      (error) => error.code === 'SSH_VERIFY_CLEANUP_FAILED'
        && error.message === 'SSH_VERIFY_CLEANUP_FAILED'
        && !JSON.stringify(error).includes(paths.root),
    );
  } finally {
    await chmod(knownHostsDirectory, 0o700);
  }
});

test('shared file lock supports validated bounded waits beyond the legacy one-second default', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-lock-options-')));
  const path = join(root, 'device');
  t.after(() => rm(root, { recursive: true, force: true }));
  let release;
  let entered;
  const firstEntered = new Promise((resolve) => { entered = resolve; });
  const hold = new Promise((resolve) => { release = resolve; });
  const first = withFileLock(path, async () => {
    entered();
    await hold;
  });
  await firstEntered;
  let secondEntered = false;
  const second = withFileLock(path, async () => { secondEntered = true; }, {
    timeoutMs: 2_000,
    retryDelayMs: 10,
  });
  await new Promise((resolve) => setTimeout(resolve, 1_100));
  assert.equal(secondEntered, false);
  release();
  await Promise.all([first, second]);
  assert.equal(secondEntered, true);
  await assert.rejects(withFileLock(path, async () => {}, { timeoutMs: 0 }), TypeError);
  await assert.rejects(withFileLock(path, async () => {}, { retryDelayMs: 0 }), TypeError);
  await assert.rejects(withFileLock(path, async () => {}, { unknown: true }), TypeError);
});

test('rejects malformed inputs, unsafe private keys, and unsafe known_hosts targets before ssh', async (t) => {
  const paths = await fixture(t);
  const invalid = [
    { deviceId: '../dev_abc123' },
    { address: 'host.example' },
    { address: ['100.64.0.10', '100.64.0.10'] },
    { sshHostKeys: ['ssh-rsa bad'] },
    { sshHostKeyFingerprints: [] },
    { privateKeyPath: join(paths.root, 'id_ed25519') },
    { knownHostsPath: join(paths.root, 'known-hosts', 'other') },
  ];
  for (const change of invalid) {
    await assert.rejects(
      verifyWindowsSsh({ ...verifierInput(paths, async () => assert.fail('must not run')), ...change }),
      { code: 'SSH_VERIFY_INPUT_INVALID' },
    );
  }

  const hardlinkPath = join(paths.root, 'hardlink');
  await link(paths.privateKeyPath, hardlinkPath);
  await assert.rejects(
    verifyWindowsSsh(verifierInput(paths, async () => assert.fail('must not run'))),
    { code: 'SSH_VERIFY_UNSAFE_PATH' },
  );
  await rm(hardlinkPath);

  const realKnownHosts = join(paths.root, 'real-known-hosts-dev_abc123');
  await writeFile(realKnownHosts, `${HOST_KEY}\n`, { mode: 0o600 });
  await mkdir(join(paths.root, 'known-hosts'), { recursive: true });
  await symlink(realKnownHosts, paths.knownHostsPath);
  await assert.rejects(
    verifyWindowsSsh(verifierInput(paths, successRunner([]))),
    { code: 'SSH_VERIFY_UNSAFE_PATH' },
  );
});

test('rejects symlinked ancestors and group/world-writable immediate directories', async (t) => {
  const symlinkPaths = await fixture(t);
  const deviceDirectory = dirname(symlinkPaths.privateKeyPath);
  const realDeviceDirectory = `${deviceDirectory}.real`;
  await rename(deviceDirectory, realDeviceDirectory);
  await symlink(realDeviceDirectory, deviceDirectory);
  await assert.rejects(
    verifyWindowsSsh(verifierInput(symlinkPaths, async () => assert.fail('must not run'))),
    { code: 'SSH_VERIFY_UNSAFE_PATH' },
  );

  const writablePaths = await fixture(t);
  await mkdir(dirname(writablePaths.knownHostsPath), { recursive: true, mode: 0o700 });
  await chmod(dirname(writablePaths.knownHostsPath), 0o770);
  await assert.rejects(
    verifyWindowsSsh(verifierInput(writablePaths, async () => assert.fail('must not run'))),
    { code: 'SSH_VERIFY_UNSAFE_PATH' },
  );
});

test('rejects controller paths whose uid is neither the current user nor root', async (t) => {
  const paths = await fixture(t);
  const originalGetuid = process.getuid;
  process.getuid = () => originalGetuid() + 10_000;
  try {
    await assert.rejects(
      verifyWindowsSsh(verifierInput(paths, async () => assert.fail('must not run'))),
      { code: 'SSH_VERIFY_UNSAFE_PATH' },
    );
  } finally {
    process.getuid = originalGetuid;
  }
});
