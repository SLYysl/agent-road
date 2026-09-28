import { chmod, lstat, mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const IDLE_SECONDS = 30;

function failure(code = 'SSH_VERIFY_FAILED') {
  return Object.assign(new Error(code), { code });
}

async function optionalStat(path) {
  try { return await lstat(path); } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function sameEndpoint(actual, expected) {
  return actual && actual.dev === expected.dev && actual.ino === expected.ino
    && actual.uid === expected.uid && actual.mode === expected.mode;
}

// Internal helper: the caller supplies validated addresses/options and retains its
// identity lock and immutable trust snapshots for this entire lifetime.
export async function createConnectionReuse(config, validateDirectoryChain) {
  const directory = await mkdtemp(join(await realpath(tmpdir()), 'ar-m-'));
  let initial;
  try {
    await chmod(directory, 0o700);
    await validateDirectoryChain(directory);
    initial = await lstat(directory);
    // OpenSSH also appends a temporary suffix before publishing its Unix socket.
    if (Buffer.byteLength(join(directory, 's7')) > 80 || /[%$\r\n]/u.test(directory)) {
      throw failure('SSH_VERIFY_UNSAFE_PATH');
    }
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
  const sockets = new Map(config.addresses.map((address, index) => [address, {
    path: join(directory, `s${index}`), attempted: false, identity: null,
  }]));
  let active = null;
  let closed = false;

  async function assertDirectory() {
    await validateDirectoryChain(directory);
    const current = await lstat(directory);
    if (!sameEndpoint(current, initial) || !current.isDirectory()
      || current.uid !== process.getuid() || (current.mode & 0o777) !== 0o700) {
      throw failure('SSH_VERIFY_UNSAFE_PATH');
    }
  }

  async function socketIdentity(socket) {
    const current = await optionalStat(socket.path);
    if (current && (!current.isSocket() || current.uid !== process.getuid()
      || current.nlink !== 1 || (current.mode & 0o077) !== 0)) {
      throw failure('SSH_VERIFY_UNSAFE_PATH');
    }
    return current;
  }

  async function assertSocket(socket) {
    const current = await socketIdentity(socket);
    if (!socket.identity || !sameEndpoint(current, socket.identity)) throw failure();
  }

  async function run(address, options, invoke) {
    if (closed || active || !sockets.has(address)) throw failure('SSH_VERIFY_INPUT_INVALID');
    // Set the guard synchronously, before checking paths or launching a process.
    let settle;
    active = new Promise((resolve) => { settle = resolve; });
    const socket = sockets.get(address);
    try {
      await assertDirectory();
      const first = !socket.attempted;
      if (first) {
        if (await optionalStat(socket.path)) throw failure('SSH_VERIFY_UNSAFE_PATH');
      } else {
        await assertSocket(socket);
      }
      socket.attempted = true;
      const reused = options.map((value) => {
        if (value === 'ControlMaster=no') return `ControlMaster=${first ? 'yes' : 'no'}`;
        if (value === 'ControlPath=none') return `ControlPath=${socket.path}`;
        // A dead master must fail, never silently open another connection.
        if (value === 'ProxyCommand=none' && !first) return 'ProxyCommand=/usr/bin/false';
        return value;
      });
      if (first) reused.push('-o', `ControlPersist=${IDLE_SECONDS}`);
      let result;
      let primary;
      try { result = await invoke(reused); } catch (error) { primary = error; }
      await assertDirectory();
      if (first) socket.identity = await socketIdentity(socket);
      if (socket.identity) await assertSocket(socket);
      else if (!primary) throw failure();
      if (primary) throw primary;
      return result;
    } finally {
      active = null;
      settle();
    }
  }

  async function close() {
    if (closed) return;
    closed = true;
    if (active) await active;
    let failed = false;
    try {
      await assertDirectory();
      for (const [address, socket] of sockets) {
        if (!socket.attempted) continue;
        try {
          const current = await socketIdentity(socket);
          if (!current && !socket.identity) continue; // Authentication never established a master.
          await assertSocket(socket);
          const result = await config.runProcess('/usr/bin/ssh', [
            '-F', 'none', '-o', 'ControlMaster=no', '-o', `ControlPath=${socket.path}`,
            '-o', 'ProxyCommand=/usr/bin/false', '-O', 'exit', `AgentRoad@${address}`,
          ], { timeoutMs: 3000, maxOutputBytes: 4096 });
          if (result.exitCode !== 0 || result.signal !== null) throw failure();
          for (let n = 0; n < 20 && await optionalStat(socket.path); n += 1) {
            await new Promise((resolve) => setTimeout(resolve, 25));
          }
          if (await optionalStat(socket.path)) throw failure();
        } catch { failed = true; }
      }
      if (!failed) {
        await assertDirectory();
        await rm(directory, { recursive: true });
      }
    } catch { failed = true; }
    // On uncertain shutdown retain the private endpoint directory. An orphaned
    // master has a 30-second idle expiry, rather than unbounded ControlPersist.
    if (failed) throw failure('SSH_VERIFY_CLEANUP_FAILED');
  }

  return Object.freeze({ run, close });
}
