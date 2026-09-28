import assert from 'node:assert/strict';
import {
  access,
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { inspect } from 'node:util';
import { join } from 'node:path';
import test from 'node:test';

import { SshIdentityStore } from '../src/identity/ssh-identity-store.mjs';
import { withFileLock } from '../src/storage/file-lock.mjs';

function sshString(bytes) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function keyBlob(fill = 7) {
  return Buffer.concat([
    sshString(Buffer.from('ssh-ed25519')),
    sshString(Buffer.alloc(32, fill)),
  ]).toString('base64');
}

const ed25519Blob = keyBlob();

function publicLine(deviceId = 'dev_abc123') {
  return `ssh-ed25519 ${ed25519Blob} agent-road:${deviceId}`;
}

async function createRoot(t) {
  const parent = await mkdtemp(join(tmpdir(), 'agent-road-ssh-identities-'));
  const root = join(parent, 'identities');
  t.after(() => rm(parent, { recursive: true, force: true }));
  return { parent, root };
}

function fixtureRunner(calls, {
  line = publicLine(),
  derivedBlob = ed25519Blob,
  delay = false,
  result,
  deriveResult,
  optionCalls,
} = {}) {
  return async (command, args, options) => {
    calls.push([command, [...args]]);
    if (args[0] === '-y') {
      optionCalls?.push(options);
      return deriveResult ?? {
        exitCode: 0,
        signal: null,
        stdout: `ssh-ed25519 ${derivedBlob} agent-road:dev_abc123\n`,
        stderr: '',
      };
    }
    if (delay) await new Promise((resolve) => setTimeout(resolve, 25));
    const privatePath = args.at(-1);
    await writeFile(privatePath, 'PRIVATE FIXTURE DO NOT RETURN\n', { mode: 0o644 });
    await writeFile(`${privatePath}.pub`, `${line}\n`, { mode: 0o644 });
    return result ?? { exitCode: 0, signal: null, stdout: '', stderr: '' };
  };
}

function deferred() {
  let resolve;
  const promise = new Promise((settle) => { resolve = settle; });
  return { promise, resolve };
}

test('creates a contained owner-only Ed25519 identity with exact ssh-keygen argv', async (t) => {
  const { root } = await createRoot(t);
  const calls = [];
  const optionCalls = [];
  const store = new SshIdentityStore(root, { runProcess: fixtureRunner(calls, { optionCalls }) });
  const identity = await store.getOrCreate('dev_abc123');
  const privateKeyPath = join(root, 'dev_abc123', 'id_ed25519');

  assert.deepEqual(calls[0], [
    '/usr/bin/ssh-keygen',
    ['-q', '-t', 'ed25519', '-N', '', '-C', 'agent-road:dev_abc123', '-f', privateKeyPath],
  ]);
  assert.equal(calls[1][0], '/usr/bin/ssh-keygen');
  assert.deepEqual(calls[1][1].slice(0, 2), ['-y', '-f']);
  const derivationPath = calls[1][1][2];
  assert.equal(derivationPath.startsWith(`${join(root, 'dev_abc123', '.derive-')}`), true);
  assert.notEqual(derivationPath, privateKeyPath);
  await assert.rejects(access(derivationPath), { code: 'ENOENT' });
  assert.deepEqual(optionCalls, [{ timeoutMs: 10_000, maxOutputBytes: 4096 }]);
  assert.deepEqual(identity, {
    privateKeyPath,
    publicKeyPath: `${privateKeyPath}.pub`,
    publicKey: publicLine(),
  });
  assert.equal(Object.isFrozen(identity), true);
  assert.equal((await lstat(root)).mode & 0o777, 0o700);
  assert.equal((await lstat(join(root, 'dev_abc123'))).mode & 0o777, 0o700);
  assert.equal((await lstat(privateKeyPath)).mode & 0o777, 0o600);
  assert.equal((await lstat(`${privateKeyPath}.pub`)).mode & 0o777, 0o600);
  assert.doesNotMatch(`${JSON.stringify(identity)}\n${inspect(identity)}`, /PRIVATE FIXTURE/);
});

test('serializes concurrent creation and reuses the complete identity', async (t) => {
  const { root } = await createRoot(t);
  const calls = [];
  const store = new SshIdentityStore(root, { runProcess: fixtureRunner(calls, { delay: true }) });

  const [first, second] = await Promise.all([
    store.getOrCreate('dev_abc123'),
    new SshIdentityStore(root, { runProcess: fixtureRunner(calls) }).getOrCreate('dev_abc123'),
  ]);
  const reused = await new SshIdentityStore(root, {
    runProcess: fixtureRunner(calls),
  }).getOrCreate('dev_abc123');

  assert.equal(calls.filter(([, args]) => args[0] !== '-y').length, 1);
  assert.equal(calls.filter(([, args]) => args[0] === '-y').length, 3);
  assert.deepEqual(first, second);
  assert.deepEqual(first, reused);
});

test('getExisting reports a missing identity without creating paths or invoking ssh-keygen', async (t) => {
  const { parent, root } = await createRoot(t);
  const calls = [];
  const store = new SshIdentityStore(root, {
    runProcess: async (...args) => {
      calls.push(args);
      throw new Error('must not run');
    },
  });

  await assert.rejects(
    store.getExisting('dev_abc123'),
    (error) => error.code === 'SSH_IDENTITY_NOT_FOUND',
  );

  assert.deepEqual(calls, []);
  assert.deepEqual(await readdir(parent), []);
});

test('getExisting reuses the strict existing-pair validation without generating keys', async (t) => {
  const { root } = await createRoot(t);
  const deviceDirectory = join(root, 'dev_abc123');
  const privateKeyPath = join(deviceDirectory, 'id_ed25519');
  await mkdir(deviceDirectory, { recursive: true, mode: 0o700 });
  await writeFile(privateKeyPath, 'EXISTING PRIVATE\n', { mode: 0o600 });
  await writeFile(`${privateKeyPath}.pub`, `${publicLine()}\n`, { mode: 0o600 });
  const calls = [];
  const identity = await new SshIdentityStore(root, {
    runProcess: fixtureRunner(calls),
  }).getExisting('dev_abc123');

  assert.deepEqual(identity, {
    privateKeyPath,
    publicKeyPath: `${privateKeyPath}.pub`,
    publicKey: publicLine(),
  });
  assert.equal(Object.isFrozen(identity), true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0][1][0], '-y');
  assert.equal(calls.some(([, args]) => args.includes('-t')), false);

  await assert.rejects(
    new SshIdentityStore(root, {
      runProcess: fixtureRunner([], { derivedBlob: keyBlob(8) }),
    }).getExisting('dev_abc123'),
    (error) => error.code === 'SSH_IDENTITY_MISMATCH',
  );
});

test('getExisting waits for one concurrent getOrCreate transaction to publish the complete pair', async (t) => {
  const { root } = await createRoot(t);
  const privateWritten = deferred();
  const finishGeneration = deferred();
  const calls = [];
  const runner = async (command, args, options) => {
    calls.push([command, [...args], options]);
    if (args[0] === '-y') {
      return {
        exitCode: 0,
        signal: null,
        stdout: `ssh-ed25519 ${ed25519Blob} agent-road:dev_abc123\n`,
        stderr: '',
      };
    }

    const privatePath = args.at(-1);
    await writeFile(privatePath, 'CONCURRENT PRIVATE\n', { mode: 0o644 });
    privateWritten.resolve();
    await finishGeneration.promise;
    await writeFile(`${privatePath}.pub`, `${publicLine()}\n`, { mode: 0o644 });
    return { exitCode: 0, signal: null, stdout: '', stderr: '' };
  };
  const creating = new SshIdentityStore(root, { runProcess: runner })
    .getOrCreate('dev_abc123');
  await privateWritten.promise;

  const loadedOutcome = new SshIdentityStore(root, { runProcess: runner })
    .getExisting('dev_abc123')
    .then(
      (value) => ({ status: 'fulfilled', value }),
      (reason) => ({ status: 'rejected', reason }),
    );
  const beforePublication = await Promise.race([
    loadedOutcome,
    new Promise((resolve) => setTimeout(() => resolve({ status: 'pending' }), 50)),
  ]);
  finishGeneration.resolve();

  const created = await creating;
  const loaded = await loadedOutcome;
  assert.equal(beforePublication.status, 'pending');
  assert.equal(loaded.status, 'fulfilled');
  assert.deepEqual(loaded.value, created);
  assert.equal(calls.filter(([, args]) => args.includes('-t')).length, 1);
  assert.equal(calls.filter(([, args]) => args[0] === '-y').length, 2);
});

test('rejects invalid device ids before filesystem or runner access', async (t) => {
  const { root } = await createRoot(t);
  let calls = 0;
  const store = new SshIdentityStore(root, { runProcess: async () => { calls += 1; } });
  const invalid = ['dev_', 'DEV_abc', '../dev_abc', 'dev_a-b', `dev_${'a'.repeat(61)}`];

  for (const deviceId of invalid) {
    await assert.rejects(
      store.getOrCreate(deviceId),
      (error) => error.code === 'SSH_IDENTITY_DEVICE_ID_INVALID',
    );
  }
  assert.equal(calls, 0);
  assert.deepEqual(await readdir(join(root, '..')), []);
});

test('fails closed without altering pre-existing partial, symlink, or permissive identities', async (t) => {
  for (const kind of ['private-only', 'public-only', 'private-symlink', 'device-symlink', 'private-mode']) {
    await t.test(kind, async (t) => {
      const { parent, root } = await createRoot(t);
      const deviceDirectory = join(root, 'dev_abc123');
      const privatePath = join(deviceDirectory, 'id_ed25519');
      await mkdir(deviceDirectory, { recursive: true, mode: 0o700 });
      if (kind === 'private-only') await writeFile(privatePath, 'KEEP PRIVATE\n', { mode: 0o600 });
      if (kind === 'public-only') await writeFile(`${privatePath}.pub`, `${publicLine()}\n`, { mode: 0o600 });
      if (kind === 'private-symlink') {
        const target = join(parent, 'outside-key');
        await writeFile(target, 'KEEP TARGET\n', { mode: 0o600 });
        await symlink(target, privatePath);
        await writeFile(`${privatePath}.pub`, `${publicLine()}\n`, { mode: 0o600 });
      }
      if (kind === 'device-symlink') {
        await rm(deviceDirectory, { recursive: true });
        const outside = join(parent, 'outside-device');
        await mkdir(outside);
        await symlink(outside, deviceDirectory);
      }
      if (kind === 'private-mode') {
        await writeFile(privatePath, 'KEEP PRIVATE\n', { mode: 0o644 });
        await writeFile(`${privatePath}.pub`, `${publicLine()}\n`, { mode: 0o600 });
      }

      const beforePrivate = kind === 'private-only' || kind === 'private-mode'
        ? await readFile(privatePath, 'utf8')
        : null;
      await assert.rejects(
        new SshIdentityStore(root, { runProcess: async () => { throw new Error('must not run'); } }).getOrCreate('dev_abc123'),
        (error) => ['SSH_IDENTITY_PARTIAL', 'SSH_IDENTITY_UNSAFE_PATH', 'SSH_IDENTITY_PERMISSIONS'].includes(error.code),
      );
      if (beforePrivate !== null) assert.equal(await readFile(privatePath, 'utf8'), beforePrivate);
    });
  }
});

test('rejects malformed existing public keys without regeneration or deletion', async (t) => {
  const malformedLines = [
    `${publicLine()}\nsecond line`,
    publicLine().replace('ssh-ed25519', 'ssh-rsa'),
    publicLine().replace('agent-road:dev_abc123', 'agent-road:dev_other'),
    publicLine().replace(ed25519Blob, `${ed25519Blob}AAAA`),
    publicLine().replace(ed25519Blob, 'not_base64!'),
    `${publicLine()}\r`,
  ];

  for (const line of malformedLines) {
    await t.test(line.slice(0, 28), async (t) => {
      const { root } = await createRoot(t);
      const privatePath = join(root, 'dev_abc123', 'id_ed25519');
      await mkdir(join(root, 'dev_abc123'), { recursive: true, mode: 0o700 });
      await writeFile(privatePath, 'KEEP PRIVATE\n', { mode: 0o600 });
      await writeFile(`${privatePath}.pub`, `${line}\n`, { mode: 0o600 });
      await assert.rejects(
        new SshIdentityStore(root, { runProcess: async () => { throw new Error('must not run'); } }).getOrCreate('dev_abc123'),
        (error) => error.code === 'SSH_IDENTITY_PUBLIC_INVALID',
      );
      assert.equal(await readFile(privatePath, 'utf8'), 'KEEP PRIVATE\n');
      assert.equal(await readFile(`${privatePath}.pub`, 'utf8'), `${line}\n`);
    });
  }
});

test('rejects an overly permissive existing public key without reading or mutating the pair', async (t) => {
  const { root } = await createRoot(t);
  const privatePath = join(root, 'dev_abc123', 'id_ed25519');
  const publicKeyPath = `${privatePath}.pub`;
  await mkdir(join(root, 'dev_abc123'), { recursive: true, mode: 0o700 });
  await writeFile(privatePath, 'KEEP PRIVATE\n', { mode: 0o600 });
  await writeFile(publicKeyPath, `${publicLine()}\n`, { mode: 0o644 });

  await assert.rejects(
    new SshIdentityStore(root, {
      runProcess: async () => { throw new Error('must not run'); },
    }).getOrCreate('dev_abc123'),
    (error) => error.code === 'SSH_IDENTITY_PERMISSIONS',
  );
  assert.equal(await readFile(privatePath, 'utf8'), 'KEEP PRIVATE\n');
  assert.equal(await readFile(publicKeyPath, 'utf8'), `${publicLine()}\n`);
  assert.equal((await lstat(privatePath)).mode & 0o777, 0o600);
  assert.equal((await lstat(publicKeyPath)).mode & 0o777, 0o644);
});

test('rejects hardlinked SSH identity files before derivation or mutation', async (t) => {
  for (const key of ['private', 'public']) {
    await t.test(key, async (t) => {
      const { root } = await createRoot(t);
      const privatePath = join(root, 'dev_abc123', 'id_ed25519');
      const publicKeyPath = `${privatePath}.pub`;
      await mkdir(join(root, 'dev_abc123'), { recursive: true, mode: 0o700 });
      await writeFile(privatePath, 'KEEP PRIVATE\n', { mode: 0o600 });
      await writeFile(publicKeyPath, `${publicLine()}\n`, { mode: 0o600 });
      const path = key === 'private' ? privatePath : publicKeyPath;
      await link(path, join(root, `${key}-hardlink`));

      await assert.rejects(
        new SshIdentityStore(root, {
          runProcess: async () => { throw new Error('must not run'); },
        }).getOrCreate('dev_abc123'),
        (error) => error.code === 'SSH_IDENTITY_UNSAFE_PATH',
      );
      assert.equal((await lstat(path)).nlink, 2);
    });
  }
});

test('requires the private SSH key to derive the exact stored Ed25519 blob', async (t) => {
  await t.test('reused mismatch', async (t) => {
    const { root } = await createRoot(t);
    const privatePath = join(root, 'dev_abc123', 'id_ed25519');
    const publicKeyPath = `${privatePath}.pub`;
    await mkdir(join(root, 'dev_abc123'), { recursive: true, mode: 0o700 });
    await writeFile(privatePath, 'PRIVATE A\n', { mode: 0o600 });
    await writeFile(publicKeyPath, `${publicLine()}\n`, { mode: 0o600 });

    await assert.rejects(
      new SshIdentityStore(root, {
        runProcess: fixtureRunner([], { derivedBlob: keyBlob(8) }),
      }).getOrCreate('dev_abc123'),
      (error) => error.code === 'SSH_IDENTITY_MISMATCH',
    );
    assert.equal(await readFile(privatePath, 'utf8'), 'PRIVATE A\n');
    assert.equal(await readFile(publicKeyPath, 'utf8'), `${publicLine()}\n`);
  });

  await t.test('malformed private', async (t) => {
    const { root } = await createRoot(t);
    const privatePath = join(root, 'dev_abc123', 'id_ed25519');
    await mkdir(join(root, 'dev_abc123'), { recursive: true, mode: 0o700 });
    await writeFile(privatePath, 'MALFORMED PRIVATE\n', { mode: 0o600 });
    await writeFile(`${privatePath}.pub`, `${publicLine()}\n`, { mode: 0o600 });

    await assert.rejects(
      new SshIdentityStore(root, {
        runProcess: fixtureRunner([], {
          deriveResult: { exitCode: 1, signal: null, stdout: 'private bytes', stderr: 'private bytes' },
        }),
      }).getOrCreate('dev_abc123'),
      (error) => error.code === 'SSH_IDENTITY_PRIVATE_INVALID' && !inspect(error).includes('private bytes'),
    );
  });

  await t.test('non-Ed25519 private', async (t) => {
    const { root } = await createRoot(t);
    const privatePath = join(root, 'dev_abc123', 'id_ed25519');
    await mkdir(join(root, 'dev_abc123'), { recursive: true, mode: 0o700 });
    await writeFile(privatePath, 'RSA PRIVATE\n', { mode: 0o600 });
    await writeFile(`${privatePath}.pub`, `${publicLine()}\n`, { mode: 0o600 });

    await assert.rejects(
      new SshIdentityStore(root, {
        runProcess: fixtureRunner([], {
          deriveResult: { exitCode: 0, signal: null, stdout: 'ssh-rsa AAAA\n', stderr: '' },
        }),
      }).getOrCreate('dev_abc123'),
      (error) => error.code === 'SSH_IDENTITY_PRIVATE_INVALID',
    );
  });

  await t.test('newly generated mismatch is cleaned', async (t) => {
    const { root } = await createRoot(t);
    await assert.rejects(
      new SshIdentityStore(root, {
        runProcess: fixtureRunner([], { derivedBlob: keyBlob(8) }),
      }).getOrCreate('dev_abc123'),
      (error) => error.code === 'SSH_IDENTITY_MISMATCH',
    );
    assert.deepEqual(await readdir(join(root, 'dev_abc123')), []);
  });
});

test('rejects a private-path inode swap during public-key derivation', async (t) => {
  const { root } = await createRoot(t);
  const privatePath = join(root, 'dev_abc123', 'id_ed25519');
  await mkdir(join(root, 'dev_abc123'), { recursive: true, mode: 0o700 });
  await writeFile(privatePath, 'ORIGINAL PRIVATE\n', { mode: 0o600 });
  await writeFile(`${privatePath}.pub`, `${publicLine()}\n`, { mode: 0o600 });
  const runner = async (_command, args) => {
    assert.equal(args[0], '-y');
    await rename(privatePath, `${privatePath}.swapped`);
    await writeFile(privatePath, 'REPLACEMENT PRIVATE\n', { mode: 0o600 });
    return {
      exitCode: 0,
      signal: null,
      stdout: `ssh-ed25519 ${ed25519Blob}\n`,
      stderr: '',
    };
  };

  await assert.rejects(
    new SshIdentityStore(root, { runProcess: runner }).getOrCreate('dev_abc123'),
    (error) => error.code === 'SSH_IDENTITY_UNSAFE_PATH',
  );
});

test('rejects same-inode private mutation and growth during derivation', async (t) => {
  for (const kind of ['overwrite', 'growth']) {
    await t.test(kind, async (t) => {
      const { root } = await createRoot(t);
      const privatePath = join(root, 'dev_abc123', 'id_ed25519');
      await mkdir(join(root, 'dev_abc123'), { recursive: true, mode: 0o700 });
      await writeFile(privatePath, 'ORIGINAL PRIVATE\n', { mode: 0o600 });
      await writeFile(`${privatePath}.pub`, `${publicLine()}\n`, { mode: 0o600 });
      const runner = async (_command, args) => {
        assert.equal(args[0], '-y');
        const replacement = kind === 'growth'
          ? Buffer.alloc(64 * 1024 + 1, 0x41)
          : Buffer.from('MUTATED-PRIVATE\n');
        await writeFile(privatePath, replacement);
        return {
          exitCode: 0,
          signal: null,
          stdout: `ssh-ed25519 ${ed25519Blob} agent-road:dev_abc123\n`,
          stderr: '',
        };
      };

      await assert.rejects(
        new SshIdentityStore(root, { runProcess: runner }).getOrCreate('dev_abc123'),
        (error) => ['SSH_IDENTITY_UNSAFE_PATH', 'SSH_IDENTITY_PRIVATE_INVALID'].includes(error.code),
      );
    });
  }
});

test('revalidates public contents after private derivation awaits', async (t) => {
  const { root } = await createRoot(t);
  const privatePath = join(root, 'dev_abc123', 'id_ed25519');
  const publicKeyPath = `${privatePath}.pub`;
  await mkdir(join(root, 'dev_abc123'), { recursive: true, mode: 0o700 });
  await writeFile(privatePath, 'ORIGINAL PRIVATE\n', { mode: 0o600 });
  await writeFile(publicKeyPath, `${publicLine()}\n`, { mode: 0o600 });
  const runner = async () => {
    await writeFile(publicKeyPath, `${publicLine().replace(ed25519Blob, keyBlob(8))}\n`);
    return {
      exitCode: 0,
      signal: null,
      stdout: `ssh-ed25519 ${ed25519Blob} agent-road:dev_abc123\n`,
      stderr: '',
    };
  };

  await assert.rejects(
    new SshIdentityStore(root, { runProcess: runner }).getOrCreate('dev_abc123'),
    (error) => [
      'SSH_IDENTITY_UNSAFE_PATH',
      'SSH_IDENTITY_MISMATCH',
      'SSH_IDENTITY_PUBLIC_INVALID',
    ].includes(error.code),
  );
});

test('cleans newly-created key files on nonzero or thrown runner failures', async (t) => {
  await t.test('nonzero', async (t) => {
    const { root } = await createRoot(t);
    const calls = [];
    const runner = fixtureRunner(calls, {
      result: { exitCode: 1, signal: null, stdout: 'secret output', stderr: 'secret error' },
    });
    await assert.rejects(
      new SshIdentityStore(root, { runProcess: runner }).getOrCreate('dev_abc123'),
      (error) => error.code === 'SSH_IDENTITY_KEYGEN_FAILED' && !inspect(error).includes('secret'),
    );
    assert.deepEqual(await readdir(join(root, 'dev_abc123')), []);
  });

  await t.test('throw preserves primary error', async (t) => {
    const { root } = await createRoot(t);
    const primary = new Error('runner failed safely');
    const runner = async (_command, args) => {
      await writeFile(args.at(-1), 'NEW PRIVATE\n', { mode: 0o600 });
      throw primary;
    };
    await assert.rejects(
      new SshIdentityStore(root, { runProcess: runner }).getOrCreate('dev_abc123'),
      (error) => error === primary,
    );
    assert.deepEqual(await readdir(join(root, 'dev_abc123')), []);
  });
});

test('rejects an invalid generated public key and removes only new output', async (t) => {
  const { root } = await createRoot(t);
  await assert.rejects(
    new SshIdentityStore(root, {
      runProcess: fixtureRunner([], { line: `${publicLine()} trailing` }),
    }).getOrCreate('dev_abc123'),
    (error) => error.code === 'SSH_IDENTITY_PUBLIC_INVALID',
  );
  assert.deepEqual(await readdir(join(root, 'dev_abc123')), []);
});

test('reports a held identity lock as busy without deriving or changing keys', async (t) => {
  const { root } = await createRoot(t);
  const calls = [];
  const store = new SshIdentityStore(root, { runProcess: fixtureRunner(calls) });
  const identity = await store.getOrCreate('dev_abc123');
  const before = await readFile(identity.privateKeyPath);
  const count = calls.length;
  await withFileLock(identity.privateKeyPath, async () => {
    await assert.rejects(
      store.getExisting('dev_abc123'),
      (error) => error.code === 'SSH_IDENTITY_BUSY' && error.message === 'SSH_IDENTITY_BUSY',
    );
  });
  assert.equal(calls.length, count);
  assert.deepEqual(await readFile(identity.privateKeyPath), before);
  assert.deepEqual(await store.getExisting('dev_abc123'), identity);
});
