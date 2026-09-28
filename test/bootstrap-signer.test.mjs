import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  verify,
} from 'node:crypto';
import {
  chmod,
  link,
  lstat,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { inspect } from 'node:util';
import { promisify } from 'node:util';
import { dirname, join } from 'node:path';
import test from 'node:test';

import { BootstrapSigner } from '../src/identity/bootstrap-signer.mjs';

const execFile = promisify(execFileCallback);

async function createPaths(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-bootstrap-signer-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  return {
    root,
    privateKeyPath: join(root, 'identity', 'bootstrap-private.pem'),
    publicKeyPath: join(root, 'identity', 'bootstrap-public.json'),
  };
}

function signerFor(paths, options) {
  return new BootstrapSigner(paths.privateKeyPath, paths.publicKeyPath, options);
}

function publicPayload(publicKey) {
  const { n, e } = publicKey.export({ format: 'jwk' });
  return { algorithm: 'RSA-SHA256', modulusBase64Url: n, exponentBase64Url: e };
}

test('keeps tracked signer files clear of private-key credential markers', async () => {
  const privateKeyMarker = ['-----BEGIN ', 'PRIVATE KEY-----'].join('');
  const [source, tests] = await Promise.all([
    readFile(new URL('../src/identity/bootstrap-signer.mjs', import.meta.url), 'utf8'),
    readFile(new URL('./bootstrap-signer.test.mjs', import.meta.url), 'utf8'),
  ]);

  assert.equal(source.includes(privateKeyMarker), false);
  assert.equal(tests.includes(privateKeyMarker), false);
});

test('creates one owner-only RSA-3072 identity concurrently, reloads it, and signs bytes', async (t) => {
  const paths = await createPaths(t);
  const signer = signerFor(paths);

  const [first, concurrent] = await Promise.all([signer.getOrCreate(), signer.getOrCreate()]);
  const reloaded = await signerFor(paths).getOrCreate();

  assert.deepEqual(first, concurrent);
  assert.deepEqual(first, reloaded);
  assert.deepEqual(Object.keys(first), ['algorithm', 'modulusBase64Url', 'exponentBase64Url']);
  assert.equal(first.algorithm, 'RSA-SHA256');
  assert.equal(first.exponentBase64Url, 'AQAB');
  assert.equal(Object.isFrozen(first), true);
  assert.equal((await lstat(dirname(paths.privateKeyPath))).mode & 0o777, 0o700);
  assert.equal((await lstat(paths.privateKeyPath)).mode & 0o777, 0o600);
  assert.equal((await lstat(paths.publicKeyPath)).mode & 0o777, 0o600);

  const privatePem = await readFile(paths.privateKeyPath, 'utf8');
  const privateKey = createPrivateKey(privatePem);
  assert.equal(privateKey.asymmetricKeyType, 'rsa');
  assert.equal(privateKey.asymmetricKeyDetails.modulusLength, 3072);
  assert.equal(privatePem.startsWith(['-----BEGIN ', 'PRIVATE KEY-----'].join('')), true);
  assert.deepEqual(JSON.parse(await readFile(paths.publicKeyPath, 'utf8')), first);

  const bytes = Buffer.from('signed stage one');
  const signature = await signer.sign(bytes);
  assert.equal(Buffer.from(signature, 'base64').toString('base64'), signature);
  assert.equal(
    verify('RSA-SHA256', bytes, createPublicKey(privateKey), Buffer.from(signature, 'base64')),
    true,
  );
  assert.doesNotMatch(inspect(first), /BEGIN PRIVATE KEY|signed stage one/);
});

test('concurrent getOrCreate waits for a slow live repairing lock without leaving residue', async (t) => {
  const paths = await createPaths(t);
  let signalSlowOpen;
  const slowOpenStarted = new Promise((resolve) => { signalSlowOpen = resolve; });
  let delayed = false;
  const signer = signerFor(paths, {
    openFile: async (...args) => {
      if (!delayed) {
        delayed = true;
        signalSlowOpen();
        await new Promise((resolve) => setTimeout(resolve, 1_200));
      }
      return open(...args);
    },
  });

  const firstPending = signer.getOrCreate();
  await slowOpenStarted;
  const concurrentPending = signer.getOrCreate();
  const [first, concurrent] = await Promise.all([firstPending, concurrentPending]);

  assert.deepEqual(first, concurrent);
  const identityDirectory = dirname(paths.privateKeyPath);
  assert.equal((await lstat(identityDirectory)).mode & 0o777, 0o700);
  assert.equal((await lstat(paths.privateKeyPath)).mode & 0o777, 0o600);
  assert.equal((await lstat(paths.publicKeyPath)).mode & 0o777, 0o600);
  assert.equal(
    (await readdir(identityDirectory)).some((name) => name.endsWith('.lock')),
    false,
  );
});

test('existing-only identity reads and signs without creating or repairing filesystem state', async (t) => {
  const missingPaths = await createPaths(t);
  const missing = signerFor(missingPaths);
  await assert.rejects(
    missing.getExisting(),
    (error) => error.code === 'BOOTSTRAP_SIGNING_KEY_PARTIAL',
  );
  assert.deepEqual(await readdir(missingPaths.root), []);

  const paths = await createPaths(t);
  const signer = signerFor(paths);
  const expected = await signer.getOrCreate();
  const identityDirectory = dirname(paths.privateKeyPath);
  const beforeNames = (await readdir(identityDirectory)).sort();
  assert.deepEqual(await signer.getExisting(), expected);

  const bytes = Buffer.from('existing-only signature');
  const signature = await signer.signExisting(bytes, expected);
  const privateKey = createPrivateKey(await readFile(paths.privateKeyPath, 'utf8'));
  assert.equal(
    verify('RSA-SHA256', bytes, createPublicKey(privateKey), Buffer.from(signature, 'base64')),
    true,
  );
  assert.deepEqual((await readdir(identityDirectory)).sort(), beforeNames);

  const replacement = generateKeyPairSync('rsa', {
    modulusLength: 3072,
    publicExponent: 0x10001,
  });
  await assert.rejects(
    signer.signExisting(bytes, publicPayload(replacement.publicKey)),
    (error) => error.code === 'BOOTSTRAP_SIGNING_KEY_MISMATCH',
  );
  assert.deepEqual((await readdir(identityDirectory)).sort(), beforeNames);
});

test('existing-only identity validation rejects unsafe parent mode without repairing it', async (t) => {
  const paths = await createPaths(t);
  const signer = signerFor(paths);
  await signer.getOrCreate();
  const identityDirectory = dirname(paths.privateKeyPath);
  await chmod(identityDirectory, 0o777);

  await assert.rejects(
    signer.getExisting(),
    (error) => error.code === 'BOOTSTRAP_SIGNING_KEY_PERMISSIONS',
  );
  assert.equal((await lstat(identityDirectory)).mode & 0o777, 0o777);
});

test('rejects Darwin extended ACLs on the signer parent and both key files without repair', async (t) => {
  if (process.platform !== 'darwin') {
    t.skip('Darwin ACL semantics are unavailable');
    return;
  }

  for (const targetName of ['parent', 'private', 'public']) {
    await t.test(targetName, async (t) => {
      const paths = await createPaths(t);
      const signer = signerFor(paths);
      const expected = await signer.getOrCreate();
      const target = targetName === 'parent'
        ? dirname(paths.privateKeyPath)
        : paths[`${targetName}KeyPath`];
      const expectedMode = targetName === 'parent' ? 0o700 : 0o600;
      await execFile('/bin/chmod', ['+a', 'everyone allow read', target]);
      t.after(async () => {
        try { await execFile('/bin/chmod', ['-N', target]); } catch {}
      });

      for (const [operation, invoke] of [
        ['getOrCreate', () => signer.getOrCreate()],
        ['getExisting', () => signer.getExisting()],
        ['signExisting', () => signer.signExisting(Buffer.from('acl-bound'), expected)],
      ]) {
        await assert.rejects(
          invoke(),
          (error) => error.code === 'BOOTSTRAP_SIGNING_KEY_PERMISSIONS',
          `${targetName}:${operation}`,
        );
        assert.match(
          (await execFile('/bin/ls', ['-lde', '--', target])).stdout,
          /^\s+[0-9]+:\s/mu,
          `${targetName}:${operation}:ACL retained`,
        );
        assert.equal((await lstat(target)).mode & 0o777, expectedMode);
      }
    });
  }
});

test('existing-only identity rejects a symlinked parent path and preserves stable-read unsafe failures', async (t) => {
  const paths = await createPaths(t);
  await signerFor(paths).getOrCreate();
  const identityDirectory = dirname(paths.privateKeyPath);
  const realIdentityDirectory = `${identityDirectory}-real`;
  await rename(identityDirectory, realIdentityDirectory);
  await symlink(realIdentityDirectory, identityDirectory);
  await assert.rejects(
    signerFor(paths).getExisting(),
    (error) => error.code === 'BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE',
  );

  const stablePaths = await createPaths(t);
  await signerFor(stablePaths).getOrCreate();
  let privateStatCalls = 0;
  const racingSigner = signerFor(stablePaths, {
    openFile: async (...args) => {
      const handle = await open(...args);
      if (args[0] !== stablePaths.privateKeyPath) return handle;
      return {
        close: handle.close.bind(handle),
        read: handle.read.bind(handle),
        stat: async () => {
          const stats = await handle.stat();
          privateStatCalls += 1;
          if (privateStatCalls > 1) stats.mtimeMs += 1;
          return stats;
        },
      };
    },
  });
  await assert.rejects(
    racingSigner.getExisting(),
    (error) => error.code === 'BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE',
  );
});

test('reconciles a valid private key when only its public payload is missing', async (t) => {
  const paths = await createPaths(t);
  const signer = signerFor(paths);
  const original = await signer.getOrCreate();
  await rm(paths.publicKeyPath);

  assert.deepEqual(await signerFor(paths).getOrCreate(), original);
  assert.deepEqual(JSON.parse(await readFile(paths.publicKeyPath, 'utf8')), original);
});

test('fails closed on public-only and mismatched identity state', async (t) => {
  const paths = await createPaths(t);
  await writeFile(paths.publicKeyPath, '{}', { recursive: true }).catch(async () => {
    const { mkdir } = await import('node:fs/promises');
    await mkdir(dirname(paths.publicKeyPath), { recursive: true });
    await writeFile(paths.publicKeyPath, '{}');
  });
  await chmod(paths.publicKeyPath, 0o600);

  await assert.rejects(
    signerFor(paths).getOrCreate(),
    (error) => error.code === 'BOOTSTRAP_SIGNING_KEY_PARTIAL',
  );
  assert.equal(await readFile(paths.publicKeyPath, 'utf8'), '{}');

  await rm(paths.root, { recursive: true, force: true });
  const mismatchPaths = await createPaths(t);
  const signer = signerFor(mismatchPaths);
  await signer.getOrCreate();
  const payload = JSON.parse(await readFile(mismatchPaths.publicKeyPath, 'utf8'));
  payload.modulusBase64Url = 'AQID';
  await writeFile(mismatchPaths.publicKeyPath, `${JSON.stringify(payload)}\n`, { mode: 0o600 });
  await assert.rejects(
    signer.getOrCreate(),
    (error) => error.code === 'BOOTSTRAP_SIGNING_KEY_MISMATCH',
  );
});

test('rejects malformed public payloads, unsafe files, and permissive modes with stable codes', async (t) => {
  const cases = [
    ['extra public key', (payload) => ({ ...payload, extra: true }), 'BOOTSTRAP_SIGNING_KEY_PUBLIC_INVALID'],
    ['wrong algorithm', (payload) => ({ ...payload, algorithm: 'RSA-PSS' }), 'BOOTSTRAP_SIGNING_KEY_PUBLIC_INVALID'],
    ['wrong exponent', (payload) => ({ ...payload, exponentBase64Url: 'Aw' }), 'BOOTSTRAP_SIGNING_KEY_PUBLIC_INVALID'],
    ['noncanonical modulus', (payload) => ({ ...payload, modulusBase64Url: `${payload.modulusBase64Url}=` }), 'BOOTSTRAP_SIGNING_KEY_PUBLIC_INVALID'],
  ];

  for (const [name, mutate, code] of cases) {
    await t.test(name, async (t) => {
      const paths = await createPaths(t);
      const signer = signerFor(paths);
      const payload = await signer.getOrCreate();
      await writeFile(paths.publicKeyPath, `${JSON.stringify(mutate(payload))}\n`, { mode: 0o600 });
      await assert.rejects(signer.getOrCreate(), (error) => error.code === code);
    });
  }

  await t.test('public symlink', async (t) => {
    const paths = await createPaths(t);
    await signerFor(paths).getOrCreate();
    const target = join(paths.root, 'public-target.json');
    await rm(paths.publicKeyPath);
    await writeFile(target, '{}');
    await symlink(target, paths.publicKeyPath);
    await assert.rejects(
      signerFor(paths).getOrCreate(),
      (error) => error.code === 'BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE',
    );
  });

  await t.test('private mode', async (t) => {
    const paths = await createPaths(t);
    await signerFor(paths).getOrCreate();
    await chmod(paths.privateKeyPath, 0o644);
    await assert.rejects(
      signerFor(paths).getOrCreate(),
      (error) => error.code === 'BOOTSTRAP_SIGNING_KEY_PERMISSIONS',
    );
  });
});

test('rejects non-3072-bit and non-RSA private keys without leaking private material', async (t) => {
  for (const [name, type, options] of [
    ['rsa-2048', 'rsa', { modulusLength: 2048, publicExponent: 0x10001 }],
    ['rsa-4096', 'rsa', { modulusLength: 4096, publicExponent: 0x10001 }],
    ['ed25519', 'ed25519', {}],
  ]) {
    await t.test(name, async (t) => {
      const paths = await createPaths(t);
      const { privateKey, publicKey } = generateKeyPairSync(type, options);
      const pem = privateKey.export({ format: 'pem', type: 'pkcs8' });
      const { mkdir } = await import('node:fs/promises');
      await mkdir(dirname(paths.privateKeyPath), { recursive: true, mode: 0o700 });
      await writeFile(paths.privateKeyPath, pem, { mode: 0o600 });
      await writeFile(paths.publicKeyPath, `${JSON.stringify(publicPayload(publicKey))}\n`, { mode: 0o600 });

      await assert.rejects(
        signerFor(paths).getOrCreate(),
        (error) => {
          assert.equal(error.code, 'BOOTSTRAP_SIGNING_KEY_PRIVATE_INVALID');
          assert.doesNotMatch(`${error}\n${inspect(error)}`, /BEGIN PRIVATE KEY/);
          return true;
        },
      );
    });
  }
});

test('validates and snapshots bounded signing bytes before touching the filesystem', async (t) => {
  const paths = await createPaths(t);
  const signer = signerFor(paths);

  for (const input of ['text', new DataView(new ArrayBuffer(4)), Buffer.alloc(0), Buffer.alloc(1024 * 1024 + 1)]) {
    await assert.rejects(
      signer.sign(input),
      (error) => error.code === 'BOOTSTRAP_SIGNING_KEY_INPUT_INVALID',
    );
  }
  assert.deepEqual(await readdir(paths.root), []);

  const bytes = new Uint8Array(Buffer.from('original'));
  const pending = signer.sign(bytes);
  bytes.fill(0);
  const signature = await pending;
  const privateKey = createPrivateKey(await readFile(paths.privateKeyPath, 'utf8'));
  assert.equal(verify('RSA-SHA256', Buffer.from('original'), createPublicKey(privateKey), Buffer.from(signature, 'base64')), true);
});

test('preserves an atomic write failure when cleanup also fails', async (t) => {
  const paths = await createPaths(t);
  const writeError = new Error('write failed');
  const closeError = new Error('close failed');
  const signer = signerFor(paths, {
    openFile: async () => ({
      writeFile: async () => { throw writeError; },
      sync: async () => {},
      close: async () => { throw closeError; },
    }),
  });

  await assert.rejects(signer.getOrCreate(), (error) => error === writeError);
  assert.doesNotMatch(inspect(writeError), /BEGIN PRIVATE KEY/);
});

test('rejects hardlinked private and public identity files', async (t) => {
  for (const key of ['private', 'public']) {
    await t.test(key, async (t) => {
      const paths = await createPaths(t);
      await signerFor(paths).getOrCreate();
      const path = key === 'private' ? paths.privateKeyPath : paths.publicKeyPath;
      await link(path, join(paths.root, `${key}-hardlink`));

      await assert.rejects(
        signerFor(paths).getOrCreate(),
        (error) => error.code === 'BOOTSTRAP_SIGNING_KEY_UNSAFE_FILE',
      );
    });
  }
});

test('revalidates a replaced signing key under the signing lock', async (t) => {
  const paths = await createPaths(t);
  const signer = signerFor(paths);
  await signer.getOrCreate();
  const originalGetOrCreate = signer.getOrCreate.bind(signer);
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 3072,
    publicExponent: 0x10001,
  });
  const replacementPem = privateKey.export({ format: 'pem', type: 'pkcs8' });
  signer.getOrCreate = async () => {
    const publicIdentity = await originalGetOrCreate();
    await rm(paths.privateKeyPath);
    await writeFile(paths.privateKeyPath, replacementPem, { mode: 0o600 });
    return publicIdentity;
  };

  await assert.rejects(
    signer.sign(Buffer.from('must not sign with replacement')),
    (error) => error.code === 'BOOTSTRAP_SIGNING_KEY_MISMATCH',
  );
});

test('rejects public-key growth before signing without accepting oversized contents', async (t) => {
  const paths = await createPaths(t);
  const signer = signerFor(paths);
  await signer.getOrCreate();
  const originalGetOrCreate = signer.getOrCreate.bind(signer);
  signer.getOrCreate = async () => {
    const publicIdentity = await originalGetOrCreate();
    await writeFile(paths.publicKeyPath, Buffer.alloc(16 * 1024 + 1, 0x41), { mode: 0o600 });
    return publicIdentity;
  };

  await assert.rejects(
    signer.sign(Buffer.from('must not sign after public growth')),
    (error) => error.code === 'BOOTSTRAP_SIGNING_KEY_PUBLIC_INVALID',
  );
});
