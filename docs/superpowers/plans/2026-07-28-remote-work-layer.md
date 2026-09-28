# Agent Road Remote Work Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add pinned-host-key `exec`, `put`, and `get` commands that let the Mac controller complete a real file-and-development task on the enrolled Windows device without local Windows interaction.

**Architecture:** Extract the verifier's trust-material lifecycle into one internal SSH session module, then build focused remote-target, script-execution, and file-transfer modules on top. Runtime commands select a healthy registered Tailscale address before mutation, pin that address for one attempt, return bounded structured results, and preserve primary plus cleanup uncertainty.

**Tech Stack:** Node.js 22 ESM, built-in `node:test`, macOS `/usr/bin/ssh` and `/usr/bin/scp`, Windows OpenSSH, Windows PowerShell 5.1.

---

## File map

- Create `src/ssh/trusted-ssh-session.mjs`: shared trust validation, session snapshots, strict SSH/SCP options, locked invocation, and remote destination formatting.
- Modify `src/ssh/ssh-verifier.mjs`: consume the shared trusted session without changing verifier behavior.
- Create `src/remote/remote-target.mjs`: load and validate one ready Windows device plus its existing identity.
- Create `src/remote/local-file.mjs`: stable local-file snapshots and atomic local publication.
- Create `src/remote/windows-remote.mjs`: canonical Base64 JSON payloads, fixed PowerShell wrappers, address probe, and stable remote errors.
- Create `src/remote/remote-exec.mjs`: script staging, integrity verification, single execution, result, and cleanup.
- Create `src/remote/remote-files.mjs`: Windows path policy, `put`, `get`, integrity, publication, and cleanup.
- Modify `src/identity/ssh-identity-store.mjs`: add a non-creating `getExisting` path for runtime use.
- Modify `src/cli.mjs`: parse and run `exec`, `put`, and `get` with stable stdout/stderr and exit codes.
- Create tests matching each new module and update `test/ssh-verifier.test.mjs`, `test/cli-help.test.mjs`, and `test/cli-enrollment.test.mjs` only where existing behavior must remain visible.
- Modify `README.md`, `docs/windows-physical-acceptance.md`, and `CURRENT_STATE.md` after automated and physical acceptance.

### Task 1: Extract the shared trusted SSH session

**Files:**
- Create: `src/ssh/trusted-ssh-session.mjs`
- Create: `test/trusted-ssh-session.test.mjs`
- Modify: `src/ssh/ssh-verifier.mjs`
- Test: `test/ssh-verifier.test.mjs`

- [ ] **Step 1: Write the failing public-contract test**

Create a fixture with owner-only private-key and known-hosts files, then import the intended API:

```js
import { withTrustedSshSession } from '../src/ssh/trusted-ssh-session.mjs';

test('builds one immutable strict session and revalidates trust around invocation', async (t) => {
  const fixture = await trustedFixture(t);
  const calls = [];
  const value = await withTrustedSshSession({
    deviceId: 'dev_abc123',
    addresses: ['100.64.0.11'],
    hostKeys: [HOST_KEY],
    fingerprints: [FINGERPRINT],
    privateKeyPath: fixture.privateKeyPath,
    knownHostsPath: fixture.knownHostsPath,
    runProcess: trustedRunner(calls),
  }, async (session) => {
    assert.deepEqual(session.addresses, ['100.64.0.11']);
    return session.invokeSsh('100.64.0.11', ['powershell.exe', '-NoProfile']);
  });
  assert.equal(value.exitCode, 0);
  assert.equal(calls.some(({ args }) => args.includes('StrictHostKeyChecking=yes')), true);
  assert.equal(calls.some(({ args }) => args.includes('IdentityAgent=none')), true);
});
```

- [ ] **Step 2: Run the focused test and verify RED**

Run: `node --test test/trusted-ssh-session.test.mjs`  
Expected: FAIL because `src/ssh/trusted-ssh-session.mjs` does not exist.

- [ ] **Step 3: Move the verifier trust lifecycle behind the new API**

Expose only this runtime surface; keep validation helpers private:

```js
export async function withTrustedSshSession(input, operation) {
  const config = validateTrustedInput(snapshotTrustedInput(input));
  if (typeof operation !== 'function') throw trustedError('SSH_TRUST_INPUT_INVALID');
  return withFileLock(config.privateKeyPath, async () => {
    const trust = await openTrustedSnapshots(config);
    try {
      const session = Object.freeze({
        addresses: Object.freeze([...config.addresses]),
        invokeSsh: (address, remoteArgs, options) => invokeTrustedSsh(config, trust, address, remoteArgs, options),
        invokeScp: (args, options) => invokeTrustedScp(config, trust, args, options),
        invokeCleanup: (address, remoteArgs, options) => invokeTrustedCleanup(config, trust, address, remoteArgs, options),
        remoteSpec: (address, path) => remoteSpec(address, path),
      });
      return await operation(session);
    } finally {
      await closeTrustedSnapshots(trust);
    }
  }, { name: `SSH session ${config.deviceId}`, timeoutMs: 30_000, retryDelayMs: 10 });
}
```

The strict option list remains a single private constant in this module. Move, do not copy, the verifier's host-key validation, known-hosts generation, safe-file snapshots, and mutation checks.

- [ ] **Step 4: Rewire the verifier through `withTrustedSshSession`**

Keep `tryAddress` and its probe/round-trip semantics in the verifier, but accept the session:

```js
return withTrustedSshSession(config, async (session) => {
  for (const address of session.addresses) {
    try {
      await tryAddress(session, address);
      return Object.freeze({ address, capabilities: CAPABILITIES });
    } catch (error) {
      if (isNonRetryableVerifierError(error)) throw error;
    }
  }
  throw verifierError();
});
```

- [ ] **Step 5: Run focused and regression tests**

Run: `node --test test/trusted-ssh-session.test.mjs test/ssh-verifier.test.mjs`  
Expected: PASS, with the verifier tests proving no behavioral drift.

- [ ] **Step 6: Commit**

```bash
git add src/ssh/trusted-ssh-session.mjs src/ssh/ssh-verifier.mjs test/trusted-ssh-session.test.mjs test/ssh-verifier.test.mjs
git commit -m "refactor: share trusted SSH sessions"
```

### Task 2: Load an existing ready remote target without generating credentials

**Files:**
- Modify: `src/identity/ssh-identity-store.mjs`
- Modify: `test/ssh-identity-store.test.mjs`
- Create: `src/remote/remote-target.mjs`
- Create: `test/remote-target.test.mjs`

- [ ] **Step 1: Write failing identity and target tests**

```js
test('getExisting validates an existing pair but never creates a missing identity', async (t) => {
  const store = new SshIdentityStore(t.root, { runProcess: t.runProcess });
  await assert.rejects(store.getExisting('dev_abc123'), { code: 'SSH_IDENTITY_NOT_FOUND' });
  assert.equal(t.calls.some(({ args }) => args.includes('-t')), false);
});

test('loads only an explicitly ready Windows target with required capabilities', async () => {
  const target = await loadRemoteTarget('dev_abc123', dependencies(readyDevice));
  assert.equal(target.device.id, 'dev_abc123');
  assert.equal(target.identity.privateKeyPath.endsWith('id_ed25519'), true);
  await assert.rejects(loadRemoteTarget('dev_missing', dependencies(null)), { code: 'DEVICE_NOT_FOUND' });
  await assert.rejects(loadRemoteTarget('dev_abc123', dependencies({ ...readyDevice, status: 'ENROLLING' })), { code: 'DEVICE_NOT_READY' });
});
```

- [ ] **Step 2: Verify RED**

Run: `node --test test/ssh-identity-store.test.mjs test/remote-target.test.mjs`  
Expected: FAIL because `getExisting` and `loadRemoteTarget` do not exist.

- [ ] **Step 3: Implement non-creating identity load**

Refactor the current pair-validation body into one private method used by both public methods:

```js
async getExisting(inputDeviceId) {
  const paths = this.#devicePaths(validateDeviceId(inputDeviceId));
  return withFileLock(paths.privateKeyPath, async () => {
    const identity = await this.#loadValidatedPair(paths);
    if (identity === null) throw identityError('SSH_IDENTITY_NOT_FOUND');
    return identity;
  }, { name: `SSH identity ${inputDeviceId}` });
}
```

`getOrCreate` calls the same validator, but only it may reach `ssh-keygen`.

- [ ] **Step 4: Implement strict remote-target loading**

```js
export async function loadRemoteTarget(deviceId, { registry, sshIdentity, knownHostsPath }) {
  if (!DEVICE_ID_PATTERN.test(deviceId)) throw remoteError('REMOTE_INPUT_INVALID');
  const device = await registry.get(deviceId);
  if (!device) throw remoteError('DEVICE_NOT_FOUND');
  if (!READY_STATUSES.has(device.status)
      || device.targetPlatform !== 'windows'
      || !REQUIRED_CAPABILITIES.every((value) => device.capabilities.includes(value))
      || !device.transport) throw remoteError('DEVICE_NOT_READY');
  const identity = await sshIdentity.getExisting(deviceId);
  return Object.freeze({ device, identity, knownHostsPath: knownHostsPath(deviceId) });
}

export function trustedInput(target, runProcess) {
  return Object.freeze({
    deviceId: target.device.id,
    addresses: target.device.transport.tailscaleAddresses,
    hostKeys: target.device.transport.sshHostKeys,
    fingerprints: target.device.transport.sshHostKeyFingerprints,
    privateKeyPath: target.identity.privateKeyPath,
    knownHostsPath: target.knownHostsPath,
    runProcess,
  });
}
```

- [ ] **Step 5: Verify GREEN and commit**

Run: `node --test test/ssh-identity-store.test.mjs test/remote-target.test.mjs`  
Expected: PASS.

```bash
git add src/identity/ssh-identity-store.mjs src/remote/remote-target.mjs test/ssh-identity-store.test.mjs test/remote-target.test.mjs
git commit -m "feat: load ready remote targets"
```

### Task 3: Add safe local-file and Windows wrapper primitives

**Files:**
- Create: `src/remote/local-file.mjs`
- Create: `test/local-file.test.mjs`
- Create: `src/remote/windows-remote.mjs`
- Create: `test/windows-remote.test.mjs`

- [ ] **Step 1: Write failing primitive tests**

```js
test('snapshots one stable regular file with restrictive permissions and a digest', async (t) => {
  const snapshot = await snapshotLocalFile(t.source, { maximumBytes: 1024 });
  assert.equal(snapshot.bytes, 5);
  assert.match(snapshot.sha256, /^[A-F0-9]{64}$/);
  assert.equal((await lstat(snapshot.path)).mode & 0o777, 0o600);
  await snapshot.close();
});

test('encodes only canonical bounded JSON and builds fixed PowerShell argv', () => {
  const payload = encodeRemotePayload({ schemaVersion: 1, operationId: 'a'.repeat(32) });
  assert.deepEqual(decodeFixture(payload), { operationId: 'a'.repeat(32), schemaVersion: 1 });
  assert.deepEqual(powershellArgv(FIXED_WRAPPER, payload).slice(0, 4), [
    'powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
  ]);
});
```

Add negative fixtures for symlink, hardlink, changing file, zero/oversized file, accessor object, unknown JSON field, noncanonical operation ID, and raw path interpolation.

- [ ] **Step 2: Verify RED**

Run: `node --test test/local-file.test.mjs test/windows-remote.test.mjs`  
Expected: FAIL because both modules are absent.

- [ ] **Step 3: Implement stable local snapshots and atomic publication**

The module exports:

```js
export async function snapshotLocalFile(path, { minimumBytes = 1, maximumBytes }) {}
export async function snapshotBytes(bytes, { minimumBytes = 1, maximumBytes }) {}
export async function createLocalDestination(path, { overwrite, expectedBytes, expectedSha256 }) {}
```

Both open with `O_NOFOLLOW`, require `isFile()` and `nlink === 1`, compare file metadata around two reads, write owner-only temporary files, and expose idempotent `close()` cleanup. Destination publication verifies the downloaded size and SHA-256 before `rename`; overwrite first verifies the existing target is one regular non-symlink file.

- [ ] **Step 4: Implement canonical payload and fixed wrapper helpers**

```js
export function encodeRemotePayload(value) {
  const snapshot = validateExactPlainObject(structuredClone(value));
  const json = canonicalJson(snapshot);
  if (Buffer.byteLength(json) > 16 * 1024) throw remoteError('REMOTE_INPUT_INVALID');
  return Buffer.from(json, 'utf8').toString('base64');
}

export function powershellInvocation(wrapper, payload) {
  const source = validateTrustedAsciiWrapper(wrapper, payload, { maximumBytes: 32 * 1024 });
  return {
    argv: fixedPowerShellFrameBootstrapArgv,
    stdin: integrityCheckedLineFrame(source, { chunkCharacters: 2048, maximumBytes: 64 * 1024 }),
  };
}
```

Physical Windows transport diagnostics required replacing the original monolithic stdin reader with this integrity-checked frame over pinned-host-key authenticated SSH. The fixed bootstrap uses bounded `ReadLine()` calls for one magic/version line, canonical source length, uppercase SHA-256, the exact chunk count derived from Base64 length, chunks, and `END`; it canonical-reencodes and verifies the ASCII non-NUL bytes before creating a script block. It starts with silent progress handling, deliberately executes without waiting for EOF, and keeps the fixed argv below the `cmd.exe` limit. The controller emits no trailing bytes after `END`; only pre-`END` verified chunks are recovered as wrapper source, without asserting that a subsequently invoked script could never read separately supplied trailing stdin.

Also export `probeWindowsAdministrator(session, address)`, `selectAddress(session)`, and a mapper that turns pre-mutation process errors into `REMOTE_CONNECTION_FAILED` without exposing child messages:

```js
export async function selectAddress(session) {
  for (const address of session.addresses) {
    try {
      await probeWindowsAdministrator(session, address);
      return address;
    } catch {}
  }
  throw remoteError('REMOTE_CONNECTION_FAILED');
}
```

- [ ] **Step 5: Verify GREEN and commit**

Run: `node --test test/local-file.test.mjs test/windows-remote.test.mjs`  
Expected: PASS.

```bash
git add src/remote/local-file.mjs src/remote/windows-remote.mjs test/local-file.test.mjs test/windows-remote.test.mjs
git commit -m "feat: add bounded remote operation primitives"
```

### Task 4: Implement one-attempt remote PowerShell execution

**Files:**
- Create: `src/remote/remote-exec.mjs`
- Create: `test/remote-exec.test.mjs`

- [ ] **Step 1: Write the failing execution tests**

Cover a successful zero exit, a completed nonzero exit, UTF-8-to-UTF-16LE conversion, first-address probe failure followed by second-address selection, no fallback after upload, remote hash mismatch, timeout after staging, output overflow after staging, and primary-plus-cleanup failure.

```js
test('executes one staged script on the selected address and returns structured output', async (t) => {
  const result = await executeRemoteScript({
    target: t.target,
    scriptPath: t.scriptPath,
    timeoutMs: 300_000,
    dependencies: t.dependencies,
  });
  assert.deepEqual(result, {
    schemaVersion: 1,
    operation: 'exec',
    deviceId: 'dev_abc123',
    address: '100.64.0.11',
    exitCode: 0,
    stdout: 'built\r\n',
    stderr: '',
    startedAt: t.startedAt,
    finishedAt: t.finishedAt,
  });
  assert.equal(t.execCalls, 1);
  assert.equal(t.remoteFiles.size, 0);
});
```

- [ ] **Step 2: Verify RED**

Run: `node --test test/remote-exec.test.mjs`  
Expected: FAIL because `executeRemoteScript` does not exist.

- [ ] **Step 3: Implement the minimal state machine**

Use explicit phases:

```js
async function snapshotPowerShellScript(path) {
  const source = await snapshotLocalFile(path, { maximumBytes: 1024 * 1024 });
  try {
    const raw = await readFile(source.path);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
    if (text.includes('\0')) throw remoteError('REMOTE_INPUT_INVALID');
    const utf16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')]);
    return snapshotBytes(utf16, { maximumBytes: 2 * 1024 * 1024 + 2 });
  } finally {
    await source.close();
  }
}

const phase = Object.seal({ selected: false, staged: false, executionStarted: false });
return withTrustedSshSession(trustedInput(target, dependencies.runProcess), async (session) => {
  const address = await selectAddress(session);
  phase.selected = true;
  const script = await snapshotPowerShellScript(scriptPath);
  try {
    await stageVerifiedScript(session, address, operationId, script);
    phase.staged = true;
    phase.executionStarted = true;
    const processResult = await invokeStagedScript(session, address, operationId, timeoutMs);
    return execResult(target, address, processResult, clock);
  } catch (error) {
    throw mapExecFailure(error, phase);
  } finally {
    await cleanupStagedScriptPreservingPrimary(session, address, operationId);
    await script.close();
  }
});
```

The fixed wrapper validates the task root, file type, reparse attribute, byte hash, and admin identity before `& $path`; it captures no wrapper chatter. An uncertain process after `executionStarted` maps to `REMOTE_EXECUTION_UNCERTAIN` and never loops to another address.

- [ ] **Step 4: Verify GREEN and commit**

Run: `node --test test/remote-exec.test.mjs test/trusted-ssh-session.test.mjs`  
Expected: PASS.

```bash
git add src/remote/remote-exec.mjs test/remote-exec.test.mjs
git commit -m "feat: execute trusted remote PowerShell scripts"
```

### Task 5: Implement strict Windows path validation and `put`

**Files:**
- Create: `src/remote/remote-files.mjs`
- Create: `test/remote-files.test.mjs`

- [ ] **Step 1: Write failing path and upload tests**

```js
for (const invalid of ['relative.txt', '\\\\server\\share\\a', '\\\\?\\C:\\a', 'C:\\a:stream', 'C:\\ProgramData\\AgentRoad\\x']) {
  test(`rejects remote path ${JSON.stringify(invalid)}`, () => {
    assert.throws(() => validateWindowsFilePath(invalid), { code: 'REMOTE_INPUT_INVALID' });
  });
}

test('uploads to internal staging, verifies SHA-256, and atomically publishes once', async (t) => {
  const result = await putRemoteFile({ target: t.target, localPath: t.local, remotePath: 'D:\\work\\site.html', overwrite: false, dependencies: t.dependencies });
  assert.equal(result.operation, 'put');
  assert.equal(result.sha256, t.sha256);
  assert.equal(t.remote.get('D:\\work\\site.html').equals(t.bytes), true);
  assert.equal(t.publications, 1);
});
```

Add negative tests for missing parent, destination exists without `--overwrite`, existing directory/reparse destination, hash mismatch, disconnect before publication, disconnect after publication starts, and cleanup suffix preservation.

- [ ] **Step 2: Verify RED**

Run: `node --test test/remote-files.test.mjs`  
Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement path validation and upload publication**

```js
export function validateWindowsFilePath(value) {
  if (typeof value !== 'string' || !/^[A-Za-z]:\\[^\r\n\0*?"<>|]*$/u.test(value)) {
    throw remoteError('REMOTE_INPUT_INVALID');
  }
  if (value.slice(2).includes(':') || isReservedAgentRoadPath(value)) {
    throw remoteError('REMOTE_INPUT_INVALID');
  }
  return value;
}
```

`putRemoteFile` selects one address before staging, uploads only to a random internal name, and calls a fixed Base64-JSON publisher. The publisher canonicalizes the destination with `[IO.Path]::GetFullPath`, validates the parent and destination attributes, copies staging to a same-directory temporary file, verifies size/hash, then uses `Move` or `File.Replace`. Set `publicationStarted` immediately before the final filesystem mutation; later transport loss maps to `FILE_TRANSFER_UNCERTAIN` and is never retried.

- [ ] **Step 4: Verify GREEN and commit**

Run: `node --test test/remote-files.test.mjs`  
Expected: PASS for path and put tests.

```bash
git add src/remote/remote-files.mjs test/remote-files.test.mjs
git commit -m "feat: upload files to Windows safely"
```

### Task 6: Implement `get` with stable remote and local snapshots

**Files:**
- Modify: `src/remote/remote-files.mjs`
- Modify: `test/remote-files.test.mjs`

- [ ] **Step 1: Write failing download tests**

```js
test('downloads a remote snapshot, verifies integrity, and atomically publishes locally', async (t) => {
  const result = await getRemoteFile({ target: t.target, remotePath: 'D:\\work\\dist\\index.html', localPath: t.destination, overwrite: false, dependencies: t.dependencies });
  assert.equal(result.operation, 'get');
  assert.equal((await readFile(t.destination)).equals(t.bytes), true);
  assert.equal(result.sha256, t.sha256);
  assert.equal(t.remoteStaging.size, 0);
});
```

Add negative tests for remote missing/directory/reparse/oversized source, remote snapshot hash mismatch, corrupt SCP download, local destination exists without overwrite, local symlink/hardlink overwrite, local publication failure, and independent local/remote cleanup suffixes.

- [ ] **Step 2: Verify RED**

Run: `node --test --test-name-pattern='downloads|remote source|local destination' test/remote-files.test.mjs`  
Expected: FAIL because `getRemoteFile` is absent.

- [ ] **Step 3: Implement remote preparation and local publication**

```js
export async function getRemoteFile({ target, remotePath, localPath, overwrite, dependencies }) {
  const source = validateWindowsFilePath(remotePath);
  return withTrustedSshSession(trustedInput(target, dependencies.runProcess), async (session) => {
    const address = await selectAddress(session);
    const prepared = await prepareRemoteSnapshot(session, address, source, dependencies.operationId());
    let local;
    try {
      local = await createLocalDestination(localPath, { overwrite, expectedBytes: prepared.bytes, expectedSha256: prepared.sha256 });
      await session.invokeScp([session.remoteSpec(address, prepared.path), local.temporaryPath], transferOptions());
      await local.publish();
      return fileResult('get', target, address, prepared, source, localPath, dependencies.clock);
    } finally {
      await cleanupRemoteSnapshotPreservingPrimary(session, address, prepared.path);
      await local?.close();
    }
  });
}
```

- [ ] **Step 4: Verify GREEN and commit**

Run: `node --test test/remote-files.test.mjs test/local-file.test.mjs`  
Expected: PASS.

```bash
git add src/remote/remote-files.mjs test/remote-files.test.mjs
git commit -m "feat: download verified Windows files"
```

### Task 7: Wire the runtime commands into the CLI

**Files:**
- Modify: `src/cli.mjs`
- Modify: `test/cli-help.test.mjs`
- Create: `test/cli-remote-work.test.mjs`

- [ ] **Step 1: Write failing CLI tests**

```js
test('exec parses one device and one script and maps remote nonzero to CLI exit 1', async () => {
  const io = captureIo();
  const exitCode = await main(['exec', 'dev_abc123', '--script', '/tmp/task.ps1'], {}, {
    ...io,
    createRemoteDependencies: async () => fixtureDependencies,
    executeRemoteScript: async () => ({ ...EXEC_RESULT, exitCode: 7 }),
  });
  assert.equal(exitCode, 1);
  assert.deepEqual(JSON.parse(io.stdout()), { ...EXEC_RESULT, exitCode: 7 });
  assert.equal(io.stderr(), '');
});

test('prints only a stable operation code for infrastructure failures', async () => {
  const io = captureIo();
  const exitCode = await main(['put', 'dev_abc123', '/tmp/a', 'D:\\work\\a'], {}, {
    ...io,
    createRemoteDependencies: async () => fixtureDependencies,
    putRemoteFile: async () => { throw Object.assign(new Error('/private/path leaked'), { code: 'FILE_TRANSFER_FAILED' }); },
  });
  assert.equal(exitCode, 2);
  assert.equal(io.stdout(), '');
  assert.equal(io.stderr(), 'FILE_TRANSFER_FAILED\n');
});
```

Also test missing/extra positionals, unknown flags, timeout bounds, overwrite parsing, dependency failure redaction, exact one-line JSON, and updated help.

- [ ] **Step 2: Verify RED**

Run: `node --test test/cli-remote-work.test.mjs test/cli-help.test.mjs`  
Expected: FAIL because the commands are not registered.

- [ ] **Step 3: Add lightweight production dependencies**

Do not call the enrollment dependency factory. Add:

```js
export function createRemoteDependencies(env = process.env) {
  const paths = statePaths(env);
  return Object.freeze({
    registry: new DeviceRegistry(paths.devices),
    sshIdentity: new SshIdentityStore(paths.sshIdentities),
    knownHostsPath: (deviceId) => join(paths.knownHosts, `agent-road-known-hosts-${deviceId}`),
    runProcess,
    clock: () => new Date(),
    operationId: () => randomUUID().replaceAll('-', ''),
  });
}
```

- [ ] **Step 4: Parse and dispatch all three commands**

Use `parseArgs` with `allowPositionals: true` and strict options. Each branch loads the target once, calls its injected operation, writes exactly `JSON.stringify(result) + '\n'`, and maps errors only through an allowlisted stable-code extractor. Never include `error.message` unless it equals the allowlisted code.

- [ ] **Step 5: Verify GREEN and full regression**

Run: `node --test test/cli-remote-work.test.mjs test/cli-help.test.mjs test/cli-enrollment.test.mjs`  
Expected: PASS.

Run: `npm test`  
Expected: all tests pass except the existing local `pwsh` availability skip.

- [ ] **Step 6: Commit**

```bash
git add src/cli.mjs test/cli-remote-work.test.mjs test/cli-help.test.mjs test/cli-enrollment.test.mjs
git commit -m "feat: expose remote work commands"
```

### Task 8: Documentation, checkpoint, and physical acceptance

**Files:**
- Modify: `README.md`
- Modify: `docs/windows-physical-acceptance.md`
- Modify: `CURRENT_STATE.md`

- [ ] **Step 1: Document the exact CLI and boundaries**

Add paste-ready examples for `exec`, `put`, and `get`, the `0/1/2` exit convention, the default no-overwrite behavior, and the fact that GUI/browser control and automatic tool installation remain deferred.

- [ ] **Step 2: Run static and full automated verification**

Run: `npm test`  
Expected: zero failures, with only the pre-existing `pwsh` availability skip if `pwsh` is absent.

Run: `npm run check`  
Expected: exit 0.

Run: `git diff --check`  
Expected: exit 0.

- [ ] **Step 3: Perform the physical website task from the Mac**

Use the registered Windows device ID without printing its key material. From a private Mac temporary directory:

1. create an isolated static website fixture and a PowerShell task script;
2. run `exec` to create `C:\AgentRoad-Acceptance\website`;
3. use `put` for each source file;
4. run `exec` to inventory Git/Node, build the fixture, start a `127.0.0.1`-only temporary server, validate it with `Invoke-WebRequest`, and stop it;
5. use `get` to retrieve one build artifact and compare SHA-256;
6. run a cleanup script through `exec` and prove the temporary process, task script, and staging files are gone;
7. rerun the existing strict SSH verifier and confirm firewall, listener, Serve, and Funnel state did not widen.

Expected: all operations complete from the Mac with no Windows keyboard or desktop action.

- [ ] **Step 4: Update the acceptance evidence and checkpoint**

Record only bounded facts: Windows edition/build, operation result classes, hash equality, cleanup result, listener/firewall invariants, test counts, commit, and remaining platform matrix. Keep `CURRENT_STATE.md` at 30 lines or fewer and include the next unresolved step.

- [ ] **Step 5: Final review, commit, and push**

Review the complete diff for secrets and scope. Then:

```bash
git add README.md docs/windows-physical-acceptance.md CURRENT_STATE.md
git commit -m "docs: accept Windows remote work layer"
git push
```

Do not merge PR #1 or deploy anything as part of this task.
