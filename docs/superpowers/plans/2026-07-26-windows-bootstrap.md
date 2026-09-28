# Windows Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `agent-road enroll` into a one-command Windows 10/11 bootstrap that joins Tailscale interactively, configures a dedicated key-only OpenSSH administrator, and verifies pinned-key SSH from the Mac.

**Architecture:** The Mac runs a localhost-only Node receiver behind a temporary Tailnet-only Tailscale Serve route. A bounded PowerShell stage-zero installs or reuses Tailscale, performs browser login, exchanges the existing one-time token for a signed stage-one script and device SSH public key, then executes the verified stage one. The Windows stage configures a preserved `AgentRoad` account and OpenSSH path, posts host facts with a single-use completion ticket, and the Mac verifies SSH with strict host-key pinning.

**Tech Stack:** Node.js 22 standard library and `node:test`; Windows PowerShell 5.1; Windows Feature on Demand OpenSSH; Tailscale 1.98.9 full installer pinned by SHA-256; macOS `ssh-keygen` and `ssh`; no npm dependencies.

---

## Scope and acceptance boundary

This plan implements phase 2 only:

- Mac controller prerequisites and Tailnet-only enrollment receiver;
- persistent controller bootstrap-signing identity and per-device SSH identity;
- Windows stage-zero Tailscale install/login and signed stage-one retrieval;
- Windows 10 build 1809+/Windows 11 detection across Home and Pro;
- dedicated `AgentRoad` administrator, account-specific authorized key, OpenSSH service, and scoped firewall rule;
- completion reporting, pinned SSH verification, and a bidirectional file-transfer probe;
- accurate `CURRENT_STATE.md` handoff for a remote user.

Do not add Windows-MCP, RustDesk, browser control, interactive desktop control, watchdogs, auto-login, RDP policy, WinRE, alternate VPNs, VPS relays, or public Tailscale Funnel exposure.

The automated implementation may be completed on the Mac. Physical acceptance remains pending until the generated command is run on a supported Windows machine; documentation must not call the phase physically verified before that run.

## File map

- `config/releases.json` — pinned third-party installer metadata.
- `src/core/paths.mjs` — controller signing, SSH identity, known-host, and journal paths.
- `src/core/device-model.mjs` — statuses and validated non-secret Windows/SSH metadata.
- `src/process/run-process.mjs` — injected no-shell child-process adapter with timeout and bounded output.
- `src/tailscale/tailscale-adapter.mjs` — Mac Tailscale status and unique Serve route lifecycle.
- `src/identity/bootstrap-signer.mjs` — persistent RSA-3072 signing key and RSA-SHA256 signatures.
- `src/identity/ssh-identity-store.mjs` — per-device Ed25519 keys created by `ssh-keygen`.
- `src/enrollment/completion-ticket-store.mjs` — in-memory, hash-only, expiring single-use completion tickets.
- `src/enrollment/enrollment-receiver.mjs` — strict localhost HTTP exchange and completion protocol.
- `src/enrollment/windows-stage-zero.mjs` — bounded encoded PowerShell loader.
- `windows/bootstrap-stage-one.ps1` — verified Windows account/OpenSSH/bootstrap implementation.
- `src/ssh/ssh-verifier.mjs` — host-key material validation, administrative probe, and SFTP/SCP round trip.
- `src/enrollment/run-windows-enrollment.mjs` — end-to-end controller orchestration and cleanup.
- `src/cli.mjs` — interactive `enroll` integration and stable diagnostics.
- `test/*.test.mjs` — isolated tests for each controller boundary and source-contract tests for PowerShell.

### Task 1: Extend validated state for bootstrap metadata

**Files:**
- Modify: `src/core/paths.mjs`
- Modify: `src/core/device-model.mjs`
- Modify: `src/storage/device-registry.mjs`
- Test: `test/device-model.test.mjs`
- Test: `test/device-registry.test.mjs`

- [ ] **Step 1: Write failing model and registry tests**

Add tests that require the following exact optional metadata shape and reject every unknown nested type, secret-shaped key, invalid IP, invalid fingerprint, or non-canonical timestamp:

```js
const connectedWindows = {
  ...validWindowsRecord,
  status: 'CONNECTED_SSH_ONLY',
  capabilities: ['ssh', 'sftp', 'admin-powershell'],
  target: {
    version: '10.0.19045',
    build: 19045,
    edition: 'Professional',
    architecture: 'AMD64',
  },
  transport: {
    tailscaleAddresses: ['100.64.0.10', 'fd7a:115c:a1e0::10'],
    sshUsername: 'AgentRoad',
    sshHostKeys: ['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest host'],
    sshHostKeyFingerprints: ['SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'],
  },
};

test('validates connected Windows metadata and updates it atomically', async () => {
  await registry.add(validWindowsRecord);
  const saved = await registry.replace(connectedWindows);
  assert.deepEqual(saved, connectedWindows);
  assert.deepEqual(await registry.get(validWindowsRecord.id), connectedWindows);
});
```

Add `TAILSCALE_SERVE_AUTH_REQUIRED`, `TAILSCALE_LOGIN_REQUIRED`, `SSH_VERIFY_FAILED`, and `BOOTSTRAP_FAILED` to the expected status array.

- [ ] **Step 2: Run the focused tests and confirm RED**

Run:

```bash
node --test test/device-model.test.mjs test/device-registry.test.mjs
```

Expected: failures for the missing statuses, optional metadata validation, and `DeviceRegistry.replace`.

- [ ] **Step 3: Implement the minimal validated schema and atomic replace**

Extend `statePaths()` with deterministic owner-only locations:

```js
signingPrivateKey: join(root, 'identity', 'bootstrap-signing-private.pem'),
signingPublicKey: join(root, 'identity', 'bootstrap-signing-public.json'),
sshIdentities: join(root, 'identity', 'devices'),
knownHosts: join(root, 'known-hosts'),
```

In `validateDeviceRecord`, accept `target` and `transport` only when all fields match the shape in Step 1. Validate IPs with `node:net.isIP`, require `sshUsername === 'AgentRoad'`, require each host key to start with `ssh-ed25519 `, and require fingerprints to match `/^SHA256:[A-Za-z0-9+/]{43}$/`. Clone and freeze both nested records and their arrays.

Implement `DeviceRegistry.replace(input)` under the existing file lock:

```js
async replace(input) {
  const snapshot = structuredClone(input);
  const replacement = validateDeviceRecord(snapshot);
  return withFileLock(this.path, async () => {
    const devices = await this.list();
    const index = devices.findIndex(({ id }) => id === replacement.id);
    if (index === -1) throw new Error(`device not found: ${replacement.id}`);
    devices[index] = replacement;
    await writeJsonAtomic(this.path, { devices });
    return cloneDevice(replacement);
  }, { name: 'device registry' });
}
```

- [ ] **Step 4: Run focused and full tests**

Run:

```bash
node --test test/device-model.test.mjs test/device-registry.test.mjs
npm test
```

Expected: all tests pass, including the original registry concurrency tests.

- [ ] **Step 5: Commit Task 1**

```bash
git add src/core/paths.mjs src/core/device-model.mjs src/storage/device-registry.mjs test/device-model.test.mjs test/device-registry.test.mjs
git commit -m "feat: model Windows bootstrap state"
```

### Task 2: Add a bounded no-shell process runner

**Files:**
- Create: `src/process/run-process.mjs`
- Create: `test/run-process.test.mjs`

- [ ] **Step 1: Write failing process-runner tests**

Cover exact argv preservation, stdout/stderr capture, non-zero exit, timeout termination, spawn failure, and a 1 MiB output cap. The public result must be:

```js
{
  command: '/usr/bin/example',
  args: ['literal;not-shell'],
  exitCode: 0,
  signal: null,
  stdout: 'ok\n',
  stderr: '',
}
```

Assert that `shell` is always `false`, injected child processes receive no enrollment token through logging, and timeout errors use code `PROCESS_TIMEOUT`.

- [ ] **Step 2: Run the focused test and confirm RED**

```bash
node --test test/run-process.test.mjs
```

Expected: module-not-found failure.

- [ ] **Step 3: Implement `runProcess`**

Export:

```js
export async function runProcess(command, args, {
  spawnProcess = spawn,
  timeoutMs = 30_000,
  maxOutputBytes = 1024 * 1024,
  env = process.env,
} = {})
```

Use `spawnProcess(command, [...args], { shell: false, stdio: ['ignore', 'pipe', 'pipe'], env })`. Count raw Buffer lengths before UTF-8 decoding, reject overflow with `PROCESS_OUTPUT_LIMIT`, send `SIGTERM` on timeout, and preserve the primary failure if cleanup also fails. Never interpolate argv into a shell string or include environment values in errors.

- [ ] **Step 4: Verify and commit**

```bash
node --test test/run-process.test.mjs
npm test
git add src/process/run-process.mjs test/run-process.test.mjs
git commit -m "feat: add bounded process execution"
```

### Task 3: Implement the Mac Tailscale adapter and Serve lifecycle

**Files:**
- Create: `src/tailscale/tailscale-adapter.mjs`
- Create: `test/tailscale-adapter.test.mjs`

- [ ] **Step 1: Write failing adapter tests**

Inject `runProcess` and test these contracts:

```js
const adapter = new TailscaleAdapter({ runProcess, executable: '/mock/tailscale' });
assert.deepEqual(await adapter.status(), {
  backendState: 'Running',
  dnsName: 'alex-mac.example.ts.net',
  tailscaleIPs: ['100.64.0.1'],
});

const route = await adapter.serve({
  deviceId: 'dev_abc123',
  localPort: 43123,
});
assert.deepEqual(route, {
  baseUrl: 'https://alex-mac.example.ts.net/agent-road/v1/dev_abc123',
  path: '/agent-road/v1/dev_abc123',
  localPort: 43123,
});
await route.close();
```

Assert exact argv:

```text
serve --bg --yes --https=443 --set-path=/agent-road/v1/dev_abc123 http://127.0.0.1:43123
serve --https=443 --set-path=/agent-road/v1/dev_abc123 off
```

Reject non-Running state with `TAILSCALE_NOT_RUNNING_ON_MAC`, missing executable with `TAILSCALE_NOT_AVAILABLE_ON_MAC`, malformed/non-`ts.net` DNS names, non-loopback proxy targets, and Serve output that requests consent with `TAILSCALE_SERVE_AUTH_REQUIRED`. Verify cleanup runs once and never calls `serve reset` or `funnel`.

- [ ] **Step 2: Run the focused test and confirm RED**

```bash
node --test test/tailscale-adapter.test.mjs
```

Expected: module-not-found failure.

- [ ] **Step 3: Implement `TailscaleAdapter`**

Resolve the executable from an injected value or these exact candidates, without shell lookup. A fixed candidate may be a symlink (as with common Homebrew installs), but it must be resolved with `realpath` and the resolved target must be a regular executable file:

```js
[
  '/Applications/Tailscale.app/Contents/MacOS/Tailscale',
  '/opt/homebrew/bin/tailscale',
  '/usr/local/bin/tailscale',
  '/usr/bin/tailscale',
]
```

`status()` runs `status --json`, parses one JSON object, requires `BackendState === 'Running'`, canonicalizes `Self.DNSName` by removing one terminal dot, and accepts only `*.ts.net`. Before setup, `serve()` queries exact JSON status for both Serve and Funnel and fails closed if either has any existing configuration. It then creates only the unique path above and returns an idempotent `close()` closure that disables exactly that path.

Map known Serve consent output containing an HTTPS enablement URL to an error with code `TAILSCALE_SERVE_AUTH_REQUIRED` and the non-secret consent URL in `error.details`.

- [ ] **Step 4: Verify and commit**

```bash
node --test test/tailscale-adapter.test.mjs
npm test
git add src/tailscale/tailscale-adapter.mjs test/tailscale-adapter.test.mjs
git commit -m "feat: manage Tailnet enrollment routes"
```

### Task 4: Add controller signing and per-device SSH identities

**Files:**
- Create: `src/identity/bootstrap-signer.mjs`
- Create: `src/identity/ssh-identity-store.mjs`
- Create: `test/bootstrap-signer.test.mjs`
- Create: `test/ssh-identity-store.test.mjs`

- [ ] **Step 1: Write failing identity tests**

For the bootstrap signer, assert first use creates a 3072-bit RSA key, private file mode `0600`, public JSON mode `0600`, and subsequent use returns the same public modulus/exponent. Verify signatures with Node `verify('RSA-SHA256', stageOneBytes, publicKey, signatureBytes)`.

The public payload is exact:

```js
{
  algorithm: 'RSA-SHA256',
  modulusBase64Url: '<base64url>',
  exponentBase64Url: 'AQAB',
}
```

For SSH identities, inject the process runner and assert exact creation argv:

```js
['-q', '-t', 'ed25519', '-N', '', '-C', 'agent-road:dev_abc123', '-f', privatePath]
```

Reject symlinks, pre-existing partial key pairs, public keys not matching one `ssh-ed25519` line, and paths outside the configured identity root. Reusing a complete pair must not regenerate it.

- [ ] **Step 2: Run focused tests and confirm RED**

```bash
node --test test/bootstrap-signer.test.mjs test/ssh-identity-store.test.mjs
```

Expected: module-not-found failures.

- [ ] **Step 3: Implement `BootstrapSigner`**

Use `generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 0x10001 })`, export the private key as PKCS#8 PEM, and extract JWK `n`/`e` from the public key. Persist both files with the existing crash-durable atomic writer or an equivalent owner-only atomic byte writer. Export:

```js
await signer.getOrCreate();
await signer.sign(stageOneBytes); // returns base64 signature
```

On reload, derive the public JWK from the private key and require it to equal the public JSON file; mismatch fails closed with `BOOTSTRAP_SIGNING_KEY_MISMATCH`.

- [ ] **Step 4: Implement `SshIdentityStore`**

Create `join(root, deviceId, 'id_ed25519')` and its `.pub` sibling under a device directory with mode `0700`. Use `/usr/bin/ssh-keygen` by default, never a shell. After creation, `lstat` both paths, reject symlinks, chmod private/public to `0600`, and return:

```js
{
  privateKeyPath,
  publicKeyPath,
  publicKey: publicLine.trim(),
}
```

- [ ] **Step 5: Verify and commit**

```bash
node --test test/bootstrap-signer.test.mjs test/ssh-identity-store.test.mjs
npm test
git add src/identity/bootstrap-signer.mjs src/identity/ssh-identity-store.mjs test/bootstrap-signer.test.mjs test/ssh-identity-store.test.mjs
git commit -m "feat: create controller and device identities"
```

### Task 5: Pin and validate the Tailscale installer manifest

**Files:**
- Create: `config/releases.json`
- Create: `src/releases/release-manifest.mjs`
- Create: `test/release-manifest.test.mjs`

- [ ] **Step 1: Write failing strict-manifest tests**

Require exactly this production manifest:

```json
{
  "schemaVersion": 1,
  "tailscaleWindows": {
    "version": "1.98.9",
    "url": "https://pkgs.tailscale.com/stable/tailscale-setup-full-1.98.9.exe",
    "sha256": "b3f7e15eb33b90f0686d6037453a0c680c3553b55deca649b56b6b05635c9e7b",
    "authenticodeSubject": "CN=Tailscale Inc."
  }
}
```

Tests reject additional properties, non-HTTPS or non-`pkgs.tailscale.com` URLs, non-versioned filenames, mismatched version in URL, invalid lowercase SHA-256, and signer subjects other than the exact allowlisted value.

- [ ] **Step 2: Run the focused test and confirm RED**

```bash
node --test test/release-manifest.test.mjs
```

Expected: manifest/module missing.

- [ ] **Step 3: Add the manifest and loader**

Implement `loadReleaseManifest(path)` using `readFile` and an exact-key validator. Return a deeply frozen copy. Do not accept a runtime CLI override for URL, digest, version, or signer.

- [ ] **Step 4: Verify the upstream checksum and tests**

Run:

```bash
test "$(curl -fsSL https://pkgs.tailscale.com/stable/tailscale-setup-full-1.98.9.exe.sha256)" = "b3f7e15eb33b90f0686d6037453a0c680c3553b55deca649b56b6b05635c9e7b"
node --test test/release-manifest.test.mjs
npm test
```

Expected: checksum comparison and all tests pass.

- [ ] **Step 5: Commit Task 5**

```bash
git add config/releases.json src/releases/release-manifest.mjs test/release-manifest.test.mjs
git commit -m "feat: pin Windows Tailscale release"
```

### Task 6: Implement single-use completion tickets and the enrollment receiver

**Files:**
- Create: `src/enrollment/completion-ticket-store.mjs`
- Create: `src/enrollment/enrollment-receiver.mjs`
- Create: `test/completion-ticket-store.test.mjs`
- Create: `test/enrollment-receiver.test.mjs`

- [ ] **Step 1: Write failing completion-ticket tests**

Use deterministic time/random injection. `issue(deviceId, 10 * 60 * 1000)` returns a 32-byte base64url ticket. Store only SHA-256 hashes in memory. `consume(rawTicket, deviceId)` succeeds once, rejects expiry, wrong device, clock rollback, and concurrent double consumption. Expose no method that returns raw stored tickets.

- [ ] **Step 2: Write failing receiver protocol tests**

Start the receiver on injected host `127.0.0.1` and port `0`. Test only these exact endpoints under a device path:

```text
POST /agent-road/v1/dev_abc123/exchange
POST /agent-road/v1/dev_abc123/complete
```

Exchange request exact schema:

```json
{"protocolVersion":1,"deviceId":"dev_abc123","token":"raw-one-use-token"}
```

Exchange response exact schema:

```json
{
  "protocolVersion": 1,
  "deviceId": "dev_abc123",
  "sshPublicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBsAFEQvB0i0RoR9qkqCHDw5BDzQPE+4wP3ScuwRjJCm agent-road:dev_abc123",
  "stageOneBase64": "V3JpdGUtT3V0cHV0ICdPSycK",
  "stageOneSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "stageOneSignatureBase64": "c2lnbmF0dXJl",
  "completionTicket": "ttttttttttttttttttttttttttttttttttttttttttt"
}
```

Completion request exact schema:

```json
{
  "protocolVersion": 1,
  "deviceId": "dev_abc123",
  "completionTicket": "ttttttttttttttttttttttttttttttttttttttttttt",
  "target": {
    "version": "10.0.19045",
    "build": 19045,
    "edition": "Professional",
    "architecture": "AMD64"
  },
  "tailscaleAddresses": ["100.64.0.10"],
  "sshHostKeys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBsAFEQvB0i0RoR9qkqCHDw5BDzQPE+4wP3ScuwRjJCm agent-road:dev_abc123"],
  "sshHostKeyFingerprints": ["SHA256:3vIF45tPRtGVuJ3VsSRd0MvFQ87Y38vAnRqfFdNcsYM"],
  "checkpoints": ["preflight", "tailscale", "openssh", "account", "firewall"]
}
```

Require localhost binding, POST only, `application/json`, 64 KiB body limit, ten-second request timeout, exact content length handling, exact object keys, bounded strings/arrays, canonical IPs, and redacted errors. Assert the token is consumed before the response and the completion ticket only once. Concurrent valid completion calls must yield one success.

- [ ] **Step 3: Run focused tests and confirm RED**

```bash
node --test test/completion-ticket-store.test.mjs test/enrollment-receiver.test.mjs
```

Expected: module-not-found failures.

- [ ] **Step 4: Implement the stores and receiver**

`startEnrollmentReceiver(options)` accepts already-created `tokenStore`, `completionTickets`, `deviceId`, `sshPublicKey`, `stageOneBytes`, and `signer`. It computes SHA-256 and signature once, starts `node:http.createServer` on `127.0.0.1`, and returns:

```js
{
  port,
  waitForCompletion({ timeoutMs }),
  close(),
}
```

Use fixed public responses such as `{"error":"invalid enrollment request"}`; never echo parser errors, raw request bodies, tokens, tickets, or signatures. `waitForCompletion` resolves one validated completion snapshot and rejects with `ENROLLMENT_TIMEOUT` on timeout.

- [ ] **Step 5: Verify and commit**

```bash
node --test test/completion-ticket-store.test.mjs test/enrollment-receiver.test.mjs
npm test
git add src/enrollment/completion-ticket-store.mjs src/enrollment/enrollment-receiver.mjs test/completion-ticket-store.test.mjs test/enrollment-receiver.test.mjs
git commit -m "feat: receive Tailnet enrollment sessions"
```

### Task 7: Build the bounded PowerShell stage-zero loader

**Files:**
- Create: `src/enrollment/windows-stage-zero.mjs`
- Modify: `src/enrollment/powershell-command.mjs`
- Modify: `test/powershell-command.test.mjs`
- Create: `test/windows-stage-zero.test.mjs`

- [ ] **Step 1: Write failing loader tests**

Decode the generated UTF-16LE `EncodedCommand` and assert it contains all of these concrete behaviors:

- administrator check using `WindowsPrincipal.IsInRole(Administrator)`;
- build detection from `Win32_OperatingSystem` and rejection below `17763`;
- PowerShell major version check at least 5;
- existing Tailscale lookup in `C:\Program Files\Tailscale\tailscale.exe`;
- pinned `https://pkgs.tailscale.com/stable/tailscale-setup-full-1.98.9.exe` download;
- SHA-256 equality with the manifest;
- `Get-AuthenticodeSignature` requiring `Valid` and exact `CN=Tailscale Inc.` subject;
- unattended install with `Start-Process -Wait -PassThru` and checked exit code;
- a fresh install uses `tailscale up --hostname=agent-road-abc123 --unattended=true` without an auth key for sample device `dev_abc123`;
- a valid existing logged-in installation uses `tailscale set --unattended=true` and does not replace its hostname or unspecified preferences;
- the short-lived login URL is parsed and opened with `Start-Process` but never copied into the bootstrap journal or controller logs;
- bounded wait for `tailscale status --json` BackendState `Running`;
- exchange POST with `MaximumRedirection 0` and timeout;
- exact response key/type checks;
- SHA-256 and RSA-SHA256 stage-one verification;
- in-memory `[ScriptBlock]::Create` execution;
- fixed user-facing status lines that never contain token or completion ticket.

Assert malicious URLs, signer fields, public-key numbers, device IDs, command overflow, newline injection, and non-plain payload objects are rejected before serialization. Assert the final command is at most 32767 characters.

- [ ] **Step 2: Run focused tests and confirm RED**

```bash
node --test test/windows-stage-zero.test.mjs test/powershell-command.test.mjs
```

Expected: missing module/new-contract failures.

- [ ] **Step 3: Implement the new builder**

Export:

```js
buildWindowsStageZeroCommand({
  controllerBaseUrl,
  deviceId,
  token,
  signingPublicKey,
  releaseManifest,
})
```

Snapshot each primitive once, validate exact plain objects, and serialize a new allowlisted payload. Embed it as UTF-8 Base64 inside the PowerShell script. Reuse the hardened URL checks but require the path to equal `/agent-road/v1/${deviceId}` after substituting the validated device ID and require the host to end in `.ts.net`.

PowerShell must construct the RSA public key from the embedded base64url modulus/exponent via `RSAParameters`, use `RSACryptoServiceProvider(3072)`, and call `VerifyData(stageOneBytes, 'SHA256', signatureBytes)`. Convert base64url to bytes with explicit padding; do not rely on PowerShell 7 APIs.

Keep the existing `buildPowerShellEnrollmentCommand` compatibility export and its tests unchanged in this task so the full suite remains green. Task 10 switches production enrollment to `buildWindowsStageZeroCommand`; only then may obsolete immediate-POST wiring be removed after its callers and tests have migrated.

- [ ] **Step 4: Verify and commit**

```bash
node --test test/windows-stage-zero.test.mjs test/powershell-command.test.mjs
npm test
git add src/enrollment/windows-stage-zero.mjs src/enrollment/powershell-command.mjs test/windows-stage-zero.test.mjs test/powershell-command.test.mjs
git commit -m "feat: build signed Windows bootstrap loader"
```

### Task 8: Implement the idempotent Windows stage-one bootstrap

**Files:**
- Create: `windows/bootstrap-stage-one.ps1`
- Create: `test/windows-stage-one-source.test.mjs`

- [ ] **Step 1: Write failing PowerShell source-contract tests**

Read the script as text and assert one implementation exists for each named function:

```text
Assert-Administrator
Get-AgentRoadSystemFacts
Enter-AgentRoadBootstrapLock
Read-AgentRoadJournal
Write-AgentRoadJournal
Complete-AgentRoadCheckpoint
Backup-AgentRoadFile
Ensure-AgentRoadAccount
Ensure-AgentRoadAuthorizedKey
Ensure-AgentRoadSshdConfiguration
Ensure-AgentRoadSshdService
Ensure-AgentRoadFirewallRule
Get-AgentRoadHostKeys
Send-AgentRoadCompletion
Restore-AgentRoadChanges
```

Assert the script:

- uses `C:\ProgramData\AgentRoad\bootstrap` and an exclusive lock file;
- applies administrator/SYSTEM-only ACLs with `icacls` and checks exit codes;
- never uses `administrators_authorized_keys`;
- writes the device key to `C:\ProgramData\AgentRoad\ssh\authorized_keys`;
- inserts a bounded block marked `# BEGIN AGENT ROAD` / `# END AGENT ROAD` before any generic `Match Group administrators` block;
- configures `Match User AgentRoad`, the dedicated key file, `AuthenticationMethods publickey`, and `PasswordAuthentication no`; it uses `KbdInteractiveAuthentication no` when the installed Windows OpenSSH accepts that directive, otherwise the inbox-compatible equivalent `ChallengeResponseAuthentication no`, and validates the selected candidate with `sshd.exe -t` and `sshd.exe -T`;
- runs `sshd.exe -t -f <candidate>` and `sshd.exe -T -C user=AgentRoad,host=localhost,addr=100.64.0.1 -f <candidate>` before activation;
- installs `OpenSSH.Server~~~~0.0.1.0` only when absent;
- creates only firewall rule `AgentRoad-OpenSSH-Tailscale` with TCP 22 and remote ranges `100.64.0.0/10,fd7a:115c:a1e0::/48`;
- uses the passed completion ticket only in memory and never in journal/log writes;
- restores Agent Road-owned files/config/service/firewall state on a failed mutable stage;
- outputs only stable stage labels and error codes.

If `pwsh` exists on the Mac, also parse the file with PowerShell's parser and require zero syntax errors. The Node source-contract test remains mandatory when `pwsh` is absent.

- [ ] **Step 2: Run the focused test and confirm RED**

```bash
node --test test/windows-stage-one-source.test.mjs
```

Expected: missing script failure.

- [ ] **Step 3: Implement stage-one preflight, journal, and lock**

The script starts with this exact parameter boundary:

```powershell
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [pscustomobject]$Configuration
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
```

Validate `Configuration` has exactly `protocolVersion`, `deviceId`, `controllerBaseUrl`, `completionTicket`, and `sshPublicKey`. Create the restricted root, open the lock with `[IO.FileShare]::None`, and atomically replace `journal.json` through a temporary file in the same directory. Journal only step names, timestamps, backup paths, detected facts, and validation results.

- [ ] **Step 4: Implement account and OpenSSH transactions**

Use `[System.Web.Security.Membership]::GeneratePassword` only if available; otherwise create 32 random bytes with `RandomNumberGenerator`, base64 them, and satisfy Windows complexity with fixed mixed character classes. Pass the password as `SecureString` to `New-LocalUser`; never print or serialize it. Preserve a valid existing `AgentRoad` account, but require it to be local and enabled before adding it to `Administrators`.

Build candidate `sshd_config` bytes beside the original, preserve original line endings, remove only an existing bounded Agent Road block, insert the new account-specific block before the first active generic administrator match, and validate both syntax and effective configuration before atomic replacement. Back up only files Agent Road changes.

Start `sshd`, set it to Automatic, and create the scoped Agent Road firewall rule only after SSH validation. Check each external process exit code.

- [ ] **Step 5: Implement completion and rollback**

Collect host public-key lines from `C:\ProgramData\ssh\ssh_host_*_key.pub`, obtain fingerprints with `ssh-keygen.exe -lf`, collect Tailscale IPs from `tailscale ip`, and POST the exact completion schema. On success, remove the raw completion ticket variable and mark `complete`. On failure, restore only Agent Road-owned mutations in reverse order, preserve the journal and non-secret error code, then throw a fixed `AGENT_ROAD_BOOTSTRAP_FAILED:<code>` message.

- [ ] **Step 6: Verify and commit**

```bash
node --test test/windows-stage-one-source.test.mjs
npm test
git add windows/bootstrap-stage-one.ps1 test/windows-stage-one-source.test.mjs
git commit -m "feat: configure Windows OpenSSH bootstrap"
```

### Task 9: Verify pinned SSH and bidirectional file transfer

**Files:**
- Create: `src/ssh/ssh-verifier.mjs`
- Create: `test/ssh-verifier.test.mjs`

- [ ] **Step 1: Write failing verifier tests**

Inject `runProcess` and a temporary state root. Validate host-key lines and fingerprints, write one device-specific known-hosts file, and assert SSH uses exact security flags:

```text
-o BatchMode=yes
-o PasswordAuthentication=no
-o KbdInteractiveAuthentication=no
-o StrictHostKeyChecking=yes
-o UserKnownHostsFile=/tmp/agent-road-known-hosts-dev_abc123
-o IdentitiesOnly=yes
-i /tmp/agent-road-identities/dev_abc123/id_ed25519
-p 22
AgentRoad@<tailscale ip>
```

The remote command is a UTF-16LE encoded PowerShell probe that emits strict JSON containing username, administrator membership, PowerShell version, and a nonce. Reject wrong nonce, non-`AgentRoad` identity, non-admin result, malformed JSON, host-key mismatch, non-zero exit, or stderr beyond the known first-connect-free path.

For file transfer, create a random local fixture under a temporary directory, copy it to `C:\ProgramData\AgentRoad\probe\<nonce>.bin` with `scp` using the same strict options, copy it back to a different local path, and require byte-for-byte SHA-256 equality. Always request remote fixture cleanup through SSH.

- [ ] **Step 2: Run the focused test and confirm RED**

```bash
node --test test/ssh-verifier.test.mjs
```

Expected: module-not-found failure.

- [ ] **Step 3: Implement `verifyWindowsSsh`**

Export:

```js
await verifyWindowsSsh({
  deviceId,
  address,
  sshHostKeys,
  sshHostKeyFingerprints,
  privateKeyPath,
  knownHostsPath,
  runProcess,
});
```

Use `ssh-keygen -lf -` through a temporary owner-only file to derive and compare each reported fingerprint before creating known_hosts entries. Format IPv4/IPv6 host patterns correctly for port 22. Try validated Tailscale addresses in order without weakening host-key checks. Return the selected address and capabilities only after command and file probes both pass.

- [ ] **Step 4: Verify and commit**

```bash
node --test test/ssh-verifier.test.mjs
npm test
git add src/ssh/ssh-verifier.mjs test/ssh-verifier.test.mjs
git commit -m "feat: verify pinned Windows SSH access"
```

### Task 10: Orchestrate live enrollment and update the CLI

**Files:**
- Create: `src/enrollment/run-windows-enrollment.mjs`
- Modify: `src/enrollment/create-enrollment.mjs`
- Modify: `src/cli.mjs`
- Modify: `test/create-enrollment.test.mjs`
- Modify: `test/cli-enrollment.test.mjs`
- Create: `test/run-windows-enrollment.test.mjs`

- [ ] **Step 1: Write failing orchestration tests**

Inject every side-effecting adapter and assert this order:

```text
tailscale.status
signer.getOrCreate
sshIdentity.getOrCreate
receiver.start
tailscale.serve
token.issue + registry.add
command.print callback
receiver.waitForCompletion
ssh.verify
serve.close
receiver.close
registry.replace(CONNECTED_SSH_ONLY)
```

The command callback must receive exactly one PowerShell line before waiting. Assert cleanup runs in reverse order on every failure, token compensation remains correct before exchange, and an exchanged token is not incorrectly revoked. Serve and receiver cleanup form a success-publication barrier: `CONNECTED_SSH_ONLY` is persisted only after both close successfully; cleanup failure records `BOOTSTRAP_FAILED` and never publishes a false connected state. Failures known on the Mac map to `TAILSCALE_SERVE_AUTH_REQUIRED`, `BOOTSTRAP_FAILED`, or `SSH_VERIFY_FAILED` without persisting secrets. A pre-exchange Windows login failure prints `TAILSCALE_LOGIN_REQUIRED` locally; because the target is not yet on the Tailnet, the Mac can only record the eventual enrollment timeout rather than falsely claiming it received that Windows-local code.

The success registry record must contain the validated target metadata, Tailscale addresses, SSH username, host keys/fingerprints, and capabilities `ssh`, `sftp`, and `admin-powershell`.

- [ ] **Step 2: Write failing CLI integration tests**

Change production enrollment to:

```text
agent-road enroll [--name <display-name>]
```

Remove the user-supplied `--controller-url`; the controller derives its Tailnet-only URL. Assert stdout receives exactly one generated PowerShell command for safe copy/paste. Progress, the fixed final success line, and stable error codes go to stderr. Add `--timeout-minutes` only as a bounded integer from 5 through 30 for physical testing; default 10.

- [ ] **Step 3: Run focused tests and confirm RED**

```bash
node --test test/run-windows-enrollment.test.mjs test/create-enrollment.test.mjs test/cli-enrollment.test.mjs
```

Expected: missing orchestrator and old CLI contract failures.

- [ ] **Step 4: Implement orchestration and dependency wiring**

`runWindowsEnrollment` owns receiver/Serve lifetimes and always attempts reverse-order cleanup. Start the localhost receiver before Serve, derive the controller base URL from the validated Tailscale DNS name, then use `createEnrollment` only after all non-persistent preflight succeeds. Pass the finalized URL, signer public key, manifest, token, and device ID to the stage-zero builder. After SSH verification, close Serve and the receiver before atomically publishing `CONNECTED_SSH_ONLY`; cleanup failure publishes only `BOOTSTRAP_FAILED`.

Update `createEnrollment` to accept an injected `buildCommand` and payload extras while retaining its existing preflight-before-persistence and token compensation behavior. Do not let the CLI construct adapters inside branch logic; create one production dependency factory so tests can replace it as a unit.

- [ ] **Step 5: Verify focused, full, syntax, and secret tests**

```bash
node --test test/run-windows-enrollment.test.mjs test/create-enrollment.test.mjs test/cli-enrollment.test.mjs
npm test
npm run check
git diff --check
```

Expected: all tests pass and checks exit 0.

- [ ] **Step 6: Commit Task 10**

```bash
git add src/enrollment/run-windows-enrollment.mjs src/enrollment/create-enrollment.mjs src/cli.mjs test/run-windows-enrollment.test.mjs test/create-enrollment.test.mjs test/cli-enrollment.test.mjs
git commit -m "feat: enroll Windows over Tailnet SSH"
```

### Task 11: Documentation, checkpoint, and automated release verification

**Files:**
- Modify: `README.md`
- Modify: `CURRENT_STATE.md`
- Modify: `package.json`
- Create: `docs/windows-physical-acceptance.md`

- [ ] **Step 1: Add an exhaustive syntax-check script**

Replace the narrow check with:

```json
"check": "find src test -name '*.mjs' -print0 | xargs -0 -n1 node --check"
```

On macOS this checks every source and test module. Keep `npm test` unchanged.

- [ ] **Step 2: Document the exact remote-session workflow**

README must state:

```bash
cd /Users/example/agent-road
node src/cli.mjs enroll --name "Home Windows PC"
```

It must explain that the CLI stays running, the user pastes the single stdout PowerShell command into elevated Windows PowerShell, completes Tailscale browser login once, and waits for the Mac to print `CONNECTED_SSH_ONLY`. Document the one-time Mac Serve consent possibility and state that Funnel is never used.

`docs/windows-physical-acceptance.md` must provide checkboxes for Windows build/edition capture, pre-existing Tailscale/OpenSSH inventory, generated command paste, browser login, strict SSH probe, bidirectional file transfer, reboot, reconnection, rollback observations, and secret/output inspection. It must say not to paste tokens, commands, or private keys into bug reports.

- [ ] **Step 3: Update `CURRENT_STATE.md` within 30 lines**

Record:

- automated implementation commit and exact test count;
- whether `pwsh` syntax parsing ran or was unavailable;
- physical Windows acceptance as `pending` until actually performed;
- exact next action: run the README enroll command on Mac, then paste its one output line into elevated Windows PowerShell;
- desktop/MCP/RustDesk/watchdog still deferred;
- private repository and primary paths.

Do not claim Windows is connected until the physical test succeeds.

- [ ] **Step 4: Run final automated verification**

```bash
npm test
npm run check
git diff --check
git grep -IlE '(gh[opsu]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)' -- .
```

Expected: all tests and syntax checks pass; diff check exits 0; credential scan prints no tracked files. Test fixtures may contain generated ephemeral keys only inside temporary directories, never the repository.

If `pwsh` exists:

```bash
pwsh -NoProfile -Command '$e=$null; [System.Management.Automation.Language.Parser]::ParseFile("windows/bootstrap-stage-one.ps1",[ref]$null,[ref]$e) > $null; if($e.Count){$e | Out-String | Write-Error; exit 1}'
```

Expected: exit 0. If `pwsh` is absent, record that limitation in `CURRENT_STATE.md` and require the physical Windows parser/run before acceptance.

- [ ] **Step 5: Commit documentation and checkpoint**

```bash
git add README.md CURRENT_STATE.md package.json docs/windows-physical-acceptance.md
git commit -m "docs: prepare Windows bootstrap acceptance"
```

### Task 12: Whole-branch review and physical-test handoff

**Files:**
- Review all changes from the implementation base to HEAD.

- [ ] **Step 1: Run whole-branch review**

Review against `docs/superpowers/specs/2026-07-26-windows-bootstrap-design.md` with findings-first severity. Verify no public listener, Funnel call, shell interpolation, shared administrator key file, raw token persistence, long-lived Tailnet credential, ownership takeover, alternate VPN, GUI feature, or unsupported completion claim entered the branch.

- [ ] **Step 2: Re-run the complete automated gate**

```bash
npm test
npm run check
git diff --check $(git merge-base HEAD main)..HEAD
git status --short
```

Expected: tests pass, checks exit 0, and only the user's pre-existing untracked `.DS_Store` may remain outside the implementation worktree.

- [ ] **Step 3: Update the final checkpoint evidence**

If review fixes changed the final commit or test count, update `CURRENT_STATE.md`, rerun the gate, commit the checkpoint correction, and push the implementation branch according to the approved branch-finishing workflow.

- [ ] **Step 4: Hand the exact physical action to the user**

Do not stop at “code complete.” Tell the remote user exactly:

1. which Mac command to run;
2. which single stdout line to paste into elevated Windows PowerShell;
3. that one Tailscale browser login may appear;
4. which fixed success or error status to send back;
5. that physical acceptance, reboot recovery, and `CURRENT_STATE.md` finalization remain open until observed.
