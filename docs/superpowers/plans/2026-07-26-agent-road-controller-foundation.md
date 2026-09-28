# Agent Road Controller Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a dependency-free macOS controller CLI with a platform-neutral device model, atomic registry, single-use enrollment tokens, and deterministic PowerShell enrollment-command generation.

**Architecture:** A Node.js 22 ESM CLI owns controller state under `~/.agent-road` (overridable in tests), stores only non-secret device metadata in an atomic JSON registry, and keeps hashed one-time enrollment tokens in a separate store. Enrollment commands carry a short-lived token inside UTF-16LE PowerShell `-EncodedCommand`; no Windows software is installed in this foundation plan.

**Tech Stack:** Node.js 22 standard library, ECMAScript modules, built-in `node:test`, macOS Keychain integration deferred to the Windows bootstrap plan.

---

## Scope decomposition

The approved specification contains four independently testable subsystems. This plan implements subsystem 1 only:

1. Mac controller foundation and enrollment protocol — this plan.
2. Windows bootstrap, Tailscale enrollment, OpenSSH, and first SSH verification.
3. Windows-MCP, RustDesk, desktop-session handling, and Watchdog recovery.
4. Packaging, reboot/fault-injection matrix, and website/document/system end-to-end acceptance.

Do not add Windows installers, Tailscale API calls, SSH execution, MCP, RustDesk, watchdog behavior, a VPS relay, or alternate VPN logic in this plan.

## File map

- `package.json` — Node version, CLI entry point, test/check scripts.
- `src/cli.mjs` — argument parsing, stdout/stderr contract, process exit codes.
- `src/core/device-model.mjs` — platform-neutral status and device validation.
- `src/core/paths.mjs` — controller state paths with test override.
- `src/storage/json-file.mjs` — atomic JSON read/write primitive.
- `src/storage/device-registry.mjs` — non-secret device metadata operations.
- `src/enrollment/token-store.mjs` — random tokens, hash-at-rest, expiry, single consumption.
- `src/enrollment/powershell-command.mjs` — deterministic encoded PowerShell command.
- `src/enrollment/create-enrollment.mjs` — orchestration that creates the device record, token, and command.
- `test/*.test.mjs` — unit and CLI contract tests.
- `README.md` — foundation commands and explicit non-capabilities.

### Task 1: Create the dependency-free CLI skeleton

**Files:**
- Create: `package.json`
- Create: `src/cli.mjs`
- Create: `test/cli-help.test.mjs`

- [ ] **Step 1: Write the failing CLI help test**

```js
// test/cli-help.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

test('agent-road --help prints the command list', () => {
  const result = spawnSync(process.execPath, ['src/cli.mjs', '--help'], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });

  assert.equal(result.status, 0);
  assert.match(result.stdout, /agent-road enroll/);
  assert.match(result.stdout, /agent-road list/);
  assert.match(result.stdout, /agent-road status/);
  assert.equal(result.stderr, '');
});
```

- [ ] **Step 2: Run the test and verify the missing CLI failure**

Run: `node --test test/cli-help.test.mjs`

Expected: FAIL because `src/cli.mjs` does not exist.

- [ ] **Step 3: Add the package manifest and minimal CLI**

```json
{
  "name": "agent-road",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "bin": {
    "agent-road": "./src/cli.mjs"
  },
  "scripts": {
    "test": "node --test",
    "check": "node --check src/cli.mjs"
  },
  "engines": {
    "node": ">=22"
  }
}
```

```js
#!/usr/bin/env node
// src/cli.mjs
const HELP = `Agent Road controller

Usage:
  agent-road enroll --controller-url <https-url>
  agent-road list
  agent-road status <device-id>
`;

export function main(argv = process.argv.slice(2)) {
  if (argv.length === 0 || argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(HELP);
    return 0;
  }

  process.stderr.write(`Unknown command: ${argv[0]}\n`);
  return 2;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exitCode = main();
}
```

- [ ] **Step 4: Run the CLI test and syntax check**

Run: `npm test && npm run check`

Expected: one passing test and both commands exit 0.

- [ ] **Step 5: Commit the CLI skeleton**

```bash
git add package.json src/cli.mjs test/cli-help.test.mjs
git commit -m "feat: scaffold Agent Road controller CLI"
```

### Task 2: Define the platform-neutral device model

**Files:**
- Create: `src/core/device-model.mjs`
- Create: `test/device-model.test.mjs`

- [ ] **Step 1: Write validation tests**

```js
// test/device-model.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEVICE_STATUSES,
  validateDeviceRecord,
} from '../src/core/device-model.mjs';

const validWindowsRecord = {
  id: 'dev_018f',
  displayName: 'Windows workstation',
  controllerPlatform: 'darwin',
  targetPlatform: 'windows',
  status: 'READY',
  capabilities: ['ssh', 'mcp'],
  createdAt: '2026-07-26T00:00:00.000Z',
  updatedAt: '2026-07-26T00:00:00.000Z',
};

test('exports the exact device status array', () => {
  assert.deepEqual(DEVICE_STATUSES, [
    'ENROLLING',
    'CONNECTED_SSH_ONLY',
    'GUI_LOGIN_REQUIRED',
    'MCP_UNAVAILABLE',
    'TAILSCALE_AUTH_REQUIRED',
    'DEGRADED_RECOVERY_AVAILABLE',
    'REBOOT_RECOVERY_FAILED',
    'READY',
  ]);
  assert.ok(Object.isFrozen(DEVICE_STATUSES));
});

test('validates and freezes a Windows device record', () => {
  const result = validateDeviceRecord(validWindowsRecord);
  assert.deepEqual(result, validWindowsRecord);
  assert.notEqual(result, validWindowsRecord);
  assert.notEqual(result.capabilities, validWindowsRecord.capabilities);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.capabilities));
});

test('rejects a device record with a password field', () => {
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, password: 'not-allowed' }),
    /secret field is forbidden: password/i,
  );
});

test('rejects a nested secret-shaped field', () => {
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, transport: { token: 'not-allowed' } }),
    /secret field is forbidden: token/i,
  );
});

test('rejects non-string capabilities so nested mutable data cannot persist', () => {
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, capabilities: [{ name: 'ssh' }] }),
    /capabilities.*strings/i,
  );
});

test('rejects non-object device records', () => {
  assert.throws(() => validateDeviceRecord([]), {
    name: 'TypeError',
    message: 'device record must be an object',
  });
});

test('rejects a device record with an invalid required field', () => {
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, id: 'device_018f' }),
    /id/i,
  );
});

test('rejects whitespace-only display names', () => {
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, displayName: ' \t ' }),
    /displayName.*non-empty/i,
  );
});

test('rejects non-canonical timestamps that Date.parse accepts', () => {
  assert.throws(
    () => validateDeviceRecord({ ...validWindowsRecord, updatedAt: '0' }),
    /updatedAt.*ISO/i,
  );
});
```

- [ ] **Step 2: Verify the module is missing**

Run: `node --test test/device-model.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: Implement the model and validation**

```js
// src/core/device-model.mjs
export const DEVICE_STATUSES = Object.freeze([
  'ENROLLING',
  'CONNECTED_SSH_ONLY',
  'GUI_LOGIN_REQUIRED',
  'MCP_UNAVAILABLE',
  'TAILSCALE_AUTH_REQUIRED',
  'DEGRADED_RECOVERY_AVAILABLE',
  'REBOOT_RECOVERY_FAILED',
  'READY',
]);

const SECRET_FIELD_PATTERN = /password|secret|token|private.?key|credential/i;
const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/;
const PLATFORMS = new Set(['darwin', 'windows']);

function assertNoSecretFields(value, visited = new WeakSet()) {
  if (value === null || typeof value !== 'object' || visited.has(value)) {
    return;
  }
  visited.add(value);
  for (const key of Object.keys(value)) {
    if (SECRET_FIELD_PATTERN.test(key)) {
      throw new Error(`secret field is forbidden: ${key}`);
    }
    assertNoSecretFields(value[key], visited);
  }
}

function isCanonicalIsoTimestamp(value) {
  if (typeof value !== 'string') {
    return false;
  }
  const date = new Date(value);
  return !Number.isNaN(date.valueOf()) && date.toISOString() === value;
}

export function validateDeviceRecord(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('device record must be an object');
  }
  assertNoSecretFields(input);
  if (typeof input.id !== 'string' || !DEVICE_ID_PATTERN.test(input.id)) {
    throw new Error('device record id must match /^dev_[a-z0-9]+$/');
  }
  if (typeof input.displayName !== 'string' || input.displayName.trim() === '') {
    throw new Error('device record displayName must be a non-empty string');
  }
  if (!PLATFORMS.has(input.controllerPlatform)) {
    throw new Error('device record controllerPlatform must be darwin or windows');
  }
  if (!PLATFORMS.has(input.targetPlatform)) {
    throw new Error('device record targetPlatform must be darwin or windows');
  }
  if (!DEVICE_STATUSES.includes(input.status)) {
    throw new Error('device record status must be a listed device status');
  }
  if (!Array.isArray(input.capabilities) || !input.capabilities.every((capability) => typeof capability === 'string')) {
    throw new Error('device record capabilities must be an array of strings');
  }
  for (const field of ['createdAt', 'updatedAt']) {
    if (!isCanonicalIsoTimestamp(input[field])) {
      throw new Error(`device record ${field} must be an ISO date`);
    }
  }
  return Object.freeze({ ...input, capabilities: Object.freeze([...input.capabilities]) });
}
```

- [ ] **Step 4: Run focused and full tests**

Run: `node --test test/device-model.test.mjs && npm test`

Expected: 12 total passing tests (three Task 1 tests and nine Task 2 tests).

- [ ] **Step 5: Commit the device model**

```bash
git add src/core/device-model.mjs test/device-model.test.mjs
git commit -m "feat: define platform-neutral device states"
```

### Task 3: Add controller paths and atomic JSON storage

**Files:**
- Create: `src/core/paths.mjs`
- Create: `src/storage/json-file.mjs`
- Create: `test/json-file.test.mjs`

- [ ] **Step 1: Write atomic storage tests**

```js
// test/json-file.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readJson, writeJsonAtomic } from '../src/storage/json-file.mjs';

test('writes formatted JSON atomically and leaves no temporary file', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-road-json-'));
  const path = join(dir, 'registry.json');
  await writeJsonAtomic(path, { devices: [{ id: 'dev_a' }] });

  assert.deepEqual(await readJson(path, {}), { devices: [{ id: 'dev_a' }] });
  assert.equal(await readFile(path, 'utf8'), '{\n  "devices": [\n    {\n      "id": "dev_a"\n    }\n  ]\n}\n');
  assert.deepEqual(await readdir(dir), ['registry.json']);
});

test('returns the fallback when the file is absent', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-road-json-'));
  assert.deepEqual(await readJson(join(dir, 'missing.json'), { devices: [] }), { devices: [] });
});
```

- [ ] **Step 2: Run the storage test and verify failure**

Run: `node --test test/json-file.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: Implement paths and atomic JSON storage**

```js
// src/core/paths.mjs
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

export function statePaths(env = process.env) {
  const root = resolve(env.AGENT_ROAD_HOME || join(homedir(), '.agent-road'));
  return Object.freeze({
    root,
    devices: join(root, 'devices.json'),
    tokens: join(root, 'enrollment-tokens.json'),
  });
}
```

```js
// src/storage/json-file.mjs
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';

export async function readJson(path, fallback) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return structuredClone(fallback);
    throw error;
  }
}

export async function writeJsonAtomic(path, value) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true });
  }
}
```

- [ ] **Step 4: Run storage and full tests**

Run: `node --test test/json-file.test.mjs && npm test`

Expected: all tests pass and temporary directories contain only the final JSON file.

- [ ] **Step 5: Commit atomic storage**

```bash
git add src/core/paths.mjs src/storage/json-file.mjs test/json-file.test.mjs
git commit -m "feat: add atomic controller state storage"
```

### Task 4: Implement the non-secret device registry

**Files:**
- Create: `src/storage/device-registry.mjs`
- Create: `test/device-registry.test.mjs`

- [ ] **Step 1: Write registry behavior tests**

```js
// test/device-registry.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DeviceRegistry } from '../src/storage/device-registry.mjs';

const DEVICE = {
  id: 'dev_abc123',
  displayName: 'New Windows PC',
  controllerPlatform: 'darwin',
  targetPlatform: 'windows',
  status: 'ENROLLING',
  capabilities: [],
  createdAt: '2026-07-26T00:00:00.000Z',
  updatedAt: '2026-07-26T00:00:00.000Z',
};

test('adds, lists, reads, and updates a device', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-road-registry-'));
  const registry = new DeviceRegistry(join(dir, 'devices.json'));
  await registry.add(DEVICE);
  assert.deepEqual(await registry.list(), [DEVICE]);
  assert.deepEqual(await registry.get(DEVICE.id), DEVICE);
  await registry.updateStatus(DEVICE.id, 'CONNECTED_SSH_ONLY', '2026-07-26T01:00:00.000Z');
  assert.equal((await registry.get(DEVICE.id)).status, 'CONNECTED_SSH_ONLY');
});

test('rejects duplicate device ids', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-road-registry-'));
  const registry = new DeviceRegistry(join(dir, 'devices.json'));
  await registry.add(DEVICE);
  await assert.rejects(registry.add(DEVICE), /already exists/);
});
```

- [ ] **Step 2: Verify registry tests fail**

Run: `node --test test/device-registry.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: Implement the registry**

```js
// src/storage/device-registry.mjs
import { validateDeviceRecord } from '../core/device-model.mjs';
import { readJson, writeJsonAtomic } from './json-file.mjs';

export class DeviceRegistry {
  constructor(path) {
    this.path = path;
  }

  async list() {
    const data = await readJson(this.path, { devices: [] });
    return data.devices.map((device) => ({ ...validateDeviceRecord(device), capabilities: [...device.capabilities] }));
  }

  async get(id) {
    return (await this.list()).find((device) => device.id === id) ?? null;
  }

  async add(input) {
    const device = validateDeviceRecord(input);
    const devices = await this.list();
    if (devices.some((entry) => entry.id === device.id)) throw new Error(`device already exists: ${device.id}`);
    await writeJsonAtomic(this.path, { devices: [...devices, device] });
    return { ...device, capabilities: [...device.capabilities] };
  }

  async updateStatus(id, status, updatedAt) {
    const devices = await this.list();
    const index = devices.findIndex((device) => device.id === id);
    if (index === -1) throw new Error(`device not found: ${id}`);
    devices[index] = validateDeviceRecord({ ...devices[index], status, updatedAt });
    await writeJsonAtomic(this.path, { devices });
    return { ...devices[index], capabilities: [...devices[index].capabilities] };
  }
}
```

- [ ] **Step 4: Run the registry and complete test suite**

Run: `node --test test/device-registry.test.mjs && npm test`

Expected: all tests pass.

- [ ] **Step 5: Commit the registry**

```bash
git add src/storage/device-registry.mjs test/device-registry.test.mjs
git commit -m "feat: persist non-secret device metadata"
```

### Task 5: Add single-use enrollment tokens

**Files:**
- Create: `src/enrollment/token-store.mjs`
- Create: `test/token-store.test.mjs`
- Create: `src/storage/file-lock.mjs`
- Modify: `src/storage/device-registry.mjs`

Token issue and consumption are serialized read-modify-write transactions through the
owner-aware, bounded, fail-closed file lock shared with the device registry. Before
using persisted state, the token-store envelope and every record are schema-validated
(including canonical timestamps and timestamp ordering); malformed state is rejected.
`consume` captures the clock once within its transaction for both expiry and `consumedAt`.
`revoke(rawToken)` uses the same serialized, schema-validated transaction to remove exactly
one matching record by hash (whether consumed or unconsumed), returning `true` when it
removes a record and `false` when absent. This supports enrollment compensation.

- [ ] **Step 1: Write expiry, hashing, and consumption tests**

```js
// test/token-store.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EnrollmentTokenStore } from '../src/enrollment/token-store.mjs';

test('stores only a token hash and consumes the token once', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-road-token-'));
  const path = join(dir, 'tokens.json');
  const store = new EnrollmentTokenStore(path, {
    now: () => new Date('2026-07-26T00:00:00.000Z'),
    randomBytes: () => Buffer.alloc(32, 7),
  });
  const issued = await store.issue({ deviceId: 'dev_abc123', ttlMs: 600_000 });

  const rawFile = await readFile(path, 'utf8');
  assert.equal(rawFile.includes(issued.token), false);
  assert.equal((await store.consume(issued.token)).deviceId, 'dev_abc123');
  await assert.rejects(store.consume(issued.token), /already consumed/);
});

test('rejects an expired token', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-road-token-'));
  let now = new Date('2026-07-26T00:00:00.000Z');
  const store = new EnrollmentTokenStore(join(dir, 'tokens.json'), { now: () => now });
  const issued = await store.issue({ deviceId: 'dev_abc123', ttlMs: 1_000 });
  now = new Date('2026-07-26T00:00:02.000Z');
  await assert.rejects(store.consume(issued.token), /expired/);
});
```

- [ ] **Step 2: Verify token tests fail**

Run: `node --test test/token-store.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: Implement hashed one-time tokens**

```js
// src/enrollment/token-store.mjs
import { createHash, randomBytes as systemRandomBytes, randomUUID } from 'node:crypto';
import { readJson, writeJsonAtomic } from '../storage/json-file.mjs';

function hashToken(token) {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export class EnrollmentTokenStore {
  constructor(path, dependencies = {}) {
    this.path = path;
    this.now = dependencies.now ?? (() => new Date());
    this.randomBytes = dependencies.randomBytes ?? systemRandomBytes;
  }

  async issue({ deviceId, ttlMs }) {
    if (!Number.isInteger(ttlMs) || ttlMs <= 0) throw new Error('ttlMs must be positive');
    const token = this.randomBytes(32).toString('base64url');
    const issuedAt = this.now();
    const record = {
      id: `enr_${randomUUID().replaceAll('-', '')}`,
      deviceId,
      tokenHash: hashToken(token),
      issuedAt: issuedAt.toISOString(),
      expiresAt: new Date(issuedAt.getTime() + ttlMs).toISOString(),
      consumedAt: null,
    };
    const data = await readJson(this.path, { tokens: [] });
    await writeJsonAtomic(this.path, { tokens: [...data.tokens, record] });
    return { token, expiresAt: record.expiresAt };
  }

  async consume(token) {
    const data = await readJson(this.path, { tokens: [] });
    const tokenHash = hashToken(token);
    const index = data.tokens.findIndex((entry) => entry.tokenHash === tokenHash);
    if (index === -1) throw new Error('unknown enrollment token');
    const record = data.tokens[index];
    if (record.consumedAt) throw new Error('enrollment token already consumed');
    if (this.now().getTime() >= Date.parse(record.expiresAt)) throw new Error('enrollment token expired');
    record.consumedAt = this.now().toISOString();
    await writeJsonAtomic(this.path, data);
    return { deviceId: record.deviceId, expiresAt: record.expiresAt };
  }
}
```

- [ ] **Step 4: Run token and full tests**

Run: `node --test test/token-store.test.mjs && npm test`

Expected: all tests pass; raw tokens are absent from the token-store file.

- [ ] **Step 5: Commit enrollment token storage**

```bash
git add src/enrollment/token-store.mjs test/token-store.test.mjs
git commit -m "feat: add expiring single-use enrollment tokens"
```

### Task 6: Generate deterministic PowerShell enrollment commands

**Files:**
- Create: `src/enrollment/powershell-command.mjs`
- Create: `test/powershell-command.test.mjs`

**Hardened contract:** Read `controllerUrl`, `deviceId`, and `token` from the caller exactly once. Reject non-string URL values, leading/trailing whitespace, URLs over 2048 characters, non-HTTPS URLs, userinfo, fragments, `localhost`/`.localhost` after stripping one terminal DNS dot, IPv4 `127/8`, IPv6 `::1`, and IPv4-mapped IPv6 (`::ffff:`); legitimate LAN, Tailscale, and MagicDNS hosts remain valid. Canonicalize once with `new URL`, then serialize only a new plain allowlisted object in this field order: `{ deviceId, token, controllerUrl: url.href }`. Never stringify the caller object or invoke its `toJSON`.

Device IDs must match `/^dev_[a-z0-9]+$/` and be at most 64 characters. Tokens must be strings from 16 through 128 characters. Encode the allowlisted JSON as UTF-8 Base64, embed it in a semicolon-separated PowerShell script, and encode the whole script as UTF-16LE Base64. Return exactly the existing one-line `powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ...` form; reject a resulting command longer than 32767 characters with a clear error.

The PowerShell request uses `Invoke-RestMethod -Method Post`, `-ContentType 'application/json'`, `-MaximumRedirection 0`, and `-TimeoutSec 30`; `$ErrorActionPreference = 'Stop'` handles non-success responses. It accepts only a non-null, non-collection `[pscustomobject]` with exactly two case-sensitive properties, `status` and `deviceId`, both strings. Compare both values case-sensitively with `-cne` against `accepted` and `$payload.deviceId`; otherwise throw the fixed `invalid enrollment response` error. It writes only a fixed success string and never serializes the response.

- [ ] **Step 1: Write decoding and hardening tests**

Decode both Base64 layers and assert the canonical allowlisted payload, the request flags, strict response-schema checks, fixed/redacted output, and absence of `ConvertTo-Json`. Test terminal-dot localhost names, mapped IPv6 loopback, input bounds, the final command bound, and permitted LAN/Tailscale/MagicDNS hosts. Include a getter whose second read differs and a throwing `toJSON` to prove the builder reads each primitive once and never serializes the caller object. Document that a copied command can be decoded to recover its one-use enrollment token, while the visible command does not contain the literal token. Run generated scripts against real PowerShell only where a `pwsh` or Windows runtime is available.

- [ ] **Step 2: Verify command tests fail**

Run: `node --test test/powershell-command.test.mjs`

Expected: FAIL for the missing hardening behavior.

- [ ] **Step 3: Implement the bounded command builder**

Use only Node's standard library. Keep the generated script one line and encoded; do not execute network activity while building it.

- [ ] **Step 4: Run command and full tests**

Run: `node --test test/powershell-command.test.mjs && npm test && npm run check`

Expected: all tests pass; the visible command contains no literal token, while its encoded payload remains intentionally recoverable by the Windows shell.

- [ ] **Step 5: Commit PowerShell command hardening**

```bash
git add src/enrollment/powershell-command.mjs test/powershell-command.test.mjs
git commit -m "fix: harden PowerShell enrollment commands"
```

### Task 7: Orchestrate enrollment and expose CLI commands

**Files:**
- Create: `src/enrollment/create-enrollment.mjs`
- Create: `test/create-enrollment.test.mjs`
- Modify: `src/cli.mjs`
- Create: `test/cli-enrollment.test.mjs`

Enrollment is deliberately not cross-file atomic. Before either store is written, build and
schema-validate the complete device record and preflight the controller command inputs with a
fixed valid dummy token. Persist the short-lived token first, then build the final command and
add the device. If the post-issue command build fails, revoke the raw token. If `registry.add`
fails, first read back that device id: an exact match to the intended record reconciles as
success and keeps the token; a missing or conflicting record revokes the token before rethrowing
the primary add failure. If reconciliation itself fails, do not revoke because persistence is
ambiguous; surface the add and read failures in an `AggregateError`. Compensation failure also
surfaces both failures with the primary failure first. The residual crash or reconciliation-
ambiguity window leaves at most an expiring token whose registry outcome cannot yet be proven;
it never knowingly revokes a token for a registry record that may already exist.

- [ ] **Step 1: Write enrollment orchestration test**

```js
// test/create-enrollment.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { createEnrollment } from '../src/enrollment/create-enrollment.mjs';

test('creates an ENROLLING device and returns one command', async () => {
  const added = [];
  const result = await createEnrollment({
    displayName: 'New Windows PC',
    controllerUrl: 'https://controller.example.test/enroll',
    registry: { add: async (device) => added.push(device) },
    tokenStore: { issue: async () => ({ token: 'x'.repeat(32), expiresAt: '2026-07-26T00:10:00.000Z' }) },
    now: () => new Date('2026-07-26T00:00:00.000Z'),
    createDeviceId: () => 'dev_abc123',
  });

  assert.equal(added[0].status, 'ENROLLING');
  assert.equal(added[0].targetPlatform, 'windows');
  assert.match(result.command, /^powershell\.exe /);
  assert.equal(result.deviceId, 'dev_abc123');
});
```

- [ ] **Step 2: Write CLI integration test**

```js
// test/cli-enrollment.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

function run(args, home) {
  return spawnSync(process.execPath, ['src/cli.mjs', ...args], {
    cwd: process.cwd(),
    env: { ...process.env, AGENT_ROAD_HOME: home },
    encoding: 'utf8',
  });
}

test('enroll, list, and status share the same device registry', async () => {
  const home = await mkdtemp(join(tmpdir(), 'agent-road-cli-'));
  const enrolled = run([
    'enroll',
    '--controller-url', 'https://controller.example.test/enroll',
    '--name', 'Studio PC',
  ], home);
  assert.equal(enrolled.status, 0);
  assert.match(enrolled.stdout, /^powershell\.exe /);

  const listed = run(['list'], home);
  assert.equal(listed.status, 0);
  const devices = JSON.parse(listed.stdout);
  assert.equal(devices.length, 1);
  assert.equal(devices[0].displayName, 'Studio PC');

  const status = run(['status', devices[0].id], home);
  assert.equal(status.status, 0);
  assert.equal(JSON.parse(status.stdout).status, 'ENROLLING');
});
```

- [ ] **Step 3: Run both tests and verify failure**

Run: `node --test test/create-enrollment.test.mjs test/cli-enrollment.test.mjs`

Expected: FAIL because orchestration and CLI commands are not implemented.

- [ ] **Step 4: Implement enrollment orchestration**

```js
// src/enrollment/create-enrollment.mjs
import { randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { validateDeviceRecord } from '../core/device-model.mjs';
import { buildPowerShellEnrollmentCommand } from './powershell-command.mjs';

export async function createEnrollment(options) {
  const now = options.now ?? (() => new Date());
  const createDeviceId = options.createDeviceId ?? (() => `dev_${randomUUID().replaceAll('-', '')}`);
  const deviceId = createDeviceId();
  const timestamp = now().toISOString();
  const device = validateDeviceRecord({
    id: deviceId,
    displayName: options.displayName,
    controllerPlatform: 'darwin',
    targetPlatform: 'windows',
    status: 'ENROLLING',
    capabilities: [],
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  buildPowerShellEnrollmentCommand({
    deviceId,
    token: 'x'.repeat(32),
    controllerUrl: options.controllerUrl,
  });
  const issued = await options.tokenStore.issue({ deviceId, ttlMs: 600_000 });
  let command;
  try {
    command = buildPowerShellEnrollmentCommand({
      deviceId,
      token: issued.token,
      controllerUrl: options.controllerUrl,
    });
  } catch (error) {
    try {
      await options.tokenStore.revoke(issued.token);
    } catch (revokeError) {
      throw new AggregateError([error, revokeError], 'failed to add device and revoke enrollment token');
    }
    throw error;
  }
  try {
    await options.registry.add(device);
  } catch (addError) {
    let persisted;
    try {
      persisted = await options.registry.get(deviceId);
    } catch (readError) {
      throw new AggregateError([addError, readError], 'ambiguous enrollment persistence after registry add failure');
    }
    if (!isDeepStrictEqual(persisted, device)) {
      try {
        await options.tokenStore.revoke(issued.token);
      } catch (revokeError) {
        throw new AggregateError([addError, revokeError], 'failed to add device and revoke enrollment token');
      }
      throw addError;
    }
  }
  return {
    deviceId,
    expiresAt: issued.expiresAt,
    command,
  };
}
```

- [ ] **Step 5: Replace the CLI skeleton with working commands**

```js
#!/usr/bin/env node
// src/cli.mjs
import { parseArgs } from 'node:util';
import { statePaths } from './core/paths.mjs';
import { DeviceRegistry } from './storage/device-registry.mjs';
import { EnrollmentTokenStore } from './enrollment/token-store.mjs';
import { createEnrollment } from './enrollment/create-enrollment.mjs';

const HELP = `Agent Road controller

Usage:
  agent-road enroll --controller-url <https-url> [--name <display-name>]
  agent-road list
  agent-road status <device-id>
`;

export async function main(argv = process.argv.slice(2), env = process.env) {
  if (argv.length === 0 || argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(HELP);
    return 0;
  }

  const paths = statePaths(env);
  const registry = new DeviceRegistry(paths.devices);
  const tokenStore = new EnrollmentTokenStore(paths.tokens);
  const command = argv[0];

  if (command === 'enroll') {
    const parsed = parseArgs({
      args: argv.slice(1),
      options: {
        'controller-url': { type: 'string' },
        name: { type: 'string', default: 'New Windows PC' },
      },
      strict: true,
    });
    if (!parsed.values['controller-url']) throw new Error('--controller-url is required');
    const enrollment = await createEnrollment({
      displayName: parsed.values.name,
      controllerUrl: parsed.values['controller-url'],
      registry,
      tokenStore,
    });
    process.stdout.write(`${enrollment.command}\n`);
    return 0;
  }

  if (command === 'list') {
    process.stdout.write(`${JSON.stringify(await registry.list(), null, 2)}\n`);
    return 0;
  }

  if (command === 'status') {
    if (!argv[1]) throw new Error('device id is required');
    const device = await registry.get(argv[1]);
    if (!device) throw new Error(`device not found: ${argv[1]}`);
    process.stdout.write(`${JSON.stringify(device, null, 2)}\n`);
    return 0;
  }

  throw new Error(`unknown command: ${command}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().then(
    (code) => { process.exitCode = code; },
    (error) => {
      process.stderr.write(`agent-road: ${error.message}\n`);
      process.exitCode = 2;
    },
  );
}
```

- [ ] **Step 6: Run focused and complete tests**

Run: `node --test test/create-enrollment.test.mjs test/cli-enrollment.test.mjs && npm test`

Expected: all tests pass; `enroll` prints only one PowerShell command to stdout.

- [ ] **Step 7: Commit enrollment orchestration and CLI commands**

```bash
git add src/cli.mjs src/enrollment/create-enrollment.mjs test/create-enrollment.test.mjs test/cli-enrollment.test.mjs
git commit -m "feat: generate controller enrollment sessions"
```

### Task 8: Document and verify the controller foundation

**Files:**
- Create: `README.md`
- Modify: `CURRENT_STATE.md`

- [ ] **Step 1: Write the foundation README**

````markdown
# Agent Road

Agent Road is a Mac-hosted control plane for enrolling and operating remote computers without running a model on the target.

## Foundation commands

```bash
node src/cli.mjs --help
AGENT_ROAD_HOME="$(mktemp -d)" node src/cli.mjs enroll \
  --controller-url https://controller.example.test/enroll \
  --name "Test Windows PC"
```

The current foundation generates and stores enrollment metadata. It does not yet install Tailscale, OpenSSH, Windows-MCP, RustDesk, or a Windows watchdog.

## Development checks

```bash
npm test
npm run check
```
````

- [ ] **Step 2: Update the project checkpoint**

```markdown
# CURRENT_STATE — Agent Road
> 更新时间: 2026-07-26 | 线程: Mac 控制端基础

## 目标
- Mac 生成一次性 Windows 注册命令；目标端不运行模型。

## 已做
- 完成跨平台设备状态、原子 registry、一次性 token 和 PowerShell 命令生成。
- `npm test`：14 项通过；`npm run check`：通过。

## 未做 / 下一步
- 尚未连接真实 Windows。
- 下一计划：Windows bootstrap、Tailscale、OpenSSH 与首次 SSH 验收。

## 关键约束 / 红线
- 第一版仅 Mac 控制端 -> Windows 目标端，传输仅实现 Tailscale。
- 当前命令只承载注册协议，不安装 Windows 组件。

## 关键路径 / 文件
- `src/`、`test/`
- `docs/superpowers/specs/2026-07-26-agent-road-design.md`
- `docs/superpowers/plans/2026-07-26-agent-road-controller-foundation.md`
```

- [ ] **Step 3: Run final verification**

Run:

```bash
npm test
npm run check
git diff --check
git status --short
```

Expected:

- all 14 Node tests pass;
- syntax check exits 0;
- `git diff --check` prints nothing;
- only `README.md` and `CURRENT_STATE.md` are uncommitted.

- [ ] **Step 4: Inspect tracked content for credential material**

Run:

```bash
rg -n '(sk-[A-Za-z0-9]|tskey-[A-Za-z0-9]|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY)' . \
  -g '!docs/superpowers/**' -g '!.git/**'
```

Expected: no matches.

- [ ] **Step 5: Commit documentation and checkpoint**

```bash
git add README.md CURRENT_STATE.md
git commit -m "docs: document Agent Road controller foundation"
```

## Plan completion check

Before declaring this plan complete:

1. Confirm each status in the approved design exists in `DEVICE_STATUSES`.
2. Confirm raw enrollment tokens are absent from files at rest.
3. Confirm device registry validation rejects secret-shaped fields.
4. Confirm the visible PowerShell command does not contain the literal token.
5. Confirm one enrollment produces one device in `ENROLLING` state.
6. Confirm no Windows installation, VPN-specific workaround, or remote-control dependency entered this foundation scope.
7. Record the exact passing test count and commit hash in `CURRENT_STATE.md`.
