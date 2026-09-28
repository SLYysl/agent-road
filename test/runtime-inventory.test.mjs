import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import {
  digestRuntimeInventory,
  runtimeInventoriesSemanticallyEqual,
  validateRuntimeInventory,
} from '../src/runtime/runtime-inventory.mjs';

const SHA_A = 'A'.repeat(64);
const SHA_B = 'B'.repeat(64);
const WINDOWS_INVENTORY_SCRIPT_URL = new URL(
  '../windows/runtime-inventory.ps1',
  import.meta.url,
);

function sourceSection(source, start, end) {
  const startIndex = source.indexOf(`function ${start}`);
  const endIndex = source.indexOf(`function ${end}`, startIndex + 1);
  assert.notEqual(startIndex, -1, `missing ${start}`);
  assert.notEqual(endIndex, -1, `missing ${end}`);
  return source.slice(startIndex, endIndex);
}

const EMPTY_INVENTORY = {
  schemaVersion: 1,
  platform: {
    os: 'windows',
    version: '10.0.26200',
    build: 26_200,
    edition: 'Microsoft Windows 11 Home',
    architecture: 'x64',
    windowsPowerShellVersion: '5.1.26100.8655',
    elevated: true,
  },
  freeBytes: 50_000_000_000,
  pendingReboot: false,
  interactiveSession: false,
  runtime: {
    schemaVersion: null,
    catalogRevision: null,
    catalogDigest: null,
    generationDigest: null,
    generationVerified: false,
    pendingOperationId: null,
    restartRequired: false,
  },
  managedArtifacts: [],
};

const VERIFIED_INVENTORY = {
  ...EMPTY_INVENTORY,
  runtime: {
    schemaVersion: 1,
    catalogRevision: 7,
    catalogDigest: SHA_A,
    generationDigest: SHA_B,
    generationVerified: true,
    pendingOperationId: null,
    restartRequired: false,
  },
  managedArtifacts: [
    {
      id: 'mingit',
      version: '2.50.1',
      bytes: 64_000_000,
      sha256: SHA_A,
      verified: true,
    },
    {
      id: 'powershell-7',
      version: '7.5.2',
      bytes: 108_000_000,
      sha256: SHA_B,
      verified: true,
    },
  ],
};

function clone(value = EMPTY_INVENTORY) {
  return structuredClone(value);
}

function rejectsInput(callback) {
  assert.throws(callback, { code: 'RUNTIME_INPUT_INVALID' });
}

test('validates an empty runtime inventory into a detached deeply frozen snapshot', () => {
  const input = clone();
  const result = validateRuntimeInventory(input);

  assert.deepEqual(result, EMPTY_INVENTORY);
  assert.notEqual(result, input);
  assert.notEqual(result.platform, input.platform);
  assert.notEqual(result.runtime, input.runtime);
  assert.notEqual(result.managedArtifacts, input.managedArtifacts);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.platform), true);
  assert.equal(Object.isFrozen(result.runtime), true);
  assert.equal(Object.isFrozen(result.managedArtifacts), true);
  assert.throws(() => { result.platform.build = 1; }, TypeError);
  assert.throws(() => { result.managedArtifacts.push({}); }, TypeError);

  input.platform.build = 99_999;
  input.runtime.pendingOperationId = 'a'.repeat(32);
  assert.equal(result.platform.build, 26_200);
  assert.equal(result.runtime.pendingOperationId, null);
});

test('accepts a complete verified generation and preserves canonical artifact order', () => {
  const result = validateRuntimeInventory(clone(VERIFIED_INVENTORY));

  assert.deepEqual(result, VERIFIED_INVENTORY);
  assert.equal(Object.isFrozen(result.managedArtifacts[0]), true);
  assert.throws(() => { result.managedArtifacts[0].verified = false; }, TypeError);
});

test('rejects missing and extra fields at every inventory level', () => {
  const cases = [];
  const missingRoot = clone();
  delete missingRoot.freeBytes;
  cases.push(missingRoot, { ...clone(), timestamp: '2026-07-29T00:00:00.000Z' });

  const missingPlatform = clone();
  delete missingPlatform.platform.build;
  cases.push(missingPlatform);
  const extraPlatform = clone();
  extraPlatform.platform.username = 'secret';
  cases.push(extraPlatform);

  const missingRuntime = clone();
  delete missingRuntime.runtime.generationDigest;
  cases.push(missingRuntime);
  const extraRuntime = clone();
  extraRuntime.runtime.path = 'C:\\secret';
  cases.push(extraRuntime);

  const missingArtifact = clone(VERIFIED_INVENTORY);
  delete missingArtifact.managedArtifacts[0].bytes;
  cases.push(missingArtifact);
  const extraArtifact = clone(VERIFIED_INVENTORY);
  extraArtifact.managedArtifacts[0].stdout = 'secret';
  cases.push(extraArtifact);

  for (const value of cases) rejectsInput(() => validateRuntimeInventory(value));
});

test('rejects Proxy, revoked Proxy, getters, symbols, prototypes and sparse arrays without invoking hostile code', () => {
  let getterReads = 0;
  const getterRoot = clone();
  Object.defineProperty(getterRoot, 'schemaVersion', {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error('must not run');
    },
  });
  rejectsInput(() => validateRuntimeInventory(getterRoot));
  assert.equal(getterReads, 0);

  const nestedGetter = clone();
  Object.defineProperty(nestedGetter.platform, 'build', {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error('must not run');
    },
  });
  rejectsInput(() => validateRuntimeInventory(nestedGetter));
  assert.equal(getterReads, 0);

  let proxyTraps = 0;
  const proxy = new Proxy(clone(), {
    ownKeys() {
      proxyTraps += 1;
      throw new Error('must not run');
    },
  });
  rejectsInput(() => validateRuntimeInventory(proxy));
  assert.equal(proxyTraps, 0);

  const nestedProxy = clone();
  nestedProxy.runtime = new Proxy(nestedProxy.runtime, {
    getPrototypeOf() {
      proxyTraps += 1;
      throw new Error('must not run');
    },
  });
  rejectsInput(() => validateRuntimeInventory(nestedProxy));
  assert.equal(proxyTraps, 0);

  const revoked = Proxy.revocable(clone(), {});
  revoked.revoke();
  rejectsInput(() => validateRuntimeInventory(revoked.proxy));

  const symbolic = clone();
  symbolic.runtime[Symbol('secret')] = true;
  rejectsInput(() => validateRuntimeInventory(symbolic));

  const inherited = clone();
  Object.setPrototypeOf(inherited.platform, { build: 26_200 });
  rejectsInput(() => validateRuntimeInventory(inherited));

  const nullPrototype = clone();
  nullPrototype.runtime = Object.assign(Object.create(null), nullPrototype.runtime);
  rejectsInput(() => validateRuntimeInventory(nullPrototype));

  const sparse = clone(VERIFIED_INVENTORY);
  sparse.managedArtifacts = [sparse.managedArtifacts[0], , sparse.managedArtifacts[1]];
  rejectsInput(() => validateRuntimeInventory(sparse));
});

test('rejects unsupported schema and noncanonical platform facts while accepting bounded unsupported planning facts', () => {
  for (const value of [0, 2, '1', 1.5]) {
    const inventory = clone();
    inventory.schemaVersion = value;
    rejectsInput(() => validateRuntimeInventory(inventory));
  }

  for (const mutation of [
    ['os', 'Windows'],
    ['version', '10.0'],
    ['version', '10.00.26200'],
    ['version', '10.0.26200-preview'],
    ['build', 10_239],
    ['build', 100_000],
    ['build', 26_200.5],
    ['edition', ''],
    ['edition', ' Windows 11 Home'],
    ['edition', 'Windows\n11'],
    ['architecture', 'AMD64'],
    ['architecture', 'x86'],
    ['windowsPowerShellVersion', '5.1-preview'],
    ['elevated', 1],
  ]) {
    const inventory = clone();
    inventory.platform[mutation[0]] = mutation[1];
    rejectsInput(() => validateRuntimeInventory(inventory));
  }

  const boundedUnsupported = clone();
  boundedUnsupported.platform.build = 17_762;
  boundedUnsupported.platform.architecture = 'arm64';
  boundedUnsupported.platform.windowsPowerShellVersion = '4.0.0.0';
  assert.equal(validateRuntimeInventory(boundedUnsupported).platform.architecture, 'arm64');
});

test('rejects invalid free-space and boolean scalars including negative zero', () => {
  for (const freeBytes of [-1, -0, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '0']) {
    const inventory = clone();
    inventory.freeBytes = freeBytes;
    rejectsInput(() => validateRuntimeInventory(inventory));
  }

  for (const field of ['pendingReboot', 'interactiveSession']) {
    for (const value of [0, 1, null, 'false']) {
      const inventory = clone();
      inventory[field] = value;
      rejectsInput(() => validateRuntimeInventory(inventory));
    }
  }
});

test('enforces null and complete runtime generation tuples', () => {
  for (const [field, value] of [
    ['schemaVersion', 1],
    ['catalogRevision', 1],
    ['catalogDigest', SHA_A],
    ['generationDigest', SHA_B],
    ['generationVerified', true],
  ]) {
    const inventory = clone();
    inventory.runtime[field] = value;
    rejectsInput(() => validateRuntimeInventory(inventory));
  }

  for (const [field, value] of [
    ['schemaVersion', null],
    ['catalogRevision', null],
    ['catalogDigest', null],
    ['generationDigest', null],
  ]) {
    const inventory = clone(VERIFIED_INVENTORY);
    inventory.runtime[field] = value;
    rejectsInput(() => validateRuntimeInventory(inventory));
  }

  for (const [field, values] of [
    ['schemaVersion', [0, -1, 1.5, '1']],
    ['catalogRevision', [0, -1, 1.5, 2_147_483_648]],
    ['catalogDigest', ['a'.repeat(64), 'G'.repeat(64), 'A'.repeat(63)]],
    ['generationDigest', ['a'.repeat(64), 'G'.repeat(64), 'A'.repeat(63)]],
    ['pendingOperationId', ['A'.repeat(32), 'a'.repeat(31), 'g'.repeat(32)]],
    ['restartRequired', [0, null, 'false']],
  ]) {
    for (const value of values) {
      const inventory = clone(VERIFIED_INVENTORY);
      inventory.runtime[field] = value;
      rejectsInput(() => validateRuntimeInventory(inventory));
    }
  }
});

test('validates artifact shape, ordering, bounds and verification relationships', () => {
  const validUnverified = clone();
  validUnverified.managedArtifacts = [{
    id: 'powershell-7',
    version: '7.5.2',
    bytes: 108_000_000,
    sha256: SHA_A,
    verified: false,
  }];
  assert.equal(validateRuntimeInventory(validUnverified).managedArtifacts[0].verified, false);

  const validUnreadable = clone();
  validUnreadable.managedArtifacts = [{
    id: 'powershell-7',
    version: '7.5.2',
    bytes: null,
    sha256: null,
    verified: false,
  }];
  assert.equal(validateRuntimeInventory(validUnreadable).managedArtifacts[0].bytes, null);

  const invalidRecords = [
    { id: 'PowerShell', version: '7.5.2', bytes: null, sha256: null, verified: false },
    { id: 'powershell-7', version: 'v7.5.2', bytes: null, sha256: null, verified: false },
    { id: 'powershell-7', version: '7.5.2', bytes: 0, sha256: SHA_A, verified: false },
    { id: 'powershell-7', version: '7.5.2', bytes: 256 * 1024 ** 2 + 1, sha256: SHA_A, verified: false },
    { id: 'powershell-7', version: '7.5.2', bytes: null, sha256: SHA_A, verified: false },
    { id: 'powershell-7', version: '7.5.2', bytes: 1, sha256: null, verified: false },
    { id: 'powershell-7', version: '7.5.2', bytes: null, sha256: null, verified: true },
    { id: 'powershell-7', version: '7.5.2', bytes: 1, sha256: 'a'.repeat(64), verified: true },
    { id: 'powershell-7', version: '7.5.2', bytes: 1, sha256: SHA_A, verified: 1 },
  ];
  for (const record of invalidRecords) {
    const inventory = clone();
    inventory.managedArtifacts = [record];
    rejectsInput(() => validateRuntimeInventory(inventory));
  }

  for (const bytes of [-0, NaN, Infinity, 1.5, '1']) {
    const inventory = clone();
    inventory.managedArtifacts = [{
      id: 'powershell-7',
      version: '7.5.2',
      bytes,
      sha256: SHA_A,
      verified: false,
    }];
    rejectsInput(() => validateRuntimeInventory(inventory));
  }

  const unsorted = clone(VERIFIED_INVENTORY);
  unsorted.managedArtifacts.reverse();
  rejectsInput(() => validateRuntimeInventory(unsorted));

  const duplicate = clone(VERIFIED_INVENTORY);
  duplicate.managedArtifacts[1].id = duplicate.managedArtifacts[0].id;
  rejectsInput(() => validateRuntimeInventory(duplicate));

  const tooMany = clone();
  tooMany.managedArtifacts = Array.from({ length: 33 }, (_, index) => ({
    id: `tool-${String(index).padStart(2, '0')}`,
    version: '1.0.0',
    bytes: null,
    sha256: null,
    verified: false,
  }));
  rejectsInput(() => validateRuntimeInventory(tooMany));
});

test('requires every managed artifact to be verified when generation is verified', () => {
  const inventory = clone(VERIFIED_INVENTORY);
  inventory.managedArtifacts[0].verified = false;
  rejectsInput(() => validateRuntimeInventory(inventory));

  const noGeneration = clone();
  noGeneration.managedArtifacts = [{
    id: 'powershell-7',
    version: '7.5.2',
    bytes: 108_000_000,
    sha256: SHA_A,
    verified: true,
  }];
  rejectsInput(() => validateRuntimeInventory(noGeneration));
});

test('computes an uppercase deterministic digest from validated canonical facts', () => {
  const first = clone(VERIFIED_INVENTORY);
  const reordered = {
    managedArtifacts: structuredClone(first.managedArtifacts),
    runtime: { ...first.runtime },
    interactiveSession: first.interactiveSession,
    pendingReboot: first.pendingReboot,
    freeBytes: first.freeBytes,
    platform: { ...first.platform },
    schemaVersion: first.schemaVersion,
  };

  const firstDigest = digestRuntimeInventory(first);
  const secondDigest = digestRuntimeInventory(reordered);
  assert.match(firstDigest, /^[0-9A-F]{64}$/);
  assert.equal(firstDigest, secondDigest);

  const nestedReordered = {
    managedArtifacts: first.managedArtifacts.map((artifact) => ({
      verified: artifact.verified,
      sha256: artifact.sha256,
      bytes: artifact.bytes,
      version: artifact.version,
      id: artifact.id,
    })),
    runtime: {
      restartRequired: first.runtime.restartRequired,
      pendingOperationId: first.runtime.pendingOperationId,
      generationVerified: first.runtime.generationVerified,
      generationDigest: first.runtime.generationDigest,
      catalogDigest: first.runtime.catalogDigest,
      catalogRevision: first.runtime.catalogRevision,
      schemaVersion: first.runtime.schemaVersion,
    },
    interactiveSession: first.interactiveSession,
    pendingReboot: first.pendingReboot,
    freeBytes: first.freeBytes,
    platform: {
      elevated: first.platform.elevated,
      windowsPowerShellVersion: first.platform.windowsPowerShellVersion,
      architecture: first.platform.architecture,
      edition: first.platform.edition,
      build: first.platform.build,
      version: first.platform.version,
      os: first.platform.os,
    },
    schemaVersion: first.schemaVersion,
  };
  assert.equal(digestRuntimeInventory(nestedReordered), firstDigest);

  reordered.freeBytes -= 1;
  assert.notEqual(digestRuntimeInventory(reordered), firstDigest);

  const hostile = clone();
  Object.defineProperty(hostile, 'schemaVersion', {
    enumerable: true,
    get() { throw new Error('must not run'); },
  });
  rejectsInput(() => digestRuntimeInventory(hostile));
});

test('compares exact inventory facts while treating free bytes only as a threshold predicate', () => {
  const requiredFreeBytes = 1_000;
  const high = clone();
  const higher = clone();
  high.freeBytes = requiredFreeBytes;
  higher.freeBytes = requiredFreeBytes + 1;
  assert.equal(runtimeInventoriesSemanticallyEqual(high, higher, requiredFreeBytes), true);

  const low = clone();
  const lower = clone();
  low.freeBytes = requiredFreeBytes - 1;
  lower.freeBytes = 0;
  assert.equal(runtimeInventoriesSemanticallyEqual(low, lower, requiredFreeBytes), true);
  assert.equal(runtimeInventoriesSemanticallyEqual(low, high, requiredFreeBytes), false);
  assert.equal(runtimeInventoriesSemanticallyEqual(high, low, requiredFreeBytes), false);

  for (const changed of [
    { pendingReboot: true },
    { interactiveSession: true },
    { platform: { ...high.platform, build: 26_201 } },
    { runtime: { ...high.runtime, pendingOperationId: 'b'.repeat(32) } },
    { managedArtifacts: [{
      id: 'powershell-7',
      version: '7.6.4',
      bytes: null,
      sha256: null,
      verified: false,
    }] },
  ]) {
    const actual = { ...clone(high), ...changed };
    assert.equal(
      runtimeInventoriesSemanticallyEqual(high, actual, requiredFreeBytes),
      false,
    );
  }
});

test('inventory semantic comparison rejects hostile snapshots and invalid thresholds without invoking traps', () => {
  let getterReads = 0;
  const hostile = clone();
  Object.defineProperty(hostile, 'freeBytes', {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error('must not run');
    },
  });
  rejectsInput(() => runtimeInventoriesSemanticallyEqual(hostile, clone(), 1));
  assert.equal(getterReads, 0);

  let proxyTraps = 0;
  const proxy = new Proxy(clone(), {
    ownKeys() {
      proxyTraps += 1;
      throw new Error('must not run');
    },
  });
  rejectsInput(() => runtimeInventoriesSemanticallyEqual(clone(), proxy, 1));
  assert.equal(proxyTraps, 0);

  for (const threshold of [-1, -0, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '1']) {
    rejectsInput(() => runtimeInventoriesSemanticallyEqual(clone(), clone(), threshold));
  }
});

test('Windows inventory normalizes raw ACL API failures without weakening ACL checks', async () => {
  const source = await readFile(WINDOWS_INVENTORY_SCRIPT_URL, 'utf8');
  const acl = sourceSection(
    source,
    'Assert-AgentRoadRestrictedAcl',
    'Assert-AgentRoadDirectoryNode',
  );

  assert.match(
    acl,
    /\$e='RUNTIME_STATE_UNSUPPORTED'[\s\S]*?try\s*\{[\s\S]*?GetAccessControl\([\s\S]*?GetAccessRules\([\s\S]*?GetOwner\([\s\S]*?catch\s*\{[\s\S]*?throw \$e/u,
  );
  assert.match(acl, /AreAccessRulesProtected/u);
  assert.match(acl, /AreAccessRulesCanonical/u);
  assert.match(acl, /S-1-5-18/u);
  assert.match(acl, /S-1-5-32-544/u);
  assert.match(acl, /FullControl/u);
});

test('Windows inventory normalizes raw direct-child failures while preserving bounded lazy checks', async () => {
  const source = await readFile(WINDOWS_INVENTORY_SCRIPT_URL, 'utf8');
  const children = sourceSection(
    source,
    'Get-AgentRoadDirectChildren',
    'Get-AgentRoadBoundedTree',
  );

  assert.match(
    children,
    /try\s*\{\s*foreach \(\$childPath in \[IO\.Directory\]::EnumerateFileSystemEntries\(\$Path\)\)\s*\{/u,
  );
  assert.match(
    children,
    /\$items\.Add\(\(Get-Item -LiteralPath \$childPath -Force -ErrorAction Stop\)\)/u,
  );
  assert.match(
    children,
    /\$e='RUNTIME_STATE_UNSUPPORTED'[\s\S]*?catch\s*\{\s*if \(\[string\]\$_\.Exception\.Message -ceq \$e\) \{ throw \};throw \$e\s*\}/u,
  );
  assert.doesNotMatch(children, /\$childPaths\s*=\s*@\(/u);
  assert.match(children, /Assert-AgentRoadDirectoryNode \$Path/u);
  assert.match(children, /\[IO\.Path\]::GetDirectoryName\(\$childPath\) -cne \$Path/u);
  assert.match(children, /\$items\.Count -ge \$MaximumCount/u);
});

test('Windows PowerShell 5.1 reports an exact empty operation as pending', {
  skip: process.platform !== 'win32' ? 'requires Windows PowerShell 5.1' : false,
}, async () => {
  const source = await readFile(WINDOWS_INVENTORY_SCRIPT_URL, 'utf8');
  const mainMarker = "\ntry {\n $runtimeRoot = 'C:\\ProgramData\\AgentRoad\\runtime'";
  const mainIndex = source.indexOf(mainMarker);
  assert.notEqual(mainIndex, -1, 'missing inventory main marker');

  const fixture = String.raw`
$fixtureRoot = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('AgentRoad-Inventory-' + [guid]::NewGuid().ToString('N')))
function New-AgentRoadFixtureDirectorySecurity {
 $system = New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'
 $admins = New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'
 $owner = $admins.Translate([Security.Principal.NTAccount])
 $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
 $acl = New-Object Security.AccessControl.DirectorySecurity
 $acl.SetOwner($owner)
 $acl.SetAccessRuleProtection($true, $false)
 $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $inherit, 'None', 'Allow')))
 $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($admins, 'FullControl', $inherit, 'None', 'Allow')))
 return $acl
}
try {
 if ($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'WRONG_POWERSHELL' }
 $script:AgentRoadRoot = $fixtureRoot
 $script:RuntimeRoot = [IO.Path]::Combine($fixtureRoot, 'runtime')
 $script:TrustRoot = [IO.Path]::Combine($script:RuntimeRoot, 'trust')
 $script:TrustKeyPath = [IO.Path]::Combine($script:TrustRoot, 'controller-key.json')
 $script:StagingRoot = [IO.Path]::Combine($script:RuntimeRoot, 'staging')
 $script:VersionsRoot = [IO.Path]::Combine($script:RuntimeRoot, 'versions')
 $script:StateRoot = [IO.Path]::Combine($script:RuntimeRoot, 'state')
 $script:JournalPath = [IO.Path]::Combine($script:StateRoot, 'journal.json')
 $script:ActivePath = [IO.Path]::Combine($script:StateRoot, 'active.json')
 $script:PreviousPath = [IO.Path]::Combine($script:StateRoot, 'previous.json')
 $operationId = 'a' * 32
 $operationRoot = [IO.Path]::Combine($script:StagingRoot, $operationId)
 foreach ($path in @($fixtureRoot, $script:RuntimeRoot, $script:StagingRoot, $operationRoot)) {
  [IO.Directory]::CreateDirectory($path, (New-AgentRoadFixtureDirectorySecurity)) | Out-Null
 }
 $snapshot = Get-AgentRoadRuntimeStateSnapshot -RuntimeRoot $script:RuntimeRoot
 if (
  [string]$snapshot.runtime.pendingOperationId -cne $operationId -or
  $null -ne $snapshot.runtime.schemaVersion -or
  $snapshot.runtime.generationVerified -or
  @($snapshot.managedArtifacts).Count -ne 0
 ) { throw 'FIXTURE_ASSERTION_FAILED' }
 [Console]::Out.Write('AGENT_ROAD_EMPTY_OPERATION_FIXTURE_OK')
} finally {
 if (Test-Path -LiteralPath $fixtureRoot) { [IO.Directory]::Delete($fixtureRoot, $true) }
}
`;
  const command = Buffer.from(`${source.slice(0, mainIndex)}\n${fixture}`, 'utf16le').toString('base64');
  const result = spawnSync('powershell.exe', [
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-EncodedCommand',
    command,
  ], { encoding: 'utf8', timeout: 30_000 });

  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  assert.equal(result.stdout, 'AGENT_ROAD_EMPTY_OPERATION_FIXTURE_OK');
});

test('Windows object-list helpers avoid PowerShell 5.1 array-subexpression binding failure', async () => {
  const inventory = await readFile(WINDOWS_INVENTORY_SCRIPT_URL, 'utf8');
  const provision = await readFile(new URL('../windows/runtime-provision-core.ps1', import.meta.url), 'utf8');
  for (const [source, start, variable] of [
    [inventory, 'Get-AgentRoadDirectChildren', 'items'],
    [inventory, 'Get-AgentRoadBoundedTree', 'nodes'],
    [inventory, 'Get-AgentRoadFixedFileRecords', 'records'],
    [provision, 'Get-AgentRoadFixedFileReceipts', 'records'],
  ]) {
    const begin = source.indexOf(`function ${start}`);
    assert.notEqual(begin, -1);
    const next = source.indexOf('\nfunction ', begin + 1);
    const helper = source.slice(begin, next < 0 ? undefined : next);
    assert.ok(helper.includes(`return $${variable}.ToArray()`), start);
    assert.ok(!helper.includes(`return @($${variable})`), start);
  }
});

test('optional Windows file hashes distinguish omission from an explicitly empty digest', async () => {
  for (const path of ['runtime-inventory.ps1', 'runtime-provision-core.ps1']) {
    const source = await readFile(new URL(`../windows/${path}`, import.meta.url), 'utf8');
    const start = source.indexOf('function Assert-AgentRoadFileNode {');
    const end = source.indexOf('\nfunction ', start + 1);
    const helper = source.slice(start, end);
    assert.ok(helper.includes("$PSBoundParameters.ContainsKey('ExpectedSha256')"), path);
    assert.ok(!helper.includes('$null -ne $ExpectedSha256'), path);
  }
});

test('Windows file hash checks accept omission and matching hashes but reject supplied invalid hashes', {
  skip: process.platform !== 'win32' ? 'requires Windows PowerShell 5.1' : false,
}, async () => {
  for (const path of ['runtime-inventory.ps1', 'runtime-provision-core.ps1']) {
    const source = await readFile(new URL(`../windows/${path}`, import.meta.url), 'utf8');
    const start = source.indexOf('function Assert-AgentRoadFileNode {');
    const end = source.indexOf('\nfunction ', start + 1);
    // Isolate optional digest semantics; ACL/link validation has separate coverage.
    const script = String.raw`
$ErrorActionPreference='Stop'
function Assert-AgentRoadRestrictedAcl {}
function Get-AgentRoadFileLinkCount { return 1 }
function Get-AgentRoadSha256 { param($Path); return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
${source.slice(start, end)}
$file=[IO.Path]::GetTempFileName()
try {
 [IO.File]::WriteAllText($file,'optional-hash-regression')
 $hash=Get-AgentRoadSha256 $file
 Assert-AgentRoadFileNode $file
 Assert-AgentRoadFileNode $file -ExpectedSha256 $hash
 foreach($bad in @('',('0'*64))) {
  $rejected=$false
  try { Assert-AgentRoadFileNode $file -ExpectedSha256 $bad } catch { $rejected=$true }
  if(-not $rejected){throw 'INVALID_HASH_ACCEPTED'}
 }
 [Console]::Out.Write('OPTIONAL_HASH_OK')
} finally { [IO.File]::Delete($file) }
`;
    const result = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive',
      '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], {
      encoding: 'utf8', timeout: 30_000,
    });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, '');
    assert.equal(result.stdout, 'OPTIONAL_HASH_OK');
  }
});

test('Windows staged capsule checks preserve absent trust and reject invalid supplied pins', {
  skip: process.platform !== 'win32' ? 'requires Windows PowerShell 5.1' : false,
}, async () => {
  const source = await readFile(WINDOWS_INVENTORY_SCRIPT_URL, 'utf8');
  const capsule = sourceSection(source, 'Read-AgentRoadCapsule', 'Get-AgentRoadToolTreeRecord');
  const pin = sourceSection(source, 'Assert-AgentRoadPinnedControllerTrust', 'Read-AgentRoadBootstrapDeviceId');
  const staged = sourceSection(source, 'Read-AgentRoadStagedOperation', 'Get-AgentRoadRuntimeStateSnapshot');
  const parameters = staged.split('\n').find((line) => line.trimStart().startsWith('param('));
  assert.ok(parameters);
  // Exercise the actual forwarding parameter binder and capsule trust check.
  // Manifest/signature/file validation is outside this isolated binding regression.
  const script = String.raw`
$ErrorActionPreference='Stop'
$script:Utf8=New-Object Text.UTF8Encoding($false,$true)
$script:CapsuleFields=@()
function Read-AgentRoadJsonFile { return [pscustomobject]@{value=[pscustomobject]@{manifestJson='{"operationId":"op","deviceId":"device"}';manifestDigest='digest';controllerPublicKeyJson='key'};bytes=@()} }
function Assert-AgentRoadExactOrderedRecord {}
function ConvertFrom-AgentRoadCanonicalJson { param($Bytes);return ($script:Utf8.GetString($Bytes)|ConvertFrom-Json) }
function Assert-AgentRoadManifest {}
function Assert-AgentRoadControllerSignature {}
function Read-AgentRoadBootstrapDeviceId { return 'device' }
${pin}
${capsule}
function Invoke-StagedBinding {
${parameters}
 return Read-AgentRoadCapsule 'fixture' 'digest' 'op' $PinnedKeyJson
}
$null=Invoke-StagedBinding 'fixture'
$null=Invoke-StagedBinding 'fixture' 'key'
foreach($bad in @('', 'wrong', 123)) {
 $rejected=$false
 try { $null=Invoke-StagedBinding 'fixture' $bad } catch { $rejected=$true }
 if(-not $rejected){throw 'INVALID_PIN_ACCEPTED'}
}
[Console]::Out.Write('NULLABLE_PIN_OK')
`;
  const result = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive',
    '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], {
    encoding: 'utf8', timeout: 30_000,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  assert.equal(result.stdout, 'NULLABLE_PIN_OK');
});
