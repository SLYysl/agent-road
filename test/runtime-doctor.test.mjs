import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  parseRuntimeInventoryExecution,
  readRuntimeInventory,
  RUNTIME_INVENTORY_SCRIPT_PATH,
} from '../src/runtime/runtime-doctor.mjs';

const DEVICE_ID = 'dev_0123456789abcdef0123456789abcdef';
const ADDRESS = '100.64.0.10';
const STARTED_AT = '2026-07-29T10:00:00.000Z';
const FINISHED_AT = '2026-07-29T10:00:01.000Z';
const SCRIPT_URL = new URL('../windows/runtime-inventory.ps1', import.meta.url);

const POINTER_FIELDS = [
  'schemaVersion',
  'receiptFormatRevision',
  'manifestDigest',
  'generationDigest',
  'catalogRevision',
  'catalogDigest',
  'receiptBytes',
  'receiptSha256',
];

const RECEIPT_FIELDS = [
  'schemaVersion',
  'receiptFormatRevision',
  'operationId',
  'manifestDigest',
  'generationDigest',
  'catalogRevision',
  'catalogDigest',
  'controllerKeyId',
  'profiles',
  'components',
  'files',
  'restartRequired',
];

const JOURNAL_FIELDS = [
  'schemaVersion',
  'revision',
  'operationId',
  'manifestDigest',
  'generationDigest',
  'catalogDigest',
  'inventoryDigest',
  'controllerKeyId',
  'requestedProfiles',
  'status',
  'phase',
  'completedPhases',
  'changes',
  'snapshot',
  'restartRequired',
  'failureCode',
  'rollbackStatus',
];

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}

function literalArray(source, name) {
  const match = new RegExp(
    `\\$script:${escapeRegExp(name)}\\s*=\\s*@\\(([\\s\\S]*?)\\n\\)`,
    'u',
  ).exec(source);
  assert.ok(match, `missing literal array ${name}`);
  return [...match[1].matchAll(/'([^']+)'/gu)].map((entry) => entry[1]);
}

function section(source, startName, endName) {
  const start = source.indexOf(`function ${startName}`);
  assert.notEqual(start, -1, `missing ${startName}`);
  const end = endName === undefined
    ? source.length
    : source.indexOf(`function ${endName}`, start + 1);
  assert.notEqual(end, -1, `missing ${endName}`);
  return source.slice(start, end);
}

function assertInOrder(source, values, label) {
  let cursor = -1;
  for (const value of values) {
    const next = source.indexOf(value, cursor + 1);
    assert.ok(next > cursor, `${label}: ${value} must occur in order`);
    cursor = next;
  }
}

function inventory() {
  return {
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
    interactiveSession: true,
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
}

function executionResult(overrides = {}) {
  return {
    schemaVersion: 1,
    operation: 'exec',
    deviceId: DEVICE_ID,
    address: ADDRESS,
    exitCode: 0,
    stdout: JSON.stringify(inventory()),
    stderr: '',
    startedAt: STARTED_AT,
    finishedAt: FINISHED_AT,
    ...overrides,
  };
}

function fixture(overrides = {}) {
  const calls = [];
  const target = Object.freeze({ fixture: 'trusted-target' });
  const runProcess = async () => {};
  const operationId = () => 'a'.repeat(32);
  const clock = () => new Date(STARTED_AT);
  const executeRemoteScript = overrides.executeRemoteScript ?? (async (input) => {
    calls.push(input);
    return executionResult(overrides.result);
  });
  return {
    calls,
    target,
    runProcess,
    operationId,
    clock,
    input: {
      target,
      dependencies: {
        executeRemoteScript,
        runProcess,
        operationId,
        clock,
      },
    },
  };
}

async function rejectsCode(promise, code, forbidden = []) {
  let observed;
  try {
    await promise;
  } catch (error) {
    observed = error;
  }
  assert.ok(observed, `expected ${code}`);
  assert.equal(observed.code, code);
  assert.equal(observed.message, code);
  assert.equal(Object.hasOwn(observed, 'cause'), false);
  for (const value of forbidden) {
    assert.doesNotMatch(observed.message, new RegExp(value, 'u'));
  }
}

test('runs the fixed read-only source once and returns only canonical frozen inventory', async () => {
  const f = fixture();
  const result = await readRuntimeInventory(f.input);

  assert.deepEqual(result, inventory());
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.platform), true);
  assert.equal(Object.isFrozen(result.runtime), true);
  assert.equal(Object.isFrozen(result.managedArtifacts), true);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].target, f.target);
  assert.match(f.calls[0].scriptPath, /windows[/\\]runtime-inventory\.ps1$/u);
  assert.equal(f.calls[0].timeoutMs, 120_000);
  assert.deepEqual(f.calls[0].dependencies, {
    runProcess: f.runProcess,
    operationId: f.operationId,
    clock: f.clock,
  });
  assert.equal(JSON.stringify(result).includes(ADDRESS), false);
  assert.equal(JSON.stringify(result).includes(STARTED_AT), false);
});

test('session-scoped inventory parser binds the exact expected device and selected address', () => {
  assert.match(RUNTIME_INVENTORY_SCRIPT_PATH, /windows[/\\]runtime-inventory\.ps1$/u);
  const result = parseRuntimeInventoryExecution(executionResult(), {
    deviceId: DEVICE_ID,
    address: ADDRESS,
  });
  assert.deepEqual(result, inventory());
  assert.equal(Object.isFrozen(result), true);

  for (const [execution, expected] of [
    [executionResult({ deviceId: 'dev_wrong' }), { deviceId: DEVICE_ID, address: ADDRESS }],
    [executionResult({ address: '100.64.0.11' }), { deviceId: DEVICE_ID, address: ADDRESS }],
    [executionResult(), { deviceId: 'dev_wrong', address: ADDRESS }],
    [executionResult(), { deviceId: DEVICE_ID, address: '100.64.0.11' }],
  ]) {
    assert.throws(
      () => parseRuntimeInventoryExecution(execution, expected),
      { code: 'RUNTIME_INVENTORY_FAILED' },
    );
  }
});

test('requires exact canonical JSON with no whitespace, duplicate object, reordered or extra data', async () => {
  const canonical = JSON.stringify(inventory());
  const reordered = JSON.stringify({
    managedArtifacts: [],
    runtime: inventory().runtime,
    interactiveSession: true,
    pendingReboot: false,
    freeBytes: 50_000_000_000,
    platform: inventory().platform,
    schemaVersion: 1,
  });
  const extra = JSON.stringify({ ...inventory(), command: 'secret-command' });
  const duplicateKey = canonical.replace(
    '"schemaVersion":1',
    '"schemaVersion":1,"schemaVersion":1',
  );

  for (const stdout of [
    `${canonical}\n`,
    ` ${canonical}`,
    JSON.stringify(inventory(), null, 2),
    reordered,
    extra,
    duplicateKey,
    `${canonical}${canonical}`,
    '{',
    'x'.repeat(32 * 1024 + 1),
  ]) {
    const f = fixture({ result: { stdout } });
    await rejectsCode(
      readRuntimeInventory(f.input),
      'RUNTIME_INVENTORY_INVALID',
      ['secret-command'],
    );
  }
});

test('rejects nonzero exit, stderr and malformed execution envelopes without leaking output', async () => {
  for (const result of [
    { exitCode: 1, stdout: 'private stdout', stderr: '' },
    { exitCode: 0, stdout: JSON.stringify(inventory()), stderr: 'private stderr' },
    { operation: 'put' },
    { schemaVersion: 2 },
    { address: 1 },
    { startedAt: null },
    { extra: true },
  ]) {
    const f = fixture({ result });
    await rejectsCode(
      readRuntimeInventory(f.input),
      'RUNTIME_INVENTORY_FAILED',
      ['private stdout', 'private stderr'],
    );
  }
});

test('maps the initial source residual-state exit to a finite fail-closed code', async () => {
  const f = fixture({ result: { exitCode: 41, stdout: '' } });
  await rejectsCode(readRuntimeInventory(f.input), 'RUNTIME_STATE_UNSUPPORTED');
});

test('preserves finite lower-layer failures and maps unknown failures without their details', async () => {
  for (const code of [
    'REMOTE_INPUT_INVALID',
    'REMOTE_CONNECTION_FAILED',
    'FILE_TRANSFER_FAILED',
    'FILE_INTEGRITY_FAILED',
    'REMOTE_EXECUTION_UNCERTAIN',
    'REMOTE_CLEANUP_UNCERTAIN',
    'LOCAL_CLEANUP_FAILED',
  ]) {
    const f = fixture({
      executeRemoteScript: async () => {
        throw Object.assign(new Error(`private-${code}`), { code });
      },
    });
    await rejectsCode(readRuntimeInventory(f.input), code, ['private-']);
  }

  const unknown = fixture({
    executeRemoteScript: async () => { throw new Error('private unknown failure'); },
  });
  await rejectsCode(
    readRuntimeInventory(unknown.input),
    'RUNTIME_INVENTORY_FAILED',
    ['private unknown failure'],
  );

  let hostileReads = 0;
  const getterError = new Error('private getter error');
  Object.defineProperty(getterError, 'code', {
    get() {
      hostileReads += 1;
      throw new Error('must not run');
    },
  });
  const hostileProxy = new Proxy(new Error('private proxy error'), {
    get() {
      hostileReads += 1;
      throw new Error('must not run');
    },
  });
  for (const thrown of [getterError, hostileProxy]) {
    const f = fixture({ executeRemoteScript: async () => { throw thrown; } });
    await rejectsCode(readRuntimeInventory(f.input), 'RUNTIME_INVENTORY_FAILED');
  }
  assert.equal(hostileReads, 0);
});

test('rejects hostile doctor inputs without invoking getters, proxies or the executor', async () => {
  let getterReads = 0;
  let proxyTraps = 0;
  let executions = 0;
  const f = fixture({
    executeRemoteScript: async () => {
      executions += 1;
      return executionResult();
    },
  });

  const getterInput = { target: f.target };
  Object.defineProperty(getterInput, 'dependencies', {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error('must not run');
    },
  });
  await rejectsCode(readRuntimeInventory(getterInput), 'RUNTIME_INPUT_INVALID');

  const proxyInput = new Proxy(f.input, {
    ownKeys() {
      proxyTraps += 1;
      throw new Error('must not run');
    },
  });
  await rejectsCode(readRuntimeInventory(proxyInput), 'RUNTIME_INPUT_INVALID');

  const getterDependencies = { ...f.input.dependencies };
  Object.defineProperty(getterDependencies, 'executeRemoteScript', {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error('must not run');
    },
  });
  await rejectsCode(
    readRuntimeInventory({ target: f.target, dependencies: getterDependencies }),
    'RUNTIME_INPUT_INVALID',
  );

  const proxiedExecutor = new Proxy(async () => executionResult(), {});
  await rejectsCode(readRuntimeInventory({
    target: f.target,
    dependencies: { ...f.input.dependencies, executeRemoteScript: proxiedExecutor },
  }), 'RUNTIME_INPUT_INVALID');

  await rejectsCode(readRuntimeInventory({ ...f.input, extra: true }), 'RUNTIME_INPUT_INVALID');
  await rejectsCode(readRuntimeInventory(null), 'RUNTIME_INPUT_INVALID');
  assert.equal(getterReads, 0);
  assert.equal(proxyTraps, 0);
  assert.equal(executions, 0);
});

test('Windows inventory source is PowerShell 5.1-compatible, bounded and read-only', async () => {
  const source = await readFile(SCRIPT_URL, 'utf8');
  assert.ok(Buffer.byteLength(source, 'utf8') <= 128 * 1024);
  assert.match(source, /^#requires -Version 5\.1$/mu);
  assert.match(source, /Get-AgentRoadRuntimeStateSnapshot/u);
  assert.match(source, /C:\\ProgramData\\AgentRoad\\runtime/u);
  assert.match(source, /Get-CimInstance[\s\S]*Win32_OperatingSystem/u);
  assert.match(source, /AvailableFreeSpace/u);
  assert.match(source, /PendingFileRenameOperations/u);
  assert.match(source, /WindowsPrincipal/u);
  assert.match(source, /ConvertTo-Json[^\r\n]*-Compress/u);
  assert.match(source, /UTF8Encoding/u);
  assert.match(source, /GetByteCount\(\$json\)[\s\S]*32768/u);
  assert.equal((source.match(/\[Console\]::Out\.Write\(\$json\)/gu) ?? []).length, 1);
  assert.doesNotMatch(source, /Write-Output|Write-Host/u);

  const keyProbe = section(
    source,
    'Test-AgentRoadRegistryKey',
    'Test-AgentRoadRegistryValue',
  );
  const valueProbeStart = source.indexOf('function Test-AgentRoadRegistryValue');
  const valueProbeEnd = source.indexOf('\ntry {\n $runtimeRoot', valueProbeStart);
  assert.ok(valueProbeStart >= 0 && valueProbeEnd > valueProbeStart);
  const valueProbe = source.slice(valueProbeStart, valueProbeEnd);
  assertInOrder(keyProbe, [
    'OpenSubKey($SubKey, $false)',
    '$null -eq $key',
    'return $true',
    'finally',
    '$key.Dispose()',
  ], 'registry-key reboot probe');
  assertInOrder(valueProbe, [
    'OpenSubKey($SubKey, $false)',
    '$null -eq $key',
    '$key.GetValueNames()',
    '-icontains $ValueName',
    'finally',
    '$key.Dispose()',
  ], 'registry-value-name reboot probe');
  assert.doesNotMatch(valueProbe, /\.GetValue\(/u,
    'empty or non-data registry values must still count as present');

  assertInOrder(source, [
    'Component Based Servicing\\RebootPending',
    'WindowsUpdate\\Auto Update\\RebootRequired',
    'SYSTEM\\CurrentControlSet\\Control\\Session Manager',
    "-ValueName 'PendingFileRenameOperations'",
  ], 'complete pending-reboot inventory predicate');

  for (const forbidden of [
    /Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|curl\.exe|winget|choco/u,
    /Add-WindowsCapability|Enable-WindowsOptionalFeature|msiexec/u,
    /New-Item|Set-Content|Add-Content|Out-File|Remove-Item|Move-Item|Copy-Item/u,
    /Set-Acl|icacls|takeown/u,
    /Set-ItemProperty|New-ItemProperty|Remove-ItemProperty/u,
    /Start-Service|Stop-Service|Set-Service|New-Service/u,
    /Register-ScheduledTask|schtasks|New-NetFirewallRule/u,
    /Restart-Computer|Stop-Computer|shutdown\.exe/u,
    /Get-ChildItem|Get-LocalUser|C:\\Users|Documents|Browser|Cookies/u,
    /ForEach-Object\s+-Parallel|ConvertFrom-Json\s+-AsHashtable|\?\?/u,
  ]) {
    assert.doesNotMatch(source, forbidden);
  }
});

test('Windows source freezes the Task-5 pointer, receipt and journal schemas', async () => {
  const source = await readFile(SCRIPT_URL, 'utf8');

  assert.deepEqual(literalArray(source, 'PointerFields'), POINTER_FIELDS);
  assert.deepEqual(literalArray(source, 'ReceiptFields'), RECEIPT_FIELDS);
  assert.deepEqual(literalArray(source, 'JournalFields'), JOURNAL_FIELDS);
  assert.deepEqual(literalArray(source, 'JournalSnapshotFields'), ['active', 'previous']);
  assert.deepEqual(literalArray(source, 'ReceiptComponentFields'), [
    'id',
    'version',
    'bytes',
    'sha256',
    'installRoot',
    'fileCount',
    'directoryCount',
    'expandedBytes',
    'treeSha256',
    'verificationCommandId',
    'verified',
  ]);
  assert.deepEqual(literalArray(source, 'ReceiptFileFields'), ['path', 'bytes', 'sha256']);
});

test('Windows source verifies installed generations before reporting them as managed', async () => {
  const source = await readFile(SCRIPT_URL, 'utf8');
  const generation = section(
    source,
    'Read-AgentRoadVerifiedGeneration',
    'Read-AgentRoadStagedOperation',
  );

  assert.match(generation, /Read-AgentRoadPointer|Assert-AgentRoadPointer/u);
  assert.match(generation, /receiptBytes/u);
  assert.match(generation, /receiptSha256/u);
  assert.match(generation, /Read-AgentRoadCapsule/u);
  assert.match(generation, /Get-AgentRoadToolTreeRecord/u);
  assert.match(generation, /Get-AgentRoadFixedFileRecords/u);
  assert.match(generation, /Assert-AgentRoadExecutableVerification/u);
  assert.match(generation, /id\s*=\s*'powershell-7'/u);
  assert.match(generation, /verified\s*=\s*\$true/u);

  const capsule = section(source, 'Read-AgentRoadCapsule', 'Get-AgentRoadToolTreeRecord');
  assert.match(capsule, /Assert-AgentRoadControllerSignature/u);
  assert.match(capsule, /Assert-AgentRoadPinnedControllerTrust/u);
  const executable = section(
    source,
    'Assert-AgentRoadExecutableVerification',
    'Assert-AgentRoadGenerationLayout',
  );
  assert.match(executable, /Get-AuthenticodeSignature/u);
  assert.match(executable, /Invoke-AgentRoadPowerShellCheck/u);

  const acl = section(source, 'Assert-AgentRoadRestrictedAcl', 'Assert-AgentRoadDirectoryNode');
  assert.match(acl, /AreAccessRulesProtected/u);
  assert.match(acl, /AreAccessRulesCanonical/u);
  assert.match(acl, /S-1-5-18/u);
  assert.match(acl, /S-1-5-32-544/u);
  assert.match(acl, /FullControl/u);
  assert.match(acl, /PropagationFlags/u);
  assert.match(acl,
    /GetAccessRules\(\$true,\s*\$true,\s*\[Security\.Principal\.SecurityIdentifier\]\)/u,
    'inventory must enumerate inherited ACEs before rejecting them');
  assert.match(acl, /\$rule\.IsInherited/u);
  assert.match(source, /NumberOfLinks/u);
  assert.match(source, /ReparsePoint/u);
});

test('Windows source bounds the verified installed tree by the signed expansion ceiling', async () => {
  const source = await readFile(SCRIPT_URL, 'utf8');
  const generation = section(
    source,
    'Read-AgentRoadVerifiedGeneration',
    'Assert-AgentRoadPartialGenerationTree',
  );

  assert.match(
    generation,
    /\[long\]\$tree\.expandedBytes\s+-gt\s+\[long\]\$manifestComponent\.maximumExpandedBytes/u,
  );
});

test('Windows source binds every nonterminal journal to the only staged operation', async () => {
  const source = await readFile(SCRIPT_URL, 'utf8');
  const snapshot = section(
    source,
    'Get-AgentRoadRuntimeStateSnapshot',
    'Test-AgentRoadRegistryKey',
  );
  const branch = /if \(\$journal\.status -cin @\('running', 'uncertain', 'failed'\)\) \{([\s\S]*?)\n \}/u.exec(snapshot);

  assert.ok(branch, 'missing nonterminal journal branch');
  assert.match(branch[1], /\$operations\.Count\s+-ne\s+1/u);
  assert.match(branch[1], /\$own\.Count\s+-ne\s+1/u);
});

test('Windows source recognizes only the fixed bounded trust-key temporary before pinning', async () => {
  const source = await readFile(SCRIPT_URL, 'utf8');
  const staged = section(
    source,
    'Read-AgentRoadStagedOperation',
    'Get-AgentRoadRuntimeStateSnapshot',
  );
  const temporary = /elseif \(([^\n]*\.controller-key\.next[^\n]*)\) \{([\s\S]*?)\n  \}/u.exec(staged);

  assert.ok(temporary, 'missing fixed controller-key temporary branch');
  assert.match(temporary[1], /\$entry\.Name\s+-ceq\s+'\.controller-key\.next'/u);
  assert.match(staged, /Get-AgentRoadDirectChildren\s+\$work\.FullName/u);
  assert.match(staged, /if \(\$null\s+-eq\s+\$capsuleRecord\) \{ throw 'RUNTIME_STATE_UNSUPPORTED' \}/u);
  assert.match(temporary[2], /Test-Path\s+-LiteralPath\s+\$script:TrustKeyPath/u);
  assert.match(temporary[2], /Assert-AgentRoadFileNode\s+\$entry\.FullName/u);
  assert.match(temporary[2], /\[long\]\$entry\.Length\s+-gt\s+4096/u);
  assert.doesNotMatch(temporary[2], /ReadAllBytes|Read-AgentRoadJsonFile|Get-Content/u);
  assert.match(staged, /hasTemporary\s*=\s*\([^\n]*\$keyTemp/u);
});

test('Windows source recognizes only bounded staged, active, pending and terminal topologies', async () => {
  const source = await readFile(SCRIPT_URL, 'utf8');
  const staged = section(
    source,
    'Read-AgentRoadStagedOperation',
    'Get-AgentRoadRuntimeStateSnapshot',
  );
  const snapshot = section(
    source,
    'Get-AgentRoadRuntimeStateSnapshot',
    'Test-AgentRoadRegistryKey',
  );

  assert.match(source, /EnumerateFileSystemEntries/u);
  assert.match(source, /RUNTIME_STATE_UNSUPPORTED/u);
  assert.match(staged, /\^\[a-f0-9\]\{32\}\$/u);
  assert.match(staged, /\^\[A-F0-9\]\{64\}\$/u);
  assert.match(staged, /work-/u);
  assert.match(staged, /\.capsule-/u);
  assert.match(staged, /\.upload/u);
  assert.match(staged, /powershell-7/u);
  assert.match(snapshot, /active\.json/u);
  assert.match(snapshot, /previous\.json/u);
  assert.match(snapshot, /journal\.json/u);
  assert.match(snapshot, /\.retired-/u);
  assert.match(snapshot, /\.rollback-/u);
  assert.match(snapshot, /'running'\s*,\s*'uncertain'\s*,\s*'failed'/u);
  assert.match(snapshot, /'committed'\s*,\s*'rolled-back'/u);
  assert.match(snapshot, /pendingOperationId\s*=\s*\$pendingOperationId/u);
  assert.match(snapshot, /restartRequired\s*=\s*\$restartRequired/u);
  assert.match(snapshot, /generationVerified\s*=\s*\$true/u);
  assert.match(snapshot, /managedArtifacts\s*=\s*@\(\$activeGeneration\.artifact\)/u);
  assert.match(snapshot, /status\s+-cin\s+@\('committed',\s*'rolled-back'\)/u);

  const runtimeProbe = source.indexOf(
    'Get-AgentRoadRuntimeStateSnapshot -RuntimeRoot $runtimeRoot',
  );
  const platformProbe = source.indexOf('Get-CimInstance -ClassName Win32_OperatingSystem');
  assert.ok(runtimeProbe >= 0);
  assert.ok(platformProbe >= 0);
  assert.ok(runtimeProbe < platformProbe, 'runtime residue must fail closed before platform probes');
  assert.match(source, /schemaVersion\s*=\s*\$null/u);
  assert.match(source, /catalogRevision\s*=\s*\$null/u);
  assert.match(source, /catalogDigest\s*=\s*\$null/u);
  assert.match(source, /generationDigest\s*=\s*\$null/u);
  assert.match(source, /generationVerified\s*=\s*\$false/u);
  assert.match(source, /pendingOperationId\s*=\s*\$null/u);
  assert.match(source, /restartRequired\s*=\s*\$false/u);
  assert.match(source, /managedArtifacts\s*=\s*@\(\)/u);
});

test('Windows source accepts only journal-consistent nonterminal pointer transitions', async () => {
  const source = await readFile(SCRIPT_URL, 'utf8');
  const snapshot = section(
    source,
    'Get-AgentRoadRuntimeStateSnapshot',
    'Test-AgentRoadRegistryKey',
  );
  assert.match(snapshot, /\$operations\.Count\s+-ne\s+1/u);
  assert.match(snapshot, /\$previousPlanned\s*=\s*@\(\$journal\.changes\)\s+-ccontains\s+'previous-replace-planned'/u);
  assert.match(snapshot, /\$activePlanned\s*=\s*@\(\$journal\.changes\)\s+-ccontains\s+'active-replace-planned'/u);
  assert.match(snapshot, /\$rollbackInProgress\s*=/u);
  assert.match(snapshot, /if\s*\(\$rollbackInProgress\s+-and\s+\$activePlanned\)/u);
  assert.match(snapshot, /elseif\s*\(\$previousPlanned\s+-and\s+-not\s+\$activePlanned\)/u);
  assert.match(snapshot, /elseif\s*\(\$activePlanned\)/u);
  assert.doesNotMatch(snapshot, /\$allowedActive|\$allowedPrevious/u);
});

test('Windows source rejects duplicate journal snapshots and missing nonterminal work or publication', async () => {
  const source = await readFile(SCRIPT_URL, 'utf8');
  const staged = section(
    source,
    'Read-AgentRoadStagedOperation',
    'Get-AgentRoadRuntimeStateSnapshot',
  );
  const snapshot = section(
    source,
    'Get-AgentRoadRuntimeStateSnapshot',
    'Test-AgentRoadRegistryKey',
  );
  assert.match(staged, /hasWork\s*=\s*\(\$null\s+-ne\s+\$work\)/u);
  assert.match(snapshot, /\$journal\.snapshot\.active[\s\S]+\$journal\.snapshot\.previous[\s\S]+manifestDigest[\s\S]+RUNTIME_STATE_UNSUPPORTED/u);
  assert.match(snapshot, /-not\s+\$own\[0\]\.hasWork/u);
  assert.match(
    snapshot,
    /\(@\(\$journal\.completedPhases\)\s+-ccontains\s+'materialize-generation'\s+-or\s+@\(\$journal\.changes\)\.Count\s+-gt\s+2\)\s+-and\s+\$null\s+-eq\s+\$journalGeneration/u,
  );
});

test('Windows source applies the exact restricted file assertion to the bootstrap identity journal', async () => {
  const source = await readFile(SCRIPT_URL, 'utf8');
  const bootstrap = section(
    source,
    'Read-AgentRoadBootstrapDeviceId',
    'Read-AgentRoadCapsule',
  );
  assert.match(bootstrap, /Assert-AgentRoadFileNode\s+\$script:BootstrapJournalPath/u);
  assert.doesNotMatch(bootstrap, /GetAccessRules|GetOwner/u);
});

test('Windows source permits an empty trust directory only for one verified staged capsule', async () => {
  const source = await readFile(SCRIPT_URL, 'utf8');
  const snapshot = section(
    source,
    'Get-AgentRoadRuntimeStateSnapshot',
    'Test-AgentRoadRegistryKey',
  );
  assert.match(snapshot, /\$trustEmpty\s*=\s*\$false/u);
  assert.match(snapshot, /\$trustEmpty\s*=\s*\$trustEntries\.Count\s+-eq\s+0/u);
  assert.match(
    snapshot,
    /\$trustEmpty\s+-and\s+\(\$operations\.Count\s+-ne\s+1\s+-or\s+\$null\s+-eq\s+\$operations\[0\]\.capsuleRecord\)/u,
  );
});

test('Windows inventory source parses as PowerShell when pwsh is locally available', async (t) => {
  const probe = spawnSync('pwsh', ['-NoLogo', '-NoProfile', '-Command', '$null'], {
    encoding: 'utf8',
  });
  if (probe.error?.code === 'ENOENT') {
    t.skip('pwsh is unavailable on this Mac');
    return;
  }
  assert.equal(probe.status, 0, probe.stderr);

  const path = RUNTIME_INVENTORY_SCRIPT_PATH.replaceAll("'", "''");
  const parsed = spawnSync('pwsh', [
    '-NoLogo',
    '-NoProfile',
    '-Command',
    `$tokens=$null;$errors=$null;[Management.Automation.Language.Parser]::ParseFile('${path}',[ref]$tokens,[ref]$errors)|Out-Null;if($errors.Count){$errors|ForEach-Object Message;exit 1}`,
  ], { encoding: 'utf8' });
  assert.equal(parsed.status, 0, parsed.stderr || parsed.stdout);
});
