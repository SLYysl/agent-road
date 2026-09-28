import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const scriptUrl = new URL('../windows/runtime-provision-core.ps1', import.meta.url);

const PHASES = [
  'discover',
  'verify-manifest',
  'verify-artifacts',
  'snapshot',
  'materialize-generation',
  'self-test',
  'atomic-activate',
  'validate',
  'commit',
  'rollback',
  'reconcile',
];

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

const RECEIPT_COMPONENT_FIELDS = [
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
];

const RECEIPT_FILE_FIELDS = ['path', 'bytes', 'sha256'];

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

const JOURNAL_SNAPSHOT_FIELDS = ['active', 'previous'];

const RESULT_FIELDS = [
  'schemaVersion',
  'status',
  'operationId',
  'manifestDigest',
  'generationDigest',
  'restartRequired',
  'failureCode',
];

async function source() {
  return readFile(scriptUrl, 'utf8');
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}

function literalArray(text, name) {
  const match = new RegExp(
    `\\$script:${escapeRegExp(name)}\\s*=\\s*@\\(([\\s\\S]*?)\\n\\)`,
    'u',
  ).exec(text);
  assert.ok(match, `missing literal array ${name}`);
  return [...match[1].matchAll(/'([^']+)'/gu)].map((entry) => entry[1]);
}

function section(text, startName, endName) {
  const start = text.indexOf(`function ${startName}`);
  assert.notEqual(start, -1, `missing ${startName}`);
  const end = endName === undefined ? text.length : text.indexOf(`function ${endName}`, start + 1);
  assert.notEqual(end, -1, `missing ${endName}`);
  return text.slice(start, end);
}

function assertInOrder(text, values, label) {
  let cursor = -1;
  for (const value of values) {
    const next = text.indexOf(value, cursor + 1);
    assert.ok(next > cursor, `${label}: ${value} must occur in order`);
    cursor = next;
  }
}

test('freezes the exact eleven-phase vocabulary and forward prefix', async () => {
  const text = await source();

  assert.deepEqual(literalArray(text, 'Phases'), PHASES);
  assert.deepEqual(literalArray(text, 'ForwardPhases'), PHASES.slice(0, 9));
  const journalValidation = section(
    text,
    'Assert-AgentRoadJournal',
    'New-AgentRoadJournal',
  );
  assert.match(journalValidation, /completedPhases[\s\S]+ForwardPhases/u);
  assert.match(journalValidation, /rollback[\s\S]+reconcile/u);
  assert.doesNotMatch(text, /materialize new generation|atomic activate/iu);
});

test('rejects impossible journal terminal states and does not rewrite a committed journal during reconcile', async () => {
  const text = await source();
  const journal = section(text, 'Assert-AgentRoadJournal', 'New-AgentRoadJournal');
  const reconcile = section(text, 'Invoke-AgentRoadReconcile', 'Remove-AgentRoadOwnedTree');

  assert.match(journal, /status\s+-ceq\s+'committed'[\s\S]+completed\.Count\s+-ne\s+\$script:ForwardPhases\.Count/u);
  assert.match(journal, /status\s+-ceq\s+'committed'[\s\S]+phase\s+-cne\s+'commit'/u);
  assert.match(journal, /status\s+-ceq\s+'rolled-back'[\s\S]+phase\s+-cne\s+'rollback'/u);
  assert.match(journal, /status\s+-cin\s+@\('failed',\s*'uncertain',\s*'rolled-back'\)[\s\S]+failureCode/u);
  assert.match(journal, /status\s+-ceq\s+'running'[\s\S]+failureCode/u);

  const committed = reconcile.indexOf("$script:Journal.status -ceq 'committed'");
  const reconcilePublication = reconcile.indexOf("Set-AgentRoadPhase 'reconcile'");
  assert.ok(committed >= 0, 'missing committed reconciliation branch');
  assert.ok(reconcilePublication > committed,
    'a committed journal must be validated without first rewriting its terminal phase');
});

test('uses exact ordered pointer, receipt, journal, and result schemas', async () => {
  const text = await source();
  const schemas = [
    ['PointerFields', POINTER_FIELDS],
    ['ReceiptFields', RECEIPT_FIELDS],
    ['ReceiptComponentFields', RECEIPT_COMPONENT_FIELDS],
    ['ReceiptFileFields', RECEIPT_FILE_FIELDS],
    ['JournalFields', JOURNAL_FIELDS],
    ['JournalSnapshotFields', JOURNAL_SNAPSHOT_FIELDS],
    ['ResultFields', RESULT_FIELDS],
  ];
  for (const [name, fields] of schemas) {
    assert.deepEqual(literalArray(text, name), fields, name);
  }

  const pointerFixture = {
    schemaVersion: 1,
    receiptFormatRevision: 1,
    manifestDigest: 'A'.repeat(64),
    generationDigest: 'B'.repeat(64),
    catalogRevision: 7,
    catalogDigest: 'C'.repeat(64),
    receiptBytes: 1234,
    receiptSha256: 'D'.repeat(64),
  };
  const receiptFixture = {
    schemaVersion: 1,
    receiptFormatRevision: 1,
    operationId: 'a'.repeat(32),
    manifestDigest: 'A'.repeat(64),
    generationDigest: 'B'.repeat(64),
    catalogRevision: 7,
    catalogDigest: 'C'.repeat(64),
    controllerKeyId: 'D'.repeat(64),
    profiles: ['core'],
    components: [],
    files: [],
    restartRequired: false,
  };
  const journalFixture = {
    schemaVersion: 1,
    revision: 1,
    operationId: 'a'.repeat(32),
    manifestDigest: 'A'.repeat(64),
    generationDigest: 'B'.repeat(64),
    catalogDigest: 'C'.repeat(64),
    inventoryDigest: 'D'.repeat(64),
    controllerKeyId: 'E'.repeat(64),
    requestedProfiles: [],
    status: 'running',
    phase: 'discover',
    completedPhases: [],
    changes: [],
    snapshot: { active: null, previous: null },
    restartRequired: false,
    failureCode: null,
    rollbackStatus: 'not-attempted',
  };
  assert.deepEqual(Object.keys(pointerFixture), literalArray(text, 'PointerFields'));
  assert.deepEqual(Object.keys(receiptFixture), literalArray(text, 'ReceiptFields'));
  assert.deepEqual(Object.keys(journalFixture), literalArray(text, 'JournalFields'));
  assert.deepEqual(Object.keys(journalFixture.snapshot), literalArray(text, 'JournalSnapshotFields'));

  const exactRecord = section(
    text,
    'Assert-AgentRoadExactOrderedRecord',
    'ConvertFrom-AgentRoadCanonicalJson',
  );
  assert.match(exactRecord, /PSObject\.Properties\.Name/u);
  assert.match(exactRecord, /CompareOrdinal/u);
  for (const name of ['Assert-AgentRoadPointer', 'Assert-AgentRoadReceipt', 'Assert-AgentRoadJournal']) {
    assert.match(section(text, name, undefined), /Assert-AgentRoadExactOrderedRecord/u, name);
  }
});

test('validates every immutable receipt value and the complete fixed-file allowlist', async () => {
  const text = await source();
  const receipt = section(text, 'Assert-AgentRoadReceipt', 'Assert-AgentRoadJournal');

  for (const expected of [
    "id -cne 'powershell-7'",
    "installRoot -cne 'tools/powershell-7'",
    "verificationCommandId -cne 'powershell-json-roundtrip'",
    'verified -isnot [bool]',
    "'bin/pwsh.cmd'",
    "'capsule.json'",
    "'env.cmd'",
    "'env.ps1'",
    "'scripts/runtime-inventory.ps1'",
    "'scripts/runtime-provision-core.ps1'",
  ]) {
    assert.ok(receipt.includes(expected), `missing receipt invariant: ${expected}`);
  }
  assert.match(receipt, /\$files\.Count\s+-ne\s+\$requiredFiles\.Count/u);
  assert.match(receipt, /treeSha256[\s\S]+\^\[A-F0-9\]\{64\}\$/u);
});

test('read-only node assertions never repair hostile ACLs while validating inputs', async () => {
  const text = await source();
  const fileAssertion = section(text, 'Assert-AgentRoadFileNode', 'Read-AgentRoadInvocation');
  assert.match(fileAssertion, /Assert-AgentRoadRestrictedAcl\s+\$Path\s+\$false/u);
  assert.doesNotMatch(fileAssertion, /Set-AgentRoadRestrictedFileAcl/u);
  const directoryAssertion = section(text, 'Assert-AgentRoadDirectoryNode', 'Assert-AgentRoadRestrictedAcl');
  assert.match(directoryAssertion, /Assert-AgentRoadRestrictedAcl\s+\$Path\s+\$true/u);
  assert.doesNotMatch(directoryAssertion, /Set-AgentRoadRestrictedDirectoryAcl/u);
});

test('requires propagation-none on every exact runtime ACL rule', async () => {
  const text = await source();
  const acl = section(
    text,
    'Assert-AgentRoadRestrictedAcl',
    'New-AgentRoadRestrictedDirectorySecurity',
  );

  assert.match(
    acl,
    /\$rule\.PropagationFlags\s+-ne\s+\[Security\.AccessControl\.PropagationFlags\]::None/u,
  );
  assert.match(acl,
    /GetAccessRules\(\$true,\s*\$true,\s*\[Security\.Principal\.SecurityIdentifier\]\)/u,
    'exact ACL reads must include inherited ACEs so they can be rejected');
  assert.match(acl, /\$rule\.IsInherited/u);
});

test('attaches the exact protected filesystem security descriptor at every creation point', async () => {
  const text = await source();
  const directorySecurity = section(
    text,
    'New-AgentRoadRestrictedDirectorySecurity',
    'New-AgentRoadRestrictedFileSecurity',
  );
  const fileSecurity = section(
    text,
    'New-AgentRoadRestrictedFileSecurity',
    'New-AgentRoadRestrictedFileStream',
  );
  const fileCreation = section(
    text,
    'New-AgentRoadRestrictedFileStream',
    'Ensure-AgentRoadRestrictedDirectory',
  );
  const directoryCreation = section(
    text,
    'Ensure-AgentRoadRestrictedDirectory',
    'Ensure-AgentRoadRestrictedDirectoryChain',
  );

  for (const [name, descriptor] of [
    ['directory', directorySecurity],
    ['file', fileSecurity],
  ]) {
    assert.match(descriptor,
      /\$owner\s*=\s*\$admins\.Translate\(\[Security\.Principal\.NTAccount\]\)/u,
      `${name} owner translation`);
    assert.match(descriptor, /SetOwner\(\$owner\)/u, `${name} translated owner`);
    assert.doesNotMatch(descriptor, /\.SetOwner\(\$admins\)/u,
      `${name} must not pass a SID directly to SetOwner`);
    assert.match(descriptor, /SetAccessRuleProtection\(\$true,\s*\$false\)/u,
      `${name} protected DACL`);
    assert.equal((descriptor.match(/FileSystemRights\]::FullControl/gu) ?? []).length, 2,
      `${name} SYSTEM and Administrators FullControl`);
    assert.match(descriptor, /S-1-5-18/u, `${name} SYSTEM SID`);
    assert.match(descriptor, /S-1-5-32-544/u, `${name} Administrators SID`);
    assert.match(descriptor, /PropagationFlags\]::None/u, `${name} no propagation`);
  }
  assert.match(directorySecurity, /ContainerInherit/u);
  assert.match(directorySecurity, /ObjectInherit/u);
  assert.match(fileSecurity, /InheritanceFlags\]::None/u);

  assert.match(fileCreation, /\[Security\.AccessControl\.FileSecurity\]\$security/u,
    'type the security argument for Windows PowerShell 5.1 overload resolution');
  assertInOrder(fileCreation, [
    'New-Object IO.FileStream(',
    '[IO.FileMode]::CreateNew',
    '[Security.AccessControl.FileSystemRights]::FullControl',
    '[IO.FileShare]::None',
    '[IO.FileOptions]::WriteThrough',
    '$security',
  ], 'security-aware FileStream constructor');
  assertInOrder(directoryCreation, [
    'New-AgentRoadRestrictedDirectorySecurity',
    '[IO.Directory]::CreateDirectory($Path, $security)',
    'Assert-AgentRoadDirectoryNode $Path',
  ], 'security-aware directory creation');

  assert.equal((text.match(/\[IO\.FileMode\]::CreateNew/gu) ?? []).length, 1,
    'all runtime-owned files must use the one security-aware creation primitive');
  assert.equal((text.match(/\[IO\.Directory\]::CreateDirectory/gu) ?? []).length, 1,
    'all runtime-owned directories must use the one security-aware creation primitive');
  assert.equal((text.match(/New-AgentRoadRestrictedFileStream/gu) ?? []).length, 5,
    'the helper definition plus ZIP, mutable JSON, trust key, and immutable generation files');
  assert.equal((text.match(/\[IO\.File\]::Open\(/gu) ?? []).length, 1,
    'the only raw File.Open call is the read-only ZIP input');
  assert.match(text,
    /\[IO\.File\]::Open\(\$ArchivePath,\s*\[IO\.FileMode\]::Open,\s*\[IO\.FileAccess\]::Read/u);
  assert.doesNotMatch(text,
    /\[IO\.File\]::(?:Create|OpenWrite|WriteAllBytes|WriteAllText|AppendAllText)\b/u);
  assert.doesNotMatch(text,
    /\[IO\.FileMode\]::(?:Create|OpenOrCreate|Append|Truncate)\b/u);
  assert.doesNotMatch(text, /\b(?:New-Item|Out-File|Set-Content|Add-Content)\b/u);
  assert.doesNotMatch(text, /SetAccessControl/u,
    'no runtime-owned node may be created first and secured later');

  for (const [start, end, label] of [
    ['Expand-AgentRoadPowerShellArchive', 'Get-AgentRoadFileLinkCount', 'ZIP output'],
    ['Publish-AgentRoadMutableJson', 'Publish-AgentRoadGeneration', 'mutable next file'],
    ['Ensure-AgentRoadControllerTrust', 'Assert-AgentRoadBootstrapJournalFile', 'trust key'],
    ['Write-AgentRoadImmutableBytes', 'Write-AgentRoadGenerationFiles', 'immutable generation file'],
  ]) {
    const createSite = section(text, start, end);
    assert.match(createSite, /New-AgentRoadRestrictedFileStream/u, label);
    assert.match(createSite, /Assert-AgentRoadFileNode/u, `${label} post-create ACL check`);
  }
});

test('permits exactly one portable powershell-7 core component and no machine-wide integration', async () => {
  const text = await source();
  assert.deepEqual(literalArray(text, 'CoreProfiles'), ['core']);
  assert.match(text, /\$script:CoreComponentId\s*=\s*'powershell-7'/u);
  assert.match(text, /components\.Count\s+-ne\s+1/u);
  assert.match(text, /packaging\s+-cne\s+'zip'/u);
  assert.match(text, /verificationCommandId\s+-cne\s+'powershell-json-roundtrip'/u);
  assert.match(text, /tools\\powershell-7/u);
  assert.match(text, /bin\\pwsh\.cmd/u);
  assert.match(text, /env\.ps1/u);
  assert.match(text, /env\.cmd/u);
  assert.match(text, /\$environmentPowerShell\s*=\s*"`\$AgentRoadRuntimeRoot = `\$PSScriptRoot`r`n"/u,
    'env.ps1 lives at the generation root and must resolve that directory directly');

  assert.doesNotMatch(text, /(?:New|Set|Start|Restart|Stop)-Service\b|sc\.exe/iu);
  assert.doesNotMatch(text, /ScheduledTask|schtasks(?:\.exe)?/iu);
  assert.doesNotMatch(text, /(?:New|Set|Remove)-NetFirewallRule|netsh\b/iu);
  assert.doesNotMatch(text, /(?:New|Set|Remove)-ItemProperty\b|CreateSubKey/u);
  assert.doesNotMatch(text, /SetEnvironmentVariable|EnvironmentVariableTarget|\$env:Path\s*=|setx(?:\.exe)?/iu);
  assert.doesNotMatch(text, /Restart-Computer|Stop-Computer|shutdown(?:\.exe)?|ExitWindowsEx/iu);
  assert.doesNotMatch(text, /mingit|nodejs|python/iu);
});

test('post-upload disk gate requires exactly 256 MiB reserve plus expanded bytes', async () => {
  const text = await source();
  const preconditions = section(
    text,
    'Assert-AgentRoadMachinePreconditions',
    'Assert-AgentRoadArtifact',
  );

  assert.match(preconditions, /\$transactionReserveBytes\s*=\s*\[long\]268435456/u);
  assert.match(
    preconditions,
    /\$maximumExpandedBytes\s*=\s*\[long\]\$Manifest\.components\[0\]\.maximumExpandedBytes/u,
  );
  assert.match(
    preconditions,
    /\$maximumExpandedBytes\s+-gt\s*\(\[long\]::MaxValue\s+-\s*\$transactionReserveBytes\)/u,
    'addition must fail closed before signed Int64 overflow',
  );
  assert.match(
    preconditions,
    /\$requiredFreeBytes\s*=\s*\[long\]\(\$transactionReserveBytes\s*\+\s*\$maximumExpandedBytes\)/u,
  );
  assert.match(
    preconditions,
    /\[long\]\$drive\.AvailableFreeSpace\s+-lt\s+\$requiredFreeBytes/u,
  );
  assert.doesNotMatch(preconditions, /maximumExpandedBytes\s*\*\s*2/iu);

  assertInOrder(preconditions, [
    'Component Based Servicing\\RebootPending',
    'WindowsUpdate\\Auto Update\\RebootRequired',
    'SYSTEM\\CurrentControlSet\\Control\\Session Manager',
    'PendingFileRenameOperations',
  ], 'complete mutation-lock pending-reboot predicate');

  const keyLoopStart = preconditions.indexOf('foreach ($subKey');
  const valueProbeStart = preconditions.indexOf('$sessionManager =');
  const diskStart = preconditions.indexOf('$drive =');
  assert.ok(keyLoopStart >= 0 && valueProbeStart > keyLoopStart && diskStart > valueProbeStart);
  const keyLoop = preconditions.slice(keyLoopStart, valueProbeStart);
  const valueProbe = preconditions.slice(valueProbeStart, diskStart);
  assertInOrder(keyLoop, [
    'OpenSubKey($subKey, $false)',
    '$null -ne $key',
    "throw 'RUNTIME_INVENTORY_CHANGED'",
    'finally',
    '$key.Dispose()',
  ], 'registry-key reboot gate');
  assertInOrder(valueProbe, [
    'OpenSubKey(',
    'SYSTEM\\CurrentControlSet\\Control\\Session Manager',
    '$null -eq $sessionManager',
    '$sessionManager.GetValueNames()',
    "-icontains 'PendingFileRenameOperations'",
    "throw 'RUNTIME_INVENTORY_CHANGED'",
    'finally',
    '$sessionManager.Dispose()',
  ], 'registry-value-name reboot gate');
  assert.doesNotMatch(valueProbe, /\.GetValue\(/u,
    'empty or non-data registry values must still block mutation');

  const reserve = 256n * 1024n * 1024n;
  const expanded = 296_034_085n;
  const required = reserve + expanded;
  assert.equal(564_469_540n < required, true);
  assert.equal(564_469_541n < required, false);
  assert.equal(required, 564_469_541n);
  assert.equal(34_359_738_368n <= BigInt.asIntN(64, (2n ** 63n) - 1n) - reserve, true);
});

test('binds the signed new plan before the machine gate and every new-plan mutator', async () => {
  const text = await source();
  const main = text.slice(text.lastIndexOf('$lock = $null'));
  const newPlanStart = main.indexOf(
    "if (-not $finished) {\n        Assert-AgentRoadStagedTransaction",
  );
  assert.ok(newPlanStart >= 0, 'missing signed new-plan branch');
  const newPlan = main.slice(newPlanStart);

  assertInOrder(newPlan, [
    'Assert-AgentRoadManifest $capsule $manifestBytes $manifest',
    'Assert-AgentRoadControllerSignature $capsule $manifestBytes',
    'Assert-AgentRoadOperationBinding $script:Transaction $capsule $manifest $capsuleBytes',
    'Assert-AgentRoadMachinePreconditions $manifest',
    'Ensure-AgentRoadRestrictedDirectory $script:TrustRoot',
    '$script:Journal = New-AgentRoadJournal',
    'Invoke-AgentRoadMaterializeGeneration',
    'Invoke-AgentRoadActivation',
  ], 'signed binding and machine gate before new-plan mutation');
});

test('installed runtime inventory resolves the runtime state root above versions and generation', async () => {
  const text = await source();
  const files = section(
    text,
    'Write-AgentRoadGenerationFiles',
    'Get-AgentRoadFixedFileReceipts',
  );

  assertInOrder(files, [
    '$generationRoot = Split-Path -Parent $PSScriptRoot',
    '$versionsRoot = Split-Path -Parent $generationRoot',
    '$runtimeRoot = Split-Path -Parent $versionsRoot',
    "$active = Join-Path (Join-Path $runtimeRoot 'state') 'active.json'",
  ], 'installed runtime inventory root');
  assert.doesNotMatch(files, /Join-Path \(Join-Path \$generationRoot 'state'\)/u);
});

test('holds one explicitly secured Global mutex without a split-domain fallback', async () => {
  const text = await source();
  const lock = section(text, 'Enter-AgentRoadMutationLock', 'Exit-AgentRoadMutationLock');
  const unlock = section(text, 'Exit-AgentRoadMutationLock', 'Assert-AgentRoadDirectoryNode');

  assert.match(lock, /Threading\.Mutex/u);
  assert.match(lock, /Global\\AgentRoadRuntimeMutation/u);
  assert.match(lock, /Security\.AccessControl\.MutexSecurity/u);
  assert.match(lock, /SetAccessRuleProtection\(\$true,\s*\$false\)/u);
  assert.match(lock,
    /\$ownerAccount\s*=\s*\$admins\.Translate\(\[Security\.Principal\.NTAccount\]\)/u);
  assert.match(lock, /SetOwner\(\$ownerAccount\)/u);
  assert.doesNotMatch(lock, /SetOwner\(\$admins\)/u,
    'Windows PowerShell 5.1 must not pass a SID directly as the mutex owner');
  assert.match(lock, /S-1-5-18/u);
  assert.match(lock, /S-1-5-32-544/u);
  assert.match(lock, /MutexRights\]::FullControl/u);
  assertInOrder(lock, [
    '$ownerAccount = $admins.Translate([Security.Principal.NTAccount])',
    '$security.SetOwner($ownerAccount)',
    "New-Object Threading.Mutex($false, 'Global\\AgentRoadRuntimeMutation'",
    '$mutex.GetAccessControl()',
    'GetOwner([Security.Principal.SecurityIdentifier]).Value',
    'GetAccessRules($true, $false',
    'AreAccessRulesProtected',
    'AreAccessRulesCanonical',
    'IsInherited',
    'WaitOne(0)',
  ], 'post-open mutex ACL verification before acquisition');
  assert.match(lock, /\$rules\.Count\s+-ne\s+2/u);
  assert.match(lock, /\$owner\s+-cne\s+'S-1-5-32-544'/u);
  assert.match(lock, /InheritanceFlags[\s\S]+InheritanceFlags\]::None/u);
  assert.match(lock, /PropagationFlags[\s\S]+PropagationFlags\]::None/u);
  assert.doesNotMatch(lock, /SetAccessControl/u, 'an existing mutex ACL must never be repaired');
  assert.match(lock, /MutexRights\]::FullControl/u);
  assert.match(lock, /WaitOne\(0\)/u);
  assert.match(lock, /catch\s+\[System\.Threading\.AbandonedMutexException\][\s\S]+kind\s*=\s*'mutex'/u,
    'an abandoned mutex is already acquired by this thread and must be returned as the live lock');
  assert.match(lock, /catch\s+\[System\.UnauthorizedAccessException\][\s\S]+RUNTIME_STATE_UNSUPPORTED/u);
  assert.match(lock, /catch\s+\[System\.Threading\.WaitHandleCannotBeOpenedException\][\s\S]+RUNTIME_STATE_UNSUPPORTED/u);
  assert.equal((lock.match(/RUNTIME_ALREADY_RUNNING/gu) ?? []).length, 1,
    'only contention on a verified mutex is already-running');
  assert.doesNotMatch(lock, /FileMode|FileAccess|FileShare|mutation\.lock/u);
  assert.match(unlock, /ReleaseMutex/u);
  assert.match(unlock, /Dispose\(\)/u);
  assert.doesNotMatch(lock, /LastWriteTime|CreationTime|UtcNow|AddMinutes|stale/iu);

  const main = text.slice(text.lastIndexOf('$lock = $null'));
  assert.match(main, /finally[\s\S]+Exit-AgentRoadMutationLock/u);
  assert.doesNotMatch(text, /\.SetOwner\(\$(?:admins|system)\)/u,
    'all security descriptor owners must be translated NTAccount values');
});

test('reads one bounded canonical invocation record from stdin instead of guessing an operation', async () => {
  const text = await source();
  assert.deepEqual(literalArray(text, 'InvocationFields'), [
    'schemaVersion',
    'operationId',
    'manifestDigest',
  ]);
  const reader = section(text, 'Read-AgentRoadInvocation', 'Get-AgentRoadTransaction');
  assert.match(reader, /\[Console\]::InputEncoding/u);
  assert.match(reader, /\[Console\]::In\.Read\(\)/u);
  assert.match(reader, /-gt\s+192/u);
  assert.match(reader, /FEFF|65279/u);
  assert.match(reader, /(?:0x0A|10)[\s\S]+(?:0x0D|13)/u);
  assert.match(reader, /Assert-AgentRoadExactOrderedRecord[\s\S]+InvocationFields/u);
  assert.match(reader, /ConvertTo-Json[^\n]+-Compress/u);
  assert.match(reader, /operationId[\s\S]+\^\[a-f0-9\]\{32\}\$/u);
  assert.match(reader, /manifestDigest[\s\S]+\^\[A-F0-9\]\{64\}\$/u);
  assert.doesNotMatch(reader, /ReadToEnd|ReadLine/u);
  assert.doesNotMatch(text.slice(0, text.indexOf('function ')), /^\s*param\s*\(/imu);
  assert.doesNotMatch(text, /Environment\.GetEnvironmentVariable|\$env:AGENT_ROAD/iu);

  const transaction = section(text, 'Get-AgentRoadTransaction', 'Assert-AgentRoadStagedTransaction');
  assert.match(transaction, /\[pscustomobject\]\$Invocation/u);
  assert.match(transaction, /\$Invocation\.operationId/u);
  assert.match(transaction, /\$Invocation\.manifestDigest/u);
  assert.doesNotMatch(transaction, /transactions\[0\]|operations\[0\]/u);
});

test('classifies a committed journal before requiring a complete upload transaction', async () => {
  const text = await source();
  const main = text.slice(text.lastIndexOf('$lock = $null'));

  assertInOrder(main, [
    'Read-AgentRoadInvocation',
    'Get-AgentRoadTransaction',
    'Enter-AgentRoadMutationLock',
    'Read-AgentRoadJournal',
    "$script:Journal.status -ceq 'committed'",
    'Assert-AgentRoadStagedTransaction',
  ], 'committed cleanup recovery ordering');
  assert.match(main, /Read-AgentRoadCommittedRuntime/u);
  assert.match(main, /Remove-AgentRoadCommittedStaging/u);
});

test('binds a non-committed journal before capsule checks and before any rollback-owned deletion', async () => {
  const text = await source();
  const binding = section(
    text,
    'Assert-AgentRoadJournalTransactionBinding',
    'Read-AgentRoadJournalGenerationPointer',
  );
  const rollback = section(text, 'Invoke-AgentRoadRollback', 'Invoke-AgentRoadReconcile');
  const removal = section(text, 'Remove-AgentRoadNewGeneration', 'Invoke-AgentRoadRollback');
  const main = text.slice(text.lastIndexOf('$lock = $null'));

  assert.match(binding, /Journal\.operationId[\s\S]+Transaction\.operationId/u);
  assert.match(binding, /Journal\.manifestDigest[\s\S]+Transaction\.manifestDigest/u);
  assert.match(binding, /RUNTIME_OPERATION_CONFLICT/u);
  assertInOrder(main, [
    'Read-AgentRoadJournal',
    "$script:Journal.status -cnotin @('committed', 'rolled-back')",
    'Assert-AgentRoadJournalTransactionBinding',
    'Assert-AgentRoadStagedTransaction',
    '$capsuleBytes = [IO.File]::ReadAllBytes',
    'Assert-AgentRoadMachinePreconditions',
  ], 'non-committed journal binding');
  assertInOrder(rollback, [
    'Assert-AgentRoadJournalTransactionBinding',
    "$script:Journal.status = 'failed'",
    'Restore-AgentRoadActivePointer',
    'Remove-AgentRoadNewGeneration',
  ], 'rollback binding');
  assert.match(removal, /generation-publish-planned/u);
  assert.match(removal, /\$script:Journal\.manifestDigest/u);
  assert.match(removal, /Read-AgentRoadJournalGenerationPointer/u,
    'a rollback deletion must validate the journal-bound generation receipt first');
  assert.doesNotMatch(removal, /\$script:Transaction\.manifestDigest/u);
});

test('authorizes catch rollback only after full signed and trusted transaction binding', async () => {
  const text = await source();
  const main = text.slice(text.lastIndexOf('$lock = $null'));
  const resumeStart = main.indexOf('if ($null -ne $script:Journal)');
  const resumeEnd = main.indexOf('if (-not $finished -and', resumeStart);
  assert.ok(resumeStart >= 0 && resumeEnd > resumeStart, 'missing resume/new-journal dispatch');
  const dispatch = main.slice(resumeStart, resumeEnd);
  const newJournalStart = dispatch.indexOf('} else {');
  assert.ok(newJournalStart >= 0, 'missing fresh-journal branch');
  const existing = dispatch.slice(0, newJournalStart);
  const fresh = dispatch.slice(newJournalStart);

  assertInOrder(main, [
    '$rollbackAuthorized = $false',
    'Assert-AgentRoadControllerSignature $capsule $manifestBytes',
    'Assert-AgentRoadOperationBinding $script:Transaction $capsule $manifest $capsuleBytes',
    'Ensure-AgentRoadControllerTrust',
  ], 'rollback authorization prerequisites');
  assertInOrder(existing, [
    '$rollbackAuthorized = $true',
    'Invoke-AgentRoadReconcile',
  ], 'existing journal authorization');
  assertInOrder(fresh, [
    '$script:Journal = New-AgentRoadJournal',
    'Publish-AgentRoadJournal',
    '$rollbackAuthorized = $true',
  ], 'fresh journal authorization');
  assert.match(main, /elseif\s*\(\s*\$null\s+-ne\s+\$script:Journal\s+-and\s+\$rollbackAuthorized\s*\)/u);
});

test('guards both pointer transitions before rollback can restore either pointer', async () => {
  const text = await source();
  const guard = section(
    text,
    'Assert-AgentRoadRollbackPointerTransitions',
    'Invoke-AgentRoadActivation',
  );
  const rollback = section(text, 'Invoke-AgentRoadRollback', 'Invoke-AgentRoadReconcile');

  assertInOrder(guard, [
    '$currentActive = Read-AgentRoadPointer',
    '$currentPrevious = Read-AgentRoadPointer',
    "$script:Journal.changes) -ccontains 'active-replace-planned'",
    'Read-AgentRoadJournalGenerationPointer',
    "throw 'RUNTIME_ROLLBACK_INCOMPLETE'",
  ], 'rollback transition guard');
  assert.match(guard, /Test-AgentRoadPointerValue\s+\$currentActive\s+\$script:Journal\.snapshot\.active/u);
  assert.match(guard, /Test-AgentRoadPointerValue\s+\$currentPrevious\s+\$script:Journal\.snapshot\.previous/u);
  assert.match(guard, /Test-AgentRoadPointerValue\s+\$currentPrevious\s+\$script:Journal\.snapshot\.active/u);
  assertInOrder(rollback, [
    'Assert-AgentRoadRollbackPointerTransitions',
    'Restore-AgentRoadActivePointer',
    'Restore-AgentRoadPreviousPointer',
    'Invoke-AgentRoadOldGenerationSmokeTest',
    'Remove-AgentRoadNewGeneration',
  ], 'guarded rollback');
});

test('captures the pre-mutation pointer snapshot before any early failure can roll back', async () => {
  const text = await source();
  const early = section(
    text,
    'Initialize-AgentRoadPointerSnapshot',
    'Publish-AgentRoadPreviousPointer',
  );
  assert.match(early, /completedPhases[\s\S]+snapshot/u);
  assert.match(early, /generation-publish-planned/u);
  assert.match(early, /Journal\.snapshot\.active/u);
  assert.match(early, /Journal\.snapshot\.previous/u);
  assert.match(early, /Save-AgentRoadPointerSnapshot/u);

  const main = text.slice(text.lastIndexOf('$lock = $null'));
  const forward = main.slice(main.indexOf('if (-not $finished)'));
  assertInOrder(forward, [
    'Ensure-AgentRoadControllerTrust',
    'Initialize-AgentRoadPointerSnapshot',
    'Invoke-AgentRoadReconcile',
  ], 'resumed journal snapshot before reconciliation/rollback');
  const fresh = forward.slice(forward.indexOf('} else {'));
  assertInOrder(fresh, [
    '$script:Journal = New-AgentRoadJournal',
    'Publish-AgentRoadJournal',
    'Initialize-AgentRoadPointerSnapshot',
    "Add-AgentRoadChange 'work-created'",
  ], 'fresh journal snapshot before fallible forward phases');
});

test('keeps exact committed retries idempotent but opens a validated different transaction', async () => {
  const text = await source();
  const main = text.slice(text.lastIndexOf('$lock = $null'));
  const committedStart = main.indexOf("$script:Journal.status -ceq 'committed'");
  const forwardStart = main.indexOf('if (-not $finished)', committedStart);
  assert.ok(committedStart >= 0 && forwardStart > committedStart, 'missing committed dispatch');
  const committed = main.slice(committedStart, forwardStart);

  assert.match(committed, /sameCommittedOperation[\s\S]+Journal\.operationId[\s\S]+invocation\.operationId/u);
  assert.match(committed, /sameCommittedManifest[\s\S]+Journal\.manifestDigest[\s\S]+invocation\.manifestDigest/u);
  assert.match(committed, /sameCommittedOperation\s+-and\s+\$sameCommittedManifest/u);
  assert.match(committed, /sameCommittedOperation\s+-or\s+\$sameCommittedManifest[\s\S]+RUNTIME_OPERATION_CONFLICT/u,
    'partial identity reuse is a conflict, not a new transaction');
  assertInOrder(committed, [
    '$committedInvocation = [pscustomobject][ordered]@{',
    'Read-AgentRoadCommittedRuntime $committedInvocation',
    '$script:Journal = $null',
  ], 'validated committed handoff');
  assert.ok(main.indexOf('$script:Journal = $null', committedStart) < main.indexOf('Assert-AgentRoadStagedTransaction'),
    'the old terminal journal must not enter new capsule failure or rollback handling');
  assert.ok(main.indexOf('New-AgentRoadJournal', forwardStart) > forwardStart,
    'the different upgrade must publish a fresh transaction journal');
});

test('turns over only an exact terminal rolled-back operation before a different upgrade', async () => {
  const text = await source();
  const cleanup = section(
    text,
    'Remove-AgentRoadRolledBackStaging',
    'Remove-AgentRoadCommittedStaging',
  );
  assert.match(cleanup, /Journal\.status\s+-cne\s+'rolled-back'/u);
  assert.match(cleanup, /Journal\.rollbackStatus\s+-cne\s+'succeeded'/u);
  assert.match(cleanup, /Assert-AgentRoadJournalTransactionBinding/u);
  assert.match(cleanup, /PreservedTransaction/u);
  assert.match(cleanup, /Assert-AgentRoadManifest/u);
  assert.match(cleanup, /Assert-AgentRoadControllerSignature/u);
  assert.match(cleanup, /Assert-AgentRoadPinnedControllerTrust/u);
  assert.match(cleanup, /Assert-AgentRoadGenerationTombstoneTree/u);
  assertInOrder(cleanup, [
    'Remove-AgentRoadOwnedTree $OldTransaction.workRoot',
    '[IO.File]::Delete($artifact.FullName)',
    '[IO.Directory]::Delete($OldTransaction.filesRoot, $false)',
    '[IO.File]::Delete($OldTransaction.capsulePath)',
    '[IO.Directory]::Delete($OldTransaction.transactionRoot, $false)',
    '[IO.Directory]::Delete($OldTransaction.operationRoot, $false)',
  ], 'monotone rolled-back staging cleanup');

  const main = text.slice(text.lastIndexOf('$lock = $null'));
  const rolledBackDispatch = main.indexOf("$script:Journal.status -ceq 'rolled-back'");
  const genericBinding = main.indexOf('Assert-AgentRoadJournalTransactionBinding');
  assert.ok(rolledBackDispatch >= 0 && rolledBackDispatch < genericBinding,
    'terminal rolled-back dispatch must precede generic nonterminal binding');
  const terminal = main.slice(rolledBackDispatch, main.indexOf("$script:Journal.status -ceq 'committed'"));
  assert.match(terminal, /sameRolledBackOperation/u);
  assert.match(terminal, /sameRolledBackManifest/u);
  assert.match(terminal, /sameRolledBackOperation\s+-or\s+\$sameRolledBackManifest[\s\S]+RUNTIME_OPERATION_CONFLICT/u);
  assertInOrder(terminal, [
    '$rolledBackTransaction = Get-AgentRoadTransaction',
    'Remove-AgentRoadNewGeneration',
    'Remove-AgentRoadRolledBackStaging',
  ], 'terminal cleanup before retry/turnover');
  assert.match(terminal, /Write-AgentRoadResult\s+'rolled-back'/u);
  assertInOrder(terminal, [
    'Remove-AgentRoadRolledBackStaging',
    '$script:Journal = $null',
  ], 'different operation turnover only after old cleanup');
});

test('preserves a terminal rolled-back journal when cleanup completion is uncertain', async () => {
  const text = await source();
  const main = text.slice(text.lastIndexOf('$lock = $null'));
  assert.match(main, /Journal\.status\s+-cin\s+@\('committed',\s*'rolled-back'\)[\s\S]+RUNTIME_COMPLETION_UNCERTAIN/u);
  const uncertain = main.slice(main.indexOf("if ($failureCode -ceq 'RUNTIME_COMPLETION_UNCERTAIN')"));
  assert.match(uncertain, /Journal\.status\s+-cnotin\s+@\('committed',\s*'rolled-back'\)/u);
});

test('cleans only old committed staging while preserving a staged different upgrade', async () => {
  const text = await source();
  const cleanup = section(text, 'Remove-AgentRoadCommittedStaging', 'Write-AgentRoadResult');
  const main = text.slice(text.lastIndexOf('$lock = $null'));
  const committedStart = main.indexOf("$script:Journal.status -ceq 'committed'");
  const forwardStart = main.indexOf('if (-not $finished)', committedStart);
  const committed = main.slice(committedStart, forwardStart);

  assert.match(cleanup, /\[pscustomobject\]\$Transaction/u);
  assert.match(cleanup, /\$PreservedTransaction/u);
  assert.match(cleanup, /allowedOperationRoots/iu);
  assert.match(cleanup, /PreservedTransaction\.operationRoot/u);
  assert.match(cleanup, /Remove-AgentRoadOwnedTree\s+\$Transaction\.workRoot/u);
  assert.match(cleanup, /Remove-AgentRoadOwnedTree\s+\$Transaction\.transactionRoot/u);
  assert.doesNotMatch(cleanup, /Remove-AgentRoadOwnedTree\s+\$PreservedTransaction/u,
    'new staged transaction must never be a cleanup target');
  assertInOrder(committed, [
    '$committedTransaction = Get-AgentRoadTransaction $committedInvocation',
    'Read-AgentRoadCommittedRuntime $committedInvocation',
    'Remove-AgentRoadCommittedStaging',
    '$committedTransaction',
    '$script:Transaction',
    '$script:Journal = $null',
  ], 'old committed cleanup before journal turnover');
  assert.match(main, /Journal\.status\s+-ceq\s+'committed'[\s\S]+failureCode\s+-cnotin\s+@\('RUNTIME_OPERATION_CONFLICT',\s*'RUNTIME_STATE_UNSUPPORTED'\)[\s\S]+RUNTIME_COMPLETION_UNCERTAIN/u,
    'definitive committed conflicts and hostile state must not be rewritten as uncertainty');
});

test('validates exact runtime topology and every persisted pointer before mutation', async () => {
  const text = await source();
  assert.deepEqual(literalArray(text, 'RuntimeEntryNames'), [
    'staging',
    'trust',
    'versions',
    'state',
  ]);
  assert.deepEqual(literalArray(text, 'TrustEntryNames'), ['controller-key.json']);
  assert.deepEqual(literalArray(text, 'StateEntryNames'), [
    'journal.json',
    'active.json',
    'previous.json',
  ]);

  const verified = section(
    text,
    'Read-AgentRoadVerifiedGenerationPointer',
    'Assert-AgentRoadRuntimeTopology',
  );
  assertInOrder(verified, [
    'Assert-AgentRoadGenerationTree',
    'ReadAllBytes($capsulePath)',
    'Assert-AgentRoadManifest',
    'Assert-AgentRoadControllerSignature',
    'Assert-AgentRoadPinnedControllerTrust',
    'Assert-AgentRoadAdoptedGeneration',
    'Test-AgentRoadPointerValue',
  ], 'persisted generation verification');

  const topology = section(
    text,
    'Assert-AgentRoadRuntimeTopology',
    'Publish-AgentRoadMutableJson',
  );
  assert.match(topology, /Get-ChildItem\s+-LiteralPath\s+\$script:RuntimeRoot/u);
  assert.match(topology, /RuntimeEntryNames/u);
  assert.match(topology, /TrustEntryNames/u);
  assert.match(topology, /StateEntryNames/u);
  assert.match(topology, /Read-AgentRoadPointer\s+\$script:ActivePath/u);
  assert.match(topology, /Read-AgentRoadPointer\s+\$script:PreviousPath/u);
  assert.match(topology, /Read-AgentRoadVerifiedGenerationPointer/u);
  assert.match(topology, /Get-ChildItem\s+-LiteralPath\s+\$script:VersionsRoot/u);
  assert.match(topology, /generation-publish-planned/u);
  assert.match(topology, /RUNTIME_STATE_UNSUPPORTED/u);

  const main = text.slice(text.lastIndexOf('$lock = $null'));
  assertInOrder(main, [
    'Read-AgentRoadJournal',
    'Assert-AgentRoadRuntimeTopology',
    'Remove-AgentRoadCommittedStaging',
  ], 'topology before committed cleanup mutation');
  assert.ok(
    main.indexOf('Assert-AgentRoadRuntimeTopology')
      < main.indexOf('Ensure-AgentRoadRestrictedDirectory $script:TrustRoot'),
    'topology must precede directory/trust mutation',
  );
});

test('publishes first controller trust atomically from only its operation-bound work temp', async () => {
  const text = await source();
  const nextPath = section(
    text,
    'Get-AgentRoadControllerTrustNextPath',
    'Remove-AgentRoadControllerTrustNextFile',
  );
  const cleanup = section(
    text,
    'Remove-AgentRoadControllerTrustNextFile',
    'Ensure-AgentRoadControllerTrust',
  );
  const trust = section(
    text,
    'Ensure-AgentRoadControllerTrust',
    'Assert-AgentRoadBootstrapJournalFile',
  );
  const topology = section(
    text,
    'Assert-AgentRoadRuntimeTopology',
    'Publish-AgentRoadMutableJson',
  );

  assertInOrder(nextPath, [
    '$Transaction.operationId',
    '$Transaction.manifestDigest',
    '$Transaction.workRoot',
    "'.controller-key.next'",
    '[IO.Path]::GetFullPath($nextPath)',
    '[IO.Path]::GetDirectoryName($nextPath)',
  ], 'operation-bound trust temp path');
  assert.doesNotMatch(nextPath, /TrustRoot|NewGuid|GetTempPath/iu,
    'the trust temp belongs to the exact staged operation work root');

  assertInOrder(cleanup, [
    'Get-AgentRoadControllerTrustNextPath $Transaction',
    '$Path -cne $expectedPath',
    'Test-Path -LiteralPath $script:TrustKeyPath',
    'Assert-AgentRoadDirectoryNode $Transaction.workRoot',
    'Assert-AgentRoadFileNode $Path',
    '[IO.File]::Delete($Path)',
    'Test-Path -LiteralPath $Path',
  ], 'bounded partial trust-temp cleanup');
  assert.doesNotMatch(cleanup,
    /Get-ChildItem|Remove-Item|\[IO\.File\]::Delete\(\$script:TrustKeyPath\)/u,
    'cleanup must delete neither a glob nor the final trust anchor');

  assertInOrder(trust, [
    '$bytes = $script:Utf8.GetBytes($CanonicalKeyJson)',
    '$expectedSha256 = Get-AgentRoadBytesSha256 $bytes',
    '$nextPath = Get-AgentRoadControllerTrustNextPath $script:Transaction',
    'if (Test-Path -LiteralPath $script:TrustKeyPath)',
    'Assert-AgentRoadFileNode $script:TrustKeyPath',
    'Test-AgentRoadExactFileBytes $script:TrustKeyPath $bytes $expectedSha256',
    "throw 'RUNTIME_SIGNATURE_INVALID'",
    'if (Test-Path -LiteralPath $nextPath)',
    'Assert-AgentRoadFileNode $nextPath',
    'Test-AgentRoadExactFileBytes $nextPath $bytes $expectedSha256',
    'Remove-AgentRoadControllerTrustNextFile $nextPath $script:Transaction',
    'New-AgentRoadRestrictedFileStream $nextPath 4096',
    '$stream.Write($bytes, 0, $bytes.Length)',
    '$stream.Flush($true)',
    'Assert-AgentRoadFileNode $nextPath $bytes.Length $expectedSha256',
    'Assert-AgentRoadDirectoryNode $script:Transaction.workRoot',
    'Assert-AgentRoadDirectoryNode $script:TrustRoot',
    'Test-Path -LiteralPath $script:TrustKeyPath',
    '[AgentRoad.NativeMethods]::MoveFileEx',
    '$nextPath',
    '$script:TrustKeyPath',
    '$script:MOVEFILE_WRITE_THROUGH',
    'Assert-AgentRoadFileNode $script:TrustKeyPath $bytes.Length $expectedSha256',
    'Test-AgentRoadExactFileBytes $script:TrustKeyPath $bytes $expectedSha256',
  ], 'non-replacing trust-anchor publication');
  assert.doesNotMatch(trust, /MOVEFILE_REPLACE_EXISTING|New-AgentRoadRestrictedFileStream\s+\$script:TrustKeyPath/u,
    'the final trust anchor is neither directly written nor replaced');
  assert.doesNotMatch(trust, /Delete\(\$script:TrustKeyPath\)|Remove-Item[^\n]+TrustKeyPath/u,
    'an existing trust anchor is never deleted');

  assert.match(topology, /Get-AgentRoadControllerTrustNextPath\s+\$script:Transaction/u);
  assert.match(topology, /TrustKeyPath[\s\S]+trustNextPath[\s\S]+RUNTIME_STATE_UNSUPPORTED/u,
    'topology must distinguish the final anchor from this invocation temp');

  const main = text.slice(text.lastIndexOf('$lock = $null'));
  assertInOrder(main, [
    'Ensure-AgentRoadRestrictedDirectory $script:TrustRoot',
    'Ensure-AgentRoadRestrictedDirectory $script:Transaction.workRoot',
    'Ensure-AgentRoadControllerTrust',
    '$script:Journal = New-AgentRoadJournal',
    'Publish-AgentRoadJournal',
  ], 'work temp and atomic trust publication before the first journal');
});

test('binds every owned generation to an exact fixed root layout', async () => {
  const text = await source();
  const layout = section(
    text,
    'Assert-AgentRoadExactGenerationTopology',
    'Get-AgentRoadToolTreeRecord',
  );
  assert.match(layout, /Get-ChildItem\s+-LiteralPath\s+\$GenerationRoot\s+-Force/u);
  for (const required of [
    'capsule.json',
    'receipt.json',
    'env.cmd',
    'env.ps1',
    'bin',
    'pwsh.cmd',
    'scripts',
    'runtime-inventory.ps1',
    'runtime-provision-core.ps1',
    'tools',
    'powershell-7',
  ]) {
    assert.match(layout, new RegExp(required.replaceAll('.', '\\.')));
  }
  assert.match(layout, /RUNTIME_STATE_UNSUPPORTED/u);

  const adopted = section(text, 'Assert-AgentRoadAdoptedGeneration', 'Invoke-AgentRoadMaterializeGeneration');
  assertInOrder(adopted, [
    'Assert-AgentRoadGenerationTree $GenerationRoot',
    'Assert-AgentRoadExactGenerationTopology $GenerationRoot',
    'ReadAllBytes($capsulePath)',
  ], 'layout before adopted ownership');
});

test('retires only an exact unreferenced snapshot previous generation after commit', async () => {
  const text = await source();
  const retirement = section(
    text,
    'Remove-AgentRoadSupersededPreviousGeneration',
    'Remove-AgentRoadOwnedTree',
  );
  assertInOrder(retirement, [
    "$script:Journal.status -cne 'committed'",
    '$script:Journal.snapshot.previous',
    'Read-AgentRoadPointer $script:ActivePath',
    'Read-AgentRoadPointer $script:PreviousPath',
    'manifestDigest',
    'Read-AgentRoadVerifiedGenerationPointer',
    'Read-AgentRoadPointer $script:ActivePath',
    'Read-AgentRoadPointer $script:PreviousPath',
    'Directory]::Move',
    'Assert-AgentRoadRetirementTombstone',
    'Remove-AgentRoadOwnedTree',
  ], 'retirement ownership and repeated reference guards');
  assert.match(retirement, /Test-Path[\s\S]+return/u, 'already-retired generations are idempotent');

  const reconcile = section(text, 'Invoke-AgentRoadReconcile', 'Remove-AgentRoadSupersededPreviousGeneration');
  assertInOrder(reconcile, [
    "$script:Journal.status -ceq 'committed'",
    'Invoke-AgentRoadValidation',
    'Remove-AgentRoadSupersededPreviousGeneration',
  ], 'committed reconciliation cleanup');

  const main = text.slice(text.lastIndexOf('$lock = $null'));
  assert.ok(
    (main.match(/Remove-AgentRoadSupersededPreviousGeneration/gu) ?? []).length >= 3,
    'same retry, committed turnover, and new commit must all retire superseded previous',
  );
  const newCommit = main.slice(main.lastIndexOf("$script:Journal.status = 'committed'"));
  assertInOrder(newCommit, [
    "Complete-AgentRoadForwardPhase 'commit'",
    'Remove-AgentRoadSupersededPreviousGeneration',
    'Remove-AgentRoadCommittedStaging',
  ], 'retirement after durable commit and before staging cleanup');
});

test('recovers retirement through one deterministic exact-owned tombstone', async () => {
  const text = await source();
  const tombstone = section(
    text,
    'Assert-AgentRoadRetirementTombstone',
    'Assert-AgentRoadRuntimeTopology',
  );
  assert.match(tombstone, /Journal\.status\s+-cne\s+'committed'/u);
  assert.match(tombstone, /Journal\.snapshot\.previous/u);
  assert.match(tombstone, /\.retired-[\s\S]+manifestDigest/u);
  assert.match(tombstone, /Read-AgentRoadPointer\s+\$script:ActivePath/u);
  assert.match(tombstone, /Read-AgentRoadPointer\s+\$script:PreviousPath/u);
  assert.match(tombstone, /Assert-AgentRoadGenerationTombstoneTree/u);

  const tombstoneTree = section(
    text,
    'Assert-AgentRoadGenerationTombstoneTree',
    'Assert-AgentRoadRetirementTombstone',
  );
  assert.match(tombstoneTree, /Get-ChildItem[\s\S]+-Recurse/u);
  assert.match(tombstoneTree, /capsule\.json/u);
  assert.match(tombstoneTree, /receipt\.json/u);
  assert.match(tombstoneTree, /bin\/pwsh\.cmd/u);
  assert.match(tombstoneTree, /scripts\/runtime-provision-core\.ps1/u);
  assert.match(tombstoneTree, /tools\/powershell-7\//u);
  assert.match(tombstoneTree, /Assert-AgentRoadDirectoryNode/u);
  assert.match(tombstoneTree, /Assert-AgentRoadFileNode/u);

  const topology = section(text, 'Assert-AgentRoadRuntimeTopology', 'Publish-AgentRoadMutableJson');
  assert.match(topology, /\^\\\.retired-\(\[A-F0-9\]\{64\}\)\$/u);
  assert.match(topology, /Assert-AgentRoadRetirementTombstone/u);

  const retirement = section(
    text,
    'Remove-AgentRoadSupersededPreviousGeneration',
    'Remove-AgentRoadOwnedTree',
  );
  assertInOrder(retirement, [
    "$tombstoneRoot = [IO.Path]::Combine($script:VersionsRoot, ('.retired-' + $candidateDigest))",
    '$hasGeneration',
    '$hasTombstone',
    'Assert-AgentRoadRetirementTombstone',
    'Remove-AgentRoadOwnedTree $tombstoneRoot',
  ], 'resume a prior tombstone deletion');
  assertInOrder(retirement, [
    'Read-AgentRoadVerifiedGenerationPointer $candidate',
    'Read-AgentRoadPointer $script:ActivePath',
    'Read-AgentRoadPointer $script:PreviousPath',
    '[IO.Directory]::Move($generationRoot, $tombstoneRoot)',
    'Assert-AgentRoadRetirementTombstone',
    'Remove-AgentRoadOwnedTree $tombstoneRoot',
  ], 'verify, recheck references, atomically tombstone, then delete');
  assert.doesNotMatch(retirement, /Remove-AgentRoadOwnedTree\s+\$generationRoot/u);
});

test('recovers rollback generation deletion through its own deterministic tombstone', async () => {
  const text = await source();
  const rollbackTombstone = section(
    text,
    'Assert-AgentRoadRollbackTombstone',
    'Assert-AgentRoadRuntimeTopology',
  );
  assert.match(rollbackTombstone, /Journal\.phase\s+-cne\s+'rollback'/u);
  assert.match(rollbackTombstone, /generation-publish-planned/u);
  assert.match(rollbackTombstone, /Journal\.manifestDigest/u);
  assert.match(rollbackTombstone, /Read-AgentRoadPointer\s+\$script:ActivePath/u);
  assert.match(rollbackTombstone, /Read-AgentRoadPointer\s+\$script:PreviousPath/u);
  assert.match(rollbackTombstone, /Assert-AgentRoadGenerationTombstoneTree/u);

  const topology = section(text, 'Assert-AgentRoadRuntimeTopology', 'Publish-AgentRoadMutableJson');
  assert.match(topology, /\^\\\.rollback-\(\[A-F0-9\]\{64\}\)\$/u);
  assert.match(topology, /Assert-AgentRoadRollbackTombstone/u);

  const removal = section(text, 'Remove-AgentRoadNewGeneration', 'Invoke-AgentRoadRollback');
  assertInOrder(removal, [
    "$tombstoneRoot = [IO.Path]::Combine($script:VersionsRoot, ('.rollback-' + $newManifestDigest))",
    '$hasGeneration',
    '$hasTombstone',
    'Assert-AgentRoadRollbackTombstone',
    'Remove-AgentRoadOwnedTree $tombstoneRoot',
  ], 'resume rollback tombstone cleanup');
  assertInOrder(removal, [
    'Read-AgentRoadJournalGenerationPointer',
    'Read-AgentRoadVerifiedGenerationPointer',
    'Read-AgentRoadPointer $script:ActivePath',
    'Read-AgentRoadPointer $script:PreviousPath',
    '[IO.Directory]::Move($newRoot, $tombstoneRoot)',
    'Assert-AgentRoadRollbackTombstone',
    'Remove-AgentRoadOwnedTree $tombstoneRoot',
  ], 'verify, unreference, tombstone, and delete rollback generation');
  assert.doesNotMatch(removal, /Remove-AgentRoadOwnedTree\s+\$newRoot/u);
});

test('keeps immutable upload transaction and mutable work directory as siblings', async () => {
  const text = await source();
  const paths = section(text, 'Get-AgentRoadTransaction', 'Assert-AgentRoadOperationBinding');

  assert.match(paths, /\$operationRoot\s*=\s*\[IO\.Path\]::Combine\(\$script:StagingRoot,\s*\$operationId\)/u);
  assert.match(paths, /\$transactionRoot\s*=\s*\[IO\.Path\]::Combine\(\$operationRoot,\s*\$manifestDigest\)/u);
  assert.match(paths, /\$workRoot\s*=\s*\[IO\.Path\]::Combine\(\$operationRoot,\s*'work'\)/u);
  assert.match(paths, /\$legacyWorkRoot\s*=\s*\[IO\.Path\]::Combine\(\$operationRoot,\s*\('work-'\s*\+\s*\$manifestDigest\)\)/u);
  assert.match(paths, /if \(Test-Path -LiteralPath \$legacyWorkRoot\)[\s\S]+if \(Test-Path -LiteralPath \$workRoot\) \{ throw 'RUNTIME_STATE_UNSUPPORTED' \}[\s\S]+\$workRoot = \$legacyWorkRoot/u);
  assert.doesNotMatch(paths, /Combine\(\$transactionRoot,[^\n]*work-/u);
  assert.match(paths, /capsule\.json/u);
  assert.match(paths, /files/u);

  const binding = section(text, 'Assert-AgentRoadOperationBinding', 'Get-AgentRoadSha256');
  assert.match(binding, /RUNTIME_OPERATION_CONFLICT/u);
  assert.match(binding, /\[IO\.Path\]::GetFileName\(\$Transaction.workRoot\)/u);
  assert.match(binding, /capsule[\s\S]+manifestDigest/u);
});

test('rejects ZIP traversal, ADS, collisions, dangerous names, link tricks, and resource bombs', async () => {
  const text = await source();
  const entry = section(text, 'Assert-AgentRoadZipEntry', 'Expand-AgentRoadPowerShellArchive');
  const expand = section(text, 'Expand-AgentRoadPowerShellArchive', 'Get-AgentRoadFileLinkCount');
  const links = section(text, 'Get-AgentRoadFileLinkCount', 'Assert-AgentRoadGenerationTree');

  assert.match(entry, /IsPathRooted/u, 'absolute path');
  assert.ok(entry.includes("$segment -ceq '.' -or $segment -ceq '..'"), 'dot and parent segment');
  assert.match(entry, /:/u, 'alternate data stream or drive colon');
  assert.match(entry, /\\x00-\\x1F\\x7F/u, 'control characters');
  assert.match(entry, /\[\.\\s\]\$/u, 'trailing dot or space');
  assert.match(entry, /CON\|PRN\|AUX\|NUL\|COM\[1-9\]\|LPT\[1-9\]/u, 'device names');
  assert.match(entry, /OrdinalIgnoreCase/u, 'case-insensitive collision set');
  assert.match(entry, /ExternalAttributes/u);
  assert.match(entry, /ReparsePoint/u);
  assert.match(entry, /0xA000|40960/u, 'unix symlink mode');
  assert.match(entry, /0x8000|32768/u, 'unix regular-file mode');

  assert.match(expand, /ZipArchiveMode\]::Read/u);
  assert.match(expand, /Entries\.Count\s+-gt\s+8192/u);
  assert.match(expand, /maximumExpandedBytes/iu);
  assert.match(expand, /expandedBytes/u);
  assert.match(expand, /filePaths/u, 'file/directory hierarchy collisions');
  assert.match(expand, /directoryPaths/u, 'implicit parent directory tracking');
  assert.match(expand, /\.Contains\(/u, 'hierarchy conflicts are rejected before extraction');
  assert.ok(expand.indexOf('Assert-AgentRoadZipEntry') < expand.indexOf('$record.entry.Open()'),
    'every name and type must be rejected before extraction');
  assert.doesNotMatch(expand, /ExtractToFile/u);
  assert.match(expand, /actualEntryBytes/u);
  assert.match(expand, /actualExpandedBytes/u);
  assert.match(expand, /expandedBytes\s+-gt\s+\$MaximumExpandedBytes/u);
  assert.match(expand, /record\.length\s+-\s+\$count/u);
  assert.match(expand, /MaximumExpandedBytes\s+-\s+\$count/u);
  assert.match(expand, /actualEntryBytes\s+-ne\s+\[long\]\$record\.length/u);
  assert.match(expand, /actualExpandedBytes\s+-ne\s+\$expandedBytes/u);
  assert.match(links, /NumberOfLinks/u);
  assert.match(links, /-ne\s+1/u);
});

test('locks down each extracted node immediately so partial work remains strictly owned', async () => {
  const text = await source();
  const chain = section(
    text,
    'Ensure-AgentRoadRestrictedDirectoryChain',
    'Assert-AgentRoadFileNode',
  );
  const expand = section(text, 'Expand-AgentRoadPowerShellArchive', 'Get-AgentRoadFileLinkCount');

  assert.match(chain, /StartsWith\([\s\S]+OrdinalIgnoreCase/u);
  assert.match(chain, /Ensure-AgentRoadRestrictedDirectory/u);
  assertInOrder(expand, [
    'Ensure-AgentRoadRestrictedDirectoryChain',
    '$record.entry.Open()',
    'New-AgentRoadRestrictedFileStream',
    '$output.Write(',
    '$output.Flush($true)',
    'Assert-AgentRoadFileNode',
  ], 'incremental extraction hardening');
  assert.match(expand, /if \(-not \$completed[\s\S]+\[IO\.File\]::Delete\(\$destination\)/u,
    'a failed bounded copy must remove its partial file');
});

test('binds a resumed operation to the exact original capsule and rejects a different manifest', async () => {
  const text = await source();
  const binding = section(text, 'Assert-AgentRoadOperationBinding', 'Get-AgentRoadSha256');

  assert.match(binding, /operationId/u);
  assert.match(binding, /manifestDigest/u);
  assert.match(binding, /capsulePath/u);
  assert.match(binding, /ReadAllBytes/u);
  assert.match(binding, /RUNTIME_OPERATION_CONFLICT/u);
  assert.match(binding, /RUNTIME_STATE_UNSUPPORTED/u);
  assert.doesNotMatch(text, /SignData|privateKey|re-sign/iu);
});

test('requires exact signed-manifest scalar and JSON-array types', async () => {
  const text = await source();
  const manifest = section(
    text,
    'Assert-AgentRoadManifest',
    'ConvertFrom-AgentRoadBase64Url',
  );

  for (const expected of [
    /\$Manifest\.deviceId\s+-isnot\s+\[string\]/u,
    /\$Manifest\.createdAt\s+-isnot\s+\[string\]/u,
    /\$Manifest\.requestedProfiles\s+-isnot\s+\[Array\]/u,
    /\$Manifest\.profiles\s+-isnot\s+\[Array\]/u,
    /\$Manifest\.phases\s+-isnot\s+\[Array\]/u,
    /\$Manifest\.components\s+-isnot\s+\[Array\]/u,
    /\$Manifest\.platform\.build\s+-isnot\s+\[int\]/u,
    /\$Manifest\.platform\.edition\s+-isnot\s+\[string\]/u,
    /\$Manifest\.platform\.windowsPowerShellVersion\s+-isnot\s+\[string\]/u,
    /\$Manifest\.platform\.elevated\s+-isnot\s+\[bool\]/u,
  ]) {
    assert.match(manifest, expected);
  }
  assert.match(manifest, /yyyy-MM-ddTHH:mm:ss\.fffZ/u);
});

test('requires the embedded controller key to be exact canonical bytes', async () => {
  const text = await source();
  const signature = section(
    text,
    'Assert-AgentRoadControllerSignature',
    'Ensure-AgentRoadControllerTrust',
  );

  assertInOrder(signature, [
    '[pscustomobject][ordered]@{',
    'algorithm = [string]$key.algorithm',
    'modulusBase64Url = [string]$key.modulusBase64Url',
    'exponentBase64Url = [string]$key.exponentBase64Url',
    'ConvertTo-Json -Depth 2 -Compress',
    '-cne [string]$Capsule.controllerPublicKeyJson',
    'AGENT_ROAD_CONTROLLER_KEY_V1',
  ], 'controller key canonicalization before identity hashing');
});

test('binds device and complete platform to the restricted stage-zero identity journal', async () => {
  const text = await source();
  assert.match(text, /\$script:BootstrapRoot\s*=\s*\[IO\.Path\]::Combine\(\$script:AgentRoadRoot,\s*'bootstrap'\)/u);
  assert.match(text, /\$script:BootstrapStageZeroJournalPath[\s\S]+stage-zero-journal\.json/u);
  assert.deepEqual(literalArray(text, 'BootstrapJournalFields'), [
    'schemaVersion',
    'phase',
    'deviceId',
    'updatedAt',
    'checkpoints',
  ]);

  const identity = section(
    text,
    'Read-AgentRoadBootstrapDeviceId',
    'Assert-AgentRoadMachinePreconditions',
  );
  const bootstrapAcl = section(
    text,
    'Assert-AgentRoadBootstrapJournalFile',
    'Read-AgentRoadBootstrapDeviceId',
  );
  assert.match(identity, /Assert-AgentRoadDirectoryNode\s+\$script:AgentRoadRoot/u);
  assert.match(identity, /Assert-AgentRoadDirectoryNode\s+\$script:BootstrapRoot/u);
  assert.match(identity, /Assert-AgentRoadBootstrapJournalFile/u);
  assert.match(bootstrapAcl,
    /GetOwner\(\[Security\.Principal\.SecurityIdentifier\]\)\.Value/u,
    'bootstrap journal owner must be compared as a stable SID');
  assert.match(bootstrapAcl, /AreAccessRulesProtected/u,
    'bootstrap journal must not inherit a mutable parent DACL');
  assert.match(bootstrapAcl, /AreAccessRulesCanonical/u);
  assert.match(bootstrapAcl, /\$owner\s+-cne\s+'S-1-5-32-544'/u,
    'bootstrap journal owner is Administrators');
  assert.match(bootstrapAcl, /\$rules\.Count\s+-ne\s+2/u);
  assert.match(bootstrapAcl, /\$rule\.IsInherited/u,
    'both SYSTEM and Administrators rules must be explicit');
  assert.match(bootstrapAcl, /InheritanceFlags[\s\S]+InheritanceFlags\]::None/u);
  assert.match(identity, /ReadAllBytes\(\$script:BootstrapStageZeroJournalPath\)/u);
  assert.match(identity, /ConvertFrom-AgentRoadCanonicalJson\s+\$bytes\s+4096/u);
  assert.match(identity, /Assert-AgentRoadExactFieldSet[\s\S]+BootstrapJournalFields/u);
  assert.match(identity, /\$journal\.deviceId[\s\S]+\^dev_\[a-z0-9\]\+\$/u);
  assert.match(identity, /\$journal\.checkpoints\s+-isnot\s+\[Array\]/u);
  assert.match(identity, /yyyy-MM-ddTHH:mm:ss\.fffffffZ/u);

  const machine = section(
    text,
    'Assert-AgentRoadMachinePreconditions',
    'Assert-AgentRoadArtifact',
  );
  assertInOrder(machine, [
    'Read-AgentRoadBootstrapDeviceId',
    '$localDeviceId -cne [string]$Manifest.deviceId',
  ], 'device binding');
  assert.match(machine, /\$os\.Caption\s+-cne\s+\[string\]\$Manifest\.platform\.edition/u);
  assert.match(machine, /\$PSVersionTable\.PSVersion\.ToString\(\)[\s\S]+windowsPowerShellVersion/u);
});

test('write-ahead logs generation and pointer publication before each mutation', async () => {
  const text = await source();
  const materialize = section(text, 'Invoke-AgentRoadMaterializeGeneration', 'Invoke-AgentRoadSelfTest');
  const activation = section(text, 'Invoke-AgentRoadActivation', 'Invoke-AgentRoadValidation');

  assertInOrder(materialize, [
    "Add-AgentRoadChange 'generation-publish-planned'",
    'Publish-AgentRoadGeneration',
  ], 'generation publication');
  assertInOrder(activation, [
    "Add-AgentRoadChange 'previous-replace-planned'",
    'Publish-AgentRoadPreviousPointer',
    "Add-AgentRoadChange 'active-replace-planned'",
    'Publish-AgentRoadActivePointer',
  ], 'pointer activation');
  assert.doesNotMatch(activation, /Save-AgentRoadPointerSnapshot/u,
    'activation must use the already-persisted snapshot, not overwrite it');
  assert.doesNotMatch(activation, /Invoke-AgentRoadValidation/u,
    'validation belongs to the validate phase after atomic activation is journaled complete');

  const atomicJson = section(text, 'Publish-AgentRoadMutableJson', 'Publish-AgentRoadGeneration');
  assertInOrder(atomicJson, [
    'New-AgentRoadRestrictedFileStream',
    'Flush($true)',
    'Assert-AgentRoadFileNode',
    'MoveFileEx',
    'MOVEFILE_REPLACE_EXISTING',
    'MOVEFILE_WRITE_THROUGH',
    'ReadAllBytes',
  ], 'mutable JSON publication');

  const generation = section(text, 'Publish-AgentRoadGeneration', 'Save-AgentRoadPointerSnapshot');
  assert.match(generation, /\[IO\.Directory\]::Move/u);
  assert.doesNotMatch(generation, /-Force|REPLACE_EXISTING/u);

  const main = text.slice(text.lastIndexOf('$lock = $null'));
  assert.equal((main.match(/Save-AgentRoadPointerSnapshot/gu) ?? []).length, 1,
    'the old pointer snapshot must be persisted exactly once');
  assert.ok(main.indexOf('Save-AgentRoadPointerSnapshot') < main.indexOf('Invoke-AgentRoadActivation'));
  assertInOrder(main, [
    'Invoke-AgentRoadActivation',
    "Complete-AgentRoadForwardPhase 'atomic-activate'",
    'Invoke-AgentRoadValidation',
    "Complete-AgentRoadForwardPhase 'validate'",
  ], 'activation and validation phases');
});

test('replays every logged mutation boundary without duplicating change records', async () => {
  const text = await source();
  const materialize = section(text, 'Invoke-AgentRoadMaterializeGeneration', 'Invoke-AgentRoadSelfTest');
  const activation = section(text, 'Invoke-AgentRoadActivation', 'Invoke-AgentRoadValidation');
  const reconcile = section(text, 'Invoke-AgentRoadReconcile', 'Remove-AgentRoadOwnedTree');
  const main = text.slice(text.lastIndexOf('$lock = $null'));

  assert.match(materialize, /changes\)\s+-cnotcontains\s+'generation-publish-planned'[\s\S]+Add-AgentRoadChange 'generation-publish-planned'/u);
  assert.match(activation, /changes\)\s+-cnotcontains\s+'previous-replace-planned'[\s\S]+Add-AgentRoadChange 'previous-replace-planned'/u);
  assert.match(activation, /changes\)\s+-cnotcontains\s+'active-replace-planned'[\s\S]+Add-AgentRoadChange 'active-replace-planned'/u);
  assert.match(reconcile, /completedCount\s+-lt\s+6\s+-or\s+\$completedCount\s+-gt\s+8/u);
  assert.doesNotMatch(reconcile, /completedPhases\)\.Count\s+-ne\s+6/u);
  assert.match(main, /changes\)\s+-cnotcontains\s+'work-created'[\s\S]+Add-AgentRoadChange 'work-created'/u);
  assert.match(main, /failureCode\s+-cin\s+@\('RUNTIME_OPERATION_CONFLICT',\s*'RUNTIME_STATE_UNSUPPORTED'\)[\s\S]+Write-AgentRoadResult 'failed'/u,
    'unknown or conflicting state must fail closed without entering rollback');
});

test('committed cleanup retries only known remaining children and rejects hostile extras', async () => {
  const text = await source();
  const cleanup = section(text, 'Remove-AgentRoadCommittedStaging', 'Write-AgentRoadResult');

  assert.match(cleanup, /foreach \(\$entry in @\(Get-ChildItem[^\n]+workRoot[^\n]+\)\)/u);
  assert.match(cleanup, /Remove-AgentRoadOwnedTree \$Transaction\.workRoot/u);
  assert.match(cleanup, /journal\|active\|previous/u);
  assert.doesNotMatch(cleanup, /entry\.PSIsContainer[^\n]+generation|Assert-AgentRoadGenerationTree \$entry\.FullName/u,
    'a committed operation has already moved generation into versions, so any work generation is unknown residue');
  assert.match(cleanup, /else\s*\{\s*throw 'RUNTIME_STATE_UNSUPPORTED'/u,
    'every unknown work child must fail closed instead of being deleted');
});

test('reconstructs the active pointer when adopting an already-published exact generation', async () => {
  const text = await source();
  const adopted = section(text, 'Assert-AgentRoadAdoptedGeneration', 'Invoke-AgentRoadMaterializeGeneration');
  assert.match(adopted, /capsuleBytes/iu);
  assert.match(adopted, /Get-AgentRoadToolTreeRecord/u);
  assert.match(adopted, /Get-AgentRoadFixedFileReceipts/u);
  assert.match(adopted, /Invoke-AgentRoadExecutableVerification/u);
  assert.match(adopted, /New-AgentRoadPointer/u);
  const materialize = section(text, 'Invoke-AgentRoadMaterializeGeneration', 'Invoke-AgentRoadSelfTest');
  assert.match(materialize, /Test-Path[\s\S]+\$script:NewPointer\s*=\s*Assert-AgentRoadAdoptedGeneration/u);
});

test('bounds verifier output while it is read and uses an encoded fixed command', async () => {
  const text = await source();
  const check = section(
    text,
    'Invoke-AgentRoadPowerShellCheck',
    'Invoke-AgentRoadExecutableVerification',
  );

  assert.match(check, /-EncodedCommand/u);
  assert.match(check, /ReadAsync/u);
  assert.match(check, /WaitAny/u);
  assert.match(check, /4096/u);
  assert.match(check, /Kill\(\)/u);
  assert.doesNotMatch(check, /ReadToEnd(?:Async)?/u);
  assert.doesNotMatch(check, /\.Trim\(\)/u,
    'strict verifier output must not be normalized after execution');
});

test('activates active/previous deterministically and restores active then previous before deleting new generation', async () => {
  const text = await source();
  const activation = section(text, 'Invoke-AgentRoadActivation', 'Invoke-AgentRoadValidation');
  const rollback = section(text, 'Invoke-AgentRoadRollback', 'Invoke-AgentRoadReconcile');

  assert.match(activation, /old active|snapshot\.active/iu);
  assert.match(section(text, 'Publish-AgentRoadPreviousPointer', 'Publish-AgentRoadActivePointer'), /PreviousPath/u);
  assert.match(section(text, 'Publish-AgentRoadActivePointer', 'Restore-AgentRoadPointerValue'), /ActivePath/u);
  assertInOrder(rollback, [
    'Restore-AgentRoadActivePointer',
    'Restore-AgentRoadPreviousPointer',
    'Invoke-AgentRoadOldGenerationSmokeTest',
    'Remove-AgentRoadNewGeneration',
  ], 'rollback');
  assert.match(rollback, /RUNTIME_ROLLBACK_INCOMPLETE/u);
});

test('revalidates the published capsule signature, receipt, tree, and fixed files before commit', async () => {
  const text = await source();
  const validation = section(text, 'Invoke-AgentRoadValidation', 'Invoke-AgentRoadOldGenerationSmokeTest');

  assertInOrder(validation, [
    'Read-AgentRoadPointer',
    'capsule.json',
    'Assert-AgentRoadManifest',
    'Assert-AgentRoadControllerSignature',
    'Assert-AgentRoadAdoptedGeneration',
  ], 'post-activation validation chain');
  assert.match(validation, /RUNTIME_ACTIVATION_FAILED/u);
});

test('returns only finite redacted results and never emits raw failures or machine data', async () => {
  const text = await source();
  const failures = literalArray(text, 'FailureCodes');

  assert.deepEqual(failures, [
    'RUNTIME_INPUT_INVALID',
    'RUNTIME_ALREADY_RUNNING',
    'RUNTIME_OPERATION_CONFLICT',
    'RUNTIME_STATE_UNSUPPORTED',
    'RUNTIME_INVENTORY_CHANGED',
    'RUNTIME_SIGNATURE_INVALID',
    'RUNTIME_ARTIFACT_INVALID',
    'RUNTIME_SELF_TEST_FAILED',
    'RUNTIME_ACTIVATION_FAILED',
    'RUNTIME_COMPLETION_UNCERTAIN',
    'RUNTIME_ROLLBACK_INCOMPLETE',
    'RUNTIME_INTERNAL_ERROR',
  ]);
  assert.deepEqual(literalArray(text, 'ResultStatuses'), [
    'committed',
    'failed',
    'uncertain',
    'rolled-back',
  ]);

  const writer = section(text, 'Write-AgentRoadResult', 'Get-AgentRoadFailureCode');
  assert.match(writer, /\[ordered\]@\{/u);
  assert.match(writer, /ConvertTo-Json[^\n]+-Compress/u);
  assert.match(writer, /4096/u);
  assert.match(writer, /\[Console\]::Out\.Write/u);
  assert.doesNotMatch(writer, /path|message|exception|command|stdout|stderr|token|key/iu);
  assert.doesNotMatch(text, /Write-(?:Error|Host|Verbose|Debug)|Format-(?:List|Table)/iu);
  assert.doesNotMatch(text, /(?:Exception\.Message|InvocationInfo|ScriptStackTrace|FullyQualifiedErrorId)/u);

  const main = text.slice(text.lastIndexOf('$lock = $null'));
  assert.doesNotMatch(main, /^\s*return\s*$/gmu, 'top-level early return would bypass the finite exit code');
  for (const [status, code] of [
    ['committed', 0],
    ['failed', 1],
    ['rolled-back', 2],
    ['uncertain', 3],
  ]) {
    assert.match(main, new RegExp(`Write-AgentRoadResult '${status}'[\\s\\S]{0,240}\\$exitCode = ${code}`, 'u'));
  }
  assert.match(main, /RUNTIME_ROLLBACK_INCOMPLETE[\s\S]{0,240}\$exitCode = 4/u);
});

test('PowerShell parser accepts the provisioner when pwsh is locally available', async (t) => {
  const probe = spawnSync('pwsh', ['-NoLogo', '-NoProfile', '-Command', '$PSVersionTable.PSVersion.Major'], {
    encoding: 'utf8',
  });
  if (probe.error?.code === 'ENOENT') {
    t.skip('pwsh is not installed on this Mac');
    return;
  }
  assert.equal(probe.status, 0, probe.stderr);
  const path = decodeURIComponent(scriptUrl.pathname).replaceAll("'", "''");
  const parsed = spawnSync('pwsh', [
    '-NoLogo',
    '-NoProfile',
    '-Command',
    `$errors=$null;[Management.Automation.Language.Parser]::ParseFile('${path}',[ref]$null,[ref]$errors)|Out-Null;if($errors.Count){$errors|ForEach-Object{$_.ErrorId};exit 1}`,
  ], { encoding: 'utf8' });
  assert.equal(parsed.status, 0, parsed.stdout || parsed.stderr);
});
