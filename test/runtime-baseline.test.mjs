import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  captureRuntimeBaseline,
  compareRuntimeBaseline,
  parseRuntimeBaselineExecution,
  RUNTIME_BASELINE_SCRIPT_PATH,
} from '../src/runtime/runtime-baseline.mjs';

const DEVICE_ID = 'dev_0123456789abcdef0123456789abcdef';
const ADDRESS = '100.64.0.10';
const BASELINE_ID = `rbl_${'11'.repeat(32)}`;
const COMPARISON_ID = `rbc_${'22'.repeat(32)}`;
const STARTED_AT = '2026-07-30T10:00:00.000Z';
const FINISHED_AT = '2026-07-30T10:00:01.000Z';
const CAPTURED_AT = '2026-07-30T10:00:02.000Z';
const EXPIRES_AT = '2026-07-31T10:00:02.000Z';
const SURFACE_IDS = Object.freeze([
  'account-environment',
  'account-profile-identity',
  'command-resolution',
  'external-sentinel-acls',
  'firewall-profiles',
  'firewall-rules',
  'machine-environment',
  'scheduled-tasks',
  'service-definitions',
]);
const SURFACE_LIMITS = Object.freeze([128, 4, 32, 16, 3, 32, 256, 64, 16]);

function observation() {
  return {
    schemaVersion: 1,
    protocolRevision: 1,
    surfaces: SURFACE_IDS.map((id, index) => ({
      id,
      count: id === 'firewall-profiles' ? 3 : index,
      mac: String(index).repeat(64),
    })),
  };
}

function executionResult(overrides = {}) {
  return {
    schemaVersion: 1,
    operation: 'exec',
    deviceId: DEVICE_ID,
    address: ADDRESS,
    exitCode: 0,
    stdout: JSON.stringify(observation()),
    stderr: '',
    startedAt: STARTED_AT,
    finishedAt: FINISHED_AT,
    ...overrides,
  };
}

function aggregateMac(hmacKeyBase64, surfaces) {
  const hmac = createHmac('sha256', Buffer.from(hmacKeyBase64, 'base64'));
  hmac.update(Buffer.from('AgentRoad.RuntimeBaseline.Aggregate.v1\0', 'ascii'));
  for (const surface of surfaces) {
    for (const value of [surface.id, String(surface.count), surface.mac]) {
      const bytes = Buffer.from(value, 'utf8');
      const length = Buffer.alloc(4);
      length.writeUInt32BE(bytes.length);
      hmac.update(length);
      hmac.update(bytes);
    }
  }
  return hmac.digest('hex').toUpperCase();
}

function recordDigest(domain, value) {
  return createHash('sha256')
    .update(domain, 'ascii')
    .update(JSON.stringify(value), 'utf8')
    .digest('hex')
    .toUpperCase();
}

async function scriptSha256() {
  return createHash('sha256')
    .update(await readFile(RUNTIME_BASELINE_SCRIPT_PATH))
    .digest('hex')
    .toUpperCase();
}

function baselineRecord({ hmacKeyBase64, scriptSha256: sha, surfaces = observation().surfaces }) {
  const base = {
    schemaVersion: 1,
    recordType: 'RUNTIME_BASELINE',
    baselineId: BASELINE_ID,
    deviceId: DEVICE_ID,
    protocolRevision: 1,
    scriptSha256: sha,
    hmacKeyBase64,
    surfaces: Object.freeze(surfaces.map((surface) => Object.freeze({ ...surface }))),
    captureAggregateMac: aggregateMac(hmacKeyBase64, surfaces),
    capturedAt: CAPTURED_AT,
    expiresAt: EXPIRES_AT,
  };
  return Object.freeze({
    ...base,
    recordDigest: recordDigest('AgentRoad.RuntimeBaseline.Record.v1\0', base),
  });
}

function comparisonRecord({ baseline, surfaces = observation().surfaces }) {
  const changedSurfaces = Object.freeze(surfaces.flatMap((surface, index) => {
    const before = baseline.surfaces[index];
    const countChanged = before.count !== surface.count;
    const macChanged = before.mac !== surface.mac;
    return countChanged || macChanged
      ? [Object.freeze({ id: surface.id, countChanged, macChanged })]
      : [];
  }));
  const base = {
    schemaVersion: 1,
    recordType: 'RUNTIME_BASELINE_COMPARISON',
    comparisonId: COMPARISON_ID,
    deviceId: DEVICE_ID,
    baselineId: baseline.baselineId,
    baselineRecordDigest: baseline.recordDigest,
    protocolRevision: 1,
    scriptSha256: baseline.scriptSha256,
    observedSurfaces: Object.freeze(surfaces.map((surface) => Object.freeze({ ...surface }))),
    observedAggregateMac: aggregateMac(baseline.hmacKeyBase64, surfaces),
    status: changedSurfaces.length === 0 ? 'UNCHANGED' : 'CHANGED',
    changedSurfaces,
    comparedAt: '2026-07-30T10:00:03.000Z',
  };
  return Object.freeze({
    ...base,
    recordDigest: recordDigest('AgentRoad.RuntimeBaseline.Comparison.v1\0', base),
  });
}

async function rejectsCode(promise, code, forbidden = []) {
  let error;
  try {
    await promise;
  } catch (caught) {
    error = caught;
  }
  assert.ok(error, `expected ${code}`);
  assert.equal(error.code, code);
  assert.equal(error.message, code);
  assert.deepEqual(Object.keys(error), ['code']);
  assert.equal(Object.hasOwn(error, 'cause'), false);
  for (const value of forbidden) assert.doesNotMatch(error.message, new RegExp(value, 'u'));
}

test('strictly parses the canonical ordered and bounded runtime baseline observation', () => {
  assert.match(RUNTIME_BASELINE_SCRIPT_PATH, /windows[/\\]runtime-baseline\.ps1$/u);
  const parsed = parseRuntimeBaselineExecution(executionResult(), {
    deviceId: DEVICE_ID,
    address: ADDRESS,
  });

  assert.deepEqual(parsed, observation());
  assert.equal(Object.isFrozen(parsed), true);
  assert.equal(Object.isFrozen(parsed.surfaces), true);
  assert.equal(parsed.surfaces.every(Object.isFrozen), true);
});

test('accepts every exact surface ceiling and rejects each ceiling plus one', () => {
  const atLimit = observation();
  atLimit.surfaces = atLimit.surfaces.map((surface, index) => ({
    ...surface,
    count: SURFACE_LIMITS[index],
  }));
  assert.deepEqual(
    parseRuntimeBaselineExecution(
      executionResult({ stdout: JSON.stringify(atLimit) }),
      { deviceId: DEVICE_ID, address: ADDRESS },
    ),
    atLimit,
  );

  for (let index = 0; index < SURFACE_IDS.length; index += 1) {
    const excessive = structuredClone(atLimit);
    excessive.surfaces[index].count += 1;
    assert.throws(
      () => parseRuntimeBaselineExecution(
        executionResult({ stdout: JSON.stringify(excessive) }),
        { deviceId: DEVICE_ID, address: ADDRESS },
      ),
      { code: 'RUNTIME_INVENTORY_FAILED' },
    );
  }
});

test('rejects noncanonical, reordered, oversized, out-of-bound and unbound observations', () => {
  const canonical = JSON.stringify(observation());
  const duplicate = canonical.replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1');
  const rootReordered = JSON.stringify({
    protocolRevision: 1,
    schemaVersion: 1,
    surfaces: observation().surfaces,
  });
  const surfaceReordered = observation();
  surfaceReordered.surfaces[0] = {
    count: 0,
    id: SURFACE_IDS[0],
    mac: '0'.repeat(64),
  };
  const wrongOrder = observation();
  [wrongOrder.surfaces[0], wrongOrder.surfaces[1]] = [
    wrongOrder.surfaces[1],
    wrongOrder.surfaces[0],
  ];
  const lowercaseMac = observation();
  lowercaseMac.surfaces[0].mac = 'a'.repeat(64);
  const tooMany = observation();
  tooMany.surfaces[0].count = SURFACE_LIMITS[0] + 1;
  const missingProfiles = observation();
  missingProfiles.surfaces[4].count = 2;

  for (const input of [
    executionResult({ stdout: `${canonical}\n` }),
    executionResult({ stdout: rootReordered }),
    executionResult({ stdout: JSON.stringify(surfaceReordered) }),
    executionResult({ stdout: duplicate }),
    executionResult({ stdout: JSON.stringify({ ...observation(), secret: 'must-not-leak' }) }),
    executionResult({ stdout: JSON.stringify(wrongOrder) }),
    executionResult({ stdout: JSON.stringify(lowercaseMac) }),
    executionResult({ stdout: JSON.stringify(tooMany) }),
    executionResult({ stdout: JSON.stringify(missingProfiles) }),
    executionResult({ stdout: '汉'.repeat(2_731) }),
    executionResult({ exitCode: 1, stdout: 'private stdout' }),
    executionResult({ stderr: 'private stderr' }),
    executionResult({ deviceId: 'dev_wrong' }),
    executionResult({ address: '100.64.0.11' }),
    executionResult({ startedAt: FINISHED_AT, finishedAt: STARTED_AT }),
    executionResult({ extra: true }),
  ]) {
    assert.throws(
      () => parseRuntimeBaselineExecution(input, { deviceId: DEVICE_ID, address: ADDRESS }),
      (error) => error?.code === 'RUNTIME_INVENTORY_FAILED'
        && error.message === 'RUNTIME_INVENTORY_FAILED'
        && Object.keys(error).join(',') === 'code'
        && !/private|must-not-leak/u.test(error.message),
    );
  }
});

test('capture sends a fresh key only through bounded canonical stdin and returns a redacted projection', async () => {
  const calls = [];
  const createCalls = [];
  const randomKey = Buffer.alloc(32, 0x5a);
  const sha = await scriptSha256();
  const result = await captureRuntimeBaseline({
    deviceId: DEVICE_ID,
    dependencies: {
      executeBaselineScript: async (input) => {
        calls.push(input);
        return executionResult();
      },
      createBaseline: async (input) => {
        createCalls.push(input);
        return baselineRecord({ hmacKeyBase64: input.hmacKeyBase64, scriptSha256: sha });
      },
      randomBytes: (size) => {
        assert.equal(size, 32);
        return randomKey;
      },
    },
  });

  assert.deepEqual(result, {
    baselineId: BASELINE_ID,
    capturedAt: CAPTURED_AT,
    expiresAt: EXPIRES_AT,
  });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(calls.length, 1);
  assert.deepEqual(Object.keys(calls[0]), [
    'deviceId',
    'scriptPath',
    'scriptSha256',
    'timeoutMs',
    'maxOutputBytes',
    'stdinText',
  ]);
  assert.equal(calls[0].deviceId, DEVICE_ID);
  assert.equal(calls[0].scriptPath, RUNTIME_BASELINE_SCRIPT_PATH);
  assert.equal(calls[0].scriptSha256, sha);
  assert.equal(calls[0].timeoutMs, 120_000);
  assert.equal(calls[0].maxOutputBytes, 8_192);
  const stdin = JSON.parse(calls[0].stdinText);
  assert.deepEqual(Object.keys(stdin), ['schemaVersion', 'protocolRevision', 'hmacKeyBase64']);
  assert.equal(stdin.hmacKeyBase64, Buffer.alloc(32, 0x5a).toString('base64'));
  assert.ok(Buffer.byteLength(calls[0].stdinText, 'utf8') <= 256);
  assert.equal(JSON.stringify({ ...calls[0], stdinText: '' }).includes(stdin.hmacKeyBase64), false);
  assert.equal(JSON.stringify(result).includes(stdin.hmacKeyBase64), false);
  assert.equal(JSON.stringify(result).includes(observation().surfaces[0].mac), false);
  assert.equal(createCalls.length, 1);
  assert.equal(createCalls[0].captureAggregateMac, aggregateMac(
    stdin.hmacKeyBase64,
    observation().surfaces,
  ));
  assert.deepEqual([...randomKey], Array(32).fill(0));
});

test('compare binds the exact live script before execution and returns only change flags', async () => {
  const sha = await scriptSha256();
  const key = Buffer.alloc(32, 7).toString('base64');
  const baseline = baselineRecord({ hmacKeyBase64: key, scriptSha256: sha });
  const observed = observation();
  observed.surfaces[7] = { ...observed.surfaces[7], mac: 'F'.repeat(64) };
  const calls = [];
  const createCalls = [];
  const result = await compareRuntimeBaseline({
    deviceId: DEVICE_ID,
    baselineId: BASELINE_ID,
    dependencies: {
      executeBaselineScript: async (input) => {
        calls.push(input);
        return executionResult({ stdout: JSON.stringify(observed) });
      },
      readBaseline: async (input) => {
        assert.deepEqual(input, { deviceId: DEVICE_ID, baselineId: BASELINE_ID });
        return baseline;
      },
      createComparison: async (input) => {
        createCalls.push(input);
        return comparisonRecord({ baseline, surfaces: observed.surfaces });
      },
    },
  });

  assert.deepEqual(result, {
    baselineId: BASELINE_ID,
    comparisonId: COMPARISON_ID,
    status: 'CHANGED',
    changedSurfaces: [{
      id: 'scheduled-tasks',
      countChanged: false,
      macChanged: true,
    }],
  });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.changedSurfaces), true);
  assert.equal(calls.length, 1);
  assert.equal(JSON.parse(calls[0].stdinText).hmacKeyBase64, key);
  assert.equal(createCalls.length, 1);
  assert.equal(createCalls[0].baselineRecordDigest, baseline.recordDigest);
  assert.equal(createCalls[0].protocolRevision, 1);
  assert.equal(createCalls[0].scriptSha256, sha);
  assert.equal(JSON.stringify(result).includes(key), false);
  assert.equal(JSON.stringify(result).includes('F'.repeat(64)), false);
  assert.equal(JSON.stringify(result).includes(ADDRESS), false);
});

test('compare rejects script provenance drift before remote execution', async () => {
  let executions = 0;
  const key = Buffer.alloc(32, 7).toString('base64');
  await rejectsCode(compareRuntimeBaseline({
    deviceId: DEVICE_ID,
    baselineId: BASELINE_ID,
    dependencies: {
      executeBaselineScript: async () => { executions += 1; },
      readBaseline: async () => baselineRecord({
        hmacKeyBase64: key,
        scriptSha256: 'F'.repeat(64),
      }),
      createComparison: async () => assert.fail('comparison published'),
    },
  }), 'RUNTIME_STATE_UNSUPPORTED');
  assert.equal(executions, 0);
});

test('maps execution failures to one redacted code and validates entropy before side effects', async () => {
  let executions = 0;
  let publications = 0;
  const invalidKey = Buffer.alloc(31, 0x4a);
  await rejectsCode(captureRuntimeBaseline({
    deviceId: DEVICE_ID,
    dependencies: {
      executeBaselineScript: async () => { executions += 1; },
      createBaseline: async () => { publications += 1; },
      randomBytes: () => invalidKey,
    },
  }), 'RUNTIME_INTERNAL_ERROR');
  assert.equal(executions, 0);
  assert.equal(publications, 0);
  assert.deepEqual([...invalidKey], Array(31).fill(0));

  for (const thrown of [new Error('private transport data'), new Proxy({}, {})]) {
    await rejectsCode(captureRuntimeBaseline({
      deviceId: DEVICE_ID,
      dependencies: {
        executeBaselineScript: async () => { throw thrown; },
        createBaseline: async () => { publications += 1; },
        randomBytes: () => Buffer.alloc(32, 9),
      },
    }), 'RUNTIME_INVENTORY_FAILED', ['private']);
  }
  assert.equal(publications, 0);
});

test('preserves only trusted-session contention from baseline execution', async () => {
  const contention = Object.assign(new Error('private lock path'), {
    code: 'RUNTIME_ALREADY_RUNNING',
  });
  await rejectsCode(captureRuntimeBaseline({
    deviceId: DEVICE_ID,
    dependencies: {
      executeBaselineScript: async () => { throw contention; },
      createBaseline: async () => assert.fail('baseline published'),
      randomBytes: () => Buffer.alloc(32, 9),
    },
  }), 'RUNTIME_ALREADY_RUNNING', ['private', 'lock', 'path']);

  const sha = await scriptSha256();
  const key = Buffer.alloc(32, 7).toString('base64');
  await rejectsCode(compareRuntimeBaseline({
    deviceId: DEVICE_ID,
    baselineId: BASELINE_ID,
    dependencies: {
      executeBaselineScript: async () => { throw contention; },
      readBaseline: async () => baselineRecord({
        hmacKeyBase64: key,
        scriptSha256: sha,
      }),
      createComparison: async () => assert.fail('comparison published'),
    },
  }), 'RUNTIME_ALREADY_RUNNING', ['private', 'lock', 'path']);
});

test('copies and zeroes hostile Buffer entropy before encoding can expose an error', async () => {
  const hostile = Buffer.alloc(32, 0x5a);
  const sha = await scriptSha256();
  const hostilePrototype = Object.create(Buffer.prototype, {
    toString: {
      value() { throw new Error('PRIVATE_KEY_ENCODING_SECRET'); },
    },
    fill: {
      value() { throw new Error('PRIVATE_KEY_ZEROIZATION_SECRET'); },
    },
  });
  Object.setPrototypeOf(hostile, hostilePrototype);

  const result = await captureRuntimeBaseline({
    deviceId: DEVICE_ID,
    dependencies: {
      executeBaselineScript: async () => executionResult(),
      createBaseline: async (input) => baselineRecord({
        hmacKeyBase64: input.hmacKeyBase64,
        scriptSha256: sha,
      }),
      randomBytes: () => hostile,
    },
  });
  assert.equal(result.baselineId, BASELINE_ID);
  assert.deepEqual([...hostile], Array(32).fill(0));
});

test('rejects hostile or expanded orchestration input before dependencies run', async () => {
  let called = 0;
  const dependencies = {
    executeBaselineScript: async () => { called += 1; },
    createBaseline: async () => { called += 1; },
    randomBytes: () => Buffer.alloc(32),
  };
  for (const input of [
    { deviceId: DEVICE_ID, dependencies, extra: true },
    { deviceId: 'DEV_WRONG', dependencies },
    new Proxy({ deviceId: DEVICE_ID, dependencies }, {}),
    { deviceId: DEVICE_ID, dependencies: { ...dependencies, extra: true } },
  ]) {
    await rejectsCode(captureRuntimeBaseline(input), 'RUNTIME_INPUT_INVALID');
  }
  assert.equal(called, 0);
});

test('Windows source freezes the read-only bounded HMAC protocol and excludes mutation or volatile APIs', async () => {
  const source = await readFile(RUNTIME_BASELINE_SCRIPT_PATH, 'utf8');
  assert.match(source, /^#requires -Version 5\.1$/mu);
  assert.match(source, /AgentRoad\.RuntimeBaseline\.Surface\.v1\\0/u);
  assert.match(source, /RegistryView\]::Registry64/u);
  assert.match(source, /-PolicyStore\s+'PersistentStore'/u);
  assert.match(source, /\\AgentRoad\\/u);
  for (const id of SURFACE_IDS) assert.match(source, new RegExp(`'${id}'`, 'u'));
  for (const limit of [...new Set(SURFACE_LIMITS)]) {
    assert.match(source, new RegExp(`(?:^|\\D)${limit}(?:\\D|$)`, 'u'));
  }
  assert.match(source, /rank\s*=\s*\$rank/u);
  assert.match(source, /winner\s*=\s*\(\$rank\s+-eq\s+0\)/u);
  assert.match(source, /Export-ScheduledTask/u);
  assert.match(source, /StartsWith\(\$script:TaskNamespace/u);
  assert.match(source, /S-1-5-32-544/u);
  for (const valueName of [
    'DelayedAutoStart',
    'DependOnService',
    'FailureActions',
    'FailureActionsOnNonCrashFailures',
    'ServiceSidType',
  ]) assert.match(source, new RegExp(`'${valueName}'`, 'u'));
  for (const path of [
    'authorized_keys',
    'sshd_config',
    '\\\\tasks',
    '\\\\transfers',
  ]) assert.match(source, new RegExp(path, 'u'));
  assert.match(source, /Get-NetFirewallInterfaceFilter/u);
  assert.match(source, /Get-AgentRoadProperty \$_ 'IcmpType' \$null/u);
  assert.match(source, /Get-AgentRoadProperty \$_ 'DynamicTransport' \$null/u);
  assert.doesNotMatch(
    source,
    /Get-AgentRoadProperty \$_ 'Protocol' \$null[\s\S]{0,180}Convert-AgentRoadEnum/u,
  );
  assert.doesNotMatch(
    source,
    /local-name\(\)='Author' or local-name\(\)='Source'/u,
  );
  assert.match(source, /FieldByteLimit/u);
  assert.match(source, /NestedItemLimit/u);
  assert.equal((source.match(/\[Console\]::Out\.Write\(/gu) ?? []).length, 1);
  assert.doesNotMatch(source, /\b(?:Write-Host|Write-Output|Write-Error|Out-File)\b/u);
  assert.doesNotMatch(source, /\b(?:Add-WindowsCapability|Set-Acl|Set-Item|Set-ItemProperty|Set-Service|Start-Service|Stop-Service|Restart-Service|New-Item|New-Service|Remove-Item|Copy-Item|Move-Item|Rename-Item|New-NetFirewallRule|Set-NetFirewallRule|Remove-NetFirewallRule|Enable-NetFirewallRule|Disable-NetFirewallRule|Register-ScheduledTask|Unregister-ScheduledTask|Enable-ScheduledTask|Disable-ScheduledTask|Start-ScheduledTask|Stop-ScheduledTask|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|Start-Process|Invoke-Expression|Restart-Computer|Stop-Computer)\b/u);
  assert.doesNotMatch(source, /\[(?:IO\.(?:File|Directory)|Microsoft\.Win32\.RegistryKey)\]::(?:Write|Create|Delete|Move|Copy|Replace|Set)/u);
  assert.doesNotMatch(source, /\.(?:SetValue|DeleteValue|CreateSubKey|DeleteSubKey|SetAccessControl)\s*\(/u);
  assert.doesNotMatch(source, /\b(?:Get-Process|Win32_Process|Get-EventLog|Get-WinEvent|LastRunTime|NextRunTime|LastTaskResult|ProcessId|FreeSpace|LastUseTime|LastWriteTime|CreationTime)\b/u);
});

test('Windows producer enforces exact nested and byte ceilings when PowerShell 5.1 is available', async (t) => {
  const probe = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-Command', '$PSVersionTable.PSVersion.Major'], {
    encoding: 'utf8',
  });
  if (probe.error?.code === 'ENOENT') {
    t.skip('Windows PowerShell 5.1 is unavailable on this Mac');
    return;
  }
  assert.equal(probe.status, 0, probe.stderr);
  assert.equal(probe.stdout.trim(), '5');
  const path = RUNTIME_BASELINE_SCRIPT_PATH.replaceAll("'", "''");
  const fixture = String.raw`
$tokens=$null
$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('${path}',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'PARSE_FAILED'}
$wanted=@('Assert-AgentRoadBoundedValue','Convert-AgentRoadRecordToJson','Convert-AgentRoadRecords')
$definitions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $wanted -contains $node.Name},$true))
if($definitions.Count -ne $wanted.Count){throw 'FUNCTION_SET_INVALID'}
$script:Utf8=New-Object Text.UTF8Encoding($false,$true)
$script:FieldNameByteLimit=256
$script:FieldByteLimit=8192
$script:NestedItemLimit=256
$script:RecordFieldLimit=64
$script:ValueDepthLimit=8
$script:RecordByteLimit=16384
$script:SurfaceByteLimit=131072
. ([ScriptBlock]::Create((($definitions|Sort-Object {$_.Extent.StartOffset}|ForEach-Object {$_.Extent.Text}) -join [Environment]::NewLine)))
function Assert-Rejected([scriptblock]$Action){$rejected=$false;try{& $Action}catch{$rejected=$true};if(-not $rejected){throw 'BOUND_NOT_ENFORCED'}}
Assert-AgentRoadBoundedValue -Value ('a'*8192)
Assert-Rejected {Assert-AgentRoadBoundedValue -Value ('a'*8193)}
Assert-AgentRoadBoundedValue -Value ([ordered]@{('k'*256)='v'})
Assert-Rejected {Assert-AgentRoadBoundedValue -Value ([ordered]@{('k'*257)='v'})}
Assert-AgentRoadBoundedValue -Value (@('x')*256)
Assert-Rejected {Assert-AgentRoadBoundedValue -Value (@('x')*257)}
Assert-AgentRoadBoundedValue -Value 'x' -Depth 8
Assert-Rejected {Assert-AgentRoadBoundedValue -Value 'x' -Depth 9}
$fieldsAt=[ordered]@{};0..63|ForEach-Object{$fieldsAt[[string]$_]=0};Assert-AgentRoadBoundedValue $fieldsAt
$fieldsOver=[ordered]@{};0..64|ForEach-Object{$fieldsOver[[string]$_]=0};Assert-Rejected {Assert-AgentRoadBoundedValue $fieldsOver}
$recordAt=$null
for($right=0;$right -le 8192;$right++){$candidate=[ordered]@{a=('a'*8192);b=('b'*$right)};if($script:Utf8.GetByteCount((ConvertTo-Json -Compress -Depth 12 -InputObject $candidate)) -eq 16384){$recordAt=$candidate;break}}
if($null -eq $recordAt){throw 'RECORD_LIMIT_FIXTURE_INVALID'}
$null=Convert-AgentRoadRecordToJson $recordAt
$recordOver=[ordered]@{a=$recordAt.a;b=($recordAt.b+'b')}
Assert-Rejected {Convert-AgentRoadRecordToJson $recordOver}
$surfaceRecords=New-Object 'Collections.Generic.List[object]'
0..15|ForEach-Object{$surfaceRecords.Add([ordered]@{n=$_;p=('p'*8100)})}
$surfaceAt=$null
for($last=0;$last -le 8192;$last++){
  $candidate=@($surfaceRecords.ToArray())+@([ordered]@{n=16;p=('q'*$last)})
  $json=@($candidate|ForEach-Object{Convert-AgentRoadRecordToJson $_})
  $bytes=8+$script:Utf8.GetByteCount('fixture')+$script:Utf8.GetByteCount([string]$json.Count)
  foreach($entry in $json){$bytes+=4+$script:Utf8.GetByteCount($entry)}
  if($bytes -eq 131072){$surfaceAt=$candidate;break}
}
if($null -eq $surfaceAt){throw 'SURFACE_LIMIT_FIXTURE_INVALID'}
$null=Convert-AgentRoadRecords $surfaceAt 256 'fixture'
$surfaceOver=@($surfaceAt);$surfaceOver[-1]=[ordered]@{n=16;p=([string]$surfaceOver[-1].p+'q')}
Assert-Rejected {Convert-AgentRoadRecords $surfaceOver 256 'fixture'}
'BOUNDS_OK'
`;
  const bounded = spawnSync('powershell.exe', [
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-Command',
    fixture,
  ], { encoding: 'utf8', timeout: 120_000 });
  assert.equal(bounded.status, 0, bounded.stderr || bounded.stdout);
  assert.equal(bounded.stderr, '');
  assert.equal(bounded.stdout.trim(), 'BOUNDS_OK');
});

test('Windows source parses and runs under Windows PowerShell 5.1 when powershell.exe is available', async (t) => {
  const probe = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-Command', '$PSVersionTable.PSVersion.Major'], {
    encoding: 'utf8',
  });
  if (probe.error?.code === 'ENOENT') {
    t.skip('Windows PowerShell 5.1 is unavailable on this Mac');
    return;
  }
  assert.equal(probe.status, 0, probe.stderr);
  assert.equal(probe.stdout.trim(), '5');
  const path = RUNTIME_BASELINE_SCRIPT_PATH.replaceAll("'", "''");
  const parsed = spawnSync('powershell.exe', [
    '-NoLogo',
    '-NoProfile',
    '-Command',
    `$tokens=$null;$errors=$null;[Management.Automation.Language.Parser]::ParseFile('${path}',[ref]$tokens,[ref]$errors)|Out-Null;if($errors.Count){$errors|ForEach-Object Message;exit 1}`,
  ], { encoding: 'utf8' });
  assert.equal(parsed.status, 0, parsed.stderr || parsed.stdout);

  const identity = spawnSync('powershell.exe', [
    '-NoLogo',
    '-NoProfile',
    '-Command',
    '[Security.Principal.WindowsIdentity]::GetCurrent().Name',
  ], { encoding: 'utf8' });
  assert.equal(identity.status, 0, identity.stderr);
  if (!/(?:^|\\)AgentRoad$/iu.test(identity.stdout.trim())) {
    t.skip('positive execution requires the provisioned AgentRoad SSH identity');
    return;
  }

  const hmacKeyBase64 = Buffer.alloc(32, 7).toString('base64');
  const executed = spawnSync('powershell.exe', [
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    RUNTIME_BASELINE_SCRIPT_PATH,
  ], {
    encoding: 'utf8',
    input: JSON.stringify({ schemaVersion: 1, protocolRevision: 1, hmacKeyBase64 }),
    maxBuffer: 16 * 1024,
    timeout: 120_000,
  });
  assert.equal(executed.status, 0, executed.stderr || executed.stdout);
  assert.equal(executed.stderr, '');
  parseRuntimeBaselineExecution(executionResult({ stdout: executed.stdout }));
});
