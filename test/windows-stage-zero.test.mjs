import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { gunzipSync } from 'node:zlib';

import { buildWindowsStageZeroCommand, buildWindowsPairedStageZeroCommand } from '../src/enrollment/windows-stage-zero.mjs';

const PREFIX = 'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ';
const INSTALLER_URL = 'https://pkgs.tailscale.com/stable/tailscale-setup-full-1.98.9.exe';
const INSTALLER_SHA = 'b3f7e15eb33b90f0686d6037453a0c680c3553b55deca649b56b6b05635c9e7b';
const MODULUS = Buffer.concat([Buffer.from([0x80]), Buffer.alloc(383, 0x42)]).toString('base64url');
const STAGE_ONE_FAILURE_CODES = [
  'ADMIN_REQUIRED',
  'UNSUPPORTED_WINDOWS_BUILD',
  'CONFIGURATION_INVALID',
  'BOOTSTRAP_ALREADY_RUNNING',
  'BOOTSTRAP_STATE_INVALID',
  'TAILSCALE_LOGIN_REQUIRED',
  'OPENSSH_INSTALL_FAILED',
  'SSHD_CONFIG_INVALID',
  'SSHD_START_FAILED',
  'FIREWALL_CONFIG_FAILED',
  'COMPLETION_REJECTED',
  'COMPLETION_UNCERTAIN',
  'INTERNAL_ERROR',
];

function validOptions(overrides = {}) {
  return {
    controllerBaseUrl: 'https://shilins-macbook-air.tail98fb26.ts.net/agent-road/v1/dev_abc123',
    deviceId: 'dev_abc123',
    token: Buffer.alloc(32, 0xa5).toString('base64url'),
    signingPublicKey: {
      algorithm: 'RSA-SHA256',
      modulusBase64Url: MODULUS,
      exponentBase64Url: 'AQAB',
    },
    releaseManifest: {
      schemaVersion: 1,
      tailscaleWindows: {
        version: '1.98.9',
        url: INSTALLER_URL,
        sha256: INSTALLER_SHA,
        authenticodeSubject: 'CN=Tailscale Inc.',
      },
    },
    ...overrides,
  };
}

function decodeCommand(command) {
  assert.ok(command.startsWith(PREFIX));
  const wrapper = Buffer.from(command.slice(PREFIX.length), 'base64').toString('utf16le');
  const gzipBase64 = wrapper.match(/^\$g='([^']+)'/)?.[1];
  assert.ok(gzipBase64, 'stage zero must use the bounded compressed wrapper');
  return gunzipSync(Buffer.from(gzipBase64, 'base64')).toString('utf8');
}

function decodePayload(script) {
  const encoded = script.match(/\$pe='([^']+)'/)?.[1];
  assert.ok(encoded, 'stage zero must contain one encoded allowlisted payload');
  return JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
}

test('builds a bounded UTF-16LE stage-zero command with preflight and pinned Tailscale installation', () => {
  const command = buildWindowsStageZeroCommand(validOptions());
  const script = decodeCommand(command);

  assert.ok(command.length <= 32767);
  assert.doesNotMatch(command, /[\r\n]/);
  assert.match(script, /WindowsPrincipal/);
  assert.match(script, /IsInRole\(\[Security\.Principal\.WindowsBuiltInRole\]::Administrator\)/);
  assert.match(script, /\$PSVersionTable\.PSVersion\.Major -lt 5/);
  assert.match(script, /Get-CimInstance Win32_OperatingSystem/);
  assert.match(script, /17763/);
  assert.match(script, /C:\\Program Files\\Tailscale\\tailscale\.exe/);
  assert.match(script, /\[Net\.SecurityProtocolType\]::Tls12/);
  assert.match(script, /Invoke-WebRequest/);
  assert.match(script, /-MaximumRedirection 0/);
  assert.match(script, /-TimeoutSec 120/);
  assert.match(script, /Get-FileHash[^;]+-Algorithm SHA256/);
  assert.match(script, /Get-AuthenticodeSignature/);
  assert.match(script, /Get-AuthenticodeSignature -FilePath \$tailscale/);
  assert.match(script, /SignatureStatus\]::Valid/);
  const signerChecks = script.match(/SignerCertificate\.GetNameInfo\(\[Security\.Cryptography\.X509Certificates\.X509NameType\]::SimpleName,\$false\) -cne \$x\.s\.Substring\(3\)/g) ?? [];
  assert.equal(signerChecks.length, 2);
  assert.doesNotMatch(script, /SignerCertificate\.Subject -cne/);
  assert.match(script, /Run \$installer @\('\/quiet','\/norestart'\) 180 @\(0,3010\)/);
  assert.match(script, /TAILSCALE_DOWNLOAD_INVALID/);
  assert.match(script, /Acl \$tmp/);

  const payload = decodePayload(script);
  assert.deepEqual(payload, {
    u: 'https://shilins-macbook-air.tail98fb26.ts.net/agent-road/v1/dev_abc123',
    d: 'dev_abc123',
    t: Buffer.alloc(32, 0xa5).toString('base64url'),
    n: MODULUS,
    e: 'AQAB',
    i: INSTALLER_URL,
    h: INSTALLER_SHA,
    s: 'CN=Tailscale Inc.',
  });
});

test('uses a managed bounded login process, opens consent while it runs, and preserves preferences', () => {
  const script = decodeCommand(buildWindowsStageZeroCommand(validOptions()));

  assert.match(script, /BackendState -ceq 'Running'/);
  assert.match(script, /@\('set','--unattended=true'\)/);
  assert.match(script, /@\('up','--hostname=agent-road-abc123','--unattended=true','--timeout=300s'\)/);
  assert.match(script, /@\('up','--timeout=300s'\)/);
  assert.doesNotMatch(script, /authkey|auth-key/i);
  assert.doesNotMatch(script, /else\{@\('up'[^)]*--unattended=true/);
  assert.ok(script.includes("https://login\\.tailscale\\.com/a/"));
  assert.match(script, /function Login[^;]+Start-Process -FilePath \$file[^;]+-PassThru[^;]+RedirectStandardOutput[^;]+RedirectStandardError/);
  assert.doesNotMatch(script, /Start-Process -FilePath \$file[^;]+-Wait(?:\s|;)/);
  assert.match(script, /Start-Process -FilePath \$loginUrl/);
  assert.match(script, /\[Diagnostics\.Stopwatch\]::StartNew\(\)/);
  assert.match(script, /Elapsed\.TotalSeconds -lt 300/);
  assert.match(script, /300 - \$sw\.Elapsed\.TotalSeconds/);
  assert.match(script, /TS \(\[Math\]::Min\(10,\$remaining\)\)/);
  assert.match(script, /--timeout=300s/);
  assert.doesNotMatch(script, /--timeout=0/);
  assert.match(script, /Stop-Process[^;]+-Force/);
  assert.match(script, /ReadBounded @\(\$lout,\$lerr\)/);
  assert.match(script, /@\('status','--json'\)/);
  assert.match(script, /TAILSCALE_LOGIN_REQUIRED/);
  assert.doesNotMatch(script, /Write-(?:Output|Host)\s+\$(?:loginUrl|token|completionTicket)/i);

  const start = script.indexOf('Start-Process -FilePath $file');
  const open = script.indexOf('Start-Process -FilePath $loginUrl');
  const set = script.indexOf("@('set','--unattended=true')");
  assert.ok(start >= 0 && open > start, 'login URL must be reachable after nonblocking process start');
  assert.ok(set > open, 'unattended mode is set only after the bounded Running poll');
});

test('secures persistent bootstrap state, locks, and journals before Tailscale mutation', () => {
  const script = decodeCommand(buildWindowsStageZeroCommand(validOptions()));

  assert.match(script, /\$parent='C:\\ProgramData\\AgentRoad'/);
  assert.match(script, /\$root=Join-Path \$parent 'bootstrap'/);
  assert.match(script, /stage-zero\.lock/);
  assert.doesNotMatch(script, /File\.Open\([^;]+bootstrap\.lock/);
  assert.match(script, /\[IO\.FileShare\]::None/);
  assert.match(script, /BOOTSTRAP_ALREADY_RUNNING/);
  assert.match(script, /stage-zero-journal\.json/);
  assert.doesNotMatch(script, /Join-Path \$root 'journal\.json'/);
  assert.match(script, /Move-Item[^;]+-Force/);
  assert.match(script, /\[IO\.File\]::Replace\(\$jt,\$jp,\[Management\.Automation\.Language\.NullString\]::Value,\$true\)/);
  assert.doesNotMatch(script, /\[IO\.File\]::Replace\([^;]+,\$null,/);
  assert.match(script, /function Acl/);
  assert.match(script, /S-1-5-18/);
  assert.match(script, /S-1-5-32-544/);
  const journalRecord = script.match(/\$journal=@\{([^}]+)\}/)?.[1];
  assert.ok(journalRecord);
  assert.doesNotMatch(journalRecord, /token|completionTicket|loginUrl/i);

  const lock = script.indexOf('[IO.FileShare]::None');
  const journal = script.indexOf("journal.json");
  const install = script.indexOf('Run $installer');
  const login = script.indexOf('Login $tailscale');
  assert.ok(lock >= 0 && journal > lock);
  assert.ok(install > journal && login > journal, 'journal must precede all persistent Tailscale mutation');
  assert.match(script, /\$lock\.Dispose\(\)/);
});

test('reports finite redacted diagnostics for directory and ACL initialization', () => {
  const script = decodeCommand(buildWindowsStageZeroCommand(validOptions()));

  assert.match(script, /BOOTSTRAP_TEMP_CREATE_FAILED/);
  assert.match(script, /Acl \$tmp 'TEMP'/);
  assert.match(script, /ARDir \$parent 'STATE_PARENT'/);
  assert.match(script, /Acl \$parent 'STATE_PARENT'/);
  assert.match(script, /ARDir \$root 'STATE_ROOT'/);
  assert.match(script, /Acl \$root 'STATE_ROOT'/);

  for (const suffix of [
    'ACL_APPLY_FAILED',
    'ACL_PROTECTION_INVALID',
    'ACL_OWNER_INVALID',
    'ACL_RULE_COUNT_INVALID',
    'ACL_RULE_INVALID',
    'ACL_PRINCIPALS_INVALID',
    'PATH_INVALID',
    'CREATE_FAILED',
  ]) assert.ok(script.includes(suffix), suffix);

  assert.match(script, /\^BOOTSTRAP_\(TEMP\|STATE_PARENT\|STATE_ROOT\)_\(ACL_\(APPLY_FAILED\|PROTECTION_INVALID\|OWNER_INVALID\|RULE_COUNT_INVALID\|RULE_INVALID\|PRINCIPALS_INVALID\)\|PATH_INVALID\|CREATE_FAILED\)\$/);
  assert.doesNotMatch(script, /Write-(?:Error|Output|Host)\s+\$_/);
});

test('falls back to a finite phase code for unexpected pre-exchange failures', () => {
  const script = decodeCommand(buildWindowsStageZeroCommand(validOptions()));
  const phases = [
    'PREFLIGHT_IDENTITY',
    'PREFLIGHT_OS',
    'TEMP_PATH',
    'TEMP_CREATE',
    'TEMP_ACL',
    'STATE_PARENT_PATH',
    'STATE_PARENT_ACL',
    'STATE_ROOT_PATH',
    'STATE_ROOT_ACL',
    'STATE_LOCK',
    'STATE_JOURNAL_VALIDATE',
    'STATE_JOURNAL_SERIALIZE',
    'STATE_JOURNAL_OPEN',
    'STATE_JOURNAL_WRITE',
    'STATE_JOURNAL_TEMP_VERIFY',
    'STATE_JOURNAL_REVALIDATE',
    'STATE_JOURNAL_PUBLISH',
    'STATE_JOURNAL_ACL_MIGRATE',
    'STATE_JOURNAL_FINAL_VERIFY',
    'TAILSCALE',
    'EXCHANGE',
    'SIGNATURE',
    'STAGE_ONE',
  ];

  for (const phase of phases) {
    assert.ok(script.includes(`'BOOTSTRAP_PHASE_${phase}'`), phase);
  }
  assert.match(script, /\$phaseFailures -ccontains \$phase/);
  assert.match(script, /else\{ 'BOOTSTRAP_FAILED' \}/);
  assert.doesNotMatch(script, /Write-(?:Error|Output|Host)\s+\$_/);
});

test('does not collide with the built-in PowerShell dir alias', () => {
  const script = decodeCommand(buildWindowsStageZeroCommand(validOptions()));

  assert.match(script, /function ARDir\(/);
  assert.doesNotMatch(script, /function Dir\(/i);
  assert.doesNotMatch(script, /(?:^|;)Dir \$(?:parent|root)(?:;|\s)/i);
});

test('leaves the shared stage-one journal untouched and validates every persistent directory component', () => {
  const script = decodeCommand(buildWindowsStageZeroCommand(validOptions()));

  assert.match(script, /\$parent='C:\\ProgramData\\AgentRoad'/);
  assert.match(script, /\$root=Join-Path \$parent 'bootstrap'/);
  const directoryGuard = script.match(/function ARDir\([\s\S]+?function Acl/)?.[0];
  assert.ok(directoryGuard);
  assert.match(directoryGuard, /Test-Path -LiteralPath \$p/);
  assert.match(directoryGuard, /Get-Item -LiteralPath \$p -Force/);
  assert.match(directoryGuard, /PathType Container/);
  assert.match(directoryGuard, /ReparsePoint/);
  assert.match(script, /ARDir \$parent/);
  assert.match(script, /ARDir \$root/);

  const parentValidation = script.indexOf('ARDir $parent');
  const rootValidation = script.indexOf('ARDir $root');
  const stateAcl = script.indexOf('Acl $root');
  const lock = script.indexOf("stage-zero.lock");
  assert.ok(parentValidation >= 0 && rootValidation > parentValidation);
  assert.ok(stateAcl > rootValidation && lock > stateAcl, 'all path checks must precede ACLs and writes');

  assert.equal(script.includes("Join-Path $root 'journal.json'"), false,
    'generated logic must leave a preexisting shared journal byte-for-byte unchanged');
  assert.doesNotMatch(script, /(?:Replace|Move-Item)[^;]*(?:\\|')journal\.json(?:'|\b)/);
});

test('performs an exact bounded exchange and verifies signed stage one before in-memory execution', () => {
  const script = decodeCommand(buildWindowsStageZeroCommand(validOptions()));

  assert.match(script, /\/exchange/);
  assert.match(script, /Invoke-RestMethod -Method Post/);
  assert.match(script, /-ContentType 'application\/json'/);
  assert.match(script, /-MaximumRedirection 0/);
  assert.match(script, /-TimeoutSec 30/);
  assert.match(script, /PSObject\.Properties\)\.Count -ne 7/);
  assert.match(script, /\$required=@\('protocolVersion','deviceId','sshPublicKey','stageOneBase64','stageOneSha256','stageOneSignatureBase64','completionTicket'\)/);
  assert.match(script, /foreach\(\$name in \$required\)\{ if\(\$names -cnotcontains \$name\)/);
  assert.match(script, /stageOneBase64\.Length -gt 1398104/);
  assert.match(script, /\$sb\.Length -gt 1048576/);
  assert.match(script, /B64u \$result\.completionTicket 43/);
  assert.match(script, /Get-FileHash|SHA256Managed|SHA256\.Create/);
  assert.match(script, /RSAParameters/);
  assert.match(script, /RSACryptoServiceProvider 3072/);
  assert.match(script, /ImportParameters/);
  assert.match(script, /VerifyData\(\$sb,'SHA256',\$sigBytes\)/);
  assert.match(script, /\[ScriptBlock\]::Create\(\$st\)/);
  assert.match(script, /-Configuration \$cfg/);
  assert.match(script, /Clean \$tmp \$true/);
  assert.match(script, /BOOTSTRAP_SIGNATURE_INVALID/);
});

test('prints only fixed progress and redacted stable failures', () => {
  const options = validOptions();
  const script = decodeCommand(buildWindowsStageZeroCommand(options));
  const outputs = [...script.matchAll(/Write-Output '([^']+)'/g)].map((match) => match[1]);

  assert.deepEqual(outputs, [
    'Agent Road: checking Windows',
    'Agent Road: preparing Tailscale',
    'Agent Road: waiting for Tailscale login',
    'Agent Road: verifying bootstrap',
    'Agent Road: configuring Windows',
    'AGENT_ROAD_STAGE_ZERO_COMPLETE',
  ]);
  assert.equal(script.includes(options.token), false);
  assert.doesNotMatch(script, /Write-(?:Output|Host|Error)\s+\$(?:token|completionTicket|loginUrl)/i);
  assert.match(script, /\[Console\]::Error\.WriteLine\(\$primary\);exit 1/);
  assert.doesNotMatch(script, /Write-Error/);
  for (const code of [
    'AGENT_ROAD_BOOTSTRAP_FAILED:OPENSSH_INSTALL_FAILED',
    'AGENT_ROAD_BOOTSTRAP_FAILED:SSHD_CONFIG_INVALID',
    'AGENT_ROAD_BOOTSTRAP_FAILED:SSHD_START_FAILED',
    'AGENT_ROAD_BOOTSTRAP_FAILED:FIREWALL_CONFIG_FAILED',
  ]) {
    assert.ok(script.includes(`'${code}'`));
  }
  assert.match(script, /\$stageOneFailures -ccontains \$msg/);
});

test('passes through every finite stage-one failure and only its exact rollback suffix', async () => {
  const stageOne = await readFile(new URL('../windows/bootstrap-stage-one.ps1', import.meta.url), 'utf8');
  const stableFunction = stageOne.match(/function Test-AgentRoadStableFailure[\s\S]+?\n}/)?.[0];
  assert.ok(stableFunction);
  const stageOneCodes = [...stableFunction.matchAll(/'([A-Z][A-Z0-9_]+)'/g)].map((match) => match[1]);
  assert.deepEqual(stageOneCodes, STAGE_ONE_FAILURE_CODES);

  const script = decodeCommand(buildWindowsStageZeroCommand(validOptions()));
  const literalBody = script.match(/\$stageOneFailures=@\(([^)]+)\)/)?.[1];
  assert.ok(literalBody);
  const generated = [...literalBody.matchAll(/'AGENT_ROAD_BOOTSTRAP_FAILED:([A-Z0-9_]+)'/g)]
    .map((match) => match[1]);
  assert.deepEqual(generated, STAGE_ONE_FAILURE_CODES);
  assert.match(script, /\$stageOneRollbackFailures=@\(\$stageOneFailures \| ForEach-Object \{ \$_ \+ ':ROLLBACK_INCOMPLETE' }\)/);
  assert.match(script, /\$stageOneRollbackFailures -ccontains \$msg/);
  assert.doesNotMatch(script, /StartsWith\('AGENT_ROAD_BOOTSTRAP_FAILED:'\)|AGENT_ROAD_BOOTSTRAP_FAILED:\.\*/);

  const accepted = new Set(generated.flatMap((code) => [
    `AGENT_ROAD_BOOTSTRAP_FAILED:${code}`,
    `AGENT_ROAD_BOOTSTRAP_FAILED:${code}:ROLLBACK_INCOMPLETE`,
  ]));
  for (const rejected of [
    'AGENT_ROAD_BOOTSTRAP_FAILED:UNKNOWN',
    'AGENT_ROAD_BOOTSTRAP_FAILED:INTERNAL_ERROR:secret',
    'AGENT_ROAD_BOOTSTRAP_FAILED:INTERNAL_ERROR:ROLLBACK_INCOMPLETE:secret',
    'AGENT_ROAD_BOOTSTRAP_FAILED:INTERNAL_ERROR\nsecret',
  ]) assert.equal(accepted.has(rejected), false, rejected);
});

test('snapshots each primitive once and serializes no caller-owned objects', () => {
  const source = validOptions();
  const reads = new Map();
  const once = (object, key) => Object.defineProperty(object, key, {
    enumerable: true,
    get() {
      reads.set(key, (reads.get(key) ?? 0) + 1);
      return source[key];
    },
  });
  const options = {};
  for (const key of Object.keys(source)) once(options, key);
  Object.defineProperty(options, 'toJSON', { value() { throw new Error('must not serialize caller'); } });

  const command = buildWindowsStageZeroCommand(options);
  assert.ok(command.length <= 32767);
  assert.deepEqual(Object.fromEntries(reads), Object.fromEntries(Object.keys(source).map((key) => [key, 1])));
});

test('rejects unsafe URLs, identifiers, keys, manifests, injection, bounds, and non-plain objects', () => {
  const badUrls = [
    'http://host.tail123.ts.net/agent-road/v1/dev_abc123',
    'https://evil.example/agent-road/v1/dev_abc123',
    'https://tail98fb26.ts.net.evil.example/agent-road/v1/dev_abc123',
    'https://user:pass@host.tail123.ts.net/agent-road/v1/dev_abc123',
    'https://host.tail123.ts.net/agent-road/v1/dev_other',
    'https://host.tail123.ts.net/agent-road/v1/dev_abc123/exchange',
    'https://host.tail123.ts.net/agent-road/v1/dev_abc123?x=1',
    'https://host.tail123.ts.net/agent-road/v1/dev_abc123#x',
    'https://host.tail123.ts.net/agent-road/v1/dev_abc123\nboom',
  ];
  for (const controllerBaseUrl of badUrls) {
    assert.throws(() => buildWindowsStageZeroCommand(validOptions({ controllerBaseUrl })), /controller/i);
  }

  for (const deviceId of ['dev_A', 'dev_a\nb', `dev_${'a'.repeat(61)}`]) {
    assert.throws(() => buildWindowsStageZeroCommand(validOptions({ deviceId })), /device/i);
  }
  for (const token of ['short', 'a'.repeat(129), `${'a'.repeat(42)}!`, `${'a'.repeat(43)}\n`]) {
    assert.throws(() => buildWindowsStageZeroCommand(validOptions({ token })), /token/i);
  }

  const keyCases = [
    { algorithm: 'RSA-PSS', modulusBase64Url: MODULUS, exponentBase64Url: 'AQAB' },
    { algorithm: 'RSA-SHA256', modulusBase64Url: `${MODULUS}=`, exponentBase64Url: 'AQAB' },
    { algorithm: 'RSA-SHA256', modulusBase64Url: Buffer.alloc(256).toString('base64url'), exponentBase64Url: 'AQAB' },
    { algorithm: 'RSA-SHA256', modulusBase64Url: MODULUS, exponentBase64Url: 'Aw' },
    { algorithm: 'RSA-SHA256', modulusBase64Url: MODULUS, exponentBase64Url: 'AQAB', extra: true },
  ];
  for (const signingPublicKey of keyCases) {
    assert.throws(() => buildWindowsStageZeroCommand(validOptions({ signingPublicKey })), /signing public key/i);
  }

  for (const mutate of [
    (manifest) => { manifest.tailscaleWindows.url = 'https://evil.example/installer.exe'; },
    (manifest) => { manifest.tailscaleWindows.sha256 = 'A'.repeat(64); },
    (manifest) => { manifest.tailscaleWindows.authenticodeSubject = 'CN=Tailscale Inc.\nmalicious'; },
    (manifest) => { manifest.tailscaleWindows.extra = true; },
    (manifest) => { manifest.extra = true; },
  ]) {
    const manifest = structuredClone(validOptions().releaseManifest);
    mutate(manifest);
    assert.throws(() => buildWindowsStageZeroCommand(validOptions({ releaseManifest: manifest })), /release manifest/i);
  }

  for (const [key, value] of [
    ['signingPublicKey', Object.assign(Object.create(null), validOptions().signingPublicKey)],
    ['releaseManifest', Object.assign(Object.create(null), validOptions().releaseManifest)],
    ['releaseManifest', []],
  ]) {
    assert.throws(() => buildWindowsStageZeroCommand(validOptions({ [key]: value })), /plain object/i);
  }
  assert.throws(() => buildWindowsStageZeroCommand(null), /plain object/i);
});

test('bounds the fresh Tailscale hostname for the largest accepted device id', () => {
  const deviceId = `dev_${'a'.repeat(60)}`;
  const controllerBaseUrl = `https://host.tail123.ts.net/agent-road/v1/${deviceId}`;
  const script = decodeCommand(buildWindowsStageZeroCommand(validOptions({ deviceId, controllerBaseUrl })));

  assert.match(script, new RegExp(`--hostname=agent-road-${'a'.repeat(52)}'`));
  assert.doesNotMatch(script, new RegExp(`--hostname=agent-road-${'a'.repeat(53)}`));
});

test('runs every required native process through bounded redacting lifecycle helpers', () => {
  const script = decodeCommand(buildWindowsStageZeroCommand(validOptions()));

  assert.doesNotMatch(script, /&\s*\$tailscale/);
  assert.doesNotMatch(script, /icacls\.exe/i);
  assert.doesNotMatch(script, /Start-Process[^;]+-Wait(?:\s|;)/);
  assert.match(script, /RedirectStandardOutput/);
  assert.match(script, /RedirectStandardError/);
  assert.match(script, /Stopwatch\]::StartNew/);
  assert.match(script, /Elapsed\.TotalSeconds/);
  assert.match(script, /65536/);
  assert.match(script, /New-Object byte\[\]/);
  assert.match(script, /\.Read\([^;]+65536|\$remaining/);
  assert.doesNotMatch(script, /ReadAllText\(\$(?:out|err|p)\)/);
  assert.match(script, /Stop-Process[^;]+-Force/);
  assert.match(script, /WaitForExit/);
  assert.match(script, /\.Dispose\(\)/);
  assert.match(script, /NATIVE_PROCESS_FAILED/);
  assert.match(script, /NATIVE_PROCESS_TIMEOUT/);
  assert.doesNotMatch(script, /Write-(?:Output|Error|Host)[^;]*stderr/i);
  assert.doesNotMatch(script, /\$args\b/);
  assert.match(script, /function Run\(\[string\]\$file,\[object\[\]\]\$argv/);
  assert.match(script, /function Login\(\[string\]\$file,\[object\[\]\]\$argv/);
  assert.equal((script.match(/-ArgumentList \$argv/g) ?? []).length, 2);

  for (const invocation of [
    /Run[^;]+\$installer/,
    /Run[^;]+\$tailscale[^;]+status/,
    /Login[^;]+\$tailscale/,
    /Run[^;]+\$tailscale[^;]+set/,
  ]) assert.match(script, invocation);
});

test('anchors native process handles before polling so Windows PowerShell 5.1 exposes exit codes', () => {
  const script = decodeCommand(buildWindowsStageZeroCommand(validOptions()));

  assert.match(
    script,
    /\$proc=Start-Process[^;]+;\$null=\$proc\.Handle;\$sw=\[Diagnostics\.Stopwatch\]::StartNew\(\)/,
  );
});

test('applies and verifies an exact trusted DACL on both persistent directories', () => {
  const script = decodeCommand(buildWindowsStageZeroCommand(validOptions()));
  const descriptorStart = script.indexOf('function DirSec');
  const guardStart = script.indexOf('function ARDir');
  const applyStart = script.indexOf('function Acl');
  const nextStart = script.indexOf('function FileSec');
  const descriptor = script.slice(descriptorStart, guardStart);
  const guard = script.slice(guardStart, applyStart);
  const apply = script.slice(applyStart, nextStart);

  assert.ok(descriptorStart >= 0 && guardStart > descriptorStart && applyStart > guardStart);
  assert.match(script, /Security\.AccessControl\.DirectorySecurity/);
  assert.match(script, /SetAccessRuleProtection\(\$true,\$false\)/);
  assert.match(script, /\$own=\$adm\.Translate\(\[Security\.Principal\.NTAccount\]\)/);
  assert.match(script, /SetOwner\(\$own\)/);
  assert.doesNotMatch(script, /SetOwner\(\$adm\)/,
    'Windows PowerShell 5.1 must not receive a SID directly as owner');
  assert.match(script, /S-1-5-18/);
  assert.match(script, /S-1-5-32-544/);
  assert.match(script, /AddAccessRule/);
  assert.match(script, /\[IO\.Directory\]::SetAccessControl/);
  assert.match(script, /\[IO\.Directory\]::GetAccessControl/);
  assert.match(script, /AreAccessRulesProtected/);
  assert.match(script, /AccessControlType/);
  assert.match(script, /IsInherited/);
  assert.match(script, /BOOTSTRAP_STATE_INVALID/);
  assert.match(descriptor, /\$own=\$adm\.Translate\(\[Security\.Principal\.NTAccount\]\)/);
  assert.match(descriptor, /SetOwner\(\$own\)/);
  assert.match(guard, /\[Security\.AccessControl\.DirectorySecurity\]\$ds=DirSec/);
  assert.match(guard, /\[IO\.Directory\]::CreateDirectory\(\$p,\$ds\)/);
  assert.match(apply,
    /GetAccessRules\(\$true,\$true,\[Security\.Principal\.SecurityIdentifier\]\)/);
  assert.match(script,
    /BOOTSTRAP_PHASE_TEMP_CREATE';try\{ \[Security\.AccessControl\.DirectorySecurity\]\$ds=DirSec;\[IO\.Directory\]::CreateDirectory\(\$tmp,\$ds\)/);
  assert.doesNotMatch(script, /New-Item -ItemType Directory/,
    'each stage-zero directory must receive its exact descriptor at creation time');

  assert.match(script, /Acl \$parent/);
  assert.match(script, /Acl \$root/);
  const parentAcl = script.indexOf('Acl $parent');
  const rootAcl = script.indexOf('Acl $root');
  const lock = script.indexOf('stage-zero.lock');
  assert.ok(parentAcl >= 0 && rootAcl > parentAcl && lock > rootAcl);
  assert.match(script.slice(rootAcl, lock), /ARDir \$parent 'STATE_PARENT';ARDir \$root 'STATE_ROOT'/,
    'persistent components must be revalidated immediately after ACL application');
});

test('creates, flushes, verifies, and migrates the stage-zero journal with an exact file ACL', () => {
  const script = decodeCommand(buildWindowsStageZeroCommand(validOptions()));
  const securityStart = script.indexOf('function FileSec');
  const assertStart = script.indexOf('function FileAcl');
  const setterStart = script.indexOf('function SetFileAcl');
  const streamStart = script.indexOf('function NewFile');
  const nextFunction = script.indexOf('function ', streamStart + 1);

  assert.ok(securityStart >= 0 && assertStart > securityStart);
  assert.ok(setterStart > assertStart && streamStart > setterStart && nextFunction > streamStart);

  const security = script.slice(securityStart, assertStart);
  const verifier = script.slice(assertStart, setterStart);
  const setter = script.slice(setterStart, streamStart);
  const stream = script.slice(streamStart, nextFunction);

  assert.match(security, /Security\.AccessControl\.FileSecurity/);
  assert.match(security, /\$own=\$adm\.Translate\(\[Security\.Principal\.NTAccount\]\)/);
  assert.match(security, /SetOwner\(\$own\)/);
  assert.doesNotMatch(security, /SetOwner\(\$adm\)/);
  assert.match(security, /SetAccessRuleProtection\(\$true,\$false\)/);
  assert.match(security, /foreach\(\$sid in @\(\$sys,\$adm\)\)/);
  assert.equal((security.match(/FileSystemRights\]::FullControl/g) ?? []).length, 1);
  assert.equal((security.match(/InheritanceFlags\]::None/g) ?? []).length, 1);
  assert.equal((security.match(/PropagationFlags\]::None/g) ?? []).length, 1);

  assert.match(verifier, /\[IO\.File\]::GetAccessControl/);
  assert.match(verifier,
    /GetAccessRules\(\$true,\$true,\[Security\.Principal\.SecurityIdentifier\]\)/);
  assert.match(verifier, /AreAccessRulesProtected/);
  assert.match(verifier, /AreAccessRulesCanonical/);
  assert.match(verifier, /GetOwner\(\[Security\.Principal\.SecurityIdentifier\]\)\.Value/);
  assert.match(verifier, /IsInherited/);
  assert.match(verifier, /FileSystemRights\]::FullControl/);
  assert.match(verifier, /InheritanceFlags\]::None/);
  assert.match(verifier, /PropagationFlags\]::None/);
  assert.match(verifier, /\$rs\.Count -ne 2/);
  assert.match(verifier, /function FileAcl\(\[string\]\$p,\[string\]\$code\)/);
  assert.doesNotMatch(verifier, /BOOTSTRAP_STATE_INVALID/);
  assert.match(verifier, /Fail \$code/);

  assert.match(setter, /function SetFileAcl\(\[string\]\$p,\[string\]\$code\)/);
  assert.match(setter, /\[Security\.AccessControl\.FileSecurity\]\$fs=FileSec/);
  assert.match(setter, /\[IO\.File\]::SetAccessControl\(\$p,\$fs\)/);
  assert.match(setter, /FileAcl \$p \$code/);
  assert.match(stream, /function NewFile\(\[string\]\$p,\[string\]\$code\)/);
  assert.match(stream, /\[Security\.AccessControl\.FileSecurity\]\$fs=FileSec/);
  assert.match(stream, /New-Object IO\.FileStream\(/);
  assert.match(stream, /\[IO\.FileMode\]::CreateNew/);
  assert.match(stream, /\[Security\.AccessControl\.FileSystemRights\]::FullControl/);
  assert.match(stream, /\[IO\.FileShare\]::None/);
  assert.match(stream, /4096/);
  assert.match(stream, /\[IO\.FileOptions\]::WriteThrough/);

  assert.doesNotMatch(script, /\[IO\.File\]::Open\(\$jt,\[IO\.FileMode\]::CreateNew/);
  assert.match(script, /\$js=NewFile \$jt \$phase/);
  assert.match(script, /\$js\.Flush\(\$true\)/);
  assert.match(script, /BOOTSTRAP_PHASE_STATE_JOURNAL_TEMP_VERIFY';FileAcl \$jt \$phase;FileBytes \$jt \$jb \$phase/);

  const publish = script.indexOf('[IO.File]::Replace($jt,$jp');
  const migratePhase = script.indexOf("BOOTSTRAP_PHASE_STATE_JOURNAL_ACL_MIGRATE'", publish);
  const migrate = script.indexOf('SetFileAcl $jp $phase', migratePhase);
  const finalPhase = script.indexOf("BOOTSTRAP_PHASE_STATE_JOURNAL_FINAL_VERIFY'", migrate);
  const finalBytes = script.indexOf('FileBytes $jp $jb $phase', finalPhase);
  const write = script.indexOf('$js.Write($jb,0,$jb.Length)');
  const flush = script.indexOf('$js.Flush($true)', write);
  const dispose = script.indexOf('$js.Dispose()', flush);
  const tempPhase = script.indexOf("BOOTSTRAP_PHASE_STATE_JOURNAL_TEMP_VERIFY'", dispose);
  const tempAcl = script.indexOf('FileAcl $jt $phase', tempPhase);
  const tempBytes = script.indexOf('FileBytes $jt $jb $phase', tempAcl);
  const tailscale = script.indexOf("BOOTSTRAP_PHASE_TAILSCALE'", finalBytes);
  assert.ok(write >= 0 && flush > write && dispose > flush && tempPhase > dispose
    && tempAcl > tempPhase && tempBytes > tempAcl && publish > tempBytes
    && tailscale > finalBytes,
  'journal content and ACLs must be durable and verified before publication and Tailscale mutation');
  assert.ok(publish >= 0 && migratePhase > publish && migrate > migratePhase
    && finalPhase > migrate && finalBytes > finalPhase,
    'legacy destination ACL must be explicitly replaced and verified after atomic content publish');

  for (const alias of ['DirSec', 'FileSec', 'FileAcl', 'SetFileAcl', 'NewFile', 'FileBytes']) {
    assert.equal((script.match(new RegExp(`function ${alias}\\b`, 'g')) ?? []).length, 1, alias);
  }
  for (const longName of [
    'New-AgentRoadRestrictedDirectorySecurity',
    'New-AgentRoadRestrictedFileSecurity',
    'Assert-AgentRoadRestrictedFileAcl',
    'Set-AgentRoadRestrictedFileAcl',
    'New-AgentRoadRestrictedFileStream',
    'Assert-AgentRoadFileBytes',
  ]) assert.equal(script.includes(longName), false, longName);
});

test('emits the exact bootstrap journal ACL required by both runtime consumers', async () => {
  const script = decodeCommand(buildWindowsStageZeroCommand(validOptions()));
  const securityStart = script.indexOf('function FileSec');
  const assertStart = script.indexOf('function FileAcl');
  const producer = script.slice(securityStart, assertStart);
  const [core, inventory] = await Promise.all([
    readFile(new URL('../windows/runtime-provision-core.ps1', import.meta.url), 'utf8'),
    readFile(new URL('../windows/runtime-inventory.ps1', import.meta.url), 'utf8'),
  ]);

  for (const expected of [
    'S-1-5-18',
    'S-1-5-32-544',
    'FileSystemRights]::FullControl',
    'InheritanceFlags]::None',
    'PropagationFlags]::None',
  ]) assert.ok(producer.includes(expected), `producer must emit ${expected}`);

  for (const [name, consumer] of [['core', core], ['inventory', inventory]]) {
    assert.match(consumer, /stage-zero-journal\.json/u, `${name} journal path`);
    assert.match(consumer, /AreAccessRulesProtected/u, `${name} protected DACL`);
    assert.match(consumer, /GetOwner\(\[Security\.Principal\.SecurityIdentifier\]\)\.Value/u,
      `${name} stable owner SID`);
    assert.match(consumer, /\$owner\s+-cne\s+'S-1-5-32-544'/u, `${name} Administrators owner`);
    assert.match(consumer, /\$rules\.Count\s+-ne\s+2/u, `${name} exact ACE count`);
    assert.match(consumer,
      /GetAccessRules\(\$true,\s*\$true,\s*\[Security\.Principal\.SecurityIdentifier\]\)/u,
      `${name} enumerates inherited ACEs`);
    assert.match(consumer, /\$rule\.IsInherited/u, `${name} explicit ACEs`);
    assert.match(consumer, /FileSystemRights\]::FullControl/u, `${name} FullControl`);
    assert.match(consumer, /InheritanceFlags\]::None/u, `${name} no file inheritance`);
    assert.match(consumer, /PropagationFlags\]::None/u, `${name} no propagation`);
  }
});

test('fails closed on unsafe state children and revalidates before every state mutation', () => {
  const script = decodeCommand(buildWindowsStageZeroCommand(validOptions()));

  assert.match(script, /stage-zero\.lock/);
  assert.match(script, /stage-zero-journal\.json/);
  assert.match(script, /stage-zero-journal\.\*/);
  assert.match(script, /PathType Leaf/);
  assert.match(script, /ReparsePoint/);
  assert.match(script, /LinkType/);
  assert.match(script, /\[IO\.FileMode\]::CreateNew/);

  const lockOpen = script.indexOf('[IO.File]::Open($lockFile');
  assert.ok(script.lastIndexOf('ARDir $parent', lockOpen) >= 0);
  assert.ok(script.lastIndexOf('ARDir $root', lockOpen) >= 0);
});

test('preserves primary errors, reports cleanup failures, and publishes completion only after cleanup', () => {
  const script = decodeCommand(buildWindowsStageZeroCommand(validOptions()));

  assert.match(script, /\$primary/);
  assert.match(script, /BOOTSTRAP_CLEANUP_FAILED/);
  assert.match(script, /AGENT_ROAD_STAGE_ZERO_COMPLETE/);
  assert.doesNotMatch(script, /Agent Road: bootstrap complete/);
  assert.match(script, /@\(\$lout,\$lerr,\$sp,\$jt,\$installer\)/);
  assert.match(script, /Clean \$cp \$false/);
  assert.match(script, /function Clean[\s\S]+?Remove-Item -LiteralPath \$p/);
  assert.match(script, /elseif\(\$cf\)\{ \[Console\]::Error\.WriteLine\('BOOTSTRAP_CLEANUP_FAILED'\);exit 1/);

  const cleanup = script.indexOf('finally{');
  const error = script.lastIndexOf('[Console]::Error.WriteLine');
  const complete = script.indexOf("Write-Output 'AGENT_ROAD_STAGE_ZERO_COMPLETE'");
  assert.ok(cleanup >= 0 && error > cleanup && complete > cleanup);
  assert.match(script, /if\(\$null -ne \$primary\)[^;]+\[Console\]::Error\.WriteLine\(\$primary\);exit 1/);
});


test('paired bootstrap uses a restricted key file and keeps ordinary enrollment unchanged', () => {
  const key = 'tskey-auth-' + 'fixture'.repeat(8);
  const command = buildWindowsPairedStageZeroCommand(validOptions(), key);
  assert.ok(command.length <= 32767);
  const script = decodeCommand(command);
  assert.equal(decodePayload(script).a, key);
  assert.match(script, /--auth-key=file:/);
  assert.match(script, /join-auth\.key/);
  assert.doesNotMatch(script, new RegExp(key));
  assert.doesNotMatch(decodeCommand(buildWindowsStageZeroCommand(validOptions())), /auth-key|join-auth/);
  for (const value of ['', key + '\n', 'not-a-key']) {
    assert.throws(() => buildWindowsPairedStageZeroCommand(validOptions(), value));
  }
});
