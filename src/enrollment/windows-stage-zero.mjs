import { encodePowerShellCommand } from './powershell-command.mjs';
import { gzipSync } from 'node:zlib';

const OPTION_KEYS = ['controllerBaseUrl', 'deviceId', 'token', 'signingPublicKey', 'releaseManifest'];
const PUBLIC_KEY_KEYS = ['algorithm', 'modulusBase64Url', 'exponentBase64Url'];
const MANIFEST_KEYS = ['schemaVersion', 'tailscaleWindows'];
const RELEASE_KEYS = ['version', 'url', 'sha256', 'authenticodeSubject'];
const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const VERSION_PATTERN = /^\d+\.\d+\.\d+$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const MAX_COMMAND_URL_LENGTH = 2048;
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

function isPlainObject(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function requirePlainObject(value, name) {
  if (!isPlainObject(value)) throw new TypeError(`${name} must be a plain object`);
}

function hasExactKeys(value, keys) {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function decodeCanonicalBase64Url(value) {
  if (typeof value !== 'string' || !BASE64URL_PATTERN.test(value)) return null;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length > 0 && bytes.toString('base64url') === value ? bytes : null;
}

function invalid(message) {
  throw new TypeError(message);
}

function validateControllerBaseUrl(value, deviceId) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_COMMAND_URL_LENGTH
    || value.trim() !== value
    || /[\x00-\x20\x7f]/u.test(value)
  ) {
    invalid('invalid controller base URL');
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    invalid('invalid controller base URL');
  }
  const hostname = url.hostname.toLowerCase().replace(/\.$/u, '');
  if (
    url.protocol !== 'https:'
    || url.username
    || url.password
    || url.port
    || url.search
    || url.hash
    || !hostname.endsWith('.ts.net')
    || url.pathname !== `/agent-road/v1/${deviceId}`
  ) {
    invalid('invalid controller base URL');
  }
  return url.href.replace(/\/$/u, '');
}

function snapshotPublicKey(value) {
  requirePlainObject(value, 'signing public key');
  if (!hasExactKeys(value, PUBLIC_KEY_KEYS)) invalid('invalid signing public key');
  const algorithm = value.algorithm;
  const modulusBase64Url = value.modulusBase64Url;
  const exponentBase64Url = value.exponentBase64Url;
  const modulus = decodeCanonicalBase64Url(modulusBase64Url);
  if (
    algorithm !== 'RSA-SHA256'
    || exponentBase64Url !== 'AQAB'
    || !modulus
    || modulus.length !== 384
    || (modulus[0] & 0x80) === 0
  ) {
    invalid('invalid signing public key');
  }
  return { algorithm, modulusBase64Url, exponentBase64Url };
}

function snapshotManifest(value) {
  requirePlainObject(value, 'release manifest');
  if (!hasExactKeys(value, MANIFEST_KEYS)) invalid('invalid release manifest');
  const schemaVersion = value.schemaVersion;
  const releaseValue = value.tailscaleWindows;
  requirePlainObject(releaseValue, 'release manifest tailscaleWindows');
  if (!hasExactKeys(releaseValue, RELEASE_KEYS)) invalid('invalid release manifest');
  const version = releaseValue.version;
  const url = releaseValue.url;
  const sha256 = releaseValue.sha256;
  const authenticodeSubject = releaseValue.authenticodeSubject;
  if (
    schemaVersion !== 1
    || typeof version !== 'string'
    || !VERSION_PATTERN.test(version)
    || url !== `https://pkgs.tailscale.com/stable/tailscale-setup-full-${version}.exe`
    || typeof sha256 !== 'string'
    || !SHA256_PATTERN.test(sha256)
    || authenticodeSubject !== 'CN=Tailscale Inc.'
  ) {
    invalid('invalid release manifest');
  }
  return { version, url, sha256, authenticodeSubject };
}

function buildScript(payloadBase64, hostname, paired = false) {
  const stageOneFailures = STAGE_ONE_FAILURE_CODES
    .map((code) => `'AGENT_ROAD_BOOTSTRAP_FAILED:${code}'`)
    .join(',');
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "$ProgressPreference = 'SilentlyContinue'",
    'Set-StrictMode -Version 2.0',
    `$payloadEncoded = '${payloadBase64}'`,
    '$payloadJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payloadEncoded))',
    '$payload = $payloadJson | ConvertFrom-Json',
    '$tempRoot = $null',
    '$bootstrapLock = $null',
    '$lockPath = $null',
    '$journalTemp = $null',
    '$stageOnePath = $null',
    '$installer = $null',
    '$loginStdout = $null',
    '$loginStderr = $null',
    ...(paired ? ['$pairAuthPath = $null'] : []),
    '$script:loginProcess = $null',
    '$primary = $null',
    '$cleanupFailed = $false',
    '$completed = $false',
    "$phase = 'BOOTSTRAP_PHASE_PREFLIGHT_IDENTITY'",
    "function Stop-AgentRoad([string]$code) { throw $code }",
    "function New-AgentRoadRestrictedDirectorySecurity { $system = New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'; $admins = New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'; $ownerAccount = $admins.Translate([Security.Principal.NTAccount]); $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit; $security = New-Object Security.AccessControl.DirectorySecurity; $security.SetOwner($ownerAccount); $security.SetAccessRuleProtection($true,$false); foreach ($sid in @($system,$admins)) { $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))) }; return $security }",
    "function Confirm-AgentRoadDirectory([string]$path,[string]$scope) { if (Test-Path -LiteralPath $path) { $valid = $false; try { $item = Get-Item -LiteralPath $path -Force; $valid = (Test-Path -LiteralPath $path -PathType Container) -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) } catch { Stop-AgentRoad ('BOOTSTRAP_' + $scope + '_PATH_INVALID') }; if (-not $valid) { Stop-AgentRoad ('BOOTSTRAP_' + $scope + '_PATH_INVALID') } } else { try { [Security.AccessControl.DirectorySecurity]$directorySecurity = New-AgentRoadRestrictedDirectorySecurity; [IO.Directory]::CreateDirectory($path,$directorySecurity) | Out-Null } catch { Stop-AgentRoad ('BOOTSTRAP_' + $scope + '_CREATE_FAILED') } } }",
    "function Set-AgentRoadAcl([string]$path,[string]$scope) { try { $system = New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'; $admins = New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'; $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit; [Security.AccessControl.DirectorySecurity]$directorySecurity = New-AgentRoadRestrictedDirectorySecurity; [IO.Directory]::SetAccessControl($path,$directorySecurity); $verify = [IO.Directory]::GetAccessControl($path); $rules = @($verify.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])); $owner = $verify.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { Stop-AgentRoad ('BOOTSTRAP_' + $scope + '_ACL_APPLY_FAILED') }; if (-not $verify.AreAccessRulesProtected) { Stop-AgentRoad ('BOOTSTRAP_' + $scope + '_ACL_PROTECTION_INVALID') }; if ($owner -cne $admins.Value) { Stop-AgentRoad ('BOOTSTRAP_' + $scope + '_ACL_OWNER_INVALID') }; if ($rules.Count -ne 2) { Stop-AgentRoad ('BOOTSTRAP_' + $scope + '_ACL_RULE_COUNT_INVALID') }; foreach ($rule in $rules) { if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $rule.InheritanceFlags -ne $inherit -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or @($system.Value,$admins.Value) -cnotcontains $rule.IdentityReference.Value) { Stop-AgentRoad ('BOOTSTRAP_' + $scope + '_ACL_RULE_INVALID') } }; if (@($rules.IdentityReference.Value | Select-Object -Unique).Count -ne 2) { Stop-AgentRoad ('BOOTSTRAP_' + $scope + '_ACL_PRINCIPALS_INVALID') } }",
    "function New-AgentRoadRestrictedFileSecurity { $system = New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'; $admins = New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'; $ownerAccount = $admins.Translate([Security.Principal.NTAccount]); $security = New-Object Security.AccessControl.FileSecurity; $security.SetOwner($ownerAccount); $security.SetAccessRuleProtection($true,$false); foreach ($sid in @($system,$admins)) { $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.InheritanceFlags]::None,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))) }; return $security }",
    "function Assert-AgentRoadRestrictedFileAcl([string]$path,[string]$code) { try { Confirm-AgentRoadFile $path; $verify = [IO.File]::GetAccessControl($path); $rules = @($verify.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])); $actualOwner = $verify.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { Stop-AgentRoad $code }; if (-not $verify.AreAccessRulesProtected -or -not $verify.AreAccessRulesCanonical -or $actualOwner -cne 'S-1-5-32-544' -or $rules.Count -ne 2) { Stop-AgentRoad $code }; $seen = @(); foreach ($rule in $rules) { $sid = [string]$rule.IdentityReference.Value; if ($rule.IsInherited -or $sid -cnotin @('S-1-5-18','S-1-5-32-544') -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { Stop-AgentRoad $code }; $seen += $sid }; if ($seen -cnotcontains 'S-1-5-18' -or $seen -cnotcontains 'S-1-5-32-544') { Stop-AgentRoad $code } }",
    "function Set-AgentRoadRestrictedFileAcl([string]$path,[string]$code) { try { [Security.AccessControl.FileSecurity]$fileSecurity = New-AgentRoadRestrictedFileSecurity; [IO.File]::SetAccessControl($path,$fileSecurity) } catch { Stop-AgentRoad $code }; Assert-AgentRoadRestrictedFileAcl $path $code }",
    "function New-AgentRoadRestrictedFileStream([string]$path,[string]$code) { try { [Security.AccessControl.FileSecurity]$fileSecurity = New-AgentRoadRestrictedFileSecurity; $stream = New-Object IO.FileStream($path,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough,$fileSecurity); return $stream } catch { Stop-AgentRoad $code } }",
    "function Assert-AgentRoadFileBytes([string]$path,[byte[]]$expectedBytes,[string]$code) { try { $actualBytes = [IO.File]::ReadAllBytes($path) } catch { Stop-AgentRoad $code }; if ($actualBytes.Length -ne $expectedBytes.Length -or [Convert]::ToBase64String($actualBytes) -cne [Convert]::ToBase64String($expectedBytes)) { Stop-AgentRoad $code } }",
    "function Confirm-AgentRoadFile([string]$path) { if (Test-Path -LiteralPath $path) { $item = Get-Item -LiteralPath $path -Force; $link = $item.PSObject.Properties['LinkType']; if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint -or ($null -ne $link -and -not [string]::IsNullOrEmpty($link.Value))) { Stop-AgentRoad 'BOOTSTRAP_STATE_INVALID' } } }",
    "function Remove-AgentRoadPath([string]$path,[bool]$recurse) { if ([string]::IsNullOrEmpty($path)) { return $true }; try { if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -Recurse:$recurse -ErrorAction Stop } } catch { return $false }; return -not (Test-Path -LiteralPath $path) }",
    "function Read-AgentRoadBounded([string[]]$paths) { $buffer = New-Object byte[] 65537; $builder = New-Object Text.StringBuilder; $total = 0; foreach ($path in $paths) { if (Test-Path -LiteralPath $path) { $stream = [IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite); try { $remaining = 65536 - $total; if ($remaining -lt 0 -or $stream.Length -gt $remaining) { Stop-AgentRoad 'NATIVE_PROCESS_FAILED' }; $count = $stream.Read($buffer,0,[Math]::Min($buffer.Length,$remaining + 1)); if ($count -gt $remaining -or $stream.Length -gt $remaining) { Stop-AgentRoad 'NATIVE_PROCESS_FAILED' }; $null = $builder.Append([Text.Encoding]::UTF8.GetString($buffer,0,$count)); $total += $count } finally { $stream.Dispose() } } }; return $builder.ToString() }",
    "function Convert-AgentRoadBase64([string]$value,[int]$maximum) { if ([string]::IsNullOrEmpty($value) -or $value.Length -gt $maximum -or $value -notmatch '^[A-Za-z0-9+/]+={0,2}$') { Stop-AgentRoad 'BOOTSTRAP_SIGNATURE_INVALID' }; try { $bytes = [Convert]::FromBase64String($value) } catch { Stop-AgentRoad 'BOOTSTRAP_SIGNATURE_INVALID' }; if ([Convert]::ToBase64String($bytes) -cne $value) { Stop-AgentRoad 'BOOTSTRAP_SIGNATURE_INVALID' }; return $bytes }",
    "function Convert-AgentRoadBase64Url([string]$value,[int]$maximum) { if ([string]::IsNullOrEmpty($value) -or $value.Length -gt $maximum -or $value -notmatch '^[A-Za-z0-9_-]+$') { Stop-AgentRoad 'BOOTSTRAP_SIGNATURE_INVALID' }; $encoded = $value.Replace('-','+').Replace('_','/'); switch ($encoded.Length % 4) { 0 {} 2 { $encoded += '==' } 3 { $encoded += '=' } default { Stop-AgentRoad 'BOOTSTRAP_SIGNATURE_INVALID' } }; try { $bytes = [Convert]::FromBase64String($encoded) } catch { Stop-AgentRoad 'BOOTSTRAP_SIGNATURE_INVALID' }; $canonical = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_'); if ($canonical -cne $value) { Stop-AgentRoad 'BOOTSTRAP_SIGNATURE_INVALID' }; return $bytes }",
    "function Stop-TailscaleLogin { $ok = $true; if ($null -ne $script:loginProcess) { try { if (-not $script:loginProcess.HasExited) { Stop-Process -Id $script:loginProcess.Id -Force -ErrorAction Stop }; if (-not $script:loginProcess.WaitForExit(5000)) { $ok = $false } } catch { $ok = $false }; try { $script:loginProcess.Dispose() } catch { $ok = $false }; $script:loginProcess = $null }; return $ok }",
    "function Invoke-AgentRoadNative([string]$file,[object[]]$argv,[double]$seconds,[int[]]$accepted,[string]$code) { $out = Join-Path $tempRoot ('native-' + [guid]::NewGuid().ToString('N') + '.out'); $err = $out + '.err'; $process = $null; $failure = $null; $cleanup = $false; $text = ''; $exit = -1; try { $process = Start-Process -FilePath $file -ArgumentList $argv -PassThru -RedirectStandardOutput $out -RedirectStandardError $err; $null = $process.Handle; $timer = [Diagnostics.Stopwatch]::StartNew(); while (-not $process.HasExited -and $timer.Elapsed.TotalSeconds -lt $seconds) { $null = Read-AgentRoadBounded @($out,$err); Start-Sleep -Milliseconds 100 }; if (-not $process.HasExited) { Stop-AgentRoad 'NATIVE_PROCESS_TIMEOUT' }; $process.WaitForExit(); $exit = $process.ExitCode; $null = Read-AgentRoadBounded @($out,$err); $text = Read-AgentRoadBounded @($out); if ($null -ne $accepted -and $accepted -notcontains $exit) { Stop-AgentRoad $code } } catch { $failure = $_.Exception.Message } finally { if ($null -ne $process) { try { if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction Stop }; if (-not $process.WaitForExit(5000)) { $cleanup = $true } } catch { $cleanup = $true }; try { $process.Dispose() } catch { $cleanup = $true } }; if (-not (Remove-AgentRoadPath $out $false) -or -not (Remove-AgentRoadPath $err $false)) { $cleanup = $true } }; if ($null -ne $failure) { Stop-AgentRoad $failure }; if ($cleanup) { Stop-AgentRoad 'BOOTSTRAP_CLEANUP_FAILED' }; return [pscustomobject]@{ ExitCode = $exit; Text = $text } }",
    "function Get-TailscaleStatus([double]$seconds) { $run = Invoke-AgentRoadNative $tailscale @('status','--json') $seconds $null 'NATIVE_PROCESS_FAILED'; if ($run.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($run.Text)) { return $null }; try { return ($run.Text | ConvertFrom-Json) } catch { return $null } }",
    "function Invoke-AgentRoadLogin([string]$file,[object[]]$argv) { $script:loginProcess = Start-Process -FilePath $file -ArgumentList $argv -PassThru -RedirectStandardOutput $loginStdout -RedirectStandardError $loginStderr; $opened = $false; $timer = [Diagnostics.Stopwatch]::StartNew(); while ($timer.Elapsed.TotalSeconds -lt 300) { $output = Read-AgentRoadBounded @($loginStdout,$loginStderr); if (-not $opened) { $match = [regex]::Match($output, 'https://login\\.tailscale\\.com/a/[A-Za-z0-9_-]{1,256}'); if ($match.Success) { $loginUrl = $match.Value; Start-Process -FilePath $loginUrl | Out-Null; $loginUrl = $null; $opened = $true } }; $remaining = 300 - $timer.Elapsed.TotalSeconds; if ($remaining -le 0) { break }; $status = Get-TailscaleStatus ([Math]::Min(10,$remaining)); if ($null -ne $status -and $status.BackendState -ceq 'Running' -and @($status.TailscaleIPs).Count -gt 0) { break }; if ($script:loginProcess.HasExited -and -not $opened) { break }; Start-Sleep -Milliseconds 250 }; if (-not (Stop-TailscaleLogin)) { Stop-AgentRoad 'BOOTSTRAP_CLEANUP_FAILED' }; if ($null -eq $status -or $status.BackendState -cne 'Running' -or @($status.TailscaleIPs).Count -eq 0) { Stop-AgentRoad 'TAILSCALE_LOGIN_REQUIRED' }; return $status }",
    'try {',
    "Write-Output 'Agent Road: checking Windows'",
    "$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())",
    "if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Stop-AgentRoad 'ADMIN_REQUIRED' }",
    "if ($PSVersionTable.PSVersion.Major -lt 5) { Stop-AgentRoad 'UNSUPPORTED_POWERSHELL' }",
    "$phase = 'BOOTSTRAP_PHASE_PREFLIGHT_OS'",
    '$operatingSystem = Get-CimInstance Win32_OperatingSystem',
    "if ([int]$operatingSystem.BuildNumber -lt 17763) { Stop-AgentRoad 'UNSUPPORTED_WINDOWS_BUILD' }",
    '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12',
    "$phase = 'BOOTSTRAP_PHASE_TEMP_PATH'",
    "$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('AgentRoad-' + [guid]::NewGuid().ToString('N'))",
    "$phase = 'BOOTSTRAP_PHASE_TEMP_CREATE'",
    "try { [Security.AccessControl.DirectorySecurity]$directorySecurity = New-AgentRoadRestrictedDirectorySecurity; [IO.Directory]::CreateDirectory($tempRoot,$directorySecurity) | Out-Null } catch { Stop-AgentRoad 'BOOTSTRAP_TEMP_CREATE_FAILED' }",
    "$phase = 'BOOTSTRAP_PHASE_TEMP_ACL'",
    "Set-AgentRoadAcl $tempRoot 'TEMP'",
    "$stateParent = 'C:\\ProgramData\\AgentRoad'",
    "$phase = 'BOOTSTRAP_PHASE_STATE_PARENT_PATH'",
    "Confirm-AgentRoadDirectory $stateParent 'STATE_PARENT'",
    "$phase = 'BOOTSTRAP_PHASE_STATE_PARENT_ACL'",
    "Set-AgentRoadAcl $stateParent 'STATE_PARENT'",
    "$stateRoot = Join-Path $stateParent 'bootstrap'",
    "$phase = 'BOOTSTRAP_PHASE_STATE_ROOT_PATH'",
    "Confirm-AgentRoadDirectory $stateRoot 'STATE_ROOT'",
    "$phase = 'BOOTSTRAP_PHASE_STATE_ROOT_ACL'",
    "Set-AgentRoadAcl $stateRoot 'STATE_ROOT'",
    "Confirm-AgentRoadDirectory $stateParent 'STATE_PARENT'",
    "Confirm-AgentRoadDirectory $stateRoot 'STATE_ROOT'",
    "$phase = 'BOOTSTRAP_PHASE_STATE_LOCK'",
    "$lockPath = Join-Path $stateRoot 'stage-zero.lock'",
    'Confirm-AgentRoadFile $lockPath',
    "try { $bootstrapLock = [IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None) } catch [IO.IOException] { Stop-AgentRoad 'BOOTSTRAP_ALREADY_RUNNING' }",
    "$phase = 'BOOTSTRAP_PHASE_STATE_JOURNAL_VALIDATE'",
    "$journalPath = Join-Path $stateRoot 'stage-zero-journal.json'",
    'Confirm-AgentRoadFile $journalPath',
    "foreach ($stale in @(Get-ChildItem -LiteralPath $stateRoot -Filter 'stage-zero-journal.*.tmp' -Force)) { Confirm-AgentRoadFile $stale.FullName }",
    "Confirm-AgentRoadDirectory $stateParent 'STATE_PARENT'",
    "Confirm-AgentRoadDirectory $stateRoot 'STATE_ROOT'",
    "$journalTemp = Join-Path $stateRoot ('stage-zero-journal.' + [guid]::NewGuid().ToString('N') + '.tmp')",
    "$phase = 'BOOTSTRAP_PHASE_STATE_JOURNAL_SERIALIZE'",
    "$journal = @{ schemaVersion = 1; phase = 'stage-zero'; deviceId = $payload.deviceId; updatedAt = [DateTime]::UtcNow.ToString('o'); checkpoints = @('preflight') } | ConvertTo-Json -Compress",
    '$journalBytes = (New-Object Text.UTF8Encoding($false)).GetBytes($journal)',
    "$phase = 'BOOTSTRAP_PHASE_STATE_JOURNAL_OPEN'",
    '$journalStream = New-AgentRoadRestrictedFileStream $journalTemp $phase',
    "$phase = 'BOOTSTRAP_PHASE_STATE_JOURNAL_WRITE'",
    'try { $journalStream.Write($journalBytes,0,$journalBytes.Length); $journalStream.Flush($true) } finally { $journalStream.Dispose() }',
    "$phase = 'BOOTSTRAP_PHASE_STATE_JOURNAL_TEMP_VERIFY'",
    'Assert-AgentRoadRestrictedFileAcl $journalTemp $phase',
    'Assert-AgentRoadFileBytes $journalTemp $journalBytes $phase',
    "$phase = 'BOOTSTRAP_PHASE_STATE_JOURNAL_REVALIDATE'",
    "Confirm-AgentRoadDirectory $stateParent 'STATE_PARENT'",
    "Confirm-AgentRoadDirectory $stateRoot 'STATE_ROOT'",
    'Confirm-AgentRoadFile $journalPath',
    "$phase = 'BOOTSTRAP_PHASE_STATE_JOURNAL_PUBLISH'",
    "if (Test-Path -LiteralPath $journalPath) { [IO.File]::Replace($journalTemp,$journalPath,[Management.Automation.Language.NullString]::Value,$true) } else { Move-Item -LiteralPath $journalTemp -Destination $journalPath -Force }",
    "$phase = 'BOOTSTRAP_PHASE_STATE_JOURNAL_ACL_MIGRATE'",
    'Set-AgentRoadRestrictedFileAcl $journalPath $phase',
    "$phase = 'BOOTSTRAP_PHASE_STATE_JOURNAL_FINAL_VERIFY'",
    'Assert-AgentRoadFileBytes $journalPath $journalBytes $phase',
    "$phase = 'BOOTSTRAP_PHASE_TAILSCALE'",
    "Write-Output 'Agent Road: preparing Tailscale'",
    "$tailscale = 'C:\\Program Files\\Tailscale\\tailscale.exe'",
    '$freshInstall = -not (Test-Path -LiteralPath $tailscale -PathType Leaf)',
    'if ($freshInstall) {',
    "$installer = Join-Path $tempRoot 'tailscale-installer.exe'",
    "Invoke-WebRequest -UseBasicParsing -Uri $payload.tailscaleInstallerUrl -OutFile $installer -MaximumRedirection 0 -TimeoutSec 120",
    "if ((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant() -cne $payload.tailscaleInstallerSha256) { Stop-AgentRoad 'TAILSCALE_DOWNLOAD_INVALID' }",
    '$installerSignature = Get-AuthenticodeSignature -FilePath $installer',
    "if ($installerSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or $null -eq $installerSignature.SignerCertificate -or $installerSignature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -cne $payload.tailscaleAuthenticodeSubject.Substring(3)) { Stop-AgentRoad 'TAILSCALE_DOWNLOAD_INVALID' }",
    "$install = Invoke-AgentRoadNative $installer @('/quiet','/norestart') 180 @(0,3010) 'TAILSCALE_DOWNLOAD_INVALID'",
    "if (-not (Test-Path -LiteralPath $tailscale -PathType Leaf)) { Stop-AgentRoad 'TAILSCALE_DOWNLOAD_INVALID' }",
    '}',
    '$tailscaleSignature = Get-AuthenticodeSignature -FilePath $tailscale',
    "if ($tailscaleSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or $null -eq $tailscaleSignature.SignerCertificate -or $tailscaleSignature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -cne $payload.tailscaleAuthenticodeSubject.Substring(3)) { Stop-AgentRoad 'TAILSCALE_DOWNLOAD_INVALID' }",
    "Write-Output 'Agent Road: waiting for Tailscale login'",
    '$status = Get-TailscaleStatus 10',
    "$running = $null -ne $status -and $status.BackendState -ceq 'Running' -and @($status.TailscaleIPs).Count -gt 0",
    'if (-not $running) {',
    ...(paired ? [
      "$pairAuthPath = Join-Path $tempRoot 'join-auth.key'",
      "$pairAuthStream = New-AgentRoadRestrictedFileStream $pairAuthPath 'TAILSCALE_LOGIN_REQUIRED'",
      "try { $pairAuthBytes = [Text.Encoding]::ASCII.GetBytes($payload.a); $pairAuthStream.Write($pairAuthBytes,0,$pairAuthBytes.Length); $pairAuthStream.Flush($true) } finally { $pairAuthStream.Dispose(); $pairAuthBytes = $null; $payload.a = $null }",
      "Assert-AgentRoadRestrictedFileAcl $pairAuthPath 'TAILSCALE_LOGIN_REQUIRED'",
      `$upArgs = @('up',('\"--auth-key=file:' + $pairAuthPath + '\"'),'--unattended=true','--timeout=300s'); if ($freshInstall) { $upArgs += '--hostname=${hostname}' }`,
      "$null = Invoke-AgentRoadNative $tailscale $upArgs 310 @(0) 'TAILSCALE_LOGIN_REQUIRED'",
      "if (-not (Remove-AgentRoadPath $pairAuthPath $false)) { Stop-AgentRoad 'BOOTSTRAP_CLEANUP_FAILED' }; $pairAuthPath = $null",
      '$status = Get-TailscaleStatus 10',
    ] : [
      "$loginStdout = Join-Path $tempRoot 'tailscale-login.out'",
      "$loginStderr = Join-Path $tempRoot 'tailscale-login.err'",
      `$upArgs = if ($freshInstall) { @('up','--hostname=${hostname}','--unattended=true','--timeout=300s') } else { @('up','--timeout=300s') }`,
      '$status = Invoke-AgentRoadLogin $tailscale $upArgs',
    ]),
    '}',
    "if ($null -eq $status -or $status.BackendState -cne 'Running' -or @($status.TailscaleIPs).Count -eq 0) { Stop-AgentRoad 'TAILSCALE_LOGIN_REQUIRED' }",
    "$setResult = Invoke-AgentRoadNative $tailscale @('set','--unattended=true') 30 @(0) 'TAILSCALE_LOGIN_REQUIRED'",
    "$phase = 'BOOTSTRAP_PHASE_EXCHANGE'",
    "$exchangeBody = '{\"protocolVersion\":1,\"deviceId\":\"' + $payload.deviceId + '\",\"token\":\"' + $payload.token + '\"}'",
    "$result = Invoke-RestMethod -Method Post -Uri ($payload.controllerBaseUrl + '/exchange') -ContentType 'application/json' -Body $exchangeBody -MaximumRedirection 0 -TimeoutSec 30",
    '$exchangeBody = $null',
    "if ($null -eq $result -or $result -is [Collections.IEnumerable] -or $result -isnot [pscustomobject]) { Stop-AgentRoad 'ENROLLMENT_TOKEN_INVALID' }",
    '$responseNames = @($result.PSObject.Properties.Name)',
    "$requiredNames = @('protocolVersion','deviceId','sshPublicKey','stageOneBase64','stageOneSha256','stageOneSignatureBase64','completionTicket')",
    "if (@($result.PSObject.Properties).Count -ne 7) { Stop-AgentRoad 'ENROLLMENT_TOKEN_INVALID' }",
    "foreach ($name in $requiredNames) { if ($responseNames -cnotcontains $name) { Stop-AgentRoad 'ENROLLMENT_TOKEN_INVALID' } }",
    "if ($result.protocolVersion -isnot [int] -or $result.protocolVersion -ne 1 -or $result.deviceId -isnot [string] -or $result.deviceId -cne $payload.deviceId -or $result.sshPublicKey -isnot [string] -or $result.sshPublicKey.Length -lt 1 -or $result.sshPublicKey.Length -gt 1024 -or $result.stageOneBase64 -isnot [string] -or $result.stageOneSha256 -isnot [string] -or $result.stageOneSha256 -cnotmatch '^[a-f0-9]{64}$' -or $result.stageOneSignatureBase64 -isnot [string] -or $result.completionTicket -isnot [string] -or $result.completionTicket -cnotmatch '^[A-Za-z0-9_-]{43}$') { Stop-AgentRoad 'ENROLLMENT_TOKEN_INVALID' }",
    '$completionTicketBytes = Convert-AgentRoadBase64Url $result.completionTicket 43',
    "if ($completionTicketBytes.Length -ne 32) { Stop-AgentRoad 'ENROLLMENT_TOKEN_INVALID' }",
    '$completionTicketBytes = $null',
    "$phase = 'BOOTSTRAP_PHASE_SIGNATURE'",
    "Write-Output 'Agent Road: verifying bootstrap'",
    "if ($result.stageOneBase64.Length -gt 1398104) { Stop-AgentRoad 'BOOTSTRAP_SIGNATURE_INVALID' }",
    '$stageOneBytes = Convert-AgentRoadBase64 $result.stageOneBase64 1398104',
    "if ($stageOneBytes.Length -lt 1 -or $stageOneBytes.Length -gt 1048576) { Stop-AgentRoad 'BOOTSTRAP_SIGNATURE_INVALID' }",
    '$hasher = [Security.Cryptography.SHA256]::Create()',
    "try { $actualHash = ([BitConverter]::ToString($hasher.ComputeHash($stageOneBytes))).Replace('-','').ToLowerInvariant() } finally { $hasher.Dispose() }",
    "if ($actualHash -cne $result.stageOneSha256) { Stop-AgentRoad 'BOOTSTRAP_SIGNATURE_INVALID' }",
    '$signatureBytes = Convert-AgentRoadBase64 $result.stageOneSignatureBase64 512',
    "if ($signatureBytes.Length -ne 384) { Stop-AgentRoad 'BOOTSTRAP_SIGNATURE_INVALID' }",
    '$rsaParameters = New-Object Security.Cryptography.RSAParameters',
    '$rsaParameters.Modulus = Convert-AgentRoadBase64Url $payload.signingModulusBase64Url 512',
    '$rsaParameters.Exponent = Convert-AgentRoadBase64Url $payload.signingExponentBase64Url 4',
    "if ($rsaParameters.Modulus.Length -ne 384 -or $rsaParameters.Exponent.Length -ne 3) { Stop-AgentRoad 'BOOTSTRAP_SIGNATURE_INVALID' }",
    '$rsa = New-Object Security.Cryptography.RSACryptoServiceProvider 3072',
    "try { $rsa.PersistKeyInCsp = $false; $rsa.ImportParameters($rsaParameters); if (-not $rsa.VerifyData($stageOneBytes, 'SHA256', $signatureBytes)) { Stop-AgentRoad 'BOOTSTRAP_SIGNATURE_INVALID' } } finally { $rsa.Dispose() }",
    "$stageOnePath = Join-Path $tempRoot 'bootstrap-stage-one.ps1'",
    '[IO.File]::WriteAllBytes($stageOnePath, $stageOneBytes)',
    "try { $stageOneText = (New-Object Text.UTF8Encoding($false,$true)).GetString($stageOneBytes) } catch { Stop-AgentRoad 'BOOTSTRAP_SIGNATURE_INVALID' }",
    '$configuration = [pscustomobject]@{ protocolVersion = 1; deviceId = $payload.deviceId; controllerBaseUrl = $payload.controllerBaseUrl; completionTicket = $result.completionTicket; sshPublicKey = $result.sshPublicKey }',
    '$payload.token = $null',
    "$phase = 'BOOTSTRAP_PHASE_STAGE_ONE'",
    "Write-Output 'Agent Road: configuring Windows'",
    '& ([ScriptBlock]::Create($stageOneText)) -Configuration $configuration',
    '$configuration.completionTicket = $null',
    '$completed = $true',
    '} catch {',
    "$known = @('ADMIN_REQUIRED','UNSUPPORTED_POWERSHELL','UNSUPPORTED_WINDOWS_BUILD','BOOTSTRAP_TEMP_INVALID','BOOTSTRAP_STATE_INVALID','BOOTSTRAP_ALREADY_RUNNING','TAILSCALE_DOWNLOAD_INVALID','TAILSCALE_LOGIN_REQUIRED','ENROLLMENT_TOKEN_INVALID','BOOTSTRAP_SIGNATURE_INVALID','NATIVE_PROCESS_FAILED','NATIVE_PROCESS_TIMEOUT','BOOTSTRAP_CLEANUP_FAILED')",
    "$diagnosticPattern = '^BOOTSTRAP_(TEMP|STATE_PARENT|STATE_ROOT)_(ACL_(APPLY_FAILED|PROTECTION_INVALID|OWNER_INVALID|RULE_COUNT_INVALID|RULE_INVALID|PRINCIPALS_INVALID)|PATH_INVALID|CREATE_FAILED)$'",
    "$phaseFailures = @('BOOTSTRAP_PHASE_PREFLIGHT_IDENTITY','BOOTSTRAP_PHASE_PREFLIGHT_OS','BOOTSTRAP_PHASE_TEMP_PATH','BOOTSTRAP_PHASE_TEMP_CREATE','BOOTSTRAP_PHASE_TEMP_ACL','BOOTSTRAP_PHASE_STATE_PARENT_PATH','BOOTSTRAP_PHASE_STATE_PARENT_ACL','BOOTSTRAP_PHASE_STATE_ROOT_PATH','BOOTSTRAP_PHASE_STATE_ROOT_ACL','BOOTSTRAP_PHASE_STATE_LOCK','BOOTSTRAP_PHASE_STATE_JOURNAL_VALIDATE','BOOTSTRAP_PHASE_STATE_JOURNAL_SERIALIZE','BOOTSTRAP_PHASE_STATE_JOURNAL_OPEN','BOOTSTRAP_PHASE_STATE_JOURNAL_WRITE','BOOTSTRAP_PHASE_STATE_JOURNAL_TEMP_VERIFY','BOOTSTRAP_PHASE_STATE_JOURNAL_REVALIDATE','BOOTSTRAP_PHASE_STATE_JOURNAL_PUBLISH','BOOTSTRAP_PHASE_STATE_JOURNAL_ACL_MIGRATE','BOOTSTRAP_PHASE_STATE_JOURNAL_FINAL_VERIFY','BOOTSTRAP_PHASE_TAILSCALE','BOOTSTRAP_PHASE_EXCHANGE','BOOTSTRAP_PHASE_SIGNATURE','BOOTSTRAP_PHASE_STAGE_ONE')",
    `$stageOneFailures = @(${stageOneFailures})`,
    "$stageOneRollbackFailures = @($stageOneFailures | ForEach-Object { $_ + ':ROLLBACK_INCOMPLETE' })",
    '$failureMessage = [string]$_.Exception.Message',
    "$primary = if ($known -ccontains $failureMessage -or $failureMessage -cmatch $diagnosticPattern -or $stageOneFailures -ccontains $failureMessage -or $stageOneRollbackFailures -ccontains $failureMessage) { $failureMessage } elseif ($phaseFailures -ccontains $phase) { $phase } else { 'BOOTSTRAP_FAILED' }",
    '} finally {',
    ...(paired ? [
      'try { $payload.a = $null } catch { $cleanupFailed = $true }',
      'if (-not (Remove-AgentRoadPath $pairAuthPath $false)) { $cleanupFailed = $true }',
    ] : []),
    'try { $payload.token = $null } catch { $cleanupFailed = $true }',
    'if (-not (Stop-TailscaleLogin)) { $cleanupFailed = $true }',
    'if ($null -ne $bootstrapLock) { try { $bootstrapLock.Dispose() } catch { $cleanupFailed = $true }; $bootstrapLock = $null }',
    'foreach ($cleanupPath in @($loginStdout,$loginStderr,$stageOnePath,$journalTemp,$installer)) { if (-not (Remove-AgentRoadPath $cleanupPath $false)) { $cleanupFailed = $true } }',
    'if (-not (Remove-AgentRoadPath $lockPath $false)) { $cleanupFailed = $true }',
    'if (-not (Remove-AgentRoadPath $tempRoot $true)) { $cleanupFailed = $true }',
    '}',
    'if ($null -ne $primary) { [Console]::Error.WriteLine($primary);exit 1 } elseif ($cleanupFailed) { [Console]::Error.WriteLine(\'BOOTSTRAP_CLEANUP_FAILED\');exit 1 } elseif ($completed) { Write-Output \'AGENT_ROAD_STAGE_ZERO_COMPLETE\' }',
  ].join('\n');
  return script
    .replaceAll('New-AgentRoadRestrictedDirectorySecurity', 'DirSec')
    .replaceAll('New-AgentRoadRestrictedFileSecurity', 'FileSec')
    .replaceAll('Assert-AgentRoadRestrictedFileAcl', 'FileAcl')
    .replaceAll('Set-AgentRoadRestrictedFileAcl', 'SetFileAcl')
    .replaceAll('New-AgentRoadRestrictedFileStream', 'NewFile')
    .replaceAll('Assert-AgentRoadFileBytes', 'FileBytes')
    .replaceAll('Convert-AgentRoadBase64Url', 'B64u')
    .replaceAll('Convert-AgentRoadBase64', 'B64')
    .replaceAll('Stop-AgentRoad', 'Fail')
    .replaceAll('Get-TailscaleStatus', 'TS')
    .replaceAll('Confirm-AgentRoadDirectory', 'ARDir')
    .replaceAll('Set-AgentRoadAcl', 'Acl')
    .replaceAll('Confirm-AgentRoadFile', 'File')
    .replaceAll('Remove-AgentRoadPath', 'Clean')
    .replaceAll('Read-AgentRoadBounded', 'ReadBounded')
    .replaceAll('Invoke-AgentRoadNative', 'Run')
    .replaceAll('Invoke-AgentRoadLogin', 'Login')
    .replaceAll('Stop-TailscaleLogin', 'StopLogin')
    .replaceAll('$completionTicketBytes', '$ct')
    .replaceAll('$rsaParameters', '$rp')
    .replaceAll('$signatureBytes', '$sigBytes')
    .replaceAll('$tailscaleSignature', '$tsSig')
    .replaceAll('$installerSignature', '$inSig')
    .replaceAll('$operatingSystem', '$os')
    .replaceAll('$responseNames', '$names')
    .replaceAll('$requiredNames', '$required')
    .replaceAll('$script:loginProcess', '$script:lp')
    .replaceAll('$loginOutput', '$lo')
    .replaceAll('$loginLength', '$ll')
    .replaceAll('$loginPath', '$lpath')
    .replaceAll('$loginOpened', '$opened')
    .replaceAll('$loginMatch', '$lm')
    .replaceAll('$loginStdout', '$lout')
    .replaceAll('$loginStderr', '$lerr')
    .replaceAll('$deadline', '$dl')
    .replaceAll('$payload.controllerBaseUrl', '$payload.u')
    .replaceAll('$payload.deviceId', '$payload.d')
    .replaceAll('$payload.token', '$payload.t')
    .replaceAll('$payload.signingModulusBase64Url', '$payload.n')
    .replaceAll('$payload.signingExponentBase64Url', '$payload.e')
    .replaceAll('$payload.tailscaleInstallerUrl', '$payload.i')
    .replaceAll('$payload.tailscaleInstallerSha256', '$payload.h')
    .replaceAll('$payload.tailscaleAuthenticodeSubject', '$payload.s')
    .replaceAll('$payloadEncoded', '$pe')
    .replaceAll('$payloadJson', '$pj')
    .replaceAll('$payload', '$x')
    .replaceAll('$tempRoot', '$tmp')
    .replaceAll('$bootstrapLock', '$lock')
    .replaceAll('$lockPath', '$lockFile')
    .replaceAll('$journalTemp', '$jt')
    .replaceAll('$journalPath', '$jp')
    .replaceAll('$journalBytes', '$jb')
    .replaceAll('$journalStream', '$js')
    .replaceAll('$stateParent', '$parent')
    .replaceAll('$stateRoot', '$root')
    .replaceAll('$freshInstall', '$fresh')
    .replaceAll('$exchangeBody', '$body')
    .replaceAll('$stageOnePath', '$sp')
    .replaceAll('$stageOneBytes', '$sb')
    .replaceAll('$stageOneText', '$st')
    .replaceAll('$configuration', '$cfg')
    .replaceAll('$actualHash', '$digest')
    .replaceAll('$hasher', '$sha')
    .replaceAll('$principal', '$pr')
    .replaceAll('$cleanupFailed', '$cf')
    .replaceAll('$completed', '$done')
    .replaceAll('$cleanupPath', '$cp')
    .replaceAll('$directorySecurity', '$ds')
    .replaceAll('$ownerAccount', '$own')
    .replaceAll('$fileSecurity', '$fs')
    .replaceAll('$actualOwner', '$ao')
    .replaceAll('$expectedBytes', '$eb')
    .replaceAll('$actualBytes', '$ab')
    .replaceAll('$maximum', '$max')
    .replaceAll('$canonical', '$can')
    .replaceAll('$encoded', '$enc')
    .replaceAll('$process', '$proc')
    .replaceAll('$failureMessage', '$msg')
    .replaceAll('$failure', '$why')
    .replaceAll('$accepted', '$codes')
    .replaceAll('$seconds', '$secs')
    .replaceAll('$length', '$len')
    .replaceAll('$timer', '$sw')
    .replaceAll('$cleanup', '$bad')
    .replaceAll('$text', '$tx')
    .replaceAll('$exit', '$ex')
    .replaceAll('$system', '$sys')
    .replaceAll('$admins', '$adm')
    .replaceAll('$inherit', '$inh')
    .replaceAll('$verify', '$va')
    .replaceAll('$rules', '$rs')
    .replaceAll('$rule', '$r')
    .replaceAll('$path', '$p')
    .replaceAll('\n', ';')
    .replaceAll(' = ', '=')
    .replaceAll('; ', ';')
    .replaceAll(', ', ',')
    .replaceAll('if (', 'if(')
    .replaceAll('for (', 'for(')
    .replaceAll('foreach (', 'foreach(')
    .replaceAll('try {', 'try{')
    .replaceAll('catch {', 'catch{')
    .replaceAll('finally {', 'finally{')
    .replaceAll(') {', '){')
    .replaceAll('} else {', '}else{')
    .replaceAll('{;', '{')
    .replaceAll(';;', ';')
    .replaceAll(';}','}');
}

function wrapCompressedScript(script) {
  const gzipBase64 = gzipSync(Buffer.from(script, 'utf8'), { level: 9 }).toString('base64');
  return `$g='${gzipBase64}';$m=New-Object IO.MemoryStream(,[Convert]::FromBase64String($g));$z=New-Object IO.Compression.GZipStream($m,[IO.Compression.CompressionMode]::Decompress);$r=New-Object IO.StreamReader($z);try{&([ScriptBlock]::Create($r.ReadToEnd()))}finally{$r.Dispose();$z.Dispose();$m.Dispose()}`;
}

function buildStageZeroCommand(options, authKey) {
  requirePlainObject(options, 'stage-zero options');
  if (!hasExactKeys(options, OPTION_KEYS)) invalid('invalid stage-zero options');

  const controllerBaseUrlValue = options.controllerBaseUrl;
  const deviceId = options.deviceId;
  const token = options.token;
  const signingPublicKeyValue = options.signingPublicKey;
  const releaseManifestValue = options.releaseManifest;

  if (typeof deviceId !== 'string' || deviceId.length > 64 || !DEVICE_ID_PATTERN.test(deviceId)) {
    invalid('invalid device id');
  }
  const tokenBytes = decodeCanonicalBase64Url(token);
  if (!TOKEN_PATTERN.test(token ?? '') || !tokenBytes || tokenBytes.length !== 32) {
    invalid('invalid enrollment token');
  }

  const controllerBaseUrl = validateControllerBaseUrl(controllerBaseUrlValue, deviceId);
  const publicKey = snapshotPublicKey(signingPublicKeyValue);
  const release = snapshotManifest(releaseManifestValue);
  const payload = {
    u: controllerBaseUrl,
    d: deviceId,
    t: token,
    n: publicKey.modulusBase64Url,
    e: publicKey.exponentBase64Url,
    i: release.url,
    h: release.sha256,
    s: release.authenticodeSubject,
  };
  if (authKey !== undefined) payload.a = authKey;
  const payloadBase64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  const script = buildScript(payloadBase64, `agent-road-${deviceId.slice(4, 56)}`, authKey !== undefined);
  return encodePowerShellCommand(wrapCompressedScript(script));
}

export function buildWindowsStageZeroCommand(options) {
  return buildStageZeroCommand(options);
}

export function buildWindowsPairedStageZeroCommand(options, authKey) {
  if (typeof authKey !== 'string' || !/^tskey-auth-[A-Za-z0-9_-]{10,500}$/.test(authKey)) {
    invalid('invalid one-off Tailscale auth key');
  }
  return buildStageZeroCommand(options, authKey);
}
