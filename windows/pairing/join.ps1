# Served by the configured HTTPS pairing service; no device secret in the pasted command.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$pairOrigin = '__PAIR_ORIGIN__'
$pairPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $pairPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'PAIR_ADMIN_REQUIRED' }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$pairCode = '__PAIR_CODE__'
if ([string]::IsNullOrEmpty($pairCode)) { $pairCode = Read-Host 'Agent Road pairing code' }
$pairCode = $pairCode.ToUpperInvariant().Replace('-', '')
if ($pairCode -cnotmatch '^[A-HJ-NP-Z2-9]{12}$') { throw 'PAIR_INPUT_INVALID' }
Write-Host 'Agent Road will install remote access components (Tailscale and OpenSSH) and its private runtime.'
Write-Host 'The approved controller will be able to run commands and transfer files on this computer.'
Write-Host 'Only continue for a controller you trust. Compare the verification code before approving on the Mac.'
if ((Read-Host 'Type YES to allow this computer to join').Trim() -cne 'YES') { throw 'PAIR_CONSENT_DECLINED' }
$pairBytes = New-Object byte[] 32
$pairRandom = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $pairRandom.GetBytes($pairBytes) } finally { $pairRandom.Dispose() }
$pairToken = [Convert]::ToBase64String($pairBytes).TrimEnd('=').Replace('+','-').Replace('/','_')
$pairBytes = $null
function Invoke-AgentRoadPair([string]$action) {
    $pairBody = @{code=$pairCode;clientToken=$pairToken} | ConvertTo-Json -Compress
    try { return Invoke-RestMethod -Method Post -Uri ($pairOrigin + '/v1/' + $action) -ContentType 'application/json' -Body $pairBody -MaximumRedirection 0 -TimeoutSec 20 }
    catch { throw 'PAIR_REQUEST_FAILED_DO_NOT_REPLAY' }
    finally { $pairBody = $null }
}
try {
    $pairClaim = Invoke-AgentRoadPair 'claim'
    if ($pairClaim.state -cne 'CLAIMED' -or [string]$pairClaim.verification -cnotmatch '^[0-9]{8}$') { throw 'PAIR_RESPONSE_INVALID' }
    Write-Host ('Verify this code on your Mac: ' + $pairClaim.verification)
    Write-Host 'Waiting for approval. Keep this window open.'
    $pairTimer = [Diagnostics.Stopwatch]::StartNew()
    $pairCommand = $null
    while ($pairTimer.Elapsed.TotalSeconds -lt 600) {
        $pairResponse = Invoke-AgentRoadPair 'receive'
        if ($pairResponse.state -ceq 'DELIVERED') { $pairCommand = [string]$pairResponse.command; break }
        if ($pairResponse.state -cne 'PENDING') { throw 'PAIR_RESPONSE_INVALID' }
        Start-Sleep -Seconds 3
    }
    if ([string]::IsNullOrEmpty($pairCommand)) { throw 'PAIR_EXPIRED' }
    $pairPrefix = 'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '
    if ($pairCommand.Length -gt 32767 -or -not $pairCommand.StartsWith($pairPrefix, [StringComparison]::Ordinal)) { throw 'PAIR_BOOTSTRAP_INVALID' }
    $pairEncoded = $pairCommand.Substring($pairPrefix.Length)
    if ($pairEncoded -cnotmatch '^[A-Za-z0-9+/]+={0,2}$') { throw 'PAIR_BOOTSTRAP_INVALID' }
    # Exactly one invocation. A lost/failed execution must be reconciled, not replayed.
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $pairEncoded
    if ($LASTEXITCODE -ne 0) { throw 'PAIR_BOOTSTRAP_FAILED_DO_NOT_REPLAY' }
} finally {
    $pairToken = $null; $pairCommand = $null; $pairEncoded = $null; $pairResponse = $null
}
