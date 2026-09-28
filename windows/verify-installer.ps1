param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$ExpectedSignerThumbprint
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
# Read-only release gate. Never execute the artifact or modify trust/security settings.
$result = @{schemaVersion=1; ready=$false; code='INSTALLER_INSPECTION_FAILED'}
try {
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':')) { throw 'INSTALLER_PATH_INVALID' }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'INSTALLER_PATH_INVALID' }
    if ($item.Extension -notin @('.exe','.msi','.ps1')) { throw 'INSTALLER_TYPE_INVALID' }
    $digest = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($digest -cne $ExpectedSha256.ToUpperInvariant()) { throw 'INSTALLER_HASH_MISMATCH' }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) { throw 'INSTALLER_SIGNATURE_NOT_TRUSTED' }
    if ($null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -cne $ExpectedSignerThumbprint.ToUpperInvariant()) { throw 'INSTALLER_SIGNER_MISMATCH' }
    $result.ready = $true
    $result.code = 'INSTALLER_IDENTITY_VERIFIED'
    $result.sha256 = $digest
    $result.signerThumbprint = $signature.SignerCertificate.Thumbprint
} catch {
    $known = @('INSTALLER_PATH_INVALID','INSTALLER_TYPE_INVALID','INSTALLER_HASH_MISMATCH','INSTALLER_SIGNATURE_NOT_TRUSTED','INSTALLER_SIGNER_MISMATCH')
    if ($_.Exception.Message -cin $known) { $result.code = $_.Exception.Message }
}
$result | ConvertTo-Json -Compress
if (-not $result.ready) { exit 2 }
