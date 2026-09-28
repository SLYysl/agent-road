#requires -Version 5.1
param([switch]$PlanningObservation)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:Phases = @(
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
 'reconcile'
)
$script:ForwardPhases = @($script:Phases[0..8])
$script:Changes = @(
 'work-created',
 'generation-publish-planned',
 'previous-replace-planned',
 'active-replace-planned'
)
$script:PointerFields = @(
 'schemaVersion',
 'receiptFormatRevision',
 'manifestDigest',
 'generationDigest',
 'catalogRevision',
 'catalogDigest',
 'receiptBytes',
 'receiptSha256'
)
$script:ReceiptFields = @(
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
 'restartRequired'
)
$script:ReceiptComponentFields = @(
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
 'verified'
)
$script:ReceiptFileFields = @(
 'path',
 'bytes',
 'sha256'
)
$script:JournalFields = @(
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
 'rollbackStatus'
)
$script:JournalSnapshotFields = @(
 'active',
 'previous'
)
$script:CapsuleFields = @(
 'schemaVersion',
 'manifestJson',
 'manifestDigest',
 'generationDigest',
 'signatureAlgorithm',
 'signatureBase64',
 'controllerKeyId',
 'controllerPublicKeyJson'
)
$script:ManifestFields = @(
 'schemaVersion',
 'deviceId',
 'operationId',
 'createdAt',
 'platform',
 'catalogRevision',
 'catalogDigest',
 'inventoryDigest',
 'requestedProfiles',
 'profiles',
 'acquisition',
 'generationDigest',
 'phases',
 'components'
)
$script:ManifestPlatformFields = @(
 'os',
 'version',
 'build',
 'edition',
 'architecture',
 'windowsPowerShellVersion',
 'elevated'
)
$script:ManifestComponentFields = @(
 'id',
 'version',
 'bytes',
 'maximumExpandedBytes',
 'sha256',
 'packaging',
 'signerRule',
 'verificationCommandId'
)
$script:PublicKeyFields = @(
 'algorithm',
 'modulusBase64Url',
 'exponentBase64Url'
)
$script:BootstrapJournalFields = @(
 'phase',
 'schemaVersion',
 'checkpoints',
 'updatedAt',
 'deviceId'
)
$script:CoreComponentId = 'powershell-7'
$script:FailureCodes = @(
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
 'RUNTIME_INTERNAL_ERROR'
)
$script:Utf8 = New-Object Text.UTF8Encoding($false, $true)
$script:AgentRoadRoot = 'C:\ProgramData\AgentRoad'
$script:BootstrapRoot = [IO.Path]::Combine($script:AgentRoadRoot, 'bootstrap')
$script:BootstrapJournalPath = [IO.Path]::Combine($script:BootstrapRoot, 'stage-zero-journal.json')
$script:RuntimeRoot = [IO.Path]::Combine($script:AgentRoadRoot, 'runtime')
$script:TrustRoot = [IO.Path]::Combine($script:RuntimeRoot, 'trust')
$script:TrustKeyPath = [IO.Path]::Combine($script:TrustRoot, 'controller-key.json')
$script:StagingRoot = [IO.Path]::Combine($script:RuntimeRoot, 'staging')
$script:VersionsRoot = [IO.Path]::Combine($script:RuntimeRoot, 'versions')
$script:StateRoot = [IO.Path]::Combine($script:RuntimeRoot, 'state')
$script:JournalPath = [IO.Path]::Combine($script:StateRoot, 'journal.json')
$script:ActivePath = [IO.Path]::Combine($script:StateRoot, 'active.json')
$script:PreviousPath = [IO.Path]::Combine($script:StateRoot, 'previous.json')
$script:PinnedKeyId = $null
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace AgentRoadInventory {
 [StructLayout(LayoutKind.Sequential)]
 public struct FileInformation {
 public uint FileAttributes;
 public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
 public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
 public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
 public uint VolumeSerialNumber;
 public uint FileSizeHigh;
 public uint FileSizeLow;
 public uint NumberOfLinks;
 public uint FileIndexHigh;
 public uint FileIndexLow;
 }
 public static class NativeMethods {
 [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
 public static extern SafeFileHandle CreateFile(
  string name, uint access, uint share, IntPtr security,
  uint disposition, uint flags, IntPtr template);
 [DllImport("kernel32.dll", SetLastError = true)]
 [return: MarshalAs(UnmanagedType.Bool)]
 public static extern bool GetFileInformationByHandle(
  SafeFileHandle handle, out FileInformation information);
 }
}
'@
function Assert-AgentRoadExactOrderedRecord {
 param(
 [Parameter(Mandatory = $true)]
 [object]$Value,
 [Parameter(Mandatory = $true)]
 [string[]]$Fields
 )
 if ($null -eq $Value -or $Value -isnot [pscustomobject]) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 $names = @($Value.PSObject.Properties.Name)
 if ($names.Count -ne $Fields.Count) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 for ($index = 0; $index -lt $Fields.Count; $index += 1) {
 if ([string]::CompareOrdinal([string]$names[$index], [string]$Fields[$index]) -ne 0) {
  throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 }
}
function ConvertFrom-AgentRoadCanonicalJson {
 param(
 [Parameter(Mandatory = $true)]
 [byte[]]$Bytes,
 [Parameter(Mandatory = $true)]
 [int]$MaximumBytes
 )
 if ($Bytes.Length -lt 2 -or $Bytes.Length -gt $MaximumBytes) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 try {
 $json = $script:Utf8.GetString($Bytes)
 if ($json.IndexOf([char]0) -ge 0 -or $json.Contains("`r") -or $json.Contains("`n")) {
  throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 return $json | ConvertFrom-Json -ErrorAction Stop
 } catch {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
}
function Get-AgentRoadBytesSha256 {
 param(
 [Parameter(Mandatory = $true)]
 [byte[]]$Bytes
 )
 $hash = [Security.Cryptography.SHA256]::Create()
 try {
 return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '')
 } finally {
 $hash.Dispose()
 }
}
function Get-AgentRoadSha256 {
 param(
 [Parameter(Mandatory = $true)]
 [string]$Path
 )
 return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
}
function Get-AgentRoadFileLinkCount {
 param(
 [Parameter(Mandatory = $true)]
 [string]$Path
 )
 $handle = [AgentRoadInventory.NativeMethods]::CreateFile(
 $Path,
 0x80,
 0x1,
 [IntPtr]::Zero,
 3,
 0x00200000,
 [IntPtr]::Zero
 )
 if ($handle.IsInvalid) {
 $handle.Dispose()
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 try {
 $information = New-Object AgentRoadInventory.FileInformation
 if (-not [AgentRoadInventory.NativeMethods]::GetFileInformationByHandle($handle, [ref]$information)) {
  throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 if ($information.NumberOfLinks -ne 1) {
  throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 return [uint32]$information.NumberOfLinks
 } finally {
 $handle.Dispose()
 }
}
function Assert-AgentRoadRestrictedAcl {
 param([Parameter(Mandatory=$true)][string]$Path,[Parameter(Mandatory=$true)][bool]$Directory)
 $e='RUNTIME_STATE_UNSUPPORTED'
 try{
 $acl=if($Directory){[IO.Directory]::GetAccessControl($Path)}else{[IO.File]::GetAccessControl($Path)}
 $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
 $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
 if(-not $acl.AreAccessRulesProtected -or -not $acl.AreAccessRulesCanonical -or $owner -cne 'S-1-5-32-544' -or $rules.Count -ne 2) { throw $e }
 $seen=@()
 $directoryInheritance=([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit)
 foreach($rule in $rules){
 $sid=[string]$rule.IdentityReference.Value
 $expectedInheritance=if($Directory){$directoryInheritance} else {[Security.AccessControl.InheritanceFlags]::None}
 if($rule.IsInherited -or $sid -cnotin @('S-1-5-18','S-1-5-32-544') -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $rule.InheritanceFlags -ne $expectedInheritance -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { throw $e }
 $seen+=$sid
 }
 if($seen -cnotcontains 'S-1-5-18' -or $seen -cnotcontains 'S-1-5-32-544') { throw $e }
 } catch { if ([string]$_.Exception.Message -ceq $e) { throw };throw $e }
}
function Assert-AgentRoadDirectoryNode {
 param(
 [Parameter(Mandatory = $true)]
 [string]$Path
 )
 if ([IO.Path]::GetFullPath($Path) -cne $Path -or -not (Test-Path -LiteralPath $Path -PathType Container)) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 $item = Get-Item -LiteralPath $Path -Force
 if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 Assert-AgentRoadRestrictedAcl $Path $true
}
function Assert-AgentRoadFileNode {
 param(
 [Parameter(Mandatory = $true)]
 [string]$Path,
 [long]$ExpectedBytes = -1,
 [string]$ExpectedSha256 = $null
 )
 if ([IO.Path]::GetFullPath($Path) -cne $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 $item = Get-Item -LiteralPath $Path -Force
 if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 Assert-AgentRoadRestrictedAcl $Path $false
 Get-AgentRoadFileLinkCount $Path | Out-Null
 if ($ExpectedBytes -ge 0 -and [long]$item.Length -ne $ExpectedBytes) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 if ($PSBoundParameters.ContainsKey('ExpectedSha256') -and (Get-AgentRoadSha256 $Path) -cne $ExpectedSha256) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
}
function Assert-AgentRoadTemporaryFileNode {
 param(
 [Parameter(Mandatory = $true)]
 [string]$Path,
 [Parameter(Mandatory = $true)]
 [long]$MaximumBytes
 )
 if ([IO.Path]::GetFullPath($Path) -cne $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 $item = Get-Item -LiteralPath $Path -Force
 if (
 $item.PSIsContainer -or
 ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
 [long]$item.Length -gt $MaximumBytes
 ) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 Get-AgentRoadFileLinkCount $Path | Out-Null
 $acl = [IO.File]::GetAccessControl($Path)
 $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
 $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
 $current = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 if (-not $acl.AreAccessRulesCanonical -or $owner -cnotin @($current, 'S-1-5-32-544') -or $rules.Count -ne 2) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 $seen = @()
 foreach ($rule in $rules) {
 $sid = [string]$rule.IdentityReference.Value
 if (
  $sid -cnotin @('S-1-5-18', 'S-1-5-32-544') -or
  $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
  $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl
 ) {
  throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 $seen += $sid
 }
 if ($seen -cnotcontains 'S-1-5-18' -or $seen -cnotcontains 'S-1-5-32-544') {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
}
function Get-AgentRoadDirectChildren {
 param([Parameter(Mandatory=$true)][string]$Path,[int]$MaximumCount=32)
 $e='RUNTIME_STATE_UNSUPPORTED'
 Assert-AgentRoadDirectoryNode $Path
 $items=New-Object Collections.Generic.List[object]
 try {
 foreach ($childPath in [IO.Directory]::EnumerateFileSystemEntries($Path)) {
  if ($items.Count -ge $MaximumCount) { throw $e }
  if ([IO.Path]::GetDirectoryName($childPath) -cne $Path) { throw $e }
  $items.Add((Get-Item -LiteralPath $childPath -Force -ErrorAction Stop))
 }
 } catch { if ([string]$_.Exception.Message -ceq $e) { throw };throw $e }
 return $items.ToArray()
}
function Get-AgentRoadBoundedTree {
 param(
 [Parameter(Mandatory = $true)]
 [string]$Root,
 [int]$MaximumCount = 8224
 )
 Assert-AgentRoadDirectoryNode $Root
 $queue = New-Object 'Collections.Generic.Queue[string]'
 $nodes = New-Object Collections.Generic.List[object]
 $queue.Enqueue($Root)
 while ($queue.Count -gt 0) {
 $parent = $queue.Dequeue()
 foreach ($childPath in [IO.Directory]::EnumerateFileSystemEntries($parent)) {
  if ($nodes.Count -ge $MaximumCount -or [IO.Path]::GetDirectoryName($childPath) -cne $parent) {
  throw 'RUNTIME_STATE_UNSUPPORTED'
  }
  $item = Get-Item -LiteralPath $childPath -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
  throw 'RUNTIME_STATE_UNSUPPORTED'
  }
  if ($item.PSIsContainer) {
  Assert-AgentRoadDirectoryNode $item.FullName
  $queue.Enqueue($item.FullName)
  } else {
  Assert-AgentRoadFileNode $item.FullName
  }
  $nodes.Add($item)
 }
 }
 return $nodes.ToArray()
}
function Read-AgentRoadJsonFile {
 param(
 [Parameter(Mandatory = $true)]
 [string]$Path,
 [Parameter(Mandatory = $true)]
 [int]$MaximumBytes
 )
 Assert-AgentRoadFileNode $Path
 $bytes = [IO.File]::ReadAllBytes($Path)
 $value = ConvertFrom-AgentRoadCanonicalJson $bytes $MaximumBytes
 if (($value | ConvertTo-Json -Depth 12 -Compress) -cne $script:Utf8.GetString($bytes)) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 return [pscustomobject]@{
 bytes = $bytes
 json = $script:Utf8.GetString($bytes)
 value = $value
 }
}
function Assert-AgentRoadPointer {
 param(
 [Parameter(Mandatory = $true)]
 [pscustomobject]$Pointer
 )
 Assert-AgentRoadExactOrderedRecord $Pointer $script:PointerFields
 if (
 $Pointer.schemaVersion -isnot [int] -or $Pointer.schemaVersion -ne 1 -or
 $Pointer.receiptFormatRevision -isnot [int] -or $Pointer.receiptFormatRevision -ne 1 -or
 $Pointer.manifestDigest -isnot [string] -or $Pointer.manifestDigest -cnotmatch '^[A-F0-9]{64}$' -or
 $Pointer.generationDigest -isnot [string] -or $Pointer.generationDigest -cnotmatch '^[A-F0-9]{64}$' -or
 $Pointer.catalogRevision -isnot [int] -or $Pointer.catalogRevision -lt 1 -or
 $Pointer.catalogDigest -isnot [string] -or $Pointer.catalogDigest -cnotmatch '^[A-F0-9]{64}$' -or
 $Pointer.receiptBytes -isnot [int] -or $Pointer.receiptBytes -lt 1 -or $Pointer.receiptBytes -gt 32768 -or
 $Pointer.receiptSha256 -isnot [string] -or $Pointer.receiptSha256 -cnotmatch '^[A-F0-9]{64}$'
 ) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
}
function Test-AgentRoadPointerValue {
 param(
 [object]$Left,
 [object]$Right
 )
 if ($null -eq $Left -or $null -eq $Right) {
 return ($null -eq $Left -and $null -eq $Right)
 }
 Assert-AgentRoadPointer $Left
 Assert-AgentRoadPointer $Right
 return (($Left | ConvertTo-Json -Compress) -ceq ($Right | ConvertTo-Json -Compress))
}
function Assert-AgentRoadReceipt {
 param(
 [Parameter(Mandatory = $true)]
 [pscustomobject]$Receipt
 )
 Assert-AgentRoadExactOrderedRecord $Receipt $script:ReceiptFields
 if (
 $Receipt.schemaVersion -isnot [int] -or $Receipt.schemaVersion -ne 1 -or
 $Receipt.receiptFormatRevision -isnot [int] -or $Receipt.receiptFormatRevision -ne 1 -or
 $Receipt.operationId -isnot [string] -or $Receipt.operationId -cnotmatch '^[a-f0-9]{32}$' -or
 $Receipt.manifestDigest -isnot [string] -or $Receipt.manifestDigest -cnotmatch '^[A-F0-9]{64}$' -or
 $Receipt.generationDigest -isnot [string] -or $Receipt.generationDigest -cnotmatch '^[A-F0-9]{64}$' -or
 $Receipt.catalogRevision -isnot [int] -or $Receipt.catalogRevision -lt 1 -or
 $Receipt.catalogDigest -isnot [string] -or $Receipt.catalogDigest -cnotmatch '^[A-F0-9]{64}$' -or
 $Receipt.controllerKeyId -isnot [string] -or $Receipt.controllerKeyId -cnotmatch '^[A-F0-9]{64}$' -or
 $Receipt.profiles -isnot [Array] -or @($Receipt.profiles).Count -ne 1 -or
 [string]$Receipt.profiles[0] -cne 'core' -or
 $Receipt.components -isnot [Array] -or @($Receipt.components).Count -ne 1 -or
 $Receipt.files -isnot [Array] -or
 $Receipt.restartRequired -isnot [bool] -or $Receipt.restartRequired
 ) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 $component = $Receipt.components[0]
 Assert-AgentRoadExactOrderedRecord $component $script:ReceiptComponentFields
 if (
 $component.id -cne 'powershell-7' -or
 $component.version -isnot [string] -or $component.version -cnotmatch '^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$' -or
 $component.bytes -isnot [int] -or $component.bytes -lt 1 -or $component.bytes -gt 268435456 -or
 $component.sha256 -isnot [string] -or $component.sha256 -cnotmatch '^[A-F0-9]{64}$' -or
 $component.installRoot -cne 'tools/powershell-7' -or
 $component.fileCount -isnot [int] -or $component.fileCount -lt 1 -or $component.fileCount -gt 8192 -or
 $component.directoryCount -isnot [int] -or $component.directoryCount -lt 0 -or $component.directoryCount -gt 8192 -or
 (($component.expandedBytes -isnot [int]) -and ($component.expandedBytes -isnot [long])) -or
 [long]$component.expandedBytes -lt 1 -or [long]$component.expandedBytes -gt 34359738368 -or
 $component.treeSha256 -isnot [string] -or $component.treeSha256 -cnotmatch '^[A-F0-9]{64}$' -or
 $component.verificationCommandId -cne 'powershell-json-roundtrip' -or
 $component.verified -isnot [bool] -or -not $component.verified
 ) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 $requiredFiles = @(
 'bin/pwsh.cmd',
 'capsule.json',
 'env.cmd',
 'env.ps1',
 'scripts/runtime-inventory.ps1',
 'scripts/runtime-provision-core.ps1'
 )
 $files = @($Receipt.files)
 if ($files.Count -ne $requiredFiles.Count) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 for ($index = 0; $index -lt $files.Count; $index += 1) {
 $file = $files[$index]
 Assert-AgentRoadExactOrderedRecord $file $script:ReceiptFileFields
 if (
  $file.path -isnot [string] -or $file.path -cne $requiredFiles[$index] -or
  $file.bytes -isnot [int] -or $file.bytes -lt 1 -or
  $file.sha256 -isnot [string] -or $file.sha256 -cnotmatch '^[A-F0-9]{64}$'
 ) {
  throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 }
}
function Assert-AgentRoadJournal {
 param(
 [Parameter(Mandatory = $true)]
 [pscustomobject]$Journal
 )
 Assert-AgentRoadExactOrderedRecord $Journal $script:JournalFields
 Assert-AgentRoadExactOrderedRecord $Journal.snapshot $script:JournalSnapshotFields
 if (
 $Journal.schemaVersion -isnot [int] -or $Journal.schemaVersion -ne 1 -or
 $Journal.revision -isnot [int] -or $Journal.revision -lt 1 -or
 $Journal.operationId -isnot [string] -or $Journal.operationId -cnotmatch '^[a-f0-9]{32}$' -or
 $Journal.manifestDigest -isnot [string] -or $Journal.manifestDigest -cnotmatch '^[A-F0-9]{64}$' -or
 $Journal.generationDigest -isnot [string] -or $Journal.generationDigest -cnotmatch '^[A-F0-9]{64}$' -or
 $Journal.catalogDigest -isnot [string] -or $Journal.catalogDigest -cnotmatch '^[A-F0-9]{64}$' -or
 $Journal.inventoryDigest -isnot [string] -or $Journal.inventoryDigest -cnotmatch '^[A-F0-9]{64}$' -or
 $Journal.controllerKeyId -isnot [string] -or $Journal.controllerKeyId -cnotmatch '^[A-F0-9]{64}$' -or
 $Journal.status -cnotin @('running', 'uncertain', 'failed', 'rolled-back', 'committed') -or
 $Journal.phase -cnotin $script:Phases -or
 $Journal.restartRequired -isnot [bool] -or $Journal.restartRequired -or
 $Journal.rollbackStatus -cnotin @('not-attempted', 'pending', 'succeeded', 'failed') -or
 $Journal.requestedProfiles -isnot [Array] -or @($Journal.requestedProfiles).Count -gt 1 -or
 $Journal.completedPhases -isnot [Array] -or
 $Journal.changes -isnot [Array]
 ) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 if (@($Journal.requestedProfiles).Count -eq 1 -and [string]$Journal.requestedProfiles[0] -cne 'core') {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 $completed = @($Journal.completedPhases)
 if ($completed.Count -gt $script:ForwardPhases.Count) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 for ($index = 0; $index -lt $completed.Count; $index += 1) {
 if ([string]$completed[$index] -cne [string]$script:ForwardPhases[$index]) {
  throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 }
 if ($Journal.phase -cnotin @('rollback', 'reconcile')) {
 if (
  ($completed.Count -lt $script:ForwardPhases.Count -and $Journal.phase -cne $script:ForwardPhases[$completed.Count]) -or
  ($completed.Count -eq $script:ForwardPhases.Count -and $Journal.phase -cne 'commit')
 ) {
  throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 }
 $changes = @($Journal.changes)
 if ($changes.Count -gt $script:Changes.Count) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 for ($index = 0; $index -lt $changes.Count; $index += 1) {
 if ([string]$changes[$index] -cne [string]$script:Changes[$index]) {
  throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 }
 foreach ($pointer in @($Journal.snapshot.active, $Journal.snapshot.previous)) {
 if ($null -ne $pointer) {
  Assert-AgentRoadPointer $pointer
 }
 }
 if (
 $Journal.status -ceq 'committed' -and (
  $completed.Count -ne $script:ForwardPhases.Count -or
  $changes.Count -ne $script:Changes.Count -or
  $Journal.phase -cne 'commit' -or
  $null -ne $Journal.failureCode -or
  $Journal.rollbackStatus -cne 'not-attempted'
 )
 ) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 if (
 $Journal.status -ceq 'rolled-back' -and (
  $Journal.phase -cne 'rollback' -or
  $Journal.rollbackStatus -cne 'succeeded'
 )
 ) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 if ($Journal.status -ceq 'failed' -and ($Journal.phase -cne 'rollback' -or $Journal.rollbackStatus -cne 'pending')) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 if ($Journal.status -ceq 'running' -and $null -ne $Journal.failureCode) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 if ($Journal.status -cin @('failed', 'uncertain', 'rolled-back') -and $null -eq $Journal.failureCode) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
 if ($null -ne $Journal.failureCode -and [string]$Journal.failureCode -cnotin $script:FailureCodes) {
 throw 'RUNTIME_STATE_UNSUPPORTED'
 }
}
function Read-AgentRoadPointer {
 param(
 [Parameter(Mandatory = $true)]
 [string]$Path
 )
 if (-not (Test-Path -LiteralPath $Path)) {
 return $null
 }
 $record = Read-AgentRoadJsonFile $Path 32768
 Assert-AgentRoadPointer $record.value
 return $record.value
}
function Read-AgentRoadJournal {
 if (-not (Test-Path -LiteralPath $script:JournalPath)) {
 return $null
 }
 $record = Read-AgentRoadJsonFile $script:JournalPath 32768
 Assert-AgentRoadJournal $record.value
 return $record.value
}
function Assert-AgentRoadExactFieldSet {
 param([object]$Value, [string[]]$Fields)
 if ($null -eq $Value -or $Value -isnot [pscustomobject]) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $names = @($Value.PSObject.Properties.Name)
 if ($names.Count -ne $Fields.Count) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 foreach ($field in $Fields) {
 if ($names -cnotcontains $field) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 }
}
function ConvertFrom-AgentRoadBase64Url {
 param([Parameter(Mandatory = $true)][string]$Value)
 if ($Value -cnotmatch '^[A-Za-z0-9_-]+$') { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $base64 = $Value.Replace('-', '+').Replace('_', '/')
 switch ($base64.Length % 4) {
 0 { }
 2 { $base64 += '==' }
 3 { $base64 += '=' }
 default { throw 'RUNTIME_STATE_UNSUPPORTED' }
 }
 try { return [Convert]::FromBase64String($base64) } catch { throw 'RUNTIME_STATE_UNSUPPORTED' }
}
function Assert-AgentRoadManifest {
 param([pscustomobject]$Capsule, [byte[]]$ManifestBytes, [pscustomobject]$Manifest)
 Assert-AgentRoadExactOrderedRecord $Capsule $script:CapsuleFields
 Assert-AgentRoadExactOrderedRecord $Manifest $script:ManifestFields
 Assert-AgentRoadExactOrderedRecord $Manifest.platform $script:ManifestPlatformFields
 $createdAt = [DateTimeOffset]::MinValue
 $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
 $validTime = (
 $Manifest.createdAt -is [string] -and
 [DateTimeOffset]::TryParseExact([string]$Manifest.createdAt, 'yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$createdAt) -and
 $createdAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture) -ceq [string]$Manifest.createdAt
 )
 $components = @($Manifest.components)
 if (
 $Capsule.schemaVersion -isnot [int] -or $Capsule.schemaVersion -ne 1 -or
 $Capsule.manifestDigest -isnot [string] -or $Capsule.manifestDigest -cnotmatch '^[A-F0-9]{64}$' -or
 (Get-AgentRoadBytesSha256 $ManifestBytes) -cne [string]$Capsule.manifestDigest -or
 $Capsule.generationDigest -isnot [string] -or $Capsule.generationDigest -cnotmatch '^[A-F0-9]{64}$' -or
 $Capsule.signatureAlgorithm -cne 'RSA-SHA256' -or
 $Capsule.signatureBase64 -isnot [string] -or $Capsule.signatureBase64 -cnotmatch '^[A-Za-z0-9+/]{512}$' -or
 $Capsule.controllerKeyId -isnot [string] -or $Capsule.controllerKeyId -cnotmatch '^[A-F0-9]{64}$' -or
 $Capsule.controllerPublicKeyJson -isnot [string] -or
 $Manifest.schemaVersion -isnot [int] -or $Manifest.schemaVersion -ne 1 -or
 $Manifest.deviceId -isnot [string] -or $Manifest.deviceId.Length -gt 64 -or $Manifest.deviceId -cnotmatch '^dev_[a-z0-9]+$' -or
 $Manifest.operationId -isnot [string] -or $Manifest.operationId -cnotmatch '^[a-f0-9]{32}$' -or
 -not $validTime -or
 $Manifest.platform.os -cne 'windows' -or
 $Manifest.platform.version -isnot [string] -or $Manifest.platform.version -cnotmatch '^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2,3}$' -or
 $Manifest.platform.build -isnot [int] -or $Manifest.platform.build -lt 10240 -or $Manifest.platform.build -gt 99999 -or
 $Manifest.platform.edition -isnot [string] -or [string]::IsNullOrEmpty($Manifest.platform.edition) -or
 $Manifest.platform.edition.Trim() -cne $Manifest.platform.edition -or $script:Utf8.GetByteCount($Manifest.platform.edition) -gt 256 -or
 $Manifest.platform.edition -match '[\x00-\x1F\x7F]' -or
 $Manifest.platform.architecture -cnotin @('x64', 'arm64') -or
 $Manifest.platform.windowsPowerShellVersion -isnot [string] -or $Manifest.platform.windowsPowerShellVersion -cnotmatch '^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){1,3}$' -or
 $Manifest.platform.elevated -isnot [bool] -or -not $Manifest.platform.elevated -or
 $Manifest.generationDigest -cne $Capsule.generationDigest -or
 $Manifest.catalogRevision -isnot [int] -or $Manifest.catalogRevision -lt 1 -or
 $Manifest.catalogDigest -isnot [string] -or $Manifest.catalogDigest -cnotmatch '^[A-F0-9]{64}$' -or
 $Manifest.inventoryDigest -isnot [string] -or $Manifest.inventoryDigest -cnotmatch '^[A-F0-9]{64}$' -or
 $Manifest.acquisition -cne 'mac-relay' -or
 $Manifest.phases -isnot [Array] -or @($Manifest.phases).Count -ne $script:Phases.Count -or
 $Manifest.profiles -isnot [Array] -or @($Manifest.profiles).Count -ne 1 -or [string]$Manifest.profiles[0] -cne 'core' -or
 $Manifest.requestedProfiles -isnot [Array] -or @($Manifest.requestedProfiles).Count -gt 1 -or
 $Manifest.components -isnot [Array] -or $components.Count -ne 1
 ) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 for ($index = 0; $index -lt $script:Phases.Count; $index += 1) {
 if ([string]$Manifest.phases[$index] -cne [string]$script:Phases[$index]) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 }
 if (@($Manifest.requestedProfiles).Count -eq 1 -and [string]$Manifest.requestedProfiles[0] -cne 'core') { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $component = $components[0]
 Assert-AgentRoadExactOrderedRecord $component $script:ManifestComponentFields
 if (
 $component.id -cne $script:CoreComponentId -or
 $component.version -isnot [string] -or $component.version -cnotmatch '^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$' -or
 $component.bytes -isnot [int] -or $component.bytes -lt 1 -or $component.bytes -gt 268435456 -or
 (($component.maximumExpandedBytes -isnot [int]) -and ($component.maximumExpandedBytes -isnot [long])) -or
 [long]$component.maximumExpandedBytes -lt 1 -or [long]$component.maximumExpandedBytes -gt 34359738368 -or
 $component.sha256 -isnot [string] -or $component.sha256 -cnotmatch '^[A-F0-9]{64}$' -or
 $component.packaging -cne 'zip' -or $component.signerRule -cne 'microsoft-corporation' -or
 $component.verificationCommandId -cne 'powershell-json-roundtrip'
 ) { throw 'RUNTIME_STATE_UNSUPPORTED' }
}
function Assert-AgentRoadControllerSignature {
 param([pscustomobject]$Capsule, [byte[]]$ManifestBytes)
 $keyBytes = $script:Utf8.GetBytes([string]$Capsule.controllerPublicKeyJson)
 $key = ConvertFrom-AgentRoadCanonicalJson $keyBytes 4096
 Assert-AgentRoadExactOrderedRecord $key $script:PublicKeyFields
 if (($key | ConvertTo-Json -Compress) -cne [string]$Capsule.controllerPublicKeyJson) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $modulus = ConvertFrom-AgentRoadBase64Url ([string]$key.modulusBase64Url)
 $exponent = ConvertFrom-AgentRoadBase64Url ([string]$key.exponentBase64Url)
 if (
 $key.algorithm -cne 'RSA-SHA256' -or $modulus.Length -ne 384 -or ($modulus[0] -band 0x80) -eq 0 -or
 $exponent.Length -ne 3 -or $exponent[0] -ne 1 -or $exponent[1] -ne 0 -or $exponent[2] -ne 1
 ) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $domain = $script:Utf8.GetBytes("AGENT_ROAD_CONTROLLER_KEY_V1`0")
 $identity = New-Object byte[] ($domain.Length + $keyBytes.Length)
 [Array]::Copy($domain, 0, $identity, 0, $domain.Length)
 [Array]::Copy($keyBytes, 0, $identity, $domain.Length, $keyBytes.Length)
 if ((Get-AgentRoadBytesSha256 $identity) -cne [string]$Capsule.controllerKeyId) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 try { $signature = [Convert]::FromBase64String([string]$Capsule.signatureBase64) } catch { throw 'RUNTIME_STATE_UNSUPPORTED' }
 if ($signature.Length -ne 384 -or [Convert]::ToBase64String($signature) -cne [string]$Capsule.signatureBase64) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $domain = $script:Utf8.GetBytes("AGENT_ROAD_RUNTIME_V1`0")
 $signed = New-Object byte[] ($domain.Length + $ManifestBytes.Length)
 [Array]::Copy($domain, 0, $signed, 0, $domain.Length)
 [Array]::Copy($ManifestBytes, 0, $signed, $domain.Length, $ManifestBytes.Length)
 $parameters = New-Object Security.Cryptography.RSAParameters
 $parameters.Modulus = $modulus
 $parameters.Exponent = $exponent
 $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider(3072)
 try {
 $rsa.PersistKeyInCsp = $false
 $rsa.ImportParameters($parameters)
 if (-not $rsa.VerifyData($signed, 'SHA256', $signature)) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 } finally { $rsa.Dispose() }
}
function Assert-AgentRoadPinnedControllerTrust {
 param([string]$CanonicalKeyJson, [string]$PinnedKeyJson)
 if ($null -eq $PinnedKeyJson -or $CanonicalKeyJson -cne $PinnedKeyJson) { throw 'RUNTIME_STATE_UNSUPPORTED' }
}
function Read-AgentRoadBootstrapDeviceId {
 Assert-AgentRoadDirectoryNode $script:AgentRoadRoot
 Assert-AgentRoadDirectoryNode $script:BootstrapRoot
 Assert-AgentRoadFileNode $script:BootstrapJournalPath
 $bytes = [IO.File]::ReadAllBytes($script:BootstrapJournalPath)
 $journal = ConvertFrom-AgentRoadCanonicalJson $bytes 4096
 Assert-AgentRoadExactFieldSet $journal $script:BootstrapJournalFields
 if (($journal | ConvertTo-Json -Depth 4 -Compress) -cne $script:Utf8.GetString($bytes)) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $updatedAt = [DateTimeOffset]::MinValue
 $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
 $validTime = [DateTimeOffset]::TryParseExact([string]$journal.updatedAt, 'yyyy-MM-ddTHH:mm:ss.fffffffZ', [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$updatedAt)
 if (
 $journal.schemaVersion -isnot [int] -or $journal.schemaVersion -ne 1 -or $journal.phase -cne 'stage-zero' -or
 $journal.deviceId -isnot [string] -or $journal.deviceId.Length -gt 64 -or $journal.deviceId -cnotmatch '^dev_[a-z0-9]+$' -or
 -not $validTime -or $updatedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [Globalization.CultureInfo]::InvariantCulture) -cne [string]$journal.updatedAt -or
 $journal.checkpoints -isnot [Array] -or @($journal.checkpoints).Count -ne 1 -or [string]$journal.checkpoints[0] -cne 'preflight'
 ) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 return [string]$journal.deviceId
}
function Read-AgentRoadCapsule {
 param([string]$Path, [string]$ExpectedManifestDigest = $null, [string]$ExpectedOperationId = $null, [object]$PinnedKeyJson = $null)
 if ($null -ne $PinnedKeyJson -and $PinnedKeyJson -isnot [string]) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $record = Read-AgentRoadJsonFile $Path 131072
 $capsule = $record.value
 Assert-AgentRoadExactOrderedRecord $capsule $script:CapsuleFields
 $manifestBytes = $script:Utf8.GetBytes([string]$capsule.manifestJson)
 $manifest = ConvertFrom-AgentRoadCanonicalJson $manifestBytes 65536
 if (($manifest | ConvertTo-Json -Depth 12 -Compress) -cne [string]$capsule.manifestJson) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 Assert-AgentRoadManifest $capsule $manifestBytes $manifest
 Assert-AgentRoadControllerSignature $capsule $manifestBytes
 if ($null -ne $PinnedKeyJson) { Assert-AgentRoadPinnedControllerTrust ([string]$capsule.controllerPublicKeyJson) $PinnedKeyJson }
 if (
 ($null -ne $ExpectedManifestDigest -and [string]$capsule.manifestDigest -cne $ExpectedManifestDigest) -or
 ($null -ne $ExpectedOperationId -and [string]$manifest.operationId -cne $ExpectedOperationId) -or
 (Read-AgentRoadBootstrapDeviceId) -cne [string]$manifest.deviceId
 ) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 return [pscustomobject]@{ capsule = $capsule; manifest = $manifest; bytes = $record.bytes }
}
function Get-AgentRoadToolTreeRecord {
 param([string]$ToolRoot)
 $nodes = @(Get-AgentRoadBoundedTree $ToolRoot 8192)
 $files = @($nodes | Where-Object { -not $_.PSIsContainer } | Sort-Object FullName)
 $directories = @($nodes | Where-Object { $_.PSIsContainer } | Sort-Object FullName)
 $records = New-Object Collections.Generic.List[string]
 [long]$expandedBytes = 0
 foreach ($directory in $directories) {
 $relative = $directory.FullName.Substring($ToolRoot.Length + 1).Replace('\', '/')
 $records.Add('D' + [char]0 + $relative + [char]0)
 }
 foreach ($file in $files) {
 $relative = $file.FullName.Substring($ToolRoot.Length + 1).Replace('\', '/')
 $expandedBytes += [long]$file.Length
 $records.Add('F' + [char]0 + $relative + [char]0 + [string]$file.Length + [char]0 + (Get-AgentRoadSha256 $file.FullName) + [char]0)
 }
 return [pscustomobject][ordered]@{
 fileCount = $files.Count
 directoryCount = $directories.Count
 expandedBytes = $expandedBytes
 treeSha256 = Get-AgentRoadBytesSha256 ($script:Utf8.GetBytes(($records -join '')))
 }
}
function Get-AgentRoadFixedFileRecords {
 param([string]$GenerationRoot)
 $records = New-Object Collections.Generic.List[object]
 foreach ($relative in @('bin/pwsh.cmd', 'capsule.json', 'env.cmd', 'env.ps1', 'scripts/runtime-inventory.ps1', 'scripts/runtime-provision-core.ps1')) {
 $path = [IO.Path]::Combine($GenerationRoot, $relative.Replace('/', '\'))
 Assert-AgentRoadFileNode $path
 $item = Get-Item -LiteralPath $path -Force
 $records.Add([pscustomobject][ordered]@{ path = $relative; bytes = [int]$item.Length; sha256 = Get-AgentRoadSha256 $path })
 }
 return $records.ToArray()
}
function Invoke-AgentRoadPowerShellCheck {
 param([string]$Executable, [string]$Command, [string]$Expected)
 $start = New-Object Diagnostics.ProcessStartInfo
 $start.FileName = $Executable
 $start.Arguments = '-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
 $start.UseShellExecute = $false
 $start.CreateNoWindow = $true
 $start.RedirectStandardOutput = $true
 $start.RedirectStandardError = $true
 $process = New-Object Diagnostics.Process
 $process.StartInfo = $start
 try {
 if (-not $process.Start()) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $out = New-Object Text.StringBuilder
 $err = New-Object Text.StringBuilder
 $outBuffer = New-Object char[] 1024
 $errBuffer = New-Object char[] 1024
 $outTask = $process.StandardOutput.ReadAsync($outBuffer, 0, $outBuffer.Length)
 $errTask = $process.StandardError.ReadAsync($errBuffer, 0, $errBuffer.Length)
 $outClosed = $false
 $errClosed = $false
 $timer = [Diagnostics.Stopwatch]::StartNew()
 while (-not ($outClosed -and $errClosed -and $process.HasExited)) {
  if ($timer.ElapsedMilliseconds -ge 30000) { try { $process.Kill() } catch { }; throw 'RUNTIME_STATE_UNSUPPORTED' }
  $pending = New-Object 'Collections.Generic.List[Threading.Tasks.Task]'
  if (-not $outClosed) { $pending.Add([Threading.Tasks.Task]$outTask) }
  if (-not $errClosed) { $pending.Add([Threading.Tasks.Task]$errTask) }
  if ($pending.Count -gt 0) { [Threading.Tasks.Task]::WaitAny($pending.ToArray(), 100) | Out-Null } else { $process.WaitForExit(100) | Out-Null }
  if (-not $outClosed -and $outTask.IsCompleted) {
  $count = [int]$outTask.Result
  if ($count -eq 0) { $outClosed = $true } else {
   if ($out.Length -gt (4096 - $count)) { try { $process.Kill() } catch { }; throw 'RUNTIME_STATE_UNSUPPORTED' }
   $out.Append($outBuffer, 0, $count) | Out-Null
   $outTask = $process.StandardOutput.ReadAsync($outBuffer, 0, $outBuffer.Length)
  }
  }
  if (-not $errClosed -and $errTask.IsCompleted) {
  $count = [int]$errTask.Result
  if ($count -eq 0) { $errClosed = $true } else {
   if ($err.Length -gt (4096 - $count)) { try { $process.Kill() } catch { }; throw 'RUNTIME_STATE_UNSUPPORTED' }
   $err.Append($errBuffer, 0, $count) | Out-Null
   $errTask = $process.StandardError.ReadAsync($errBuffer, 0, $errBuffer.Length)
  }
  }
 }
 $process.WaitForExit()
 if ($process.ExitCode -ne 0 -or $err.Length -ne 0 -or $out.ToString() -cne $Expected) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 } finally { $process.Dispose() }
}
function Assert-AgentRoadExecutableVerification {
 param([string]$ToolRoot, [pscustomobject]$Component)
 $executable = [IO.Path]::Combine($ToolRoot, 'pwsh.exe')
 Assert-AgentRoadFileNode $executable
 $signature = Get-AuthenticodeSignature -LiteralPath $executable
 if (
 [string]$signature.Status -cne 'Valid' -or $null -eq $signature.SignerCertificate -or
 [string]$Component.signerRule -cne 'microsoft-corporation' -or
 [string]$signature.SignerCertificate.Subject -cnotmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)'
 ) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 Invoke-AgentRoadPowerShellCheck $executable '[Console]::Out.Write($PSVersionTable.PSVersion.ToString())' ([string]$Component.version)
 Invoke-AgentRoadPowerShellCheck $executable "[Console]::Out.Write((@{agentRoad=1}|ConvertTo-Json -Compress))" '{"agentRoad":1}'
}
function Assert-AgentRoadGenerationLayout {
 param([string]$GenerationRoot)
 $root = @(Get-AgentRoadDirectChildren $GenerationRoot 8)
 $required = @('capsule.json', 'receipt.json', 'env.cmd', 'env.ps1', 'bin', 'scripts', 'tools')
 if ($root.Count -ne $required.Count) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 foreach ($entry in $root) {
 if ($entry.Name -cnotin $required -or $entry.FullName -cne [IO.Path]::Combine($GenerationRoot, [string]$entry.Name)) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 }
 $nodes = @(Get-AgentRoadBoundedTree $GenerationRoot 8224)
 foreach ($node in $nodes) {
 $relative = $node.FullName.Substring($GenerationRoot.Length + 1).Replace('\', '/')
 if ($node.PSIsContainer) {
  if ($relative -cnotin @('bin', 'scripts', 'tools', 'tools/powershell-7') -and -not $relative.StartsWith('tools/powershell-7/', [StringComparison]::Ordinal)) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 } elseif (
  $relative -cnotin @('capsule.json', 'receipt.json', 'env.cmd', 'env.ps1', 'bin/pwsh.cmd', 'scripts/runtime-inventory.ps1', 'scripts/runtime-provision-core.ps1') -and
  -not $relative.StartsWith('tools/powershell-7/', [StringComparison]::Ordinal)
 ) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 }
 foreach ($relative in @('bin/pwsh.cmd', 'scripts/runtime-inventory.ps1', 'scripts/runtime-provision-core.ps1', 'tools/powershell-7/pwsh.exe')) {
 if (-not (Test-Path -LiteralPath ([IO.Path]::Combine($GenerationRoot, $relative.Replace('/', '\'))) -PathType Leaf)) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 }
 if (@(Get-AgentRoadDirectChildren ([IO.Path]::Combine($GenerationRoot, 'bin')) 2).Count -ne 1 -or @(Get-AgentRoadDirectChildren ([IO.Path]::Combine($GenerationRoot, 'scripts')) 3).Count -ne 2 -or @(Get-AgentRoadDirectChildren ([IO.Path]::Combine($GenerationRoot, 'tools')) 2).Count -ne 1) { throw 'RUNTIME_STATE_UNSUPPORTED' }
}
function Read-AgentRoadVerifiedGeneration {
 param([pscustomobject]$ExpectedPointer, [string]$PinnedKeyJson)
 Assert-AgentRoadPointer $ExpectedPointer
 $generationRoot = [IO.Path]::Combine($script:VersionsRoot, [string]$ExpectedPointer.manifestDigest)
 if ([IO.Path]::GetDirectoryName($generationRoot) -cne $script:VersionsRoot) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 Assert-AgentRoadGenerationLayout $generationRoot
 $receiptRecord = Read-AgentRoadJsonFile ([IO.Path]::Combine($generationRoot, 'receipt.json')) 32768
 $receipt = $receiptRecord.value
 Assert-AgentRoadReceipt $receipt
 if ($receiptRecord.bytes.Length -ne [int]$ExpectedPointer.receiptBytes -or (Get-AgentRoadBytesSha256 $receiptRecord.bytes) -cne [string]$ExpectedPointer.receiptSha256) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $capsuleRecord = Read-AgentRoadCapsule ([IO.Path]::Combine($generationRoot, 'capsule.json')) ([string]$ExpectedPointer.manifestDigest) ([string]$receipt.operationId) $PinnedKeyJson
 $capsule = $capsuleRecord.capsule
 $manifest = $capsuleRecord.manifest
 if (
 [string]$receipt.manifestDigest -cne [string]$ExpectedPointer.manifestDigest -or
 [string]$receipt.generationDigest -cne [string]$ExpectedPointer.generationDigest -or
 [int]$receipt.catalogRevision -ne [int]$ExpectedPointer.catalogRevision -or
 [string]$receipt.catalogDigest -cne [string]$ExpectedPointer.catalogDigest -or
 [string]$receipt.controllerKeyId -cne [string]$capsule.controllerKeyId -or
 [string]$manifest.generationDigest -cne [string]$receipt.generationDigest -or
 [int]$manifest.catalogRevision -ne [int]$receipt.catalogRevision -or
 [string]$manifest.catalogDigest -cne [string]$receipt.catalogDigest
 ) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $tree = Get-AgentRoadToolTreeRecord ([IO.Path]::Combine($generationRoot, 'tools\powershell-7'))
 $files = @(Get-AgentRoadFixedFileRecords $generationRoot)
 $component = $receipt.components[0]
 $manifestComponent = $manifest.components[0]
 if (
 [string]$component.version -cne [string]$manifestComponent.version -or [int]$component.bytes -ne [int]$manifestComponent.bytes -or
 [string]$component.sha256 -cne [string]$manifestComponent.sha256 -or [int]$component.fileCount -ne [int]$tree.fileCount -or
 [int]$component.directoryCount -ne [int]$tree.directoryCount -or [long]$component.expandedBytes -ne [long]$tree.expandedBytes -or
 [long]$tree.expandedBytes -gt [long]$manifestComponent.maximumExpandedBytes -or
 [string]$component.treeSha256 -cne [string]$tree.treeSha256 -or
 (($receipt.files | ConvertTo-Json -Depth 4 -Compress) -cne ($files | ConvertTo-Json -Depth 4 -Compress))
 ) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 Assert-AgentRoadExecutableVerification ([IO.Path]::Combine($generationRoot, 'tools\powershell-7')) $manifestComponent
 return [pscustomobject]@{
 pointer = $ExpectedPointer
 receipt = $receipt
 manifest = $manifest
 artifact = [pscustomobject][ordered]@{ id = 'powershell-7'; version = [string]$component.version; bytes = [int]$component.bytes; sha256 = [string]$component.sha256; verified = $true }
 }
}
function Assert-AgentRoadPartialGenerationTree {
 param([string]$Root)
 foreach ($node in @(Get-AgentRoadBoundedTree $Root 8224)) {
 $relative = $node.FullName.Substring($Root.Length + 1).Replace('\', '/')
 if ($node.PSIsContainer) {
  if ($relative -cnotin @('bin', 'scripts', 'tools', 'tools/powershell-7') -and -not $relative.StartsWith('tools/powershell-7/', [StringComparison]::Ordinal)) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 } elseif ($relative -cnotin @('capsule.json', 'receipt.json', 'env.cmd', 'env.ps1', 'bin/pwsh.cmd', 'scripts/runtime-inventory.ps1', 'scripts/runtime-provision-core.ps1') -and -not $relative.StartsWith('tools/powershell-7/', [StringComparison]::Ordinal)) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 }
}
function Read-AgentRoadStagedOperation {
 param([string]$OperationRoot, [object]$PinnedKeyJson = $null)
 Assert-AgentRoadDirectoryNode $OperationRoot
 $operationId = [IO.Path]::GetFileName($OperationRoot)
 if ($operationId -cnotmatch '^[a-f0-9]{32}$' -or [IO.Path]::GetDirectoryName($OperationRoot) -cne $script:StagingRoot) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $entries = @(Get-AgentRoadDirectChildren $OperationRoot 3)
 $transaction = $null
 $work = $null
 foreach ($entry in $entries) {
 if (-not $entry.PSIsContainer) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 if ($entry.Name -cmatch '^[A-F0-9]{64}$') {
  if ($null -ne $transaction) { throw 'RUNTIME_STATE_UNSUPPORTED' }
  $transaction = $entry
 } elseif ($entry.Name -ceq 'work' -or $entry.Name -cmatch '^work-([A-F0-9]{64})$') {
  if ($null -ne $work) { throw 'RUNTIME_STATE_UNSUPPORTED' }
  $work = $entry
 } else { throw 'RUNTIME_STATE_UNSUPPORTED' }
 }
 if ($null -eq $transaction -and $null -ne $work) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 if ($null -eq $transaction) { return [pscustomobject]@{ operationId = $operationId; manifestDigest = $null; capsuleRecord = $null; hasTemporary = $false; hasWork = $false } }
 $digest = [string]$transaction.Name
 if ($null -ne $work -and [string]$work.Name -cnotin @('work', ('work-' + $digest))) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $capsuleRecord = $null
 $capsuleTemp = $null
 $filesRoot = $null
 $artifacts = @()
 foreach ($entry in @(Get-AgentRoadDirectChildren $transaction.FullName 4)) {
 if (-not $entry.PSIsContainer -and $entry.Name -ceq 'capsule.json') {
  if ($null -ne $capsuleRecord) { throw 'RUNTIME_STATE_UNSUPPORTED' }
  $capsuleRecord = Read-AgentRoadCapsule $entry.FullName $digest $operationId $PinnedKeyJson
 } elseif (-not $entry.PSIsContainer -and $entry.Name -cmatch '^\.capsule-([A-F0-9]{64})\.upload$') {
  if ($null -ne $capsuleTemp) { throw 'RUNTIME_STATE_UNSUPPORTED' }
  Assert-AgentRoadTemporaryFileNode $entry.FullName 131072
  $capsuleTemp = $entry
 } elseif ($entry.PSIsContainer -and $entry.Name -ceq 'files') {
  $filesRoot = $entry
 } else { throw 'RUNTIME_STATE_UNSUPPORTED' }
 }
 if ($null -ne $capsuleRecord -and $null -ne $capsuleTemp) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 if ($null -ne $filesRoot) {
 $artifacts = @(Get-AgentRoadDirectChildren $filesRoot.FullName 3)
 if ($artifacts.Count -gt 1) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 foreach ($artifact in $artifacts) {
  if ($artifact.PSIsContainer) { throw 'RUNTIME_STATE_UNSUPPORTED' }
  if ($artifact.Name -cmatch '^\.powershell-7-(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-([A-F0-9]{64})\.upload$') {
  Assert-AgentRoadTemporaryFileNode $artifact.FullName 268435456
  } elseif ($artifact.Name -cmatch '^powershell-7-(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.zip$') {
  if ($null -eq $capsuleRecord) { Assert-AgentRoadFileNode $artifact.FullName } else {
   $component = $capsuleRecord.manifest.components[0]
   if ($artifact.Name -cne ('powershell-7-' + [string]$component.version + '.zip')) { throw 'RUNTIME_STATE_UNSUPPORTED' }
   Assert-AgentRoadFileNode $artifact.FullName ([long]$component.bytes) ([string]$component.sha256)
  }
  } else { throw 'RUNTIME_STATE_UNSUPPORTED' }
 }
 }
$keyTemp = $null
 if ($null -ne $work) {
 if ($null -eq $capsuleRecord) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 foreach ($entry in @(Get-AgentRoadDirectChildren $work.FullName 6)) {
  if ($entry.PSIsContainer -and $entry.Name -ceq 'generation') {
  Assert-AgentRoadPartialGenerationTree $entry.FullName
  } elseif (-not $entry.PSIsContainer -and $entry.Name -cmatch '^\.(?:journal|active|previous)\.json\.[a-f0-9]{32}\.next$') {
  Assert-AgentRoadFileNode $entry.FullName
  } elseif ($entry.Name -ceq '.controller-key.next') {
  if (Test-Path -LiteralPath $script:TrustKeyPath) { throw 'RUNTIME_STATE_UNSUPPORTED' }
  Assert-AgentRoadFileNode $entry.FullName
  if ([long]$entry.Length -gt 4096) { throw 'RUNTIME_STATE_UNSUPPORTED' }
  $keyTemp = $entry
  } else { throw 'RUNTIME_STATE_UNSUPPORTED' }
 }
 }
 return [pscustomobject]@{ operationId = $operationId; manifestDigest = $digest; capsuleRecord = $capsuleRecord; hasTemporary = ($null -ne $keyTemp -or $null -ne $capsuleTemp -or @($artifacts | Where-Object { $_.Name -cmatch '\.upload$' }).Count -ne 0); hasWork = ($null -ne $work) }
}
function Get-AgentRoadRuntimeStateSnapshot {
 param([Parameter(Mandatory = $true)][string]$RuntimeRoot)
 if ($RuntimeRoot -cne $script:RuntimeRoot) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 if (-not (Test-Path -LiteralPath $RuntimeRoot)) {
 return [pscustomobject][ordered]@{ runtime = [pscustomobject][ordered]@{ schemaVersion = $null; catalogRevision = $null; catalogDigest = $null; generationDigest = $null; generationVerified = $false; pendingOperationId = $null; restartRequired = $false }; managedArtifacts = @() }
 }
 Assert-AgentRoadDirectoryNode $RuntimeRoot
 $runtimeEntries = @(Get-AgentRoadDirectChildren $RuntimeRoot 5)
 foreach ($entry in $runtimeEntries) {
 if (-not $entry.PSIsContainer -or $entry.Name -cnotin @('staging', 'trust', 'versions', 'state') -or $entry.FullName -cne [IO.Path]::Combine($RuntimeRoot, [string]$entry.Name)) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 }
 if ($runtimeEntries.Name -cnotcontains 'staging') { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $pinnedKeyJson = $null
 $pinnedKeyId = $null
 $trustEmpty = $false
 if (Test-Path -LiteralPath $script:TrustRoot) {
 $trustEntries = @(Get-AgentRoadDirectChildren $script:TrustRoot 2)
 $trustEmpty = $trustEntries.Count -eq 0
 foreach ($entry in $trustEntries) {
  if ($entry.PSIsContainer -or $entry.Name -cne 'controller-key.json' -or $entry.FullName -cne $script:TrustKeyPath) { throw 'RUNTIME_STATE_UNSUPPORTED' }
  $keyRecord = Read-AgentRoadJsonFile $entry.FullName 4096
  Assert-AgentRoadExactOrderedRecord $keyRecord.value $script:PublicKeyFields
  $modulus = ConvertFrom-AgentRoadBase64Url ([string]$keyRecord.value.modulusBase64Url)
  $exponent = ConvertFrom-AgentRoadBase64Url ([string]$keyRecord.value.exponentBase64Url)
  if ($keyRecord.value.algorithm -cne 'RSA-SHA256' -or $modulus.Length -ne 384 -or ($modulus[0] -band 0x80) -eq 0 -or $exponent.Length -ne 3 -or $exponent[0] -ne 1 -or $exponent[1] -ne 0 -or $exponent[2] -ne 1) { throw 'RUNTIME_STATE_UNSUPPORTED' }
  $pinnedKeyJson = $keyRecord.json
  $domain = $script:Utf8.GetBytes("AGENT_ROAD_CONTROLLER_KEY_V1`0")
  $identity = New-Object byte[] ($domain.Length + $keyRecord.bytes.Length)
  [Array]::Copy($domain, 0, $identity, 0, $domain.Length)
  [Array]::Copy($keyRecord.bytes, 0, $identity, $domain.Length, $keyRecord.bytes.Length)
  $pinnedKeyId = Get-AgentRoadBytesSha256 $identity
 }
 }
 $script:PinnedKeyId = $pinnedKeyId
 $operations = @()
 foreach ($entry in @(Get-AgentRoadDirectChildren $script:StagingRoot 3)) {
 if (-not $entry.PSIsContainer) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $operations += Read-AgentRoadStagedOperation $entry.FullName $pinnedKeyJson
 }
 if ($trustEmpty -and ($operations.Count -ne 1 -or $null -eq $operations[0].capsuleRecord)) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 if (Test-Path -LiteralPath $script:StateRoot) {
 foreach ($entry in @(Get-AgentRoadDirectChildren $script:StateRoot 4)) {
  $expected = switch -CaseSensitive ([string]$entry.Name) {
  'active.json' { $script:ActivePath; break }
  'previous.json' { $script:PreviousPath; break }
  'journal.json' { $script:JournalPath; break }
  default { $null }
  }
  if ($entry.PSIsContainer -or $null -eq $expected -or $entry.FullName -cne $expected) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 }
 }
 $active = Read-AgentRoadPointer $script:ActivePath
 $previous = Read-AgentRoadPointer $script:PreviousPath
 $journal = Read-AgentRoadJournal
 if ($null -eq $active -and $null -ne $previous) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 if ($null -ne $active -and $null -ne $previous -and [string]$active.manifestDigest -ceq [string]$previous.manifestDigest) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 if ($null -ne $journal -and $null -ne $journal.snapshot.active -and $null -ne $journal.snapshot.previous -and [string]$journal.snapshot.active.manifestDigest -ceq [string]$journal.snapshot.previous.manifestDigest) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 if ($null -eq $journal -and ($null -ne $active -or $null -ne $previous)) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 if (($null -ne $active -or $null -ne $journal) -and $null -eq $pinnedKeyJson) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 if ($null -ne $journal -and [string]$journal.controllerKeyId -cne $pinnedKeyId) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $verified = @{}
 $activeGeneration = $null
 foreach ($record in @([pscustomobject]@{ role = 'active'; pointer = $active }, [pscustomobject]@{ role = 'previous'; pointer = $previous })) {
 if ($null -eq $record.pointer) { continue }
 $digest = [string]$record.pointer.manifestDigest
 if ($verified.ContainsKey($digest) -and -not (Test-AgentRoadPointerValue $verified[$digest].pointer $record.pointer)) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 if (-not $verified.ContainsKey($digest)) { $verified[$digest] = Read-AgentRoadVerifiedGeneration $record.pointer $pinnedKeyJson }
 if ($record.role -ceq 'active') { $activeGeneration = $verified[$digest] }
 }
 $journalGeneration = $null
 $journalPointer = $null
 if ($null -ne $journal) {
 foreach ($snapshotPointer in @($journal.snapshot.active, $journal.snapshot.previous)) {
  if ($null -eq $snapshotPointer) { continue }
  $digest = [string]$snapshotPointer.manifestDigest
  if ($verified.ContainsKey($digest)) {
  if (-not (Test-AgentRoadPointerValue $verified[$digest].pointer $snapshotPointer)) { throw 'RUNTIME_STATE_UNSUPPORTED' }
  } elseif (Test-Path -LiteralPath ([IO.Path]::Combine($script:VersionsRoot, $digest)) -PathType Container) {
  $verified[$digest] = Read-AgentRoadVerifiedGeneration $snapshotPointer $pinnedKeyJson
  } elseif (-not ($journal.status -ceq 'committed' -and $null -ne $journal.snapshot.previous -and $digest -ceq [string]$journal.snapshot.previous.manifestDigest)) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 }
 if (@($journal.changes) -ccontains 'generation-publish-planned' -and (Test-Path -LiteralPath ([IO.Path]::Combine($script:VersionsRoot, [string]$journal.manifestDigest)) -PathType Container)) {
  $root = [IO.Path]::Combine($script:VersionsRoot, [string]$journal.manifestDigest)
  $receiptRecord = Read-AgentRoadJsonFile ([IO.Path]::Combine($root, 'receipt.json')) 32768
  Assert-AgentRoadReceipt $receiptRecord.value
  $receipt = $receiptRecord.value
  $journalPointer = [pscustomobject][ordered]@{ schemaVersion = 1; receiptFormatRevision = 1; manifestDigest = [string]$receipt.manifestDigest; generationDigest = [string]$receipt.generationDigest; catalogRevision = [int]$receipt.catalogRevision; catalogDigest = [string]$receipt.catalogDigest; receiptBytes = [int]$receiptRecord.bytes.Length; receiptSha256 = Get-AgentRoadBytesSha256 $receiptRecord.bytes }
  $journalGeneration = Read-AgentRoadVerifiedGeneration $journalPointer $pinnedKeyJson
  if (
  [string]$journalGeneration.receipt.operationId -cne [string]$journal.operationId -or
  [string]$journalGeneration.pointer.generationDigest -cne [string]$journal.generationDigest -or
  [string]$journalGeneration.pointer.catalogDigest -cne [string]$journal.catalogDigest -or
  [string]$journalGeneration.receipt.controllerKeyId -cne [string]$journal.controllerKeyId
  ) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $verified[[string]$journal.manifestDigest] = $journalGeneration
 }
 if ((@($journal.completedPhases) -ccontains 'materialize-generation' -or @($journal.changes).Count -gt 2) -and $null -eq $journalGeneration) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 if ($journal.status -ceq 'committed') {
  if ($null -eq $journalGeneration -or -not (Test-AgentRoadPointerValue $active $journalGeneration.pointer) -or -not (Test-AgentRoadPointerValue $previous $journal.snapshot.active)) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 } elseif ($journal.status -ceq 'rolled-back') {
  if ($null -ne $journalGeneration -or -not (Test-AgentRoadPointerValue $active $journal.snapshot.active) -or -not (Test-AgentRoadPointerValue $previous $journal.snapshot.previous)) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 }
 $own = @($operations | Where-Object { $_.operationId -ceq [string]$journal.operationId })
 if ($journal.status -cin @('running', 'uncertain', 'failed')) {
  if ($operations.Count -ne 1 -or $own.Count -ne 1 -or -not $own[0].hasWork -or $own[0].hasTemporary -or $null -eq $own[0].capsuleRecord -or [string]$own[0].manifestDigest -cne [string]$journal.manifestDigest) { throw 'RUNTIME_STATE_UNSUPPORTED' }
  $capsule = $own[0].capsuleRecord
  if (
  [string]$capsule.manifest.generationDigest -cne [string]$journal.generationDigest -or
  [string]$capsule.manifest.catalogDigest -cne [string]$journal.catalogDigest -or
  [string]$capsule.manifest.inventoryDigest -cne [string]$journal.inventoryDigest -or
  [string]$capsule.capsule.controllerKeyId -cne [string]$journal.controllerKeyId
  ) { throw 'RUNTIME_STATE_UNSUPPORTED' }
  $snapshotCaptured = $null -ne $journal.snapshot.active -or $null -ne $journal.snapshot.previous -or @($journal.completedPhases) -ccontains 'snapshot' -or @($journal.changes).Count -ge 2
  if ($snapshotCaptured) {
  $previousPlanned = @($journal.changes) -ccontains 'previous-replace-planned'
  $activePlanned = @($journal.changes) -ccontains 'active-replace-planned'
  $rollbackInProgress = $journal.phase -ceq 'rollback' -or $journal.rollbackStatus -cin @('pending', 'failed')
  $oldA = Test-AgentRoadPointerValue $active $journal.snapshot.active
  $oldP = Test-AgentRoadPointerValue $previous $journal.snapshot.previous
  $wasActive = Test-AgentRoadPointerValue $previous $journal.snapshot.active
  $newA = Test-AgentRoadPointerValue $active $journalPointer
  if ($rollbackInProgress -and $activePlanned) {
   $validPointers = ($newA -and $wasActive) -or ($oldA -and $wasActive) -or ($oldA -and $oldP)
  } elseif ($previousPlanned -and -not $activePlanned) {
   $validPointers = $oldA -and ($oldP -or $wasActive)
  } elseif ($activePlanned) {
   $validPointers = $wasActive -and ($oldA -or $newA)
  } else {
   $validPointers = $oldA -and $oldP
  }
  if (-not $validPointers) { throw 'RUNTIME_STATE_UNSUPPORTED' }
  }
 }
 }
 if (Test-Path -LiteralPath $script:VersionsRoot) {
 foreach ($entry in @(Get-AgentRoadDirectChildren $script:VersionsRoot 6)) {
  if (-not $entry.PSIsContainer) { throw 'RUNTIME_STATE_UNSUPPORTED' }
  if ($entry.Name -cmatch '^[A-F0-9]{64}$') {
  if (-not $verified.ContainsKey([string]$entry.Name)) { throw 'RUNTIME_STATE_UNSUPPORTED' }
  } elseif ($entry.Name -cmatch '^\.retired-([A-F0-9]{64})$') {
  $digest = $Matches[1]
  if ($null -eq $journal -or $journal.status -cne 'committed' -or $null -eq $journal.snapshot.previous -or $digest -cne [string]$journal.snapshot.previous.manifestDigest -or (Test-Path -LiteralPath ([IO.Path]::Combine($script:VersionsRoot, $digest))) -or ($null -ne $active -and [string]$active.manifestDigest -ceq $digest) -or ($null -ne $previous -and [string]$previous.manifestDigest -ceq $digest)) { throw 'RUNTIME_STATE_UNSUPPORTED' }
  Assert-AgentRoadPartialGenerationTree $entry.FullName
  } elseif ($entry.Name -cmatch '^\.rollback-([A-F0-9]{64})$') {
  $digest = $Matches[1]
   $rollbackTombstone = $null -ne $journal -and $journal.phase -ceq 'rollback' -and ($journal.rollbackStatus -cin @('pending', 'failed') -or ($journal.status -ceq 'rolled-back' -and $journal.rollbackStatus -ceq 'succeeded'))
   if (-not $rollbackTombstone -or @($journal.changes) -cnotcontains 'generation-publish-planned' -or $digest -cne [string]$journal.manifestDigest -or (Test-Path -LiteralPath ([IO.Path]::Combine($script:VersionsRoot, $digest))) -or ($null -ne $active -and [string]$active.manifestDigest -ceq $digest) -or ($null -ne $previous -and [string]$previous.manifestDigest -ceq $digest)) { throw 'RUNTIME_STATE_UNSUPPORTED' }
  Assert-AgentRoadPartialGenerationTree $entry.FullName
  } else { throw 'RUNTIME_STATE_UNSUPPORTED' }
 }
 }
 $pendingOperationId = $null
 if ($null -eq $journal) {
 if ($operations.Count -gt 1) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 if ($operations.Count -eq 1) { $pendingOperationId = [string]$operations[0].operationId }
 } elseif ($journal.status -cin @('committed', 'rolled-back')) {
 $own = @($operations | Where-Object { $_.operationId -ceq [string]$journal.operationId })
 if ($own.Count -gt 1 -or ($own.Count -eq 1 -and ($own[0].hasTemporary -or ($null -ne $own[0].manifestDigest -and [string]$own[0].manifestDigest -cne [string]$journal.manifestDigest)))) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $new = @($operations | Where-Object { $_.operationId -cne [string]$journal.operationId })
 if ($new.Count -gt 1) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 if ($new.Count -eq 1) { $pendingOperationId = [string]$new[0].operationId }
 } else { $pendingOperationId = [string]$journal.operationId }
 $restartRequired = if ($null -ne $journal -and $journal.status -cnotin @('committed', 'rolled-back')) { [bool]$journal.restartRequired } elseif ($null -ne $activeGeneration) { [bool]$activeGeneration.receipt.restartRequired } else { $false }
 if ($null -eq $activeGeneration) {
 return [pscustomobject][ordered]@{ runtime = [pscustomobject][ordered]@{ schemaVersion = $null; catalogRevision = $null; catalogDigest = $null; generationDigest = $null; generationVerified = $false; pendingOperationId = $pendingOperationId; restartRequired = $restartRequired }; managedArtifacts = @() }
 }
 return [pscustomobject][ordered]@{
 runtime = [pscustomobject][ordered]@{ schemaVersion = 1; catalogRevision = [int]$activeGeneration.pointer.catalogRevision; catalogDigest = [string]$activeGeneration.pointer.catalogDigest; generationDigest = [string]$activeGeneration.pointer.generationDigest; generationVerified = $true; pendingOperationId = $pendingOperationId; restartRequired = $restartRequired }
 managedArtifacts = @($activeGeneration.artifact)
 }
}
function Test-AgentRoadRegistryKey {
 param(
 [Parameter(Mandatory = $true)]
 [string]$SubKey
 )
 $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKey, $false)
 if ($null -eq $key) {
 return $false
 }
 try {
 return $true
 } finally {
 $key.Dispose()
 }
}
function Test-AgentRoadRegistryValue {
 param(
 [Parameter(Mandatory = $true)]
 [string]$SubKey,
 [Parameter(Mandatory = $true)]
 [string]$ValueName
 )
 $key=$null
 try {
 $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKey, $false)
 if($null -eq $key){
  throw 'RUNTIME_INVENTORY_INVALID'
 }
 return @($key.GetValueNames()) -icontains $ValueName
 } catch {
 throw 'RUNTIME_INVENTORY_INVALID'
 } finally {
 if($null -ne $key){$key.Dispose()}
 }
}
try {
 $runtimeRoot = 'C:\ProgramData\AgentRoad\runtime'
 $runtimeState = Get-AgentRoadRuntimeStateSnapshot -RuntimeRoot $runtimeRoot
 $utf8 = New-Object System.Text.UTF8Encoding($false)
 $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
 $version = ([string]$os.Version).Trim()
 $buildText = ([string]$os.BuildNumber).Trim()
 $edition = ([string]$os.Caption).Trim()
 $windowsPowerShellVersion = $PSVersionTable.PSVersion.ToString()
 $build = 0
 if (-not [int]::TryParse($buildText, [ref]$build)) {
 throw 'RUNTIME_INVENTORY_INVALID'
 }
 if ($version -cnotmatch '^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2,3}$') {
 throw 'RUNTIME_INVENTORY_INVALID'
 }
 if ($windowsPowerShellVersion -cnotmatch '^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){1,3}$') {
 throw 'RUNTIME_INVENTORY_INVALID'
 }
 if (
 [string]::IsNullOrWhiteSpace($edition) -or
 $edition -cne $edition.Trim() -or
 $utf8.GetByteCount($edition) -gt 256 -or
 $edition -match '[\x00-\x1F\x7F]'
 ) {
 throw 'RUNTIME_INVENTORY_INVALID'
 }
 $architecture = switch -CaseSensitive ($env:PROCESSOR_ARCHITECTURE) {
 'AMD64' { 'x64'; break }
 'ARM64' { 'arm64'; break }
 default { throw 'RUNTIME_INVENTORY_INVALID' }
 }
 $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
 $principal = New-Object Security.Principal.WindowsPrincipal($identity)
 $elevated = $principal.IsInRole(
 [Security.Principal.WindowsBuiltInRole]::Administrator
 )
 $programDataRoot = [IO.Path]::GetPathRoot('C:\ProgramData')
 $drive = New-Object -TypeName System.IO.DriveInfo -ArgumentList $programDataRoot
 $freeBytes = [long]$drive.AvailableFreeSpace
 if ($freeBytes -lt 0 -or $freeBytes -gt 9007199254740991) {
 throw 'RUNTIME_INVENTORY_INVALID'
 }
 $pendingReboot = (
 (Test-AgentRoadRegistryKey -SubKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
 (Test-AgentRoadRegistryKey -SubKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
 )
 if (Test-AgentRoadRegistryValue `
 -SubKey 'SYSTEM\CurrentControlSet\Control\Session Manager' `
 -ValueName 'PendingFileRenameOperations') {
 $pendingReboot = $true
 }
 $interactiveSession = @(
 Get-Process -Name 'explorer' -ErrorAction SilentlyContinue |
  Where-Object { $_.SessionId -gt 0 }
 ).Count -gt 0
 $result = [pscustomobject][ordered]@{
 schemaVersion = 1
 platform = [pscustomobject][ordered]@{
  os = 'windows'
  version = $version
  build = $build
  edition = $edition
  architecture = $architecture
  windowsPowerShellVersion = $windowsPowerShellVersion
  elevated = [bool]$elevated
 }
 freeBytes = $freeBytes
 pendingReboot = [bool]$pendingReboot
 interactiveSession = [bool]$interactiveSession
 runtime = $runtimeState.runtime
 managedArtifacts = @($runtimeState.managedArtifacts)
 }
 if ($PlanningObservation.IsPresent) {
 $controllerTrust = [pscustomobject][ordered]@{
  state = if ($null -eq $script:PinnedKeyId) { 'unpinned' } else { 'pinned' }
  controllerKeyId = $script:PinnedKeyId
 }
 $planningResult = [pscustomobject][ordered]@{
  schemaVersion = 1
  inventory = $result
  controllerTrust = $controllerTrust
 }
 $json = $planningResult | ConvertTo-Json -Depth 7 -Compress
 if ($utf8.GetByteCount($json) -gt 65536) {
  throw 'RUNTIME_INVENTORY_INVALID'
 }
 } else {
 $json = $result | ConvertTo-Json -Depth 6 -Compress
 if ($utf8.GetByteCount($json) -gt 32768) {
 throw 'RUNTIME_INVENTORY_INVALID'
 }
 }
 [Console]::OutputEncoding = $utf8
 [Console]::Out.Write($json)
} catch {
 $failure = [string]$_.Exception.Message
 if ($failure -ceq 'RUNTIME_STATE_UNSUPPORTED') {
 exit 41
 }
 exit 42
}
