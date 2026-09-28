#requires -Version 5.1

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
$script:ForwardPhases = @(
    'discover',
    'verify-manifest',
    'verify-artifacts',
    'snapshot',
    'materialize-generation',
    'self-test',
    'atomic-activate',
    'validate',
    'commit'
)
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
$script:ResultFields = @(
    'schemaVersion',
    'status',
    'operationId',
    'manifestDigest',
    'generationDigest',
    'restartRequired',
    'failureCode'
)
$script:ResultStatuses = @(
    'committed',
    'failed',
    'uncertain',
    'rolled-back'
)
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
$script:CoreProfiles = @(
    'core'
)
$script:InvocationFields = @(
    'schemaVersion',
    'operationId',
    'manifestDigest'
)
$script:CoreComponentId = 'powershell-7'
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
    'schemaVersion',
    'phase',
    'deviceId',
    'updatedAt',
    'checkpoints'
)
$script:RuntimeEntryNames = @(
    'staging',
    'trust',
    'versions',
    'state'
)
$script:TrustEntryNames = @(
    'controller-key.json'
)
$script:StateEntryNames = @(
    'journal.json',
    'active.json',
    'previous.json'
)
$script:AgentRoadRoot = 'C:\ProgramData\AgentRoad'
$script:BootstrapRoot = [IO.Path]::Combine($script:AgentRoadRoot, 'bootstrap')
$script:BootstrapStageZeroJournalPath = [IO.Path]::Combine($script:BootstrapRoot, 'stage-zero-journal.json')
$script:RuntimeRoot = [IO.Path]::Combine($script:AgentRoadRoot, 'runtime')
$script:TrustRoot = [IO.Path]::Combine($script:RuntimeRoot, 'trust')
$script:StagingRoot = [IO.Path]::Combine($script:RuntimeRoot, 'staging')
$script:VersionsRoot = [IO.Path]::Combine($script:RuntimeRoot, 'versions')
$script:StateRoot = [IO.Path]::Combine($script:RuntimeRoot, 'state')
$script:JournalPath = [IO.Path]::Combine($script:StateRoot, 'journal.json')
$script:ActivePath = [IO.Path]::Combine($script:StateRoot, 'active.json')
$script:PreviousPath = [IO.Path]::Combine($script:StateRoot, 'previous.json')
$script:TrustKeyPath = [IO.Path]::Combine($script:TrustRoot, 'controller-key.json')
$script:Utf8 = New-Object Text.UTF8Encoding($false, $true)
$script:MOVEFILE_REPLACE_EXISTING = 0x1
$script:MOVEFILE_WRITE_THROUGH = 0x8
$script:Journal = $null
$script:Transaction = $null

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AgentRoad {
    [StructLayout(LayoutKind.Sequential)]
    public struct ByHandleFileInformation {
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
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool MoveFileEx(string existingName, string newName, int flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFile(
            string name,
            uint access,
            uint share,
            IntPtr security,
            uint disposition,
            uint flags,
            IntPtr template
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetFileInformationByHandle(
            SafeFileHandle handle,
            out ByHandleFileInformation information
        );
    }
}
'@

function Assert-AgentRoadExactOrderedRecord {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,
        [Parameter(Mandatory = $true)]
        [string[]]$Fields,
        [Parameter(Mandatory = $true)]
        [string]$FailureCode
    )

    if ($null -eq $Value -or $Value -isnot [pscustomobject]) {
        throw $FailureCode
    }
    $names = @($Value.PSObject.Properties.Name)
    if ($names.Count -ne $Fields.Count) {
        throw $FailureCode
    }
    for ($index = 0; $index -lt $Fields.Count; $index += 1) {
        if ([string]::CompareOrdinal([string]$names[$index], [string]$Fields[$index]) -ne 0) {
            throw $FailureCode
        }
    }
}

function Assert-AgentRoadExactFieldSet {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,
        [Parameter(Mandatory = $true)]
        [string[]]$Fields,
        [Parameter(Mandatory = $true)]
        [string]$FailureCode
    )

    if ($null -eq $Value -or $Value -isnot [pscustomobject]) {
        throw $FailureCode
    }
    $names = @($Value.PSObject.Properties.Name)
    if ($names.Count -ne $Fields.Count) {
        throw $FailureCode
    }
    foreach ($field in $Fields) {
        $matches = @($names | Where-Object { [string]::CompareOrdinal([string]$_, [string]$field) -eq 0 })
        if ($matches.Count -ne 1) {
            throw $FailureCode
        }
    }
}

function ConvertFrom-AgentRoadCanonicalJson {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,
        [Parameter(Mandatory = $true)]
        [int]$MaximumBytes,
        [Parameter(Mandatory = $true)]
        [string]$FailureCode
    )

    if ($Bytes.Length -lt 2 -or $Bytes.Length -gt $MaximumBytes) {
        throw $FailureCode
    }
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        throw $FailureCode
    }
    try {
        $json = $script:Utf8.GetString($Bytes)
    } catch {
        throw $FailureCode
    }
    if ($json.IndexOf([char]0) -ge 0 -or $json.Contains("`r") -or $json.Contains("`n")) {
        throw $FailureCode
    }
    try {
        return $json | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw $FailureCode
    }
}

function Assert-AgentRoadPointer {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Pointer
    )

    Assert-AgentRoadExactOrderedRecord $Pointer $script:PointerFields 'RUNTIME_STATE_UNSUPPORTED'
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

function Assert-AgentRoadReceipt {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Receipt
    )

    Assert-AgentRoadExactOrderedRecord $Receipt $script:ReceiptFields 'RUNTIME_STATE_UNSUPPORTED'
    if (
        $Receipt.schemaVersion -isnot [int] -or $Receipt.schemaVersion -ne 1 -or
        $Receipt.receiptFormatRevision -isnot [int] -or $Receipt.receiptFormatRevision -ne 1 -or
        $Receipt.operationId -isnot [string] -or $Receipt.operationId -cnotmatch '^[a-f0-9]{32}$' -or
        $Receipt.manifestDigest -isnot [string] -or $Receipt.manifestDigest -cnotmatch '^[A-F0-9]{64}$' -or
        $Receipt.generationDigest -isnot [string] -or $Receipt.generationDigest -cnotmatch '^[A-F0-9]{64}$' -or
        $Receipt.catalogRevision -isnot [int] -or $Receipt.catalogRevision -lt 1 -or
        $Receipt.catalogDigest -isnot [string] -or $Receipt.catalogDigest -cnotmatch '^[A-F0-9]{64}$' -or
        $Receipt.controllerKeyId -isnot [string] -or $Receipt.controllerKeyId -cnotmatch '^[A-F0-9]{64}$' -or
        @($Receipt.profiles).Count -ne 1 -or [string]$Receipt.profiles[0] -cne 'core' -or
        @($Receipt.components).Count -ne 1 -or
        $Receipt.restartRequired -isnot [bool] -or $Receipt.restartRequired
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $component = $Receipt.components[0]
    Assert-AgentRoadExactOrderedRecord $component $script:ReceiptComponentFields 'RUNTIME_STATE_UNSUPPORTED'
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
    $previousPath = $null
    for ($index = 0; $index -lt $files.Count; $index += 1) {
        $file = $files[$index]
        Assert-AgentRoadExactOrderedRecord $file $script:ReceiptFileFields 'RUNTIME_STATE_UNSUPPORTED'
        if (
            $file.path -isnot [string] -or
            $file.path -cne $requiredFiles[$index] -or
            ($null -ne $previousPath -and [string]::CompareOrdinal($previousPath, [string]$file.path) -ge 0) -or
            $file.bytes -isnot [int] -or $file.bytes -lt 1 -or
            $file.sha256 -isnot [string] -or $file.sha256 -cnotmatch '^[A-F0-9]{64}$'
        ) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        $previousPath = [string]$file.path
    }
}

function Assert-AgentRoadJournal {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Journal
    )

    Assert-AgentRoadExactOrderedRecord $Journal $script:JournalFields 'RUNTIME_STATE_UNSUPPORTED'
    Assert-AgentRoadExactOrderedRecord $Journal.snapshot $script:JournalSnapshotFields 'RUNTIME_STATE_UNSUPPORTED'
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
        $Journal.rollbackStatus -cnotin @('not-attempted', 'pending', 'succeeded', 'failed')
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    if (@($Journal.requestedProfiles).Count -gt 1) {
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

function New-AgentRoadJournal {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Capsule,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Manifest
    )

    return [pscustomobject][ordered]@{
        schemaVersion = 1
        revision = 0
        operationId = [string]$Manifest.operationId
        manifestDigest = [string]$Capsule.manifestDigest
        generationDigest = [string]$Capsule.generationDigest
        catalogDigest = [string]$Manifest.catalogDigest
        inventoryDigest = [string]$Manifest.inventoryDigest
        controllerKeyId = [string]$Capsule.controllerKeyId
        requestedProfiles = @($Manifest.requestedProfiles)
        status = 'running'
        phase = 'discover'
        completedPhases = @()
        changes = @()
        snapshot = [pscustomobject][ordered]@{
            active = $null
            previous = $null
        }
        restartRequired = $false
        failureCode = $null
        rollbackStatus = 'not-attempted'
    }
}

function Enter-AgentRoadMutationLock {
    $mutex = $null
    try {
        $security = New-Object Security.AccessControl.MutexSecurity
        $security.SetAccessRuleProtection($true, $false)
        $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
        $admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $ownerAccount = $admins.Translate([Security.Principal.NTAccount])
        $security.SetOwner($ownerAccount)
        foreach ($sid in @($system, $admins)) {
            $security.AddAccessRule((New-Object Security.AccessControl.MutexAccessRule(
                $sid,
                [Security.AccessControl.MutexRights]::FullControl,
                [Security.AccessControl.AccessControlType]::Allow
            )))
        }
        $created = $false
        $mutex = New-Object Threading.Mutex($false, 'Global\AgentRoadRuntimeMutation', [ref]$created, $security)
        $actualSecurity = $mutex.GetAccessControl()
        $owner = $actualSecurity.GetOwner([Security.Principal.SecurityIdentifier]).Value
        $rules = @($actualSecurity.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
        if (
            -not $actualSecurity.AreAccessRulesProtected -or
            -not $actualSecurity.AreAccessRulesCanonical -or
            $owner -cne 'S-1-5-32-544' -or
            $rules.Count -ne 2
        ) {
            $mutex.Dispose()
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        $seen = @()
        foreach ($rule in $rules) {
            $sid = [string]$rule.IdentityReference.Value
            if (
                $rule.IsInherited -or
                $sid -cnotin @('S-1-5-18', 'S-1-5-32-544') -or
                $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                $rule.MutexRights -ne [Security.AccessControl.MutexRights]::FullControl -or
                $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
                $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None
            ) {
                $mutex.Dispose()
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
            $seen += $sid
        }
        if ($seen -cnotcontains 'S-1-5-18' -or $seen -cnotcontains 'S-1-5-32-544') {
            $mutex.Dispose()
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        if (-not $mutex.WaitOne(0)) {
            $mutex.Dispose()
            throw 'RUNTIME_ALREADY_RUNNING'
        }
        return [pscustomobject]@{
            kind = 'mutex'
            value = $mutex
        }
    } catch [System.Threading.AbandonedMutexException] {
        if ($null -eq $mutex) {
            throw 'RUNTIME_INTERNAL_ERROR'
        }
        return [pscustomobject]@{
            kind = 'mutex'
            value = $mutex
        }
    } catch [System.UnauthorizedAccessException] {
        if ($null -ne $mutex) {
            $mutex.Dispose()
        }
        throw 'RUNTIME_STATE_UNSUPPORTED'
    } catch [System.Threading.WaitHandleCannotBeOpenedException] {
        if ($null -ne $mutex) {
            $mutex.Dispose()
        }
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
}

function Exit-AgentRoadMutationLock {
    param(
        [object]$Lock
    )

    if ($null -eq $Lock) {
        return
    }
    if ([string]$Lock.kind -ceq 'mutex') {
        try {
            $Lock.value.ReleaseMutex()
        } finally {
            $Lock.value.Dispose()
        }
        return
    }
    $Lock.value.Dispose()
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

function Assert-AgentRoadRestrictedAcl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [bool]$Directory
    )

    $acl = if ($Directory) { [IO.Directory]::GetAccessControl($Path) } else { [IO.File]::GetAccessControl($Path) }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (-not $acl.AreAccessRulesProtected -or -not $acl.AreAccessRulesCanonical -or $owner -cne 'S-1-5-32-544' -or $rules.Count -ne 2) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $seen = @()
    foreach ($rule in $rules) {
        $sid = [string]$rule.IdentityReference.Value
        if (
            $rule.IsInherited -or
            $sid -cnotin @('S-1-5-18', 'S-1-5-32-544') -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
            ($Directory -and $rule.InheritanceFlags -ne (
                [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit
            )) -or
            (-not $Directory -and $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None)
        ) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        $seen += $sid
    }
    if ($seen -cnotcontains 'S-1-5-18' -or $seen -cnotcontains 'S-1-5-32-544') {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
}

function New-AgentRoadRestrictedDirectorySecurity {
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $owner = $admins.Translate([Security.Principal.NTAccount])
    $inherit = (
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($owner)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        $system,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $inherit,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )))
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        $admins,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $inherit,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )))
    return $acl
}

function New-AgentRoadRestrictedFileSecurity {
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $owner = $admins.Translate([Security.Principal.NTAccount])
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetOwner($owner)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        $system,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.InheritanceFlags]::None,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )))
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        $admins,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.InheritanceFlags]::None,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )))
    return $acl
}

function New-AgentRoadRestrictedFileStream {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [int]$BufferSize
    )

    [Security.AccessControl.FileSecurity]$security = New-AgentRoadRestrictedFileSecurity
    $stream = New-Object IO.FileStream(
        $Path,
        [IO.FileMode]::CreateNew,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [IO.FileShare]::None,
        $BufferSize,
        [IO.FileOptions]::WriteThrough,
        $security
    )
    return $stream
}

function Ensure-AgentRoadRestrictedDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Parent
    )

    if ([IO.Path]::GetFullPath($Path) -cne $Path -or [IO.Path]::GetDirectoryName($Path) -cne $Parent) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    if (Test-Path -LiteralPath $Path) {
        Assert-AgentRoadDirectoryNode $Path
        return
    }
    [Security.AccessControl.DirectorySecurity]$security = New-AgentRoadRestrictedDirectorySecurity
    [IO.Directory]::CreateDirectory($Path, $security) | Out-Null
    Assert-AgentRoadDirectoryNode $Path
}

function Ensure-AgentRoadRestrictedDirectoryChain {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    Assert-AgentRoadDirectoryNode $Root
    $canonicalRoot = [IO.Path]::GetFullPath($Root)
    $canonicalPath = [IO.Path]::GetFullPath($Path)
    if ($canonicalPath -ceq $canonicalRoot) {
        return
    }
    $rootPrefix = $canonicalRoot + [IO.Path]::DirectorySeparatorChar
    if (-not $canonicalPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'RUNTIME_ARTIFACT_INVALID'
    }
    $relative = $canonicalPath.Substring($rootPrefix.Length)
    $current = $canonicalRoot
    foreach ($segment in @($relative.Split([IO.Path]::DirectorySeparatorChar))) {
        if ([string]::IsNullOrEmpty($segment)) {
            throw 'RUNTIME_ARTIFACT_INVALID'
        }
        $next = [IO.Path]::Combine($current, $segment)
        Ensure-AgentRoadRestrictedDirectory $next $current
        $current = $next
    }
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
    if ($ExpectedBytes -ge 0 -and $item.Length -ne $ExpectedBytes) {
        throw 'RUNTIME_ARTIFACT_INVALID'
    }
    if ($PSBoundParameters.ContainsKey('ExpectedSha256') -and (Get-AgentRoadSha256 $Path) -cne $ExpectedSha256) {
        throw 'RUNTIME_ARTIFACT_INVALID'
    }
}

function Read-AgentRoadInvocation {
    [Console]::InputEncoding = New-Object Text.UTF8Encoding($false, $true)
    $builder = New-Object Text.StringBuilder
    while ($true) {
        $value = [Console]::In.Read()
        if ($value -eq -1) {
            break
        }
        if (
            $value -eq 0x0A -or $value -eq 0x0D -or
            $value -eq 0xFEFF -or $value -eq 0x7F -or $value -lt 0x20
        ) {
            throw 'RUNTIME_INPUT_INVALID'
        }
        $builder.Append([char]$value) | Out-Null
        if ($builder.Length -gt 192) {
            throw 'RUNTIME_INPUT_INVALID'
        }
    }
    if ($builder.Length -lt 2) {
        throw 'RUNTIME_INPUT_INVALID'
    }
    $json = $builder.ToString()
    $invocation = ConvertFrom-AgentRoadCanonicalJson ($script:Utf8.GetBytes($json)) 192 'RUNTIME_INPUT_INVALID'
    Assert-AgentRoadExactOrderedRecord $invocation $script:InvocationFields 'RUNTIME_INPUT_INVALID'
    if (
        $invocation.schemaVersion -isnot [int] -or $invocation.schemaVersion -ne 1 -or
        $invocation.operationId -isnot [string] -or $invocation.operationId -cnotmatch '^[a-f0-9]{32}$' -or
        $invocation.manifestDigest -isnot [string] -or $invocation.manifestDigest -cnotmatch '^[A-F0-9]{64}$'
    ) {
        throw 'RUNTIME_INPUT_INVALID'
    }
    $canonical = [pscustomobject][ordered]@{
        schemaVersion = 1
        operationId = [string]$invocation.operationId
        manifestDigest = [string]$invocation.manifestDigest
    }
    if (($canonical | ConvertTo-Json -Depth 2 -Compress) -cne $json) {
        throw 'RUNTIME_INPUT_INVALID'
    }
    return $invocation
}

function Get-AgentRoadTransaction {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Invocation
    )

    Assert-AgentRoadDirectoryNode $script:RuntimeRoot
    Assert-AgentRoadDirectoryNode $script:StagingRoot
    $operationId = [string]$Invocation.operationId
    $manifestDigest = [string]$Invocation.manifestDigest
    $operationRoot = [IO.Path]::Combine($script:StagingRoot, $operationId)
    $transactionRoot = [IO.Path]::Combine($operationRoot, $manifestDigest)
    $workRoot = [IO.Path]::Combine($operationRoot, 'work')
    $legacyWorkRoot = [IO.Path]::Combine($operationRoot, ('work-' + $manifestDigest))
    if (Test-Path -LiteralPath $legacyWorkRoot) {
        if (Test-Path -LiteralPath $workRoot) { throw 'RUNTIME_STATE_UNSUPPORTED' }
        $workRoot = $legacyWorkRoot
    }
    $capsulePath = [IO.Path]::Combine($transactionRoot, 'capsule.json')
    $filesRoot = [IO.Path]::Combine($transactionRoot, 'files')
    foreach ($candidate in @($operationRoot, $transactionRoot, $workRoot, $capsulePath, $filesRoot)) {
        if ([IO.Path]::GetFullPath($candidate) -cne $candidate) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
    }
    return [pscustomobject]@{
        operationId = $operationId
        manifestDigest = $manifestDigest
        operationRoot = $operationRoot
        transactionRoot = $transactionRoot
        workRoot = $workRoot
        capsulePath = $capsulePath
        filesRoot = $filesRoot
    }
}

function Assert-AgentRoadStagedTransaction {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Transaction
    )

    $operations = @(Get-ChildItem -LiteralPath $script:StagingRoot -Force)
    if ($operations.Count -ne 1) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $operation = $operations[0]
    if (-not $operation.PSIsContainer -or $operation.FullName -cne $Transaction.operationRoot -or $operation.Name -cne $Transaction.operationId) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    Assert-AgentRoadDirectoryNode $Transaction.operationRoot
    $entries = @(Get-ChildItem -LiteralPath $Transaction.operationRoot -Force)
    if (-not (Test-Path -LiteralPath $Transaction.transactionRoot -PathType Container)) {
        throw 'RUNTIME_OPERATION_CONFLICT'
    }
    foreach ($entry in $entries) {
        if (-not $entry.PSIsContainer -or $entry.FullName -cnotin @($Transaction.transactionRoot, $Transaction.workRoot)) {
            throw 'RUNTIME_OPERATION_CONFLICT'
        }
    }
    Assert-AgentRoadDirectoryNode $Transaction.transactionRoot
    Assert-AgentRoadDirectoryNode $Transaction.filesRoot
    $transactionEntries = @(Get-ChildItem -LiteralPath $Transaction.transactionRoot -Force)
    if ($transactionEntries.Count -ne 2 -or $transactionEntries.Name -cnotcontains 'capsule.json' -or $transactionEntries.Name -cnotcontains 'files') {
        throw 'RUNTIME_OPERATION_CONFLICT'
    }
    if (Test-Path -LiteralPath $Transaction.workRoot) {
        Assert-AgentRoadDirectoryNode $Transaction.workRoot
    }
}

function Assert-AgentRoadOperationBinding {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Transaction,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Capsule,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Manifest,
        [Parameter(Mandatory = $true)]
        [byte[]]$CapsuleBytes
    )

    if (
        [string]$Manifest.operationId -cne [string]$Transaction.operationId -or
        [string]$Capsule.manifestDigest -cne [string]$Transaction.manifestDigest -or
        [string]$Manifest.generationDigest -cne [string]$Capsule.generationDigest
    ) {
        throw 'RUNTIME_OPERATION_CONFLICT'
    }
    $entries = @(Get-ChildItem -LiteralPath $Transaction.operationRoot -Force)
    foreach ($entry in $entries) {
        if (
            -not $entry.PSIsContainer -or
            $entry.Name -cnotin @($Transaction.manifestDigest, [IO.Path]::GetFileName($Transaction.workRoot))
        ) {
            throw 'RUNTIME_OPERATION_CONFLICT'
        }
    }
    if ((Test-Path -LiteralPath $Transaction.workRoot) -and -not (Test-Path -LiteralPath $Transaction.capsulePath -PathType Leaf)) {
        throw 'RUNTIME_OPERATION_CONFLICT'
    }
    $persistedCapsule = [IO.File]::ReadAllBytes($Transaction.capsulePath)
    if ($persistedCapsule.Length -ne $CapsuleBytes.Length) {
        throw 'RUNTIME_OPERATION_CONFLICT'
    }
    for ($index = 0; $index -lt $CapsuleBytes.Length; $index += 1) {
        if ($persistedCapsule[$index] -ne $CapsuleBytes[$index]) {
            throw 'RUNTIME_OPERATION_CONFLICT'
        }
    }
    if ($Capsule.manifestDigest -cnotmatch '^[A-F0-9]{64}$') {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
}

function Get-AgentRoadSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
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

function Assert-AgentRoadZipEntry {
    param(
        [Parameter(Mandatory = $true)]
        [IO.Compression.ZipArchiveEntry]$Entry,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.HashSet[string]]$Seen
    )

    $raw = [string]$Entry.FullName
    if (
        [string]::IsNullOrEmpty($raw) -or
        $raw.Length -gt 1024 -or
        [IO.Path]::IsPathRooted($raw) -or
        $raw.StartsWith('/') -or
        $raw.StartsWith('\') -or
        $raw -match ':' -or
        $raw -match '[\x00-\x1F\x7F]'
    ) {
        throw 'RUNTIME_ARTIFACT_INVALID'
    }
    $normalized = $raw.Replace('/', '\')
    $directoryEntry = $normalized.EndsWith('\')
    $trimmed = if ($directoryEntry) { $normalized.Substring(0, $normalized.Length - 1) } else { $normalized }
    if ([string]::IsNullOrEmpty($trimmed)) {
        throw 'RUNTIME_ARTIFACT_INVALID'
    }
    foreach ($segment in @($trimmed.Split('\'))) {
        if (
            [string]::IsNullOrEmpty($segment) -or
            $segment.Length -gt 255 -or
            $segment -ceq '.' -or $segment -ceq '..' -or
            $segment -match '[.\s]$' -or
            $segment -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$'
        ) {
            throw 'RUNTIME_ARTIFACT_INVALID'
        }
    }
    if ($Seen.Comparer -ne [StringComparer]::OrdinalIgnoreCase -or -not $Seen.Add($trimmed)) {
        throw 'RUNTIME_ARTIFACT_INVALID'
    }
    $attributes = [int]$Entry.ExternalAttributes
    $unixType = ($attributes -shr 16) -band 0xF000
    if (
        ($attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $unixType -eq 0xA000 -or
        $unixType -notin @(0, 0x8000, 0x4000) -or
        ($directoryEntry -and $Entry.Length -ne 0) -or
        ($directoryEntry -and $unixType -eq 0x8000) -or
        (-not $directoryEntry -and $unixType -eq 0x4000)
    ) {
        throw 'RUNTIME_ARTIFACT_INVALID'
    }
    return [pscustomobject]@{
        relativePath = $trimmed
        directory = $directoryEntry
        length = [long]$Entry.Length
    }
}

function Expand-AgentRoadPowerShellArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArchivePath,
        [Parameter(Mandatory = $true)]
        [string]$DestinationRoot,
        [Parameter(Mandatory = $true)]
        [long]$MaximumExpandedBytes
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $stream = [IO.File]::Open($ArchivePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $archive = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Read, $false)
        try {
            if ($archive.Entries.Count -lt 1 -or $archive.Entries.Count -gt 8192) {
                throw 'RUNTIME_ARTIFACT_INVALID'
            }
            $seen = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            $filePaths = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            $directoryPaths = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            $records = New-Object Collections.Generic.List[object]
            [long]$expandedBytes = 0
            foreach ($entry in $archive.Entries) {
                $record = Assert-AgentRoadZipEntry $entry $seen
                if (-not $record.directory) {
                    if ($record.length -lt 0 -or $expandedBytes -gt ($MaximumExpandedBytes - $record.length)) {
                        throw 'RUNTIME_ARTIFACT_INVALID'
                    }
                    $expandedBytes += $record.length
                }
                $segments = @($record.relativePath.Split('\'))
                $prefix = ''
                for ($index = 0; $index -lt $segments.Count; $index += 1) {
                    $prefix = if ($index -eq 0) { [string]$segments[$index] } else { $prefix + '\' + [string]$segments[$index] }
                    $directoryNode = $index -lt ($segments.Count - 1) -or $record.directory
                    if ($directoryNode) {
                        if ($filePaths.Contains($prefix)) {
                            throw 'RUNTIME_ARTIFACT_INVALID'
                        }
                        $directoryPaths.Add($prefix) | Out-Null
                    } else {
                        if ($directoryPaths.Contains($prefix) -or -not $filePaths.Add($prefix)) {
                            throw 'RUNTIME_ARTIFACT_INVALID'
                        }
                    }
                }
                $records.Add([pscustomobject]@{
                    entry = $entry
                    relativePath = $record.relativePath
                    directory = $record.directory
                    length = [long]$record.length
                })
            }
            if ($expandedBytes -lt 1 -or $expandedBytes -gt $MaximumExpandedBytes) {
                throw 'RUNTIME_ARTIFACT_INVALID'
            }
            [long]$actualExpandedBytes = 0
            foreach ($record in $records) {
                $destination = [IO.Path]::Combine($DestinationRoot, $record.relativePath)
                if (-not $destination.StartsWith($DestinationRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'RUNTIME_ARTIFACT_INVALID'
                }
                if ($record.directory) {
                    Ensure-AgentRoadRestrictedDirectoryChain $destination $DestinationRoot
                } else {
                    $parent = [IO.Path]::GetDirectoryName($destination)
                    Ensure-AgentRoadRestrictedDirectoryChain $parent $DestinationRoot
                    $input = $null
                    $output = $null
                    $completed = $false
                    try {
                        $input = $record.entry.Open()
                        $output = New-AgentRoadRestrictedFileStream $destination 65536
                        $buffer = New-Object byte[] 65536
                        [long]$actualEntryBytes = 0
                        while (($count = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
                            if (
                                $actualEntryBytes -gt ([long]$record.length - $count) -or
                                $actualExpandedBytes -gt ($MaximumExpandedBytes - $count)
                            ) {
                                throw 'RUNTIME_ARTIFACT_INVALID'
                            }
                            $output.Write($buffer, 0, $count)
                            $actualEntryBytes += $count
                            $actualExpandedBytes += $count
                        }
                        if ($actualEntryBytes -ne [long]$record.length) {
                            throw 'RUNTIME_ARTIFACT_INVALID'
                        }
                        $output.Flush($true)
                        $completed = $true
                    } finally {
                        if ($null -ne $output) {
                            $output.Dispose()
                        }
                        if ($null -ne $input) {
                            $input.Dispose()
                        }
                        if (-not $completed -and (Test-Path -LiteralPath $destination)) {
                            try {
                                [IO.File]::Delete($destination)
                            } catch {
                                throw 'RUNTIME_COMPLETION_UNCERTAIN'
                            }
                            if (Test-Path -LiteralPath $destination) {
                                throw 'RUNTIME_COMPLETION_UNCERTAIN'
                            }
                        }
                    }
                    Assert-AgentRoadFileNode $destination ([long]$record.length)
                }
            }
            if ($actualExpandedBytes -ne $expandedBytes) {
                throw 'RUNTIME_ARTIFACT_INVALID'
            }
            return $actualExpandedBytes
        } finally {
            $archive.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Get-AgentRoadFileLinkCount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $handle = [AgentRoad.NativeMethods]::CreateFile(
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
        $information = New-Object AgentRoad.ByHandleFileInformation
        if (-not [AgentRoad.NativeMethods]::GetFileInformationByHandle($handle, [ref]$information)) {
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

function Assert-AgentRoadGenerationTree {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GenerationRoot
    )

    Assert-AgentRoadDirectoryNode $GenerationRoot
    foreach ($item in @(Get-ChildItem -LiteralPath $GenerationRoot -Force -Recurse)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        if ($item.PSIsContainer) {
            Assert-AgentRoadDirectoryNode $item.FullName
        } else {
            Assert-AgentRoadFileNode $item.FullName
        }
    }
}

function Assert-AgentRoadExactGenerationTopology {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GenerationRoot
    )

    Assert-AgentRoadDirectoryNode $GenerationRoot
    $requiredFiles = @('capsule.json', 'receipt.json', 'env.cmd', 'env.ps1')
    $requiredDirectories = @('bin', 'scripts', 'tools')
    $rootEntries = @(Get-ChildItem -LiteralPath $GenerationRoot -Force)
    if ($rootEntries.Count -ne ($requiredFiles.Count + $requiredDirectories.Count)) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    foreach ($entry in $rootEntries) {
        $expectedPath = [IO.Path]::Combine($GenerationRoot, [string]$entry.Name)
        if ($entry.FullName -cne $expectedPath) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        if ($entry.Name -cin $requiredFiles) {
            if ($entry.PSIsContainer) {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
            Assert-AgentRoadFileNode $entry.FullName
        } elseif ($entry.Name -cin $requiredDirectories) {
            if (-not $entry.PSIsContainer) {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
            Assert-AgentRoadDirectoryNode $entry.FullName
        } else {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
    }

    $binRoot = [IO.Path]::Combine($GenerationRoot, 'bin')
    $binEntries = @(Get-ChildItem -LiteralPath $binRoot -Force)
    if (
        $binEntries.Count -ne 1 -or
        $binEntries[0].PSIsContainer -or
        $binEntries[0].Name -cne 'pwsh.cmd' -or
        $binEntries[0].FullName -cne [IO.Path]::Combine($binRoot, 'pwsh.cmd')
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    Assert-AgentRoadFileNode $binEntries[0].FullName

    $scriptsRoot = [IO.Path]::Combine($GenerationRoot, 'scripts')
    $scriptNames = @('runtime-inventory.ps1', 'runtime-provision-core.ps1')
    $scriptEntries = @(Get-ChildItem -LiteralPath $scriptsRoot -Force)
    if ($scriptEntries.Count -ne $scriptNames.Count) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    foreach ($entry in $scriptEntries) {
        if (
            $entry.PSIsContainer -or
            $entry.Name -cnotin $scriptNames -or
            $entry.FullName -cne [IO.Path]::Combine($scriptsRoot, [string]$entry.Name)
        ) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        Assert-AgentRoadFileNode $entry.FullName
    }

    $toolsRoot = [IO.Path]::Combine($GenerationRoot, 'tools')
    $toolEntries = @(Get-ChildItem -LiteralPath $toolsRoot -Force)
    $toolRoot = [IO.Path]::Combine($toolsRoot, 'powershell-7')
    if (
        $toolEntries.Count -ne 1 -or
        -not $toolEntries[0].PSIsContainer -or
        $toolEntries[0].Name -cne 'powershell-7' -or
        $toolEntries[0].FullName -cne $toolRoot
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    Assert-AgentRoadDirectoryNode $toolRoot
}

function Get-AgentRoadToolTreeRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolRoot
    )

    $records = New-Object Collections.Generic.List[string]
    $files = @(Get-ChildItem -LiteralPath $ToolRoot -Force -File -Recurse | Sort-Object FullName)
    $directories = @(Get-ChildItem -LiteralPath $ToolRoot -Force -Directory -Recurse | Sort-Object FullName)
    [long]$expandedBytes = 0
    foreach ($directory in $directories) {
        $relative = $directory.FullName.Substring($ToolRoot.Length + 1).Replace('\', '/')
        $records.Add('D' + [char]0 + $relative + [char]0)
    }
    foreach ($file in $files) {
        Assert-AgentRoadFileNode $file.FullName
        $relative = $file.FullName.Substring($ToolRoot.Length + 1).Replace('\', '/')
        $expandedBytes += [long]$file.Length
        $records.Add('F' + [char]0 + $relative + [char]0 + [string]$file.Length + [char]0 + (Get-AgentRoadSha256 $file.FullName) + [char]0)
    }
    $bytes = $script:Utf8.GetBytes(($records -join ''))
    return [pscustomobject]@{
        fileCount = $files.Count
        directoryCount = $directories.Count
        expandedBytes = $expandedBytes
        treeSha256 = Get-AgentRoadBytesSha256 $bytes
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
    Assert-AgentRoadFileNode $Path
    $bytes = [IO.File]::ReadAllBytes($Path)
    $pointer = ConvertFrom-AgentRoadCanonicalJson $bytes 32768 'RUNTIME_STATE_UNSUPPORTED'
    Assert-AgentRoadPointer $pointer
    return $pointer
}

function Read-AgentRoadJournal {
    if (-not (Test-Path -LiteralPath $script:JournalPath)) {
        return $null
    }
    Assert-AgentRoadFileNode $script:JournalPath
    $bytes = [IO.File]::ReadAllBytes($script:JournalPath)
    $journal = ConvertFrom-AgentRoadCanonicalJson $bytes 32768 'RUNTIME_STATE_UNSUPPORTED'
    Assert-AgentRoadJournal $journal
    return $journal
}

function Assert-AgentRoadJournalTransactionBinding {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Journal,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Transaction
    )

    if (
        [string]$Journal.operationId -cne [string]$Transaction.operationId -or
        [string]$Journal.manifestDigest -cne [string]$Transaction.manifestDigest
    ) {
        throw 'RUNTIME_OPERATION_CONFLICT'
    }
}

function Read-AgentRoadJournalGenerationPointer {
    $generationRoot = [IO.Path]::Combine($script:VersionsRoot, [string]$script:Journal.manifestDigest)
    Assert-AgentRoadDirectoryNode $generationRoot
    Assert-AgentRoadGenerationTree $generationRoot
    $receiptPath = [IO.Path]::Combine($generationRoot, 'receipt.json')
    Assert-AgentRoadFileNode $receiptPath
    $receiptBytes = [IO.File]::ReadAllBytes($receiptPath)
    $receipt = ConvertFrom-AgentRoadCanonicalJson $receiptBytes 32768 'RUNTIME_STATE_UNSUPPORTED'
    Assert-AgentRoadReceipt $receipt
    if (
        [string]$receipt.operationId -cne [string]$script:Journal.operationId -or
        [string]$receipt.manifestDigest -cne [string]$script:Journal.manifestDigest -or
        [string]$receipt.generationDigest -cne [string]$script:Journal.generationDigest -or
        [string]$receipt.catalogDigest -cne [string]$script:Journal.catalogDigest -or
        [string]$receipt.controllerKeyId -cne [string]$script:Journal.controllerKeyId
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $pointer = [pscustomobject][ordered]@{
        schemaVersion = 1
        receiptFormatRevision = 1
        manifestDigest = [string]$receipt.manifestDigest
        generationDigest = [string]$receipt.generationDigest
        catalogRevision = [int]$receipt.catalogRevision
        catalogDigest = [string]$receipt.catalogDigest
        receiptBytes = [int]$receiptBytes.Length
        receiptSha256 = Get-AgentRoadBytesSha256 $receiptBytes
    }
    Assert-AgentRoadPointer $pointer
    return $pointer
}

function Assert-AgentRoadPinnedControllerTrust {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CanonicalKeyJson
    )

    if (
        -not (Test-Path -LiteralPath $script:TrustRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $script:TrustKeyPath -PathType Leaf)
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    Assert-AgentRoadDirectoryNode $script:TrustRoot
    Assert-AgentRoadFileNode $script:TrustKeyPath
    $expected = $script:Utf8.GetBytes($CanonicalKeyJson)
    $actual = [IO.File]::ReadAllBytes($script:TrustKeyPath)
    if ($actual.Length -ne $expected.Length) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    for ($index = 0; $index -lt $expected.Length; $index += 1) {
        if ($actual[$index] -ne $expected[$index]) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
    }
}

function Read-AgentRoadVerifiedGenerationPointer {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$ExpectedPointer
    )

    try {
        Assert-AgentRoadPointer $ExpectedPointer
        $generationRoot = [IO.Path]::Combine($script:VersionsRoot, [string]$ExpectedPointer.manifestDigest)
        if (
            [IO.Path]::GetFullPath($generationRoot) -cne $generationRoot -or
            [IO.Path]::GetDirectoryName($generationRoot) -cne $script:VersionsRoot
        ) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        Assert-AgentRoadGenerationTree $generationRoot
        $capsulePath = [IO.Path]::Combine($generationRoot, 'capsule.json')
        Assert-AgentRoadFileNode $capsulePath
        $capsuleBytes = [IO.File]::ReadAllBytes($capsulePath)
        $capsule = ConvertFrom-AgentRoadCanonicalJson $capsuleBytes 131072 'RUNTIME_STATE_UNSUPPORTED'
        Assert-AgentRoadExactOrderedRecord $capsule $script:CapsuleFields 'RUNTIME_STATE_UNSUPPORTED'
        $manifestBytes = $script:Utf8.GetBytes([string]$capsule.manifestJson)
        $manifest = ConvertFrom-AgentRoadCanonicalJson $manifestBytes 65536 'RUNTIME_STATE_UNSUPPORTED'
        Assert-AgentRoadManifest $capsule $manifestBytes $manifest
        Assert-AgentRoadControllerSignature $capsule $manifestBytes
        Assert-AgentRoadPinnedControllerTrust ([string]$capsule.controllerPublicKeyJson)
        $actualPointer = Assert-AgentRoadAdoptedGeneration $generationRoot $capsule $manifest $capsuleBytes
        if (-not (Test-AgentRoadPointerValue $actualPointer $ExpectedPointer)) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        return $actualPointer
    } catch {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
}

function Assert-AgentRoadGenerationTombstoneTree {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TombstoneRoot
    )

    Assert-AgentRoadDirectoryNode $TombstoneRoot
    $nodes = @(Get-ChildItem -LiteralPath $TombstoneRoot -Force -Recurse)
    if ($nodes.Count -gt 8224) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    foreach ($node in $nodes) {
        $relative = $node.FullName.Substring($TombstoneRoot.Length + 1).Replace('\', '/')
        if ($node.PSIsContainer) {
            $allowedDirectory = (
                $relative -cin @('bin', 'scripts', 'tools', 'tools/powershell-7') -or
                $relative.StartsWith('tools/powershell-7/', [StringComparison]::Ordinal)
            )
            if (-not $allowedDirectory) {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
            Assert-AgentRoadDirectoryNode $node.FullName
        } else {
            $allowedFile = (
                $relative -cin @(
                    'capsule.json',
                    'receipt.json',
                    'env.cmd',
                    'env.ps1',
                    'bin/pwsh.cmd',
                    'scripts/runtime-inventory.ps1',
                    'scripts/runtime-provision-core.ps1'
                ) -or
                $relative.StartsWith('tools/powershell-7/', [StringComparison]::Ordinal)
            )
            if (-not $allowedFile) {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
            Assert-AgentRoadFileNode $node.FullName
        }
    }
}

function Assert-AgentRoadRetirementTombstone {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TombstoneRoot,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Journal
    )

    if ($Journal.status -cne 'committed' -or $null -eq $Journal.snapshot.previous) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $candidate = $Journal.snapshot.previous
    Assert-AgentRoadPointer $candidate
    $candidateDigest = [string]$candidate.manifestDigest
    $expectedTombstone = [IO.Path]::Combine($script:VersionsRoot, ('.retired-' + $candidateDigest))
    $generationRoot = [IO.Path]::Combine($script:VersionsRoot, $candidateDigest)
    if (
        [IO.Path]::GetFullPath($TombstoneRoot) -cne $TombstoneRoot -or
        [IO.Path]::GetDirectoryName($TombstoneRoot) -cne $script:VersionsRoot -or
        $TombstoneRoot -cne $expectedTombstone -or
        (Test-Path -LiteralPath $generationRoot)
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }

    $active = Read-AgentRoadPointer $script:ActivePath
    $previous = Read-AgentRoadPointer $script:PreviousPath
    if (
        ($null -ne $active -and [string]$active.manifestDigest -ceq $candidateDigest) -or
        ($null -ne $previous -and [string]$previous.manifestDigest -ceq $candidateDigest)
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    Assert-AgentRoadGenerationTombstoneTree $TombstoneRoot
}

function Assert-AgentRoadRollbackTombstone {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TombstoneRoot,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Journal
    )

    $pendingRollback = $Journal.rollbackStatus -cin @('pending', 'failed')
    $terminalRollback = ($Journal.status -ceq 'rolled-back' -and $Journal.rollbackStatus -ceq 'succeeded')
    if (
        $Journal.phase -cne 'rollback' -or
        (-not $pendingRollback -and -not $terminalRollback) -or
        @($Journal.changes) -cnotcontains 'generation-publish-planned'
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $digest = [string]$Journal.manifestDigest
    $expectedTombstone = [IO.Path]::Combine($script:VersionsRoot, ('.rollback-' + $digest))
    $generationRoot = [IO.Path]::Combine($script:VersionsRoot, $digest)
    if (
        [IO.Path]::GetFullPath($TombstoneRoot) -cne $TombstoneRoot -or
        [IO.Path]::GetDirectoryName($TombstoneRoot) -cne $script:VersionsRoot -or
        $TombstoneRoot -cne $expectedTombstone -or
        (Test-Path -LiteralPath $generationRoot)
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $active = Read-AgentRoadPointer $script:ActivePath
    $previous = Read-AgentRoadPointer $script:PreviousPath
    if (
        ($null -ne $active -and [string]$active.manifestDigest -ceq $digest) -or
        ($null -ne $previous -and [string]$previous.manifestDigest -ceq $digest)
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    Assert-AgentRoadGenerationTombstoneTree $TombstoneRoot
}

function Assert-AgentRoadRuntimeTopology {
    param(
        [object]$Journal
    )

    Assert-AgentRoadDirectoryNode $script:RuntimeRoot
    Assert-AgentRoadDirectoryNode $script:StagingRoot
    $runtimeEntries = @(Get-ChildItem -LiteralPath $script:RuntimeRoot -Force)
    foreach ($entry in $runtimeEntries) {
        $expectedPath = [IO.Path]::Combine($script:RuntimeRoot, [string]$entry.Name)
        if (
            -not $entry.PSIsContainer -or
            $entry.Name -cnotin $script:RuntimeEntryNames -or
            $entry.FullName -cne $expectedPath
        ) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        Assert-AgentRoadDirectoryNode $entry.FullName
    }
    if ($runtimeEntries.Name -cnotcontains 'staging') {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }

    $trustKeyExists = $false
    if (Test-Path -LiteralPath $script:TrustRoot) {
        Assert-AgentRoadDirectoryNode $script:TrustRoot
        $trustEntries = @(Get-ChildItem -LiteralPath $script:TrustRoot -Force)
        foreach ($entry in $trustEntries) {
            if (
                $entry.PSIsContainer -or
                $entry.Name -cnotin $script:TrustEntryNames -or
                $entry.FullName -cne $script:TrustKeyPath
            ) {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
            Assert-AgentRoadFileNode $entry.FullName
            $trustKeyExists = $true
        }
    }
    $trustNextPath = Get-AgentRoadControllerTrustNextPath $script:Transaction
    $trustNextExists = Test-Path -LiteralPath $trustNextPath -PathType Leaf
    if ($trustNextExists) {
        if ($trustKeyExists -or $null -ne $Journal) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        Assert-AgentRoadDirectoryNode $script:Transaction.workRoot
        Assert-AgentRoadFileNode $trustNextPath
    }

    $journalExists = Test-Path -LiteralPath $script:JournalPath -PathType Leaf
    if (($null -ne $Journal) -ne $journalExists) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    if (Test-Path -LiteralPath $script:StateRoot) {
        Assert-AgentRoadDirectoryNode $script:StateRoot
        $stateEntries = @(Get-ChildItem -LiteralPath $script:StateRoot -Force)
        foreach ($entry in $stateEntries) {
            $expectedPath = switch -CaseSensitive ([string]$entry.Name) {
                'journal.json' { $script:JournalPath; break }
                'active.json' { $script:ActivePath; break }
                'previous.json' { $script:PreviousPath; break }
                default { $null }
            }
            if (
                $entry.PSIsContainer -or
                $entry.Name -cnotin $script:StateEntryNames -or
                $null -eq $expectedPath -or
                $entry.FullName -cne $expectedPath
            ) {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
            Assert-AgentRoadFileNode $entry.FullName
        }
    }

    $active = Read-AgentRoadPointer $script:ActivePath
    $previous = Read-AgentRoadPointer $script:PreviousPath
    if ($null -eq $active -and $null -ne $previous) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    if ($null -eq $Journal -and ($null -ne $active -or $null -ne $previous)) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    if ($null -ne $Journal) {
        Assert-AgentRoadJournal $Journal
        if (-not $trustKeyExists) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
    }

    $versionEntries = @()
    $generationEntries = @()
    $retirementEntries = @()
    $rollbackEntries = @()
    if (Test-Path -LiteralPath $script:VersionsRoot) {
        Assert-AgentRoadDirectoryNode $script:VersionsRoot
        $versionEntries = @(Get-ChildItem -LiteralPath $script:VersionsRoot -Force)
        foreach ($entry in $versionEntries) {
            if (-not $entry.PSIsContainer -or $entry.FullName -cne [IO.Path]::Combine($script:VersionsRoot, [string]$entry.Name)) {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
            Assert-AgentRoadDirectoryNode $entry.FullName
            if ($entry.Name -cmatch '^[A-F0-9]{64}$') {
                $generationEntries += $entry
            } elseif ($entry.Name -cmatch '^\.retired-([A-F0-9]{64})$') {
                $retirementEntries += $entry
            } elseif ($entry.Name -cmatch '^\.rollback-([A-F0-9]{64})$') {
                $rollbackEntries += $entry
            } else {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
        }
    }
    if ($null -eq $Journal -and $versionEntries.Count -ne 0) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    if ($retirementEntries.Count -gt 1 -or $rollbackEntries.Count -gt 1) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }

    $allowedDigests = @()
    $verifiedPointers = @{}
    foreach ($pointer in @($active, $previous)) {
        if ($null -eq $pointer) {
            continue
        }
        $digest = [string]$pointer.manifestDigest
        $allowedDigests += $digest
        if ($verifiedPointers.ContainsKey($digest)) {
            if (-not (Test-AgentRoadPointerValue $verifiedPointers[$digest] $pointer)) {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
        } else {
            Read-AgentRoadVerifiedGenerationPointer $pointer | Out-Null
            $verifiedPointers[$digest] = $pointer
        }
    }

    if ($null -ne $Journal) {
        if (
            $null -ne $Journal.snapshot.active -and
            $null -ne $Journal.snapshot.previous -and
            [string]$Journal.snapshot.active.manifestDigest -ceq [string]$Journal.snapshot.previous.manifestDigest
        ) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        foreach ($snapshotRecord in @(
            [pscustomobject]@{ role = 'active'; pointer = $Journal.snapshot.active },
            [pscustomobject]@{ role = 'previous'; pointer = $Journal.snapshot.previous }
        )) {
            $pointer = $snapshotRecord.pointer
            if ($null -eq $pointer) {
                continue
            }
            $digest = [string]$pointer.manifestDigest
            $allowedDigests += $digest
            if ($verifiedPointers.ContainsKey($digest)) {
                if (-not (Test-AgentRoadPointerValue $verifiedPointers[$digest] $pointer)) {
                    throw 'RUNTIME_STATE_UNSUPPORTED'
                }
                continue
            }
            $generationRoot = [IO.Path]::Combine($script:VersionsRoot, $digest)
            if (-not (Test-Path -LiteralPath $generationRoot -PathType Container)) {
                $retiredCommittedPrevious = (
                    $Journal.status -ceq 'committed' -and
                    [string]$snapshotRecord.role -ceq 'previous' -and
                    ($null -eq $active -or [string]$active.manifestDigest -cne $digest) -and
                    ($null -eq $previous -or [string]$previous.manifestDigest -cne $digest)
                )
                if ($retiredCommittedPrevious) {
                    continue
                }
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
            Read-AgentRoadVerifiedGenerationPointer $pointer | Out-Null
            $verifiedPointers[$digest] = $pointer
        }

        $journalPointer = $null
        $journalDigest = [string]$Journal.manifestDigest
        $journalGenerationRoot = [IO.Path]::Combine($script:VersionsRoot, $journalDigest)
        if (@($Journal.changes) -ccontains 'generation-publish-planned') {
            $allowedDigests += $journalDigest
            $rollbackMayHaveRemovedGeneration = (
                $Journal.phase -ceq 'rollback' -or
                $Journal.rollbackStatus -cin @('pending', 'failed', 'succeeded') -or
                $Journal.status -ceq 'rolled-back'
            )
            $journalGenerationRequired = (
                -not $rollbackMayHaveRemovedGeneration -and (
                    @($Journal.completedPhases) -ccontains 'materialize-generation' -or
                    @($Journal.changes).Count -gt 2
                )
            )
            if (Test-Path -LiteralPath $journalGenerationRoot -PathType Container) {
                if ($Journal.status -ceq 'rolled-back') {
                    throw 'RUNTIME_STATE_UNSUPPORTED'
                }
                $journalPointer = Read-AgentRoadJournalGenerationPointer
                if ($verifiedPointers.ContainsKey($journalDigest)) {
                    if (-not (Test-AgentRoadPointerValue $verifiedPointers[$journalDigest] $journalPointer)) {
                        throw 'RUNTIME_STATE_UNSUPPORTED'
                    }
                } else {
                    Read-AgentRoadVerifiedGenerationPointer $journalPointer | Out-Null
                    $verifiedPointers[$journalDigest] = $journalPointer
                }
            } elseif ($journalGenerationRequired) {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
        }

        foreach ($entry in $retirementEntries) {
            Assert-AgentRoadRetirementTombstone $entry.FullName $Journal
        }
        foreach ($entry in $rollbackEntries) {
            Assert-AgentRoadRollbackTombstone $entry.FullName $Journal
        }

        $snapshotCaptured = (
            $null -ne $Journal.snapshot.active -or
            $null -ne $Journal.snapshot.previous -or
            @($Journal.completedPhases) -ccontains 'snapshot' -or
            @($Journal.changes).Count -ge 2
        )
        if ($Journal.status -ceq 'committed') {
            if (
                $null -eq $journalPointer -or
                -not (Test-AgentRoadPointerValue $active $journalPointer) -or
                -not (Test-AgentRoadPointerValue $previous $Journal.snapshot.active)
            ) {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
        } elseif ($Journal.status -ceq 'rolled-back') {
            if (
                $null -ne $journalPointer -or
                -not (Test-AgentRoadPointerValue $active $Journal.snapshot.active) -or
                -not (Test-AgentRoadPointerValue $previous $Journal.snapshot.previous)
            ) {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
        } elseif ($snapshotCaptured) {
            $previousPlanned = @($Journal.changes) -ccontains 'previous-replace-planned'
            $activePlanned = @($Journal.changes) -ccontains 'active-replace-planned'
            $rollbackInProgress = (
                $Journal.phase -ceq 'rollback' -or
                $Journal.rollbackStatus -cin @('pending', 'failed')
            )
            if ($rollbackInProgress -and $activePlanned) {
                $validPointers = (
                    ((Test-AgentRoadPointerValue $active $journalPointer) -and
                        (Test-AgentRoadPointerValue $previous $Journal.snapshot.active)) -or
                    ((Test-AgentRoadPointerValue $active $Journal.snapshot.active) -and
                        (Test-AgentRoadPointerValue $previous $Journal.snapshot.active)) -or
                    ((Test-AgentRoadPointerValue $active $Journal.snapshot.active) -and
                        (Test-AgentRoadPointerValue $previous $Journal.snapshot.previous))
                )
            } elseif ($previousPlanned -and -not $activePlanned) {
                $validPointers = (
                    (Test-AgentRoadPointerValue $active $Journal.snapshot.active) -and (
                        (Test-AgentRoadPointerValue $previous $Journal.snapshot.previous) -or
                        (Test-AgentRoadPointerValue $previous $Journal.snapshot.active)
                    )
                )
            } elseif ($activePlanned) {
                $validPointers = (
                    (Test-AgentRoadPointerValue $previous $Journal.snapshot.active) -and (
                        (Test-AgentRoadPointerValue $active $Journal.snapshot.active) -or
                        (Test-AgentRoadPointerValue $active $journalPointer)
                    )
                )
            } else {
                $validPointers = (
                    (Test-AgentRoadPointerValue $active $Journal.snapshot.active) -and
                    (Test-AgentRoadPointerValue $previous $Journal.snapshot.previous)
                )
            }
            if (-not $validPointers) {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
        }
    }

    foreach ($entry in $generationEntries) {
        if (
            $allowedDigests -cnotcontains [string]$entry.Name -or
            -not $verifiedPointers.ContainsKey([string]$entry.Name)
        ) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
    }
}

function Publish-AgentRoadMutableJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Value,
        [Parameter(Mandatory = $true)]
        [string[]]$Fields
    )

    Assert-AgentRoadExactOrderedRecord $Value $Fields 'RUNTIME_STATE_UNSUPPORTED'
    $json = $Value | ConvertTo-Json -Depth 12 -Compress
    $bytes = $script:Utf8.GetBytes($json)
    if ($bytes.Length -lt 2 -or $bytes.Length -gt 32768) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $parent = [IO.Path]::GetDirectoryName($Path)
    Assert-AgentRoadDirectoryNode $parent
    Assert-AgentRoadDirectoryNode $script:Transaction.workRoot
    $nextPath = [IO.Path]::Combine($script:Transaction.workRoot, ('.' + [IO.Path]::GetFileName($Path) + '.' + [guid]::NewGuid().ToString('N') + '.next'))
    $stream = New-AgentRoadRestrictedFileStream $nextPath 4096
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
    Assert-AgentRoadFileNode $nextPath $bytes.Length (Get-AgentRoadBytesSha256 $bytes)
    Assert-AgentRoadDirectoryNode $script:Transaction.workRoot
    Assert-AgentRoadDirectoryNode $parent
    $moved = [AgentRoad.NativeMethods]::MoveFileEx($nextPath, $Path, ($script:MOVEFILE_REPLACE_EXISTING -bor $script:MOVEFILE_WRITE_THROUGH))
    if (-not $moved) {
        throw 'RUNTIME_COMPLETION_UNCERTAIN'
    }
    $published = [IO.File]::ReadAllBytes($Path)
    if ($published.Length -ne $bytes.Length) {
        throw 'RUNTIME_COMPLETION_UNCERTAIN'
    }
    for ($index = 0; $index -lt $bytes.Length; $index += 1) {
        if ($published[$index] -ne $bytes[$index]) {
            throw 'RUNTIME_COMPLETION_UNCERTAIN'
        }
    }
    Assert-AgentRoadFileNode $Path $bytes.Length (Get-AgentRoadBytesSha256 $bytes)
}

function Publish-AgentRoadGeneration {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [string]$Destination,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Capsule,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Manifest,
        [Parameter(Mandatory = $true)]
        [byte[]]$CapsuleBytes
    )

    Assert-AgentRoadDirectoryNode $script:Transaction.workRoot
    Assert-AgentRoadDirectoryNode $script:VersionsRoot
    Assert-AgentRoadGenerationTree $Source
    if (Test-Path -LiteralPath $Destination) {
        Assert-AgentRoadGenerationTree $Destination
        Assert-AgentRoadAdoptedGeneration $Destination $Capsule $Manifest $CapsuleBytes | Out-Null
        return
    }
    if ([IO.Path]::GetDirectoryName($Source) -cne $script:Transaction.workRoot -or [IO.Path]::GetDirectoryName($Destination) -cne $script:VersionsRoot) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    [IO.Directory]::Move($Source, $Destination)
    Assert-AgentRoadGenerationTree $Destination
    Assert-AgentRoadAdoptedGeneration $Destination $Capsule $Manifest $CapsuleBytes | Out-Null
}

function Save-AgentRoadPointerSnapshot {
    $active = Read-AgentRoadPointer $script:ActivePath
    $previous = Read-AgentRoadPointer $script:PreviousPath
    $script:Journal.snapshot = [pscustomobject][ordered]@{
        active = $active
        previous = $previous
    }
    Publish-AgentRoadJournal
}

function Initialize-AgentRoadPointerSnapshot {
    if (
        @($script:Journal.completedPhases) -ccontains 'snapshot' -or
        @($script:Journal.changes) -ccontains 'generation-publish-planned' -or
        $null -ne $script:Journal.snapshot.active -or
        $null -ne $script:Journal.snapshot.previous
    ) {
        return
    }

    Save-AgentRoadPointerSnapshot
}

function Publish-AgentRoadPreviousPointer {
    param(
        [object]$OldActive
    )

    if ($null -eq $OldActive) {
        if (Test-Path -LiteralPath $script:PreviousPath) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        return
    }
    Assert-AgentRoadPointer $OldActive
    Publish-AgentRoadMutableJson $script:PreviousPath $OldActive $script:PointerFields
}

function Publish-AgentRoadActivePointer {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Pointer
    )

    Assert-AgentRoadPointer $Pointer
    Publish-AgentRoadMutableJson $script:ActivePath $Pointer $script:PointerFields
}

function Restore-AgentRoadPointerValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [object]$Value
    )

    if ($null -ne $Value) {
        Assert-AgentRoadPointer $Value
        Publish-AgentRoadMutableJson $Path $Value $script:PointerFields
        return
    }
    if (Test-Path -LiteralPath $Path) {
        Assert-AgentRoadFileNode $Path
        [IO.File]::Delete($Path)
        if (Test-Path -LiteralPath $Path) {
            throw 'RUNTIME_ROLLBACK_INCOMPLETE'
        }
    }
}

function Restore-AgentRoadActivePointer {
    Restore-AgentRoadPointerValue $script:ActivePath $script:Journal.snapshot.active
}

function Restore-AgentRoadPreviousPointer {
    Restore-AgentRoadPointerValue $script:PreviousPath $script:Journal.snapshot.previous
}

function Publish-AgentRoadJournal {
    $script:Journal.revision = [int]$script:Journal.revision + 1
    Assert-AgentRoadJournal $script:Journal
    Publish-AgentRoadMutableJson $script:JournalPath $script:Journal $script:JournalFields
}

function Set-AgentRoadPhase {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Phase
    )

    if ($Phase -cnotin $script:Phases) {
        throw 'RUNTIME_INTERNAL_ERROR'
    }
    $script:Journal.phase = $Phase
    Publish-AgentRoadJournal
}

function Complete-AgentRoadForwardPhase {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Phase
    )

    $completed = @($script:Journal.completedPhases)
    if ($completed.Count -ge $script:ForwardPhases.Count -or $script:ForwardPhases[$completed.Count] -cne $Phase) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $script:Journal.completedPhases = @($completed + $Phase)
    if ($script:Journal.completedPhases.Count -lt $script:ForwardPhases.Count) {
        $script:Journal.phase = $script:ForwardPhases[$script:Journal.completedPhases.Count]
    }
    Publish-AgentRoadJournal
}

function Add-AgentRoadChange {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Change
    )

    $changes = @($script:Journal.changes)
    if ($changes.Count -ge $script:Changes.Count -or $script:Changes[$changes.Count] -cne $Change) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $script:Journal.changes = @($changes + $Change)
    Publish-AgentRoadJournal
}

function Assert-AgentRoadManifest {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Capsule,
        [Parameter(Mandatory = $true)]
        [byte[]]$ManifestBytes,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Manifest
    )

    Assert-AgentRoadExactOrderedRecord $Capsule $script:CapsuleFields 'RUNTIME_SIGNATURE_INVALID'
    Assert-AgentRoadExactOrderedRecord $Manifest $script:ManifestFields 'RUNTIME_SIGNATURE_INVALID'
    Assert-AgentRoadExactOrderedRecord $Manifest.platform $script:ManifestPlatformFields 'RUNTIME_SIGNATURE_INVALID'
    $parsedCreatedAt = [DateTimeOffset]::MinValue
    $dateStyles = (
        [Globalization.DateTimeStyles]::AssumeUniversal -bor
        [Globalization.DateTimeStyles]::AdjustToUniversal
    )
    $createdAtValid = (
        $Manifest.createdAt -is [string] -and
        [DateTimeOffset]::TryParseExact(
            [string]$Manifest.createdAt,
            'yyyy-MM-ddTHH:mm:ss.fffZ',
            [Globalization.CultureInfo]::InvariantCulture,
            $dateStyles,
            [ref]$parsedCreatedAt
        ) -and
        $parsedCreatedAt.ToUniversalTime().ToString(
            'yyyy-MM-ddTHH:mm:ss.fffZ',
            [Globalization.CultureInfo]::InvariantCulture
        ) -ceq [string]$Manifest.createdAt
    )
    $components = @($Manifest.components)
    if (
        $Capsule.schemaVersion -isnot [int] -or $Capsule.schemaVersion -ne 1 -or
        $Capsule.manifestDigest -isnot [string] -or $Capsule.manifestDigest -cnotmatch '^[A-F0-9]{64}$' -or
        (Get-AgentRoadBytesSha256 $ManifestBytes) -cne $Capsule.manifestDigest -or
        $Capsule.generationDigest -isnot [string] -or $Capsule.generationDigest -cnotmatch '^[A-F0-9]{64}$' -or
        $Capsule.signatureAlgorithm -cne 'RSA-SHA256' -or
        $Capsule.signatureBase64 -isnot [string] -or $Capsule.signatureBase64 -cnotmatch '^[A-Za-z0-9+/]{512}$' -or
        $Capsule.controllerKeyId -isnot [string] -or $Capsule.controllerKeyId -cnotmatch '^[A-F0-9]{64}$' -or
        $Capsule.controllerPublicKeyJson -isnot [string] -or
        $Manifest.schemaVersion -isnot [int] -or $Manifest.schemaVersion -ne 1 -or
        $Manifest.deviceId -isnot [string] -or $Manifest.deviceId.Length -gt 64 -or $Manifest.deviceId -cnotmatch '^dev_[a-z0-9]+$' -or
        $Manifest.operationId -isnot [string] -or $Manifest.operationId -cnotmatch '^[a-f0-9]{32}$' -or
        $Manifest.createdAt -isnot [string] -or -not $createdAtValid -or
        $Manifest.platform.os -isnot [string] -or $Manifest.platform.os -cne 'windows' -or
        $Manifest.platform.version -isnot [string] -or $Manifest.platform.version.Length -gt 32 -or
        $Manifest.platform.version -cnotmatch '^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2,3}$' -or
        $Manifest.platform.build -isnot [int] -or $Manifest.platform.build -lt 10240 -or $Manifest.platform.build -gt 99999 -or
        $Manifest.platform.edition -isnot [string] -or [string]::IsNullOrEmpty($Manifest.platform.edition) -or
        $Manifest.platform.edition.Trim() -cne $Manifest.platform.edition -or
        $script:Utf8.GetByteCount($Manifest.platform.edition) -gt 256 -or $Manifest.platform.edition -match '[\x00-\x1F\x7F]' -or
        $Manifest.platform.architecture -isnot [string] -or $Manifest.platform.architecture -cnotin @('x64', 'arm64') -or
        $Manifest.platform.windowsPowerShellVersion -isnot [string] -or $Manifest.platform.windowsPowerShellVersion.Length -gt 32 -or
        $Manifest.platform.windowsPowerShellVersion -cnotmatch '^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){1,3}$' -or
        $Manifest.platform.elevated -isnot [bool] -or -not $Manifest.platform.elevated -or
        $Manifest.generationDigest -cne $Capsule.generationDigest -or
        $Manifest.catalogRevision -isnot [int] -or $Manifest.catalogRevision -lt 1 -or
        $Manifest.catalogDigest -isnot [string] -or $Manifest.catalogDigest -cnotmatch '^[A-F0-9]{64}$' -or
        $Manifest.inventoryDigest -isnot [string] -or $Manifest.inventoryDigest -cnotmatch '^[A-F0-9]{64}$' -or
        $Manifest.acquisition -cne 'mac-relay' -or
        $Manifest.phases -isnot [Array] -or
        @($Manifest.phases).Count -ne $script:Phases.Count -or
        $Manifest.profiles -isnot [Array] -or
        @($Manifest.profiles).Count -ne 1 -or [string]$Manifest.profiles[0] -cne 'core' -or
        $Manifest.requestedProfiles -isnot [Array] -or
        @($Manifest.requestedProfiles).Count -gt 1 -or
        $Manifest.components -isnot [Array] -or
        $components.Count -ne 1
    ) {
        throw 'RUNTIME_SIGNATURE_INVALID'
    }
    for ($index = 0; $index -lt $script:Phases.Count; $index += 1) {
        if ([string]$Manifest.phases[$index] -cne [string]$script:Phases[$index]) {
            throw 'RUNTIME_SIGNATURE_INVALID'
        }
    }
    if (@($Manifest.requestedProfiles).Count -eq 1 -and [string]$Manifest.requestedProfiles[0] -cne 'core') {
        throw 'RUNTIME_SIGNATURE_INVALID'
    }
    $component = $components[0]
    Assert-AgentRoadExactOrderedRecord $component $script:ManifestComponentFields 'RUNTIME_SIGNATURE_INVALID'
    if (
        $component.id -cne $script:CoreComponentId -or
        $component.version -isnot [string] -or $component.version -cnotmatch '^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$' -or
        $component.bytes -isnot [int] -or $component.bytes -lt 1 -or $component.bytes -gt 268435456 -or
        $component.maximumExpandedBytes -isnot [long] -and $component.maximumExpandedBytes -isnot [int] -or
        [long]$component.maximumExpandedBytes -lt 1 -or [long]$component.maximumExpandedBytes -gt 34359738368 -or
        $component.sha256 -isnot [string] -or $component.sha256 -cnotmatch '^[A-F0-9]{64}$' -or
        $component.packaging -cne 'zip' -or
        $component.signerRule -isnot [string] -or $component.signerRule -cnotmatch '^[a-z][a-z0-9-]{0,63}$' -or
        $component.verificationCommandId -cne 'powershell-json-roundtrip'
    ) {
        throw 'RUNTIME_SIGNATURE_INVALID'
    }
}

function ConvertFrom-AgentRoadBase64Url {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if ($Value -cnotmatch '^[A-Za-z0-9_-]+$') {
        throw 'RUNTIME_SIGNATURE_INVALID'
    }
    $base64 = $Value.Replace('-', '+').Replace('_', '/')
    switch ($base64.Length % 4) {
        0 { }
        2 { $base64 += '==' }
        3 { $base64 += '=' }
        default { throw 'RUNTIME_SIGNATURE_INVALID' }
    }
    try {
        return [Convert]::FromBase64String($base64)
    } catch {
        throw 'RUNTIME_SIGNATURE_INVALID'
    }
}

function Assert-AgentRoadControllerSignature {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Capsule,
        [Parameter(Mandatory = $true)]
        [byte[]]$ManifestBytes
    )

    $keyBytes = $script:Utf8.GetBytes([string]$Capsule.controllerPublicKeyJson)
    $key = ConvertFrom-AgentRoadCanonicalJson $keyBytes 4096 'RUNTIME_SIGNATURE_INVALID'
    Assert-AgentRoadExactOrderedRecord $key $script:PublicKeyFields 'RUNTIME_SIGNATURE_INVALID'
    if (
        $key.algorithm -isnot [string] -or
        $key.modulusBase64Url -isnot [string] -or
        $key.exponentBase64Url -isnot [string]
    ) {
        throw 'RUNTIME_SIGNATURE_INVALID'
    }
    $canonicalKey = [pscustomobject][ordered]@{
        algorithm = [string]$key.algorithm
        modulusBase64Url = [string]$key.modulusBase64Url
        exponentBase64Url = [string]$key.exponentBase64Url
    }
    $canonicalKeyJson = $canonicalKey | ConvertTo-Json -Depth 2 -Compress
    if ($canonicalKeyJson -cne [string]$Capsule.controllerPublicKeyJson) {
        throw 'RUNTIME_SIGNATURE_INVALID'
    }
    $modulus = ConvertFrom-AgentRoadBase64Url ([string]$key.modulusBase64Url)
    $exponent = ConvertFrom-AgentRoadBase64Url ([string]$key.exponentBase64Url)
    if (
        $key.algorithm -cne 'RSA-SHA256' -or
        $modulus.Length -ne 384 -or ($modulus[0] -band 0x80) -eq 0 -or
        $exponent.Length -ne 3 -or $exponent[0] -ne 1 -or $exponent[1] -ne 0 -or $exponent[2] -ne 1
    ) {
        throw 'RUNTIME_SIGNATURE_INVALID'
    }
    $keyDomain = $script:Utf8.GetBytes("AGENT_ROAD_CONTROLLER_KEY_V1`0")
    $keyIdentityBytes = New-Object byte[] ($keyDomain.Length + $keyBytes.Length)
    [Array]::Copy($keyDomain, 0, $keyIdentityBytes, 0, $keyDomain.Length)
    [Array]::Copy($keyBytes, 0, $keyIdentityBytes, $keyDomain.Length, $keyBytes.Length)
    if ((Get-AgentRoadBytesSha256 $keyIdentityBytes) -cne [string]$Capsule.controllerKeyId) {
        throw 'RUNTIME_SIGNATURE_INVALID'
    }
    try {
        $signature = [Convert]::FromBase64String([string]$Capsule.signatureBase64)
    } catch {
        throw 'RUNTIME_SIGNATURE_INVALID'
    }
    if ($signature.Length -ne 384 -or [Convert]::ToBase64String($signature) -cne [string]$Capsule.signatureBase64) {
        throw 'RUNTIME_SIGNATURE_INVALID'
    }
    $runtimeDomain = $script:Utf8.GetBytes("AGENT_ROAD_RUNTIME_V1`0")
    $signedBytes = New-Object byte[] ($runtimeDomain.Length + $ManifestBytes.Length)
    [Array]::Copy($runtimeDomain, 0, $signedBytes, 0, $runtimeDomain.Length)
    [Array]::Copy($ManifestBytes, 0, $signedBytes, $runtimeDomain.Length, $ManifestBytes.Length)
    $parameters = New-Object Security.Cryptography.RSAParameters
    $parameters.Modulus = $modulus
    $parameters.Exponent = $exponent
    $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider(3072)
    try {
        $rsa.PersistKeyInCsp = $false
        $rsa.ImportParameters($parameters)
        if (-not $rsa.VerifyData($signedBytes, 'SHA256', $signature)) {
            throw 'RUNTIME_SIGNATURE_INVALID'
        }
    } finally {
        $rsa.Dispose()
    }
}

function Test-AgentRoadExactFileBytes {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [byte[]]$ExpectedBytes,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedSha256
    )

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Length -ne $ExpectedBytes.Length) {
        return $false
    }
    if ((Get-AgentRoadSha256 $Path) -cne $ExpectedSha256) {
        return $false
    }
    $actual = [IO.File]::ReadAllBytes($Path)
    if ($actual.Length -ne $ExpectedBytes.Length) {
        return $false
    }
    for ($index = 0; $index -lt $ExpectedBytes.Length; $index += 1) {
        if ($actual[$index] -ne $ExpectedBytes[$index]) {
            return $false
        }
    }
    return $true
}

function Get-AgentRoadControllerTrustNextPath {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Transaction
    )

    $operationId = [string]$Transaction.operationId
    $manifestDigest = [string]$Transaction.manifestDigest
    $workRoot = [string]$Transaction.workRoot
    if ($operationId -cnotmatch '^[a-f0-9]{32}$' -or $manifestDigest -cnotmatch '^[A-F0-9]{64}$') {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $expectedOperationRoot = [IO.Path]::Combine($script:StagingRoot, $operationId)
    $expectedWorkRoots = @([IO.Path]::Combine($expectedOperationRoot, 'work'), [IO.Path]::Combine($expectedOperationRoot, ('work-' + $manifestDigest)))
    if ($workRoot -cnotin $expectedWorkRoots) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $nextPath = [IO.Path]::Combine($workRoot, '.controller-key.next')
    if (
        [IO.Path]::GetFullPath($nextPath) -cne $nextPath -or
        [IO.Path]::GetDirectoryName($nextPath) -cne $workRoot
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    return $nextPath
}

function Remove-AgentRoadControllerTrustNextFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Transaction
    )

    $expectedPath = Get-AgentRoadControllerTrustNextPath $Transaction
    if ($Path -cne $expectedPath -or (Test-Path -LiteralPath $script:TrustKeyPath)) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    Assert-AgentRoadDirectoryNode $Transaction.workRoot
    Assert-AgentRoadFileNode $Path
    [IO.File]::Delete($Path)
    if (Test-Path -LiteralPath $Path) {
        throw 'RUNTIME_COMPLETION_UNCERTAIN'
    }
}

function Ensure-AgentRoadControllerTrust {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CanonicalKeyJson
    )

    $bytes = $script:Utf8.GetBytes($CanonicalKeyJson)
    $expectedSha256 = Get-AgentRoadBytesSha256 $bytes
    $nextPath = Get-AgentRoadControllerTrustNextPath $script:Transaction
    Assert-AgentRoadDirectoryNode $script:TrustRoot
    Assert-AgentRoadDirectoryNode $script:Transaction.workRoot
    if (Test-Path -LiteralPath $script:TrustKeyPath) {
        Assert-AgentRoadFileNode $script:TrustKeyPath
        if (-not (Test-AgentRoadExactFileBytes $script:TrustKeyPath $bytes $expectedSha256)) {
            throw 'RUNTIME_SIGNATURE_INVALID'
        }
        if (Test-Path -LiteralPath $nextPath) {
            Assert-AgentRoadFileNode $nextPath
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        return
    }

    if (Test-Path -LiteralPath $nextPath) {
        Assert-AgentRoadFileNode $nextPath
        if (-not (Test-AgentRoadExactFileBytes $nextPath $bytes $expectedSha256)) {
            Remove-AgentRoadControllerTrustNextFile $nextPath $script:Transaction
        }
    }
    if (-not (Test-Path -LiteralPath $nextPath)) {
        $stream = New-AgentRoadRestrictedFileStream $nextPath 4096
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
    }
    Assert-AgentRoadFileNode $nextPath $bytes.Length $expectedSha256
    if (-not (Test-AgentRoadExactFileBytes $nextPath $bytes $expectedSha256)) {
        throw 'RUNTIME_COMPLETION_UNCERTAIN'
    }
    Assert-AgentRoadDirectoryNode $script:Transaction.workRoot
    Assert-AgentRoadDirectoryNode $script:TrustRoot
    if (Test-Path -LiteralPath $script:TrustKeyPath) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $moved = [AgentRoad.NativeMethods]::MoveFileEx(
        $nextPath,
        $script:TrustKeyPath,
        $script:MOVEFILE_WRITE_THROUGH
    )
    if (-not $moved) {
        throw 'RUNTIME_COMPLETION_UNCERTAIN'
    }
    Assert-AgentRoadFileNode $script:TrustKeyPath $bytes.Length $expectedSha256
    if (-not (Test-AgentRoadExactFileBytes $script:TrustKeyPath $bytes $expectedSha256)) {
        throw 'RUNTIME_COMPLETION_UNCERTAIN'
    }
    if (Test-Path -LiteralPath $nextPath) {
        throw 'RUNTIME_COMPLETION_UNCERTAIN'
    }
}

function Assert-AgentRoadBootstrapJournalFile {
    if (
        [IO.Path]::GetFullPath($script:BootstrapStageZeroJournalPath) -cne $script:BootstrapStageZeroJournalPath -or
        [IO.Path]::GetDirectoryName($script:BootstrapStageZeroJournalPath) -cne $script:BootstrapRoot -or
        -not (Test-Path -LiteralPath $script:BootstrapStageZeroJournalPath -PathType Leaf)
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $item = Get-Item -LiteralPath $script:BootstrapStageZeroJournalPath -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    Get-AgentRoadFileLinkCount $script:BootstrapStageZeroJournalPath | Out-Null

    $acl = [IO.File]::GetAccessControl($script:BootstrapStageZeroJournalPath)
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if (
        -not $acl.AreAccessRulesProtected -or
        -not $acl.AreAccessRulesCanonical -or
        $owner -cne 'S-1-5-32-544' -or
        $rules.Count -ne 2
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $seen = @()
    foreach ($rule in $rules) {
        $sid = [string]$rule.IdentityReference.Value
        if (
            $rule.IsInherited -or
            $sid -cnotin @('S-1-5-18', 'S-1-5-32-544') -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None
        ) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        $seen += $sid
    }
    if ($seen -cnotcontains 'S-1-5-18' -or $seen -cnotcontains 'S-1-5-32-544') {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
}

function Read-AgentRoadBootstrapDeviceId {
    Assert-AgentRoadDirectoryNode $script:AgentRoadRoot
    Assert-AgentRoadDirectoryNode $script:BootstrapRoot
    Assert-AgentRoadBootstrapJournalFile
    $bytes = [IO.File]::ReadAllBytes($script:BootstrapStageZeroJournalPath)
    $journal = ConvertFrom-AgentRoadCanonicalJson $bytes 4096 'RUNTIME_STATE_UNSUPPORTED'
    Assert-AgentRoadExactFieldSet $journal $script:BootstrapJournalFields 'RUNTIME_STATE_UNSUPPORTED'
    $json = $script:Utf8.GetString($bytes)
    if (($journal | ConvertTo-Json -Depth 4 -Compress) -cne $json) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }

    $parsedUpdatedAt = [DateTimeOffset]::MinValue
    $dateStyles = (
        [Globalization.DateTimeStyles]::AssumeUniversal -bor
        [Globalization.DateTimeStyles]::AdjustToUniversal
    )
    $updatedAtValid = (
        $journal.updatedAt -is [string] -and
        [DateTimeOffset]::TryParseExact(
            [string]$journal.updatedAt,
            'yyyy-MM-ddTHH:mm:ss.fffffffZ',
            [Globalization.CultureInfo]::InvariantCulture,
            $dateStyles,
            [ref]$parsedUpdatedAt
        ) -and
        $parsedUpdatedAt.ToUniversalTime().ToString(
            'yyyy-MM-ddTHH:mm:ss.fffffffZ',
            [Globalization.CultureInfo]::InvariantCulture
        ) -ceq [string]$journal.updatedAt
    )
    if (
        $journal.schemaVersion -isnot [int] -or $journal.schemaVersion -ne 1 -or
        $journal.phase -isnot [string] -or $journal.phase -cne 'stage-zero' -or
        $journal.deviceId -isnot [string] -or $journal.deviceId.Length -gt 64 -or
        $journal.deviceId -cnotmatch '^dev_[a-z0-9]+$' -or
        $journal.updatedAt -isnot [string] -or -not $updatedAtValid -or
        $journal.checkpoints -isnot [Array] -or @($journal.checkpoints).Count -ne 1 -or
        $journal.checkpoints[0] -isnot [string] -or $journal.checkpoints[0] -cne 'preflight'
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    return [string]$journal.deviceId
}

function Assert-AgentRoadMachinePreconditions {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Manifest
    )

    $localDeviceId = Read-AgentRoadBootstrapDeviceId
    if ($localDeviceId -cne [string]$Manifest.deviceId) {
        throw 'RUNTIME_INVENTORY_CHANGED'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'RUNTIME_INVENTORY_CHANGED'
    }
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $architecture = switch -CaseSensitive ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { 'x64'; break }
        'ARM64' { 'arm64'; break }
        default { throw 'RUNTIME_INVENTORY_CHANGED' }
    }
    if (
        [string]$Manifest.platform.os -cne 'windows' -or
        [string]$os.Version -cne [string]$Manifest.platform.version -or
        [int]$os.BuildNumber -ne [int]$Manifest.platform.build -or
        [string]$os.Caption -cne [string]$Manifest.platform.edition -or
        $architecture -cne [string]$Manifest.platform.architecture -or
        $PSVersionTable.PSVersion.ToString() -cne [string]$Manifest.platform.windowsPowerShellVersion -or
        -not [bool]$Manifest.platform.elevated
    ) {
        throw 'RUNTIME_INVENTORY_CHANGED'
    }
    foreach ($subKey in @(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )) {
        $key = $null
        try {
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subKey, $false)
            if ($null -ne $key) {
                throw 'RUNTIME_INVENTORY_CHANGED'
            }
        } catch {
            throw 'RUNTIME_INVENTORY_CHANGED'
        } finally {
            if ($null -ne $key) {
                $key.Dispose()
            }
        }
    }
    $sessionManager = $null
    try {
        $sessionManager = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            'SYSTEM\CurrentControlSet\Control\Session Manager',
            $false
        )
        if ($null -eq $sessionManager) {
            throw 'RUNTIME_INVENTORY_CHANGED'
        }
        $valueNames = @($sessionManager.GetValueNames())
        if ($valueNames -icontains 'PendingFileRenameOperations') {
            throw 'RUNTIME_INVENTORY_CHANGED'
        }
    } catch {
        throw 'RUNTIME_INVENTORY_CHANGED'
    } finally {
        if ($null -ne $sessionManager) {
            $sessionManager.Dispose()
        }
    }
    $drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($script:RuntimeRoot))
    $transactionReserveBytes = [long]268435456
    $maximumExpandedBytes = [long]$Manifest.components[0].maximumExpandedBytes
    if ($maximumExpandedBytes -gt ([long]::MaxValue - $transactionReserveBytes)) {
        throw 'RUNTIME_INVENTORY_CHANGED'
    }
    $requiredFreeBytes = [long]($transactionReserveBytes + $maximumExpandedBytes)
    if ([long]$drive.AvailableFreeSpace -lt $requiredFreeBytes) {
        throw 'RUNTIME_INVENTORY_CHANGED'
    }
}

function Assert-AgentRoadArtifact {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Transaction,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Component
    )

    Assert-AgentRoadDirectoryNode $Transaction.transactionRoot
    Assert-AgentRoadDirectoryNode $Transaction.filesRoot
    $transactionEntries = @(Get-ChildItem -LiteralPath $Transaction.transactionRoot -Force)
    if ($transactionEntries.Count -ne 2 -or $transactionEntries.Name -cnotcontains 'capsule.json' -or $transactionEntries.Name -cnotcontains 'files') {
        throw 'RUNTIME_ARTIFACT_INVALID'
    }
    $fileName = $script:CoreComponentId + '-' + [string]$Component.version + '.zip'
    $files = @(Get-ChildItem -LiteralPath $Transaction.filesRoot -Force)
    if ($files.Count -ne 1 -or $files[0].PSIsContainer -or $files[0].Name -cne $fileName) {
        throw 'RUNTIME_ARTIFACT_INVALID'
    }
    Assert-AgentRoadFileNode $files[0].FullName ([long]$Component.bytes) ([string]$Component.sha256)
    return $files[0].FullName
}

function Write-AgentRoadImmutableBytes {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

    $parent = [IO.Path]::GetDirectoryName($Path)
    Assert-AgentRoadDirectoryNode $parent
    $stream = New-AgentRoadRestrictedFileStream $Path 4096
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
    Assert-AgentRoadFileNode $Path $Bytes.Length (Get-AgentRoadBytesSha256 $Bytes)
}

function Write-AgentRoadGenerationFiles {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GenerationRoot,
        [Parameter(Mandatory = $true)]
        [byte[]]$CapsuleBytes
    )

    $binRoot = [IO.Path]::Combine($GenerationRoot, 'bin')
    $scriptsRoot = [IO.Path]::Combine($GenerationRoot, 'scripts')
    Ensure-AgentRoadRestrictedDirectory $binRoot $GenerationRoot
    Ensure-AgentRoadRestrictedDirectory $scriptsRoot $GenerationRoot
    $pwshCommand = "@echo off`r`n`"%~dp0..\tools\powershell-7\pwsh.exe`" %*`r`n"
    $environmentCommand = "@echo off`r`nset `"AGENT_ROAD_RUNTIME_ROOT=%~dp0`"`r`n"
    $environmentPowerShell = "`$AgentRoadRuntimeRoot = `$PSScriptRoot`r`n"
    $inventoryPowerShell = @'
#requires -Version 5.1
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$generationRoot = Split-Path -Parent $PSScriptRoot
$versionsRoot = Split-Path -Parent $generationRoot
$runtimeRoot = Split-Path -Parent $versionsRoot
$active = Join-Path (Join-Path $runtimeRoot 'state') 'active.json'
if (-not (Test-Path -LiteralPath $active -PathType Leaf)) { exit 41 }
$value = Get-Content -LiteralPath $active -Raw -Encoding UTF8 | ConvertFrom-Json
[Console]::Out.Write(($value | ConvertTo-Json -Depth 4 -Compress))
'@
    $files = [ordered]@{
        'capsule.json' = $CapsuleBytes
        'bin\pwsh.cmd' = $script:Utf8.GetBytes($pwshCommand)
        'env.cmd' = $script:Utf8.GetBytes($environmentCommand)
        'env.ps1' = $script:Utf8.GetBytes($environmentPowerShell)
        'scripts\runtime-inventory.ps1' = $script:Utf8.GetBytes($inventoryPowerShell)
        'scripts\runtime-provision-core.ps1' = [IO.File]::ReadAllBytes($PSCommandPath)
    }
    foreach ($relative in $files.Keys) {
        Write-AgentRoadImmutableBytes ([IO.Path]::Combine($GenerationRoot, $relative)) ([byte[]]$files[$relative])
    }
}

function Get-AgentRoadFixedFileReceipts {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GenerationRoot
    )

    $relativePaths = @(
        'bin/pwsh.cmd',
        'capsule.json',
        'env.cmd',
        'env.ps1',
        'scripts/runtime-inventory.ps1',
        'scripts/runtime-provision-core.ps1'
    )
    $records = New-Object Collections.Generic.List[object]
    foreach ($relative in $relativePaths) {
        $nativeRelative = $relative.Replace('/', '\')
        $path = [IO.Path]::Combine($GenerationRoot, $nativeRelative)
        Assert-AgentRoadFileNode $path
        $item = Get-Item -LiteralPath $path -Force
        $records.Add([pscustomobject][ordered]@{
            path = $relative
            bytes = [int]$item.Length
            sha256 = Get-AgentRoadSha256 $path
        })
    }
    return $records.ToArray()
}

function Invoke-AgentRoadPowerShellCheck {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,
        [Parameter(Mandatory = $true)]
        [string]$Command,
        [Parameter(Mandatory = $true)]
        [string]$Expected
    )

    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $Executable
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
    $start.Arguments = '-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + $encodedCommand
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) {
            throw 'RUNTIME_SELF_TEST_FAILED'
        }
        $outputBuilder = New-Object Text.StringBuilder
        $errorBuilder = New-Object Text.StringBuilder
        $outputBuffer = New-Object char[] 1024
        $errorBuffer = New-Object char[] 1024
        $outputTask = $process.StandardOutput.ReadAsync($outputBuffer, 0, $outputBuffer.Length)
        $errorTask = $process.StandardError.ReadAsync($errorBuffer, 0, $errorBuffer.Length)
        $outputClosed = $false
        $errorClosed = $false
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while (-not ($outputClosed -and $errorClosed -and $process.HasExited)) {
            if ($timer.ElapsedMilliseconds -ge 30000) {
                try { $process.Kill() } catch { }
                throw 'RUNTIME_SELF_TEST_FAILED'
            }
            $pending = New-Object 'Collections.Generic.List[Threading.Tasks.Task]'
            if (-not $outputClosed) {
                $pending.Add([Threading.Tasks.Task]$outputTask)
            }
            if (-not $errorClosed) {
                $pending.Add([Threading.Tasks.Task]$errorTask)
            }
            if ($pending.Count -gt 0) {
                [Threading.Tasks.Task]::WaitAny($pending.ToArray(), 100) | Out-Null
            } else {
                $process.WaitForExit(100) | Out-Null
            }
            if (-not $outputClosed -and $outputTask.IsCompleted) {
                $count = [int]$outputTask.Result
                if ($count -eq 0) {
                    $outputClosed = $true
                } else {
                    if ($outputBuilder.Length -gt (4096 - $count)) {
                        try { $process.Kill() } catch { }
                        throw 'RUNTIME_SELF_TEST_FAILED'
                    }
                    $outputBuilder.Append($outputBuffer, 0, $count) | Out-Null
                    $outputTask = $process.StandardOutput.ReadAsync($outputBuffer, 0, $outputBuffer.Length)
                }
            }
            if (-not $errorClosed -and $errorTask.IsCompleted) {
                $count = [int]$errorTask.Result
                if ($count -eq 0) {
                    $errorClosed = $true
                } else {
                    if ($errorBuilder.Length -gt (4096 - $count)) {
                        try { $process.Kill() } catch { }
                        throw 'RUNTIME_SELF_TEST_FAILED'
                    }
                    $errorBuilder.Append($errorBuffer, 0, $count) | Out-Null
                    $errorTask = $process.StandardError.ReadAsync($errorBuffer, 0, $errorBuffer.Length)
                }
            }
        }
        $process.WaitForExit()
        $output = $outputBuilder.ToString()
        $errorOutput = $errorBuilder.ToString()
        if ($process.ExitCode -ne 0 -or -not [string]::IsNullOrEmpty($errorOutput) -or $output -cne $Expected) {
            throw 'RUNTIME_SELF_TEST_FAILED'
        }
    } finally {
        $process.Dispose()
    }
}

function Invoke-AgentRoadExecutableVerification {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolRoot,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Component
    )

    $executable = [IO.Path]::Combine($ToolRoot, 'pwsh.exe')
    Assert-AgentRoadFileNode $executable
    $signature = Get-AuthenticodeSignature -LiteralPath $executable
    if (
        [string]$signature.Status -cne 'Valid' -or
        $null -eq $signature.SignerCertificate -or
        [string]$Component.signerRule -cne 'microsoft-corporation' -or
        [string]$signature.SignerCertificate.Subject -cnotmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)'
    ) {
        throw 'RUNTIME_SELF_TEST_FAILED'
    }
    Invoke-AgentRoadPowerShellCheck $executable '[Console]::Out.Write($PSVersionTable.PSVersion.ToString())' ([string]$Component.version)
    Invoke-AgentRoadPowerShellCheck $executable "[Console]::Out.Write((@{agentRoad=1}|ConvertTo-Json -Compress))" '{"agentRoad":1}'
}

function New-AgentRoadReceipt {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Capsule,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Manifest,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Tree,
        [Parameter(Mandatory = $true)]
        [object[]]$Files
    )

    $component = $Manifest.components[0]
    return [pscustomobject][ordered]@{
        schemaVersion = 1
        receiptFormatRevision = 1
        operationId = [string]$Manifest.operationId
        manifestDigest = [string]$Capsule.manifestDigest
        generationDigest = [string]$Capsule.generationDigest
        catalogRevision = [int]$Manifest.catalogRevision
        catalogDigest = [string]$Manifest.catalogDigest
        controllerKeyId = [string]$Capsule.controllerKeyId
        profiles = @('core')
        components = @([pscustomobject][ordered]@{
            id = 'powershell-7'
            version = [string]$component.version
            bytes = [int]$component.bytes
            sha256 = [string]$component.sha256
            installRoot = 'tools/powershell-7'
            fileCount = [int]$Tree.fileCount
            directoryCount = [int]$Tree.directoryCount
            expandedBytes = [long]$Tree.expandedBytes
            treeSha256 = [string]$Tree.treeSha256
            verificationCommandId = 'powershell-json-roundtrip'
            verified = $true
        })
        files = @($Files)
        restartRequired = $false
    }
}

function Write-AgentRoadReceipt {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GenerationRoot,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Receipt
    )

    Assert-AgentRoadReceipt $Receipt
    $json = $Receipt | ConvertTo-Json -Depth 10 -Compress
    $bytes = $script:Utf8.GetBytes($json)
    if ($bytes.Length -gt 32768) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    Write-AgentRoadImmutableBytes ([IO.Path]::Combine($GenerationRoot, 'receipt.json')) $bytes
    return [pscustomobject]@{
        bytes = $bytes.Length
        sha256 = Get-AgentRoadBytesSha256 $bytes
    }
}

function New-AgentRoadPointer {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Capsule,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Manifest,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$ReceiptIdentity
    )

    $pointer = [pscustomobject][ordered]@{
        schemaVersion = 1
        receiptFormatRevision = 1
        manifestDigest = [string]$Capsule.manifestDigest
        generationDigest = [string]$Capsule.generationDigest
        catalogRevision = [int]$Manifest.catalogRevision
        catalogDigest = [string]$Manifest.catalogDigest
        receiptBytes = [int]$ReceiptIdentity.bytes
        receiptSha256 = [string]$ReceiptIdentity.sha256
    }
    Assert-AgentRoadPointer $pointer
    return $pointer
}

function Assert-AgentRoadAdoptedGeneration {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GenerationRoot,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Capsule,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Manifest,
        [Parameter(Mandatory = $true)]
        [byte[]]$CapsuleBytes
    )

    $receiptPath = [IO.Path]::Combine($GenerationRoot, 'receipt.json')
    $capsulePath = [IO.Path]::Combine($GenerationRoot, 'capsule.json')
    Assert-AgentRoadGenerationTree $GenerationRoot
    Assert-AgentRoadExactGenerationTopology $GenerationRoot
    Assert-AgentRoadFileNode $receiptPath
    Assert-AgentRoadFileNode $capsulePath
    $storedCapsuleBytes = [IO.File]::ReadAllBytes($capsulePath)
    if ($storedCapsuleBytes.Length -ne $CapsuleBytes.Length) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    for ($index = 0; $index -lt $CapsuleBytes.Length; $index += 1) {
        if ($storedCapsuleBytes[$index] -ne $CapsuleBytes[$index]) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
    }
    $receiptBytes = [IO.File]::ReadAllBytes($receiptPath)
    $receipt = ConvertFrom-AgentRoadCanonicalJson $receiptBytes 32768 'RUNTIME_STATE_UNSUPPORTED'
    Assert-AgentRoadReceipt $receipt
    if (
        [string]$receipt.operationId -cne [string]$Manifest.operationId -or
        [string]$receipt.manifestDigest -cne [string]$Capsule.manifestDigest -or
        [string]$receipt.generationDigest -cne [string]$Capsule.generationDigest -or
        [int]$receipt.catalogRevision -ne [int]$Manifest.catalogRevision -or
        [string]$receipt.catalogDigest -cne [string]$Manifest.catalogDigest -or
        [string]$receipt.controllerKeyId -cne [string]$Capsule.controllerKeyId
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $toolRoot = [IO.Path]::Combine($GenerationRoot, 'tools\powershell-7')
    Invoke-AgentRoadExecutableVerification $toolRoot $Manifest.components[0]
    $tree = Get-AgentRoadToolTreeRecord $toolRoot
    $files = Get-AgentRoadFixedFileReceipts $GenerationRoot
    $expectedReceipt = New-AgentRoadReceipt $Capsule $Manifest $tree $files
    if (($receipt | ConvertTo-Json -Depth 10 -Compress) -cne ($expectedReceipt | ConvertTo-Json -Depth 10 -Compress)) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $identity = [pscustomobject]@{
        bytes = $receiptBytes.Length
        sha256 = Get-AgentRoadBytesSha256 $receiptBytes
    }
    return New-AgentRoadPointer $Capsule $Manifest $identity
}

function Invoke-AgentRoadMaterializeGeneration {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Capsule,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Manifest,
        [Parameter(Mandatory = $true)]
        [byte[]]$CapsuleBytes,
        [Parameter(Mandatory = $true)]
        [string]$ArchivePath
    )

    $generationRoot = [IO.Path]::Combine($script:Transaction.workRoot, 'generation')
    $destination = [IO.Path]::Combine($script:VersionsRoot, [string]$Capsule.manifestDigest)
    if (Test-Path -LiteralPath $destination) {
        $script:NewPointer = Assert-AgentRoadAdoptedGeneration $destination $Capsule $Manifest $CapsuleBytes
        return $destination
    }
    if (Test-Path -LiteralPath $generationRoot) {
        Remove-AgentRoadOwnedTree $generationRoot
    }
    Ensure-AgentRoadRestrictedDirectory $generationRoot $script:Transaction.workRoot
    $toolsRoot = [IO.Path]::Combine($generationRoot, 'tools')
    Ensure-AgentRoadRestrictedDirectory $toolsRoot $generationRoot
    $toolRoot = [IO.Path]::Combine($toolsRoot, 'powershell-7')
    Ensure-AgentRoadRestrictedDirectory $toolRoot $toolsRoot
    Expand-AgentRoadPowerShellArchive $ArchivePath $toolRoot ([long]$Manifest.components[0].maximumExpandedBytes) | Out-Null
    foreach ($item in @(Get-ChildItem -LiteralPath $toolRoot -Force -Recurse)) {
        if ($item.PSIsContainer) {
            Assert-AgentRoadDirectoryNode $item.FullName
        } else {
            Assert-AgentRoadFileNode $item.FullName
        }
    }
    Write-AgentRoadGenerationFiles $generationRoot $CapsuleBytes
    Invoke-AgentRoadExecutableVerification $toolRoot $Manifest.components[0]
    $tree = Get-AgentRoadToolTreeRecord $toolRoot
    $files = Get-AgentRoadFixedFileReceipts $generationRoot
    $receipt = New-AgentRoadReceipt $Capsule $Manifest $tree $files
    $receiptIdentity = Write-AgentRoadReceipt $generationRoot $receipt
    $script:NewPointer = New-AgentRoadPointer $Capsule $Manifest $receiptIdentity
    Assert-AgentRoadGenerationTree $generationRoot
    if (@($script:Journal.changes) -cnotcontains 'generation-publish-planned') {
        Add-AgentRoadChange 'generation-publish-planned'
    }
    Publish-AgentRoadGeneration $generationRoot $destination $Capsule $Manifest $CapsuleBytes
    return $destination
}

function Invoke-AgentRoadSelfTest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GenerationRoot,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Manifest
    )

    $toolRoot = [IO.Path]::Combine($GenerationRoot, 'tools\powershell-7')
    Invoke-AgentRoadExecutableVerification $toolRoot $Manifest.components[0]
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

function Assert-AgentRoadPointerTransition {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [object]$Before,
        [object]$After
    )

    $current = Read-AgentRoadPointer $Path
    if (-not (Test-AgentRoadPointerValue $current $Before) -and -not (Test-AgentRoadPointerValue $current $After)) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
}

function Assert-AgentRoadRollbackPointerTransitions {
    $currentActive = Read-AgentRoadPointer $script:ActivePath
    $currentPrevious = Read-AgentRoadPointer $script:PreviousPath
    $activeMutationPlanned = @($script:Journal.changes) -ccontains 'active-replace-planned'
    $previousMutationPlanned = @($script:Journal.changes) -ccontains 'previous-replace-planned'

    if (-not (Test-AgentRoadPointerValue $currentActive $script:Journal.snapshot.active)) {
        if (-not $activeMutationPlanned) {
            throw 'RUNTIME_ROLLBACK_INCOMPLETE'
        }
        $newPointer = Read-AgentRoadJournalGenerationPointer
        if (-not (Test-AgentRoadPointerValue $currentActive $newPointer)) {
            throw 'RUNTIME_ROLLBACK_INCOMPLETE'
        }
    }
    if (-not (Test-AgentRoadPointerValue $currentPrevious $script:Journal.snapshot.previous)) {
        if (
            -not $previousMutationPlanned -or
            -not (Test-AgentRoadPointerValue $currentPrevious $script:Journal.snapshot.active)
        ) {
            throw 'RUNTIME_ROLLBACK_INCOMPLETE'
        }
    }
}

function Invoke-AgentRoadActivation {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Pointer,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Capsule,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Manifest
    )

    $oldActive = $script:Journal.snapshot.active
    if (@($script:Journal.changes) -cnotcontains 'previous-replace-planned') {
        Add-AgentRoadChange 'previous-replace-planned'
    }
    Assert-AgentRoadPointerTransition $script:PreviousPath $script:Journal.snapshot.previous $oldActive
    Publish-AgentRoadPreviousPointer $oldActive
    if (@($script:Journal.changes) -cnotcontains 'active-replace-planned') {
        Add-AgentRoadChange 'active-replace-planned'
    }
    Assert-AgentRoadPointerTransition $script:ActivePath $script:Journal.snapshot.active $Pointer
    Publish-AgentRoadActivePointer $Pointer
}

function Invoke-AgentRoadValidation {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Pointer,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Capsule,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Manifest
    )

    try {
        $active = Read-AgentRoadPointer $script:ActivePath
        if (($active | ConvertTo-Json -Compress) -cne ($Pointer | ConvertTo-Json -Compress)) {
            throw 'RUNTIME_ACTIVATION_FAILED'
        }
        $generationRoot = [IO.Path]::Combine($script:VersionsRoot, [string]$active.manifestDigest)
        $capsulePath = [IO.Path]::Combine($generationRoot, 'capsule.json')
        Assert-AgentRoadFileNode $capsulePath
        $publishedCapsuleBytes = [IO.File]::ReadAllBytes($capsulePath)
        $publishedCapsule = ConvertFrom-AgentRoadCanonicalJson $publishedCapsuleBytes 131072 'RUNTIME_ACTIVATION_FAILED'
        Assert-AgentRoadExactOrderedRecord $publishedCapsule $script:CapsuleFields 'RUNTIME_ACTIVATION_FAILED'
        $publishedManifestBytes = $script:Utf8.GetBytes([string]$publishedCapsule.manifestJson)
        $publishedManifest = ConvertFrom-AgentRoadCanonicalJson $publishedManifestBytes 65536 'RUNTIME_ACTIVATION_FAILED'
        Assert-AgentRoadManifest $publishedCapsule $publishedManifestBytes $publishedManifest
        Assert-AgentRoadControllerSignature $publishedCapsule $publishedManifestBytes
        if (
            [string]$publishedCapsule.manifestDigest -cne [string]$Capsule.manifestDigest -or
            [string]$publishedCapsule.generationDigest -cne [string]$Manifest.generationDigest -or
            [string]$publishedManifest.operationId -cne [string]$Manifest.operationId
        ) {
            throw 'RUNTIME_ACTIVATION_FAILED'
        }
        $validatedPointer = Assert-AgentRoadAdoptedGeneration $generationRoot $publishedCapsule $publishedManifest $publishedCapsuleBytes
        if (($active | ConvertTo-Json -Compress) -cne ($validatedPointer | ConvertTo-Json -Compress)) {
            throw 'RUNTIME_ACTIVATION_FAILED'
        }
    } catch {
        throw 'RUNTIME_ACTIVATION_FAILED'
    }
}

function Read-AgentRoadCommittedRuntime {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Invocation
    )

    if (
        $script:Journal.status -cne 'committed' -or
        [string]$script:Journal.operationId -cne [string]$Invocation.operationId -or
        [string]$script:Journal.manifestDigest -cne [string]$Invocation.manifestDigest
    ) {
        throw 'RUNTIME_OPERATION_CONFLICT'
    }
    Assert-AgentRoadDirectoryNode $script:TrustRoot
    Assert-AgentRoadDirectoryNode $script:VersionsRoot
    Assert-AgentRoadDirectoryNode $script:StateRoot
    if (-not (Test-Path -LiteralPath $script:TrustKeyPath -PathType Leaf)) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $active = Read-AgentRoadPointer $script:ActivePath
    if (
        $null -eq $active -or
        [string]$active.manifestDigest -cne [string]$script:Journal.manifestDigest -or
        [string]$active.generationDigest -cne [string]$script:Journal.generationDigest -or
        [string]$active.catalogDigest -cne [string]$script:Journal.catalogDigest
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $generationRoot = [IO.Path]::Combine($script:VersionsRoot, [string]$active.manifestDigest)
    $capsulePath = [IO.Path]::Combine($generationRoot, 'capsule.json')
    Assert-AgentRoadFileNode $capsulePath
    $capsuleBytes = [IO.File]::ReadAllBytes($capsulePath)
    $capsule = ConvertFrom-AgentRoadCanonicalJson $capsuleBytes 131072 'RUNTIME_STATE_UNSUPPORTED'
    Assert-AgentRoadExactOrderedRecord $capsule $script:CapsuleFields 'RUNTIME_STATE_UNSUPPORTED'
    $manifestBytes = $script:Utf8.GetBytes([string]$capsule.manifestJson)
    $manifest = ConvertFrom-AgentRoadCanonicalJson $manifestBytes 65536 'RUNTIME_STATE_UNSUPPORTED'
    Assert-AgentRoadManifest $capsule $manifestBytes $manifest
    Assert-AgentRoadControllerSignature $capsule $manifestBytes
    if (
        [string]$manifest.operationId -cne [string]$script:Journal.operationId -or
        [string]$capsule.manifestDigest -cne [string]$script:Journal.manifestDigest -or
        [string]$capsule.generationDigest -cne [string]$script:Journal.generationDigest -or
        [string]$manifest.catalogDigest -cne [string]$script:Journal.catalogDigest -or
        [string]$manifest.inventoryDigest -cne [string]$script:Journal.inventoryDigest -or
        [string]$capsule.controllerKeyId -cne [string]$script:Journal.controllerKeyId -or
        ((@($manifest.requestedProfiles) | ConvertTo-Json -Compress) -cne (@($script:Journal.requestedProfiles) | ConvertTo-Json -Compress))
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    Ensure-AgentRoadControllerTrust ([string]$capsule.controllerPublicKeyJson)
    Invoke-AgentRoadValidation $active $capsule $manifest
    return [pscustomobject]@{
        capsule = $capsule
        capsuleBytes = $capsuleBytes
        manifest = $manifest
    }
}

function Invoke-AgentRoadOldGenerationSmokeTest {
    if ($null -eq $script:Journal.snapshot.active) {
        return
    }
    $oldRoot = [IO.Path]::Combine($script:VersionsRoot, [string]$script:Journal.snapshot.active.manifestDigest)
    Assert-AgentRoadGenerationTree $oldRoot
    $oldExecutable = [IO.Path]::Combine($oldRoot, 'tools\powershell-7\pwsh.exe')
    Assert-AgentRoadFileNode $oldExecutable
    Invoke-AgentRoadPowerShellCheck $oldExecutable "[Console]::Out.Write((@{agentRoad=1}|ConvertTo-Json -Compress))" '{"agentRoad":1}'
}

function Remove-AgentRoadNewGeneration {
    if (
        $null -eq $script:Journal -or
        @($script:Journal.changes) -cnotcontains 'generation-publish-planned'
    ) {
        return
    }
    $newManifestDigest = [string]$script:Journal.manifestDigest
    $newRoot = [IO.Path]::Combine($script:VersionsRoot, $newManifestDigest)
    $tombstoneRoot = [IO.Path]::Combine($script:VersionsRoot, ('.rollback-' + $newManifestDigest))
    $oldActiveDigest = if ($null -eq $script:Journal.snapshot.active) { $null } else { [string]$script:Journal.snapshot.active.manifestDigest }
    $oldPreviousDigest = if ($null -eq $script:Journal.snapshot.previous) { $null } else { [string]$script:Journal.snapshot.previous.manifestDigest }
    if ($newManifestDigest -cin @($oldActiveDigest, $oldPreviousDigest)) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $hasGeneration = Test-Path -LiteralPath $newRoot
    $hasTombstone = Test-Path -LiteralPath $tombstoneRoot
    if ($hasGeneration -and $hasTombstone) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    if ($hasTombstone) {
        Assert-AgentRoadRollbackTombstone $tombstoneRoot $script:Journal
        Remove-AgentRoadOwnedTree $tombstoneRoot
        return
    }
    if (-not $hasGeneration) {
        return
    }

    $journalPointer = Read-AgentRoadJournalGenerationPointer
    Read-AgentRoadVerifiedGenerationPointer $journalPointer | Out-Null
    $currentActive = Read-AgentRoadPointer $script:ActivePath
    $currentPrevious = Read-AgentRoadPointer $script:PreviousPath
    if (
        ($null -ne $currentActive -and [string]$currentActive.manifestDigest -ceq $newManifestDigest) -or
        ($null -ne $currentPrevious -and [string]$currentPrevious.manifestDigest -ceq $newManifestDigest)
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    if ((Test-Path -LiteralPath $tombstoneRoot) -or -not (Test-Path -LiteralPath $newRoot -PathType Container)) {
        throw 'RUNTIME_COMPLETION_UNCERTAIN'
    }
    [IO.Directory]::Move($newRoot, $tombstoneRoot)
    if ((Test-Path -LiteralPath $newRoot) -or -not (Test-Path -LiteralPath $tombstoneRoot -PathType Container)) {
        throw 'RUNTIME_COMPLETION_UNCERTAIN'
    }
    Assert-AgentRoadRollbackTombstone $tombstoneRoot $script:Journal
    Remove-AgentRoadOwnedTree $tombstoneRoot
}

function Invoke-AgentRoadRollback {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OriginalFailure
    )

    Assert-AgentRoadJournalTransactionBinding $script:Journal $script:Transaction
    try {
        $script:Journal.status = 'failed'
        $script:Journal.failureCode = $OriginalFailure
        $script:Journal.rollbackStatus = 'pending'
        $script:Journal.phase = 'rollback'
        Publish-AgentRoadJournal
        $pointerMutationPlanned = (
            @($script:Journal.changes) -ccontains 'previous-replace-planned' -or
            @($script:Journal.changes) -ccontains 'active-replace-planned'
        )
        if ($pointerMutationPlanned) {
            Assert-AgentRoadRollbackPointerTransitions
            Restore-AgentRoadActivePointer
            Restore-AgentRoadPreviousPointer
            Invoke-AgentRoadOldGenerationSmokeTest
        }
        Remove-AgentRoadNewGeneration
        $script:Journal.status = 'rolled-back'
        $script:Journal.rollbackStatus = 'succeeded'
        Publish-AgentRoadJournal
    } catch {
        $script:Journal.status = 'uncertain'
        $script:Journal.failureCode = $OriginalFailure
        $script:Journal.rollbackStatus = 'failed'
        try { Publish-AgentRoadJournal } catch { }
        throw 'RUNTIME_ROLLBACK_INCOMPLETE'
    }
}

function Invoke-AgentRoadReconcile {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Capsule,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Manifest
    )

    if ($script:Journal.operationId -cne $Manifest.operationId -or $script:Journal.manifestDigest -cne $Capsule.manifestDigest) {
        throw 'RUNTIME_OPERATION_CONFLICT'
    }
    if ($script:Journal.status -ceq 'committed') {
        $pointer = Read-AgentRoadPointer $script:ActivePath
        Invoke-AgentRoadValidation $pointer $Capsule $Manifest
        Remove-AgentRoadSupersededPreviousGeneration
        return 'committed'
    }
    if ($script:Journal.status -ceq 'rolled-back') {
        return 'rolled-back'
    }
    if ($script:Journal.phase -ceq 'rollback' -or $script:Journal.rollbackStatus -cin @('pending', 'failed')) {
        Invoke-AgentRoadRollback ([string]$script:Journal.failureCode)
        return 'rolled-back'
    }
    $completedCount = @($script:Journal.completedPhases).Count
    $changeCount = @($script:Journal.changes).Count
    if (
        ($changeCount -eq 0 -and $completedCount -ne 0) -or
        ($changeCount -ge 2 -and $completedCount -lt 4) -or
        ($completedCount -ge 5 -and $changeCount -lt 2) -or
        ($changeCount -ge 3 -and ($completedCount -lt 6 -or $completedCount -gt 8)) -or
        ($completedCount -ge 7 -and $changeCount -ne 4)
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    if (@($script:Journal.changes) -ccontains 'active-replace-planned' -and ($completedCount -lt 6 -or $completedCount -gt 8)) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    Set-AgentRoadPhase 'reconcile'
    return 'resume-forward'
}

function Remove-AgentRoadSupersededPreviousGeneration {
    if ($null -eq $script:Journal -or $script:Journal.status -cne 'committed') {
        return
    }
    $candidate = $script:Journal.snapshot.previous
    if ($null -eq $candidate) {
        return
    }
    Assert-AgentRoadPointer $candidate
    $candidateDigest = [string]$candidate.manifestDigest
    $generationRoot = [IO.Path]::Combine($script:VersionsRoot, $candidateDigest)
    $tombstoneRoot = [IO.Path]::Combine($script:VersionsRoot, ('.retired-' + $candidateDigest))
    if (
        [IO.Path]::GetFullPath($generationRoot) -cne $generationRoot -or
        [IO.Path]::GetDirectoryName($generationRoot) -cne $script:VersionsRoot
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }

    $currentActive = Read-AgentRoadPointer $script:ActivePath
    $currentPrevious = Read-AgentRoadPointer $script:PreviousPath
    if (
        ($null -ne $currentActive -and [string]$currentActive.manifestDigest -ceq $candidateDigest) -or
        ($null -ne $currentPrevious -and [string]$currentPrevious.manifestDigest -ceq $candidateDigest)
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $hasGeneration = Test-Path -LiteralPath $generationRoot
    $hasTombstone = Test-Path -LiteralPath $tombstoneRoot
    if ($hasGeneration -and $hasTombstone) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    if ($hasTombstone) {
        Assert-AgentRoadRetirementTombstone $tombstoneRoot $script:Journal
        Remove-AgentRoadOwnedTree $tombstoneRoot
        return
    }
    if (-not $hasGeneration) {
        return
    }

    Read-AgentRoadVerifiedGenerationPointer $candidate | Out-Null
    $currentActive = Read-AgentRoadPointer $script:ActivePath
    $currentPrevious = Read-AgentRoadPointer $script:PreviousPath
    if (
        ($null -ne $currentActive -and [string]$currentActive.manifestDigest -ceq $candidateDigest) -or
        ($null -ne $currentPrevious -and [string]$currentPrevious.manifestDigest -ceq $candidateDigest)
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    if ((Test-Path -LiteralPath $tombstoneRoot) -or -not (Test-Path -LiteralPath $generationRoot -PathType Container)) {
        throw 'RUNTIME_COMPLETION_UNCERTAIN'
    }
    [IO.Directory]::Move($generationRoot, $tombstoneRoot)
    if ((Test-Path -LiteralPath $generationRoot) -or -not (Test-Path -LiteralPath $tombstoneRoot -PathType Container)) {
        throw 'RUNTIME_COMPLETION_UNCERTAIN'
    }
    Assert-AgentRoadRetirementTombstone $tombstoneRoot $script:Journal
    Remove-AgentRoadOwnedTree $tombstoneRoot
}

function Remove-AgentRoadOwnedTree {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    Assert-AgentRoadDirectoryNode $Root
    $nodes = @(Get-ChildItem -LiteralPath $Root -Force -Recurse | Sort-Object { $_.FullName.Length } -Descending)
    foreach ($node in $nodes) {
        if (($node.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        if ($node.PSIsContainer) {
            Assert-AgentRoadDirectoryNode $node.FullName
            [IO.Directory]::Delete($node.FullName, $false)
        } else {
            Assert-AgentRoadFileNode $node.FullName
            [IO.File]::Delete($node.FullName)
        }
    }
    [IO.Directory]::Delete($Root, $false)
    if (Test-Path -LiteralPath $Root) {
        throw 'RUNTIME_COMPLETION_UNCERTAIN'
    }
}

function Remove-AgentRoadRolledBackStaging {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Journal,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$OldTransaction,
        [object]$PreservedTransaction = $null
    )

    if ($Journal.status -cne 'rolled-back' -or $Journal.rollbackStatus -cne 'succeeded' -or $Journal.phase -cne 'rollback') {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    Assert-AgentRoadJournalTransactionBinding $Journal $OldTransaction
    if (
        -not (Test-AgentRoadPointerValue (Read-AgentRoadPointer $script:ActivePath) $Journal.snapshot.active) -or
        -not (Test-AgentRoadPointerValue (Read-AgentRoadPointer $script:PreviousPath) $Journal.snapshot.previous)
    ) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }
    $generationRoot = [IO.Path]::Combine($script:VersionsRoot, [string]$Journal.manifestDigest)
    $rollbackTombstone = [IO.Path]::Combine($script:VersionsRoot, ('.rollback-' + [string]$Journal.manifestDigest))
    if ((Test-Path -LiteralPath $generationRoot) -or (Test-Path -LiteralPath $rollbackTombstone)) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }

    Assert-AgentRoadDirectoryNode $script:StagingRoot
    $allowedOperationRoots = @([string]$OldTransaction.operationRoot)
    if ($null -ne $PreservedTransaction) {
        if ([string]$PreservedTransaction.operationRoot -ceq [string]$OldTransaction.operationRoot) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        $allowedOperationRoots += [string]$PreservedTransaction.operationRoot
    }
    $oldOperationFound = $false
    foreach ($operation in @(Get-ChildItem -LiteralPath $script:StagingRoot -Force)) {
        if (-not $operation.PSIsContainer -or $operation.FullName -cnotin $allowedOperationRoots) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        Assert-AgentRoadDirectoryNode $operation.FullName
        if ($operation.FullName -ceq $OldTransaction.operationRoot) {
            if ($operation.Name -cne [string]$OldTransaction.operationId -or $oldOperationFound) {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
            $oldOperationFound = $true
        } elseif ($operation.Name -cne [string]$PreservedTransaction.operationId) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
    }
    if (-not $oldOperationFound) {
        return
    }

    Assert-AgentRoadDirectoryNode $OldTransaction.operationRoot
    $operationEntries = @(Get-ChildItem -LiteralPath $OldTransaction.operationRoot -Force)
    foreach ($entry in $operationEntries) {
        if (-not $entry.PSIsContainer -or $entry.FullName -cnotin @($OldTransaction.transactionRoot, $OldTransaction.workRoot)) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
    }

    $capsule = $null
    $manifest = $null
    $capsuleBytes = $null
    $transactionExists = Test-Path -LiteralPath $OldTransaction.transactionRoot -PathType Container
    $capsuleExists = Test-Path -LiteralPath $OldTransaction.capsulePath -PathType Leaf
    if ($transactionExists) {
        Assert-AgentRoadDirectoryNode $OldTransaction.transactionRoot
        $transactionEntries = @(Get-ChildItem -LiteralPath $OldTransaction.transactionRoot -Force)
        foreach ($entry in $transactionEntries) {
            if (
                ($entry.FullName -ceq $OldTransaction.capsulePath -and $entry.PSIsContainer) -or
                ($entry.FullName -ceq $OldTransaction.filesRoot -and -not $entry.PSIsContainer) -or
                $entry.FullName -cnotin @($OldTransaction.capsulePath, $OldTransaction.filesRoot)
            ) {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
        }
        if ($capsuleExists) {
            try {
                Assert-AgentRoadFileNode $OldTransaction.capsulePath
                $capsuleBytes = [IO.File]::ReadAllBytes($OldTransaction.capsulePath)
                $capsule = ConvertFrom-AgentRoadCanonicalJson $capsuleBytes 131072 'RUNTIME_STATE_UNSUPPORTED'
                Assert-AgentRoadExactOrderedRecord $capsule $script:CapsuleFields 'RUNTIME_STATE_UNSUPPORTED'
                $manifestBytes = $script:Utf8.GetBytes([string]$capsule.manifestJson)
                $manifest = ConvertFrom-AgentRoadCanonicalJson $manifestBytes 65536 'RUNTIME_STATE_UNSUPPORTED'
                Assert-AgentRoadManifest $capsule $manifestBytes $manifest
                Assert-AgentRoadControllerSignature $capsule $manifestBytes
                Assert-AgentRoadPinnedControllerTrust ([string]$capsule.controllerPublicKeyJson)
                Assert-AgentRoadOperationBinding $OldTransaction $capsule $manifest $capsuleBytes
                if (
                    [string]$manifest.operationId -cne [string]$Journal.operationId -or
                    [string]$capsule.manifestDigest -cne [string]$Journal.manifestDigest -or
                    [string]$capsule.generationDigest -cne [string]$Journal.generationDigest -or
                    [string]$manifest.catalogDigest -cne [string]$Journal.catalogDigest -or
                    [string]$manifest.inventoryDigest -cne [string]$Journal.inventoryDigest -or
                    [string]$capsule.controllerKeyId -cne [string]$Journal.controllerKeyId -or
                    ((@($manifest.requestedProfiles) | ConvertTo-Json -Compress) -cne (@($Journal.requestedProfiles) | ConvertTo-Json -Compress))
                ) {
                    throw 'RUNTIME_STATE_UNSUPPORTED'
                }
            } catch {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
        } elseif ($transactionEntries.Count -ne 0) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
    } elseif ($operationEntries.Count -ne 0) {
        throw 'RUNTIME_STATE_UNSUPPORTED'
    }

    if (Test-Path -LiteralPath $OldTransaction.workRoot) {
        if (-not $capsuleExists) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        Assert-AgentRoadDirectoryNode $OldTransaction.workRoot
        foreach ($entry in @(Get-ChildItem -LiteralPath $OldTransaction.workRoot -Force)) {
            $workGenerationRoot = [IO.Path]::Combine($OldTransaction.workRoot, 'generation')
            if ($entry.PSIsContainer -and $entry.FullName -ceq $workGenerationRoot) {
                Assert-AgentRoadGenerationTombstoneTree $entry.FullName
            } elseif (-not $entry.PSIsContainer -and $entry.Name -cmatch '^\.(?:journal|active|previous)\.json\.[a-f0-9]{32}\.next$') {
                Assert-AgentRoadFileNode $entry.FullName
            } else {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
        }
        Remove-AgentRoadOwnedTree $OldTransaction.workRoot
    }

    if ($transactionExists) {
        if (Test-Path -LiteralPath $OldTransaction.filesRoot) {
            if (-not $capsuleExists) {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
            Assert-AgentRoadDirectoryNode $OldTransaction.filesRoot
            $expectedArtifact = $script:CoreComponentId + '-' + [string]$manifest.components[0].version + '.zip'
            foreach ($artifact in @(Get-ChildItem -LiteralPath $OldTransaction.filesRoot -Force)) {
                if ($artifact.PSIsContainer -or $artifact.Name -cne $expectedArtifact) {
                    throw 'RUNTIME_STATE_UNSUPPORTED'
                }
                try {
                    Assert-AgentRoadFileNode $artifact.FullName ([long]$manifest.components[0].bytes) ([string]$manifest.components[0].sha256)
                } catch {
                    throw 'RUNTIME_STATE_UNSUPPORTED'
                }
                [IO.File]::Delete($artifact.FullName)
            }
            if (@(Get-ChildItem -LiteralPath $OldTransaction.filesRoot -Force).Count -ne 0) {
                throw 'RUNTIME_COMPLETION_UNCERTAIN'
            }
            [IO.Directory]::Delete($OldTransaction.filesRoot, $false)
        }
        if ($capsuleExists) {
            Assert-AgentRoadFileNode $OldTransaction.capsulePath
            [IO.File]::Delete($OldTransaction.capsulePath)
        }
        if (@(Get-ChildItem -LiteralPath $OldTransaction.transactionRoot -Force).Count -ne 0) {
            throw 'RUNTIME_COMPLETION_UNCERTAIN'
        }
        [IO.Directory]::Delete($OldTransaction.transactionRoot, $false)
    }
    if (@(Get-ChildItem -LiteralPath $OldTransaction.operationRoot -Force).Count -ne 0) {
        throw 'RUNTIME_COMPLETION_UNCERTAIN'
    }
    [IO.Directory]::Delete($OldTransaction.operationRoot, $false)
    if (Test-Path -LiteralPath $OldTransaction.operationRoot) {
        throw 'RUNTIME_COMPLETION_UNCERTAIN'
    }
}

function Remove-AgentRoadCommittedStaging {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$CapsuleBytes,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Manifest,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Transaction,
        [object]$PreservedTransaction = $null
    )

    Assert-AgentRoadDirectoryNode $script:StagingRoot
    $operations = @(Get-ChildItem -LiteralPath $script:StagingRoot -Force)
    if ($operations.Count -eq 0) {
        return
    }
    $allowedOperationRoots = @([string]$Transaction.operationRoot)
    if ($null -ne $PreservedTransaction) {
        if ([string]$PreservedTransaction.operationRoot -ceq [string]$Transaction.operationRoot) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        $allowedOperationRoots += [string]$PreservedTransaction.operationRoot
    }
    $targetFound = $false
    foreach ($operation in $operations) {
        if (-not $operation.PSIsContainer -or $operation.FullName -cnotin $allowedOperationRoots) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        $expectedName = if ($operation.FullName -ceq $Transaction.operationRoot) {
            [string]$Transaction.operationId
        } else {
            [string]$PreservedTransaction.operationId
        }
        if ($operation.Name -cne $expectedName) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
        Assert-AgentRoadDirectoryNode $operation.FullName
        if ($operation.FullName -ceq $Transaction.operationRoot) {
            if ($targetFound) {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
            $targetFound = $true
        }
    }
    if (-not $targetFound) {
        return
    }
    Assert-AgentRoadDirectoryNode $Transaction.operationRoot
    $operationEntries = @(Get-ChildItem -LiteralPath $Transaction.operationRoot -Force)
    foreach ($entry in $operationEntries) {
        if (-not $entry.PSIsContainer -or $entry.FullName -cnotin @($Transaction.transactionRoot, $Transaction.workRoot)) {
            throw 'RUNTIME_STATE_UNSUPPORTED'
        }
    }
    if (Test-Path -LiteralPath $Transaction.transactionRoot) {
        Assert-AgentRoadDirectoryNode $Transaction.transactionRoot
        foreach ($entry in @(Get-ChildItem -LiteralPath $Transaction.transactionRoot -Force)) {
            if ($entry.FullName -ceq $Transaction.capsulePath -and -not $entry.PSIsContainer) {
                Assert-AgentRoadFileNode $entry.FullName
                $stagedBytes = [IO.File]::ReadAllBytes($entry.FullName)
                if ($stagedBytes.Length -ne $CapsuleBytes.Length) {
                    throw 'RUNTIME_STATE_UNSUPPORTED'
                }
                for ($index = 0; $index -lt $CapsuleBytes.Length; $index += 1) {
                    if ($stagedBytes[$index] -ne $CapsuleBytes[$index]) {
                        throw 'RUNTIME_STATE_UNSUPPORTED'
                    }
                }
            } elseif ($entry.FullName -ceq $Transaction.filesRoot -and $entry.PSIsContainer) {
                Assert-AgentRoadDirectoryNode $entry.FullName
                $expectedArtifact = $script:CoreComponentId + '-' + [string]$Manifest.components[0].version + '.zip'
                foreach ($artifact in @(Get-ChildItem -LiteralPath $entry.FullName -Force)) {
                    if ($artifact.PSIsContainer -or $artifact.Name -cne $expectedArtifact) {
                        throw 'RUNTIME_STATE_UNSUPPORTED'
                    }
                    Assert-AgentRoadFileNode $artifact.FullName ([long]$Manifest.components[0].bytes) ([string]$Manifest.components[0].sha256)
                }
            } else {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
        }
    }
    if (Test-Path -LiteralPath $Transaction.workRoot) {
        Assert-AgentRoadDirectoryNode $Transaction.workRoot
        foreach ($entry in @(Get-ChildItem -LiteralPath $Transaction.workRoot -Force)) {
            if (-not $entry.PSIsContainer -and $entry.Name -cmatch '^\.(?:journal|active|previous)\.json\.[a-f0-9]{32}\.next$') {
                Assert-AgentRoadFileNode $entry.FullName
            } else {
                throw 'RUNTIME_STATE_UNSUPPORTED'
            }
        }
    }
    if (Test-Path -LiteralPath $Transaction.workRoot) {
        Remove-AgentRoadOwnedTree $Transaction.workRoot
    }
    if (Test-Path -LiteralPath $Transaction.transactionRoot) {
        Remove-AgentRoadOwnedTree $Transaction.transactionRoot
    }
    Assert-AgentRoadDirectoryNode $Transaction.operationRoot
    if (@(Get-ChildItem -LiteralPath $Transaction.operationRoot -Force).Count -ne 0) {
        throw 'RUNTIME_COMPLETION_UNCERTAIN'
    }
    [IO.Directory]::Delete($Transaction.operationRoot, $false)
    if (Test-Path -LiteralPath $Transaction.operationRoot) {
        throw 'RUNTIME_COMPLETION_UNCERTAIN'
    }
    $remaining = @(Get-ChildItem -LiteralPath $script:StagingRoot -Force)
    if ($null -eq $PreservedTransaction) {
        if ($remaining.Count -ne 0) {
            throw 'RUNTIME_COMPLETION_UNCERTAIN'
        }
    } elseif (
        $remaining.Count -ne 1 -or
        -not $remaining[0].PSIsContainer -or
        $remaining[0].FullName -cne $PreservedTransaction.operationRoot -or
        $remaining[0].Name -cne $PreservedTransaction.operationId
    ) {
        throw 'RUNTIME_COMPLETION_UNCERTAIN'
    }
}

function Write-AgentRoadResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Status,
        [object]$OperationId,
        [object]$ManifestDigest,
        [object]$GenerationDigest,
        [object]$FailureCode
    )

    if ($Status -cnotin $script:ResultStatuses -or ($null -ne $FailureCode -and [string]$FailureCode -cnotin $script:FailureCodes)) {
        $Status = 'failed'
        $FailureCode = 'RUNTIME_INTERNAL_ERROR'
    }
    $result = [pscustomobject][ordered]@{
        schemaVersion = 1
        status = $Status
        operationId = $OperationId
        manifestDigest = $ManifestDigest
        generationDigest = $GenerationDigest
        restartRequired = $false
        failureCode = $FailureCode
    }
    Assert-AgentRoadExactOrderedRecord $result $script:ResultFields 'RUNTIME_INTERNAL_ERROR'
    $json = $result | ConvertTo-Json -Depth 3 -Compress
    if ($script:Utf8.GetByteCount($json) -gt 4096) {
        $json = '{"schemaVersion":1,"status":"failed","operationId":null,"manifestDigest":null,"generationDigest":null,"restartRequired":false,"failureCode":"RUNTIME_INTERNAL_ERROR"}'
    }
    [Console]::OutputEncoding = $script:Utf8
    [Console]::Out.Write($json)
}

function Get-AgentRoadFailureCode {
    param(
        [object]$Failure
    )

    $candidate = [string]$Failure
    if ($candidate -cin $script:FailureCodes) {
        return $candidate
    }
    return 'RUNTIME_INTERNAL_ERROR'
}

$lock = $null
$capsule = $null
$manifest = $null
$operationId = $null
$manifestDigest = $null
$generationDigest = $null
$exitCode = 1
$rollbackAuthorized = $false
try {
    $invocation = Read-AgentRoadInvocation
    $operationId = [string]$invocation.operationId
    $manifestDigest = [string]$invocation.manifestDigest
    $script:Transaction = Get-AgentRoadTransaction $invocation
    $lock = Enter-AgentRoadMutationLock
    if (Test-Path -LiteralPath $script:StateRoot) {
        Assert-AgentRoadDirectoryNode $script:StateRoot
    }
    $script:Journal = Read-AgentRoadJournal
    Assert-AgentRoadRuntimeTopology $script:Journal
    $finished = $false

    if ($null -ne $script:Journal -and $script:Journal.status -ceq 'rolled-back') {
        $sameRolledBackOperation = [string]$script:Journal.operationId -ceq [string]$invocation.operationId
        $sameRolledBackManifest = [string]$script:Journal.manifestDigest -ceq [string]$invocation.manifestDigest
        if ($sameRolledBackOperation -or $sameRolledBackManifest) {
            if (-not ($sameRolledBackOperation -and $sameRolledBackManifest)) {
                throw 'RUNTIME_OPERATION_CONFLICT'
            }
        }
        $rolledBackInvocation = [pscustomobject][ordered]@{
            schemaVersion = 1
            operationId = [string]$script:Journal.operationId
            manifestDigest = [string]$script:Journal.manifestDigest
        }
        $rolledBackTransaction = Get-AgentRoadTransaction $rolledBackInvocation
        $rolledBackGenerationDigest = [string]$script:Journal.generationDigest
        $rolledBackFailureCode = [string]$script:Journal.failureCode
        Remove-AgentRoadNewGeneration
        $preservedTransaction = if ($sameRolledBackOperation -and $sameRolledBackManifest) { $null } else { $script:Transaction }
        Remove-AgentRoadRolledBackStaging $script:Journal $rolledBackTransaction $preservedTransaction
        if ($sameRolledBackOperation -and $sameRolledBackManifest) {
            $generationDigest = $rolledBackGenerationDigest
            Write-AgentRoadResult 'rolled-back' $operationId $manifestDigest $generationDigest $rolledBackFailureCode
            $exitCode = 2
            $finished = $true
        } else {
            $script:Journal = $null
        }
    }

    if ($null -ne $script:Journal -and $script:Journal.status -cnotin @('committed', 'rolled-back')) {
        Assert-AgentRoadJournalTransactionBinding $script:Journal $script:Transaction
    }

    if ($null -ne $script:Journal -and $script:Journal.status -ceq 'committed') {
        $sameCommittedOperation = [string]$script:Journal.operationId -ceq [string]$invocation.operationId
        $sameCommittedManifest = [string]$script:Journal.manifestDigest -ceq [string]$invocation.manifestDigest
        if ($sameCommittedOperation -and $sameCommittedManifest) {
            $committedRuntime = Read-AgentRoadCommittedRuntime $invocation
            $capsule = $committedRuntime.capsule
            $capsuleBytes = [byte[]]$committedRuntime.capsuleBytes
            $manifest = $committedRuntime.manifest
            $manifestBytes = $script:Utf8.GetBytes([string]$capsule.manifestJson)
            $generationDigest = [string]$capsule.generationDigest
            Remove-AgentRoadSupersededPreviousGeneration
            Remove-AgentRoadCommittedStaging $capsuleBytes $manifest $script:Transaction
            Write-AgentRoadResult 'committed' $operationId $manifestDigest $generationDigest $null
            $exitCode = 0
            $finished = $true
        } elseif ($sameCommittedOperation -or $sameCommittedManifest) {
            throw 'RUNTIME_OPERATION_CONFLICT'
        } else {
            $committedInvocation = [pscustomobject][ordered]@{
                schemaVersion = 1
                operationId = [string]$script:Journal.operationId
                manifestDigest = [string]$script:Journal.manifestDigest
            }
            $committedTransaction = Get-AgentRoadTransaction $committedInvocation
            $committedRuntime = Read-AgentRoadCommittedRuntime $committedInvocation
            Remove-AgentRoadSupersededPreviousGeneration
            Remove-AgentRoadCommittedStaging ([byte[]]$committedRuntime.capsuleBytes) $committedRuntime.manifest $committedTransaction $script:Transaction
            $script:Journal = $null
        }
    }

    if (-not $finished) {
        Assert-AgentRoadStagedTransaction $script:Transaction
        Assert-AgentRoadFileNode $script:Transaction.capsulePath
        $capsuleBytes = [IO.File]::ReadAllBytes($script:Transaction.capsulePath)
        $capsule = ConvertFrom-AgentRoadCanonicalJson $capsuleBytes 131072 'RUNTIME_SIGNATURE_INVALID'
        Assert-AgentRoadExactOrderedRecord $capsule $script:CapsuleFields 'RUNTIME_SIGNATURE_INVALID'
        $manifestBytes = $script:Utf8.GetBytes([string]$capsule.manifestJson)
        $manifest = ConvertFrom-AgentRoadCanonicalJson $manifestBytes 65536 'RUNTIME_SIGNATURE_INVALID'
        Assert-AgentRoadManifest $capsule $manifestBytes $manifest
        Assert-AgentRoadControllerSignature $capsule $manifestBytes
        Assert-AgentRoadOperationBinding $script:Transaction $capsule $manifest $capsuleBytes
        $generationDigest = [string]$capsule.generationDigest

        Assert-AgentRoadMachinePreconditions $manifest
        Ensure-AgentRoadRestrictedDirectory $script:TrustRoot $script:RuntimeRoot
        Ensure-AgentRoadRestrictedDirectory $script:VersionsRoot $script:RuntimeRoot
        Ensure-AgentRoadRestrictedDirectory $script:StateRoot $script:RuntimeRoot
        if (-not (Test-Path -LiteralPath $script:Transaction.workRoot)) {
            Ensure-AgentRoadRestrictedDirectory $script:Transaction.workRoot $script:Transaction.operationRoot
        } else {
            Assert-AgentRoadDirectoryNode $script:Transaction.workRoot
        }
        Ensure-AgentRoadControllerTrust ([string]$capsule.controllerPublicKeyJson)

        if ($null -ne $script:Journal) {
            Initialize-AgentRoadPointerSnapshot
            $rollbackAuthorized = $true
            $reconciled = Invoke-AgentRoadReconcile $capsule $manifest
            if ($reconciled -ceq 'rolled-back') {
                Write-AgentRoadResult 'rolled-back' $operationId $manifestDigest $generationDigest ([string]$script:Journal.failureCode)
                $exitCode = 2
                $finished = $true
            }
        } else {
            $script:Journal = New-AgentRoadJournal $capsule $manifest
            Publish-AgentRoadJournal
            Initialize-AgentRoadPointerSnapshot
            $rollbackAuthorized = $true
        }
        if (-not $finished -and @($script:Journal.changes) -cnotcontains 'work-created') {
            Add-AgentRoadChange 'work-created'
        }
    }

    if (-not $finished) {
        if (@($script:Journal.completedPhases) -notcontains 'discover') {
            Complete-AgentRoadForwardPhase 'discover'
        }
        if (@($script:Journal.completedPhases) -notcontains 'verify-manifest') {
            Assert-AgentRoadManifest $capsule $manifestBytes $manifest
            Assert-AgentRoadControllerSignature $capsule $manifestBytes
            Complete-AgentRoadForwardPhase 'verify-manifest'
        }
        $archivePath = Assert-AgentRoadArtifact $script:Transaction $manifest.components[0]
        if (@($script:Journal.completedPhases) -notcontains 'verify-artifacts') {
            Complete-AgentRoadForwardPhase 'verify-artifacts'
        }
        if (@($script:Journal.completedPhases) -notcontains 'snapshot') {
            Save-AgentRoadPointerSnapshot
            Complete-AgentRoadForwardPhase 'snapshot'
        }
        $generationRoot = Invoke-AgentRoadMaterializeGeneration $capsule $manifest $capsuleBytes $archivePath
        if (@($script:Journal.completedPhases) -notcontains 'materialize-generation') {
            Complete-AgentRoadForwardPhase 'materialize-generation'
        }
        Invoke-AgentRoadSelfTest $generationRoot $manifest
        if (@($script:Journal.completedPhases) -notcontains 'self-test') {
            Complete-AgentRoadForwardPhase 'self-test'
        }
        if (@($script:Journal.completedPhases) -notcontains 'atomic-activate') {
            Invoke-AgentRoadActivation $script:NewPointer $capsule $manifest
            Complete-AgentRoadForwardPhase 'atomic-activate'
        }
        Invoke-AgentRoadValidation $script:NewPointer $capsule $manifest
        if (@($script:Journal.completedPhases) -notcontains 'validate') {
            Complete-AgentRoadForwardPhase 'validate'
        }
        $script:Journal.status = 'committed'
        $script:Journal.failureCode = $null
        if (@($script:Journal.completedPhases) -notcontains 'commit') {
            Complete-AgentRoadForwardPhase 'commit'
        }
        Remove-AgentRoadSupersededPreviousGeneration
        Remove-AgentRoadCommittedStaging $capsuleBytes $manifest $script:Transaction
        Write-AgentRoadResult 'committed' $operationId $manifestDigest $generationDigest $null
        $exitCode = 0
    }
} catch {
    $failureCode = Get-AgentRoadFailureCode $_
    if (
        $null -ne $script:Journal -and
        $script:Journal.status -cin @('committed', 'rolled-back') -and
        $failureCode -cnotin @('RUNTIME_OPERATION_CONFLICT', 'RUNTIME_STATE_UNSUPPORTED')
    ) {
        $failureCode = 'RUNTIME_COMPLETION_UNCERTAIN'
    }
    if ($failureCode -ceq 'RUNTIME_COMPLETION_UNCERTAIN') {
        if ($null -ne $script:Journal -and $script:Journal.status -cnotin @('committed', 'rolled-back')) {
            $script:Journal.status = 'uncertain'
            $script:Journal.failureCode = $failureCode
            try { Publish-AgentRoadJournal } catch { }
        }
        Write-AgentRoadResult 'uncertain' $operationId $manifestDigest $generationDigest $failureCode
        $exitCode = 3
    } elseif ($failureCode -cin @('RUNTIME_OPERATION_CONFLICT', 'RUNTIME_STATE_UNSUPPORTED')) {
        Write-AgentRoadResult 'failed' $operationId $manifestDigest $generationDigest $failureCode
        $exitCode = 1
    } elseif ($null -ne $script:Journal -and $rollbackAuthorized) {
        try {
            Invoke-AgentRoadRollback $failureCode
            Write-AgentRoadResult 'rolled-back' $operationId $manifestDigest $generationDigest $failureCode
            $exitCode = 2
        } catch {
            Write-AgentRoadResult 'uncertain' $operationId $manifestDigest $generationDigest 'RUNTIME_ROLLBACK_INCOMPLETE'
            $exitCode = 4
        }
    } else {
        Write-AgentRoadResult 'failed' $operationId $manifestDigest $generationDigest $failureCode
        $exitCode = 1
    }
} finally {
    Exit-AgentRoadMutationLock $lock
}
exit $exitCode
