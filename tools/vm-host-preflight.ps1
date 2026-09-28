# Read-only host diagnostics. No cleanup/start/resume and no guest network probe.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$VmName,
    [ValidateRange(1,1048576)][int]$MinimumFreeGiB = 20
)
$ErrorActionPreference = 'Stop'

function Get-AgentRoadVmHostAssessment {
    param([string[]]$VmInfo, [int]$HeadroomGiB, [scriptblock]$ReadDisk)
    $state = $null
    $volumes = @()
    $observations = @()
    $findings = @()
    $controllers = @()
    $configSeen = $false
    foreach ($line in $VmInfo) {
        if ($line -match '^VMState="([a-z]+)"$') { $state = $Matches[1] }
        if ($line -match '^storagecontrollername[0-9]+="([^"\r\n]+)"$') { $controllers += [regex]::Escape($Matches[1]) }
    }
    if ($state -eq 'paused') { $findings += 'VM_PAUSED_REVIEW_REQUIRED' }
    if (!$state) { $findings += 'VM_STATE_UNKNOWN' }
    $controllerPattern = if ($controllers.Count) { '^"(?:' + ($controllers -join '|') + ')-[0-9]+-[0-9]+"="([^"\r\n]*)"$' } else { '(?!)' }
    foreach ($line in $VmInfo) {
        $path = $null
        if ($line -match '^(CfgFile|SnapFldr|LogFldr)="([^"\r\n]*)"$') {
            if ($Matches[1] -eq 'CfgFile') { $configSeen = $true }
            $path = $Matches[2]
        } elseif ($line -match $controllerPattern) {
            $path = $Matches[1]
            if ($path -in @('none','emptydrive')) { continue }
        }
        if ($null -ne $path) {
            if ($path -match '^[A-Za-z]:\\') { $volumes += $path.Substring(0,2).ToUpperInvariant() }
            else { $findings += 'VM_STORAGE_UNRESOLVED' }
        }
    }
    if (!$configSeen -or !$volumes.Count -or !$controllers.Count) { $findings += 'VM_STORAGE_UNRESOLVED' }
    foreach ($drive in @($volumes | Sort-Object -Unique)) {
        try {
            $disk = & $ReadDisk $drive
            if (!$disk -or $disk.DriveType -ne 3 -or $null -eq $disk.FreeSpace -or $null -eq $disk.Size -or [long]$disk.FreeSpace -lt 0 -or [long]$disk.Size -le 0 -or [long]$disk.FreeSpace -gt [long]$disk.Size) { throw 'UNKNOWN' }
            $enough = [long]$disk.FreeSpace -ge ([long]$HeadroomGiB * 1GB)
            $observations += [pscustomobject]@{drive=$drive;freeBytes=[long]$disk.FreeSpace;totalBytes=[long]$disk.Size;meetsHeadroom=$enough;result='OBSERVED'}
            if (!$enough) { $findings += 'HOST_STORAGE_LOW' }
        } catch {
            $findings += 'HOST_STORAGE_UNKNOWN'
            $observations += [pscustomobject]@{drive=$drive;freeBytes=$null;totalBytes=$null;meetsHeadroom=$null;result='HOST_STORAGE_UNKNOWN'}
        }
    }
    $findings = @($findings | Sort-Object -Unique)
    $result = 'STORAGE_HEADROOM_OBSERVED'
    foreach ($code in @('VM_STATE_UNKNOWN','VM_STORAGE_UNRESOLVED','HOST_STORAGE_UNKNOWN','HOST_STORAGE_LOW','VM_PAUSED_REVIEW_REQUIRED')) {
        if ($findings -contains $code) { $result=$code; break }
    }
    [pscustomobject]@{
        schemaVersion=1;observedAt=[DateTime]::UtcNow.ToString('o');vmState=$state
        minimumFreeGiB=$HeadroomGiB;volumes=$observations;result=$result;findings=$findings
        guestConnectivity='NOT_CHECKED';mutationPerformed=$false;readinessClaim=$false
    }
}

try {
    $vbox = Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe'
    if (!(Test-Path -LiteralPath $vbox -PathType Leaf)) { throw 'VBOX_NOT_FOUND' }
    # Windows PowerShell can turn native stderr into an exception before exit-code inspection.
    $priorPreference=$ErrorActionPreference
    try {
        $ErrorActionPreference='Continue'
        $info = @(& $vbox showvminfo $VmName --machinereadable 2>$null)
        $inspectionExit=$LASTEXITCODE
    } finally { $ErrorActionPreference=$priorPreference }
    if ($inspectionExit -ne 0) { throw 'VM_INSPECTION_FAILED' }
    $assessment = Get-AgentRoadVmHostAssessment -VmInfo $info -HeadroomGiB $MinimumFreeGiB -ReadDisk {
        param($drive)
        Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='" + $drive + "'") -ErrorAction Stop
    }
    $assessment | ConvertTo-Json -Depth 4 -Compress
    if ($assessment.findings.Count -gt 0) { exit 2 }
    exit 0
} catch {
    $known = @('VBOX_NOT_FOUND','VM_INSPECTION_FAILED')
    $code = if ($known -contains $_.Exception.Message) { $_.Exception.Message } else { 'HOST_PREFLIGHT_UNKNOWN' }
    [pscustomobject]@{schemaVersion=1;result=$code;findings=@($code);guestConnectivity='NOT_CHECKED';mutationPerformed=$false;readinessClaim=$false} | ConvertTo-Json -Compress
    exit 2
}
