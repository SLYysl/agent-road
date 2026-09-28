# Read-only. Does not enable services, install packages or change execution policy.
$ErrorActionPreference = 'Stop'
function Observe($Name, [scriptblock]$Action) {
    try { [pscustomobject]@{ Check=$Name; Value=(& $Action); Result='OBSERVED' } }
    catch { [pscustomobject]@{ Check=$Name; Value='UNKNOWN'; Result=$_.Exception.GetType().Name } }
}
Observe 'Windows' { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select-Object EditionID, CurrentBuildNumber) | ConvertTo-Json -Compress }
Observe 'Architecture' { [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE','Machine') }
Observe 'Administrator' { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
foreach ($Tool in @('git','node','python','tailscale','ssh')) {
    Observe "Tool $Tool" { (Get-Command $Tool -ErrorAction Stop).Source }
}
Observe 'sshd' { Get-Service sshd | Select-Object Status,StartType | ConvertTo-Json -Compress }
Observe 'Tailscale service' { Get-Service Tailscale | Select-Object Status,StartType | ConvertTo-Json -Compress }
Observe 'AgentRoad root exists' { Test-Path 'C:\ProgramData\AgentRoad' }
Observe 'SSH directory entries' { if (Test-Path 'C:\ProgramData\ssh') { @(Get-ChildItem 'C:\ProgramData\ssh' -Force).Count } else { 0 } }
Observe 'Reboot CBS flag' { Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' }
Observe 'Reboot WindowsUpdate flag' { Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' }
Observe 'Pending file operations' { $v=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'; @($v.PendingFileRenameOperations | Where-Object { $_ }).Count }
Write-Output 'No readiness claim. Native preflight and owner-reviewed Tailscale identity check still required.'
