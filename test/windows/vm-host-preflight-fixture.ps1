param([Parameter(Mandatory=$true)][string]$SourcePath)
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($SourcePath,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'SOURCE_PARSE_FAILED' }
$function=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-AgentRoadVmHostAssessment'},$false)
if (!$function) { throw 'ASSESSMENT_FUNCTION_MISSING' }
# Load only the pure assessment function, never the executable host inspection.
. ([scriptblock]::Create($function.Extent.Text))
$base=@('VMState="running"','CfgFile="D:\trial\test.vbox"','SnapFldr="D:\trial\Snapshots"','LogFldr="D:\trial\Logs"','storagecontrollername0="SATA"','"SATA-0-0"="D:\trial\disk.vdi"','"SATA-1-0"="emptydrive"')
$good={param($drive) [pscustomobject]@{DriveType=3;FreeSpace=30GB;Size=100GB}}
$low={param($drive) [pscustomobject]@{DriveType=3;FreeSpace=1GB;Size=100GB}}
$passed=New-Object 'System.Collections.Generic.List[string]'
function Assert-Case($Name,$Info,$Reader,$Expected,$Findings) {
    $r=Get-AgentRoadVmHostAssessment -VmInfo $Info -HeadroomGiB 20 -ReadDisk $Reader
    if ($r.result -ne $Expected -or $r.readinessClaim -or $r.mutationPerformed -or $r.guestConnectivity -ne 'NOT_CHECKED') { throw ('CASE_FAILED_'+$Name) }
    foreach($f in $Findings) { if($r.findings -notcontains $f){throw ('MISSING_FINDING_'+$Name)} }
    $passed.Add($Name)
    return $r
}
$r=Assert-Case 'headroom-only' $base $good 'STORAGE_HEADROOM_OBSERVED' @()
if($r.volumes.Count -ne 1 -or $r.volumes[0].drive -ne 'D:'){throw 'WRONG_DISK'}
$paused=$base -replace '^VMState=.*','VMState="paused"'
$null=Assert-Case 'paused-and-low' $paused $low 'HOST_STORAGE_LOW' @('HOST_STORAGE_LOW','VM_PAUSED_REVIEW_REQUIRED')
$null=Assert-Case 'paused-with-headroom' $paused $good 'VM_PAUSED_REVIEW_REQUIRED' @('VM_PAUSED_REVIEW_REQUIRED')
$null=Assert-Case 'unknown-state' ($base | Where-Object {$_ -notmatch '^VMState='}) $good 'VM_STATE_UNKNOWN' @('VM_STATE_UNKNOWN')
$null=Assert-Case 'denied-volume' $base {param($drive) throw 'ACCESS_DENIED fixture detail must not leak'} 'HOST_STORAGE_UNKNOWN' @('HOST_STORAGE_UNKNOWN')
$null=Assert-Case 'invalid-size' $base {param($drive) [pscustomobject]@{DriveType=3;FreeSpace=101GB;Size=100GB}} 'HOST_STORAGE_UNKNOWN' @('HOST_STORAGE_UNKNOWN')
$unc=$base -replace '^"SATA-0-0"=.*','"SATA-0-0"="\\server\share\disk.vdi"'
$null=Assert-Case 'UNC-not-silently-ignored' $unc $good 'VM_STORAGE_UNRESOLVED' @('VM_STORAGE_UNRESOLVED')
$other=$base -replace '^"SATA-0-0"=.*','"SATA-0-0"="E:\trial\disk.vdi"'
$r=Assert-Case 'separate-attached-volume' $other {param($drive) if($drive -eq 'E:'){& $low $drive}else{& $good $drive}} 'HOST_STORAGE_LOW' @('HOST_STORAGE_LOW')
if($r.volumes.Count -ne 2){throw 'ATTACHED_VOLUME_MISSING'}
if($passed.Count -ne 8){throw 'CASE_COUNT_MISMATCH'}
[pscustomobject]@{status='PASS';count=$passed.Count;cases=$passed;vmMutationPerformed=$false} | ConvertTo-Json -Compress
