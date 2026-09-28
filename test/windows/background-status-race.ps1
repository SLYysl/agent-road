param([Parameter(Mandatory=$true)][string]$ControlScriptPath)
$ErrorActionPreference='Stop'
$fixtureRoot=Join-Path $env:TEMP ('AgentRoad-JobStatusRace-'+[Guid]::NewGuid().ToString('N'))
$fixtureJob='job_'+('a'*32)
$fixtureDirectory=Join-Path $fixtureRoot $fixtureJob
$fixtureSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
[void](New-Item -ItemType Directory -Path $fixtureDirectory -Force)
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach($id in @($fixtureSid,'S-1-5-18','S-1-5-32-544')|Select-Object -Unique){
  $identity=New-Object Security.Principal.SecurityIdentifier($id)
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
}
Set-Acl -LiteralPath $fixtureRoot -AclObject $acl
Set-Acl -LiteralPath $fixtureDirectory -AclObject $acl
$fixtureUtf8=New-Object Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path $fixtureDirectory 'owner.txt'),$fixtureSid,$fixtureUtf8)
[IO.File]::WriteAllText((Join-Path $fixtureDirectory 'state.json'),'{"status":"RUNNING","exitCode":null}',$fixtureUtf8)
# Publish completion exactly when the scheduler is observed, after the original
# implementation's first state read. No real scheduled task is created or changed.
function Get-ScheduledTask {
  param($TaskName,$ErrorAction)
  [IO.File]::WriteAllText((Join-Path $fixtureDirectory 'state.json'),'{"status":"SUCCEEDED","exitCode":0}',$fixtureUtf8)
  return [pscustomobject]@{
    State='Ready'
    Principal=[pscustomobject]@{UserId=$fixtureSid;LogonType='S4U';RunLevel='Limited'}
    Actions=@([pscustomobject]@{
      Execute=(Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
      Arguments=('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $fixtureDirectory 'worker.ps1')+'" -Directory "'+$fixtureDirectory+'"')
      WorkingDirectory=$fixtureDirectory
    })
  }
}
function Get-ScheduledTaskInfo {param($TaskName);return [pscustomobject]@{LastTaskResult=0}}
$source=[IO.File]::ReadAllText($ControlScriptPath).Replace("'C:\ProgramData\AgentRoad\jobs'",("'"+$fixtureRoot+"'"))
$request=[pscustomobject]@{action='status';jobId=$fixtureJob}
$result=(& ([ScriptBlock]::Create($source))) | ConvertFrom-Json
if($result.state.status -cne 'SUCCEEDED' -or $result.state.exitCode -ne 0 -or $result.schedulerActive){throw ('JOB_COMPLETION_RACE_REGRESSION_'+$result.state.status)}
Write-Output 'JOB_COMPLETION_RACE_PASSED'
