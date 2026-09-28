param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
Set-Location -LiteralPath $Directory
$utf8=New-Object Text.UTF8Encoding($false)
function Save-State($state) {
  $temp=Join-Path $Directory ('state-'+[Guid]::NewGuid().ToString('N')+'.tmp')
  [IO.File]::WriteAllText($temp,($state|ConvertTo-Json -Compress),$utf8)
  $dest=Join-Path $Directory 'state.json'
  if([IO.File]::Exists($dest)){[IO.File]::Replace($temp,$dest,($temp+'.bak'));[IO.File]::Delete($temp+'.bak')}else{[IO.File]::Move($temp,$dest)}
}
$lock=$null
try {$lock=[IO.File]::Open((Join-Path $Directory 'worker.lock'),'OpenOrCreate','ReadWrite','None')}catch{exit 2}
try {
  if(Test-Path -LiteralPath (Join-Path $Directory 'claimed')){exit 0}
  $claim=[IO.File]::Open((Join-Path $Directory 'claimed'),'CreateNew','Write','None');$claim.Dispose()
  $config=Get-Content -LiteralPath (Join-Path $Directory 'config.json') -Raw|ConvertFrom-Json
  Save-State @{status='RUNNING';startedAt=[DateTime]::UtcNow.ToString('o');exitCode=$null}
  if(Test-Path -LiteralPath (Join-Path $Directory 'cancel.request')){
    Save-State @{status='CANCELLED';exitCode=$null;finishedAt=[DateTime]::UtcNow.ToString('o')};exit 0
  }
  Add-Type -Path (Join-Path $Directory 'runner.cs')
  $result=[AgentRoad.BackgroundRunner]::Run($Directory,[int]$config.timeoutSeconds)
  Save-State @{status=$result.Status;exitCode=$result.ExitCode;finishedAt=[DateTime]::UtcNow.ToString('o')}
} catch {
  Save-State @{status='FAILED';exitCode=$null;reason='JOB_WORKER_FAILED';finishedAt=[DateTime]::UtcNow.ToString('o')}
  exit 1
} finally {if($null -ne $lock){$lock.Dispose()}}
