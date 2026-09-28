param([Parameter(Mandatory=$true)][string]$PackageDirectory)
$ErrorActionPreference='Stop'
$target=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'AgentRoadDiagnosticsPreview'
if(Test-Path $target){throw 'ACCEPTANCE_TARGET_EXISTS'}
$ps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$install=Join-Path $PackageDirectory 'Install.ps1'
function CheckAction($action,$expected,$exit){
    $output=& $ps -NoProfile -NonInteractive -File $install -Action $action
    if($LASTEXITCODE -ne $exit){throw ('UNEXPECTED_EXIT_'+$action)}
    $r=$output|ConvertFrom-Json
    $actual=if($r.state -eq 'STOPPED'){$r.code}else{$r.state}
    if($actual -cne $expected){throw ('UNEXPECTED_RESULT_'+$action)}
    Write-Output $expected
}
CheckAction Install 'INSTALLED_DIAGNOSTICS_ONLY' 0
CheckAction Install 'INSTALL_TARGET_EXISTS' 2
$exe=Join-Path $target 'AgentRoadDiagnostics.exe'
$report=Join-Path $PackageDirectory 'acceptance-report.json'
if(Test-Path $report){throw 'ACCEPTANCE_REPORT_EXISTS'}
$p=Start-Process -FilePath $exe -ArgumentList @('--report',('"'+$report+'"')) -PassThru
$null=$p.Handle
if(!$p.WaitForExit(30000)){throw 'REPORT_TIMEOUT_INSPECT'}
if($p.ExitCode -ne 0){throw 'REPORT_FAILED'}
$r=Get-Content -LiteralPath $report -Raw|ConvertFrom-Json
if($r.product -cne 'Agent Road Diagnostics Preview' -or $r.remoteAccessConfiguredByThisApp -ne $false){throw 'REPORT_INVALID'}
Write-Output 'REPORT_CREATED'
$before=(Get-FileHash $report -Algorithm SHA256).Hash
$p=Start-Process -FilePath $exe -ArgumentList @('--report',('"'+$report+'"')) -PassThru
$null=$p.Handle
if(!$p.WaitForExit(30000)){throw 'REPORT_TIMEOUT_INSPECT'}
if($p.ExitCode -ne 2 -or (Get-FileHash $report -Algorithm SHA256).Hash -cne $before){throw 'REPORT_OVERWRITE_NOT_REFUSED'}
Write-Output 'REPORT_OVERWRITE_REFUSED'
$sentinel=Join-Path $target 'user-file.txt'
[IO.File]::WriteAllText($sentinel,'acceptance sentinel')
CheckAction Uninstall 'UNINSTALL_CONTENT_CHANGED' 2
if(!(Test-Path $exe) -or !(Test-Path $sentinel)){throw 'UNKNOWN_CONTENT_NOT_PRESERVED'}
Remove-Item -LiteralPath $sentinel
CheckAction Uninstall 'UNINSTALLED_DIAGNOSTICS_ONLY' 0
if(Test-Path $target){throw 'UNINSTALL_INCOMPLETE'}
if(!(Test-Path $report)){throw 'EXPORTED_REPORT_REMOVED'}
Write-Output 'DIAGNOSTICS_ACCEPTANCE_PASSED'
