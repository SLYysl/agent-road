param([Parameter(Mandatory=$true)][string]$PackageDirectory)
$ErrorActionPreference='Stop'
$target=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'AgentRoadDiagnosticsPreview'
if(Test-Path $target){throw 'ACCEPTANCE_TARGET_EXISTS'}
$app=Join-Path $PackageDirectory 'AgentRoadDiagnostics.exe'
function Run($arguments,$expected,$label){
    $p=Start-Process -FilePath $app -ArgumentList $arguments -PassThru
    $null=$p.Handle
    if(!$p.WaitForExit(30000)){throw 'PROCESS_TIMEOUT_INSPECT'}
    if($p.ExitCode -ne $expected){throw ('CASE_FAILED_'+$label)}
    Write-Output $label
}
Run @('--install-local') 0 'NATIVE_INSTALL_OK'
Run @('--install-local') 2 'DUPLICATE_REFUSED'
$report=Join-Path $PackageDirectory 'native-report.json'
Run @('--report',('"'+$report+'"')) 0 'REPORT_CREATED'
$before=(Get-FileHash $report -Algorithm SHA256).Hash
Run @('--report',('"'+$report+'"')) 2 'OVERWRITE_REFUSED'
if((Get-FileHash $report -Algorithm SHA256).Hash -cne $before){throw 'REPORT_CHANGED'}
$extra=Join-Path $target 'user-file.txt';[IO.File]::WriteAllText($extra,'fixture')
Run @('--uninstall-local') 2 'EXTRA_FILE_PRESERVED'
if(!(Test-Path $extra)){throw 'EXTRA_FILE_REMOVED'}
Remove-Item -LiteralPath $extra
$installed=Join-Path $target 'AgentRoadDiagnostics.exe'
$bytes=[IO.File]::ReadAllBytes($installed)
try {
    [IO.File]::WriteAllText($installed,'changed fixture bytes; never execute')
    Run @('--uninstall-local') 2 'CHANGED_BINARY_PRESERVED'
    if(!(Test-Path $installed)){throw 'CHANGED_FILE_REMOVED'}
} finally {[IO.File]::WriteAllBytes($installed,$bytes)}
Run @('--uninstall-local') 0 'NATIVE_UNINSTALL_OK'
if(Test-Path $target){throw 'UNINSTALL_INCOMPLETE'}
if(!(Test-Path $report)){throw 'REPORT_REMOVED'}
Write-Output 'NATIVE_ACCEPTANCE_PASSED'
