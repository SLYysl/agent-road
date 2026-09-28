param([Parameter(Mandatory=$true)][string]$AppPath,[Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'NONADMIN_SESSION_REQUIRED'}
if(Test-Path $OutputDirectory){throw 'OUTPUT_EXISTS'}
New-Item -ItemType Directory $OutputDirectory | Out-Null
$root=Join-Path $env:ProgramData 'AgentRoadNativeSetupPreview'
$before=Test-Path $root
$cases=@(@('--self-test',0,'PARSER_SELF_TEST_PASSED'),@('--inspect',2,'ADMIN_REQUIRED'),@('--install-openssh --accept-system-changes',2,'ADMIN_REQUIRED'),@('--install-openssh',2,'EXPLICIT_ACTION_REQUIRED'))
foreach($case in $cases){
 $out=Join-Path $OutputDirectory ($case[2]+'.json')
 $p=Start-Process -FilePath $AppPath -ArgumentList $case[0] -RedirectStandardOutput $out -RedirectStandardError ($out+'.err') -PassThru
 $null=$p.Handle
 if(!$p.WaitForExit(15000)){throw 'PROCESS_UNCERTAIN'}
 $receipt=Get-Content $out -Raw | ConvertFrom-Json
 if($p.ExitCode -ne $case[1] -or $receipt.state -cne $case[2] -or $receipt.remoteAccessReady -ne $false){throw 'UNEXPECTED_RESULT'}
 Write-Output $receipt.state
}
if((Test-Path $root) -ne $before){throw 'UNEXPECTED_JOURNAL'}
Write-Output 'NONADMIN_ACCEPTANCE_PASSED'
