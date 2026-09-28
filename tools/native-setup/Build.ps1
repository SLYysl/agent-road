param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or ![Environment]::Is64BitProcess){throw 'WINDOWS_POWERSHELL_X64_REQUIRED'}
if(Test-Path -LiteralPath $OutputDirectory){throw 'BUILD_OUTPUT_EXISTS'}
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(!(Test-Path -LiteralPath $compiler)){throw 'FRAMEWORK_COMPILER_REQUIRED'}
$repository=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$legalFiles=@('LICENSE','NOTICE','LICENSE_SCOPE.md','THIRD_PARTY_REVIEW.md')
foreach($name in $legalFiles){if(!(Test-Path -LiteralPath (Join-Path $repository $name) -PathType Leaf)){throw 'LICENSE_NOTICE_REQUIRED'}}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$exe=Join-Path $OutputDirectory 'AgentRoadNativeSetup.exe'
& $compiler /nologo /target:exe /platform:x64 /optimize+ /r:Microsoft.CSharp.dll /r:System.ServiceProcess.dll /r:System.Web.Extensions.dll "/out:$exe" (Join-Path $PSScriptRoot 'Program.cs') (Join-Path $PSScriptRoot 'NativeEnrollment.cs') (Join-Path $PSScriptRoot 'NativeSystem.cs') (Join-Path $PSScriptRoot 'NativeTailscale.cs')
if($LASTEXITCODE -ne 0){throw 'COMPILE_FAILED'}
& $exe --self-test
if($LASTEXITCODE -ne 0){throw 'SELF_TEST_FAILED'}
# Verify the native binding record round-trips through the existing PowerShell core contract.
$assembly=[Reflection.Assembly]::LoadFile($exe)
$binding=$assembly.GetType('Program').GetMethod('RuntimeDeviceBinding',[Reflection.BindingFlags]'NonPublic,Static')
$json=[string]$binding.Invoke($null,@(('dev_'+('a'*32)),[DateTime]::UtcNow))
$record=$json|ConvertFrom-Json
if(($record|ConvertTo-Json -Depth 4 -Compress) -cne $json -or $record.schemaVersion -isnot [int] -or $record.checkpoints -isnot [Array]){throw 'CORE_BINDING_CANONICAL_CHECK_FAILED'}
Write-Output 'CORE_BINDING_CANONICAL_CHECK_PASSED'
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination $OutputDirectory
foreach($name in $legalFiles){Copy-Item -LiteralPath (Join-Path $repository $name) -Destination $OutputDirectory}
@{schemaVersion=1;product='AgentRoadNativeSetupPreview';sha256=(Get-FileHash $exe -Algorithm SHA256).Hash;unsigned=$true;canConfigureRemoteAccess=$true;nativePairingPreview=$true;published=$false}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $OutputDirectory 'package-manifest.json') -Encoding UTF8
