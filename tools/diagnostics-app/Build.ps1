param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutputDirectory){throw 'BUILD_OUTPUT_EXISTS'}
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(!(Test-Path -LiteralPath $compiler)){throw 'FRAMEWORK_COMPILER_REQUIRED'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$exe=Join-Path $OutputDirectory 'AgentRoadDiagnostics.exe'
& $compiler /nologo /target:winexe /optimize+ /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.ServiceProcess.dll /r:System.Web.Extensions.dll /r:System.Xml.dll ("/win32manifest:"+(Join-Path $PSScriptRoot 'app.manifest')) "/out:$exe" (Join-Path $PSScriptRoot 'Program.cs')
if($LASTEXITCODE -ne 0){throw 'COMPILE_FAILED'}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Install.ps1') -Destination $OutputDirectory
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination $OutputDirectory
@{schemaVersion=1;product='AgentRoadDiagnosticsPreview';sha256=(Get-FileHash $exe -Algorithm SHA256).Hash;unsigned=$true;remoteAccess=$false}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $OutputDirectory 'package-manifest.json') -Encoding UTF8
Write-Output 'DIAGNOSTICS_BUILD_COMPLETE_UNSIGNED'
