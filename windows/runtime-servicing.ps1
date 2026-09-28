$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$workers=@(Get-Process TiWorker,msiexec -ErrorAction SilentlyContinue)
$installer=Get-Service TrustedInstaller -ErrorAction SilentlyContinue
[Console]::Out.Write((@{servicingActive=($workers.Count -gt 0 -or ($null -ne $installer -and $installer.Status -eq 'Running'))}|ConvertTo-Json -Compress))
