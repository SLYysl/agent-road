$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$svc=Get-CimInstance Win32_Service -Filter "Name='sshd'"
$event=Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Kernel-General';Id=12} -MaxEvents 1
[ordered]@{host=$env:COMPUTERNAME;utc=[DateTime]::UtcNow.ToString('o');boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');bootRecord=$event.RecordId;bootEventUtc=$event.TimeCreated.ToUniversalTime().ToString('o');sshd=[string](Get-Service sshd).Status;sshdPid=$svc.ProcessId;sshdExit=$svc.ExitCode;tailscale=[string](Get-Service Tailscale).Status;listener=(@(Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue).Count -gt 0)}|ConvertTo-Json -Compress
