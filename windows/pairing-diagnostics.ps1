param([ValidateRange(1,1440)][int]$LookbackMinutes=30)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
# Read-only finite facts. Never emit event messages, resources, command lines or tokens.
$result=@{schemaVersion=1;guestUtc=[DateTime]::UtcNow.ToString('o');eventRead='UNAVAILABLE';events=@();protectionRead='UNAVAILABLE';bootstrapDirectory='UNKNOWN';servicesRead='UNAVAILABLE';services=@()}
try {
    $status=Get-MpComputerStatus
    $result.protectionRead='AVAILABLE'
    $result.antivirusEnabled=[bool]$status.AntivirusEnabled
    $result.realTimeProtectionEnabled=[bool]$status.RealTimeProtectionEnabled
    $version=[string]$status.AntivirusSignatureVersion
    if($version -match '^\d{1,8}(\.\d{1,8}){1,5}$'){$result.signatureVersion=$version}
} catch {}
try {
    $events=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1116,1117;StartTime=(Get-Date).AddMinutes(-$LookbackMinutes)} -MaxEvents 20)
    $result.events=@(foreach($event in $events){
        $xml=[xml]$event.ToXml()
        $item=@{id=[int]$event.Id;recordId=[long]$event.RecordId;utc=$event.TimeCreated.ToUniversalTime().ToString('o')}
        foreach($data in $xml.Event.EventData.Data){
            $value=[string]$data.InnerText
            if($data.Name -ceq 'Threat Name' -and $value -cmatch '^[A-Za-z0-9:/._! -]{1,160}$'){$item.threat=$value}
            if($data.Name -ceq 'Action Name' -and $value -cmatch '^[A-Za-z -]{1,64}$'){$item.action=$value}
            if($data.Name -ceq 'Error Code' -and $value -cmatch '^0x[0-9a-fA-F]{8}$'){$item.errorCode=$value}
        }
        [pscustomobject]$item
    })
    $result.eventRead='AVAILABLE'
} catch {
    if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){$result.eventRead='NO_MATCHES'}
}
try {$result.bootstrapDirectory=if(Test-Path -LiteralPath 'C:\ProgramData\AgentRoad'){'PRESENT'}else{'ABSENT'}} catch {}
try {
    $services=@(Get-Service | Where-Object {$_.Name -in @('Tailscale','sshd')})
    $result.services=@($services | ForEach-Object {@{name=$_.Name;status=[string]$_.Status}})
    $result.servicesRead='AVAILABLE'
} catch {}
$result | ConvertTo-Json -Depth 5 -Compress
