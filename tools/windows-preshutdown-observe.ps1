# Read-only service observation. Does not request shutdown or change service policy.
param([ValidateRange(0,1800)][int]$DurationSeconds = 0)
$ErrorActionPreference='Stop'
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class AgentRoadPreShutdownInspect {
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenSCManager(string m,string d,uint a);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenService(IntPtr m,string n,uint a);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool QueryServiceStatus(IntPtr s,out Status x);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool QueryServiceConfig2(IntPtr s,uint l,IntPtr b,uint z,out uint needed);
 [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr h);
 [StructLayout(LayoutKind.Sequential)] struct Status {public uint type,state,controls,exit,specific,checkpoint,wait;}
 public static long[] Read(string name) {
  // SC_MANAGER_CONNECT; SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS only.
  var manager=OpenSCManager(null,null,1);
  if(manager==IntPtr.Zero)throw new Exception("SCM_QUERY_FAILED");
  try {
   var service=OpenService(manager,name,5);
   if(service==IntPtr.Zero)return new long[]{-1,Marshal.GetLastWin32Error(),0,0,0};
   try {
    Status status;
    if(!QueryServiceStatus(service,out status))return new long[]{-1,Marshal.GetLastWin32Error(),0,0,0};
    var buffer=Marshal.AllocHGlobal(4);
    try {
     uint needed;
     long timeout=QueryServiceConfig2(service,7,buffer,4,out needed)?(long)(uint)Marshal.ReadInt32(buffer):-1;
     return new long[]{status.controls,status.state,timeout,status.checkpoint,status.wait};
    } finally { Marshal.FreeHGlobal(buffer); }
   } finally { CloseServiceHandle(service); }
  } finally { CloseServiceHandle(manager); }
 }
}
'@

# Targeted candidate list, not an exhaustive monitor of all Windows services.
$names=@('DiagTrack','DoSvc','gpsvc','SecurityHealthService','wuauserv','UsoSvc','BITS','TrustedInstaller','sshd','Tailscale')+@(Get-Service 'WpnUserService*' | Select-Object -ExpandProperty Name)
$last=@{};$clock=[Diagnostics.Stopwatch]::StartNew();$heartbeat=-30
Write-Output ([pscustomobject]@{kind='START';bootUtc=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress)
do {
 foreach($name in $names){
  $v=[AgentRoadPreShutdownInspect]::Read($name);$signature=$v -join ','
  if($last[$name] -ne $signature){
   $last[$name]=$signature
   $known=$v[0] -ge 0
   [pscustomobject]@{
    kind='SERVICE'
    elapsed=[Math]::Round($clock.Elapsed.TotalSeconds,2)
    utc=[DateTime]::UtcNow.ToString('o')
    name=$name
    queryResult=$(if($known){'OBSERVED'}else{'UNKNOWN'})
    nativeError=$(if($known){$null}else{$v[1]})
    controls=$(if($known){$v[0]}else{$null})
    state=$(if($known){$v[1]}else{$null})
    timeoutMs=$(if($known -and $v[2] -ge 0){$v[2]}else{$null})
    checkpoint=$(if($known){$v[3]}else{$null})
    waitHintMs=$(if($known){$v[4]}else{$null})
   }|ConvertTo-Json -Compress
  }
 }
 if($clock.Elapsed.TotalSeconds-$heartbeat -ge 30){$heartbeat=$clock.Elapsed.TotalSeconds;Write-Output ([pscustomobject]@{kind='HEARTBEAT';elapsed=[Math]::Round($heartbeat,2);utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress)}
 if($DurationSeconds -gt 0){Start-Sleep -Seconds 2}
} while($clock.Elapsed.TotalSeconds -lt $DurationSeconds)
Write-Output ([pscustomobject]@{kind='END';elapsed=[Math]::Round($clock.Elapsed.TotalSeconds,2)}|ConvertTo-Json -Compress)
