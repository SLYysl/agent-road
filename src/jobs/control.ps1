$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$utf8=New-Object Text.UTF8Encoding($false)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$root='C:\ProgramData\AgentRoad\jobs'
$directory=Join-Path $root $request.jobId
$name='AgentRoad-'+$request.jobId
function Assert-Chain([string]$path) {
  $part=Get-Item -LiteralPath $path -Force
  while($null -ne $part){
    if(($part.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'JOB_PATH_UNSAFE'}
    if($part -is [IO.FileInfo]){$part=$part.Directory}else{$part=$part.Parent}
  }
}
function Restrict-Directory([string]$path) {
  $acl=New-Object Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true,$false)
  foreach($id in @($sid,'S-1-5-18','S-1-5-32-544')|Select-Object -Unique){
    $identity=New-Object Security.Principal.SecurityIdentifier($id)
    $rule=New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $path -AclObject $acl
}
function Assert-Private([string]$path) {
  Assert-Chain $path
  $acl=Get-Acl -LiteralPath $path
  foreach($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
    if($ace.AccessControlType -eq 'Allow' -and $ace.IdentityReference.Value -notin @($sid,'S-1-5-18','S-1-5-32-544')){throw 'JOB_PATH_UNSAFE'}
  }
}
function Read-Small([string]$path) {
  Assert-Private $path
  if((Get-Item -LiteralPath $path).Length -gt 65536){throw 'JOB_STATE_INVALID'}
  $file=[IO.File]::Open($path,'Open','Read',([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
  try{$reader=New-Object IO.StreamReader($file,$utf8);try{return $reader.ReadToEnd()}finally{$reader.Dispose()}}finally{$file.Dispose()}
}
try {
  if($request.action -eq 'start') {
    Assert-Chain (Split-Path $root)
    if(!(Test-Path -LiteralPath $root)){[void](New-Item -ItemType Directory -Path $root);Restrict-Directory $root}
    Assert-Private $root
    if((Test-Path -LiteralPath $directory) -or (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue)){throw 'JOB_ALREADY_EXISTS'}
    [void](New-Item -ItemType Directory -Path $directory);Restrict-Directory $directory
    foreach($entry in $request.files.PSObject.Properties){
      $encoding=$utf8
      if($entry.Name.EndsWith('.ps1')){$encoding=New-Object Text.UTF8Encoding($true)}
      [IO.File]::WriteAllText((Join-Path $directory $entry.Name),[string]$entry.Value,$encoding)
    }
    [IO.File]::WriteAllText((Join-Path $directory 'owner.txt'),$sid,$utf8)
    [IO.File]::WriteAllText((Join-Path $directory 'state.json'),'{"status":"QUEUED","exitCode":null}',$utf8)
    $exe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $args='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $directory 'worker.ps1')+'" -Directory "'+$directory+'"'
    $taskAction=New-ScheduledTaskAction -Execute $exe -Argument $args -WorkingDirectory $directory
    $principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType S4U -RunLevel Limited
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds ([int]$request.timeoutSeconds+120)) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    [void](Register-ScheduledTask -TaskName $name -Action $taskAction -Principal $principal -Settings $settings)
    Start-ScheduledTask -TaskName $name
    @{jobId=$request.jobId;status='SUBMITTED'}|ConvertTo-Json -Compress
    exit 0
  }
  if(!(Test-Path -LiteralPath $directory)){throw 'JOB_NOT_FOUND'}
  Assert-Private $directory
  if((Read-Small (Join-Path $directory 'owner.txt')) -cne $sid){throw 'JOB_OWNER_MISMATCH'}
  $state=(Read-Small (Join-Path $directory 'state.json'))|ConvertFrom-Json
  $scheduled=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
  if($null -ne $scheduled){
    $expectedExe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $expectedArgs='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $directory 'worker.ps1')+'" -Directory "'+$directory+'"'
    $principalId=[string]$scheduled.Principal.UserId
    if($principalId -notmatch '^S-1-'){$principalId=(New-Object Security.Principal.NTAccount($principalId)).Translate([Security.Principal.SecurityIdentifier]).Value}
    if(@($scheduled.Actions).Count -ne 1 -or $scheduled.Actions[0].Execute -ine $expectedExe -or $scheduled.Actions[0].Arguments -cne $expectedArgs -or $scheduled.Actions[0].WorkingDirectory -ine $directory -or $principalId -cne $sid -or [string]$scheduled.Principal.LogonType -ne 'S4U' -or [string]$scheduled.Principal.RunLevel -ne 'Limited'){throw 'JOB_DEFINITION_CHANGED'}
  }
  $schedulerResult=$null
  if($null -ne $scheduled){$schedulerResult=(Get-ScheduledTaskInfo -TaskName $name).LastTaskResult}
  $active=$null -ne $scheduled -and [string]$scheduled.State -in @('Running','Queued')
  $terminal=$state.status -in @('SUCCEEDED','FAILED','CANCELLED','TIMED_OUT','OUTPUT_LIMIT')
  if(!$terminal -and !$active){
    # The worker may publish its terminal state between the first read and the
    # scheduler becoming inactive. Reconcile that state before reporting a gap.
    $state=(Read-Small (Join-Path $directory 'state.json'))|ConvertFrom-Json
    $terminal=$state.status -in @('SUCCEEDED','FAILED','CANCELLED','TIMED_OUT','OUTPUT_LIMIT')
    if(!$terminal){$state.status='INTERRUPTED_OR_NOT_STARTED'}
  }
  if($request.action -eq 'cancel') {
    if(!$terminal){
      $cancel=Join-Path $directory 'cancel.request'
      if(!(Test-Path -LiteralPath $cancel)){$file=[IO.File]::Open($cancel,'CreateNew','Write','None');$file.Dispose()}
      $state.status='CANCEL_REQUESTED'
    }
  } elseif($request.action -eq 'remove') {
    if($active -or !$terminal){throw 'JOB_NOT_TERMINAL'}
    if($null -ne $scheduled){Unregister-ScheduledTask -TaskName $name -Confirm:$false}
  }
  $response=@{jobId=$request.jobId;schedulerResult=$schedulerResult;state=$state;schedulerActive=[bool]$active;definitionPresent=($null -ne $scheduled -and $request.action -ne 'remove')}
  if($request.action -eq 'logs') {
    foreach($stream in @('stdout','stderr')){
      $path=Join-Path $directory ($stream+'.log')
      $value=@{base64='';offset=0;bytes=0}
      if(Test-Path -LiteralPath $path){
        Assert-Private $path
        $file=[IO.File]::Open($path,'Open','Read','ReadWrite')
        try{
          $length=$file.Length;$offset=[Math]::Max(0,$length-65536)
          [void]$file.Seek($offset,'Begin');$buffer=New-Object byte[] ([int]($length-$offset));$count=0
          while($count -lt $buffer.Length){$n=$file.Read($buffer,$count,$buffer.Length-$count);if($n -eq 0){break};$count+=$n}
          $value=@{base64=[Convert]::ToBase64String($buffer,0,$count);offset=$offset;bytes=$count}
        }finally{$file.Dispose()}
      }
      $response[$stream]=$value
    }
  }
  $response|ConvertTo-Json -Depth 5 -Compress
} catch {
  $code=[string]$_.Exception.Message
  if($code -cnotmatch '^JOB_[A-Z_]+$'){$code='JOB_CONTROL_FAILED'}
  [Console]::Error.WriteLine($code);exit 1
}
