import { randomUUID } from 'node:crypto';
import {
  encodeRemotePayload,
  powershellInvocation,
  WINDOWS_EXEC_FINALIZE_WRAPPER,
} from '../../src/remote/windows-remote.mjs';

export function buildExecFinalizeFixture() {
  const cases = [
    { name: 'valid-exit-seven', record: '{"exitCode":7,"schemaVersion":1}', exit: 0, out: '7' },
    { name: 'malformed-receipt', record: '{"exitCode":7,"schemaVersion":2}', exit: 77, out: '' },
    { name: 'directory-cleanup-rejected', record: '{"exitCode":7,"schemaVersion":1}', exit: 78, out: '', directory: true },
  ].map((value) => {
    const id = randomUUID().replaceAll('-', '');
    const invocation = powershellInvocation(WINDOWS_EXEC_FINALIZE_WRAPPER,
      encodeRemotePayload({ schemaVersion: 1, operationId: id }));
    return { ...value, id, bootstrap: invocation.argv.at(-1), input: Buffer.from(invocation.stdin).toString('base64') };
  });
  const encoded = Buffer.from(JSON.stringify(cases)).toString('base64');
  return `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$cases=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}'))|ConvertFrom-Json
$root='C:\\ProgramData\\AgentRoad\\tasks'
$reports=@()
foreach($case in $cases){
 $path=Join-Path $root ($case.id+'.ps1');$result=Join-Path $root ($case.id+'.result.json')
 if((Test-Path -LiteralPath $path) -or (Test-Path -LiteralPath $result)){throw 'FIXTURE_COLLISION'}
 $p=$null
 try{
  if($case.directory){[void][IO.Directory]::CreateDirectory($path)}else{[IO.File]::WriteAllText($path,'# fixture')}
  [IO.File]::WriteAllText($result,$case.record,(New-Object Text.UTF8Encoding($false)))
  $acl=New-Object Security.AccessControl.FileSecurity
  $acl.SetAccessRuleProtection($true,$false)
  $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
  foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'FullControl','Allow')))}
  [IO.File]::SetAccessControl($result,$acl)
  $si=New-Object Diagnostics.ProcessStartInfo
  $si.FileName='powershell.exe';$si.Arguments='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+$case.bootstrap
  $si.UseShellExecute=$false;$si.CreateNoWindow=$true
  $si.RedirectStandardInput=$true;$si.RedirectStandardOutput=$true;$si.RedirectStandardError=$true
  $p=New-Object Diagnostics.Process;$p.StartInfo=$si;[void]$p.Start()
  $out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync()
  $inputBytes=[Convert]::FromBase64String($case.input)
  $p.StandardInput.BaseStream.Write($inputBytes,0,$inputBytes.Length);$p.StandardInput.Close()
  $done=$p.WaitForExit(20000);if(!$done){$p.Kill();$p.WaitForExit()}
  $retained=(Test-Path -LiteralPath $path) -and (Test-Path -LiteralPath $result)
  $absent=!(Test-Path -LiteralPath $path) -and !(Test-Path -LiteralPath $result)
  $passed=$done -and $p.ExitCode -eq $case.exit -and $out.Result -ceq $case.out -and $err.Result -ceq '' -and $(if($case.exit -eq 0){$absent}else{$retained})
  $reports+=@{name=$case.name;passed=$passed;exitCode=$p.ExitCode}
 }finally{
  if($p){$p.Dispose()}
  if(Test-Path -LiteralPath $path){if($case.directory){[IO.Directory]::Delete($path,$false)}else{[IO.File]::Delete($path)}}
  if(Test-Path -LiteralPath $result){[IO.File]::Delete($result)}
 }
}
[Console]::Out.Write((@{cases=$reports;passed=(@($reports|Where-Object {!$_.passed}).Count -eq 0)}|ConvertTo-Json -Depth 4 -Compress))`;
}
