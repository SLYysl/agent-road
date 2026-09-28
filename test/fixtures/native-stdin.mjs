import { createHash } from 'node:crypto';
import { powershellInvocation, WINDOWS_ADMINISTRATOR_PROBE_WRAPPER, encodeRemotePayload } from '../../src/remote/windows-remote.mjs';

function frame(source) {
  const bytes = Buffer.from(source, 'ascii');
  const chunks = bytes.toString('base64').match(/.{1,2048}/g);
  return ['AGENT_ROAD_STDIN_V1', `L:${bytes.length}`,
    `H:${createHash('sha256').update(bytes).digest('hex').toUpperCase()}`,
    `C:${chunks.length}`, ...chunks, 'END', ''].join('\r\n');
}

export function buildNativeStdinFixture() {
  const marker = 'FRAME_OK';
  const body = `[Console]::Out.Write('${marker}')`;
  const valid = frame(body);
  const maximum = frame(body + ';#' + 'x'.repeat(32768 - body.length - 2));
  const cases = [
    { name: 'fragmented-open-pipe', input: valid, close: false, exit: 0 },
    { name: 'maximum-open-pipe', input: maximum, close: false, exit: 0 },
    { name: 'hash-mismatch', input: valid.replace(/H:[A-F0-9]+/, 'H:' + '0'.repeat(64)), close: true, exit: 87 },
    { name: 'length-mismatch', input: valid.replace(/L:[0-9]+/, 'L:1'), close: true, exit: 87 },
    { name: 'truncated', input: valid.replace('END\r\n', ''), close: true, exit: 87 },
    { name: 'bom-rejected', input: '\uFEFF' + valid, close: true, exit: 87 },
  ].map(({ input, ...rest }) => ({ ...rest, input: Buffer.from(input, 'utf8').toString('base64') }));
  const bootstrap = powershellInvocation(WINDOWS_ADMINISTRATOR_PROBE_WRAPPER,
    encodeRemotePayload({ schemaVersion: 1, operationId: '0'.repeat(32) })).argv.at(-1);
  const encodedCases = Buffer.from(JSON.stringify(cases)).toString('base64');
  return `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$cases=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encodedCases}'))|ConvertFrom-Json
$reports=@()
foreach($case in $cases){
 $si=New-Object Diagnostics.ProcessStartInfo
 $si.FileName='powershell.exe';$si.Arguments='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${bootstrap}'
 $si.UseShellExecute=$false;$si.CreateNoWindow=$true
 $si.RedirectStandardInput=$true;$si.RedirectStandardOutput=$true;$si.RedirectStandardError=$true
 $p=New-Object Diagnostics.Process;$p.StartInfo=$si
 try{
  $null=$p.Start();$bytes=[Convert]::FromBase64String($case.input);$writeFailed=$false
  try{for($i=0;$i -lt $bytes.Length;$i+=37){$n=[Math]::Min(37,$bytes.Length-$i);$p.StandardInput.BaseStream.Write($bytes,$i,$n);$p.StandardInput.BaseStream.Flush()}}catch{$writeFailed=$true}
  if($case.close){$p.StandardInput.Close()}
  $done=$p.WaitForExit(20000)
  if(-not $done){$p.Kill();$p.WaitForExit()}
  $out=$p.StandardOutput.ReadToEnd();$err=$p.StandardError.ReadToEnd()
  $expected=if($case.exit -eq 0){'${marker}'}else{''}
  $passed=$done -and $p.ExitCode -eq $case.exit -and $out -ceq $expected -and $err -ceq '' -and ($case.exit -ne 0 -or -not $writeFailed)
  $reports+=@{name=$case.name;passed=$passed}
 }finally{$p.Dispose()}
}
[Console]::Out.Write((@{cases=$reports;passed=(@($reports|Where-Object {-not $_.passed}).Count -eq 0)}|ConvertTo-Json -Depth 4 -Compress))`;
}
