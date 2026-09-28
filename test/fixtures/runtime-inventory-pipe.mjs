import {readRuntimePlanInventoryPair} from '../../src/runtime/runtime-plan-inventory.mjs';
export async function buildInventoryPipeFixture() {
let invocation;
try{await readRuntimePlanInventoryPair({target:{},dependencies:{readInventoryScript:async()=>Buffer.from("param([switch]$PlanningObservation)\n[Console]::Out.Write('PAYLOAD_COMPLETE')"),trustedInput:()=>({}),withTrustedSshSession:async(_,fn)=>fn({invokeSsh:async(_,argv,options)=>{invocation={argv,options};throw Error();}}),selectAddress:async()=> '100.64.0.1',isTrustedSshSessionLockError:()=>false,runProcess:()=>{throw Error();}}});}catch{}
if(!invocation)throw Error('NO_INVOCATION');
const encoded=invocation.argv.at(-1),stdin=invocation.options.stdinText;
const source=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$si=New-Object Diagnostics.ProcessStartInfo;$si.FileName='powershell.exe';$si.Arguments='-NoLogo -NoProfile -NonInteractive -EncodedCommand ${encoded}';$si.UseShellExecute=$false;$si.CreateNoWindow=$true;$si.RedirectStandardInput=$true;$si.RedirectStandardOutput=$true;$si.RedirectStandardError=$true;$p=New-Object Diagnostics.Process;$p.StartInfo=$si;try{$null=$p.Start();$p.StandardInput.Write('${stdin}');$p.StandardInput.Flush();$done=$p.WaitForExit(7000);if(-not $done){$p.Kill();$p.WaitForExit()};$out=$p.StandardOutput.ReadToEnd();[Console]::Out.Write((@{isolated=$true;stdinKeptOpen=$true;completedWithoutEof=$done;payloadExecuted=($out -ceq 'PAYLOAD_COMPLETE')}|ConvertTo-Json -Compress))}finally{$p.Dispose()}`;
return source;
}
