import {WINDOWS_RUNTIME_PROVISION_INVOKE_WRAPPER,encodeRemotePayload} from '../../src/remote/windows-remote.mjs';
export function buildRuntimeChildInputFixture(){
 const payload={schemaVersion:1,operationId:'a'.repeat(32),expectedBytes:42,expectedSha256:'A'.repeat(64),runtimeOperationId:'b'.repeat(32),manifestDigest:'B'.repeat(64)};
 const source=WINDOWS_RUNTIME_PROVISION_INVOKE_WRAPPER(encodeRemotePayload(payload));
 const setupStart=source.indexOf('$childInput='),setupEnd=source.indexOf(";$parent=",setupStart);
 const invokeStart=source.indexOf('try{$started=$child.Start()'),invokeEnd=source.indexOf(';if($null -eq $scriptExitCode',invokeStart);
 if(setupStart<0||setupEnd<0||invokeStart<0||invokeEnd<0)throw Error('FIXTURE_BOUNDARY');
 const expected=JSON.stringify({schemaVersion:1,operationId:payload.runtimeOperationId,manifestDigest:payload.manifestDigest});
 const child=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::InputEncoding=New-Object Text.UTF8Encoding($false,$true);$text=[Console]::In.ReadToEnd();if($text -cne '${expected}'){exit 9};exit 0`;
 return `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$payload='${JSON.stringify(payload)}'|ConvertFrom-Json;${source.slice(setupStart,setupEnd)}
 $startInfo=New-Object Diagnostics.ProcessStartInfo;$startInfo.FileName='powershell.exe';$startInfo.Arguments='-NoLogo -NoProfile -NonInteractive -EncodedCommand ${Buffer.from(child,'utf16le').toString('base64')}';$startInfo.UseShellExecute=$false;$startInfo.RedirectStandardInput=$true;$startInfo.CreateNoWindow=$true;
 $child=New-Object Diagnostics.Process;$child.StartInfo=$startInfo;$scriptExitCode=$null;${source.slice(invokeStart,invokeEnd)}
 [Console]::Out.Write((@{isolated=$true;exactInputAndEof=($scriptExitCode -eq 0);childExitCode=$scriptExitCode}|ConvertTo-Json -Compress))`;
}
