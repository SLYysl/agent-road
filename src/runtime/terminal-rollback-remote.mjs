import {readFile,mkdir,open} from 'node:fs/promises';
import {createHash,randomUUID} from 'node:crypto';
import {join} from 'node:path';
import {gzipSync} from 'node:zlib';
import {TextDecoder} from 'node:util';
import {deriveRuntimeControllerKeyIdentity} from './runtime-manifest.mjs';
import {validateRuntimeStateRecord} from './runtime-state-store.mjs';
import {retentionScriptInvocation} from './staged-retention-remote.mjs';
import {trustedInput} from '../remote/remote-target.mjs';
import {withTrustedSshSession} from '../ssh/trusted-ssh-session.mjs';
import {selectAddress} from '../remote/windows-remote.mjs';
import {runProcess} from '../process/run-process.mjs';
const TAIL = `
$lock=$null
try {
 $invocation=[pscustomobject][ordered]@{schemaVersion=1;operationId=$binding.operationId;manifestDigest=$binding.manifestDigest}
 $script:Transaction=Get-AgentRoadTransaction $invocation
 $lock=Enter-AgentRoadMutationLock
 $script:Journal=Read-AgentRoadJournal
 Assert-AgentRoadRuntimeTopology $script:Journal
 Assert-AgentRoadJournalTransactionBinding $script:Journal $script:Transaction
 Assert-AgentRoadStagedTransaction $script:Transaction
 Assert-AgentRoadFileNode $script:Transaction.capsulePath
 $capsuleBytes=[IO.File]::ReadAllBytes($script:Transaction.capsulePath)
 $capsule=ConvertFrom-AgentRoadCanonicalJson $capsuleBytes 8192 'RUNTIME_SIGNATURE_INVALID'
 Assert-AgentRoadExactOrderedRecord $capsule $script:CapsuleFields 'RUNTIME_SIGNATURE_INVALID'
 $manifestBytes=$script:Utf8.GetBytes([string]$capsule.manifestJson)
 $manifest=ConvertFrom-AgentRoadCanonicalJson $manifestBytes 6144 'RUNTIME_SIGNATURE_INVALID'
 Assert-AgentRoadManifest $capsule $manifestBytes $manifest
 Assert-AgentRoadControllerSignature $capsule $manifestBytes
 Assert-AgentRoadPinnedControllerTrust ([string]$capsule.controllerPublicKeyJson)
 Assert-AgentRoadOperationBinding $script:Transaction $capsule $manifest $capsuleBytes
 if($capsule.controllerPublicKeyJson -cne $binding.controllerPublicKeyJson -or $manifest.deviceId -cne $binding.deviceId -or $capsule.generationDigest -cne $binding.generationDigest){throw 'RUNTIME_SIGNATURE_INVALID'}
 $j=$script:Journal
 if($j.status -cne 'rolled-back' -or $j.rollbackStatus -cne 'succeeded' -or $j.phase -cne 'rollback' -or $j.failureCode -cne 'RUNTIME_INTERNAL_ERROR' -or $j.generationDigest -cne $capsule.generationDigest -or $j.catalogDigest -cne $manifest.catalogDigest -or $j.inventoryDigest -cne $manifest.inventoryDigest -or $j.controllerKeyId -cne $capsule.controllerKeyId){throw 'RUNTIME_STATE_UNSUPPORTED'}
 if($null -ne $j.snapshot.active -or $null -ne $j.snapshot.previous -or $null -ne (Read-AgentRoadPointer $script:ActivePath) -or $null -ne (Read-AgentRoadPointer $script:PreviousPath)){throw 'RUNTIME_STATE_UNSUPPORTED'}
 if((Test-Path -LiteralPath (Join-Path $script:VersionsRoot $j.manifestDigest)) -or (Test-Path -LiteralPath (Join-Path $script:VersionsRoot ('.rollback-'+$j.manifestDigest)))){throw 'RUNTIME_STATE_UNSUPPORTED'}
 $archive=Assert-AgentRoadArtifact $script:Transaction $manifest.components[0]
 $journalBytes=[IO.File]::ReadAllBytes($script:JournalPath)
 $reread=ConvertFrom-AgentRoadCanonicalJson $journalBytes 4096 'RUNTIME_STATE_UNSUPPORTED'
 if(($reread|ConvertTo-Json -Depth 12 -Compress) -cne ($j|ConvertTo-Json -Depth 12 -Compress)){throw 'RUNTIME_STATE_UNSUPPORTED'}
 $result=[ordered]@{schemaVersion=1;capsuleBase64=[Convert]::ToBase64String($capsuleBytes);journalBase64=[Convert]::ToBase64String($journalBytes);activeAbsent=$true;previousAbsent=$true;generationAbsent=$true;tombstoneAbsent=$true;archiveBytes=[long](Get-Item -LiteralPath $archive -Force).Length;archiveSha256=Get-AgentRoadSha256 $archive}
 [Console]::Out.Write(($result|ConvertTo-Json -Depth 3 -Compress))
} finally {Exit-AgentRoadMutationLock $lock}
`;
const sha = s => createHash('sha256').update(s).digest('hex').toUpperCase();
function fail() {const e=new Error('RUNTIME_STATE_UNSUPPORTED');e.code=e.message;throw e;}
export async function loadTerminalRollbackObserver() {
 const source=await readFile(new URL('../../windows/runtime-provision-core.ps1',import.meta.url),'utf8');
 const marker='\n$lock = $null\n$capsule = $null';if(source.split(marker).length!==2)fail();
 const definitions=source.slice(0,source.indexOf(marker));
 return Object.freeze({definitions,executorDigest:sha(definitions+TAIL)});
}
export function buildTerminalRollbackObserver(bundle,stateInput,keyInput) {
 const state=validateRuntimeStateRecord(stateInput),key=deriveRuntimeControllerKeyIdentity(keyInput);
 if(bundle.executorDigest!==sha(bundle.definitions+TAIL))fail();
 const binding={deviceId:state.deviceId,operationId:state.operationId,manifestDigest:state.manifestDigest,generationDigest:state.generationDigest,controllerPublicKeyJson:key.controllerPublicKeyJson};
 const setup=`\n$binding=$script:Utf8.GetString([Convert]::FromBase64String('${Buffer.from(JSON.stringify(binding)).toString('base64')}'))|ConvertFrom-Json\n`;
 const bytes=Buffer.from(bundle.definitions+setup+TAIL);if(bytes.length>262144)fail();
 const z=gzipSync(bytes).toString('base64');
 return `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$z=[Convert]::FromBase64String('${z}');$m=New-Object IO.MemoryStream(,$z);$g=New-Object IO.Compression.GZipStream($m,[IO.Compression.CompressionMode]::Decompress);$q=New-Object IO.MemoryStream;$b=New-Object byte[] 8192;while(($n=$g.Read($b,0,$b.Length)) -gt 0){if($q.Length+$n -gt 262144){exit 88};$q.Write($b,0,$n)};$g.Dispose();$m.Dispose();$s=[Text.Encoding]::UTF8.GetString($q.ToArray());$q.Dispose();& ([ScriptBlock]::Create($s))`;
}
export function parseTerminalRollbackObservation(result) {
 if(result.exitCode!==0||result.signal!==null||result.stderr!==''||typeof result.stdout!=='string'||Buffer.byteLength(result.stdout)>24000)fail();
 let v;try{v=JSON.parse(result.stdout);}catch{fail();}
 const fields=['schemaVersion','capsuleBase64','journalBase64','activeAbsent','previousAbsent','generationAbsent','tombstoneAbsent','archiveBytes','archiveSha256'];
 if(v===null||Array.isArray(v)||Object.keys(v).length!==fields.length||fields.some(k=>!Object.hasOwn(v,k))||JSON.stringify(v)!==result.stdout)fail();
 const decode=(s,max)=>{if(typeof s!=='string'||s.length>max*2)fail();const b=Buffer.from(s,'base64');if(b.length>max||b.toString('base64')!==s)fail();return new TextDecoder('utf-8',{fatal:true}).decode(b);};
 return Object.freeze({schemaVersion:v.schemaVersion,capsuleJson:decode(v.capsuleBase64,8192),journalJson:decode(v.journalBase64,4096),activeAbsent:v.activeAbsent,previousAbsent:v.previousAbsent,generationAbsent:v.generationAbsent,tombstoneAbsent:v.tombstoneAbsent,archiveBytes:v.archiveBytes,archiveSha256:v.archiveSha256});
}
export async function observeTerminalRollback({target,bundle,state,controllerPublicKey,captureRoot}) {
 const call=retentionScriptInvocation(buildTerminalRollbackObserver(bundle,state,controllerPublicKey));
 const dir=join(captureRoot,'terminal-rollback-observe-'+randomUUID());await mkdir(dir,{mode:0o700});
 async function save(name,value){const f=await open(join(dir,name),'wx',0o600);try{await f.writeFile(JSON.stringify(value)+'\n');await f.sync();}finally{await f.close();}const d=await open(dir,'r');try{await d.sync();}finally{await d.close();}}
 await save('started.json',{mode:'READ_ONLY_TERMINAL_ROLLBACK',executorDigest:bundle.executorDigest});
 const result=await withTrustedSshSession(trustedInput(target,runProcess),async session=>session.invokeSsh(await selectAddress(session),call.argv,{stdinText:call.stdin,timeoutMs:120000,maxOutputBytes:24000}));
 await save('terminal.json',{exitCode:result.exitCode,signal:result.signal,stdout:result.stdout,stderr:result.stderr});
 return parseTerminalRollbackObservation(result);
}
