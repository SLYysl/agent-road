import assert from 'node:assert/strict';
import test from 'node:test';
import {runProcess} from '../src/process/run-process.mjs';
import {WINDOWS_RUNTIME_RECOVERY_INSPECT_WRAPPER,encodeRemotePayload} from '../src/remote/windows-remote.mjs';

test('Windows recovery query for one boot event returns one record, not an EOF sentinel', {skip:process.platform!=='win32'},async()=>{
 const source=WINDOWS_RUNTIME_RECOVERY_INSPECT_WRAPPER(encodeRemotePayload({schemaVersion:1,protocolRevision:1,operationId:'a'.repeat(32),beforeBootMarker:null}));
 const start=source.indexOf('function Read-EventPair('),end=source.indexOf(';function ',start);
 assert.ok(start>=0&&end>start);
 const fixture=`$ErrorActionPreference='Stop';${source.slice(start,end)}
 $query="*[System[Provider[@Guid='{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}'] and (EventID=12)]]"
 $latest=@(Read-EventPair $query $true);if($latest.Count -lt 1){throw 'BOOT_EVENT_MISSING'}
 try{$id=$latest[0].RecordId}finally{foreach($event in $latest){$event.Dispose()}}
 $one=@(Read-EventPair ("*[System[(EventRecordID="+$id+")]]") $false)
 try{[Console]::Out.Write((@{count=$one.Count;matches=($one.Count -eq 1 -and $one[0].RecordId -eq $id)}|ConvertTo-Json -Compress))}finally{foreach($event in $one){if($null -ne $event){$event.Dispose()}}}`;
 const result=await runProcess('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(fixture,'utf16le').toString('base64')],{timeoutMs:15000,maxOutputBytes:4096});
 assert.equal(result.exitCode,0);assert.equal(result.signal,null);assert.equal(result.stderr,'');
 assert.deepEqual(JSON.parse(result.stdout),{count:1,matches:true});
});
