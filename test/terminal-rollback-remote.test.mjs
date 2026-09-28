import assert from 'node:assert/strict';
import test from 'node:test';
import {fixture} from './fixtures/terminal-rollback.mjs';
import {parseTerminalRollbackObservation,loadTerminalRollbackObserver,buildTerminalRollbackObserver} from '../src/runtime/terminal-rollback-remote.mjs';
function execution(){const f=fixture(),o=f.observation;return {exitCode:0,signal:null,stderr:'',stdout:JSON.stringify({schemaVersion:1,capsuleBase64:Buffer.from(o.capsuleJson).toString('base64'),journalBase64:Buffer.from(o.journalJson).toString('base64'),activeAbsent:true,previousAbsent:true,generationAbsent:true,tombstoneAbsent:true,archiveBytes:o.archiveBytes,archiveSha256:o.archiveSha256})};}
test('preserves exact signed and journal bytes across console code pages',()=>{assert.deepEqual(parseTerminalRollbackObservation(execution()),fixture().observation);});
for(const [name,edit] of [
 ['stderr',r=>{r.stderr='warning';}],['nonzero exit',r=>{r.exitCode=1;}],['extra stdout',r=>{r.stdout+='\n';}],
 ['malformed base64',r=>{let v=JSON.parse(r.stdout);v.journalBase64+='=';r.stdout=JSON.stringify(v);}],
 ['extra field',r=>{let v=JSON.parse(r.stdout);v.extra=true;r.stdout=JSON.stringify(v);}],
])test(`rejects ${name}`,()=>{const r=execution();edit(r);assert.throws(()=>parseTerminalRollbackObservation(r));});
test('source drift invalidates an observer bundle',async()=>{const f=fixture(),b=await loadTerminalRollbackObserver();assert.ok(buildTerminalRollbackObserver(b,f.failedState,f.controllerPublicKey).length<131072);assert.throws(()=>buildTerminalRollbackObserver({...b,definitions:b.definitions+'\n'},f.failedState,f.controllerPublicKey));});
