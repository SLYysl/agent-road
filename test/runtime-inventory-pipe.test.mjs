import assert from 'node:assert/strict';
import test from 'node:test';
import {runProcess} from '../src/process/run-process.mjs';
import {buildInventoryPipeFixture} from './fixtures/runtime-inventory-pipe.mjs';
import {retentionScriptInvocation} from '../src/runtime/staged-retention-remote.mjs';

test('inventory payload completes while its parent keeps stdin open', {skip:process.platform!=='win32'},async()=>{
 const invocation=retentionScriptInvocation(await buildInventoryPipeFixture());
 const result=await runProcess(invocation.argv[0],invocation.argv.slice(1),{
  stdinText:invocation.stdin,timeoutMs:20000,maxOutputBytes:4096,
 });
 assert.equal(result.exitCode,0);assert.equal(result.signal,null);assert.equal(result.stderr,'');
 assert.deepEqual(JSON.parse(result.stdout),{completedWithoutEof:true,isolated:true,stdinKeptOpen:true,payloadExecuted:true});
});
