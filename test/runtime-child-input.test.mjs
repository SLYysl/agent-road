import assert from 'node:assert/strict';
import test from 'node:test';
import {runProcess} from '../src/process/run-process.mjs';
import {buildRuntimeChildInputFixture} from './fixtures/runtime-child-input.mjs';
import {retentionScriptInvocation} from '../src/runtime/staged-retention-remote.mjs';
test('Windows runtime child receives exact UTF-8 invocation and EOF on .NET Framework',{skip:process.platform!=='win32'},async()=>{
 const call=retentionScriptInvocation(buildRuntimeChildInputFixture());
 const result=await runProcess(call.argv[0],call.argv.slice(1),{stdinText:call.stdin,timeoutMs:20000,maxOutputBytes:4096});
 assert.equal(result.exitCode,0);assert.equal(result.signal,null);assert.equal(result.stderr,'');
 assert.deepEqual(JSON.parse(result.stdout),{exactInputAndEof:true,isolated:true,childExitCode:0});
});
