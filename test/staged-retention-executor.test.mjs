import assert from 'node:assert/strict';
import test from 'node:test';
import { runProcess } from '../src/process/run-process.mjs';
import { buildRetentionExecutorFixture } from './fixtures/staged-retention-executor.mjs';
import { retentionScriptInvocation } from '../src/runtime/staged-retention-remote.mjs';

test('Windows isolated retention executor and lost-ack reconciliation', {skip:process.platform!=='win32'}, async()=>{
 const invocation=retentionScriptInvocation(await buildRetentionExecutorFixture());
 const result=await runProcess(invocation.argv[0],invocation.argv.slice(1),{
  stdinText:invocation.stdin,timeoutMs:120000,maxOutputBytes:8192,
 });
 assert.equal(result.exitCode,0);assert.equal(result.signal,null);assert.equal(result.stderr,'');
 const report=JSON.parse(result.stdout);
 assert.equal(report.isolated,true);assert.equal(report.allPassed,true);
 assert.equal(Object.keys(report.cases).length,11);
 assert.ok(Object.values(report.cases).every(value=>value===true));
});
