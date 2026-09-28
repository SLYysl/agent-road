import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp,writeFile,symlink,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {buildJobControl,validateJobRequest} from '../src/jobs/background-task.mjs';
const jobId='job_'+'a'.repeat(32);
test('rejects malformed identities, unsupported actions and oversized or invalid tasks',()=>{
  for(const change of [{jobId:'../a'},{action:'restart'},{source:''},{source:'x\0y'},{source:'x'.repeat(65537)},{timeoutSeconds:0},{timeoutSeconds:86401},{timeoutSeconds:1.5}]){
    assert.throws(()=>validateJobRequest({action:'start',jobId,source:'exit 0',...change}),/JOB_INPUT_INVALID/);
  }
});
test('serializes task source as data and only start carries worker files',async()=>{
  const source="Write-Output '中文🙂'; exit 7";
  const script=await buildJobControl({action:'start',jobId,source,timeoutSeconds:90});
  const encoded=/FromBase64String\('([^']+)'\)/.exec(script)[1];
  const data=JSON.parse(Buffer.from(encoded,'base64').toString());
  assert.equal(data.files['task.ps1'],source);
  assert.equal(JSON.parse(data.files['config.json']).timeoutSeconds,90);
  for(const action of ['status','logs','cancel','remove']){
    const text=await buildJobControl({action,jobId});
    const raw=/FromBase64String\('([^']+)'\)/.exec(text)[1];
    assert.deepEqual(JSON.parse(Buffer.from(raw,'base64').toString()).files,{});
  }
});
test('CLI rejects invalid controls before allocating or connecting',()=>{
  for(const args of [['restart','dev_test',jobId],['status','dev_test','x'],['start','dev_test','/missing','86401'],['cancel','dev_test',jobId,'extra']]){
    const result=spawnSync(process.execPath,['tools/background-task.mjs',...args],{encoding:'utf8'});
    assert.equal(result.status,2);assert.equal(result.stdout,'');assert.equal(result.stderr,'JOB_INPUT_INVALID\n');
  }
});

test('CLI rejects empty, oversized, invalid UTF-8 and symlink sources before dispatch',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'agent-road-job-input-'));
  try{
    const cases=[['empty',Buffer.alloc(0)],['large',Buffer.alloc(65537,120)],['utf8',Buffer.from([0xff])]];
    for(const [name,bytes] of cases)await writeFile(join(dir,name),bytes);
    await symlink(join(dir,'empty'),join(dir,'link'));
    for(const name of [...cases.map(([name])=>name),'link']){
      const result=spawnSync(process.execPath,['tools/background-task.mjs','start','dev_test',join(dir,name)],{encoding:'utf8'});
      assert.equal(result.status,2);assert.equal(result.stdout,'');assert.match(result.stderr,/^JOB_(INPUT_INVALID|CONTROL_FAILED)\n$/);
    }
  }finally{await rm(dir,{recursive:true,force:true});}
});


test('job output is private by default and opt-in preserves exact bounded byte records',async()=>{
  const {jobConsoleResponse}=await import('../src/work/job.mjs');
  // A tail may start inside a multibyte character; do not silently transcode it.
  const bytes=Buffer.from([0x80,0xff,0x0a]);
  const response={jobId,state:{status:'SUCCEEDED',exitCode:0},
    stdout:{offset:65536,bytes:3,base64:bytes.toString('base64')},
    stderr:{offset:0,bytes:0,base64:''}};
  assert.deepEqual(jobConsoleResponse(response),{jobId,state:response.state});
  assert.deepEqual(jobConsoleResponse(response,true),response);
  assert.deepEqual(Buffer.from(jobConsoleResponse(response,true).stdout.base64,'base64'),bytes);
  assert.equal(response.stdout.offset,65536,'private response must not be mutated');
});

test('output opt-in is only accepted once and only for logs',()=>{
  for(const args of [
    ['status','dev_test',jobId,'--include-output'],
    ['logs','dev_test',jobId,'--include-output','--include-output'],
    ['logs','dev_test',jobId,'--unknown'],
    ['start','dev_test','/missing','--include-output'],
  ]){
    const result=spawnSync(process.execPath,['tools/background-task.mjs',...args],{encoding:'utf8'});
    assert.equal(result.status,2);assert.equal(result.stdout,'');assert.equal(result.stderr,'JOB_INPUT_INVALID\n');
  }
});
