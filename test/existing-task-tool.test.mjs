import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';
const run=args=>spawnSync(process.execPath,['tools/run-existing-task.mjs',...args],{encoding:'utf8'});
test('rejects incomplete invocation without connecting',()=>{
 const r=run(['dev_test']);assert.equal(r.status,2);assert.equal(r.stdout,'');assert.match(r.stderr,/^Usage:/);
});
test('device mismatch in private inspection fails before task loading or transport',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'existing-task-test-'));
 try{
  await writeFile(join(dir,'context.json'),JSON.stringify({deviceId:'dev_other'}),{mode:0o600});
  await writeFile(join(dir,'execution.json'),JSON.stringify({deviceId:'dev_other',operation:'exec',exitCode:0,stderr:''}),{mode:0o600});
  const r=run(['dev_test',dir,'/missing-task.ps1','git']);
  assert.equal(r.status,2);assert.equal(r.stdout,'');assert.equal(r.stderr,'EXISTING_TASK_DEVICE_MISMATCH\n');
 }finally{await rm(dir,{recursive:true,force:true});}
});

test('rejects noncanonical or excessive timeouts before loading an inspection',()=>{
 for(const value of ['0','1801','01','1.5','Infinity']){
  const r=run(['dev_test','/missing','/missing.ps1','python',value]);
  assert.equal(r.status,2);assert.equal(r.stdout,'');assert.match(r.stderr,/^Usage:/);
 }
});
