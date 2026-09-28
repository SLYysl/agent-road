import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readPrivateText, pairRequest } from '../src/pairing/client.mjs';
test('private configuration refuses public-readable files and symlinks',async t=>{
 const root=await mkdtemp(join(tmpdir(),'pair-private-test-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const file=join(root,'config'),link=join(root,'link');
 await writeFile(file,'secret',{mode:0o644});await assert.rejects(readPrivateText(file),{code:'PAIR_CONFIG_UNSAFE'});
 await symlink(file,link);await assert.rejects(readPrivateText(link));
});
test('client bounds responses and never retries an uncertain POST',async()=>{
 let calls=0;
 await assert.rejects(pairRequest('https://pair.example','create',{}, {fetchImpl:async()=>{calls++;throw Error('private network data');}}),{code:'PAIR_REQUEST_UNCERTAIN'});
 assert.equal(calls,1);
 await assert.rejects(pairRequest('https://pair.example','status',{}, {fetchImpl:async()=>new Response('x'.repeat(40001))}),{code:'PAIR_RESPONSE_INVALID'});
});
test('client rejects redirect and uses finite redacted errors',async()=>{
 await assert.rejects(pairRequest('https://pair.example','status',{}, {fetchImpl:async(url,options)=>{
 assert.equal(options.redirect,'error');assert.equal(options.method,'POST');
 return Response.json({error:'secret provider detail'},{status:500});
 }}),{code:'PAIR_REQUEST_FAILED'});
});

test('explicit v2 request never falls back to command protocol on rejection',async()=>{
 let calls=0;
 await assert.rejects(pairRequest('https://pair.example','receive',{}, {protocolVersion:2,fetchImpl:async(url)=>{
  calls++;assert.equal(url,'https://pair.example/v2/receive');
  return Response.json({code:'PAIR_PROTOCOL_UNSUPPORTED'},{status:404});
 }}),{code:'PAIR_PROTOCOL_UNSUPPORTED'});
 assert.equal(calls,1);
 await assert.rejects(pairRequest('https://pair.example','receive',{}, {protocolVersion:3,fetchImpl:()=>{throw Error('must not call');}}),{code:'PAIR_PROTOCOL_UNSUPPORTED'});
});
