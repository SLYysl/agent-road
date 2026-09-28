import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, stat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runPairCommand } from '../src/pairing/controller.mjs';
import { main } from '../src/cli.mjs';
import { pairingError } from '../src/pairing/protocol.mjs';
const command='powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand QQ==';
async function fixture(t, overrides={}) {
  const root=await mkdtemp(join(tmpdir(),'pair-controller-test-'));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const adminTokenFile=join(root,'admin'),tailscaleAuthKeyFile=join(root,'tailscale'),config=join(root,'config');
  await writeFile(adminTokenFile,'a'.repeat(43),{mode:0o600});
  await writeFile(tailscaleAuthKeyFile,(overrides.api?'tskey-api-':'tskey-auth-')+'b'.repeat(20),{mode:0o600});
  await writeFile(config,JSON.stringify({origin:'https://pair.example',adminTokenFile,...(overrides.api?{tailscaleApiTokenFile:tailscaleAuthKeyFile}:{tailscaleAuthKeyFile})}),{mode:0o600});
  let output='',errors='',approved=false,approvedConfiguration;const actions=[];let finish;
  const done=new Promise(resolve=>{finish=resolve;});
  const request=async(origin,action,body,options)=>{
    if(overrides.native)assert.equal(options.protocolVersion,2);
    actions.push(action);
    if(overrides[action])return overrides[action](body);
    if(action==='create')return {state:'WAITING',expiresAt:Date.now()+600000,...(overrides.native?{protocolVersion:2,deliveryKind:'configuration'}:{codeInJoinUrl:true})};
    if(action==='status'){
      if(approved && overrides.observeDelivery){finish();return {state:'CONSUMED'};}
      return {state:'CLAIMED',claim:{id:'c'.repeat(64),verification:'12345678'}};
    }
    if(action==='approve'){approvedConfiguration=body.configuration;if(overrides.native){assert.equal(body.command,undefined);assert.equal(body.configuration.kind,'agent-road-native-enrollment');assert.equal(body.configuration.enrollmentToken,'a'.repeat(43));}else assert.equal(body.command,command);approved=true;if(!overrides.observeDelivery)finish();return {state:'APPROVED'};}
    if(action==='cancel')throw pairingError('PAIR_ALREADY_DELIVERED');
    throw Error('unexpected action');
  };
  const code=await runPairCommand(['--config',config,...(overrides.native?['--native-preview']:[]),...(overrides.args??[])],overrides.native?{AGENT_ROAD_NATIVE_PREVIEW:'1'}:{}, {
    stdout:{write:s=>{output+=s;}},stderr:{write:s=>{errors+=s;}},
  },{request,dependencies:async()=>({startReceiver:async options=>{assert.equal(options.protocolVersion,2);assert.equal(options.signer,undefined);assert.equal(options.stageOneBytes,undefined);return {};}}),createAuthKey:overrides.createAuthKey,revokeAuthKey:overrides.revokeAuthKey,confirm:overrides.confirm??(async code=>code==='12345678'),enroll:async(args,env,io)=>{
    assert.deepEqual(args,['enroll','--name','New Windows PC','--timeout-minutes',overrides.timeout??'30']);
    io.signalSource.once('SIGINT',finish);
    let wire=command;
    if(overrides.native){const deps=await io.dependencyFactory();await deps.startReceiver({signer:{},stageOneBytes:Buffer.from('must not reach native receiver')});wire=deps.buildCommand({deviceId:'dev_'+'d'.repeat(32),controllerBaseUrl:'https://controller.example.ts.net/agent-road/v1/dev_'+'d'.repeat(32),token:'a'.repeat(43)});}
    io.stdout.write(wire+'\n');await done;
    await new Promise(resolve=>setImmediate(resolve));return 0;
  }});
  const captureName=errors.match(/capture=(agent-road-pair-[A-Za-z0-9]+)/)?.[1];
  const capture=captureName?join(tmpdir(),captureName):undefined;
  if(capture)t.after(()=>rm(capture,{recursive:true,force:true}));
  return {code,output,errors,actions,capture,approvedConfiguration};
}
test('pair bridge hides encoded command, waits for approval, preserves enrollment result',async t=>{
  const r=await fixture(t);assert.equal(r.code,0);assert.match(r.output,/irm 'https:\/\/pair.example\/join.ps1/);
  assert.ok(!r.output.includes(command));assert.deepEqual(r.actions,['create','status','approve','cancel']);
});
test('declined verification never releases bootstrap',async t=>{
  const r=await fixture(t,{confirm:async()=>false,cancel:async()=>({state:'CANCELLED'})});
  assert.equal(r.code,2);assert.match(r.errors,/PAIR_APPROVAL_DECLINED/);assert.ok(!r.actions.includes('approve'));
});
test('pair records retrieval separately from enrollment without delivering twice',async t=>{
  const r=await fixture(t,{observeDelivery:true});
  assert.equal(r.code,0);
  assert.deepEqual(r.actions,['create','status','approve','status','cancel']);
  assert.deepEqual(JSON.parse(await readFile(join(r.capture,'delivery-observation.json'),'utf8')),
    {state:'DELIVERED',executionConfirmed:false});
  assert.match(r.errors,/PAIR_DELIVERED: retrieval confirmed; execution and enrollment are not yet confirmed/);
});
test('lost create response still attempts cancellation without replay',async t=>{
  const r=await fixture(t,{create:async()=>{throw pairingError('PAIR_REQUEST_UNCERTAIN');},cancel:async()=>({state:'CANCELLED'})});
  assert.equal(r.code,2);assert.deepEqual(r.actions,['create','cancel']);
});
test('uncertain cleanup cannot report success',async t=>{
  const r=await fixture(t,{cancel:async()=>{throw pairingError('PAIR_REQUEST_UNCERTAIN');}});
  assert.equal(r.code,2);assert.match(r.errors,/PAIR_CLEANUP_UNCERTAIN/);
});
test('CLI pair route fails closed without config and exposes help',async()=>{
 let out='',err='';const io={stdout:{write:s=>out+=s},stderr:{write:s=>err+=s}};
 assert.equal(await main(['pair','--config','/nonexistent/agent-road-pairing.json'],{},io),2);
 assert.match(err,/PAIR_CONFIG_REQUIRED/);
 assert.equal(await main(['pair','--help'],{},io),0);assert.match(out,/agent-road pair/);
});

test('automatic credentials are revoked after declined pairing',async t=>{
 let revoked;
 const r=await fixture(t,{api:true,createAuthKey:async()=>({id:'key123',key:'tskey-auth-'+'b'.repeat(20)}),revokeAuthKey:async(token,id)=>{revoked=id;},confirm:async()=>false,cancel:async()=>({state:'CANCELLED'})});
 assert.equal(r.code,2);assert.equal(revoked,'key123');assert.ok(!r.output.includes('tskey-'));
});
test('failed key revocation cannot report successful enrollment',async t=>{
 const r=await fixture(t,{api:true,createAuthKey:async()=>({id:'key123',key:'tskey-auth-'+'b'.repeat(20)}),revokeAuthKey:async()=>{throw Error('network');}});
 assert.equal(r.code,2);assert.match(r.errors,/PAIR_AUTH_KEY_CLEANUP_UNCERTAIN/);
});

// Fresh Windows must download optional components before completion can arrive.
test('pair passes a bounded installation timeout while rendezvous retains its own expiry', async t=>{
 const r=await fixture(t,{args:['--timeout-minutes','20'],timeout:'20'});
 assert.equal(r.code,0);
});
test('invalid enrollment timeout creates no pairing session or auth key',async()=>{
 for(const value of ['4','31','1.5','030']) {
  let err='';
  const code=await runPairCommand(['--timeout-minutes',value],{}, {stdout:{write(){}},stderr:{write:s=>err+=s}}, {
   createAuthKey:async()=>assert.fail('must not issue key'),
   request:async()=>assert.fail('must not create session'),
  });
  assert.equal(code,2);assert.match(err,/PAIR_INPUT_INVALID/);
 }
});

test('older pairing service retains the manual-code command',async t=>{
 const r=await fixture(t,{create:async()=>({state:'WAITING',expiresAt:Date.now()+600000})});
 assert.equal(r.code,0);assert.match(r.output,/irm https:\/\/pair.example\/join.ps1 \| iex/);assert.ok(!r.output.includes('?code='));
});

for(const outcome of ['PAIR_ALREADY_DELIVERED','PAIR_EXPIRED','PAIR_UNAVAILABLE']) {
 test(`expected cancellation outcome ${outcome} remains distinguishable in private capture`,async t=>{
  const r=await fixture(t,{cancel:async()=>{throw pairingError(outcome);}});
  assert.equal(r.code,0);
  const path=join(r.capture,'cancel-outcome.json');
  assert.deepEqual(JSON.parse(await readFile(path,'utf8')),{code:outcome});
  assert.equal((await stat(path)).mode & 0o777,0o600);
  assert.ok(!r.errors.includes('PAIR_CLEANUP_UNCERTAIN'));
 });
}


test('native preview sends typed configuration, uses v2 receiver, and never prints secrets or scripts',async t=>{
 const r=await fixture(t,{native:true});assert.equal(r.code,0);
 assert.match(r.output,/AgentRoadNativeSetup.exe --pair [A-HJ-NP-Z2-9]{12} --accept-system-changes/);
 assert.doesNotMatch(r.output,/powershell|EncodedCommand|tskey-|enrollmentToken|AGENT_ROAD_NATIVE_CONFIGURATION/);
 assert.deepEqual(r.actions,['create','status','approve','cancel']);
});
test('native preview refuses a legacy create response without fallback',async t=>{
 const r=await fixture(t,{native:true,create:async()=>({state:'WAITING',expiresAt:Date.now()+600000,codeInJoinUrl:true}),cancel:async()=>({state:'CANCELLED'})});
 assert.equal(r.code,2);assert.match(r.errors,/PAIR_RESPONSE_INVALID/);assert.doesNotMatch(r.output,/irm|powershell/);
 assert.deepEqual(r.actions,['create','cancel']);
});
test('native preview requires explicit development opt-in before credentials or network',async()=>{
 let errors='';const code=await runPairCommand(['--native-preview'],{}, {stdout:{write(){}},stderr:{write:s=>errors+=s}}, {request:()=>assert.fail('network must not run')});
 assert.equal(code,2);assert.match(errors,/PAIR_NATIVE_PREVIEW_REQUIRED/);
});

test('native configuration expiry is capped to the actual server invitation',async t=>{
 const expiry=Date.now()+540000;
 const r=await fixture(t,{native:true,create:async()=>({state:'WAITING',expiresAt:expiry,protocolVersion:2,deliveryKind:'configuration'}),cancel:async()=>({state:'CANCELLED'})});
 assert.equal(r.code,0);assert.equal(r.approvedConfiguration.expiresAt,expiry);
});
