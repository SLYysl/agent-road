import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, stat, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { authRequest, cliSession } from '../src/auth/service.mjs';
import { runAuthCommand, loadCliCredential } from '../src/auth/client.mjs';
import { serviceRequest } from '../src/pairing/service.mjs';
const origin='https://agent-road.brahma-technologies.com';
const token='ar1.'+'a'.repeat(32)+'.'+'b'.repeat(43);
const token2='ar1.'+'c'.repeat(32)+'.'+'d'.repeat(43);
function fixture(version=1){
 const map=new Map();const storage={get:async k=>structuredClone(map.get(k)),put:async(k,v)=>map.set(k,structuredClone(v)),delete:async k=>map.delete(k),list:async({prefix})=>new Map([...map].filter(([k])=>k.startsWith(prefix)).map(([k,v])=>[k,structuredClone(v)])),setAlarm:async()=>{},deleteAlarm:async()=>{}};
 const env={PAIR_NATIVE_V2_ENABLED:'true',PUBLIC_ORIGIN:origin,SUPABASE_PUBLISHABLE_KEY:'sb_publishable_fixture',PAIR_ADMIN_TOKEN:'Z'.repeat(43),PAIR_STORAGE_KEY:'a'.repeat(43)};
 let now=Date.now();let fetchCalls=0;
 const fetchImpl=async(url,options)=>{fetchCalls++;assert.equal(url,'https://vogebqydhebvvchwhvdb.supabase.co/auth/v1/user');assert.equal(options.redirect,'manual');return Response.json({id:options.headers.Authorization==='Bearer other.jwt.sig'?'22222222-2222-4222-8222-222222222222':'11111111-1111-4111-8111-111111111111',aud:'authenticated',role:'authenticated',email_confirmed_at:'2026-01-01',is_anonymous:false});};
 const request=(path,body,bearer,requestOrigin=origin)=>new Request(origin+path,{method:'POST',headers:{'content-type':'application/json',...(bearer?{authorization:'Bearer '+bearer}:{}),...(requestOrigin?{origin:requestOrigin}:{})},body:JSON.stringify(body)});
 const call=async(action,body={},bearer=token,requestOrigin=origin)=>{const r=await authRequest(request('/api/cli/'+action,body,bearer,requestOrigin),env,storage,now,fetchImpl);return {status:r.status,...await r.json()};};
 const pair=async(action,body,bearer=token)=>{const r=await serviceRequest(request('/v'+version+'/'+action,body,bearer),env,storage,now);return {status:r.status,...await r.json()};};
 return {map,storage,env,request,call,pair,advance:ms=>now+=ms,fetchCalls:()=>fetchCalls,now:()=>now};
}
test('account approval, hashed controller credential, list isolation and revocation',async()=>{
 const f=fixture();const start=await f.call('start',{token,name:'My Mac'});assert.equal(start.state,'PENDING');
 await assert.rejects(cliSession(token,f.storage),{code:'AUTH_REQUIRED'});
 assert.equal((await f.call('approve',{code:start.code},'user.jwt.sig','https://evil.example')).status,403);
 assert.equal((await f.call('approve',{code:start.code},token)).status,401);
 assert.equal((await f.call('inspect',{code:start.code},'user.jwt.sig')).name,'My Mac');
 assert.equal((await f.call('approve',{code:start.code},'user.jwt.sig')).state,'AUTHORIZED');
 assert.equal((await f.call('approve',{code:start.code},'other.jwt.sig')).status,410);
 assert.equal((await f.call('list',{},'other.jwt.sig')).sessions.length,0);
 const list=await f.call('list',{},'user.jwt.sig');assert.equal(list.sessions.length,1);
 assert.equal((await f.call('revoke',{id:list.sessions[0].id},'other.jwt.sig')).status,404);
 assert.equal((await f.call('revoke',{id:list.sessions[0].id},'user.jwt.sig')).state,'REVOKED');
 assert.equal((await f.call('status')).status,401);
 const serialized=JSON.stringify([...f.map]);assert.ok(!serialized.includes(token));assert.ok(!serialized.includes('user.jwt.sig'));assert.ok(f.fetchCalls()>0);
});
test('pending expiry, denial and malformed input fail closed',async()=>{
 const f=fixture();const start=await f.call('start',{token,name:'Mac'});
 assert.equal((await f.call('start',{token,name:'Mac'})).code,start.code);
 assert.equal((await f.call('approve',{code:start.code,account:'forged'},'user.jwt.sig')).status,400);
 f.advance(600000);assert.equal((await f.call('approve',{code:start.code},'user.jwt.sig')).status,410);
 const next=await f.call('start',{token:token2,name:'Mac2'});
 assert.equal((await f.call('deny',{code:next.code},'user.jwt.sig')).state,'DENIED');
 assert.equal((await f.call('status',{},token2)).status,401);
});
for (const version of [1,2]) test(`v${version} account session gates pairing and revoke blocks delivery even after approval`,async()=>{
 const f=fixture(version);const start=await f.call('start',{token,name:'Mac'});const code='ABCDEFGHJKLM',ownerToken='C'.repeat(43),clientToken='D'.repeat(43);
 assert.equal((await f.pair('create',{code,ownerToken})).status,401);
 await f.call('approve',{code:start.code},'user.jwt.sig');
 assert.equal((await f.pair('create',{code,ownerToken})).status,200);
 const claim=await f.pair('claim',{code,clientToken},null);assert.equal(claim.state,'CLAIMED');
 assert.equal((await f.pair('status',{code,ownerToken},null)).status,401);
 const status=await f.pair('status',{code,ownerToken});
 const command='powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand QQ==';
 const deviceId='dev_'+'e'.repeat(32);
 const payload=version===1?{command}:{configuration:{schemaVersion:2,kind:'agent-road-native-enrollment',pairingOrigin:origin,deviceId,controllerBaseUrl:`https://controller.example.ts.net/agent-road/v1/${deviceId}`,enrollmentToken:'E'.repeat(43),tailscaleAuthKey:'tskey-auth-'+'F'.repeat(32),expiresAt:f.now()+600000}};
 assert.equal((await f.pair('approve',{code,ownerToken,claimId:status.claim.id,...payload})).status,200);
 await f.call('logout');assert.equal((await f.pair('receive',{code,clientToken},null)).status,401);
 const restarted=await f.call('start',{token,name:'Mac'});await f.call('approve',{code:restarted.code},'user.jwt.sig');
 assert.equal((await f.pair('receive',{code,clientToken},null)).status,401);
});
test('active credential expires and forged credential fails',async()=>{
 const f=fixture();const start=await f.call('start',{token,name:'Mac'});await f.call('approve',{code:start.code},'user.jwt.sig');
 assert.equal((await f.call('status',{},token.slice(0,-1)+'x')).status,401);
 f.advance(30*86400000);assert.equal((await f.call('status')).status,401);
});
test('CLI login, whoami and logout run through the actual service without exposing secrets',async t=>{
 const root=await mkdtemp(join(tmpdir(),'road-auth-'));t.after(()=>rm(root,{recursive:true,force:true}));const env={AGENT_ROAD_HOME:root},f=fixture();let output='',errors='',approval;
 const io={stdout:{write:s=>output+=s},stderr:{write:s=>errors+=s}};
 const call=async(_origin,action,body,bearer)=>{const r=await f.call(action,body,bearer);if(action==='start')approval=r.code;if(r.status!==200)throw Object.assign(new Error(r.code),{code:r.code});return r;};
 const injected={call,wait:async()=>{await f.call('approve',{code:approval},'user.jwt.sig');}};
 assert.equal(await runAuthCommand('login',['--no-browser'],env,io,injected),0);
 const credential=await loadCliCredential(env);assert.ok(!output.includes(credential.token));assert.equal(errors,'');
 assert.equal((await stat(join(root,'cli-auth/credential.json'))).mode&0o777,0o600);
 assert.equal(await runAuthCommand('whoami',[],env,io,injected),0);
 assert.equal(await runAuthCommand('logout',[],env,io,injected),0);
 await assert.rejects(readFile(join(root,'cli-auth/credential.json')),{code:'ENOENT'});
 assert.equal((await f.call('status',{},credential.token)).status,401);
});
test('CLI preserves credential on uncertain logout and refuses unsafe storage',async t=>{
 const root=await mkdtemp(join(tmpdir(),'road-auth-'));t.after(()=>rm(root,{recursive:true,force:true}));const env={AGENT_ROAD_HOME:root};let output='';const io={stdout:{write(){}},stderr:{write:s=>output+=s}};
 assert.equal(await runAuthCommand('login',['--no-browser'],env,io,{call:async()=>{throw Object.assign(Error(),{code:'AUTH_NETWORK_UNCERTAIN'});}}),2);
 const before=await loadCliCredential(env);
 assert.equal(await runAuthCommand('logout',[],env,io,{call:async()=>{throw Object.assign(Error(),{code:'AUTH_NETWORK_UNCERTAIN'});}}),2);
 assert.deepEqual(await loadCliCredential(env),before);
 await chmod(join(root,'cli-auth'),0o755);await assert.rejects(loadCliCredential(env),{code:'AUTH_STORAGE_UNSAFE'});
 assert.ok(!output.includes(before.token));
});

test('Supabase rejection, unconfirmed users and provider outages never authorize',async()=>{
 const f=fixture();const started=await f.call('start',{token,name:'Mac'});
 for(const fetchImpl of [async()=>new Response(null,{status:302,headers:{location:'https://untrusted.example'}}),async()=>Response.json({}, {status:401}),async()=>Response.json({id:'11111111-1111-4111-8111-111111111111',aud:'authenticated',role:'authenticated',email_confirmed_at:null}),async()=>{throw Error('provider-secret');}]){
  const r=await authRequest(f.request('/api/cli/approve',{code:started.code},'user.jwt.sig'),f.env,f.storage,f.now(),fetchImpl);
  assert.notEqual(r.status,200);assert.ok(!(await r.text()).includes('provider-secret'));
  assert.equal((await f.call('status')).state,'PENDING');
 }
});
test('personal pairing uses saved account credential without reading shared admin token',async t=>{
 const {writeFile,mkdir}=await import('node:fs/promises');const {runPairCommand}=await import('../src/pairing/controller.mjs');
 const root=await mkdtemp(join(tmpdir(),'road-personal-pair-'));t.after(()=>rm(root,{recursive:true,force:true}));
 await mkdir(join(root,'cli-auth'),{mode:0o700});await writeFile(join(root,'cli-auth/credential.json'),JSON.stringify({origin,token}),{mode:0o600});
 const network=join(root,'network');await writeFile(network,'tskey-api-'+'x'.repeat(20),{mode:0o600});
 await writeFile(join(root,'pairing.json'),JSON.stringify({origin,adminTokenFile:join(root,'absent-admin'),tailscaleApiTokenFile:network}),{mode:0o600});
 let checked=false,keyCreated=false,error='';
 const exit=await runPairCommand([], {AGENT_ROAD_HOME:root},{stderr:{write:s=>error+=s},stdout:{write(){}}},{confirm:async()=>true,authStatus:async(o,a,b,tok)=>{assert.equal(tok,token);checked=true;return {state:'PENDING'};},createAuthKey:async()=>{keyCreated=true;}});
 assert.equal(exit,2);assert.ok(checked);assert.equal(keyCreated,false);assert.match(error,/PAIR_LOGIN_REQUIRED/);
 await rm(join(root,'pairing.json'));error='';
 assert.equal(await runPairCommand([],{AGENT_ROAD_HOME:root},{stderr:{write:s=>error+=s},stdout:{write(){}}}),2);
 assert.match(error,/PAIR_NETWORK_CONFIG_REQUIRED/);
});
