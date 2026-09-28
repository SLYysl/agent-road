import test from 'node:test';
import assert from 'node:assert/strict';
import { serviceRequest } from '../src/pairing/service.mjs';
import { validateNativeConfiguration } from '../src/installer/configuration.mjs';
const code='ABCDEFGHJKMN', ownerToken='A'.repeat(43), clientToken='B'.repeat(43);
const origin='https://pair.example', deviceId='dev_'+'e'.repeat(32);
const configuration={schemaVersion:2,kind:'agent-road-native-enrollment',pairingOrigin:origin,deviceId,
 controllerBaseUrl:`https://controller.example.ts.net/agent-road/v1/${deviceId}`,
 enrollmentToken:'E'.repeat(43),tailscaleAuthKey:'tskey-auth-'+'F'.repeat(32),expiresAt:601000};
function fixture(enabled=true){
 const map=new Map(); let now=1000, failWrite=false;
 const env={PAIR_ADMIN_TOKEN:'D'.repeat(43),PAIR_STORAGE_KEY:Buffer.alloc(32,7).toString('base64url'),PUBLIC_ORIGIN:origin,PAIR_NATIVE_V2_ENABLED:enabled?'true':'false'};
 const storage={get:async k=>structuredClone(map.get(k)),put:async(k,v)=>{if(failWrite&&v.state==='CONSUMED')throw Error('disk');map.set(k,structuredClone(v));},delete:async k=>map.delete(k),list:async({prefix})=>new Map([...map].filter(([k])=>k.startsWith(prefix)).map(([k,v])=>[k,structuredClone(v)])),setAlarm:async()=>{}};
 const call=async(action,body,version=2,authorized=false)=>{
  const response=await serviceRequest(new Request(`${origin}/v${version}/${action}`,{method:'POST',headers:{'content-type':'application/json',...(authorized?{authorization:`Bearer ${env.PAIR_ADMIN_TOKEN}`}:{})},body:JSON.stringify({code,...body})}),env,storage,now);
  return {status:response.status,body:await response.json()};
 };
 const ready=async()=>{
  assert.equal((await call('create',{ownerToken},2,true)).status,200);
  assert.match((await call('claim',{clientToken})).body.verification,/^\d{8}$/);
  return (await call('status',{ownerToken})).body.claim.id;
 };
 return {map,call,ready,setClock:n=>{now=n;},failConsumption:()=>{failWrite=true;}};
}
test('v2 disabled by default and cannot consume or modify a v1 invitation',async()=>{
 const off=fixture(false);assert.equal((await off.call('create',{ownerToken},2,true)).body.code,'PAIR_PROTOCOL_UNSUPPORTED');
 const f=fixture();assert.equal((await f.call('create',{ownerToken},1,true)).status,200);
 for(const action of ['status','cancel'])assert.equal((await f.call(action,{ownerToken})).body.code,'PAIR_PROTOCOL_MISMATCH');
 assert.equal((await f.call('claim',{clientToken})).body.code,'PAIR_PROTOCOL_MISMATCH');
 assert.equal((await f.call('status',{ownerToken},1)).body.state,'WAITING');
});
test('v2 requires authorization and confirmation, encrypts credentials, delivers data once',async()=>{
 const f=fixture();assert.equal((await f.call('create',{ownerToken})).status,401);
 const claimId=await f.ready();
 assert.equal((await f.call('receive',{clientToken})).body.state,'PENDING');
 assert.equal((await f.call('approve',{ownerToken,claimId,configuration})).body.state,'APPROVED');
 for(const secret of [ownerToken,clientToken,configuration.enrollmentToken,configuration.tailscaleAuthKey])assert(!JSON.stringify([...f.map]).includes(secret));
 assert.equal((await f.call('receive',{clientToken},1)).body.code,'PAIR_PROTOCOL_MISMATCH');
 const delivered=await f.call('receive',{clientToken});
 assert.deepEqual(delivered.body,{state:'DELIVERED',protocolVersion:2,configuration});
 assert.equal([...f.map.values()].find(x=>x.state).envelope,null);
 // A dropped success response cannot be recovered by replaying receipt delivery.
 assert.equal((await f.call('receive',{clientToken})).status,410);
 assert.equal((await f.call('status',{ownerToken})).body.state,'CONSUMED');
});
test('wrong claimant, owner, verification claim and command-shaped approval leave state unchanged',async()=>{
 const f=fixture(),claimId=await f.ready();
 assert.equal((await f.call('approve',{ownerToken:'Z'.repeat(43),claimId,configuration})).status,401);
 assert.equal((await f.call('approve',{ownerToken,claimId:'0'.repeat(64),configuration})).status,409);
 assert.equal((await f.call('approve',{ownerToken,claimId,command:'anything'})).status,400);
 assert.equal((await f.call('receive',{clientToken:'Z'.repeat(43)})).status,401);
 assert.equal((await f.call('status',{ownerToken})).body.state,'CLAIMED');
});
const invalidConfigurations=[
 {...configuration,schemaVersion:1},{...configuration,kind:'agent-road-offline-preview'},
 {...configuration,command:'calc.exe'},{...configuration,profile:'arbitrary'},
 {...configuration,pairingOrigin:'https://other.example'},
 {...configuration,controllerBaseUrl:'https://attacker.example/agent-road/v1/'+deviceId},
 {...configuration,controllerBaseUrl:configuration.controllerBaseUrl+'?command=x'},
 {...configuration,controllerBaseUrl:configuration.controllerBaseUrl.replace('https://','https://user:pass@')},
 {...configuration,controllerBaseUrl:configuration.controllerBaseUrl.replace(deviceId,'dev_'+'f'.repeat(32))},
 {...configuration,enrollmentToken:42},{...configuration,tailscaleAuthKey:'tskey-api-'+'F'.repeat(32)},
 {...configuration,expiresAt:1000},{...configuration,expiresAt:601001},{...configuration,expiresAt:1000.5}
];
for(const [i,value] of invalidConfigurations.entries())test(`configuration rejects unsupported or unsafe field variant ${i+1}`,async()=>{
 assert.throws(()=>validateNativeConfiguration(value,{origin,now:1000,expiresAt:601000}),{code:'PAIR_CONFIGURATION_INVALID'});
 const f=fixture(),claimId=await f.ready();
 assert.equal((await f.call('approve',{ownerToken,claimId,configuration:value})).body.code,'PAIR_CONFIGURATION_INVALID');
 assert.equal((await f.call('status',{ownerToken})).body.state,'CLAIMED');
});
test('cancel and expiry prevent release; shorter configuration expiry is enforced at delivery',async()=>{
 const f=fixture(),claimId=await f.ready();
 await f.call('approve',{ownerToken,claimId,configuration:{...configuration,expiresAt:2000}});
 f.setClock(2000);assert.equal((await f.call('receive',{clientToken})).body.code,'PAIR_CONFIGURATION_INVALID');
 assert.equal((await f.call('status',{ownerToken})).body.state,'APPROVED');
 await f.call('cancel',{ownerToken});assert.equal((await f.call('receive',{clientToken})).status,410);
 const expired=fixture();await expired.ready();expired.setClock(601000);
 assert.equal((await expired.call('receive',{clientToken})).status,404);
});
test('storage failure at consumption does not release configuration',async()=>{
 const f=fixture(),claimId=await f.ready();await f.call('approve',{ownerToken,claimId,configuration});
 f.failConsumption();const response=await f.call('receive',{clientToken});
 assert.deepEqual(response,{status:500,body:{code:'PAIR_SERVICE_FAILED'}});
 assert.equal((await f.call('status',{ownerToken})).body.state,'APPROVED');
});
