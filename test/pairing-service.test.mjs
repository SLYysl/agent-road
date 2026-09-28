import assert from 'node:assert/strict';
import test from 'node:test';
import { serviceRequest, expirePairs } from '../src/pairing/service.mjs';
const code = 'ABCDEFGHJKMN', ownerToken = 'A'.repeat(43), clientToken = 'B'.repeat(43);
const env = { PAIR_ADMIN_TOKEN: 'D'.repeat(43), PAIR_STORAGE_KEY: Buffer.alloc(32, 7).toString('base64url') };
const command = 'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand QQ==';
function fixture() {
 const map = new Map(); let alarm = null;
 const storage = { get: async k => structuredClone(map.get(k)), put: async(k,v)=>map.set(k,structuredClone(v)), delete: async k=>map.delete(k), list: async({prefix})=>new Map([...map].filter(([k])=>k.startsWith(prefix)).map(([k,v])=>[k,structuredClone(v)])), setAlarm: async n=>{alarm=n;}, deleteAlarm: async()=>{alarm=null;} };
 let clock=1000;
 const call=async(action,body,authorized=false)=>{
  const headers={'content-type':'application/json'};
  if(authorized)headers.authorization=`Bearer ${env.PAIR_ADMIN_TOKEN}`;
  const response=await serviceRequest(new Request(`https://pair.example/v1/${action}`,{method:'POST',headers,body:JSON.stringify(body)}),env,storage,clock);
  return {status:response.status,body:await response.json(),headers:response.headers};
 };
 return {map,storage,call,alarm:()=>alarm,setClock:n=>{clock=n;}};
}
test('HTTP lifecycle persists only hashes/ciphertext and erases payload before delivery',async()=>{
 const f=fixture();
 assert.equal((await f.call('create',{code,ownerToken})).status,401);
 assert.equal((await f.call('create',{code,ownerToken},true)).body.state,'WAITING');
 const claim=await f.call('claim',{code,clientToken});assert.match(claim.body.verification,/^\d{8}$/);
 assert.equal((await f.call('receive',{code,clientToken})).body.state,'PENDING');
 const status=await f.call('status',{code,ownerToken});
 assert.equal((await f.call('approve',{code,ownerToken,claimId:status.body.claim.id,command})).body.state,'APPROVED');
 const serialized=JSON.stringify([...f.map]);
 for(const secret of [command,ownerToken,clientToken,env.PAIR_ADMIN_TOKEN])assert(!serialized.includes(secret));
 const delivered=await f.call('receive',{code,clientToken});
 assert.equal(delivered.body.command,command);assert.equal(delivered.headers.get('cache-control'),'no-store');
 assert.equal([...f.map.values()].find(x=>x.state).envelope,null);
 assert.equal((await f.call('receive',{code,clientToken})).status,410);
 assert.equal((await f.call('status',{code,ownerToken})).body.state,'CONSUMED');
});
test('wrong claimant cannot consume and wrong claim approval does not change state',async()=>{
 const f=fixture();await f.call('create',{code,ownerToken},true);await f.call('claim',{code,clientToken});
 assert.equal((await f.call('claim',{code,clientToken:'C'.repeat(43)})).status,409);
 assert.equal((await f.call('approve',{code,ownerToken,claimId:'f'.repeat(64),command})).status,409);
 assert.equal((await f.call('receive',{code,clientToken:'C'.repeat(43)})).status,401);
 assert.equal((await f.call('status',{code,ownerToken})).body.state,'CLAIMED');
});
test('expiry clears records/alarm and cannot deliver, cancellation denies release',async()=>{
 const f=fixture();await f.call('create',{code,ownerToken},true);await f.call('claim',{code,clientToken});
 await f.call('cancel',{code,ownerToken});assert.equal((await f.call('receive',{code,clientToken})).status,410);
 await expirePairs(f.storage,601001);assert.equal(f.alarm(),null);assert.equal(f.map.size,0);
 f.setClock(601001);assert.equal((await f.call('receive',{code,clientToken})).status,404);
});
test('input allowlist, global rate and size bounds reject without provisioning',async()=>{
 const f=fixture();assert.equal((await f.call('create',{code,ownerToken,extra:true},true)).status,400);
 assert.equal((await f.call('create',{code:'x'.repeat(41000),ownerToken},true)).status,413);
 for(let i=0;i<178;i++)await f.call('status',{code,ownerToken});
 assert.equal((await f.call('create',{code,ownerToken},true)).status,429);
 assert.equal([...f.map.keys()].filter(x=>x.startsWith('pair:')).length,0);
});
