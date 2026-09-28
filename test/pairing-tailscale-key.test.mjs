import test from 'node:test';
import assert from 'node:assert/strict';
import { createPairAuthKey, revokePairAuthKey } from '../src/pairing/tailscale-key.mjs';
const token='tskey-api-'+'a'.repeat(20), key='tskey-auth-'+'b'.repeat(20);
test('automatic key is one-use, persistent device, 15 minute expiry; revocation uses exact id',async()=>{
 const result=await createPairAuthKey(token,'Agent Road test',async(url,options)=>{
 assert.equal(url,'https://api.tailscale.com/api/v2/tailnet/-/keys');assert.equal(options.redirect,'error');
 assert.deepEqual(JSON.parse(options.body),{capabilities:{devices:{create:{reusable:false,ephemeral:false,preauthorized:true}}},expirySeconds:900,description:'Agent Road test'});
 return Response.json({id:'key123',key});
 });assert.deepEqual(result,{id:'key123',key});
 await revokePairAuthKey(token,result.id,async(url,options)=>{assert.match(url,/\/keys\/key123$/);assert.equal(options.method,'DELETE');return new Response(null,{status:404});});
});
test('uncertain key creation does not retry or echo provider errors',async()=>{
 let calls=0;await assert.rejects(createPairAuthKey(token,'test',async()=>{calls++;throw Error('credential secret');}),{code:'PAIR_TAILSCALE_REQUEST_UNCERTAIN'});assert.equal(calls,1);
 await assert.rejects(createPairAuthKey(token,'test',async()=>Response.json({key})),{code:'PAIR_TAILSCALE_RESPONSE_INVALID'});
});
