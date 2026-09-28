// Opt-in workerd only; fixture credentials, no installation or live account.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { newPairIdentity, pairRequest } from '../src/pairing/client.mjs';
test('native v2 real Durable Object serializes claims and one-time configuration delivery', {skip:process.env.AGENT_ROAD_PAIR_NATIVE_LOCAL_TEST!=='1'}, async()=>{
 const origin='http://127.0.0.1:18749',{code,ownerToken}=newPairIdentity();
 const clients=[randomBytes(32).toString('base64url'),randomBytes(32).toString('base64url')];
 const call=(action,body,version=2)=>pairRequest(origin,action,{code,...body},{protocolVersion:version,adminToken:action==='create'?'a'.repeat(43):undefined});
 const created=await call('create',{ownerToken});assert.equal(created.protocolVersion,2);assert.equal(created.deliveryKind,'configuration');
 const claims=await Promise.allSettled(clients.map(clientToken=>call('claim',{clientToken})));
 assert.equal(claims.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(claims.find(x=>x.status==='rejected').reason.code,'PAIR_ALREADY_CLAIMED');
 const clientToken=clients[claims.findIndex(x=>x.status==='fulfilled')];
 const {claim}=await call('status',{ownerToken});
 const deviceId='dev_'+'e'.repeat(32);
 const configuration={schemaVersion:2,kind:'agent-road-native-enrollment',pairingOrigin:'https://agent-road.brahma-technologies.com',deviceId,
 controllerBaseUrl:`https://controller.example.ts.net/agent-road/v1/${deviceId}`,enrollmentToken:'E'.repeat(43),tailscaleAuthKey:'tskey-auth-'+'F'.repeat(32),expiresAt:created.expiresAt};
 assert.equal((await call('approve',{ownerToken,claimId:claim.id,configuration})).state,'APPROVED');
 await assert.rejects(call('receive',{clientToken},1),{code:'PAIR_PROTOCOL_MISMATCH'});
 const responses=await Promise.allSettled([call('receive',{clientToken}),call('receive',{clientToken})]);
 assert.equal(responses.filter(x=>x.status==='fulfilled').length,1);
 assert.deepEqual(responses.find(x=>x.status==='fulfilled').value,{state:'DELIVERED',protocolVersion:2,configuration});
 assert.equal(responses.find(x=>x.status==='rejected').reason.code,'PAIR_UNAVAILABLE');
 assert.equal((await call('status',{ownerToken})).state,'CONSUMED');
});
