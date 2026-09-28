// Optional real workerd test. Start the documented local fixture first; never target production.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { newPairIdentity } from '../src/pairing/client.mjs';
test('real Durable Object serializes competing claims and one-shot deliveries', {skip:process.env.AGENT_ROAD_PAIR_LOCAL_TEST!=='1'}, async()=>{
  const origin='http://127.0.0.1:18749', {code,ownerToken}=newPairIdentity();
  const clients=[randomBytes(32).toString('base64url'),randomBytes(32).toString('base64url')];
  async function call(action,body,admin=false){
    const response=await fetch(`${origin}/v1/${action}`,{method:'POST',headers:{'content-type':'application/json',...(admin?{authorization:'Bearer '+'a'.repeat(43)}:{})},body:JSON.stringify({code,...body})});
    return {status:response.status,body:await response.json()};
  }
  const created=await call('create',{ownerToken},true);
  assert.equal(created.status,200);assert.equal(created.body.codeInJoinUrl,true);
  const claimed=await Promise.all(clients.map(clientToken=>call('claim',{clientToken})));
  assert.deepEqual(claimed.map(r=>r.status).sort(),[200,409]);
  const winner=clients[claimed.findIndex(r=>r.status===200)];
  const status=await call('status',{ownerToken});
  const command='powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand QQ==';
  assert.equal((await call('approve',{ownerToken,claimId:status.body.claim.id,command})).status,200);
  const received=await Promise.all([call('receive',{clientToken:winner}),call('receive',{clientToken:winner})]);
  assert.deepEqual(received.map(r=>r.status).sort(),[200,410]);
  assert.equal(received.find(r=>r.status===200).body.command,command);
  assert.equal((await call('status',{ownerToken})).body.state,'CONSUMED');
  assert.equal((await call('receive',{clientToken:winner})).status,410);
  const loader=await fetch(`${origin}/join.ps1`);assert.equal(loader.status,200);
  assert.match(await loader.text(),/https:\/\/agent-road.brahma-technologies.com/);
  const prefilled=await fetch(`${origin}/join.ps1?code=${code}`);
  assert.equal(prefilled.status,200);assert.equal(prefilled.headers.get('cache-control'),'no-store');
  assert.ok((await prefilled.text()).includes(`$pairCode = '${code}'`));
  assert.equal((await fetch(`${origin}/join.ps1?code=bad`)).status,400);
  assert.equal((await fetch(`${origin}/join.ps1?code=${code}&code=${code}`)).status,400);
});
