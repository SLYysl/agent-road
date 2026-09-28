import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { buildJoinCommand, renderPairLoader } from '../src/pairing/loader.mjs';
const origin='https://agent-road.brahma-technologies.com';
const source=await readFile(new URL('../windows/pairing/join.ps1',import.meta.url),'utf8');
test('short invitation fits 100 characters and roundtrips without embedding credentials',async()=>{
 const command=buildJoinCommand(origin,'ABCD-EFGH-JKLM');
 assert.ok(command.length<=100);
 const url=command.match(/'([^']+)'/)[1];
 const response=renderPairLoader(new Request(url),origin,source);
 assert.equal(response.headers.get('cache-control'),'no-store');
 const script=await response.text();
 assert.ok(script.includes("$pairCode = 'ABCDEFGHJKLM'"));
 assert.ok(!script.includes('__PAIR_'));
 assert.ok(script.indexOf('PAIR_CONSENT_DECLINED')<script.indexOf("Invoke-AgentRoadPair 'claim'"));
});
test('generic loader retains manual-code path',async()=>{
 const script=await renderPairLoader(new Request(origin+'/join.ps1'),origin,source).text();
 assert.ok(script.includes("$pairCode = ''"));
 assert.ok(script.includes("Read-Host 'Agent Road pairing code'"));
});
test('loader rejects injection, duplicates, unknown fields and invalid codes',()=>{
 for(const query of ['code=', 'code=INVALID','code=ABCD0FGHJKLM','code=ABCDEFGHJKLM&code=ABCDEFGHJKLM','other=x',"code=%27%3Bwhoami%3B%27"])
  assert.throws(()=>renderPairLoader(new Request(origin+'/join.ps1?'+query),origin,source));
 assert.throws(()=>buildJoinCommand("https://example.com';whoami",'ABCDEFGHJKLM'));
});
