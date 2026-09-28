const assert = require('node:assert/strict');
const { summarize } = require(process.argv[2]);
let count = 0;
function check(name, fn) { fn(); count++; console.log('PASS '+name); }
check('empty',()=>assert.deepEqual(summarize([]),{count:0,meanMs:null,p95Ms:null,stations:[]}));
check('one',()=>assert.deepEqual(summarize([{station:' Mac ',latencyMs:0}]),{count:1,meanMs:0,p95Ms:0,stations:[{station:'Mac',count:1,meanMs:0}]}));
check('grouping and rounding',()=>assert.deepEqual(summarize([{station:'b',latencyMs:1},{station:'a',latencyMs:2},{station:'b ',latencyMs:2}]),{count:3,meanMs:1.667,p95Ms:2,stations:[{station:'a',count:1,meanMs:2},{station:'b',count:2,meanMs:1.5}]}));
check('nearest rank at 20',()=>assert.equal(summarize(Array.from({length:20},(_,i)=>({station:'x',latencyMs:20-i}))).p95Ms,19));
check('no mutation frozen input',()=>{const data=Object.freeze([Object.freeze({station:' y ',latencyMs:4})]);assert.equal(summarize(data).stations[0].station,'y');assert.equal(data[0].station,' y ');});
check('special station names',()=>{const r=summarize(['__proto__','constructor','中文🚀'].map(station=>({station,latencyMs:3})));assert.deepEqual(r.stations.map(x=>x.station),['__proto__','constructor','中文🚀']);});
check('invalid arrays',()=>{for(const x of [null,{},'abc',3])assert.throws(()=>summarize(x),TypeError);});
check('invalid entries',()=>{for(const x of [null,{},3,{station:' ',latencyMs:1},{station:'x',latencyMs:NaN},{station:'x',latencyMs:Infinity},{station:'x',latencyMs:-1},{station:'x',latencyMs:'1'}])assert.throws(()=>summarize([x]),TypeError);});
check('largest finite single mean',()=>{const r=summarize([{station:'x',latencyMs:Number.MAX_VALUE}]);assert.equal(r.meanMs,Number.MAX_VALUE);assert.equal(r.stations[0].meanMs,Number.MAX_VALUE);});
check('largest finite repeated mean',()=>{const r=summarize(Array.from({length:3},()=>({station:'x',latencyMs:Number.MAX_VALUE})));assert.equal(r.meanMs,Number.MAX_VALUE);assert.equal(r.stations[0].meanMs,Number.MAX_VALUE);});
check('largest finite mixed with zero',()=>{const r=summarize([{station:'x',latencyMs:Number.MAX_VALUE},{station:'x',latencyMs:0}]);assert.equal(r.meanMs,Number.MAX_VALUE/2);assert.equal(r.stations[0].meanMs,Number.MAX_VALUE/2);});
console.log(count+' independent acceptance cases passed');
