'use strict';

const assert = require('node:assert/strict');
const { summarize } = require('./telemetry.cjs');

let passCount = 0;

function test(name, fn) {
  fn();
  passCount += 1;
  console.log(`PASS: ${name}`);
}

test('empty input returns zeroed shape', () => {
  const result = summarize([]);
  assert.deepEqual(result, { count: 0, meanMs: null, p95Ms: null, stations: [] });
});

test('single reading computes mean and p95 equal to the value', () => {
  const result = summarize([{ station: 'A', latencyMs: 10 }]);
  assert.deepEqual(result, {
    count: 1,
    meanMs: 10,
    p95Ms: 10,
    stations: [{ station: 'A', count: 1, meanMs: 10 }],
  });
});

test('p95 uses nearest-rank on 20 sorted values', () => {
  const readings = [];
  for (let i = 1; i <= 20; i += 1) {
    readings.push({ station: 'X', latencyMs: i });
  }
  const result = summarize(readings);
  assert.equal(result.count, 20);
  assert.equal(result.meanMs, 10.5);
  assert.equal(result.p95Ms, 19);
});

test('p95 nearest-rank on small unsorted set', () => {
  const readings = [
    { station: 'X', latencyMs: 30 },
    { station: 'X', latencyMs: 10 },
    { station: 'X', latencyMs: 100 },
    { station: 'X', latencyMs: 20 },
  ];
  const result = summarize(readings);
  assert.equal(result.p95Ms, 100);
});

test('stations grouped, counted, meaned, and sorted by default string order', () => {
  const readings = [
    { station: 'banana', latencyMs: 10 },
    { station: 'Apple', latencyMs: 20 },
    { station: 'banana', latencyMs: 30 },
  ];
  const result = summarize(readings);
  assert.equal(result.count, 3);
  assert.deepEqual(result.stations, [
    { station: 'Apple', count: 1, meanMs: 20 },
    { station: 'banana', count: 2, meanMs: 20 },
  ]);
});

test('station names are trimmed and merged, meanMs rounded to three decimals', () => {
  const readings = [
    { station: '  Node1  ', latencyMs: 1 },
    { station: 'Node1', latencyMs: 2 },
    { station: 'Node1', latencyMs: 2 },
  ];
  const result = summarize(readings);
  assert.deepEqual(result.stations, [{ station: 'Node1', count: 3, meanMs: 1.667 }]);
});

test('__proto__ and constructor are treated as normal station names', () => {
  const readings = [
    { station: '__proto__', latencyMs: 5 },
    { station: 'constructor', latencyMs: 15 },
  ];
  const result = summarize(readings);
  assert.equal(result.count, 2);
  assert.deepEqual(result.stations, [
    { station: '__proto__', count: 1, meanMs: 5 },
    { station: 'constructor', count: 1, meanMs: 15 },
  ]);
});

test('summarize does not mutate the input array or its items', () => {
  const readings = [{ station: '  A  ', latencyMs: 5 }];
  const snapshot = JSON.parse(JSON.stringify(readings));
  summarize(readings);
  assert.deepEqual(readings, snapshot);
});

test('non-array input throws TypeError', () => {
  assert.throws(() => summarize(null), TypeError);
  assert.throws(() => summarize({}), TypeError);
  assert.throws(() => summarize('nope'), TypeError);
});

test('invalid station values throw TypeError', () => {
  assert.throws(() => summarize([{ station: '', latencyMs: 1 }]), TypeError);
  assert.throws(() => summarize([{ station: '   ', latencyMs: 1 }]), TypeError);
  assert.throws(() => summarize([{ station: 42, latencyMs: 1 }]), TypeError);
  assert.throws(() => summarize([{ latencyMs: 1 }]), TypeError);
});

test('Number.MAX_VALUE reading produces a finite meanMs and station meanMs', () => {
  const result = summarize([{ station: 'x', latencyMs: Number.MAX_VALUE }]);
  assert.equal(result.meanMs, Number.MAX_VALUE);
  assert.equal(result.p95Ms, Number.MAX_VALUE);
  assert.deepEqual(result.stations, [
    { station: 'x', count: 1, meanMs: Number.MAX_VALUE },
  ]);
});

test('repeated Number.MAX_VALUE readings do not overflow the accumulator', () => {
  const result = summarize([
    { station: 'x', latencyMs: Number.MAX_VALUE },
    { station: 'x', latencyMs: Number.MAX_VALUE },
    { station: 'x', latencyMs: Number.MAX_VALUE },
  ]);
  assert.equal(result.meanMs, Number.MAX_VALUE);
  assert.deepEqual(result.stations, [
    { station: 'x', count: 3, meanMs: Number.MAX_VALUE },
  ]);
});

test('Number.MAX_VALUE mixed with zero yields a finite, correct mean', () => {
  const result = summarize([
    { station: 'x', latencyMs: 0 },
    { station: 'x', latencyMs: Number.MAX_VALUE },
  ]);
  const expected = Number.MAX_VALUE / 2;
  assert.equal(result.meanMs, expected);
  assert.deepEqual(result.stations, [
    { station: 'x', count: 2, meanMs: expected },
  ]);
});

test('invalid latencyMs values throw TypeError', () => {
  assert.throws(() => summarize([{ station: 'A', latencyMs: -1 }]), TypeError);
  assert.throws(() => summarize([{ station: 'A', latencyMs: NaN }]), TypeError);
  assert.throws(() => summarize([{ station: 'A', latencyMs: Infinity }]), TypeError);
  assert.throws(() => summarize([{ station: 'A', latencyMs: '5' }]), TypeError);
  assert.throws(() => summarize([{ station: 'A' }]), TypeError);
});

console.log(`\n${passCount} test cases passed.`);
