# telemetry

A small, dependency-free Node.js (CommonJS) library for summarizing latency
readings collected from stations.

## Running tests

```
node test.cjs
```

The script uses only `node:assert/strict`, runs a series of test cases, prints
a pass count, and exits with a nonzero status if any assertion fails.

## API

### `summarize(readings)`

Exported from `telemetry.cjs`.

- `readings` must be an array of objects, each with:
  - `station`: a string (leading/trailing whitespace is trimmed; must be
    nonempty after trimming)
  - `latencyMs`: a finite, nonnegative number
- Invalid input (a non-array, or any item that doesn't match the shape above)
  causes `summarize` to throw a `TypeError`.
- The input array and its items are never mutated.

Returns an object with exactly these fields:

- `count`: number of readings
- `meanMs`: arithmetic mean of all `latencyMs` values, rounded to three
  decimal places (`null` when `count` is 0)
- `p95Ms`: the 95th percentile latency using the nearest-rank method
  (`index = ceil(count * 0.95) - 1` over the ascending numeric sort of
  latencies; `null` when `count` is 0)
- `stations`: an array of `{ station, count, meanMs }`, one entry per
  distinct (trimmed) station name, with `meanMs` rounded to three decimal
  places, sorted by station name using JavaScript's default string sort.
  Station names like `__proto__` and `constructor` are treated as ordinary
  strings.

When `readings` is empty, `summarize` returns:

```js
{ count: 0, meanMs: null, p95Ms: null, stations: [] }
```

## Example

```js
const { summarize } = require('./telemetry.cjs');

const result = summarize([
  { station: 'north', latencyMs: 12 },
  { station: 'south', latencyMs: 8 },
  { station: 'north', latencyMs: 20 },
]);

console.log(result);
// {
//   count: 3,
//   meanMs: 13.333,
//   p95Ms: 20,
//   stations: [
//     { station: 'north', count: 2, meanMs: 16 },
//     { station: 'south', count: 1, meanMs: 8 }
//   ]
// }
```

Built on Windows by Claude Code, dispatched from Mac Astra via Agent Road.
