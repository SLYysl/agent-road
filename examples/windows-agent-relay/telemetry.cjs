'use strict';

function round3(n) {
  const scaled = n * 1000;
  if (!Number.isFinite(scaled)) {
    // n is too large for *1000 to stay finite; at this magnitude a double
    // has no fractional precision left, so rounding would be a no-op anyway.
    return n;
  }
  return Math.round(scaled) / 1000;
}

function summarize(readings) {
  if (!Array.isArray(readings)) {
    throw new TypeError('readings must be an array');
  }

  const parsed = readings.map((item) => {
    if (item === null || typeof item !== 'object') {
      throw new TypeError('each reading must be an object');
    }
    if (typeof item.station !== 'string') {
      throw new TypeError('station must be a string');
    }
    const station = item.station.trim();
    if (station.length === 0) {
      throw new TypeError('station must be nonempty after trimming');
    }
    if (typeof item.latencyMs !== 'number' || !Number.isFinite(item.latencyMs) || item.latencyMs < 0) {
      throw new TypeError('latencyMs must be a finite nonnegative number');
    }
    return { station, latencyMs: item.latencyMs };
  });

  const count = parsed.length;

  if (count === 0) {
    return { count: 0, meanMs: null, p95Ms: null, stations: [] };
  }

  // Incremental mean avoids overflowing the accumulator when latencies are
  // very large (e.g. Number.MAX_VALUE), since a naive sum could reach
  // Infinity even though the true mean is finite.
  let runningMean = 0;
  for (let i = 0; i < parsed.length; i += 1) {
    runningMean += (parsed[i].latencyMs - runningMean) / (i + 1);
  }
  const meanMs = round3(runningMean);

  const sortedLatencies = parsed.map((r) => r.latencyMs).sort((a, b) => a - b);
  const p95Index = Math.ceil(count * 0.95) - 1;
  const p95Ms = sortedLatencies[p95Index];

  const byStation = new Map();
  for (const r of parsed) {
    let entry = byStation.get(r.station);
    if (!entry) {
      entry = { station: r.station, count: 0, mean: 0 };
      byStation.set(r.station, entry);
    }
    entry.count += 1;
    entry.mean += (r.latencyMs - entry.mean) / entry.count;
  }

  const stations = Array.from(byStation.values())
    .map((e) => ({ station: e.station, count: e.count, meanMs: round3(e.mean) }))
    .sort((a, b) => {
      if (a.station < b.station) return -1;
      if (a.station > b.station) return 1;
      return 0;
    });

  return { count, meanMs, p95Ms, stations };
}

module.exports = { summarize };
