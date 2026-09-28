import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { renameSync } from 'node:fs';
import {
  chmod,
  link,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

import {
  RuntimeBaselineStore,
  runtimeBaselineAggregateMac,
  runtimeBaselineChangedSurfaces,
} from '../src/runtime/runtime-baseline-store.mjs';

const DEVICE_ID = 'dev_0123456789abcdef0123456789abcdef';
const BASELINE_ID = `rbl_${'11'.repeat(32)}`;
const CAPTURED_AT = '2026-07-30T10:00:00.000Z';
const HMAC_KEY_BASE64 = Buffer.alloc(32, 7).toString('base64');
const execFile = promisify(execFileCallback);
const SURFACES = Object.freeze([
  'account-environment',
  'account-profile-identity',
  'command-resolution',
  'external-sentinel-acls',
  'firewall-profiles',
  'firewall-rules',
  'machine-environment',
  'scheduled-tasks',
  'service-definitions',
].map((id, index) => Object.freeze({
  id,
  count: id === 'firewall-profiles' ? 3 : index,
  mac: String(index).repeat(64),
})));

function baselineInput() {
  return {
    deviceId: DEVICE_ID,
    protocolRevision: 1,
    scriptSha256: 'A'.repeat(64),
    hmacKeyBase64: HMAC_KEY_BASE64,
    surfaces: SURFACES,
    captureAggregateMac: runtimeBaselineAggregateMac({
      hmacKeyBase64: HMAC_KEY_BASE64,
      surfaces: SURFACES,
    }),
  };
}

async function fixture(t, options = {}) {
  const sandbox = await realpath(await mkdtemp(join(tmpdir(), 'agent-road-runtime-baseline-')));
  const root = join(sandbox, 'state');
  t.after(() => rm(sandbox, { recursive: true, force: true }));
  return {
    root,
    store: new RuntimeBaselineStore(root, {
      now: () => new Date(CAPTURED_AT),
      randomBytes: (size) => Buffer.alloc(size, 0x11),
      ...options,
    }),
  };
}

function recordPath(root, kind, id, baselineId = BASELINE_ID) {
  return join(
    root,
    DEVICE_ID,
    'runtime-baselines',
    kind === 'baseline' ? 'baselines' : 'comparisons',
    ...(kind === 'baseline' ? [] : [baselineId]),
    `${id}.json`,
  );
}

async function witnessPath(final) {
  const names = await readdir(dirname(final));
  const witness = names.find((name) => name.startsWith(`${final.split('/').at(-1)}.publish-`));
  assert.ok(witness);
  return join(dirname(final), witness);
}

async function rejectsCode(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.equal(error?.code, code);
    assert.equal(error?.message, code);
    assert.deepEqual(Object.keys(error), ['code']);
    assert.equal(Object.hasOwn(error, 'cause'), false);
    return true;
  });
}

function framedAggregateMac(domain, surfaces = SURFACES) {
  const hmac = createHmac('sha256', Buffer.from(HMAC_KEY_BASE64, 'base64'));
  hmac.update(Buffer.from(domain, 'ascii'));
  for (const surface of surfaces) {
    for (const value of [surface.id, String(surface.count), surface.mac]) {
      const bytes = Buffer.from(value, 'utf8');
      const length = Buffer.alloc(4);
      length.writeUInt32BE(bytes.length);
      hmac.update(length);
      hmac.update(bytes);
    }
  }
  return hmac.digest('hex').toUpperCase();
}

test('uses the exact aggregate domain and uint32-BE length framing for every canonical field', () => {
  const aggregate = runtimeBaselineAggregateMac({
    hmacKeyBase64: HMAC_KEY_BASE64,
    surfaces: SURFACES,
  });
  assert.equal(
    aggregate,
    framedAggregateMac('AgentRoad.RuntimeBaseline.Aggregate.v1\0'),
  );
  assert.equal(
    aggregate,
    '9AB0F6233204BD24D6D54F0EBB25881AABF6D0CAD8EC5CBEDD4DA3978035C417',
  );
  assert.notEqual(
    aggregate,
    framedAggregateMac('AgentRoad.RuntimeBaseline.Aggregate.v2\0'),
  );

  const countChanged = SURFACES.map((surface, index) => (
    index === 0 ? { ...surface, count: surface.count + 1 } : surface
  ));
  const macChanged = SURFACES.map((surface, index) => (
    index === 1 ? { ...surface, mac: 'F'.repeat(64) } : surface
  ));
  assert.notEqual(
    aggregate,
    runtimeBaselineAggregateMac({ hmacKeyBase64: HMAC_KEY_BASE64, surfaces: countChanged }),
  );
  assert.notEqual(
    aggregate,
    runtimeBaselineAggregateMac({ hmacKeyBase64: HMAC_KEY_BASE64, surfaces: macChanged }),
  );
  assert.match(aggregate, /^[A-F0-9]{64}$/u);
});

test('returns only deep-frozen ordered public change flags', () => {
  const observedSurfaces = SURFACES.map((surface, index) => {
    if (index === 1) return { ...surface, count: surface.count + 1 };
    if (index === 7) return { ...surface, mac: 'F'.repeat(64) };
    return surface;
  });
  const changed = runtimeBaselineChangedSurfaces({
    baselineSurfaces: SURFACES,
    observedSurfaces,
  });

  assert.deepEqual(changed, [
    {
      id: 'account-profile-identity',
      countChanged: true,
      macChanged: false,
    },
    {
      id: 'scheduled-tasks',
      countChanged: false,
      macChanged: true,
    },
  ]);
  assert.equal(Object.isFrozen(changed), true);
  assert.equal(changed.every(Object.isFrozen), true);
  assert.equal(JSON.stringify(changed).includes(SURFACES[7].mac), false);
  assert.equal(JSON.stringify(changed).includes(observedSurfaces[7].mac), false);
});

test('publishes and exact-reads one owner-only immutable baseline without latest lookup', async (t) => {
  const { root, store } = await fixture(t);

  const created = await store.createBaseline(baselineInput());
  assert.equal(created.baselineId, BASELINE_ID);
  assert.equal(created.expiresAt, '2026-07-31T10:00:00.000Z');
  assert.equal(Object.isFrozen(created), true);
  assert.deepEqual(
    await store.readBaseline({ deviceId: DEVICE_ID, baselineId: BASELINE_ID }),
    created,
  );

  const recordPath = join(
    root,
    DEVICE_ID,
    'runtime-baselines',
    'baselines',
    `${BASELINE_ID}.json`,
  );
  const recordStats = await stat(recordPath);
  assert.equal(recordStats.mode & 0o777, 0o600);
  assert.equal(recordStats.nlink, 2);
  await assert.rejects(
    store.readBaseline({ deviceId: DEVICE_ID, baselineId: `rbl_${'22'.repeat(32)}` }),
    { code: 'RUNTIME_STATE_UNSUPPORTED' },
  );
});

test('fails closed when an exact baseline is expired before any comparison work', async (t) => {
  let now = new Date(CAPTURED_AT);
  const { store } = await fixture(t, { now: () => now });
  await store.createBaseline(baselineInput());
  now = new Date('2026-07-31T10:00:00.000Z');

  await assert.rejects(
    store.readBaseline({ deviceId: DEVICE_ID, baselineId: BASELINE_ID }),
    (error) => error?.code === 'RUNTIME_STATE_UNSUPPORTED'
      && error.message === 'RUNTIME_STATE_UNSUPPORTED',
  );
});

test('publishes a baseline-bound comparison without copying the HMAC key', async (t) => {
  let identifier = 0x10;
  const { root, store } = await fixture(t, {
    randomBytes: (size) => Buffer.alloc(size, identifier += 1),
  });
  const baseline = await store.createBaseline(baselineInput());
  const observed = SURFACES.map((surface, index) => (
    index === 1
      ? { ...surface, count: surface.count + 1, mac: 'F'.repeat(64) }
      : surface
  ));

  const comparison = await store.createComparison({
    deviceId: DEVICE_ID,
    baselineId: baseline.baselineId,
    baselineRecordDigest: baseline.recordDigest,
    protocolRevision: 1,
    scriptSha256: baseline.scriptSha256,
    observedSurfaces: observed,
  });
  assert.equal(comparison.comparisonId, `rbc_${'12'.repeat(32)}`);
  assert.equal(comparison.baselineRecordDigest, baseline.recordDigest);
  assert.equal(comparison.status, 'CHANGED');
  assert.deepEqual(comparison.changedSurfaces, [{
    id: 'account-profile-identity',
    countChanged: true,
    macChanged: true,
  }]);
  assert.equal(JSON.stringify(comparison).includes(HMAC_KEY_BASE64), false);
  assert.deepEqual(await store.readComparison({
    deviceId: DEVICE_ID,
    baselineId: baseline.baselineId,
    comparisonId: comparison.comparisonId,
  }), comparison);

  const path = recordPath(root, 'comparison', comparison.comparisonId);
  const metadata = await stat(path);
  assert.equal(metadata.mode & 0o777, 0o600);
  assert.equal(metadata.nlink, 2);
  assert.equal((await readFile(path, 'utf8')).includes(HMAC_KEY_BASE64), false);
});

test('rejects comparison provenance drift before publishing any comparison', async (t) => {
  let identifier = 0x10;
  const { root, store } = await fixture(t, {
    randomBytes: (size) => Buffer.alloc(size, identifier += 1),
  });
  const baseline = await store.createBaseline(baselineInput());

  await rejectsCode(store.createComparison({
    deviceId: DEVICE_ID,
    baselineId: baseline.baselineId,
    baselineRecordDigest: baseline.recordDigest,
    protocolRevision: 1,
    scriptSha256: 'B'.repeat(64),
    observedSurfaces: SURFACES,
  }), 'RUNTIME_STATE_UNSUPPORTED');

  await rejectsCode(store.createComparison({
    deviceId: DEVICE_ID,
    baselineId: baseline.baselineId,
    baselineRecordDigest: 'F'.repeat(64),
    protocolRevision: 1,
    scriptSha256: baseline.scriptSha256,
    observedSurfaces: SURFACES,
  }), 'RUNTIME_STATE_UNSUPPORTED');

  const comparisonDirectory = join(root, DEVICE_ID, 'runtime-baselines', 'comparisons');
  await assert.rejects(readdir(comparisonDirectory), { code: 'ENOENT' });
});

test('does not publish a comparison from a replaced baseline namespace', async (t) => {
  let armed = false;
  let swapped = false;
  let targetDirectory;
  let replacementDirectory;
  let displacedDirectory;
  let identifier = 0x10;
  const primary = await fixture(t, {
    randomBytes: (size) => {
      if (armed) {
        renameSync(targetDirectory, displacedDirectory);
        renameSync(replacementDirectory, targetDirectory);
        swapped = true;
        armed = false;
      }
      return Buffer.alloc(size, identifier += 1);
    },
  });
  const replacement = await fixture(t);
  const baseline = await primary.store.createBaseline(baselineInput());
  const replacementBaseline = await replacement.store.createBaseline({
    ...baselineInput(),
    scriptSha256: 'B'.repeat(64),
  });
  assert.equal(replacementBaseline.baselineId, baseline.baselineId);
  assert.notEqual(replacementBaseline.recordDigest, baseline.recordDigest);

  targetDirectory = dirname(recordPath(primary.root, 'baseline', baseline.baselineId));
  replacementDirectory = dirname(recordPath(
    replacement.root,
    'baseline',
    replacementBaseline.baselineId,
  ));
  displacedDirectory = `${targetDirectory}.displaced`;
  armed = true;

  await rejectsCode(primary.store.createComparison({
    deviceId: DEVICE_ID,
    baselineId: baseline.baselineId,
    baselineRecordDigest: baseline.recordDigest,
    protocolRevision: 1,
    scriptSha256: baseline.scriptSha256,
    observedSurfaces: SURFACES,
  }), 'RUNTIME_STATE_UNSUPPORTED');

  assert.equal(swapped, true);
  const comparisonDirectory = join(
    primary.root,
    DEVICE_ID,
    'runtime-baselines',
    'comparisons',
  );
  await assert.rejects(readdir(comparisonDirectory), { code: 'ENOENT' });
});

test('rejects malformed inputs, ceilings, noncanonical keys and ID collisions', async (t) => {
  const { store } = await fixture(t);
  const excessive = SURFACES.map((surface) => (
    surface.id === 'firewall-profiles' ? { ...surface, count: 4 } : surface
  ));
  for (const input of [
    { ...baselineInput(), extra: true },
    { ...baselineInput(), hmacKeyBase64: `${HMAC_KEY_BASE64.slice(0, -2)}AA` },
    { ...baselineInput(), surfaces: excessive },
    new Proxy(baselineInput(), {}),
  ]) {
    await rejectsCode(store.createBaseline(input), 'RUNTIME_INPUT_INVALID');
  }

  await store.createBaseline(baselineInput());
  await rejectsCode(store.createBaseline(baselineInput()), 'RUNTIME_ALREADY_RUNNING');
});

test('serializes deterministic concurrent publication without orphaning the winning record', async (t) => {
  for (let round = 0; round < 8; round += 1) {
    const { root, store } = await fixture(t);
    const settled = await Promise.allSettled([
      store.createBaseline(baselineInput()),
      store.createBaseline(baselineInput()),
    ]);
    assert.equal(settled.filter((entry) => entry.status === 'fulfilled').length, 1);
    const rejected = settled.filter((entry) => entry.status === 'rejected');
    assert.equal(rejected.length, 1);
    assert.equal(rejected[0].reason?.code, 'RUNTIME_ALREADY_RUNNING');
    assert.equal(rejected[0].reason?.message, 'RUNTIME_ALREADY_RUNNING');
    const directory = dirname(recordPath(root, 'baseline', BASELINE_ID));
    const names = await readdir(directory);
    assert.equal(names.length, 2);
    assert.deepEqual(
      await store.readBaseline({ deviceId: DEVICE_ID, baselineId: BASELINE_ID }),
      settled.find((entry) => entry.status === 'fulfilled').value,
    );
  }
});

test('serializes concurrent comparisons in baseline then comparison lock order', async (t) => {
  let identifierCalls = 0;
  const { root, store } = await fixture(t, {
    randomBytes: (size) => Buffer.alloc(size, identifierCalls++ === 0 ? 0x11 : 0x12),
  });
  const baseline = await store.createBaseline(baselineInput());
  const input = {
    deviceId: DEVICE_ID,
    baselineId: baseline.baselineId,
    baselineRecordDigest: baseline.recordDigest,
    protocolRevision: 1,
    scriptSha256: baseline.scriptSha256,
    observedSurfaces: SURFACES,
  };

  const settled = await Promise.allSettled([
    store.createComparison(input),
    store.createComparison(input),
  ]);
  const fulfilled = settled.filter((entry) => entry.status === 'fulfilled');
  const rejected = settled.filter((entry) => entry.status === 'rejected');
  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].reason?.code, 'RUNTIME_ALREADY_RUNNING');
  assert.equal(rejected[0].reason?.message, 'RUNTIME_ALREADY_RUNNING');
  const comparison = fulfilled[0].value;
  const directory = dirname(recordPath(
    root,
    'comparison',
    comparison.comparisonId,
    baseline.baselineId,
  ));
  assert.equal((await readdir(directory)).length, 2);
  assert.deepEqual(await store.readComparison({
    deviceId: DEVICE_ID,
    baselineId: baseline.baselineId,
    comparisonId: comparison.comparisonId,
  }), comparison);
});

test('redacts and rejects a hostile clock object without invoking its methods', async (t) => {
  const hostile = new Date(CAPTURED_AT);
  Object.defineProperty(hostile, 'getTime', {
    value() {
      const error = new Error('PRIVATE_CLOCK_SECRET');
      error.code = 'RUNTIME_STATE_UNSUPPORTED';
      throw error;
    },
  });
  const { store } = await fixture(t, { now: () => hostile });
  await rejectsCode(store.createBaseline(baselineInput()), 'RUNTIME_INTERNAL_ERROR');
});

test('fails closed on clock rollback, unsafe mode, unknown residue and record corruption', async (t) => {
  let now = new Date(CAPTURED_AT);
  const { root, store } = await fixture(t, { now: () => now });
  await store.createBaseline(baselineInput());

  now = new Date('2026-07-30T09:59:59.999Z');
  await rejectsCode(
    store.readBaseline({ deviceId: DEVICE_ID, baselineId: BASELINE_ID }),
    'RUNTIME_STATE_UNSUPPORTED',
  );
  now = new Date(CAPTURED_AT);

  const final = recordPath(root, 'baseline', BASELINE_ID);
  await chmod(final, 0o644);
  await rejectsCode(
    store.readBaseline({ deviceId: DEVICE_ID, baselineId: BASELINE_ID }),
    'RUNTIME_STATE_UNSUPPORTED',
  );
  await chmod(final, 0o600);

  const residue = join(dirname(final), 'LATEST.json');
  await writeFile(residue, '{}', { mode: 0o600 });
  await rejectsCode(
    store.readBaseline({ deviceId: DEVICE_ID, baselineId: BASELINE_ID }),
    'RUNTIME_STATE_UNSUPPORTED',
  );
  await rm(residue);

  const original = await readFile(final);
  await writeFile(final, Buffer.from(original.toString('utf8').replace('RUNTIME_BASELINE', 'RUNTIME_BASELINF')));
  await rejectsCode(
    store.readBaseline({ deviceId: DEVICE_ID, baselineId: BASELINE_ID }),
    'RUNTIME_STATE_UNSUPPORTED',
  );
  assert.equal(await stat(await witnessPath(final)).then((value) => value.nlink), 2);
});

test('rejects Darwin extended ACLs on the owner-only managed chain', async (t) => {
  if (process.platform !== 'darwin') {
    t.skip('Darwin ACL semantics are unavailable');
    return;
  }
  const { root, store } = await fixture(t);
  await store.createBaseline(baselineInput());
  const directory = dirname(recordPath(root, 'baseline', BASELINE_ID));
  await execFile('/bin/chmod', ['+a', 'everyone allow read', directory]);
  t.after(async () => {
    try { await execFile('/bin/chmod', ['-N', directory]); } catch {}
  });
  await rejectsCode(
    store.readBaseline({ deviceId: DEVICE_ID, baselineId: BASELINE_ID }),
    'RUNTIME_STATE_UNSUPPORTED',
  );
});

test('rejects an unsafe ancestor even when the record directory remains owner-only', async (t) => {
  const { root, store } = await fixture(t);
  await store.createBaseline(baselineInput());
  await chmod(root, 0o755);

  await rejectsCode(
    store.readBaseline({ deviceId: DEVICE_ID, baselineId: BASELINE_ID }),
    'RUNTIME_STATE_UNSUPPORTED',
  );
});

test('rejects symlink, extra-hardlink, and missing-witness publication topology', async (t) => {
  const { root, store } = await fixture(t);
  await store.createBaseline(baselineInput());
  const final = recordPath(root, 'baseline', BASELINE_ID);
  const witness = await witnessPath(final);
  const original = await readFile(final);

  await unlink(final);
  await symlink(witness, final);
  await rejectsCode(
    store.readBaseline({ deviceId: DEVICE_ID, baselineId: BASELINE_ID }),
    'RUNTIME_STATE_UNSUPPORTED',
  );

  await unlink(final);
  await link(witness, final);
  const outsideLink = join(dirname(root), 'extra-hardlink.json');
  await link(final, outsideLink);
  await rejectsCode(
    store.readBaseline({ deviceId: DEVICE_ID, baselineId: BASELINE_ID }),
    'RUNTIME_STATE_UNSUPPORTED',
  );
  await unlink(outsideLink);

  await unlink(witness);
  assert.deepEqual(await readFile(final), original);
  await rejectsCode(
    store.readBaseline({ deviceId: DEVICE_ID, baselineId: BASELINE_ID }),
    'RUNTIME_STATE_UNSUPPORTED',
  );
});

test('rejects wrong-case aliases and duplicate or orphan publication witnesses', async (t) => {
  const { root, store } = await fixture(t);
  await store.createBaseline(baselineInput());
  const final = recordPath(root, 'baseline', BASELINE_ID);
  const witness = await witnessPath(final);
  const wrongCase = join(dirname(final), final.split('/').at(-1).replace('rbl_', 'RBL_'));
  await rename(final, wrongCase);
  await rejectsCode(
    store.readBaseline({ deviceId: DEVICE_ID, baselineId: BASELINE_ID }),
    'RUNTIME_STATE_UNSUPPORTED',
  );
  await rename(wrongCase, final);

  const duplicate = `${final}.publish-00000000-0000-4000-8000-000000000000.tmp`;
  await link(final, duplicate);
  await rejectsCode(
    store.readBaseline({ deviceId: DEVICE_ID, baselineId: BASELINE_ID }),
    'RUNTIME_STATE_UNSUPPORTED',
  );
  await unlink(duplicate);

  await rename(witness, `${witness}.wrong-case`);
  await rejectsCode(
    store.readBaseline({ deviceId: DEVICE_ID, baselineId: BASELINE_ID }),
    'RUNTIME_STATE_UNSUPPORTED',
  );
});
