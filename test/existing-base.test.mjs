import assert from 'node:assert/strict';
import test from 'node:test';
import { assessExistingBase, parseExistingBase } from '../src/runtime/existing-base.mjs';

const candidate = (tool, overrides = {}) => ({
  tool, path: `C:\\Tools\\${tool}.exe`, source: 'path', status: 'verified',
  version: tool === 'python' ? '3.14.5' : '24.15.0', sha256: 'A'.repeat(64),
  environmentModules: tool === 'python', reason: null, ...overrides,
});
const parse = candidates => parseExistingBase(JSON.stringify({ schemaVersion: 1, candidates }));

test('assessment reuses explicitly located tools and reports bounded missing discovery', () => {
  const report = assessExistingBase(parse(['git', 'node', 'python'].map(x => candidate(x))));
  assert.deepEqual(report.tools.map(x => [x.tool, x.action]), [
    ['git', 'reuse'], ['node', 'reuse'], ['python', 'reuse'], ['rg', 'not-found'],
  ]);
  assert.equal(report.managedBaseReady, false);
  assert.equal(report.tools[2].candidates[0].path, 'C:\\Tools\\python.exe');
  assert.equal(Object.isFrozen(report.tools[0].candidates[0]), true);
});

test('Store aliases and unsuccessful probes are never reuse candidates', () => {
  for (const status of ['store-alias', 'unavailable']) {
    const report = assessExistingBase(parse([candidate('python', {
      status, reason: status === 'store-alias' ? 'STORE_ALIAS' : 'PROBE_FAILED', version: null, sha256: null, environmentModules: false,
    })]));
    assert.equal(report.tools[2].action, 'review');
  }
});

test('ambiguous executable selection and missing Python modules require review', () => {
  const report = assessExistingBase(parse([
    candidate('node'), candidate('node', {path: 'D:\\Other\\node.exe'}),
    candidate('python', {environmentModules: false}),
  ]));
  assert.equal(report.tools[1].action, 'select');
  assert.equal(report.tools[2].action, 'review');
});

test('unavailable alternative does not prevent using a verified exact executable', () => {
  const report = assessExistingBase(parse([
    candidate('python'), candidate('python', {path: 'C:\\WindowsApps\\python.exe',
      status: 'store-alias', reason: 'STORE_ALIAS', version: null, sha256: null, environmentModules: false}),
  ]));
  assert.equal(report.tools[2].action, 'reuse');
});

test('rejects corrupted or authority-bearing reports and unsafe paths', () => {
  const invalid = [
    '{', '{}', JSON.stringify({schemaVersion: 1, candidates: [], managedBaseReady: true}),
    ...[
      {tool: 'curl'}, {source: 'managed'}, {status: 'READY'}, {version: 'latest'},
      {sha256: null}, {environmentModules: 'true'}, {path: '\\\\host\\share\\node.exe'},
      {path: 'C:\\Tools\\..\\node.exe'}, {path: 'C:\\Tools\\node.exe:stream'},
      {path: 'C:\\ProgramData\\AgentRoad\\node.exe'},
      {path: 'C:\\Tools\\node.cmd'}, {extra: true},
    ].map(x => JSON.stringify({schemaVersion: 1, candidates: [candidate('node', x)]})),
    JSON.stringify({schemaVersion: 1, candidates: Array(33).fill(candidate('node'))}),
    JSON.stringify({schemaVersion: 1, candidates: [candidate('node'),candidate('node')]}),
    ' '.repeat(65537),
  ];
  for (const text of invalid) assert.throws(() => parseExistingBase(text), {code: 'EXISTING_BASE_INVALID'});
});
