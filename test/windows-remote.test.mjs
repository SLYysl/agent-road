import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  decodePowerShellFrame,
  POWERSHELL_FRAME_CHUNK_CHARS,
  powerShellBootstrap,
} from './support/powershell-frame.mjs';

import {
  WINDOWS_ADMINISTRATOR_PROBE_WRAPPER,
  WINDOWS_EXEC_CLEANUP_WRAPPER,
  WINDOWS_EXEC_FINALIZE_WRAPPER,
  WINDOWS_EXEC_INVOKE_WRAPPER,
  WINDOWS_EXEC_PREFLIGHT_WRAPPER,
  WINDOWS_EXEC_READ_RESULT_WRAPPER,
  WINDOWS_EXEC_VERIFY_WRAPPER,
  WINDOWS_GET_CLEANUP_WRAPPER,
  WINDOWS_GET_PREPARE_WRAPPER,
  WINDOWS_PUT_CLEANUP_WRAPPER,
  WINDOWS_PUT_PREFLIGHT_WRAPPER,
  WINDOWS_PUT_PREPARE_WRAPPER,
  WINDOWS_PUT_PUBLISH_WRAPPER,
  WINDOWS_PROVISION_CLEANUP_WRAPPER,
  WINDOWS_PROVISION_FINALIZE_WRAPPER,
  WINDOWS_PROVISION_INIT_WRAPPER,
  WINDOWS_PROVISION_INSPECT_WRAPPER,
  WINDOWS_RUNTIME_RECOVERY_APPLY_WRAPPER,
  WINDOWS_RUNTIME_RECOVERY_INSPECT_WRAPPER,
  WINDOWS_RUNTIME_PROVISION_INVOKE_WRAPPER,
  encodeRemotePayload,
  mapPreMutationProcessError,
  powershellInvocation,
  probeWindowsAdministrator,
  selectAddress,
} from '../src/remote/windows-remote.mjs';

import { createRuntimeRecoveryBootMarker } from '../src/runtime/runtime-recovery-store.mjs';

const ADDRESS = '100.64.0.10';
const SECOND_ADDRESS = '100.64.0.11';
const OPERATION_ID = 'a'.repeat(32);
const PROBE_OUTPUT = 'AGENT_ROAD_ADMINISTRATOR_OK';
const AVAILABLE_POWERSHELL = (() => {
  const candidates = process.platform === 'win32'
    ? ['powershell.exe', 'pwsh.exe']
    : ['pwsh'];
  for (const executable of candidates) {
    const probe = spawnSync(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'exit 0'], {
      encoding: 'utf8',
      timeout: 5000,
    });
    if (!probe.error && probe.status === 0) return executable;
  }
  return null;
})();

function decodePayload(payload) {
  return Buffer.from(payload, 'base64').toString('utf8');
}

function canonicalFixtureJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalFixtureJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => (
    `${JSON.stringify(key)}:${canonicalFixtureJson(value[key])}`
  )).join(',')}}`;
}

function trustedWrapperSource(invocation) {
  powerShellBootstrap(invocation.argv);
  return decodePowerShellFrame(invocation.stdin);
}

function maximumWindowsPath() {
  let component = '';
  for (let index = 0; component.length < 4093; index += 1) {
    component += createHash('sha256')
      .update(`agent-road-${index}`)
      .digest('base64')
      .replaceAll('/', '_');
  }
  return `D:\\${component.slice(0, 4093)}`;
}

function frameLines(stdin) {
  const lines = stdin.split('\r\n');
  assert.equal(lines.pop(), '');
  return lines;
}

function frameFromLines(lines) {
  return `${lines.join('\r\n')}\r\n`;
}

function frameFromBytes(bytes) {
  const encoded = bytes.toString('base64');
  const chunks = [];
  for (let offset = 0; offset < encoded.length; offset += POWERSHELL_FRAME_CHUNK_CHARS) {
    chunks.push(encoded.slice(offset, offset + POWERSHELL_FRAME_CHUNK_CHARS));
  }
  return frameFromLines([
    'AGENT_ROAD_STDIN_V1',
    `L:${bytes.length}`,
    `H:${createHash('sha256').update(bytes).digest('hex').toUpperCase()}`,
    `C:${chunks.length}`,
    ...chunks,
    'END',
  ]);
}

function successfulResult(overrides = {}) {
  return {
    command: '/usr/bin/ssh',
    args: [],
    exitCode: 0,
    signal: null,
    stdout: PROBE_OUTPUT,
    stderr: '',
    ...overrides,
  };
}

function frozenSession(addresses, invokeSsh) {
  return Object.freeze({
    addresses: Object.freeze([...addresses]),
    invokeSsh,
  });
}

function rejectsCode(operation, code) {
  return assert.rejects(operation, (error) => (
    error?.code === code
    && error.message === code
    && error.cause === undefined
  ));
}

test('encodes recursively canonical bounded plain data without mutating caller values', () => {
  const value = {
    zeta: [{ beta: true, alpha: null }, 'value'],
    schemaVersion: 1,
    operationId: OPERATION_ID,
    expectedBytes: 5,
  };
  const payload = encodeRemotePayload(value);
  assert.equal(
    decodePayload(payload),
    `{"expectedBytes":5,"operationId":"${OPERATION_ID}","schemaVersion":1,"zeta":[{"alpha":null,"beta":true},"value"]}`,
  );
  assert.deepEqual(value.zeta[0], { beta: true, alpha: null });
});

test('rejects enumerable accessors, proxies, cycles, sparse arrays, and non-JSON primitives', () => {
  const accessor = { schemaVersion: 1 };
  Object.defineProperty(accessor, 'operationId', {
    enumerable: true,
    get() { throw new Error('accessor executed'); },
  });
  const cycle = { schemaVersion: 1, operationId: OPERATION_ID };
  cycle.self = cycle;
  const sparse = [];
  sparse.length = 2;
  sparse[1] = 'present';

  for (const value of [
    accessor,
    new Proxy({ schemaVersion: 1, operationId: OPERATION_ID }, {}),
    cycle,
    { sparse },
    { value: Number.NaN },
    { value: Number.POSITIVE_INFINITY },
    { value: 1n },
    { value: undefined },
    { value() {} },
    new Date(),
  ]) {
    assert.throws(() => encodeRemotePayload(value), { code: 'REMOTE_INPUT_INVALID' });
  }

  assert.throws(
    () => encodeRemotePayload({ value: 'x'.repeat(16 * 1024) }),
    { code: 'REMOTE_INPUT_INVALID' },
  );

  let deep = {};
  for (let depth = 0; depth < 40; depth += 1) deep = { value: deep };
  assert.throws(() => encodeRemotePayload(deep), { code: 'REMOTE_INPUT_INVALID' });
  assert.throws(
    () => encodeRemotePayload({ values: Array.from({ length: 1100 }, () => null) }),
    { code: 'REMOTE_INPUT_INVALID' },
  );
});

test('stops before later properties when one key or value exceeds the UTF-8 budget', () => {
  const originalDescriptor = Object.getOwnPropertyDescriptor;
  let lateDescriptorReads = 0;
  Object.getOwnPropertyDescriptor = function countedDescriptor(target, key) {
    if (key === 'z-late') lateDescriptorReads += 1;
    return originalDescriptor(target, key);
  };

  try {
    const hugeKey = {
      ['a'.repeat(20 * 1024)]: true,
      'z-late': new Date(),
    };
    assert.throws(() => encodeRemotePayload(hugeKey), { code: 'REMOTE_INPUT_INVALID' });
    assert.equal(lateDescriptorReads, 0);

    const hugeValue = {
      a: 'x'.repeat(20 * 1024),
      'z-late': new Date(),
    };
    assert.throws(() => encodeRemotePayload(hugeValue), { code: 'REMOTE_INPUT_INVALID' });
    assert.equal(lateDescriptorReads, 0);
  } finally {
    Object.getOwnPropertyDescriptor = originalDescriptor;
  }
});

test('short-circuits oversized object and array item counts before full traversal', () => {
  const oversizedObject = Object.fromEntries(
    Array.from({ length: 1100 }, (_, index) => [`p${String(index).padStart(4, '0')}`, null]),
  );
  const oversizedArray = Array.from({ length: 1100 }, () => null);
  const originalDescriptor = Object.getOwnPropertyDescriptor;
  let objectDescriptorReads = 0;
  let arrayItemDescriptorReads = 0;
  Object.getOwnPropertyDescriptor = function countedDescriptor(target, key) {
    if (target === oversizedObject) objectDescriptorReads += 1;
    if (target === oversizedArray && key !== 'length') arrayItemDescriptorReads += 1;
    return originalDescriptor(target, key);
  };

  try {
    assert.throws(
      () => encodeRemotePayload(oversizedObject),
      { code: 'REMOTE_INPUT_INVALID' },
    );
    assert.throws(
      () => encodeRemotePayload({ values: oversizedArray }),
      { code: 'REMOTE_INPUT_INVALID' },
    );
  } finally {
    Object.getOwnPropertyDescriptor = originalDescriptor;
  }

  assert.ok(objectDescriptorReads <= 1024, `read ${objectDescriptorReads} object descriptors`);
  assert.equal(arrayItemDescriptorReads, 0);
});

test('rejects excessive depth before enumerating the over-depth object', () => {
  let value = {};
  for (let depth = 0; depth < 40; depth += 1) value = { next: value };
  const originalNames = Object.getOwnPropertyNames;
  let ownNameSnapshots = 0;
  Object.getOwnPropertyNames = function countedNames(target) {
    ownNameSnapshots += 1;
    return originalNames(target);
  };

  try {
    assert.throws(() => encodeRemotePayload(value), { code: 'REMOTE_INPUT_INVALID' });
  } finally {
    Object.getOwnPropertyNames = originalNames;
  }

  assert.equal(ownNameSnapshots, 0);
});

test('defines payload data as enumerable JSON fields so hidden fields cannot affect output', () => {
  const value = { schemaVersion: 1, operationId: OPERATION_ID };
  Object.defineProperty(value, 'hidden', {
    configurable: false,
    enumerable: false,
    value: new Date(),
  });

  assert.equal(
    decodePayload(encodeRemotePayload(value)),
    `{"operationId":"${OPERATION_ID}","schemaVersion":1}`,
  );
});

test('ignores many symbol fields without invoking accessors or spending the JSON budget', () => {
  const value = { schemaVersion: 1, operationId: OPERATION_ID };
  let getterCalls = 0;
  for (let index = 0; index < 4096; index += 1) {
    Object.defineProperty(value, Symbol(`hidden-${index}`), {
      enumerable: true,
      get() {
        getterCalls += 1;
        throw new Error('symbol accessor executed');
      },
    });
  }

  assert.equal(
    decodePayload(encodeRemotePayload(value)),
    `{"operationId":"${OPERATION_ID}","schemaVersion":1}`,
  );
  assert.equal(getterCalls, 0);
});

test('builds one frozen short PowerShell stdin invocation with exact wrapper bytes', () => {
  const payload = encodeRemotePayload({ schemaVersion: 1, operationId: OPERATION_ID });
  const invocation = powershellInvocation(WINDOWS_ADMINISTRATOR_PROBE_WRAPPER, payload);
  assert.equal(Object.isFrozen(invocation), true);
  assert.equal(Object.isFrozen(invocation.argv), true);
  assert.equal(Object.isFrozen(invocation.stdin), true);
  assert.equal(invocation.argv.includes('-File'), false);
  assert.equal(invocation.argv.includes('-Command'), false);
  assert.equal(invocation.argv.at(-2), '-EncodedCommand');
  const bootstrap = powerShellBootstrap(invocation.argv);
  assert.doesNotMatch(bootstrap, /Write-(?:Host|Output)|Out-|Read-Host|Prompt/iu);
  const script = trustedWrapperSource(invocation);
  assert.match(script, /WindowsPrincipal/u);
  assert.match(script, /AGENT_ROAD_ADMINISTRATOR_OK/u);
  assert.doesNotMatch(script, /C:\\Users\\victim/u);
  assert.equal(decodePowerShellFrame(invocation.stdin), WINDOWS_ADMINISTRATOR_PROBE_WRAPPER(payload));
  assert.doesNotMatch(invocation.stdin, /[^\x00-\x7f]/u);
  assert.ok(`cmd.exe /d /s /c "${invocation.argv.join(' ')}"`.length < 8191);

  assert.throws(
    () => powershellInvocation(() => "Write-Output 'injected'", payload),
    { code: 'REMOTE_INPUT_INVALID' },
  );
  const hostile = encodeRemotePayload({
    schemaVersion: 1,
    operationId: OPERATION_ID,
    path: "C:\\Users\\victim';Write-Output injected;#",
  });
  assert.throws(
    () => powershellInvocation(WINDOWS_ADMINISTRATOR_PROBE_WRAPPER, hostile),
    { code: 'REMOTE_INPUT_INVALID' },
  );
});

test('frames trusted PowerShell source into bounded integrity-checked lines without waiting for EOF', () => {
  const payload = encodeRemotePayload({ schemaVersion: 1, operationId: OPERATION_ID });
  const invocation = powershellInvocation(WINDOWS_ADMINISTRATOR_PROBE_WRAPPER, payload);
  const bootstrap = powerShellBootstrap(invocation.argv);

  assert.match(bootstrap, /^\$ProgressPreference='SilentlyContinue';/u);
  assert.doesNotMatch(bootstrap, /ReadToEnd/u);
  // Windows SSH pipes must bypass ConsoleStream's blocking console handling.
  assert.doesNotMatch(bootstrap, /\[Console\]::(?:In|OpenStandardInput)/u);
  assert.match(bootstrap, /GetStdHandle\(-10\)/u);
  assert.match(bootstrap, /SafeFileHandle\(\$raw,\$false\)/u);
  assert.match(bootstrap, /IO\.FileStream\(\$handle,\[IO\.FileAccess\]::Read\)/u);
  assert.match(bootstrap, /IO\.StreamReader\(\$stream,\[Text.Encoding\]::ASCII,\$false\)/u);
  assert.match(bootstrap, /ReadLine/u);
  assert.ok(bootstrap.indexOf('$ProgressPreference') < bootstrap.indexOf('Security.Cryptography'));
  assert.ok(`cmd.exe /d /s /c "${invocation.argv.join(' ')}"`.length < 8191);

  const lines = invocation.stdin.split('\r\n').slice(0, -1);
  assert.ok(lines.length > 5);
  assert.ok(Math.max(...lines.map((line) => line.length)) <= POWERSHELL_FRAME_CHUNK_CHARS);
  assert.equal(decodePowerShellFrame(invocation.stdin), WINDOWS_ADMINISTRATOR_PROBE_WRAPPER(payload));

  assert.equal((bootstrap.match(/ReadLine/g) ?? []).length, 6);
  assert.match(
    bootstrap,
    /if\(\$r\.ReadLine\(\) -cne 'AGENT_ROAD_STDIN_V1'\)\{throw 0\}/u,
  );
  assert.match(bootstrap, /\^L:\(\[1-9\]\[0-9\]\{0,4\}\)\$/u);
  assert.match(bootstrap, /\^H:\(\[A-F0-9\]\{64\}\)\$/u);
  assert.match(bootstrap, /\^C:\(\[1-9\]\[0-9\]\{0,2\}\)\$/u);
  assert.equal((bootstrap.match(/\$null -eq \$x/g) ?? []).length, 4);
  const endRead = bootstrap.indexOf("$r.ReadLine() -cne 'END'");
  const create = bootstrap.indexOf('[ScriptBlock]::Create');
  assert.ok(endRead >= 0 && create > endRead);
  assert.doesNotMatch(bootstrap.slice(endRead + "$r.ReadLine() -cne 'END'".length), /ReadLine/u);
  assert.match(bootstrap, /\$c -ne \$ec/u);
  assert.match(bootstrap, /\$n -gt 32768/u);
  assert.match(
    bootstrap,
    /\$bl=\[int\]\(4\*\[Math\]::Ceiling\(\$n\/3\)\);\$ec=\[int\]\[Math\]::Ceiling\(\$bl\/2048\)/u,
  );
  assert.match(bootstrap, /\$x\.Length -ne \$el/u);
  assert.match(bootstrap, /\$i -lt \(\$c-1\)[^}]+\$x\.Contains\('='\)/u);
  assert.match(bootstrap, /\[Convert\]::ToBase64String\(\$bytes\) -cne \$b64/u);
  assert.match(bootstrap, /\$v -eq 0 -or \$v -gt 127/u);
  assert.match(bootstrap, /\[Security\.Cryptography\.SHA256\]::Create/u);
  assert.match(bootstrap, /\$ah -cne \$eh/u);
  assert.match(bootstrap, /catch\{\[Environment\]::Exit\(87\)\}/u);
  assert.doesNotMatch(bootstrap, /Write-Error|Write-Output|Write-Host|\$_/u);

  const reencode = bootstrap.indexOf('[Convert]::ToBase64String($bytes) -cne $b64');
  const hash = bootstrap.indexOf('[Security.Cryptography.SHA256]::Create');
  const hashCompare = bootstrap.indexOf('$ah -cne $eh');
  const decode = bootstrap.indexOf('[Text.Encoding]::ASCII.GetString($bytes)');
  assert.ok(reencode > endRead && hash > reencode && hashCompare > hash);
  assert.ok(decode > hashCompare && create > decode);
});

test('rejects truncated, tampered, noncanonical, and overlong framed stdin before source recovery', () => {
  const payload = encodeRemotePayload({ schemaVersion: 1, operationId: OPERATION_ID });
  const shortInvocation = powershellInvocation(WINDOWS_ADMINISTRATOR_PROBE_WRAPPER, payload);
  const short = frameLines(shortInvocation.stdin);
  const longInvocation = powershellInvocation(WINDOWS_EXEC_PREFLIGHT_WRAPPER, payload);
  const long = frameLines(longInvocation.stdin);
  assert.ok(Number(long[3].slice(2)) > 1);

  const corruptions = [];
  corruptions.push(short.slice(0, -1));
  corruptions.push(short.with(0, 'AGENT_ROAD_STDIN_V2'));
  corruptions.push(short.with(1, `L:0${short[1].slice(2)}`));
  corruptions.push(short.with(1, `L:${Number(short[1].slice(2)) + 1}`));
  corruptions.push(short.with(2, short[2].toLowerCase()));
  corruptions.push(short.with(2, `H:${'0'.repeat(64)}`));
  corruptions.push(short.with(3, `C:0${short[3].slice(2)}`));
  corruptions.push(short.with(3, `C:${Number(short[3].slice(2)) + 1}`));
  corruptions.push(short.with(4, `!${short[4].slice(1)}`));
  corruptions.push([...short.slice(0, -1), short[4], 'END']);
  corruptions.push([...long.slice(0, 4), long[4].slice(1), ...long.slice(5)]);
  corruptions.push([...long.slice(0, 4), `${long[4].slice(0, -1)}=`, ...long.slice(5)]);
  corruptions.push([...long.slice(0, 5), 'END', ...long.slice(6)]);

  for (const lines of corruptions) {
    assert.throws(() => decodePowerShellFrame(frameFromLines(lines)));
  }
  assert.throws(() => decodePowerShellFrame(frameFromBytes(Buffer.from([0]))));
  assert.throws(() => decodePowerShellFrame(frameFromBytes(Buffer.from([0x80]))));
  assert.throws(() => decodePowerShellFrame(frameFromBytes(Buffer.alloc((32 * 1024) + 1, 0x41))));
});

test('the 32 KiB source cap keeps 22 KiB, 30 KiB, and maximum frames below 64 KiB', () => {
  for (const size of [22_000, 30_000, 32 * 1024]) {
    const source = Buffer.alloc(size, 0x41);
    const frame = frameFromBytes(source);
    assert.ok(Buffer.byteLength(frame, 'ascii') <= 64 * 1024);
    assert.ok(Math.max(...frameLines(frame).map((line) => line.length)) <= 2048);
    assert.equal(Buffer.byteLength(decodePowerShellFrame(frame), 'ascii'), size);
  }
});

test('the production bootstrap executes one valid frame and rejects invalid frames before payload output', {
  skip: process.platform !== 'win32' || AVAILABLE_POWERSHELL === null ? 'Windows PowerShell required' : false,
}, () => {
  const payload = encodeRemotePayload({ schemaVersion: 1, operationId: OPERATION_ID });
  const invocation = powershellInvocation(WINDOWS_ADMINISTRATOR_PROBE_WRAPPER, payload);
  const marker = 'AGENT_ROAD_FRAME_PAYLOAD_EXECUTED';
  const valid = frameFromBytes(Buffer.from(`[Console]::Out.Write('${marker}')`, 'ascii'));
  const validLines = frameLines(valid);

  const run = (stdin) => spawnSync(
    AVAILABLE_POWERSHELL,
    invocation.argv.slice(1),
    { input: stdin, encoding: 'utf8', timeout: 10_000 },
  );

  const accepted = run(valid);
  assert.equal(accepted.error, undefined);
  assert.equal(accepted.status, 0);
  assert.equal(accepted.stdout, marker);
  assert.equal(accepted.stderr, '');

  const invalidFrames = [
    frameFromLines(validLines.with(1, `L:0${validLines[1].slice(2)}`)),
    frameFromLines(validLines.with(2, `H:${'0'.repeat(64)}`)),
    frameFromLines(validLines.slice(0, -1)),
    '\uFEFF' + valid,
  ];
  for (const invalid of invalidFrames) {
    const rejected = run(invalid);
    assert.equal(rejected.error, undefined);
    assert.equal(rejected.status, 87);
    assert.doesNotMatch(rejected.stdout, new RegExp(marker, 'u'));
    assert.equal(rejected.stderr, '');
  }
});

test('keeps every trusted wrapper argv below cmd.exe limits at maximum high-entropy paths', () => {
  const path = maximumWindowsPath();
  assert.equal(Buffer.byteLength(path, 'utf8'), 4096);
  const base = { schemaVersion: 1, operationId: OPERATION_ID };
  const verified = { ...base, expectedBytes: 42, expectedSha256: 'A'.repeat(64) };
  const runtimeProvision = {
    ...verified,
    runtimeOperationId: 'b'.repeat(32),
    manifestDigest: 'B'.repeat(64),
  };
  const put = { ...verified, destinationPath: path, overwrite: true };
  const get = { ...base, sourcePath: path };
  const identity = '00000001:00000002:00000003';
  const wrappers = [
    [WINDOWS_ADMINISTRATOR_PROBE_WRAPPER, base],
    [WINDOWS_EXEC_PREFLIGHT_WRAPPER, base],
    [WINDOWS_EXEC_VERIFY_WRAPPER, verified],
    [WINDOWS_EXEC_INVOKE_WRAPPER, verified],
    [WINDOWS_RUNTIME_PROVISION_INVOKE_WRAPPER, runtimeProvision],
    [WINDOWS_EXEC_READ_RESULT_WRAPPER, base],
    [WINDOWS_EXEC_CLEANUP_WRAPPER, base],
    [WINDOWS_PUT_PREFLIGHT_WRAPPER, put],
    [WINDOWS_PUT_PREPARE_WRAPPER, put],
    [WINDOWS_PUT_PUBLISH_WRAPPER, { ...put, expectedParentIdentity: identity }],
    [WINDOWS_PUT_CLEANUP_WRAPPER, {
      ...put,
      expectedParentIdentity: identity,
      stagingOwned: true,
      tempOwned: true,
    }],
    [WINDOWS_GET_PREPARE_WRAPPER, get],
    [WINDOWS_GET_CLEANUP_WRAPPER, {
      ...get,
      expectedBytes: 42,
      expectedSha256: 'A'.repeat(64),
      snapshotOwned: true,
    }],
  ];
  let longestSource = 0;
  let longestFrame = 0;

  for (const [wrapper, value] of wrappers) {
    const payload = encodeRemotePayload(value);
    const invocation = powershellInvocation(wrapper, payload);
    assert.ok(`cmd.exe /d /s /c "${invocation.argv.join(' ')}"`.length < 8191);
    assert.ok(Buffer.byteLength(invocation.stdin, 'ascii') <= 64 * 1024);
    assert.ok(Math.max(...frameLines(invocation.stdin).map((line) => line.length)) <= 2048);
    const source = trustedWrapperSource(invocation);
    assert.equal(source, wrapper(payload));
    longestSource = Math.max(longestSource, Buffer.byteLength(source, 'ascii'));
    longestFrame = Math.max(longestFrame, Buffer.byteLength(invocation.stdin, 'ascii'));
  }

  assert.equal(longestSource, 26_280);
  assert.equal(longestFrame, 35_185);
});

test('the fixed probe schema rejects unknown fields and noncanonical operation IDs', () => {
  for (const value of [
    { schemaVersion: 1, operationId: OPERATION_ID, unknown: true },
    { schemaVersion: 1, operationId: 'A'.repeat(32) },
    { schemaVersion: 1, operationId: 'a'.repeat(31) },
    { schemaVersion: 1, operationId: 'g'.repeat(32) },
    { schemaVersion: 2, operationId: OPERATION_ID },
  ]) {
    const payload = encodeRemotePayload(value);
    assert.throws(
      () => powershellInvocation(WINDOWS_ADMINISTRATOR_PROBE_WRAPPER, payload),
      { code: 'REMOTE_INPUT_INVALID' },
    );
  }
});

test('registers only the concrete exec wrappers with exact payload schemas', () => {
  const base = { schemaVersion: 1, operationId: OPERATION_ID };
  const verified = {
    ...base,
    expectedBytes: 42,
    expectedSha256: 'A'.repeat(64),
  };
  const valid = [
    [WINDOWS_EXEC_PREFLIGHT_WRAPPER, base],
    [WINDOWS_EXEC_VERIFY_WRAPPER, verified],
    [WINDOWS_EXEC_INVOKE_WRAPPER, verified],
    [WINDOWS_EXEC_READ_RESULT_WRAPPER, base],
    [WINDOWS_EXEC_CLEANUP_WRAPPER, base],
  ];
  for (const [wrapper, value] of valid) {
    assert.equal(typeof wrapper, 'function');
    assert.doesNotThrow(() => powershellInvocation(wrapper, encodeRemotePayload(value)));
    assert.throws(
      () => powershellInvocation(wrapper, encodeRemotePayload({ ...value, unknown: true })),
      { code: 'REMOTE_INPUT_INVALID' },
    );
  }
  for (const expectedBytes of [1, 2 * 1024 * 1024 + 3, 1.5]) {
    assert.throws(
      () => powershellInvocation(WINDOWS_EXEC_VERIFY_WRAPPER, encodeRemotePayload({
        ...base,
        expectedBytes,
        expectedSha256: 'A'.repeat(64),
      })),
      { code: 'REMOTE_INPUT_INVALID' },
    );
  }
  assert.throws(
    () => powershellInvocation(WINDOWS_EXEC_VERIFY_WRAPPER, encodeRemotePayload({
      ...base,
      expectedBytes: 42,
      expectedSha256: 'a'.repeat(64),
    })),
    { code: 'REMOTE_INPUT_INVALID' },
  );
});

test('runtime provision invoke wrapper derives one canonical child stdin record', () => {
  const payload = {
    schemaVersion: 1,
    operationId: OPERATION_ID,
    expectedBytes: 42,
    expectedSha256: 'A'.repeat(64),
    runtimeOperationId: 'b'.repeat(32),
    manifestDigest: 'B'.repeat(64),
  };
  const invocation = powershellInvocation(
    WINDOWS_RUNTIME_PROVISION_INVOKE_WRAPPER,
    encodeRemotePayload(payload),
  );
  const source = trustedWrapperSource(invocation);
  const start = source.indexOf('$started=$child.Start()');
  const write = source.indexOf('$child.StandardInput.BaseStream.Write($childInputBytes,0,$childInputBytes.Length)');
  const close = source.indexOf('$child.StandardInput.BaseStream.Close()');
  const wait = source.indexOf('$child.WaitForExit()');

  assert.ok(start >= 0 && write > start && close > write && wait > close);
  assert.match(source, /new-object Text\.UTF8Encoding\(\$false,\$true\)/iu);
  assert.equal(
    source.includes(
      '$childInput=\'{"schemaVersion":1,"operationId":"\'+$payload.runtimeOperationId+\'","manifestDigest":"\'+$payload.manifestDigest+\'"}\'',
    ),
    true,
  );
  assert.match(source, /\$childInputBytes\.Length -gt 256/u);
  assert.doesNotMatch(source, /Get-ChildItem|Get-Content|environmentVariables|StandardInputEncoding/iu);
  assert.doesNotMatch(source, new RegExp(payload.runtimeOperationId, 'u'));
  assert.doesNotMatch(source, new RegExp(payload.manifestDigest, 'u'));

  for (const invalid of [
    { ...payload, runtimeOperationId: 'B'.repeat(32) },
    { ...payload, runtimeOperationId: 'b'.repeat(31) },
    { ...payload, manifestDigest: 'b'.repeat(64) },
    { ...payload, manifestDigest: 'B'.repeat(63) },
    { ...payload, childStdin: 'caller-controlled' },
  ]) {
    assert.throws(
      () => powershellInvocation(
        WINDOWS_RUNTIME_PROVISION_INVOKE_WRAPPER,
        encodeRemotePayload(invalid),
      ),
      { code: 'REMOTE_INPUT_INVALID' },
    );
  }

  const ordinary = trustedWrapperSource(
    powershellInvocation(WINDOWS_EXEC_INVOKE_WRAPPER, encodeRemotePayload({
      schemaVersion: 1,
      operationId: OPERATION_ID,
      expectedBytes: 42,
      expectedSha256: 'A'.repeat(64),
    })),
  );
  assert.doesNotMatch(ordinary, /StandardInput\.Write/u);
});

test('registers only concrete put wrappers with phase-specific exact bounded payload schemas', () => {
  const value = {
    schemaVersion: 1,
    operationId: OPERATION_ID,
    destinationPath: 'D:\\work\\site.html',
    overwrite: false,
    expectedBytes: 42,
    expectedSha256: 'A'.repeat(64),
  };
  const parentIdentity = '00000001:00000002:00000003';
  const wrappers = [
    [WINDOWS_PUT_PREFLIGHT_WRAPPER, value],
    [WINDOWS_PUT_PREPARE_WRAPPER, value],
    [WINDOWS_PUT_PUBLISH_WRAPPER, { ...value, expectedParentIdentity: parentIdentity }],
    [WINDOWS_PUT_CLEANUP_WRAPPER, {
      ...value,
      expectedParentIdentity: parentIdentity,
      stagingOwned: true,
      tempOwned: true,
    }],
  ];
  for (const [wrapper, phaseValue] of wrappers) {
    assert.equal(typeof wrapper, 'function');
    assert.doesNotThrow(() => powershellInvocation(wrapper, encodeRemotePayload(phaseValue)));
    assert.throws(
      () => powershellInvocation(wrapper, encodeRemotePayload({ ...phaseValue, unknown: true })),
      { code: 'REMOTE_INPUT_INVALID' },
    );
  }
  assert.throws(
    () => powershellInvocation(WINDOWS_PUT_PUBLISH_WRAPPER, encodeRemotePayload(value)),
    { code: 'REMOTE_INPUT_INVALID' },
  );
  for (const cleanupValue of [
    { ...value, expectedParentIdentity: null, stagingOwned: true, tempOwned: true },
    { ...value, expectedParentIdentity: parentIdentity, stagingOwned: false, tempOwned: false },
  ]) {
    assert.throws(
      () => powershellInvocation(WINDOWS_PUT_CLEANUP_WRAPPER, encodeRemotePayload(cleanupValue)),
      { code: 'REMOTE_INPUT_INVALID' },
    );
  }
  for (const invalid of [
    { ...value, destinationPath: 'relative.txt' },
    { ...value, destinationPath: 'C:\\ProgramData\\AgentRoad\\x' },
    { ...value, destinationPath: 'C:\\work\\COM¹.txt' },
    { ...value, destinationPath: 'C:\\work\\com²' },
    { ...value, destinationPath: 'C:\\work\\LpT³.log' },
    { ...value, overwrite: 1 },
    { ...value, expectedBytes: -1 },
    { ...value, expectedBytes: 256 * 1024 * 1024 + 1 },
    { ...value, expectedSha256: 'a'.repeat(64) },
  ]) {
    assert.throws(
      () => powershellInvocation(WINDOWS_PUT_PREPARE_WRAPPER, encodeRemotePayload(invalid)),
      { code: 'REMOTE_INPUT_INVALID' },
    );
  }
  assert.throws(
    () => powershellInvocation((payload) => payload, encodeRemotePayload(value)),
    { code: 'REMOTE_INPUT_INVALID' },
  );
});

test('registers exactly four concrete provision wrappers with closed internal schemas', () => {
  const base = {
    schemaVersion: 1,
    operationId: OPERATION_ID,
    manifestDigest: 'B'.repeat(64),
  };
  const entry = {
    ...base,
    entryType: 'artifact',
    artifactId: 'powershell-7',
    version: '7.5.2',
    expectedBytes: 42,
    expectedSha256: 'A'.repeat(64),
  };
  const inspect = {
    ...base,
    components: [{
      artifactId: 'powershell-7',
      version: '7.5.2',
      expectedBytes: 42,
      expectedSha256: 'A'.repeat(64),
    }],
    capsule: { expectedBytes: 43, expectedSha256: 'C'.repeat(64) },
  };
  for (const [wrapper, payload] of [
    [WINDOWS_PROVISION_INIT_WRAPPER, base],
    [WINDOWS_PROVISION_INSPECT_WRAPPER, inspect],
    [WINDOWS_PROVISION_FINALIZE_WRAPPER, entry],
    [WINDOWS_PROVISION_CLEANUP_WRAPPER, entry],
  ]) {
    assert.equal(typeof wrapper, 'function');
    assert.doesNotThrow(() => powershellInvocation(wrapper, encodeRemotePayload(payload)));
    assert.throws(
      () => powershellInvocation(wrapper, encodeRemotePayload({ ...payload, remotePath: 'D:\\escape' })),
      { code: 'REMOTE_INPUT_INVALID' },
    );
  }
  assert.throws(
    () => powershellInvocation(WINDOWS_PROVISION_FINALIZE_WRAPPER, encodeRemotePayload({
      ...entry,
      expectedBytes: 256 * 1024 * 1024 + 1,
    })),
    { code: 'REMOTE_INPUT_INVALID' },
  );
  assert.throws(
    () => powershellInvocation(WINDOWS_PROVISION_CLEANUP_WRAPPER, encodeRemotePayload({
      ...entry,
      artifactId: '..',
    })),
    { code: 'REMOTE_INPUT_INVALID' },
  );
  assert.throws(
    () => powershellInvocation(WINDOWS_PROVISION_FINALIZE_WRAPPER, encodeRemotePayload({
      ...entry,
      version: `${'1'.repeat(65)}.2.3`,
    })),
    { code: 'REMOTE_INPUT_INVALID' },
  );
  assert.throws(
    () => powershellInvocation((payload) => payload, encodeRemotePayload(entry)),
    { code: 'REMOTE_INPUT_INVALID' },
  );
});

test('provision wrappers derive operation-bound runtime paths and never embed caller paths', () => {
  const base = {
    schemaVersion: 1,
    operationId: OPERATION_ID,
    manifestDigest: 'B'.repeat(64),
  };
  const entry = {
    ...base,
    entryType: 'artifact',
    artifactId: 'powershell-7',
    version: '7.5.2',
    expectedBytes: 42,
    expectedSha256: 'A'.repeat(64),
  };
  const inspect = {
    ...base,
    components: [{
      artifactId: 'powershell-7',
      version: '7.5.2',
      expectedBytes: 42,
      expectedSha256: 'A'.repeat(64),
    }],
    capsule: { expectedBytes: 43, expectedSha256: 'C'.repeat(64) },
  };
  for (const [wrapper, payload] of [
    [WINDOWS_PROVISION_INIT_WRAPPER, base],
    [WINDOWS_PROVISION_INSPECT_WRAPPER, inspect],
    [WINDOWS_PROVISION_FINALIZE_WRAPPER, entry],
    [WINDOWS_PROVISION_CLEANUP_WRAPPER, entry],
  ]) {
    const source = trustedWrapperSource(
      powershellInvocation(wrapper, encodeRemotePayload(payload)),
    );
    assert.match(source, /C:\\ProgramData\\AgentRoad/u);
    assert.match(source, /runtime/u);
    assert.match(source, /staging/u);
    assert.match(source, /ReparsePoint/u);
    if (wrapper !== WINDOWS_PROVISION_INIT_WRAPPER) assert.match(source, /Get-FileHash/u);
    assert.doesNotMatch(source, /D:\\escape/u);
    assert.doesNotMatch(source, new RegExp(OPERATION_ID, 'u'));
  }
});

test('provision temp validation accepts only the two effective inherited or explicit ACL rules', () => {
  const payload = {
    schemaVersion: 1,
    operationId: OPERATION_ID,
    manifestDigest: 'B'.repeat(64),
    entryType: 'artifact',
    artifactId: 'powershell-7',
    version: '7.5.2',
    expectedBytes: 42,
    expectedSha256: 'A'.repeat(64),
  };
  const source = trustedWrapperSource(
    powershellInvocation(WINDOWS_PROVISION_FINALIZE_WRAPPER, encodeRemotePayload(payload)),
  );
  assert.match(
    source,
    /GetAccessRules\(\$true,\$true,\[Security\.Principal\.SecurityIdentifier\]\)/u,
  );
  assert.match(source, /\$rules\.Count -ne 2/u);
  assert.match(source, /S-1-5-18/u);
  assert.match(source, /S-1-5-32-544/u);
});

test('restricted wrappers translate the owner and secure directories at creation time', () => {
  const base = {
    schemaVersion: 1,
    operationId: OPERATION_ID,
  };
  const payload = {
    ...base,
    manifestDigest: 'B'.repeat(64),
  };
  const source = trustedWrapperSource(
    powershellInvocation(WINDOWS_PROVISION_INIT_WRAPPER, encodeRemotePayload(payload)),
  );

  const ordinarySources = [
    [WINDOWS_EXEC_PREFLIGHT_WRAPPER, base],
    [WINDOWS_PUT_PREFLIGHT_WRAPPER, {
      ...base,
      destinationPath: 'D:\\work\\file.txt',
      overwrite: false,
      expectedBytes: 42,
      expectedSha256: 'A'.repeat(64),
    }],
    [WINDOWS_GET_PREPARE_WRAPPER, { ...base, sourcePath: 'D:\\work\\file.txt' }],
  ].map(([wrapper, value]) => trustedWrapperSource(
    powershellInvocation(wrapper, encodeRemotePayload(value)),
  ));

  for (const candidate of [source, ...ordinarySources]) {
    assert.match(
      candidate,
      /\$owner=\$administrators\.Translate\(\[Security\.Principal\.NTAccount\]\)/u,
    );
    assert.doesNotMatch(candidate, /\.SetOwner\(\$administrators\)/u);
    assert.match(candidate, /function New-AgentRoadRestrictedDirectorySecurity/u);
    assert.doesNotMatch(
      candidate,
      /CreateDirectory\(\$(?:candidate|root)\)\|Out-Null/u,
    );
  }

  assert.match(source, /function New-AgentRoadRestrictedDirectorySecurity/u);
  assert.match(
    source,
    /\[IO\.Directory\]::CreateDirectory\(\$candidate,\(New-AgentRoadRestrictedDirectorySecurity\)\)/u,
  );
  assert.doesNotMatch(
    source,
    /CreateDirectory\(\$candidate\)\|Out-Null;Set-AgentRoadRestrictedDirectoryAcl/u,
  );
});

test('the maximum 32-component provision inspect payload fits the fixed frame', () => {
  const version = `${'1'.repeat(20)}.${'2'.repeat(20)}.${'3'.repeat(22)}`;
  const components = Array.from({ length: 32 }, (_, index) => ({
    artifactId: `a${String(index).padStart(2, '0')}${'x'.repeat(61)}`,
    version,
    expectedBytes: 256 * 1024 * 1024,
    expectedSha256: index.toString(16).toUpperCase().padStart(64, '0'),
  }));
  const payload = {
    schemaVersion: 1,
    operationId: OPERATION_ID,
    manifestDigest: 'B'.repeat(64),
    components,
    capsule: { expectedBytes: 128 * 1024, expectedSha256: 'C'.repeat(64) },
  };
  assert.doesNotThrow(() => powershellInvocation(
    WINDOWS_PROVISION_INSPECT_WRAPPER,
    encodeRemotePayload(payload),
  ));
  assert.throws(
    () => powershellInvocation(
      WINDOWS_PROVISION_INSPECT_WRAPPER,
      encodeRemotePayload({ ...payload, components: [...components, {
        ...components.at(-1),
        artifactId: `a32${'x'.repeat(61)}`,
      }] }),
    ),
    { code: 'REMOTE_INPUT_INVALID' },
  );
});

test('provision init binds one operation ID to one manifest and only its work sibling', () => {
  const payload = {
    schemaVersion: 1,
    operationId: OPERATION_ID,
    manifestDigest: 'B'.repeat(64),
  };
  const source = trustedWrapperSource(
    powershellInvocation(WINDOWS_PROVISION_INIT_WRAPPER, encodeRemotePayload(payload)),
  );
  assert.match(source, /Get-ChildItem -LiteralPath \$operationRoot -Force/u);
  assert.match(source, /\('work-'\+\$payload\.manifestDigest\)/u);
  assert.match(source, /provision operation conflict/u);
  assert.match(source, /Assert-AgentRoadProvisionDirectory \$item\.FullName/u);
  assert.match(source, /\$allowedOperationEntries -cnotcontains \$item\.Name/u);
  assert.doesNotMatch(source, /allowedOperationEntries\.ContainsKey/u);
});

test('put wrappers keep caller paths encoded and separate prepare from one final atomic publish', () => {
  const value = {
    schemaVersion: 1,
    operationId: OPERATION_ID,
    destinationPath: 'D:\\work\\hostile-site.html',
    overwrite: true,
    expectedBytes: 42,
    expectedSha256: 'A'.repeat(64),
  };
  const parentIdentity = '00000001:00000002:00000003';
  const source = (wrapper, phaseValue = value) => Buffer.from(
    trustedWrapperSource(powershellInvocation(wrapper, encodeRemotePayload(phaseValue))),
  ).toString();
  const preflight = source(WINDOWS_PUT_PREFLIGHT_WRAPPER);
  const prepare = source(WINDOWS_PUT_PREPARE_WRAPPER);
  const publish = source(WINDOWS_PUT_PUBLISH_WRAPPER, {
    ...value,
    expectedParentIdentity: parentIdentity,
  });
  const cleanup = source(WINDOWS_PUT_CLEANUP_WRAPPER, {
    ...value,
    expectedParentIdentity: parentIdentity,
    stagingOwned: true,
    tempOwned: true,
  });

  for (const script of [preflight, prepare, publish, cleanup]) {
    assert.match(script, /FromBase64String/u);
    assert.match(script, /C:\\ProgramData\\AgentRoad\\transfers/u);
    assert.match(script, /ReparsePoint/u);
    assert.doesNotMatch(script, /D:\\work\\hostile-site\.html/u);
    assert.doesNotMatch(script, new RegExp(OPERATION_ID, 'u'));
  }
  assert.match(preflight, /SetAccessRuleProtection\(\$true,\$false\)/u);
  assert.match(preflight, /S-1-5-18/u);
  assert.match(preflight, /S-1-5-32-544/u);

  assert.match(prepare, /\[IO\.File\]::Copy/u);
  assert.match(prepare, /Get-FileHash/u);
  assert.match(prepare, /destinationParent/u);
  assert.match(prepare, /Set-AgentRoadRestrictedFileAcl \$stagingPath/u);
  assert.doesNotMatch(prepare, /\[IO\.File\]::(?:Move|Replace)/u);

  for (const script of [prepare, publish, cleanup]) {
    assert.match(script, /function Assert-AgentRoadSafeDestinationChain/u);
    assert.match(script, /\[IO\.Path\]::GetPathRoot/u);
    assert.match(script, /Assert-AgentRoadSafeDestinationChain \$destinationParent/u);
    assert.match(script, /GetLongPathNameW/u);
    assert.match(script, /DllImport\("kernel32\.dll"/u);
    assert.match(script, /Add-Type -TypeDefinition \$nativeSource/u);
    assert.match(script, /'AgentRoad\.NativePath' -as \[type\]/u);
    assert.match(script, /Resolve-AgentRoadExistingLongPath/u);
    assert.match(script, /Resolve-AgentRoadDestinationLongPath/u);
    assert.match(script, /32768/u);
    assert.doesNotMatch(script, /Get-Item[^;]+\.FullName/u);
  }
  for (const script of [prepare, publish, cleanup]) {
    assert.match(script, /CreateFileW/u);
    assert.match(script, /GetFileInformationByHandle/u);
    assert.match(script, /FILE_FLAG_BACKUP_SEMANTICS/u);
    assert.match(script, /FILE_FLAG_OPEN_REPARSE_POINT/u);
    assert.match(script, /FILE_ATTRIBUTE_REPARSE_POINT/u);
    assert.match(script, /FILE_SHARE_READ\|FILE_SHARE_WRITE/u);
    assert.doesNotMatch(script, /FILE_SHARE_DELETE/u);
    assert.match(script, /VolumeSerialNumber/u);
    assert.match(script, /FileIndexHigh/u);
    assert.match(script, /FileIndexLow/u);
  }
  assert.match(prepare, /AGENT_ROAD_PUT_PREPARED:/u);
  assert.match(prepare, /exit 75/u);
  assert.match(prepare, /exit 76/u);
  assert.match(publish, /expectedParentIdentity/u);
  assert.ok((publish.match(/Get-AgentRoadDirectoryHandleIdentity/gu) ?? []).length >= 2);
  assert.match(cleanup, /stagingOwned/u);
  assert.match(cleanup, /tempOwned/u);
  assert.match(cleanup, /expectedParentIdentity/u);
  const identityBeforeCopy = prepare.indexOf(
    '$parentIdentityBefore=Get-AgentRoadDirectoryHandleIdentity $parentHandle',
  );
  const prepareCopy = prepare.indexOf('[IO.File]::Copy');
  const identityAfterHash = prepare.indexOf(
    '$parentIdentityAfter=Get-AgentRoadDirectoryHandleIdentity $parentHandle',
  );
  assert.ok(identityBeforeCopy >= 0 && prepareCopy > identityBeforeCopy);
  assert.ok(identityAfterHash > prepare.indexOf('$tempHash='));
  const prepareHandleOpen = prepare.indexOf(
    '$parentHandle=Open-AgentRoadDirectoryHandle $destinationParent',
  );
  const prepareHandleDispose = prepare.indexOf('$parentHandle.Dispose()');
  assert.ok(prepareHandleOpen >= 0 && prepareCopy > prepareHandleOpen);
  assert.ok(prepareHandleDispose > identityAfterHash);
  assert.match(prepare, /destination\.StartsWith/u);
  assert.match(prepare, /StringComparison\]::OrdinalIgnoreCase/u);

  const hashIndex = publish.indexOf('Get-FileHash');
  const moveIndex = publish.indexOf('[IO.File]::Move');
  const replaceIndex = publish.indexOf('[IO.File]::Replace');
  assert.ok(hashIndex >= 0 && moveIndex > hashIndex && replaceIndex > hashIndex);
  const chainIndex = publish.indexOf('Assert-AgentRoadSafeDestinationChain $destinationParent');
  const longPathIndex = publish.indexOf('Resolve-AgentRoadDestinationLongPath');
  assert.ok(chainIndex >= 0 && moveIndex > chainIndex && replaceIndex > chainIndex);
  assert.ok(longPathIndex >= 0 && moveIndex > longPathIndex && replaceIndex > longPathIndex);
  const currentIdentityIndex = publish.indexOf('$currentParentIdentity=');
  const tempValidationIndex = publish.indexOf('$tempItem=Get-Item');
  const finalIdentityIndex = publish.indexOf('$finalParentIdentity=');
  assert.ok(currentIdentityIndex >= 0 && tempValidationIndex > currentIdentityIndex);
  assert.ok(finalIdentityIndex > tempValidationIndex);
  assert.ok(moveIndex > finalIdentityIndex && replaceIndex > finalIdentityIndex);
  const publishHandleOpen = publish.indexOf(
    '$publishParentHandle=Open-AgentRoadDirectoryHandle $destinationParent',
  );
  const publishHandleDispose = publish.indexOf('$publishParentHandle.Dispose()');
  assert.ok(publishHandleOpen >= 0 && tempValidationIndex > publishHandleOpen);
  assert.ok(publishHandleDispose > moveIndex && publishHandleDispose > replaceIndex);
  assert.equal((publish.match(/\[IO\.File\]::Move/gu) ?? []).length, 1);
  assert.equal((publish.match(/\[IO\.File\]::Replace/gu) ?? []).length, 1);
  assert.match(
    publish,
    /\[IO\.File\]::Replace\(\$tempPath,\$destination,\[Management\.Automation\.Language\.NullString\]::Value,\$true\)/u,
  );
  assert.doesNotMatch(publish, /\[IO\.File\]::Replace\([^)]*\$null/u);
  assert.doesNotMatch(publish, /Copy\(/u);
  assert.doesNotMatch(publish, /if\(\$payload\.overwrite -or/u);

  const cleanupLongPathIndex = cleanup.lastIndexOf(
    '$resolvedDestination=Resolve-AgentRoadDestinationLongPath',
  );
  const cleanupTempRemoveIndex = cleanup.indexOf('Remove-Item -LiteralPath $tempPath');
  assert.ok(cleanupLongPathIndex >= 0 && cleanupTempRemoveIndex > cleanupLongPathIndex);
  assert.match(cleanup, /Remove-Item -LiteralPath \$stagingPath/u);
  assert.match(cleanup, /Remove-Item -LiteralPath \$tempPath/u);
  assert.doesNotMatch(cleanup, /Remove-Item -LiteralPath \$destination(?:;|\s)/u);
  assert.ok(cleanup.indexOf('if($payload.stagingOwned)') < cleanup.indexOf(
    'Remove-Item -LiteralPath $stagingPath',
  ));
  assert.ok(cleanup.indexOf('if($payload.tempOwned)') < cleanupTempRemoveIndex);
  const stagingHandleOpen = cleanup.indexOf(
    '$stagingParentHandle=Open-AgentRoadDirectoryHandle $root',
  );
  const stagingHandleDispose = cleanup.indexOf('$stagingParentHandle.Dispose()');
  const stagingRemove = cleanup.indexOf('Remove-Item -LiteralPath $stagingPath');
  assert.ok(stagingHandleOpen >= 0 && stagingRemove > stagingHandleOpen);
  assert.ok(stagingHandleDispose > stagingRemove);
  const cleanupHandleOpen = cleanup.indexOf(
    '$cleanupParentHandle=Open-AgentRoadDirectoryHandle $destinationParent',
  );
  const cleanupHandleDispose = cleanup.indexOf('$cleanupParentHandle.Dispose()');
  assert.ok(cleanupHandleOpen >= 0 && cleanupTempRemoveIndex > cleanupHandleOpen);
  assert.ok(cleanupHandleDispose > cleanupTempRemoveIndex);
  assert.doesNotMatch(cleanup, /Get-ChildItem|-[A-Za-z]*Filter|\*\.agent-road-/u);
});

test('get wrappers enforce exact phase schemas and fixed stable-snapshot boundaries', () => {
  const base = {
    schemaVersion: 1,
    operationId: OPERATION_ID,
    sourcePath: 'D:\\work\\dist\\index.html',
  };
  const cleanup = {
    ...base,
    expectedBytes: 42,
    expectedSha256: 'A'.repeat(64),
    snapshotOwned: true,
  };
  const unownedCleanup = {
    ...base,
    expectedBytes: null,
    expectedSha256: null,
    snapshotOwned: false,
  };
  for (const [wrapper, value] of [
    [WINDOWS_GET_PREPARE_WRAPPER, base],
    [WINDOWS_GET_CLEANUP_WRAPPER, cleanup],
    [WINDOWS_GET_CLEANUP_WRAPPER, unownedCleanup],
  ]) {
    assert.doesNotThrow(() => powershellInvocation(wrapper, encodeRemotePayload(value)));
    assert.throws(
      () => powershellInvocation(wrapper, encodeRemotePayload({ ...value, unknown: true })),
      { code: 'REMOTE_INPUT_INVALID' },
    );
  }
  for (const invalid of [
    { ...base, sourcePath: 'relative.bin' },
    { ...base, sourcePath: 'C:\\ProgramData\\AgentRoad\\secret.bin' },
    { ...base, sourcePath: 'D:\\work\\COM¹.bin' },
  ]) {
    assert.throws(
      () => powershellInvocation(WINDOWS_GET_PREPARE_WRAPPER, encodeRemotePayload(invalid)),
      { code: 'REMOTE_INPUT_INVALID' },
    );
  }
  for (const invalid of [
    { ...cleanup, expectedBytes: -1 },
    { ...cleanup, expectedBytes: 256 * 1024 * 1024 + 1 },
    { ...cleanup, expectedSha256: 'a'.repeat(64) },
    { ...cleanup, snapshotOwned: false },
    { ...unownedCleanup, expectedBytes: 42 },
  ]) {
    assert.throws(
      () => powershellInvocation(WINDOWS_GET_CLEANUP_WRAPPER, encodeRemotePayload(invalid)),
      { code: 'REMOTE_INPUT_INVALID' },
    );
  }

  const source = (wrapper, value) => Buffer.from(
    trustedWrapperSource(powershellInvocation(wrapper, encodeRemotePayload(value))),
  ).toString();
  const prepare = source(WINDOWS_GET_PREPARE_WRAPPER, base);
  const cleanupScript = source(WINDOWS_GET_CLEANUP_WRAPPER, cleanup);
  for (const script of [prepare, cleanupScript]) {
    assert.match(script, /FromBase64String/u);
    assert.match(script, /C:\\ProgramData\\AgentRoad\\transfers/u);
    assert.match(script, /\.get\.stage/u);
    assert.doesNotMatch(script, /D:\\work\\dist\\index\.html/u);
    assert.doesNotMatch(script, new RegExp(OPERATION_ID, 'u'));
  }
  for (const boundary of [
    /GetLongPathNameW/u,
    /GetFinalPathNameByHandleW/u,
    /GetFinalPathNameByHandle\(SafeFileHandle handle,StringBuilder output,uint capacity,uint flags\)/u,
    /CreateFileW/u,
    /GetFileInformationByHandle/u,
    /FILE_FLAG_OPEN_REPARSE_POINT/u,
    /FILE_SHARE_READ/u,
    /FileMode\.CreateNew/u,
    /output\.Flush\(true\)/u,
    /SameFile\(before,after\)/u,
    /String\.Equals\(finalPath,source,StringComparison\.OrdinalIgnoreCase\)/u,
    /Resolve-AgentRoadSafeSource/u,
  ]) assert.match(prepare, boundary);
  assert.match(
    prepare,
    /value\.StartsWith\(prefix,StringComparison\.Ordinal\).*value=value\.Substring\(prefix\.Length\)/u,
  );
  assert.ok(
    prepare.indexOf('string finalPath=FinalPath(handle)')
      < prepare.indexOf('new FileStream(destination'),
  );
  assert.match(prepare, /AGENT_ROAD_GET_PREPARED:/u);
  assert.match(prepare, /Set-AgentRoadRestrictedFileAcl \$snapshotPath/u);
  assert.match(cleanupScript, /if\(\$payload\.snapshotOwned\)/u);
  assert.match(cleanupScript, /Remove-Item -LiteralPath \$snapshotPath/u);
  assert.doesNotMatch(cleanupScript, /Remove-Item -LiteralPath \$source/u);
});

test('fixed exec wrappers reconstruct one task path from payload and enforce safe source boundaries', () => {
  const base = { schemaVersion: 1, operationId: OPERATION_ID };
  const verified = {
    ...base,
    expectedBytes: 42,
    expectedSha256: 'A'.repeat(64),
  };
  const wrappers = [
    [WINDOWS_EXEC_PREFLIGHT_WRAPPER, base],
    [WINDOWS_EXEC_VERIFY_WRAPPER, verified],
    [WINDOWS_EXEC_INVOKE_WRAPPER, verified],
    [WINDOWS_EXEC_READ_RESULT_WRAPPER, base],
    [WINDOWS_EXEC_CLEANUP_WRAPPER, base],
  ];
  for (const [wrapper, payload] of wrappers) {
    const invocation = powershellInvocation(wrapper, encodeRemotePayload(payload));
    const source = trustedWrapperSource(invocation);
    assert.match(source, /C:\\ProgramData\\AgentRoad\\tasks/u);
    assert.match(source, /FromBase64String/u);
    assert.match(source, /operationId/u);
    assert.match(source, /ReparsePoint/u);
    assert.doesNotMatch(source, new RegExp(OPERATION_ID, 'u'));
    assert.doesNotMatch(source, /C:\\Users\\victim/u);
  }
  const preflight = trustedWrapperSource(
    powershellInvocation(WINDOWS_EXEC_PREFLIGHT_WRAPPER, encodeRemotePayload(base)),
  );
  assert.match(preflight, /SetAccessRuleProtection\(\$true,\$false\)/u);
  assert.match(preflight, /S-1-5-18/u);
  assert.match(preflight, /S-1-5-32-544/u);

  const verifier = trustedWrapperSource(
    powershellInvocation(WINDOWS_EXEC_VERIFY_WRAPPER, encodeRemotePayload({
      ...base,
      expectedBytes: 42,
      expectedSha256: 'A'.repeat(64),
    })),
  );
  assert.match(verifier, /Get-FileHash/u);
  assert.match(verifier, /Length/u);
  assert.match(verifier, /WindowsPrincipal/u);

  const invoke = trustedWrapperSource(
    powershellInvocation(WINDOWS_EXEC_INVOKE_WRAPPER, encodeRemotePayload(verified)),
  );
  const invokeHash = invoke.indexOf('Get-FileHash');
  const invokeChild = invoke.indexOf('$started=$child.Start()');
  const closeChildInput = invoke.indexOf('$child.StandardInput.Close()');
  const waitForChild = invoke.indexOf('$child.WaitForExit()');
  const readChildExit = invoke.indexOf('$child.ExitCode');
  const publishResult = invoke.indexOf('$record=');
  assert.ok(invokeHash >= 0 && invokeChild > invokeHash, 'same wrapper must rehash before child start');
  assert.match(invoke, /Diagnostics\.ProcessStartInfo/u);
  assert.match(
    invoke,
    /\$windowsPowerShell=Join-Path \$env:SystemRoot 'System32\\WindowsPowerShell\\v1\.0\\powershell\.exe'/u,
  );
  assert.match(invoke, /Test-Path -LiteralPath \$windowsPowerShell -PathType Leaf/u);
  assert.match(invoke, /\$windowsPowerShellItem\.Attributes -band \[IO\.FileAttributes\]::ReparsePoint/u);
  assert.match(invoke, /\$startInfo\.FileName=\$windowsPowerShell/u);
  assert.match(
    invoke,
    /\$startInfo\.Arguments='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'\+\$path\+'"'/u,
  );
  assert.doesNotMatch(invoke, /\.ArgumentList/u);
  assert.match(invoke, /UseShellExecute=\$false/u);
  assert.match(invoke, /RedirectStandardInput=\$true/u);
  assert.match(invoke, /RedirectStandardOutput=\$false/u);
  assert.match(invoke, /RedirectStandardError=\$false/u);
  assert.equal(invoke.match(/\$child\.Start\(\)/gu)?.length, 1);
  assert.match(invoke, /\$started=\$child\.Start\(\)/u);
  assert.ok(invokeChild < closeChildInput);
  assert.ok(closeChildInput < waitForChild);
  assert.ok(waitForChild < readChildExit);
  assert.ok(readChildExit < publishResult);
  assert.match(invoke, /finally\{\$child\.Dispose\(\)\}/u);
  assert.doesNotMatch(invoke, /RedirectStandard(?:Output|Error)=\$true/u);
  assert.doesNotMatch(invoke, /& powershell\.exe/u);
  assert.doesNotMatch(invoke, /\$LASTEXITCODE/u);
  assert.doesNotMatch(invoke, /Write-(?:Output|Error)|Console.*Write/u);
  assert.match(invoke, /result\.json/u);
  assert.match(invoke, /Move-Item/u);
  assert.match(invoke, /\{"exitCode":/u);

  for (const source of [preflight, invoke]) {
    assert.match(source, /Assert-AgentRoadRestrictedDirectoryAcl/u);
    assert.match(source, /Assert-AgentRoadRestrictedDirectoryAcl \$parent/u);
    assert.match(source, /Assert-AgentRoadRestrictedDirectoryAcl \$root/u);
  }

  const readResult = trustedWrapperSource(
    powershellInvocation(WINDOWS_EXEC_READ_RESULT_WRAPPER, encodeRemotePayload(base)),
  );
  assert.match(readResult, /result\.json/u);
  assert.match(readResult, /ReadAllText/u);
  assert.equal(
    readResult.includes('^(?:0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'),
    true,
  );
  assert.match(readResult, /ReparsePoint/u);
  assert.match(readResult, /Assert-AgentRoadRestrictedFileAcl/u);

  const cleanup = trustedWrapperSource(
    powershellInvocation(WINDOWS_EXEC_CLEANUP_WRAPPER, encodeRemotePayload(base)),
  );
  assert.match(cleanup, /\.ps1/u);
  assert.match(cleanup, /result\.json/u);
  assert.match(cleanup, /Remove-Item/u);
  assert.doesNotMatch(cleanup, /& powershell\.exe|-File \$path/u);
});

test('probes one exact address with strict argv, exit, stderr, and output contracts', async () => {
  const calls = [];
  const session = frozenSession([ADDRESS], async (address, argv, options) => {
    calls.push({ address, argv, options });
    return successfulResult();
  });

  assert.equal(await probeWindowsAdministrator(session, ADDRESS), ADDRESS);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].address, ADDRESS);
  powerShellBootstrap(calls[0].argv);
  const probePayload = encodeRemotePayload({ schemaVersion: 1, operationId: '0'.repeat(32) });
  const probeInvocation = powershellInvocation(WINDOWS_ADMINISTRATOR_PROBE_WRAPPER, probePayload);
  assert.deepEqual(calls[0].options, {
    timeoutMs: 10_000,
    maxOutputBytes: 4096,
    stdinText: probeInvocation.stdin,
  });
});

test('maps pre-mutation output overflow separately and redacts every child failure', async () => {
  const overflow = Object.assign(new Error('/private/key leaked'), { code: 'PROCESS_OUTPUT_LIMIT' });
  const mappedOverflow = mapPreMutationProcessError(overflow);
  assert.equal(mappedOverflow.code, 'REMOTE_OUTPUT_LIMIT');
  assert.equal(mappedOverflow.message, 'REMOTE_OUTPUT_LIMIT');
  assert.equal(mappedOverflow.cause, undefined);

  const mappedFailure = mapPreMutationProcessError(
    Object.assign(new Error('ssh: hostile child detail'), { code: 'PROCESS_TIMEOUT' }),
  );
  assert.equal(mappedFailure.code, 'REMOTE_CONNECTION_FAILED');
  assert.equal(mappedFailure.message, 'REMOTE_CONNECTION_FAILED');
  assert.equal(mappedFailure.cause, undefined);

  await rejectsCode(
    probeWindowsAdministrator(frozenSession([ADDRESS], async () => { throw overflow; }), ADDRESS),
    'REMOTE_OUTPUT_LIMIT',
  );
  await rejectsCode(
    probeWindowsAdministrator(frozenSession([ADDRESS], async () => {
      throw new Error('ssh: child secret');
    }), ADDRESS),
    'REMOTE_CONNECTION_FAILED',
  );
});

test('rejects every malformed successful-looking probe result', async () => {
  for (const result of [
    successfulResult({ exitCode: 1 }),
    successfulResult({ signal: 'SIGTERM' }),
    successfulResult({ stderr: 'warning' }),
    successfulResult({ stdout: `${PROBE_OUTPUT}\r\n` }),
    successfulResult({ stdout: `${PROBE_OUTPUT}extra` }),
    { exitCode: 0, signal: null, stdout: PROBE_OUTPUT, stderr: '', unknown: true },
  ]) {
    await rejectsCode(
      probeWindowsAdministrator(frozenSession([ADDRESS], async () => result), ADDRESS),
      'REMOTE_CONNECTION_FAILED',
    );
  }
});

test('rejects accessor and Proxy process results without invoking hostile properties', async () => {
  let getterCalls = 0;
  const accessorResult = successfulResult();
  Object.defineProperty(accessorResult, 'stdout', {
    enumerable: true,
    get() {
      getterCalls += 1;
      throw new Error('accessor executed');
    },
  });
  for (const result of [accessorResult, new Proxy(successfulResult(), {})]) {
    await rejectsCode(
      probeWindowsAdministrator(frozenSession([ADDRESS], async () => result), ADDRESS),
      'REMOTE_CONNECTION_FAILED',
    );
  }
  assert.equal(getterCalls, 0);
});

test('selects the first successful frozen address and falls back only during probes', async () => {
  const calls = [];
  const session = frozenSession([ADDRESS, SECOND_ADDRESS], async (address) => {
    calls.push(address);
    if (address === ADDRESS) throw new Error('first unavailable');
    return successfulResult();
  });
  assert.equal(await selectAddress(session), SECOND_ADDRESS);
  assert.deepEqual(calls, [ADDRESS, SECOND_ADDRESS]);

  const allFailed = frozenSession([ADDRESS, SECOND_ADDRESS], async () => {
    throw Object.assign(new Error('child detail'), { code: 'PROCESS_OUTPUT_LIMIT' });
  });
  await rejectsCode(selectAddress(allFailed), 'REMOTE_CONNECTION_FAILED');
});

test('rejects hostile session and address boundaries without invoking accessors', async () => {
  let getterCalls = 0;
  const accessor = { addresses: Object.freeze([ADDRESS]) };
  Object.defineProperty(accessor, 'invokeSsh', {
    enumerable: true,
    get() {
      getterCalls += 1;
      throw new Error('accessor executed');
    },
  });
  Object.freeze(accessor);

  for (const session of [
    accessor,
    new Proxy(frozenSession([ADDRESS], async () => successfulResult()), {}),
    Object.freeze({ addresses: [ADDRESS], invokeSsh: async () => successfulResult() }),
    frozenSession(['not-an-address'], async () => successfulResult()),
    frozenSession([ADDRESS, ADDRESS], async () => successfulResult()),
  ]) {
    await rejectsCode(selectAddress(session), 'REMOTE_INPUT_INVALID');
  }
  assert.equal(getterCalls, 0);

  await rejectsCode(
    probeWindowsAdministrator(frozenSession([ADDRESS], async () => successfulResult()), SECOND_ADDRESS),
    'REMOTE_INPUT_INVALID',
  );
});

const RECOVERY_TICKET_ID = `rct_${'b'.repeat(64)}`;
const RECOVERY_ATTEMPT_DIGEST = 'C'.repeat(64);
const RECOVERY_ACL_DIGEST = 'DD88275C41BC223A8C77B8E2CA108226DDDE5F39D2B044AD84AEFB31B9643C44';

function recoveryBootMarker(eventRecordId, second) {
  return createRuntimeRecoveryBootMarker({
    schemaVersion: 1,
    providerGuid: '{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}',
    channel: 'System',
    eventId: 12,
    version: 7,
    eventRecordId,
    timeCreated: `2026-07-30T10:00:${second}.000Z`,
    startTime: `2026-07-30T10:00:${second}.000Z`,
  });
}

function recoveryAcl() {
  return {
    ownerSid: 'S-1-5-32-544',
    protected: true,
    canonical: true,
    accessRuleCount: 2,
    administratorsFullControl: true,
    systemFullControl: true,
    aclDigest: RECOVERY_ACL_DIGEST,
  };
}

function recoveryDirectory(volume, fileId, directChildren) {
  return {
    volumeSerialNumber: volume,
    fileId,
    acl: recoveryAcl(),
    directChildCount: directChildren.length,
    directChildren,
  };
}

function recoveryInspectPayload(overrides = {}) {
  return {
    schemaVersion: 1,
    protocolRevision: 1,
    operationId: OPERATION_ID,
    beforeBootMarker: recoveryBootMarker('41', '01'),
    ...overrides,
  };
}

function recoveryApplyPayload(overrides = {}) {
  const beforeBootMarker = recoveryBootMarker('41', '01');
  const afterBootMarker = recoveryBootMarker('42', '02');
  return {
    schemaVersion: 1,
    protocolRevision: 1,
    operationId: OPERATION_ID,
    expectedWindowsProof: {
      beforeBootMarker,
      afterBootMarker,
      classification: 'EMPTY_PRE_TRANSACTION',
      priorAuthorizedAttempt: null,
      agentRoadAcl: recoveryAcl(),
      runtimeDirectory: recoveryDirectory('0000000000000001', '01'.repeat(16), ['staging']),
      stagingDirectory: recoveryDirectory('0000000000000001', '02'.repeat(16), [OPERATION_ID]),
      operationDirectory: recoveryDirectory('0000000000000001', '03'.repeat(16), []),
    },
    authorizedAttemptDigest: RECOVERY_ATTEMPT_DIGEST,
    ...overrides,
  };
}

test('registers exactly the two runtime recovery wrappers with canonical payload schemas', () => {
  const inspectValue = recoveryInspectPayload();
  const applyValue = recoveryApplyPayload();
  const inspectInvocation = powershellInvocation(
    WINDOWS_RUNTIME_RECOVERY_INSPECT_WRAPPER,
    encodeRemotePayload(inspectValue),
  );
  const applyInvocation = powershellInvocation(
    WINDOWS_RUNTIME_RECOVERY_APPLY_WRAPPER,
    encodeRemotePayload(applyValue),
  );

  assert.equal(
    decodePayload(encodeRemotePayload(inspectValue)),
    canonicalFixtureJson(inspectValue),
  );
  assert.equal(
    decodePayload(encodeRemotePayload(applyValue)),
    canonicalFixtureJson(applyValue),
  );
  assert.equal(decodePowerShellFrame(inspectInvocation.stdin), trustedWrapperSource(inspectInvocation));
  assert.equal(decodePowerShellFrame(applyInvocation.stdin), trustedWrapperSource(applyInvocation));

  for (const [wrapper, value] of [
    [WINDOWS_RUNTIME_RECOVERY_INSPECT_WRAPPER, inspectValue],
    [WINDOWS_RUNTIME_RECOVERY_APPLY_WRAPPER, applyValue],
  ]) {
    for (const invalid of [
      { ...value, extra: true },
      { ...value, schemaVersion: 2 },
      { ...value, protocolRevision: '1' },
      { ...value, operationId: OPERATION_ID.toUpperCase() },
    ]) {
      assert.throws(
        () => powershellInvocation(wrapper, encodeRemotePayload(invalid)),
        { code: 'REMOTE_INPUT_INVALID' },
      );
    }
  }

  assert.throws(
    () => powershellInvocation(
      WINDOWS_RUNTIME_RECOVERY_INSPECT_WRAPPER,
      encodeRemotePayload({
        schemaVersion: 1,
        protocolRevision: 1,
        operationId: OPERATION_ID,
      }),
    ),
    { code: 'REMOTE_INPUT_INVALID' },
  );
  assert.throws(
    () => powershellInvocation(
      WINDOWS_RUNTIME_RECOVERY_APPLY_WRAPPER,
      encodeRemotePayload({ ...applyValue, expectedWindowsProof: {
        ...applyValue.expectedWindowsProof,
        unknown: true,
      } }),
    ),
    { code: 'REMOTE_INPUT_INVALID' },
  );
});

test('runtime recovery wrapper sources fit exact ASCII and maximum frame budgets', () => {
  for (const [wrapper, value] of [
    [WINDOWS_RUNTIME_RECOVERY_INSPECT_WRAPPER, recoveryInspectPayload()],
    [WINDOWS_RUNTIME_RECOVERY_APPLY_WRAPPER, recoveryApplyPayload()],
  ]) {
    const invocation = powershellInvocation(wrapper, encodeRemotePayload(value));
    const source = trustedWrapperSource(invocation);
    assert.doesNotMatch(source, /[^\x00-\x7f]/u);
    assert.ok(Buffer.byteLength(source, 'ascii') <= 32 * 1024);
    assert.ok(Buffer.byteLength(invocation.stdin, 'ascii') <= 64 * 1024);
    assert.ok(Math.max(...frameLines(invocation.stdin).map((line) => line.length)) <= 2048);
  }
});

test('runtime recovery direct-child enumeration returns a flat empty array to its array caller', () => {
  const invocation = powershellInvocation(
    WINDOWS_RUNTIME_RECOVERY_INSPECT_WRAPPER,
    encodeRemotePayload(recoveryInspectPayload()),
  );
  const source = trustedWrapperSource(invocation);

  assert.doesNotMatch(source, /return ,\$values\.ToArray\(\)/u);
  assert.match(source, /return \$values\.ToArray\(\)/u);
});

test('runtime recovery deletion uses the one-byte Win32 FILE_DISPOSITION_INFO layout', () => {
  const invocation = powershellInvocation(
    WINDOWS_RUNTIME_RECOVERY_APPLY_WRAPPER,
    encodeRemotePayload(recoveryApplyPayload()),
  );
  const source = trustedWrapperSource(invocation);

  assert.doesNotMatch(
    source,
    /FILE_DISPOSITION_INFO \{\[MarshalAs\(UnmanagedType\.Bool\)\] public bool DeleteFile;\}/u,
  );
  assert.match(source, /FILE_DISPOSITION_INFO \{public byte DeleteFile;\}/u);
  assert.match(source, /\$disposition\.DeleteFile=1/u);
});

test('runtime recovery deletion keeps only unreturned or successful dispatches uncertain', () => {
  const invocation = powershellInvocation(
    WINDOWS_RUNTIME_RECOVERY_APPLY_WRAPPER,
    encodeRemotePayload(recoveryApplyPayload()),
  );
  const source = trustedWrapperSource(invocation);

  const dispatchFlag = source.indexOf('$deleteDispatched=$true');
  const deleteCall = source.indexOf('$deleteSucceeded=[AgentRoadRecovery.NativeMethods]::SetFileInformationByHandle(');
  const nativeError = source.indexOf('$deleteError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()', deleteCall);
  const finiteFailure = source.indexOf(
    "if(-not $deleteSucceeded){$deleteDispatched=$false;throw 'RUNTIME_STATE_UNSUPPORTED'}",
    nativeError,
  );

  assert.equal((source.match(/::SetFileInformationByHandle\s*\(/gu) ?? []).length, 1);
  assert.ok(dispatchFlag >= 0 && deleteCall > dispatchFlag);
  assert.ok(nativeError > deleteCall && finiteFailure > nativeError);
});

test('runtime recovery PowerShell exact-record fields match canonical JSON key order', () => {
  for (const [wrapper, payload] of [
    [WINDOWS_RUNTIME_RECOVERY_INSPECT_WRAPPER, recoveryInspectPayload()],
    [WINDOWS_RUNTIME_RECOVERY_APPLY_WRAPPER, recoveryApplyPayload()],
  ]) {
    const source = trustedWrapperSource(powershellInvocation(wrapper, encodeRemotePayload(payload)));
    const records = [...source.matchAll(/Assert-ExactRecord \$[a-zA-Z.]+ @\(([^)]*)\)/gu)];
    assert.ok(records.length >= 2);
    for (const [, text] of records) {
      const fields = [...text.matchAll(/'([^']+)'/gu)].map(match => match[1]);
      assert.deepEqual(fields, [...fields].sort(), 'wire records use canonical sorted keys');
    }
  }
});

test('runtime recovery event pairs omit the null end-of-log sentinel', () => {
  for (const [wrapper, payload] of [
    [WINDOWS_RUNTIME_RECOVERY_INSPECT_WRAPPER, recoveryInspectPayload()],
    [WINDOWS_RUNTIME_RECOVERY_APPLY_WRAPPER, recoveryApplyPayload()],
  ]) {
    const source = trustedWrapperSource(powershellInvocation(wrapper, encodeRemotePayload(payload)));
    assert.match(source, /if\(\$null -ne \$first\)\{\$first\};if\(\$null -ne \$second\)\{\$second\}/u);
    assert.doesNotMatch(source, /return @\(\$first,\$second\)/u);
  }
});

test('runtime recovery boot marker parsing uses the PowerShell 5.1 compatible DateTimeStyles value', () => {
  const invocation = powershellInvocation(
    WINDOWS_RUNTIME_RECOVERY_INSPECT_WRAPPER,
    encodeRemotePayload(recoveryInspectPayload()),
  );
  const source = trustedWrapperSource(invocation);

  assert.doesNotMatch(source, /DateTimeStyles\]::RoundtripKind/u);
  assert.match(source, /DateTimeStyles\]::None/u);
  assert.match(source, /\$dto\.UtcDateTime\.ToString/u);
});

test('Windows PowerShell 5.1 preserves runtime recovery array, timestamp, and disposition semantics', {
  skip: process.platform === 'win32' ? false : 'requires win32 and Windows PowerShell 5.1',
}, (t) => {
  const version = spawnSync(
    'powershell.exe',
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.ToString()'],
    { encoding: 'utf8', timeout: 5_000 },
  );
  if (version.error || version.status !== 0 || !version.stdout.trim().startsWith('5.1')) {
    t.skip('requires powershell.exe 5.1');
    return;
  }

  const source = [
    "$ErrorActionPreference='Stop'",
    "function Get-DirectChildren([string]$path,[int]$maximum){$values=New-Object Collections.Generic.List[string];$enumerator=[IO.Directory]::EnumerateFileSystemEntries($path).GetEnumerator();try{while($enumerator.MoveNext()){if($values.Count -ge $maximum){throw 'bounded'};$values.Add([IO.Path]::GetFileName([string]$enumerator.Current))}}finally{if($enumerator -is [IDisposable]){$enumerator.Dispose()}};return $values.ToArray()}",
    "$root=[IO.Path]::Combine([IO.Path]::GetTempPath(),'agent-road-recovery-'+[Guid]::NewGuid().ToString('N'))",
    'try{',
    "$empty=[IO.Path]::Combine($root,'empty')",
    "$single=[IO.Path]::Combine($root,'single')",
    '$null=[IO.Directory]::CreateDirectory($empty)',
    '$null=[IO.Directory]::CreateDirectory($single)',
    "$child=[IO.Path]::Combine($single,'child.txt')",
    "[IO.File]::WriteAllText($child,'fixture')",
    '$zero=@(Get-DirectChildren $empty 1)',
    '$one=@(Get-DirectChildren $single 1)',
    "$strict='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,7})?Z$'",
    "$text='2026-07-30T10:00:02.123Z'",
    "if($text -cnotmatch $strict -or '2026-07-30T10:00:02+00:00' -cmatch $strict){throw 'strict-z'}",
    '$dto=[DateTimeOffset]::Parse($text,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None)',
    "$canonical=$dto.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ',[Globalization.CultureInfo]::InvariantCulture)",
    "Add-Type -TypeDefinition 'using System.Runtime.InteropServices; [StructLayout(LayoutKind.Sequential)] public struct FILE_DISPOSITION_INFO { public byte DeleteFile; }'",
    '$size=[Runtime.InteropServices.Marshal]::SizeOf([type][FILE_DISPOSITION_INFO])',
    "$result=[pscustomobject][ordered]@{zeroCount=$zero.Count;oneCount=$one.Count;oneName=[string]$one[0];canonical=$canonical;dispositionSize=$size}",
    '[Console]::Out.Write(($result|ConvertTo-Json -Compress))',
    '}finally{if([IO.Directory]::Exists($root)){[IO.Directory]::Delete($root,$true)}}',
  ].join(';');
  const execution = spawnSync(
    'powershell.exe',
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', source],
    { encoding: 'utf8', timeout: 10_000 },
  );

  assert.equal(execution.error, undefined);
  assert.equal(execution.status, 0, execution.stderr);
  assert.equal(execution.stderr, '');
  assert.deepEqual(JSON.parse(execution.stdout), {
    zeroCount: 0,
    oneCount: 1,
    oneName: 'child.txt',
    canonical: '2026-07-30T10:00:02.123Z',
    dispositionSize: 1,
  });
});

test('inspect wrapper freezes the read-only identity, ACL, topology, and boot-event boundary', () => {
  const invocation = powershellInvocation(
    WINDOWS_RUNTIME_RECOVERY_INSPECT_WRAPPER,
    encodeRemotePayload(recoveryInspectPayload()),
  );
  const source = trustedWrapperSource(invocation);

  assert.match(source, /WindowsIdentity.*GetCurrent/u);
  assert.match(source, /WindowsBuiltInRole\]::Administrator/u);
  assert.match(source, /AgentRoad/u);
  assert.match(source, /C:\\ProgramData\\AgentRoad/u);
  assert.match(source, /runtime/u);
  assert.match(source, /staging/u);
  assert.match(source, /FileIdInfo/u);
  assert.match(source, /GetFileInformationByHandleEx/u);
  assert.match(source, /VolumeSerialNumber/u);
  assert.match(source, /X16/u);
  assert.match(source, /Identifier/u);
  assert.match(source, /16/u);
  assert.doesNotMatch(source, /GetFileInformationByHandle\s*\(/u);
  assert.match(source, /FileAttributes.*ReparsePoint|ReparsePoint.*FileAttributes/su);
  assert.match(source, /AreAccessRulesProtected/u);
  assert.match(source, /AreAccessRulesCanonical/u);
  assert.match(source, /S-1-5-32-544/u);
  assert.match(source, /S-1-5-18/u);
  assert.match(source, /FileSystemRights\]::FullControl/u);
  assert.match(source, /DD88275C41BC223A8C77B8E2CA108226DDDE5F39D2B044AD84AEFB31B9643C44/u);
  assert.match(source, /GetEnumerator/u);
  assert.match(source, /CompareOrdinal/u);
  assert.match(source, /RUNTIME_OPERATION_CONFLICT/u);
  assert.match(source, /RUNTIME_STATE_UNSUPPORTED/u);

  assert.match(source, /\{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d\}/u);
  assert.match(source, /System/u);
  assert.match(source, /EventID/u);
  assert.match(source, /EventRecordID/u);
  assert.match(source, /StartTime/u);
  assert.match(source, /yyyy-MM-ddTHH:mm:ss\.fffZ/u);
  assert.match(source, /AGENT_ROAD_WINDOWS_BOOT_EVENT_12_V1/u);
  assert.match(source, /RUNTIME_REBOOT_REQUIRED/u);
  assert.match(source, /RUNTIME_BOOT_IDENTITY_UNAVAILABLE/u);

  assert.doesNotMatch(
    source,
    /Remove-Item|Directory\]::Delete|Directory\.Delete|\brmdir\b|FileDispositionInfo|SetFileInformationByHandle|Mutex|SetAccessRule|CreateDirectory/iu,
  );
});

test('apply wrapper holds the secure global mutex around one handle-bound deletion and postcondition', () => {
  const invocation = powershellInvocation(
    WINDOWS_RUNTIME_RECOVERY_APPLY_WRAPPER,
    encodeRemotePayload(recoveryApplyPayload()),
  );
  const source = trustedWrapperSource(invocation);

  assert.match(source, /Global\\AgentRoadRuntimeMutation/u);
  assert.match(source, /MutexSecurity/u);
  assert.match(source, /SetAccessRuleProtection\(\$true,\$false\)/u);
  assert.match(source, /SetOwner/u);
  assert.match(source, /AreAccessRulesProtected/u);
  assert.match(source, /AreAccessRulesCanonical/u);
  assert.match(source, /WaitOne\(0\)/u);
  assert.match(source, /AbandonedMutexException/u);
  assert.match(source, /ReleaseMutex/u);
  assert.match(source, /Dispose/u);
  assert.match(source, /deleteDispatched/u);
  assert.match(source, /FileDispositionInfo/u);
  assert.match(source, /SetFileInformationByHandle/u);
  assert.equal((source.match(/::SetFileInformationByHandle\s*\(/gu) ?? []).length, 1);
  assert.doesNotMatch(
    source,
    /Remove-Item|Directory\]::Delete|Directory\.Delete|\brmdir\b|\brecurse\b/iu,
  );

  const dispatchFlag = source.indexOf('$deleteDispatched=$true');
  const deleteCall = source.indexOf('::SetFileInformationByHandle(');
  const operationClose = source.indexOf('$operationHandle.Dispose()', deleteCall);
  const postcondition = source.indexOf('Get-AgentRoadRecoveryState', operationClose);
  const resultWrite = source.indexOf('[Console]::Out.Write', postcondition);
  const release = source.lastIndexOf('ReleaseMutex');
  assert.ok(dispatchFlag >= 0 && deleteCall > dispatchFlag);
  assert.ok(operationClose > deleteCall && postcondition > operationClose);
  assert.ok(resultWrite > postcondition && release > resultWrite);
  assert.match(source, /ALREADY_ABSENT/u);
  assert.match(source, /expectedWindowsProof/u);
  assert.match(source, /authorizedAttemptDigest/u);
});


test('inspect-only Windows stage instrumentation preserves rejection and apply boundaries', () => {
  const inspect = trustedWrapperSource(powershellInvocation(
    WINDOWS_RUNTIME_RECOVERY_INSPECT_WRAPPER, encodeRemotePayload(recoveryInspectPayload())));
  const apply = trustedWrapperSource(powershellInvocation(
    WINDOWS_RUNTIME_RECOVERY_APPLY_WRAPPER, encodeRemotePayload(recoveryApplyPayload())));
  assert.doesNotMatch(apply, /agentRoadInspectStage|schemaVersion=2;error=/u);
  for (const stage of ['INPUT', 'NATIVE', 'VALIDATION', 'ADMIN', 'STATE',
    'DIRECTORY_OPEN', 'IDENTITY', 'ACL', 'CHILDREN', 'BOOT', 'STABILITY', 'OUTPUT']) {
    assert.ok(inspect.includes(`$script:agentRoadInspectStage='WINDOWS_${stage}';`));
  }
  assert.ok(inspect.indexOf("agentRoadInspectStage='WINDOWS_NATIVE'") < inspect.indexOf('Add-Type'));
  assert.equal((inspect.match(/schemaVersion=2;error=\$code;stage=\$script:agentRoadInspectStage/gu) ?? []).length, 2);
  assert.match(inspect, /schemaVersion=1;rawClassification=/u);
  assert.doesNotMatch(inspect, /SetFileInformationByHandle|Remove-Item|Restart-Computer/u);
});

test('exec finalization emits a receipt only after guarded cleanup and fits the framed transport', () => {
  const payload = encodeRemotePayload({ schemaVersion: 1, operationId: OPERATION_ID });
  const source = WINDOWS_EXEC_FINALIZE_WRAPPER(payload);
  const read = source.indexOf('ReadAllText($resultPath');
  const remove = source.indexOf('Remove-Item -LiteralPath $candidate');
  const emit = source.indexOf('[Console]::Out.Write($exitText)');
  assert.ok(read >= 0 && remove > read && emit > remove);
  assert.equal((source.match(/Console\]::Out.Write/g) ?? []).length, 1);
  assert.match(source, /catch\{exit 77\}/u);
  assert.match(source, /catch\{exit 78\}/u);
  assert.match(source, /Assert-AgentRoadRestrictedFileAcl \$resultPath/u);
  assert.match(source, /noncanonical result record/u);
  assert.match(source, /unsafe cleanup file/u);
  const invocation = powershellInvocation(WINDOWS_EXEC_FINALIZE_WRAPPER, payload);
  assert.equal(decodePowerShellFrame(invocation.stdin), source);
  assert.ok(Buffer.byteLength(invocation.stdin) <= 65536);
});
