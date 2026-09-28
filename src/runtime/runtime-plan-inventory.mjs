import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { fileURLToPath } from 'node:url';
import { TextDecoder } from 'node:util';
import { isProxy } from 'node:util/types';
import { gzipSync } from 'node:zlib';

import { validateRuntimeInventory } from './runtime-inventory.mjs';

export const RUNTIME_PLAN_INVENTORY_SCRIPT_PATH = fileURLToPath(
  new URL('../../windows/runtime-inventory.ps1', import.meta.url),
);

const INPUT_FIELDS = Object.freeze(['target', 'dependencies']);
const DEPENDENCY_FIELDS = Object.freeze([
  'readInventoryScript',
  'trustedInput',
  'withTrustedSshSession',
  'selectAddress',
  'isTrustedSshSessionLockError',
  'runProcess',
]);
const PROCESS_FIELDS = Object.freeze([
  'command',
  'args',
  'exitCode',
  'signal',
  'stdout',
  'stderr',
]);
const OBSERVATION_FIELDS = Object.freeze(['schemaVersion', 'inventory', 'controllerTrust']);
const TRUST_FIELDS = Object.freeze(['state', 'controllerKeyId']);
const SHA256_PATTERN = /^[A-F0-9]{64}$/u;
const MAX_DECOMPRESSED_BYTES = 128 * 1_024;
const MAX_STDIN_BYTES = 65_536;
const MAX_OUTPUT_BYTES = 65_536;
const WINDOWS_COMMAND_BYTES = 7_000;
const INVENTORY_TIMEOUT_MS = 120_000;
const SSH_LOCK_TIMEOUT_MS = 15 * 60 * 1_000;
const INTRINSIC_APPLY = Reflect.apply;

function runtimeError(code, Type = Error) {
  const error = new Type(code);
  error.code = code;
  return error;
}

function inputError() {
  return runtimeError('RUNTIME_INPUT_INVALID', TypeError);
}

function safeCode(error) {
  if (
    error === null
    || (typeof error !== 'object' && typeof error !== 'function')
    || isProxy(error)
  ) return undefined;
  let descriptor;
  try { descriptor = Object.getOwnPropertyDescriptor(error, 'code'); } catch { return undefined; }
  return descriptor !== undefined
    && Object.hasOwn(descriptor, 'value')
    && typeof descriptor.value === 'string'
    ? descriptor.value
    : undefined;
}

function sessionInvoker(session) {
  if (
    session === null
    || (typeof session !== 'object' && typeof session !== 'function')
    || isProxy(session)
  ) throw runtimeError('RUNTIME_INVENTORY_FAILED');
  let descriptor;
  try { descriptor = Object.getOwnPropertyDescriptor(session, 'invokeSsh'); } catch {
    throw runtimeError('RUNTIME_INVENTORY_FAILED');
  }
  if (
    descriptor === undefined
    || !Object.hasOwn(descriptor, 'value')
    || descriptor.enumerable !== true
    || typeof descriptor.value !== 'function'
    || isProxy(descriptor.value)
  ) throw runtimeError('RUNTIME_INVENTORY_FAILED');
  return descriptor.value;
}

function exactObject(input, fields, failureCode = 'RUNTIME_INPUT_INVALID') {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || (Object.getPrototypeOf(input) !== Object.prototype
      && Object.getPrototypeOf(input) !== null)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) throw runtimeError(failureCode, failureCode === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== fields.length || !fields.every((field) => names.includes(field))) {
    throw runtimeError(failureCode, failureCode === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
  }
  const output = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      throw runtimeError(failureCode, failureCode === 'RUNTIME_INPUT_INVALID' ? TypeError : Error);
    }
    output[field] = descriptor.value;
  }
  return output;
}

function validateInput(input) {
  const value = exactObject(input, INPUT_FIELDS);
  const dependencies = exactObject(value.dependencies, DEPENDENCY_FIELDS);
  for (const field of DEPENDENCY_FIELDS) {
    if (typeof dependencies[field] !== 'function' || isProxy(dependencies[field])) {
      throw inputError();
    }
  }
  return { target: value.target, dependencies: Object.freeze({ ...dependencies }) };
}

function loader(scriptBytes, scriptSha256, compressedSha256, base64Bytes) {
  const source = [
    "$ErrorActionPreference='Stop'",
    "$ProgressPreference='SilentlyContinue'",
    "$VerbosePreference='SilentlyContinue'",
    "$DebugPreference='SilentlyContinue'",
    "$InformationPreference='SilentlyContinue'",
    "$WarningPreference='SilentlyContinue'",
    `$n=${base64Bytes}`,
    `$b=${scriptBytes}`,
    `$e='${scriptSha256}'`,
    `$c='${compressedSha256}'`,
    '$l=65536',
    `$d=${MAX_DECOMPRESSED_BYTES}`,
    '$i=[Console]::OpenStandardInput()',
    "$x=New-Object 'byte[]' $n",
    // The exact byte count and compressed digest frame this payload. Waiting for
    // SSH stdin EOF after the frame can block despite receiving every byte.
    '$o=0',
    'while($o -lt $n){$r=$i.Read($x,$o,$n-$o);if($r -le 0){exit 42};$o+=$r}',
    'if($x.Length -ge $l){[Array]::Clear($x,0,$x.Length);exit 42}',
    "$u=New-Object Text.UTF8Encoding($false,$true)",
    'try{$a=$u.GetString($x);$z=[Convert]::FromBase64String($a)}catch{[Array]::Clear($x,0,$x.Length);exit 42}',
    'if([Convert]::ToBase64String($z) -cne $a -or $z.Length -ge $l){[Array]::Clear($x,0,$x.Length);[Array]::Clear($z,0,$z.Length);exit 42}',
    '[Array]::Clear($x,0,$x.Length)',
    '$h=[Security.Cryptography.SHA256]::Create()',
    "try{$v=[BitConverter]::ToString($h.ComputeHash($z)).Replace('-','')}finally{$h.Dispose()}",
    'if($v -cne $c){[Array]::Clear($z,0,$z.Length);exit 42}',
    '$m=New-Object IO.MemoryStream(,$z)',
    '$g=New-Object IO.Compression.GZipStream($m,[IO.Compression.CompressionMode]::Decompress)',
    '$q=New-Object IO.MemoryStream',
    "$k=New-Object 'byte[]' 8192",
    'try{while(($r=$g.Read($k,0,$k.Length)) -gt 0){if($q.Length+$r -gt $d){exit 42};$q.Write($k,0,$r)}}finally{$g.Dispose();$m.Dispose();[Array]::Clear($k,0,$k.Length);[Array]::Clear($z,0,$z.Length)}',
    '$s=$q.ToArray();$q.Dispose()',
    'if($s.Length -ne $b){[Array]::Clear($s,0,$s.Length);exit 42}',
    '$h=[Security.Cryptography.SHA256]::Create()',
    "try{$v=[BitConverter]::ToString($h.ComputeHash($s)).Replace('-','')}finally{$h.Dispose()}",
    'if($v -cne $e){[Array]::Clear($s,0,$s.Length);exit 42}',
    'try{$t=$u.GetString($s);[Array]::Clear($s,0,$s.Length);&([ScriptBlock]::Create($t)) -PlanningObservation}catch{[Array]::Clear($s,0,$s.Length);exit 42}',
  ].join(';');
  const encoded = Buffer.from(source, 'utf16le').toString('base64');
  const argv = Object.freeze([
    'powershell.exe',
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-EncodedCommand',
    encoded,
  ]);
  if (Buffer.byteLength(argv.join(' '), 'utf8') >= WINDOWS_COMMAND_BYTES) {
    throw runtimeError('RUNTIME_INTERNAL_ERROR');
  }
  return argv;
}

function processSnapshot(input) {
  const value = exactObject(input, PROCESS_FIELDS, 'RUNTIME_INVENTORY_FAILED');
  if (
    !Number.isSafeInteger(value.exitCode)
    || value.exitCode < 0
    || value.exitCode > 255
    || value.signal !== null
    || typeof value.stdout !== 'string'
    || typeof value.stderr !== 'string'
    || Buffer.byteLength(value.stdout, 'utf8') > MAX_OUTPUT_BYTES
    || Buffer.byteLength(value.stderr, 'utf8') > MAX_OUTPUT_BYTES - Buffer.byteLength(value.stdout, 'utf8')
  ) throw runtimeError('RUNTIME_INVENTORY_FAILED');
  return value;
}

function controllerTrust(input) {
  const value = exactObject(input, TRUST_FIELDS, 'RUNTIME_INVENTORY_FAILED');
  if (
    !['unpinned', 'pinned'].includes(value.state)
    || (value.state === 'unpinned' && value.controllerKeyId !== null)
    || (value.state === 'pinned' && (
      typeof value.controllerKeyId !== 'string' || !SHA256_PATTERN.test(value.controllerKeyId)
    ))
  ) throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
  return Object.freeze({ state: value.state, controllerKeyId: value.controllerKeyId });
}

function parseObservation(input) {
  const process = processSnapshot(input);
  if (process.exitCode === 41 && process.stdout === '' && process.stderr === '') {
    throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
  }
  if (process.exitCode !== 0 || process.stderr !== '') {
    throw runtimeError('RUNTIME_INVENTORY_FAILED');
  }
  if (
    Buffer.byteLength(process.stdout, 'utf8') < 1
    || Buffer.byteLength(process.stdout, 'utf8') > MAX_OUTPUT_BYTES
  ) throw runtimeError('RUNTIME_INVENTORY_FAILED');
  let parsed;
  try { parsed = JSON.parse(process.stdout); } catch { throw runtimeError('RUNTIME_INVENTORY_FAILED'); }
  const value = exactObject(parsed, OBSERVATION_FIELDS, 'RUNTIME_INVENTORY_FAILED');
  if (value.schemaVersion !== 1) throw runtimeError('RUNTIME_INVENTORY_FAILED');
  let inventory;
  try { inventory = validateRuntimeInventory(value.inventory); } catch {
    throw runtimeError('RUNTIME_INVENTORY_FAILED');
  }
  const trust = controllerTrust(value.controllerTrust);
  const canonical = { schemaVersion: 1, inventory, controllerTrust: trust };
  if (JSON.stringify(canonical) !== process.stdout) throw runtimeError('RUNTIME_INVENTORY_FAILED');
  return Object.freeze(canonical);
}

async function readSource(dependencies) {
  let input;
  try { input = await dependencies.readInventoryScript(); } catch {
    throw runtimeError('RUNTIME_INVENTORY_FAILED');
  }
  if (
    !Buffer.isBuffer(input)
    || isProxy(input)
    || Object.getPrototypeOf(input) !== Buffer.prototype
    || input.length < 1
    || input.length > MAX_DECOMPRESSED_BYTES
  ) throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
  const source = Buffer.from(input);
  try { new TextDecoder('utf-8', { fatal: true }).decode(source); } catch {
    throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
  }
  const scriptSha256 = createHash('sha256').update(source).digest('hex').toUpperCase();
  const compressed = gzipSync(source, { level: 9, mtime: 0 });
  const compressedSha256 = createHash('sha256').update(compressed).digest('hex').toUpperCase();
  const stdinText = compressed.toString('base64');
  compressed.fill(0);
  if (
    Buffer.byteLength(stdinText, 'ascii') >= MAX_STDIN_BYTES
    || Buffer.from(stdinText, 'base64').toString('base64') !== stdinText
  ) throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
  return Object.freeze({
    scriptSha256,
    scriptBytes: source.length,
    stdinText,
    argv: loader(
      source.length,
      scriptSha256,
      compressedSha256,
      Buffer.byteLength(stdinText, 'ascii'),
    ),
  });
}

export async function readRuntimePlanInventoryPair(input) {
  const config = validateInput(input);
  const source = await readSource(config.dependencies);
  let trust;
  try {
    trust = config.dependencies.trustedInput(config.target, config.dependencies.runProcess);
  } catch {
    throw runtimeError('RUNTIME_INVENTORY_FAILED');
  }
  try {
    return await config.dependencies.withTrustedSshSession(trust, async (session) => {
      const invokeSsh = sessionInvoker(session);
      const address = await config.dependencies.selectAddress(session);
      if (typeof address !== 'string' || isIP(address) === 0) {
        throw runtimeError('RUNTIME_INVENTORY_FAILED');
      }
      const options = Object.freeze({
        timeoutMs: INVENTORY_TIMEOUT_MS,
        maxOutputBytes: MAX_OUTPUT_BYTES,
        stdinText: source.stdinText,
      });
      const first = parseObservation(await INTRINSIC_APPLY(
        invokeSsh,
        session,
        [address, source.argv, options],
      ));
      const second = parseObservation(await INTRINSIC_APPLY(
        invokeSsh,
        session,
        [address, source.argv, options],
      ));
      return Object.freeze({
        schemaVersion: 1,
        firstInventory: first.inventory,
        firstControllerTrust: first.controllerTrust,
        secondInventory: second.inventory,
        secondControllerTrust: second.controllerTrust,
        scriptSha256: source.scriptSha256,
      });
    }, { lockTimeoutMs: SSH_LOCK_TIMEOUT_MS });
  } catch (error) {
    let locked = false;
    try { locked = config.dependencies.isTrustedSshSessionLockError(error) === true; } catch {}
    if (locked) throw runtimeError('RUNTIME_ALREADY_RUNNING');
    if (safeCode(error) === 'RUNTIME_STATE_UNSUPPORTED') {
      throw runtimeError('RUNTIME_STATE_UNSUPPORTED');
    }
    throw runtimeError('RUNTIME_INVENTORY_FAILED');
  }
}
