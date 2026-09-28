import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { isProxy } from 'node:util/types';
import { WINDOWS_INSPECT_STAGES } from '../runtime/recovery-inspect-stage.mjs';

const MAX_PAYLOAD_BYTES = 16 * 1024;
const MAX_PAYLOAD_DEPTH = 32;
const MAX_PAYLOAD_ITEMS = 1024;
const MAX_EXEC_SCRIPT_BYTES = 2 * 1024 * 1024 + 2;
const MAX_TRANSFER_BYTES = 256 * 1024 * 1024;
const MAX_PROVISION_COMPONENTS = 32;
const MAX_RUNTIME_VERSION_LENGTH = 64;
const MAX_WINDOWS_PATH_BYTES = 4096;
const MAX_POWERSHELL_STDIN_BYTES = 64 * 1024;
const MAX_POWERSHELL_SOURCE_BYTES = 32 * 1024;
const POWERSHELL_FRAME_CHUNK_CHARS = 2048;
const POWERSHELL_FRAME_MAGIC = 'AGENT_ROAD_STDIN_V1';
const OPERATION_ID_PATTERN = /^[a-f0-9]{32}$/u;
const SHA256_PATTERN = /^[A-F0-9]{64}$/u;
const RUNTIME_ARTIFACT_ID_PATTERN = /^[a-z][a-z0-9-]{0,63}$/u;
const RUNTIME_VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const PARENT_IDENTITY_PATTERN = /^[A-F0-9]{8}:[A-F0-9]{8}:[A-F0-9]{8}$/u;
const RECOVERY_TICKET_ID_PATTERN = /^rct_[a-f0-9]{64}$/u;
const RECOVERY_TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const RECOVERY_BOOT_PROVIDER_GUID = '{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}';
const RECOVERY_ACL_DIGEST = 'DD88275C41BC223A8C77B8E2CA108226DDDE5F39D2B044AD84AEFB31B9643C44';
const PROBE_OUTPUT = 'AGENT_ROAD_ADMINISTRATOR_OK';
const PROBE_OPERATION_ID = '0'.repeat(32);
const SESSION_FIELDS = new Set([
  'addresses',
  'invokeSsh',
  'invokeScp',
  'invokeCleanup',
  'remoteSpec',
]);
const PROCESS_RESULT_FIELDS = new Set([
  'command',
  'args',
  'exitCode',
  'signal',
  'stdout',
  'stderr',
]);
const TRUSTED_WRAPPERS = new WeakSet();
const POWERSHELL_STDIN_BOOTSTRAP =
  [
    "$ProgressPreference='SilentlyContinue'",
    "$ErrorActionPreference='Stop'",
    // ConsoleStream can block on Windows OpenSSH pipes. Use the native stdin
    // handle without taking ownership; keep the existing frame parser unchanged.
    'try{Add-Type -Namespace AgentRoad -Name StandardInput -MemberDefinition \'[System.Runtime.InteropServices.DllImport("kernel32.dll")]public static extern System.IntPtr GetStdHandle(int n);\'',
    '$raw=[AgentRoad.StandardInput]::GetStdHandle(-10);if($raw -eq [IntPtr]::Zero -or $raw -eq [IntPtr](-1)){throw 0}',
    '$handle=New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($raw,$false)',
    '$stream=New-Object IO.FileStream($handle,[IO.FileAccess]::Read)',
    '$r=New-Object IO.StreamReader($stream,[Text.Encoding]::ASCII,$false)',
    `if($r.ReadLine() -cne '${POWERSHELL_FRAME_MAGIC}'){throw 0}`,
    "$x=$r.ReadLine();if($null -eq $x -or $x -cnotmatch '^L:([1-9][0-9]{0,4})$'){throw 0};$n=[int]$Matches[1]",
    `$x=$r.ReadLine();if($null -eq $x -or $x -cnotmatch '^H:([A-F0-9]{64})$'){throw 0};$eh=$Matches[1]`,
    "$x=$r.ReadLine();if($null -eq $x -or $x -cnotmatch '^C:([1-9][0-9]{0,2})$'){throw 0};$c=[int]$Matches[1]",
    `$bl=[int](4*[Math]::Ceiling($n/3));$ec=[int][Math]::Ceiling($bl/${POWERSHELL_FRAME_CHUNK_CHARS});if($n -gt ${MAX_POWERSHELL_SOURCE_BYTES} -or $c -ne $ec){throw 0}`,
    '$a=New-Object System.Text.StringBuilder',
    `for($i=0;$i -lt $c;$i++){$x=$r.ReadLine();$el=if($i -lt ($c-1)){${POWERSHELL_FRAME_CHUNK_CHARS}}else{$bl-(${POWERSHELL_FRAME_CHUNK_CHARS}*$i)};if($null -eq $x -or $x.Length -ne $el -or $x -cnotmatch '^[A-Za-z0-9+/]+={0,2}$' -or ($i -lt ($c-1) -and $x.Contains('='))){throw 0};$null=$a.Append($x)}`,
    "if($r.ReadLine() -cne 'END'){throw 0}",
    '$b64=$a.ToString();$bytes=[Convert]::FromBase64String($b64)',
    'if($bytes.Length -ne $n -or [Convert]::ToBase64String($bytes) -cne $b64){throw 0}',
    'foreach($v in $bytes){if($v -eq 0 -or $v -gt 127){throw 0}}',
    '$sha=[Security.Cryptography.SHA256]::Create();try{$ah=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace(\'-\',\'\')}finally{$sha.Dispose()}',
    'if($ah -cne $eh){throw 0};$s=[Text.Encoding]::ASCII.GetString($bytes)',
    '}catch{[Environment]::Exit(87)}',
    '&([ScriptBlock]::Create($s))',
  ].join(';');
const POWERSHELL_STDIN_BOOTSTRAP_BASE64 = Buffer
  .from(POWERSHELL_STDIN_BOOTSTRAP, 'utf16le')
  .toString('base64');
const POWERSHELL_STDIN_ARGV = Object.freeze([
  'powershell.exe',
  '-NoLogo',
  '-NoProfile',
  '-NonInteractive',
  '-ExecutionPolicy',
  'Bypass',
  '-EncodedCommand',
  POWERSHELL_STDIN_BOOTSTRAP_BASE64,
]);

function remoteError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function failInput() {
  throw remoteError('REMOTE_INPUT_INVALID');
}

function canonicalAddress(value) {
  if (typeof value !== 'string' || value !== value.trim()) return false;
  const family = isIP(value);
  if (family === 4) return true;
  return family === 6 && new URL(`http://[${value}]/`).hostname === `[${value}]`;
}

function consumeJsonStringBytes(value, budget, { key = false } = {}) {
  if (key && value.length === 0) failInput();
  budget.consume(2);
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (key && code === 0) failInput();
    if (code === 0x22 || code === 0x5c || [0x08, 0x09, 0x0a, 0x0c, 0x0d].includes(code)) {
      budget.consume(2);
    } else if (code <= 0x1f) {
      budget.consume(6);
    } else if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        budget.consume(4);
        index += 1;
      } else {
        budget.consume(6);
      }
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      budget.consume(6);
    } else if (code <= 0x7f) {
      budget.consume(1);
    } else if (code <= 0x7ff) {
      budget.consume(2);
    } else {
      budget.consume(3);
    }
  }
}

function snapshotPlainData(input) {
  const budget = {
    bytes: 0,
    items: 0,
    consume(bytes) {
      if (bytes > MAX_PAYLOAD_BYTES - this.bytes) failInput();
      this.bytes += bytes;
    },
    consumeItem() {
      this.items += 1;
      if (this.items > MAX_PAYLOAD_ITEMS) failInput();
    },
  };
  const ancestors = new WeakSet();

  function snapshot(value, depth) {
    if (depth > MAX_PAYLOAD_DEPTH) failInput();
    budget.consumeItem();
    if (value === null) {
      budget.consume(4);
      return value;
    }
    if (typeof value === 'boolean') {
      budget.consume(value ? 4 : 5);
      return value;
    }
    if (typeof value === 'string') {
      consumeJsonStringBytes(value, budget);
      return value;
    }
    if (typeof value === 'number') {
      if (!Number.isFinite(value) || Object.is(value, -0)) failInput();
      budget.consume(String(value).length);
      return value;
    }
    if (typeof value !== 'object' || isProxy(value) || ancestors.has(value)) failInput();

    const array = Array.isArray(value);
    const prototype = Object.getPrototypeOf(value);
    if (
      (array && prototype !== Array.prototype)
      || (!array && prototype !== Object.prototype && prototype !== null)
    ) failInput();

    ancestors.add(value);
    try {
      if (array) {
        const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
        if (
          !lengthDescriptor
          || !Object.hasOwn(lengthDescriptor, 'value')
          || !Number.isSafeInteger(lengthDescriptor.value)
          || lengthDescriptor.value < 0
          || lengthDescriptor.value > MAX_PAYLOAD_ITEMS - budget.items
        ) failInput();
        budget.consume(1);
        const result = [];
        let index = 0;
        for (const property in value) {
          if (!Object.hasOwn(value, property) || property !== String(index)) failInput();
          if (index !== 0) budget.consume(1);
          const descriptor = Object.getOwnPropertyDescriptor(value, property);
          if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) failInput();
          result.push(snapshot(descriptor.value, depth + 1));
          index += 1;
        }
        if (index !== lengthDescriptor.value) failInput();
        budget.consume(1);
        return result;
      }

      // Payload semantics deliberately include only enumerable string-keyed JSON fields.
      // JavaScript has no lazy own-key iterator for millions of hidden string
      // or symbol properties; hidden fields cannot affect the snapshot or exact schemas.
      budget.consume(1);
      const entries = [];
      for (const key in value) {
        if (!Object.hasOwn(value, key)) failInput();
        if (entries.length !== 0) budget.consume(1);
        consumeJsonStringBytes(key, budget, { key: true });
        budget.consume(1);
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (
          !descriptor
          || !Object.hasOwn(descriptor, 'value')
          || !descriptor.enumerable
        ) failInput();
        entries.push([key, snapshot(descriptor.value, depth + 1)]);
      }
      budget.consume(1);
      entries.sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
      const result = Object.create(null);
      for (const [key, child] of entries) result[key] = child;
      return result;
    } finally {
      ancestors.delete(value);
    }
  }

  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
  ) failInput();
  return snapshot(input, 0);
}

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => (
    `${JSON.stringify(key)}:${canonicalJson(value[key])}`
  )).join(',')}}`;
}

export function encodeRemotePayload(value) {
  const json = canonicalJson(snapshotPlainData(value));
  return Buffer.from(json, 'utf8').toString('base64');
}

function decodeCanonicalPayload(payload) {
  if (
    typeof payload !== 'string'
    || payload.length === 0
    || payload.length > Math.ceil(MAX_PAYLOAD_BYTES / 3) * 4
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(payload)
  ) failInput();
  let bytes;
  let json;
  let parsed;
  try {
    bytes = Buffer.from(payload, 'base64');
    if (bytes.length > MAX_PAYLOAD_BYTES || bytes.toString('base64') !== payload) failInput();
    json = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    parsed = JSON.parse(json);
  } catch (error) {
    if (error?.code === 'REMOTE_INPUT_INVALID') throw error;
    failInput();
  }
  const snapshot = snapshotPlainData(parsed);
  if (canonicalJson(snapshot) !== json) failInput();
  return snapshot;
}

function validateProbePayload(payload) {
  const value = decodeCanonicalPayload(payload);
  if (
    Object.keys(value).length !== 2
    || !Object.hasOwn(value, 'schemaVersion')
    || !Object.hasOwn(value, 'operationId')
    || value.schemaVersion !== 1
    || typeof value.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(value.operationId)
  ) failInput();
  return value;
}

function validateOperationPayload(payload) {
  const value = decodeCanonicalPayload(payload);
  if (
    Object.keys(value).length !== 2
    || !Object.hasOwn(value, 'schemaVersion')
    || !Object.hasOwn(value, 'operationId')
    || value.schemaVersion !== 1
    || typeof value.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(value.operationId)
  ) failInput();
  return value;
}

function validateExecVerifyPayload(payload) {
  const value = decodeCanonicalPayload(payload);
  if (
    Object.keys(value).length !== 4
    || !Object.hasOwn(value, 'schemaVersion')
    || !Object.hasOwn(value, 'operationId')
    || !Object.hasOwn(value, 'expectedBytes')
    || !Object.hasOwn(value, 'expectedSha256')
    || value.schemaVersion !== 1
    || typeof value.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(value.operationId)
    || !Number.isSafeInteger(value.expectedBytes)
    || value.expectedBytes < 2
    || value.expectedBytes > MAX_EXEC_SCRIPT_BYTES
    || typeof value.expectedSha256 !== 'string'
    || !SHA256_PATTERN.test(value.expectedSha256)
  ) failInput();
  return value;
}

function validateRuntimeProvisionInvokePayload(payload) {
  const value = decodeCanonicalPayload(payload);
  if (
    Object.keys(value).length !== 6
    || !Object.hasOwn(value, 'schemaVersion')
    || !Object.hasOwn(value, 'operationId')
    || !Object.hasOwn(value, 'expectedBytes')
    || !Object.hasOwn(value, 'expectedSha256')
    || !Object.hasOwn(value, 'runtimeOperationId')
    || !Object.hasOwn(value, 'manifestDigest')
    || value.schemaVersion !== 1
    || typeof value.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(value.operationId)
    || !Number.isSafeInteger(value.expectedBytes)
    || value.expectedBytes < 2
    || value.expectedBytes > MAX_EXEC_SCRIPT_BYTES
    || typeof value.expectedSha256 !== 'string'
    || !SHA256_PATTERN.test(value.expectedSha256)
    || typeof value.runtimeOperationId !== 'string'
    || !OPERATION_ID_PATTERN.test(value.runtimeOperationId)
    || typeof value.manifestDigest !== 'string'
    || !SHA256_PATTERN.test(value.manifestDigest)
  ) failInput();
  return value;
}

function canonicalWindowsFilePath(value) {
  if (
    typeof value !== 'string'
    || value.length < 4
    || Buffer.byteLength(value) > MAX_WINDOWS_PATH_BYTES
    || !/^[A-Za-z]:\\/u.test(value)
    || value.includes('/')
    || /[\x00-\x1f\x7f*?"<>|]/u.test(value)
    || value.slice(2).includes(':')
  ) return false;
  const components = value.slice(3).split('\\');
  if (
    components.length === 0
    || components.some((component) => (
      component.length === 0
      || component === '.'
      || component === '..'
      || /[. ]$/u.test(component)
      || /^(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)/iu.test(component)
    ))
  ) return false;
  const folded = value.toLowerCase();
  return folded !== 'c:\\programdata\\agentroad'
    && !folded.startsWith('c:\\programdata\\agentroad\\');
}

function validatePutPayload(payload, phase = 'base') {
  const value = decodeCanonicalPayload(payload);
  const expectedFields = phase === 'publish' ? 7 : phase === 'cleanup' ? 9 : 6;
  if (
    Object.keys(value).length !== expectedFields
    || !Object.hasOwn(value, 'schemaVersion')
    || !Object.hasOwn(value, 'operationId')
    || !Object.hasOwn(value, 'destinationPath')
    || !Object.hasOwn(value, 'overwrite')
    || !Object.hasOwn(value, 'expectedBytes')
    || !Object.hasOwn(value, 'expectedSha256')
    || value.schemaVersion !== 1
    || typeof value.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(value.operationId)
    || !canonicalWindowsFilePath(value.destinationPath)
    || typeof value.overwrite !== 'boolean'
    || !Number.isSafeInteger(value.expectedBytes)
    || value.expectedBytes < 0
    || value.expectedBytes > MAX_TRANSFER_BYTES
    || typeof value.expectedSha256 !== 'string'
    || !SHA256_PATTERN.test(value.expectedSha256)
    || (phase === 'publish' && (
      !Object.hasOwn(value, 'expectedParentIdentity')
      || typeof value.expectedParentIdentity !== 'string'
      || !PARENT_IDENTITY_PATTERN.test(value.expectedParentIdentity)
    ))
    || (phase === 'cleanup' && (
      !Object.hasOwn(value, 'expectedParentIdentity')
      || !Object.hasOwn(value, 'stagingOwned')
      || !Object.hasOwn(value, 'tempOwned')
      || typeof value.stagingOwned !== 'boolean'
      || typeof value.tempOwned !== 'boolean'
      || (value.tempOwned
        ? typeof value.expectedParentIdentity !== 'string'
          || !PARENT_IDENTITY_PATTERN.test(value.expectedParentIdentity)
        : value.expectedParentIdentity !== null)
    ))
  ) failInput();
  return value;
}

function validateGetPayload(payload, phase = 'prepare') {
  const value = decodeCanonicalPayload(payload);
  const cleanup = phase === 'cleanup';
  if (
    Object.keys(value).length !== (cleanup ? 6 : 3)
    || !Object.hasOwn(value, 'schemaVersion')
    || !Object.hasOwn(value, 'operationId')
    || !Object.hasOwn(value, 'sourcePath')
    || value.schemaVersion !== 1
    || typeof value.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(value.operationId)
    || !canonicalWindowsFilePath(value.sourcePath)
    || (cleanup && (
      !Object.hasOwn(value, 'expectedBytes')
      || !Object.hasOwn(value, 'expectedSha256')
      || !Object.hasOwn(value, 'snapshotOwned')
      || typeof value.snapshotOwned !== 'boolean'
      || (value.snapshotOwned
        ? !Number.isSafeInteger(value.expectedBytes)
          || value.expectedBytes < 0
          || value.expectedBytes > MAX_TRANSFER_BYTES
          || typeof value.expectedSha256 !== 'string'
          || !SHA256_PATTERN.test(value.expectedSha256)
        : value.expectedBytes !== null || value.expectedSha256 !== null)
    ))
  ) failInput();
  return value;
}

function validateProvisionBase(value, expectedFields) {
  if (
    Object.keys(value).length !== expectedFields
    || !Object.hasOwn(value, 'schemaVersion')
    || !Object.hasOwn(value, 'operationId')
    || !Object.hasOwn(value, 'manifestDigest')
    || value.schemaVersion !== 1
    || typeof value.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(value.operationId)
    || typeof value.manifestDigest !== 'string'
    || !SHA256_PATTERN.test(value.manifestDigest)
  ) failInput();
}

function validateProvisionComponent(input) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || Object.keys(input).length !== 4
    || !Object.hasOwn(input, 'artifactId')
    || !Object.hasOwn(input, 'version')
    || !Object.hasOwn(input, 'expectedBytes')
    || !Object.hasOwn(input, 'expectedSha256')
    || typeof input.artifactId !== 'string'
    || !RUNTIME_ARTIFACT_ID_PATTERN.test(input.artifactId)
    || typeof input.version !== 'string'
    || input.version.length > MAX_RUNTIME_VERSION_LENGTH
    || !RUNTIME_VERSION_PATTERN.test(input.version)
    || !Number.isSafeInteger(input.expectedBytes)
    || input.expectedBytes < 1
    || input.expectedBytes > MAX_TRANSFER_BYTES
    || typeof input.expectedSha256 !== 'string'
    || !SHA256_PATTERN.test(input.expectedSha256)
  ) failInput();
  return input;
}

function validateProvisionCapsule(input) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || Object.keys(input).length !== 2
    || !Object.hasOwn(input, 'expectedBytes')
    || !Object.hasOwn(input, 'expectedSha256')
    || !Number.isSafeInteger(input.expectedBytes)
    || input.expectedBytes < 1
    || input.expectedBytes > MAX_TRANSFER_BYTES
    || typeof input.expectedSha256 !== 'string'
    || !SHA256_PATTERN.test(input.expectedSha256)
  ) failInput();
  return input;
}

function validateProvisionPayload(payload, phase) {
  const value = decodeCanonicalPayload(payload);
  if (phase === 'init') {
    validateProvisionBase(value, 3);
    return value;
  }
  if (phase === 'inspect') {
    validateProvisionBase(value, 5);
    if (
      !Object.hasOwn(value, 'components')
      || !Object.hasOwn(value, 'capsule')
      || !Array.isArray(value.components)
      || value.components.length < 1
      || value.components.length > MAX_PROVISION_COMPONENTS
    ) failInput();
    let previous = null;
    for (const component of value.components) {
      validateProvisionComponent(component);
      if (previous !== null && component.artifactId <= previous) failInput();
      previous = component.artifactId;
    }
    validateProvisionCapsule(value.capsule);
    return value;
  }
  validateProvisionBase(value, 8);
  if (
    !Object.hasOwn(value, 'entryType')
    || !Object.hasOwn(value, 'artifactId')
    || !Object.hasOwn(value, 'version')
    || !Object.hasOwn(value, 'expectedBytes')
    || !Object.hasOwn(value, 'expectedSha256')
    || !['artifact', 'capsule'].includes(value.entryType)
    || !Number.isSafeInteger(value.expectedBytes)
    || value.expectedBytes < 1
    || value.expectedBytes > MAX_TRANSFER_BYTES
    || typeof value.expectedSha256 !== 'string'
    || !SHA256_PATTERN.test(value.expectedSha256)
    || (value.entryType === 'artifact' && (
      typeof value.artifactId !== 'string'
      || !RUNTIME_ARTIFACT_ID_PATTERN.test(value.artifactId)
      || typeof value.version !== 'string'
      || value.version.length > MAX_RUNTIME_VERSION_LENGTH
      || !RUNTIME_VERSION_PATTERN.test(value.version)
    ))
    || (value.entryType === 'capsule' && (
      value.artifactId !== null || value.version !== null
    ))
  ) failInput();
  return value;
}

function operationPayloadPrelude(payload, expectedProperties) {
  return [
    "$ErrorActionPreference='Stop'",
    "$ProgressPreference='SilentlyContinue'",
    'Set-StrictMode -Version 2.0',
    `$payloadJson=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}'))`,
    '$payload=$payloadJson|ConvertFrom-Json',
    '$propertyNames=@($payload.PSObject.Properties.Name)',
    `if(@($payload.PSObject.Properties).Count -ne ${expectedProperties} -or $propertyNames -cnotcontains 'schemaVersion' -or $propertyNames -cnotcontains 'operationId' -or $payload.schemaVersion -isnot [int] -or $payload.schemaVersion -ne 1 -or $payload.operationId -isnot [string] -or $payload.operationId -cnotmatch '^[a-f0-9]{32}$'){throw 'invalid exec payload'}`,
    "$root='C:\\ProgramData\\AgentRoad\\tasks'",
    "$path=[IO.Path]::Combine($root,($payload.operationId+'.ps1'))",
    "$resultPath=[IO.Path]::Combine($root,($payload.operationId+'.result.json'))",
    "$resultTempPath=[IO.Path]::Combine($root,($payload.operationId+'.result.json.tmp'))",
    "foreach($candidate in @($root,$path,$resultPath,$resultTempPath)){if([IO.Path]::GetFullPath($candidate) -cne $candidate){throw 'invalid task path'}}",
    "foreach($candidate in @($path,$resultPath,$resultTempPath)){if([IO.Path]::GetDirectoryName($candidate) -cne $root){throw 'invalid task path'}}",
  ];
}

function administratorGuard() {
  return [
    '$identity=[Security.Principal.WindowsIdentity]::GetCurrent()',
    '$principal=New-Object Security.Principal.WindowsPrincipal($identity)',
    "if(($identity.Name -split '\\\\')[-1] -cne 'AgentRoad' -or -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'administrator validation failed'}",
  ];
}

function directoryGuard(pathExpression) {
  return [
    `if(-not (Test-Path -LiteralPath ${pathExpression} -PathType Container)){throw 'task directory missing'}`,
    `$directoryItem=Get-Item -LiteralPath ${pathExpression} -Force`,
    "if(($directoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'task directory reparse point'}",
  ];
}

function restrictedAclFunctions() {
  return [
    "function Assert-AgentRoadRestrictedDirectoryAcl([string]$candidate){$candidateAcl=[IO.Directory]::GetAccessControl($candidate);$candidateRules=@($candidateAcl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]));$candidateOwner=$candidateAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value;$expectedInheritance=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit;$expectedPropagation=[Security.AccessControl.PropagationFlags]::None;$expectedAllow=[Security.AccessControl.AccessControlType]::Allow;$expectedRights=[Security.AccessControl.FileSystemRights]::FullControl;if(-not $candidateAcl.AreAccessRulesProtected -or -not $candidateAcl.AreAccessRulesCanonical -or $candidateOwner -cne 'S-1-5-32-544' -or $candidateRules.Count -ne 2){throw 'unsafe directory acl'};$observed=@();foreach($rule in $candidateRules){$sid=[string]$rule.IdentityReference.Value;if($sid -cnotin @('S-1-5-18','S-1-5-32-544') -or $rule.IsInherited -or $rule.AccessControlType -ne $expectedAllow -or $rule.FileSystemRights -ne $expectedRights -or $rule.InheritanceFlags -ne $expectedInheritance -or $rule.PropagationFlags -ne $expectedPropagation){throw 'unsafe directory acl'};$observed+=$sid};foreach($sid in @('S-1-5-18','S-1-5-32-544')){if($observed -cnotcontains $sid){throw 'unsafe directory acl'}}}",
    "function New-AgentRoadRestrictedDirectorySecurity(){$administrators=New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544';$system=New-Object Security.Principal.SecurityIdentifier 'S-1-5-18';$owner=$administrators.Translate([Security.Principal.NTAccount]);$acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($owner);$inheritance=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit;$propagation=[Security.AccessControl.PropagationFlags]::None;$allow=[Security.AccessControl.AccessControlType]::Allow;$rights=[Security.AccessControl.FileSystemRights]::FullControl;$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($administrators,$rights,$inheritance,$propagation,$allow)));$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system,$rights,$inheritance,$propagation,$allow)));return $acl}",
    "function Set-AgentRoadRestrictedDirectoryAcl([string]$candidate){$acl=New-AgentRoadRestrictedDirectorySecurity;[IO.Directory]::SetAccessControl($candidate,$acl);Assert-AgentRoadRestrictedDirectoryAcl $candidate}",
    "function Assert-AgentRoadRestrictedFileAcl([string]$candidate){$candidateAcl=[IO.File]::GetAccessControl($candidate);$candidateRules=@($candidateAcl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]));$candidateOwner=$candidateAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value;$expectedInheritance=[Security.AccessControl.InheritanceFlags]::None;$expectedPropagation=[Security.AccessControl.PropagationFlags]::None;$expectedAllow=[Security.AccessControl.AccessControlType]::Allow;$expectedRights=[Security.AccessControl.FileSystemRights]::FullControl;if(-not $candidateAcl.AreAccessRulesProtected -or -not $candidateAcl.AreAccessRulesCanonical -or $candidateOwner -cne 'S-1-5-32-544' -or $candidateRules.Count -ne 2){throw 'unsafe file acl'};$observed=@();foreach($rule in $candidateRules){$sid=[string]$rule.IdentityReference.Value;if($sid -cnotin @('S-1-5-18','S-1-5-32-544') -or $rule.IsInherited -or $rule.AccessControlType -ne $expectedAllow -or $rule.FileSystemRights -ne $expectedRights -or $rule.InheritanceFlags -ne $expectedInheritance -or $rule.PropagationFlags -ne $expectedPropagation){throw 'unsafe file acl'};$observed+=$sid};foreach($sid in @('S-1-5-18','S-1-5-32-544')){if($observed -cnotcontains $sid){throw 'unsafe file acl'}}}",
    "function New-AgentRoadRestrictedFileSecurity(){$administrators=New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544';$system=New-Object Security.Principal.SecurityIdentifier 'S-1-5-18';$owner=$administrators.Translate([Security.Principal.NTAccount]);$acl=New-Object Security.AccessControl.FileSecurity;$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($owner);$inheritance=[Security.AccessControl.InheritanceFlags]::None;$propagation=[Security.AccessControl.PropagationFlags]::None;$allow=[Security.AccessControl.AccessControlType]::Allow;$rights=[Security.AccessControl.FileSystemRights]::FullControl;$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($administrators,$rights,$inheritance,$propagation,$allow)));$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system,$rights,$inheritance,$propagation,$allow)));return $acl}",
    "function Set-AgentRoadRestrictedFileAcl([string]$candidate){$acl=New-AgentRoadRestrictedFileSecurity;[IO.File]::SetAccessControl($candidate,$acl);Assert-AgentRoadRestrictedFileAcl $candidate}",
  ];
}

function stagedFileGuard(failure, pathExpression = '$path', itemVariable = '$fileItem') {
  return [
    `if(-not (Test-Path -LiteralPath ${pathExpression} -PathType Leaf)){${failure}}`,
    `${itemVariable}=Get-Item -LiteralPath ${pathExpression} -Force`,
    `if(${itemVariable}.PSIsContainer -or (${itemVariable}.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){${failure}}`,
  ];
}

function execPreflightWrapper(payload) {
  validateOperationPayload(payload);
  return [
    ...operationPayloadPrelude(payload, 2),
    ...administratorGuard(),
    "$parent='C:\\ProgramData\\AgentRoad'",
    ...restrictedAclFunctions(),
    ...directoryGuard("'C:\\ProgramData'"),
    ...directoryGuard('$parent'),
    'Assert-AgentRoadRestrictedDirectoryAcl $parent',
    "$rootCreated=$false;if(Test-Path -LiteralPath $root){$existing=Get-Item -LiteralPath $root -Force;if(-not $existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'unsafe task root'}}else{[IO.Directory]::CreateDirectory($root,(New-AgentRoadRestrictedDirectorySecurity))|Out-Null;$rootCreated=$true}",
    ...directoryGuard('$root'),
    'Assert-AgentRoadRestrictedDirectoryAcl $root',
    "foreach($candidate in @($path,$resultPath,$resultTempPath)){if(Test-Path -LiteralPath $candidate){throw 'task path already exists'}}",
    "[Console]::Out.Write('AGENT_ROAD_EXEC_PREFLIGHT_OK')",
  ].join(';');
}

function execVerifyWrapper(payload) {
  validateExecVerifyPayload(payload);
  return [
    ...operationPayloadPrelude(payload, 4),
    "if($propertyNames -cnotcontains 'expectedBytes' -or $propertyNames -cnotcontains 'expectedSha256' -or $payload.expectedBytes -isnot [int] -or $payload.expectedBytes -lt 2 -or $payload.expectedBytes -gt 2097154 -or $payload.expectedSha256 -isnot [string] -or $payload.expectedSha256 -cnotmatch '^[A-F0-9]{64}$'){throw 'invalid verify payload'}",
    ...administratorGuard(),
    "$parent='C:\\ProgramData\\AgentRoad'",
    ...restrictedAclFunctions(),
    ...directoryGuard('$parent'),
    ...directoryGuard('$root'),
    'Assert-AgentRoadRestrictedDirectoryAcl $parent',
    'Assert-AgentRoadRestrictedDirectoryAcl $root',
    ...stagedFileGuard('exit 73'),
    'if($fileItem.Length -ne $payload.expectedBytes){exit 73}',
    '$actualHash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash',
    'if($actualHash -cne $payload.expectedSha256){exit 73}',
    "[Console]::Out.Write('AGENT_ROAD_EXEC_VERIFIED')",
  ].join(';');
}

function buildExecInvokeWrapper(payload, runtimeProvision) {
  const expectedProperties = runtimeProvision ? 6 : 4;
  const runtimeValidation = runtimeProvision
    ? "if($propertyNames -cnotcontains 'runtimeOperationId' -or $propertyNames -cnotcontains 'manifestDigest' -or $payload.runtimeOperationId -isnot [string] -or $payload.runtimeOperationId -cnotmatch '^[a-f0-9]{32}$' -or $payload.manifestDigest -isnot [string] -or $payload.manifestDigest -cnotmatch '^[A-F0-9]{64}$'){exit 75}"
    : null;
  const childInputSetup = runtimeProvision ? [
    '$childInput=\'{"schemaVersion":1,"operationId":"\'+$payload.runtimeOperationId+\'","manifestDigest":"\'+$payload.manifestDigest+\'"}\'',
    '$childInputEncoding=New-Object Text.UTF8Encoding($false,$true)',
    '$childInputBytes=$childInputEncoding.GetBytes($childInput)',
    'if($childInputBytes.Length -lt 1 -or $childInputBytes.Length -gt 256){exit 75}',
  ] : [];
  const childInvocation = runtimeProvision
    ? 'try{$started=$child.Start();if(-not $started){exit 76};$child.StandardInput.BaseStream.Write($childInputBytes,0,$childInputBytes.Length);$child.StandardInput.BaseStream.Flush();$child.StandardInput.BaseStream.Close();$child.WaitForExit();$scriptExitCode=$child.ExitCode}catch{exit 76}finally{$child.Dispose()}'
    : 'try{$started=$child.Start();if(-not $started){exit 76};$child.StandardInput.Close();$child.WaitForExit();$scriptExitCode=$child.ExitCode}catch{exit 76}finally{$child.Dispose()}';
  return [
    ...operationPayloadPrelude(payload, expectedProperties),
    "if($propertyNames -cnotcontains 'expectedBytes' -or $propertyNames -cnotcontains 'expectedSha256' -or $payload.expectedBytes -isnot [int] -or $payload.expectedBytes -lt 2 -or $payload.expectedBytes -gt 2097154 -or $payload.expectedSha256 -isnot [string] -or $payload.expectedSha256 -cnotmatch '^[A-F0-9]{64}$'){exit 75}",
    ...(runtimeValidation === null ? [] : [runtimeValidation]),
    ...childInputSetup,
    "$parent='C:\\ProgramData\\AgentRoad'",
    ...restrictedAclFunctions(),
    `try{${[
      ...administratorGuard(),
      ...directoryGuard("'C:\\ProgramData'"),
      ...directoryGuard('$parent'),
      ...directoryGuard('$root'),
      'Assert-AgentRoadRestrictedDirectoryAcl $parent',
      'Assert-AgentRoadRestrictedDirectoryAcl $root',
    ].join(';')}}catch{exit 75}`,
    `try{${[
      ...stagedFileGuard("throw 'unsafe staged script'"),
      'if($fileItem.Length -ne $payload.expectedBytes){throw \'invalid staged length\'}',
      '$actualHash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash',
      "if($actualHash -cne $payload.expectedSha256){throw 'invalid staged hash'}",
      "foreach($candidate in @($resultPath,$resultTempPath)){if(Test-Path -LiteralPath $candidate){throw 'result path exists'}}",
    ].join(';')}}catch{exit 74}`,
    "$windowsPowerShell=Join-Path $env:SystemRoot 'System32\\WindowsPowerShell\\v1.0\\powershell.exe'",
    'if(-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)){exit 76}',
    '$windowsPowerShellItem=Get-Item -LiteralPath $windowsPowerShell -Force',
    'if($windowsPowerShellItem.PSIsContainer -or ($windowsPowerShellItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){exit 76}',
    '$startInfo=New-Object Diagnostics.ProcessStartInfo',
    '$startInfo.FileName=$windowsPowerShell',
    '$startInfo.Arguments=\'-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "\'+$path+\'"\'',
    '$startInfo.UseShellExecute=$false',
    '$startInfo.RedirectStandardInput=$true',
    '$startInfo.RedirectStandardOutput=$false',
    '$startInfo.RedirectStandardError=$false',
    '$child=New-Object Diagnostics.Process',
    '$child.StartInfo=$startInfo',
    '$scriptExitCode=$null',
    childInvocation,
    'if($null -eq $scriptExitCode -or $scriptExitCode -isnot [int] -or $scriptExitCode -lt 0 -or $scriptExitCode -gt 255){exit 76}',
    `try{${[
      "$record='{\"exitCode\":'+[string]$scriptExitCode+',\"schemaVersion\":1}'",
      '$recordEncoding=New-Object Text.UTF8Encoding($false,$true)',
      '$recordBytes=$recordEncoding.GetBytes($record)',
      "if($recordBytes.Length -lt 32 -or $recordBytes.Length -gt 35){throw 'invalid result record'}",
      '$resultStream=[IO.File]::Open($resultTempPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)',
      'try{$resultStream.Write($recordBytes,0,$recordBytes.Length);$resultStream.Flush($true)}finally{$resultStream.Dispose()}',
      'Set-AgentRoadRestrictedFileAcl $resultTempPath',
      ...stagedFileGuard("throw 'unsafe result temp'", '$resultTempPath', '$resultTempItem'),
      'Assert-AgentRoadRestrictedFileAcl $resultTempPath',
      "if($resultTempItem.Length -ne $recordBytes.Length){throw 'invalid result temp'}",
      'Move-Item -LiteralPath $resultTempPath -Destination $resultPath -ErrorAction Stop',
      ...stagedFileGuard("throw 'unsafe result file'", '$resultPath', '$resultItem'),
      'Assert-AgentRoadRestrictedFileAcl $resultPath',
      '$publishedRecord=[IO.File]::ReadAllText($resultPath,$recordEncoding)',
      "if($resultItem.Length -ne $recordBytes.Length -or $publishedRecord -cne $record){throw 'invalid published result'}",
    ].join(';')}}catch{exit 76}`,
    'exit 0',
  ].join(';');
}

function execInvokeWrapper(payload) {
  validateExecVerifyPayload(payload);
  return buildExecInvokeWrapper(payload, false);
}

function runtimeProvisionInvokeWrapper(payload) {
  validateRuntimeProvisionInvokePayload(payload);
  return buildExecInvokeWrapper(payload, true);
}

function execReadResultCommands(payload) {
  validateOperationPayload(payload);
  return [
    ...operationPayloadPrelude(payload, 2),
    ...administratorGuard(),
    "$parent='C:\\ProgramData\\AgentRoad'",
    ...restrictedAclFunctions(),
    ...directoryGuard("'C:\\ProgramData'"),
    ...directoryGuard('$parent'),
    ...directoryGuard('$root'),
    'Assert-AgentRoadRestrictedDirectoryAcl $parent',
    'Assert-AgentRoadRestrictedDirectoryAcl $root',
    ...stagedFileGuard("throw 'missing result file'", '$resultPath', '$resultItem'),
    'Assert-AgentRoadRestrictedFileAcl $resultPath',
    "if($resultItem.Length -lt 32 -or $resultItem.Length -gt 35){throw 'invalid result size'}",
    '$recordEncoding=New-Object Text.UTF8Encoding($false,$true)',
    '$record=[IO.File]::ReadAllText($resultPath,$recordEncoding)',
    "$exitPattern='^(?:0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'",
    "$recordPattern='^\\{\"exitCode\":(0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5]),\"schemaVersion\":1\\}$'",
    "$match=[regex]::Match($record,$recordPattern);if(-not $match.Success){throw 'invalid result record'}",
    '$exitText=$match.Groups[1].Value',
    "if($exitText -cnotmatch $exitPattern){throw 'invalid result exit'}",
    "$canonical='{\"exitCode\":'+$exitText+',\"schemaVersion\":1}'",
    "if($canonical -cne $record){throw 'noncanonical result record'}",
  ];
}

function execReadResultWrapper(payload) {
  return [...execReadResultCommands(payload), '[Console]::Out.Write($exitText)'].join(';');
}

function execCleanupCommands(payload) {
  validateOperationPayload(payload);
  return [
    ...operationPayloadPrelude(payload, 2),
    ...administratorGuard(),
    "$parent='C:\\ProgramData\\AgentRoad'",
    ...restrictedAclFunctions(),
    "if(Test-Path -LiteralPath $root){$rootItem=Get-Item -LiteralPath $root -Force;if(-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'unsafe task root'};Assert-AgentRoadRestrictedDirectoryAcl $parent;Assert-AgentRoadRestrictedDirectoryAcl $root;foreach($candidate in @($path,$resultPath,$resultTempPath)){if(Test-Path -LiteralPath $candidate){$cleanupItem=Get-Item -LiteralPath $candidate -Force;if($cleanupItem.PSIsContainer -or ($cleanupItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'unsafe cleanup file'};Remove-Item -LiteralPath $candidate -Force -ErrorAction Stop};if(Test-Path -LiteralPath $candidate){throw 'cleanup failed'}}}",
  ];
}

function execCleanupWrapper(payload) {
  return [...execCleanupCommands(payload), "[Console]::Out.Write('AGENT_ROAD_EXEC_CLEANED')"].join(';');
}

function execFinalizeWrapper(payload) {
  // Publish success only after both the canonical receipt and cleanup checks pass.
  return [
    `try{${execReadResultCommands(payload).join(';')}}catch{exit 77}`,
    `try{${execCleanupCommands(payload).join(';')}}catch{exit 78}`,
    '[Console]::Out.Write($exitText)',
  ].join(';');
}

function putPayloadPrelude(payload, phase = 'base') {
  const expectedProperties = phase === 'publish' ? 7 : phase === 'cleanup' ? 9 : 6;
  const phaseValidation = phase === 'publish'
    ? " -or $propertyNames -cnotcontains 'expectedParentIdentity' -or $payload.expectedParentIdentity -isnot [string] -or $payload.expectedParentIdentity -cnotmatch '^[A-F0-9]{8}:[A-F0-9]{8}:[A-F0-9]{8}$'"
    : phase === 'cleanup'
      ? " -or $propertyNames -cnotcontains 'expectedParentIdentity' -or $propertyNames -cnotcontains 'stagingOwned' -or $propertyNames -cnotcontains 'tempOwned' -or $payload.stagingOwned -isnot [bool] -or $payload.tempOwned -isnot [bool] -or ($payload.tempOwned -and ($payload.expectedParentIdentity -isnot [string] -or $payload.expectedParentIdentity -cnotmatch '^[A-F0-9]{8}:[A-F0-9]{8}:[A-F0-9]{8}$')) -or (-not $payload.tempOwned -and $null -ne $payload.expectedParentIdentity)"
      : '';
  return [
    "$ErrorActionPreference='Stop'",
    "$ProgressPreference='SilentlyContinue'",
    'Set-StrictMode -Version 2.0',
    `$payloadJson=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}'))`,
    '$payload=$payloadJson|ConvertFrom-Json',
    '$propertyNames=@($payload.PSObject.Properties.Name)',
    `if(@($payload.PSObject.Properties).Count -ne ${expectedProperties} -or $propertyNames -cnotcontains 'schemaVersion' -or $propertyNames -cnotcontains 'operationId' -or $propertyNames -cnotcontains 'destinationPath' -or $propertyNames -cnotcontains 'overwrite' -or $propertyNames -cnotcontains 'expectedBytes' -or $propertyNames -cnotcontains 'expectedSha256' -or $payload.schemaVersion -isnot [int] -or $payload.schemaVersion -ne 1 -or $payload.operationId -isnot [string] -or $payload.operationId -cnotmatch '^[a-f0-9]{32}$' -or $payload.destinationPath -isnot [string] -or $payload.overwrite -isnot [bool] -or $payload.expectedBytes -isnot [int] -or $payload.expectedBytes -lt 0 -or $payload.expectedBytes -gt 268435456 -or $payload.expectedSha256 -isnot [string] -or $payload.expectedSha256 -cnotmatch '^[A-F0-9]{64}$'${phaseValidation}){throw 'invalid put payload'}`,
    "$root='C:\\ProgramData\\AgentRoad\\transfers'",
    "$stagingPath=[IO.Path]::Combine($root,($payload.operationId+'.put.stage'))",
    "$destination=[IO.Path]::GetFullPath($payload.destinationPath)",
    "if($destination -cne $payload.destinationPath -or $destination -cnotmatch '^[A-Za-z]:\\\\' -or $destination.Length -lt 4){exit 74}",
    "$internalRoot='C:\\ProgramData\\AgentRoad'",
    "if($destination.Equals($internalRoot,[StringComparison]::OrdinalIgnoreCase) -or $destination.StartsWith(($internalRoot+'\\'),[StringComparison]::OrdinalIgnoreCase)){exit 74}",
    '$destinationParent=[IO.Path]::GetDirectoryName($destination)',
    '$destinationName=[IO.Path]::GetFileName($destination)',
    "if([string]::IsNullOrEmpty($destinationParent) -or [string]::IsNullOrEmpty($destinationName)){exit 74}",
    "$tempName='.'+$destinationName+'.agent-road-'+$payload.operationId+'.tmp'",
    '$tempPath=[IO.Path]::Combine($destinationParent,$tempName)',
    "if([IO.Path]::GetFullPath($tempPath) -cne $tempPath -or [IO.Path]::GetDirectoryName($tempPath) -cne $destinationParent){exit 74}",
    "foreach($candidate in @($root,$stagingPath)){if([IO.Path]::GetFullPath($candidate) -cne $candidate){throw 'invalid transfer path'}}",
    "if([IO.Path]::GetDirectoryName($stagingPath) -cne $root){throw 'invalid transfer path'}",
  ];
}

function longPathResolutionFunctions({ includeSnapshot = false } = {}) {
  const nativeSource = [
    'using System;',
    'using System.ComponentModel;',
    'using System.Globalization;',
    'using System.IO;',
    'using System.Runtime.InteropServices;',
    ...(includeSnapshot ? ['using System.Security.Cryptography;'] : []),
    'using System.Text;',
    'using Microsoft.Win32.SafeHandles;',
    'namespace AgentRoad{public static class NativePath{',
    '[StructLayout(LayoutKind.Sequential)]private struct ByHandleFileInformation{public uint FileAttributes;public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;public uint VolumeSerialNumber;public uint FileSizeHigh;public uint FileSizeLow;public uint NumberOfLinks;public uint FileIndexHigh;public uint FileIndexLow;}',
    '[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="GetLongPathNameW")]private static extern uint GetLongPathName(string input,StringBuilder output,uint capacity);',
    '[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="CreateFileW")]private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);',
    ...(includeSnapshot ? ['[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="GetFinalPathNameByHandleW")]private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,StringBuilder output,uint capacity,uint flags);'] : []),
    '[DllImport("kernel32.dll",SetLastError=true,EntryPoint="GetFileInformationByHandle")][return:MarshalAs(UnmanagedType.Bool)]private static extern bool GetFileInformationByHandle(SafeFileHandle handle,out ByHandleFileInformation information);',
    'private const uint GENERIC_READ=0x80000000;private const uint FILE_SHARE_READ=1;private const uint FILE_SHARE_WRITE=2;private const uint OPEN_EXISTING=3;private const uint FILE_ATTRIBUTE_DIRECTORY=0x00000010;private const uint FILE_ATTRIBUTE_REPARSE_POINT=0x00000400;private const uint FILE_FLAG_OPEN_REPARSE_POINT=0x00200000;private const uint FILE_FLAG_BACKUP_SEMANTICS=0x02000000;private const uint FILE_FLAG_SEQUENTIAL_SCAN=0x08000000;',
    'private static string NativeInput(string input){if(String.IsNullOrEmpty(input)||input.Length>4096)throw new ArgumentException();string prefix=@"\\\\?\\";return input.StartsWith(prefix,StringComparison.Ordinal)?input:prefix+input;}',
    'public static string Resolve(string input){string prefix=@"\\\\?\\";var output=new StringBuilder(32768);uint length=GetLongPathName(NativeInput(input),output,(uint)output.Capacity);if(length==0||length>=(uint)output.Capacity||length!=(uint)output.Length)throw new Win32Exception(Marshal.GetLastWin32Error());string value=output.ToString();if(value.StartsWith(prefix,StringComparison.Ordinal))value=value.Substring(prefix.Length);if(String.IsNullOrEmpty(value)||value.Length>32767)throw new InvalidOperationException();return value;}',
    'public static SafeFileHandle OpenDirectory(string input){SafeFileHandle handle=CreateFile(NativeInput(input),0,FILE_SHARE_READ|FILE_SHARE_WRITE,IntPtr.Zero,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,IntPtr.Zero);if(handle.IsInvalid){int error=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(error);}return handle;}',
    'public static string Identity(SafeFileHandle handle){if(handle==null||handle.IsInvalid||handle.IsClosed)throw new ArgumentException();ByHandleFileInformation information;if(!GetFileInformationByHandle(handle,out information))throw new Win32Exception(Marshal.GetLastWin32Error());if((information.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)==0||(information.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)!=0)throw new InvalidOperationException();return String.Format(CultureInfo.InvariantCulture,"{0:X8}:{1:X8}:{2:X8}",information.VolumeSerialNumber,information.FileIndexHigh,information.FileIndexLow);}',
    ...(includeSnapshot ? [
      'private static string FinalPath(SafeFileHandle handle){if(handle==null||handle.IsInvalid||handle.IsClosed)throw new ArgumentException();var output=new StringBuilder(32768);uint length=GetFinalPathNameByHandle(handle,output,(uint)output.Capacity,0);if(length==0||length>=(uint)output.Capacity||length!=(uint)output.Length)throw new Win32Exception(Marshal.GetLastWin32Error());string value=output.ToString();string prefix=@"\\\\?\\";if(value.StartsWith(prefix,StringComparison.Ordinal))value=value.Substring(prefix.Length);if(String.IsNullOrEmpty(value)||value.Length<4||value.Length>32767||value.Substring(1,1)!=":"||value.Substring(2,1)!=@"\\")throw new InvalidOperationException();return value;}',
    'private static bool SameFile(ByHandleFileInformation left,ByHandleFileInformation right){return left.VolumeSerialNumber==right.VolumeSerialNumber&&left.FileIndexHigh==right.FileIndexHigh&&left.FileIndexLow==right.FileIndexLow&&left.FileSizeHigh==right.FileSizeHigh&&left.FileSizeLow==right.FileSizeLow&&left.LastWriteTime.dwHighDateTime==right.LastWriteTime.dwHighDateTime&&left.LastWriteTime.dwLowDateTime==right.LastWriteTime.dwLowDateTime;}',
      'public static string Snapshot(string source,string destination,long maximumBytes){if(maximumBytes<1)throw new ArgumentException();using(SafeFileHandle handle=CreateFile(NativeInput(source),GENERIC_READ,FILE_SHARE_READ,IntPtr.Zero,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_SEQUENTIAL_SCAN,IntPtr.Zero)){if(handle.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());string finalPath=FinalPath(handle);if(!String.Equals(finalPath,source,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException();ByHandleFileInformation before;if(!GetFileInformationByHandle(handle,out before))throw new Win32Exception(Marshal.GetLastWin32Error());if((before.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0||(before.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)!=0)throw new InvalidOperationException();long length=((long)before.FileSizeHigh<<32)|before.FileSizeLow;if(length<0||length>maximumBytes)throw new InvalidOperationException();using(var input=new FileStream(handle,FileAccess.Read,65536,false))using(var output=new FileStream(destination,FileMode.CreateNew,FileAccess.Write,FileShare.None,65536,FileOptions.WriteThrough))using(var hash=SHA256.Create()){byte[] buffer=new byte[65536];long copied=0;int read;while((read=input.Read(buffer,0,buffer.Length))>0){copied+=read;if(copied>length||copied>maximumBytes)throw new InvalidOperationException();output.Write(buffer,0,read);hash.TransformBlock(buffer,0,read,buffer,0);}hash.TransformFinalBlock(new byte[0],0,0);output.Flush(true);ByHandleFileInformation after;if(!GetFileInformationByHandle(handle,out after))throw new Win32Exception(Marshal.GetLastWin32Error());if(copied!=length||!SameFile(before,after))throw new InvalidOperationException();return copied.ToString(CultureInfo.InvariantCulture)+":"+BitConverter.ToString(hash.Hash).Replace("-",String.Empty);}}}',
    ] : []),
    '}}',
  ].join('');
  return [
    `function Initialize-AgentRoadNativePath{$nativeType=('AgentRoad.NativePath' -as [type]);if($null -eq $nativeType){$nativeSource='${nativeSource}';Add-Type -TypeDefinition $nativeSource -Language CSharp -ErrorAction Stop|Out-Null;$nativeType=('AgentRoad.NativePath' -as [type])};if($null -eq $nativeType){throw 'native path type missing'};$resolveMethod=$nativeType.GetMethod('Resolve');$openMethod=$nativeType.GetMethod('OpenDirectory');$identityMethod=$nativeType.GetMethod('Identity');if($null -eq $resolveMethod -or $null -eq $openMethod -or $null -eq $identityMethod){throw 'native path type mismatch'};$resolveParameters=@($resolveMethod.GetParameters());$openParameters=@($openMethod.GetParameters());$identityParameters=@($identityMethod.GetParameters());$safeHandleType=[Microsoft.Win32.SafeHandles.SafeFileHandle];if(-not $resolveMethod.IsStatic -or $resolveMethod.ReturnType -ne [string] -or $resolveParameters.Count -ne 1 -or $resolveParameters[0].ParameterType -ne [string] -or -not $openMethod.IsStatic -or $openMethod.ReturnType -ne $safeHandleType -or $openParameters.Count -ne 1 -or $openParameters[0].ParameterType -ne [string] -or -not $identityMethod.IsStatic -or $identityMethod.ReturnType -ne [string] -or $identityParameters.Count -ne 1 -or $identityParameters[0].ParameterType -ne $safeHandleType){throw 'native path type mismatch'}}`,
    "function Resolve-AgentRoadExistingLongPath([string]$candidate){Initialize-AgentRoadNativePath;$nativeType=('AgentRoad.NativePath' -as [type]);$nativeMethod=$nativeType.GetMethod('Resolve');$resolved=[string]$nativeMethod.Invoke($null,[object[]]@($candidate));if([string]::IsNullOrEmpty($resolved) -or $resolved.Length -gt 32767 -or -not ([IO.Path]::GetFullPath($resolved).Equals($resolved,[StringComparison]::OrdinalIgnoreCase))){throw 'invalid resolved path'};return $resolved}",
    ...(!includeSnapshot ? [
      "function Resolve-AgentRoadDestinationLongPath([string]$candidate,[string]$parent,[string]$leaf,[string]$internal){$longInternal=Resolve-AgentRoadExistingLongPath $internal;$longParent=Resolve-AgentRoadExistingLongPath $parent;$expected=[IO.Path]::Combine($longParent,$leaf);if(-not ([IO.Path]::GetFullPath($expected).Equals($expected,[StringComparison]::OrdinalIgnoreCase))){throw 'invalid resolved destination'};if(Test-Path -LiteralPath $candidate){$longDestination=Resolve-AgentRoadExistingLongPath $candidate;if(-not $longDestination.Equals($expected,[StringComparison]::OrdinalIgnoreCase)){throw 'ambiguous resolved destination'}}else{$longDestination=$expected};$resolvedParent=[IO.Path]::GetDirectoryName($longDestination);if([string]::IsNullOrEmpty($resolvedParent) -or -not $resolvedParent.Equals($longParent,[StringComparison]::OrdinalIgnoreCase)){throw 'invalid resolved parent'};if($longDestination.Equals($longInternal,[StringComparison]::OrdinalIgnoreCase) -or $longDestination.StartsWith(($longInternal+'\\'),[StringComparison]::OrdinalIgnoreCase)){throw 'internal destination'};return $longDestination}",
    "function Get-AgentRoadDirectoryHandleIdentity([Microsoft.Win32.SafeHandles.SafeFileHandle]$handle){Initialize-AgentRoadNativePath;if($null -eq $handle -or $handle.IsInvalid -or $handle.IsClosed){throw 'invalid directory handle'};$nativeType=('AgentRoad.NativePath' -as [type]);$identityMethod=$nativeType.GetMethod('Identity');$identity=[string]$identityMethod.Invoke($null,[object[]]@($handle));if($identity -cnotmatch '^[A-F0-9]{8}:[A-F0-9]{8}:[A-F0-9]{8}$'){throw 'invalid directory identity'};return $identity}",
      "function Open-AgentRoadDirectoryHandle([string]$candidate){$before=Get-Item -LiteralPath $candidate -Force;if(-not $before.PSIsContainer -or ($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'unsafe identity path'};Initialize-AgentRoadNativePath;$nativeType=('AgentRoad.NativePath' -as [type]);$openMethod=$nativeType.GetMethod('OpenDirectory');$handle=[Microsoft.Win32.SafeHandles.SafeFileHandle]$openMethod.Invoke($null,[object[]]@($candidate));try{if($null -eq $handle -or $handle.IsInvalid -or $handle.IsClosed){throw 'invalid directory handle'};$after=Get-Item -LiteralPath $candidate -Force;if(-not $after.PSIsContainer -or ($after.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'unsafe identity path'};[void](Get-AgentRoadDirectoryHandleIdentity $handle);return $handle}catch{if($null -ne $handle){$handle.Dispose()};throw}}",
    ] : []),
  ];
}

function safeDestinationChainFunction() {
  return [
    "function Assert-AgentRoadSafeDestinationChain([string]$candidate){$pathRoot=[IO.Path]::GetPathRoot($candidate);if([string]::IsNullOrEmpty($pathRoot) -or [IO.Path]::GetFullPath($pathRoot) -cne $pathRoot){throw 'unsafe destination root'};$rootItem=Get-Item -LiteralPath $pathRoot -Force;if(-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'unsafe destination root'};[void](Resolve-AgentRoadExistingLongPath $pathRoot);$relative=$candidate.Substring($pathRoot.Length);$current=$pathRoot;if($relative.Length -gt 0){foreach($component in @($relative -split '\\\\')){if([string]::IsNullOrEmpty($component)){throw 'unsafe destination component'};$current=[IO.Path]::Combine($current,$component);if(-not (Test-Path -LiteralPath $current -PathType Container)){throw 'destination component missing'};$currentItem=Get-Item -LiteralPath $current -Force;if(-not $currentItem.PSIsContainer -or ($currentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'unsafe destination component'};[void](Resolve-AgentRoadExistingLongPath $current)}}}",
  ];
}

function resolveLongDestinationStatements() {
  return [
    '$resolvedDestination=Resolve-AgentRoadDestinationLongPath $destination $destinationParent $destinationName $internalRoot',
    '$destination=$resolvedDestination',
    '$destinationParent=[IO.Path]::GetDirectoryName($destination)',
    '$destinationName=[IO.Path]::GetFileName($destination)',
    "$tempName='.'+$destinationName+'.agent-road-'+$payload.operationId+'.tmp'",
    '$tempPath=[IO.Path]::Combine($destinationParent,$tempName)',
  ];
}

function putPreflightWrapper(payload) {
  validatePutPayload(payload);
  return [
    ...putPayloadPrelude(payload),
    ...administratorGuard(),
    "$agentRoadRoot='C:\\ProgramData\\AgentRoad'",
    ...restrictedAclFunctions(),
    ...directoryGuard("'C:\\ProgramData'"),
    ...directoryGuard('$agentRoadRoot'),
    'Assert-AgentRoadRestrictedDirectoryAcl $agentRoadRoot',
    "$rootCreated=$false;if(Test-Path -LiteralPath $root){$existing=Get-Item -LiteralPath $root -Force;if(-not $existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'unsafe transfer root'}}else{[IO.Directory]::CreateDirectory($root,(New-AgentRoadRestrictedDirectorySecurity))|Out-Null;$rootCreated=$true}",
    ...directoryGuard('$root'),
    'Assert-AgentRoadRestrictedDirectoryAcl $root',
    "if(Test-Path -LiteralPath $stagingPath){throw 'staging path already exists'}",
    "[Console]::Out.Write('AGENT_ROAD_PUT_PREFLIGHT_OK')",
  ].join(';');
}

function putPrepareWrapper(payload) {
  validatePutPayload(payload);
  return [
    ...putPayloadPrelude(payload),
    ...administratorGuard(),
    "$agentRoadRoot='C:\\ProgramData\\AgentRoad'",
    ...restrictedAclFunctions(),
    ...longPathResolutionFunctions(),
    ...safeDestinationChainFunction(),
    ...directoryGuard('$agentRoadRoot'),
    ...directoryGuard('$root'),
    'Assert-AgentRoadRestrictedDirectoryAcl $agentRoadRoot',
    'Assert-AgentRoadRestrictedDirectoryAcl $root',
    ...stagedFileGuard('exit 73', '$stagingPath', '$stagingItem'),
    'Set-AgentRoadRestrictedFileAcl $stagingPath',
    'Assert-AgentRoadRestrictedFileAcl $stagingPath',
    'if($stagingItem.Length -ne $payload.expectedBytes){exit 73}',
    '$stagingHash=(Get-FileHash -LiteralPath $stagingPath -Algorithm SHA256).Hash',
    'if($stagingHash -cne $payload.expectedSha256){exit 73}',
    `try{${[
      'Assert-AgentRoadSafeDestinationChain $destinationParent',
      ...resolveLongDestinationStatements(),
    ].join(';')}}catch{exit 74}`,
    "if(-not (Test-Path -LiteralPath $destinationParent -PathType Container)){exit 74}",
    '$destinationParentItem=Get-Item -LiteralPath $destinationParent -Force',
    'if(-not $destinationParentItem.PSIsContainer -or ($destinationParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){exit 74}',
    'try{$parentHandle=Open-AgentRoadDirectoryHandle $destinationParent}catch{exit 74}',
    `try{${[
      'try{$parentIdentityBefore=Get-AgentRoadDirectoryHandleIdentity $parentHandle}catch{exit 74}',
      'if(Test-Path -LiteralPath $tempPath){exit 74}',
      "if(Test-Path -LiteralPath $destination){$destinationItem=Get-Item -LiteralPath $destination -Force;if(-not $payload.overwrite -or $destinationItem.PSIsContainer -or ($destinationItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){exit 74}}",
      '[IO.File]::Copy($stagingPath,$tempPath,$false)',
      ...stagedFileGuard('exit 75', '$tempPath', '$tempItem'),
      'if($tempItem.Length -ne $payload.expectedBytes){exit 75}',
      '$tempHash=(Get-FileHash -LiteralPath $tempPath -Algorithm SHA256).Hash',
      'if($tempHash -cne $payload.expectedSha256){exit 75}',
      'try{$parentIdentityAfter=Get-AgentRoadDirectoryHandleIdentity $parentHandle}catch{exit 76}',
      'if($parentIdentityAfter -cne $parentIdentityBefore){exit 76}',
    ].join(';')}}finally{$parentHandle.Dispose()}`,
    "[Console]::Out.Write('AGENT_ROAD_PUT_PREPARED:'+$parentIdentityBefore)",
  ].join(';');
}

function putPublishWrapper(payload) {
  validatePutPayload(payload, 'publish');
  return [
    ...putPayloadPrelude(payload, 'publish'),
    ...administratorGuard(),
    ...longPathResolutionFunctions(),
    ...safeDestinationChainFunction(),
    `try{${[
      'Assert-AgentRoadSafeDestinationChain $destinationParent',
      ...resolveLongDestinationStatements(),
    ].join(';')}}catch{exit 74}`,
    "if(-not (Test-Path -LiteralPath $destinationParent -PathType Container)){exit 74}",
    '$destinationParentItem=Get-Item -LiteralPath $destinationParent -Force',
    'if(-not $destinationParentItem.PSIsContainer -or ($destinationParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){exit 74}',
    'try{$publishParentHandle=Open-AgentRoadDirectoryHandle $destinationParent}catch{exit 74}',
    `try{${[
      "try{$currentParentIdentity=Get-AgentRoadDirectoryHandleIdentity $publishParentHandle;if($currentParentIdentity -cne $payload.expectedParentIdentity){throw 'destination parent changed'}}catch{exit 74}",
      ...stagedFileGuard('exit 73', '$tempPath', '$tempItem'),
      'if($tempItem.Length -ne $payload.expectedBytes){exit 73}',
      '$tempHash=(Get-FileHash -LiteralPath $tempPath -Algorithm SHA256).Hash',
      'if($tempHash -cne $payload.expectedSha256){exit 73}',
      '$destinationExists=Test-Path -LiteralPath $destination',
      "if($destinationExists){$destinationItem=Get-Item -LiteralPath $destination -Force;if(-not $payload.overwrite -or $destinationItem.PSIsContainer -or ($destinationItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){exit 74}}",
      "try{$finalParentIdentity=Get-AgentRoadDirectoryHandleIdentity $publishParentHandle;if($finalParentIdentity -cne $payload.expectedParentIdentity){throw 'destination parent changed'}}catch{exit 74}",
      "if($destinationExists){[IO.File]::Replace($tempPath,$destination,[Management.Automation.Language.NullString]::Value,$true)}else{if(Test-Path -LiteralPath $destination){exit 74};[IO.File]::Move($tempPath,$destination)}",
    ].join(';')}}finally{$publishParentHandle.Dispose()}`,
    "[Console]::Out.Write('AGENT_ROAD_PUT_PUBLISHED')",
  ].join(';');
}

function putCleanupWrapper(payload) {
  validatePutPayload(payload, 'cleanup');
  return [
    ...putPayloadPrelude(payload, 'cleanup'),
    ...administratorGuard(),
    "$agentRoadRoot='C:\\ProgramData\\AgentRoad'",
    ...restrictedAclFunctions(),
    ...longPathResolutionFunctions(),
    ...safeDestinationChainFunction(),
    `if($payload.stagingOwned){if(-not (Test-Path -LiteralPath $root -PathType Container)){throw 'missing transfer root'};$rootItem=Get-Item -LiteralPath $root -Force;if(-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'unsafe transfer root'};Assert-AgentRoadRestrictedDirectoryAcl $agentRoadRoot;Assert-AgentRoadRestrictedDirectoryAcl $root;$stagingParentHandle=Open-AgentRoadDirectoryHandle $root;try{$stagingParentIdentity=Get-AgentRoadDirectoryHandleIdentity $stagingParentHandle;if(Test-Path -LiteralPath $stagingPath){${[
      ...stagedFileGuard("throw 'unsafe staging cleanup'", '$stagingPath', '$stagingItem'),
      "if($stagingItem.Length -ne $payload.expectedBytes){throw 'staging cleanup size mismatch'}",
      '$stagingHash=(Get-FileHash -LiteralPath $stagingPath -Algorithm SHA256).Hash',
      "if($stagingHash -cne $payload.expectedSha256){throw 'staging cleanup hash mismatch'}",
      '$finalStagingParentIdentity=Get-AgentRoadDirectoryHandleIdentity $stagingParentHandle',
      "if($finalStagingParentIdentity -cne $stagingParentIdentity){throw 'transfer parent changed'}",
      'Remove-Item -LiteralPath $stagingPath -Force -ErrorAction Stop',
    ].join(';')}};if(Test-Path -LiteralPath $stagingPath){throw 'staging cleanup failed'}}finally{$stagingParentHandle.Dispose()}}`,
    `if($payload.tempOwned){if(-not (Test-Path -LiteralPath $destinationParent -PathType Container)){throw 'missing publication parent'};${[
      'Assert-AgentRoadSafeDestinationChain $destinationParent',
      ...resolveLongDestinationStatements(),
      '$destinationParentItem=Get-Item -LiteralPath $destinationParent -Force',
      "if(-not $destinationParentItem.PSIsContainer -or ($destinationParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'unsafe publication parent'}",
      '$cleanupParentHandle=Open-AgentRoadDirectoryHandle $destinationParent',
      `try{${[
        '$cleanupParentIdentity=Get-AgentRoadDirectoryHandleIdentity $cleanupParentHandle',
        "if($cleanupParentIdentity -cne $payload.expectedParentIdentity){throw 'destination parent changed'}",
        "if(Test-Path -LiteralPath $tempPath){$tempItem=Get-Item -LiteralPath $tempPath -Force;if($tempItem.PSIsContainer -or ($tempItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $tempItem.Length -ne $payload.expectedBytes){throw 'unsafe publication cleanup'};$tempHash=(Get-FileHash -LiteralPath $tempPath -Algorithm SHA256).Hash;if($tempHash -cne $payload.expectedSha256){throw 'publication cleanup hash mismatch'};$finalCleanupParentIdentity=Get-AgentRoadDirectoryHandleIdentity $cleanupParentHandle;if($finalCleanupParentIdentity -cne $payload.expectedParentIdentity){throw 'destination parent changed'};Remove-Item -LiteralPath $tempPath -Force -ErrorAction Stop}",
        "if(Test-Path -LiteralPath $tempPath){throw 'publication cleanup failed'}",
      ].join(';')}}finally{$cleanupParentHandle.Dispose()}`,
    ].join(';')}}`,
    "[Console]::Out.Write('AGENT_ROAD_PUT_CLEANED')",
  ].join(';');
}

function getPayloadPrelude(payload, phase = 'prepare') {
  const cleanup = phase === 'cleanup';
  const cleanupValidation = cleanup
    ? " -or $propertyNames -cnotcontains 'expectedBytes' -or $propertyNames -cnotcontains 'expectedSha256' -or $propertyNames -cnotcontains 'snapshotOwned' -or $payload.snapshotOwned -isnot [bool] -or ($payload.snapshotOwned -and ($payload.expectedBytes -isnot [int] -or $payload.expectedBytes -lt 0 -or $payload.expectedBytes -gt 268435456 -or $payload.expectedSha256 -isnot [string] -or $payload.expectedSha256 -cnotmatch '^[A-F0-9]{64}$')) -or (-not $payload.snapshotOwned -and ($null -ne $payload.expectedBytes -or $null -ne $payload.expectedSha256))"
    : '';
  return [
    "$ErrorActionPreference='Stop'",
    "$ProgressPreference='SilentlyContinue'",
    'Set-StrictMode -Version 2.0',
    `$payloadJson=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}'))`,
    '$payload=$payloadJson|ConvertFrom-Json',
    '$propertyNames=@($payload.PSObject.Properties.Name)',
    `if(@($payload.PSObject.Properties).Count -ne ${cleanup ? 6 : 3} -or $propertyNames -cnotcontains 'schemaVersion' -or $propertyNames -cnotcontains 'operationId' -or $propertyNames -cnotcontains 'sourcePath' -or $payload.schemaVersion -isnot [int] -or $payload.schemaVersion -ne 1 -or $payload.operationId -isnot [string] -or $payload.operationId -cnotmatch '^[a-f0-9]{32}$' -or $payload.sourcePath -isnot [string]${cleanupValidation}){throw 'invalid get payload'}`,
    "$root='C:\\ProgramData\\AgentRoad\\transfers'",
    "$snapshotPath=[IO.Path]::Combine($root,($payload.operationId+'.get.stage'))",
    "$source=[IO.Path]::GetFullPath($payload.sourcePath)",
    "if($source -cne $payload.sourcePath -or $source -cnotmatch '^[A-Za-z]:\\\\' -or $source.Length -lt 4){exit 73}",
    "$internalRoot='C:\\ProgramData\\AgentRoad'",
    "if($source.Equals($internalRoot,[StringComparison]::OrdinalIgnoreCase) -or $source.StartsWith(($internalRoot+'\\'),[StringComparison]::OrdinalIgnoreCase)){exit 73}",
    "foreach($candidate in @($root,$snapshotPath)){if([IO.Path]::GetFullPath($candidate) -cne $candidate){throw 'invalid transfer path'}}",
    "if([IO.Path]::GetDirectoryName($snapshotPath) -cne $root){throw 'invalid transfer path'}",
  ];
}

function safeSourceChainFunction() {
  return [
    "function Resolve-AgentRoadSafeSource([string]$candidate,[string]$internal){$longInternal=Resolve-AgentRoadExistingLongPath $internal;$longSource=Resolve-AgentRoadExistingLongPath $candidate;if($longSource.Equals($longInternal,[StringComparison]::OrdinalIgnoreCase) -or $longSource.StartsWith(($longInternal+'\\'),[StringComparison]::OrdinalIgnoreCase)){throw 'internal source'};$parent=[IO.Path]::GetDirectoryName($longSource);if([string]::IsNullOrEmpty($parent)){throw 'missing source parent'};Assert-AgentRoadSafeDestinationChain $parent;$item=Get-Item -LiteralPath $longSource -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -lt 0 -or $item.Length -gt 268435456){throw 'unsafe source'};return $longSource}",
  ];
}

function getPrepareWrapper(payload) {
  validateGetPayload(payload);
  return [
    ...getPayloadPrelude(payload),
    ...administratorGuard(),
    "$agentRoadRoot='C:\\ProgramData\\AgentRoad'",
    ...restrictedAclFunctions(),
    ...longPathResolutionFunctions({ includeSnapshot: true }),
    ...safeDestinationChainFunction(),
    ...safeSourceChainFunction(),
    ...directoryGuard("'C:\\ProgramData'"),
    ...directoryGuard('$agentRoadRoot'),
    'Assert-AgentRoadRestrictedDirectoryAcl $agentRoadRoot',
    "$rootCreated=$false;if(Test-Path -LiteralPath $root){$existing=Get-Item -LiteralPath $root -Force;if(-not $existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'unsafe transfer root'}}else{[IO.Directory]::CreateDirectory($root,(New-AgentRoadRestrictedDirectorySecurity))|Out-Null;$rootCreated=$true}",
    ...directoryGuard('$root'),
    'Assert-AgentRoadRestrictedDirectoryAcl $root',
    'if(Test-Path -LiteralPath $snapshotPath){exit 74}',
    'try{$source=Resolve-AgentRoadSafeSource $source $internalRoot}catch{exit 73}',
    "try{Initialize-AgentRoadNativePath;$nativeType=('AgentRoad.NativePath' -as [type]);$snapshotMethod=$nativeType.GetMethod('Snapshot');$snapshotParameters=@($snapshotMethod.GetParameters());if($null -eq $snapshotMethod -or -not $snapshotMethod.IsStatic -or $snapshotMethod.ReturnType -ne [string] -or $snapshotParameters.Count -ne 3 -or $snapshotParameters[0].ParameterType -ne [string] -or $snapshotParameters[1].ParameterType -ne [string] -or $snapshotParameters[2].ParameterType -ne [long]){throw 'native snapshot mismatch'};$snapshotResult=[string]$snapshotMethod.Invoke($null,[object[]]@($source,$snapshotPath,[long]268435456))}catch{exit 75}",
    'try{Set-AgentRoadRestrictedFileAcl $snapshotPath;Assert-AgentRoadRestrictedFileAcl $snapshotPath}catch{exit 75}',
    "if($snapshotResult -cnotmatch '^(?:0|[1-9][0-9]{0,8}):[A-F0-9]{64}$'){exit 75}",
    "$snapshotParts=@($snapshotResult -split ':')",
    'if($snapshotParts.Count -ne 2){exit 75}',
    '$snapshotBytes=[long]$snapshotParts[0]',
    '$snapshotHash=[string]$snapshotParts[1]',
    'if($snapshotBytes -lt 0 -or $snapshotBytes -gt 268435456){exit 75}',
    ...stagedFileGuard('exit 75', '$snapshotPath', '$snapshotItem'),
    'if($snapshotItem.Length -ne $snapshotBytes){exit 75}',
    '$verifiedHash=(Get-FileHash -LiteralPath $snapshotPath -Algorithm SHA256).Hash',
    'if($verifiedHash -cne $snapshotHash){exit 75}',
    "[Console]::Out.Write('AGENT_ROAD_GET_PREPARED:'+$snapshotBytes+':'+$snapshotHash)",
  ].join(';');
}

function getCleanupWrapper(payload) {
  validateGetPayload(payload, 'cleanup');
  return [
    ...getPayloadPrelude(payload, 'cleanup'),
    ...administratorGuard(),
    "$agentRoadRoot='C:\\ProgramData\\AgentRoad'",
    ...restrictedAclFunctions(),
    ...longPathResolutionFunctions(),
    `if($payload.snapshotOwned){if(-not (Test-Path -LiteralPath $root -PathType Container)){throw 'missing transfer root'};$rootItem=Get-Item -LiteralPath $root -Force;if(-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'unsafe transfer root'};Assert-AgentRoadRestrictedDirectoryAcl $agentRoadRoot;Assert-AgentRoadRestrictedDirectoryAcl $root;$rootHandle=Open-AgentRoadDirectoryHandle $root;try{$rootIdentity=Get-AgentRoadDirectoryHandleIdentity $rootHandle;if(Test-Path -LiteralPath $snapshotPath){${[
      ...stagedFileGuard("throw 'unsafe snapshot cleanup'", '$snapshotPath', '$snapshotItem'),
      "if($snapshotItem.Length -ne $payload.expectedBytes){throw 'snapshot cleanup size mismatch'}",
      '$snapshotHash=(Get-FileHash -LiteralPath $snapshotPath -Algorithm SHA256).Hash',
      "if($snapshotHash -cne $payload.expectedSha256){throw 'snapshot cleanup hash mismatch'}",
      '$finalRootIdentity=Get-AgentRoadDirectoryHandleIdentity $rootHandle',
      "if($finalRootIdentity -cne $rootIdentity){throw 'transfer root changed'}",
      'Remove-Item -LiteralPath $snapshotPath -Force -ErrorAction Stop',
    ].join(';')}};if(Test-Path -LiteralPath $snapshotPath){throw 'snapshot cleanup failed'}}finally{$rootHandle.Dispose()}}`,
    "[Console]::Out.Write('AGENT_ROAD_GET_CLEANED')",
  ].join(';');
}

function provisionBasePrelude(payload, expectedProperties) {
  return [
    "$ErrorActionPreference='Stop'",
    "$ProgressPreference='SilentlyContinue'",
    'Set-StrictMode -Version 2.0',
    `$payloadJson=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}'))`,
    '$payload=$payloadJson|ConvertFrom-Json',
    '$propertyNames=@($payload.PSObject.Properties.Name)',
    `if(@($payload.PSObject.Properties).Count -ne ${expectedProperties} -or $propertyNames -cnotcontains 'schemaVersion' -or $propertyNames -cnotcontains 'operationId' -or $propertyNames -cnotcontains 'manifestDigest' -or $payload.schemaVersion -isnot [int] -or $payload.schemaVersion -ne 1 -or $payload.operationId -isnot [string] -or $payload.operationId -cnotmatch '^[a-f0-9]{32}$' -or $payload.manifestDigest -isnot [string] -or $payload.manifestDigest -cnotmatch '^[A-F0-9]{64}$'){throw 'invalid provision payload'}`,
    "$agentRoadRoot='C:\\ProgramData\\AgentRoad'",
    "$runtimeRoot=[IO.Path]::Combine($agentRoadRoot,'runtime')",
    "$stagingRoot=[IO.Path]::Combine($runtimeRoot,'staging')",
    '$operationRoot=[IO.Path]::Combine($stagingRoot,$payload.operationId)',
    '$transactionRoot=[IO.Path]::Combine($operationRoot,$payload.manifestDigest)',
    "$filesRoot=[IO.Path]::Combine($transactionRoot,'files')",
    'foreach($candidate in @($agentRoadRoot,$runtimeRoot,$stagingRoot,$operationRoot,$transactionRoot,$filesRoot)){if([IO.Path]::GetFullPath($candidate) -cne $candidate){throw \'invalid provision path\'}}',
    "if([IO.Path]::GetDirectoryName($runtimeRoot) -cne $agentRoadRoot -or [IO.Path]::GetDirectoryName($stagingRoot) -cne $runtimeRoot -or [IO.Path]::GetDirectoryName($operationRoot) -cne $stagingRoot -or [IO.Path]::GetDirectoryName($transactionRoot) -cne $operationRoot -or [IO.Path]::GetDirectoryName($filesRoot) -cne $transactionRoot){throw 'invalid provision path'}",
  ];
}

function provisionDirectoryFunctions() {
  return [
    "function Assert-AgentRoadProvisionDirectory([string]$candidate){if(-not (Test-Path -LiteralPath $candidate -PathType Container)){throw 'missing provision directory'};$item=Get-Item -LiteralPath $candidate -Force;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'unsafe provision directory'};Assert-AgentRoadRestrictedDirectoryAcl $candidate}",
    "function Ensure-AgentRoadProvisionDirectory([string]$candidate){if(Test-Path -LiteralPath $candidate){Assert-AgentRoadProvisionDirectory $candidate}else{[IO.Directory]::CreateDirectory($candidate,(New-AgentRoadRestrictedDirectorySecurity))|Out-Null;Assert-AgentRoadProvisionDirectory $candidate}}",
  ];
}

function provisionFileFunctions() {
  return [
    "function Assert-AgentRoadProvisionTemporaryAcl([string]$candidate){$acl=[IO.File]::GetAccessControl($candidate);$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;$current=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;if(-not $acl.AreAccessRulesCanonical -or $owner -cnotin @($current,'S-1-5-32-544') -or $rules.Count -ne 2){throw 'unsafe provision temp acl'};$seen=@();foreach($rule in $rules){$sid=[string]$rule.IdentityReference.Value;if($sid -cnotin @('S-1-5-18','S-1-5-32-544') -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl){throw 'unsafe provision temp acl'};$seen+=$sid};foreach($sid in @('S-1-5-18','S-1-5-32-544')){if($seen -cnotcontains $sid){throw 'unsafe provision temp acl'}}}",
    "function Assert-AgentRoadProvisionFile([string]$candidate,[long]$expectedBytes,[string]$expectedSha256,[bool]$final){$item=Get-Item -LiteralPath $candidate -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -ne $expectedBytes){throw 'unsafe provision file'};if($final){Assert-AgentRoadRestrictedFileAcl $candidate}else{Assert-AgentRoadProvisionTemporaryAcl $candidate};$actual=(Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash;if($actual -cne $expectedSha256){throw 'provision hash mismatch'}}",
    "function Get-AgentRoadProvisionState([string]$finalPath,[string]$tempPath,[long]$expectedBytes,[string]$expectedSha256){$hasFinal=Test-Path -LiteralPath $finalPath;$hasTemp=Test-Path -LiteralPath $tempPath;if($hasFinal -and $hasTemp){throw 'duplicate provision entry'};if($hasFinal){Assert-AgentRoadProvisionFile $finalPath $expectedBytes $expectedSha256 $true;return 'F'};if($hasTemp){Assert-AgentRoadProvisionFile $tempPath $expectedBytes $expectedSha256 $false;return 'T'};return 'M'}",
  ];
}

function provisionEntryStatements() {
  return [
    "if($payload.entryType -ceq 'artifact'){$finalName=$payload.artifactId+'-'+$payload.version+'.zip';$tempName='.'+$payload.artifactId+'-'+$payload.version+'-'+$payload.expectedSha256+'.upload';$entryRoot=$filesRoot}else{$finalName='capsule.json';$tempName='.capsule-'+$payload.expectedSha256+'.upload';$entryRoot=$transactionRoot}",
    '$finalPath=[IO.Path]::Combine($entryRoot,$finalName)',
    '$tempPath=[IO.Path]::Combine($entryRoot,$tempName)',
    "if([IO.Path]::GetFullPath($finalPath) -cne $finalPath -or [IO.Path]::GetFullPath($tempPath) -cne $tempPath -or [IO.Path]::GetDirectoryName($finalPath) -cne $entryRoot -or [IO.Path]::GetDirectoryName($tempPath) -cne $entryRoot){throw 'invalid provision entry path'}",
  ];
}

function provisionInitWrapper(payload) {
  validateProvisionPayload(payload, 'init');
  return [
    ...provisionBasePrelude(payload, 3),
    ...administratorGuard(),
    ...restrictedAclFunctions(),
    ...provisionDirectoryFunctions(),
    'Assert-AgentRoadProvisionDirectory $agentRoadRoot',
    'foreach($candidate in @($runtimeRoot,$stagingRoot)){Ensure-AgentRoadProvisionDirectory $candidate}',
    "if(Test-Path -LiteralPath $operationRoot){Assert-AgentRoadProvisionDirectory $operationRoot;$allowedOperationEntries=@($payload.manifestDigest,'work',('work-'+$payload.manifestDigest));$operationEntries=@(Get-ChildItem -LiteralPath $operationRoot -Force);foreach($item in $operationEntries){if(-not $item.PSIsContainer -or $allowedOperationEntries -cnotcontains $item.Name){throw 'provision operation conflict'};Assert-AgentRoadProvisionDirectory $item.FullName};if(($operationEntries.Name -ccontains 'work') -and ($operationEntries.Name -ccontains ('work-'+$payload.manifestDigest))){throw 'provision operation conflict'};if((($operationEntries.Name -ccontains 'work') -or ($operationEntries.Name -ccontains ('work-'+$payload.manifestDigest))) -and ($operationEntries.Name -cnotcontains $payload.manifestDigest)){throw 'provision operation conflict'}}else{Ensure-AgentRoadProvisionDirectory $operationRoot}",
    'foreach($candidate in @($transactionRoot,$filesRoot)){Ensure-AgentRoadProvisionDirectory $candidate}',
    "[Console]::Out.Write('AGENT_ROAD_PROVISION_INIT_OK')",
  ].join(';');
}

function provisionInspectWrapper(payload) {
  validateProvisionPayload(payload, 'inspect');
  return [
    ...provisionBasePrelude(payload, 5),
    ...administratorGuard(),
    ...restrictedAclFunctions(),
    ...provisionDirectoryFunctions(),
    ...provisionFileFunctions(),
    "$propertyNames=@($payload.PSObject.Properties.Name);if($propertyNames -cnotcontains 'components' -or $propertyNames -cnotcontains 'capsule'){throw 'invalid provision inspect payload'}",
    'foreach($candidate in @($agentRoadRoot,$runtimeRoot,$stagingRoot,$operationRoot,$transactionRoot,$filesRoot)){Assert-AgentRoadProvisionDirectory $candidate}',
    "$components=@($payload.components);if($components.Count -lt 1 -or $components.Count -gt 32){throw 'invalid provision components'}",
    '$allowedFiles=@();$states=New-Object Collections.Generic.List[string];$previous=$null',
    `foreach($component in $components){$names=@($component.PSObject.Properties.Name);if(@($component.PSObject.Properties).Count -ne 4 -or $names -cnotcontains 'artifactId' -or $names -cnotcontains 'version' -or $names -cnotcontains 'expectedBytes' -or $names -cnotcontains 'expectedSha256' -or $component.artifactId -isnot [string] -or $component.artifactId -cnotmatch '^[a-z][a-z0-9-]{0,63}$' -or $component.version -isnot [string] -or $component.version.Length -gt 64 -or $component.version -cnotmatch '^(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)$' -or $component.expectedBytes -isnot [int] -or $component.expectedBytes -lt 1 -or $component.expectedBytes -gt 268435456 -or $component.expectedSha256 -isnot [string] -or $component.expectedSha256 -cnotmatch '^[A-F0-9]{64}$' -or ($null -ne $previous -and [string]::CompareOrdinal([string]$component.artifactId,[string]$previous) -le 0)){throw 'invalid provision component'};$previous=$component.artifactId;$finalName=$component.artifactId+'-'+$component.version+'.zip';$tempName='.'+$component.artifactId+'-'+$component.version+'-'+$component.expectedSha256+'.upload';if($allowedFiles -ccontains $finalName -or $allowedFiles -ccontains $tempName){throw 'duplicate provision component'};$allowedFiles+=@($finalName,$tempName);$finalPath=[IO.Path]::Combine($filesRoot,$finalName);$tempPath=[IO.Path]::Combine($filesRoot,$tempName);$states.Add((Get-AgentRoadProvisionState $finalPath $tempPath $component.expectedBytes $component.expectedSha256))}`,
    "foreach($item in @(Get-ChildItem -LiteralPath $filesRoot -Force)){if($item.PSIsContainer -or $allowedFiles -cnotcontains $item.Name){throw 'unexpected provision residue'}}",
    "$capsuleNames=@($payload.capsule.PSObject.Properties.Name);if(@($payload.capsule.PSObject.Properties).Count -ne 2 -or $capsuleNames -cnotcontains 'expectedBytes' -or $capsuleNames -cnotcontains 'expectedSha256' -or $payload.capsule.expectedBytes -isnot [int] -or $payload.capsule.expectedBytes -lt 1 -or $payload.capsule.expectedBytes -gt 268435456 -or $payload.capsule.expectedSha256 -isnot [string] -or $payload.capsule.expectedSha256 -cnotmatch '^[A-F0-9]{64}$'){throw 'invalid provision capsule'}",
    "$capsuleFinal=[IO.Path]::Combine($transactionRoot,'capsule.json');$capsuleTemp=[IO.Path]::Combine($transactionRoot,('.capsule-'+$payload.capsule.expectedSha256+'.upload'));$capsuleState=Get-AgentRoadProvisionState $capsuleFinal $capsuleTemp $payload.capsule.expectedBytes $payload.capsule.expectedSha256",
    "$allowedTransaction=@('files','capsule.json',('.capsule-'+$payload.capsule.expectedSha256+'.upload'));foreach($item in @(Get-ChildItem -LiteralPath $transactionRoot -Force)){if($allowedTransaction -cnotcontains $item.Name -or ($item.Name -ceq 'files' -and -not $item.PSIsContainer) -or ($item.Name -cne 'files' -and $item.PSIsContainer)){throw 'unexpected provision residue'}}",
    "[Console]::Out.Write('AGENT_ROAD_PROVISION_INSPECT:'+([string]::Join(',',@($states)))+':'+$capsuleState)",
  ].join(';');
}

function provisionEntryWrapper(payload, phase) {
  validateProvisionPayload(payload, phase);
  const marker = phase === 'finalize'
    ? 'AGENT_ROAD_PROVISION_FINALIZED'
    : 'AGENT_ROAD_PROVISION_CLEANED';
  const action = phase === 'finalize'
    ? [
      '$state=Get-AgentRoadProvisionState $finalPath $tempPath $payload.expectedBytes $payload.expectedSha256',
      "if($state -ceq 'M'){throw 'missing provision temp'}",
      "if($state -ceq 'T'){Set-AgentRoadRestrictedFileAcl $tempPath;Assert-AgentRoadProvisionFile $tempPath $payload.expectedBytes $payload.expectedSha256 $true;if(Test-Path -LiteralPath $finalPath){throw 'provision final collision'};[IO.File]::Move($tempPath,$finalPath);Assert-AgentRoadProvisionFile $finalPath $payload.expectedBytes $payload.expectedSha256 $true;if(Test-Path -LiteralPath $tempPath){throw 'provision temp remained'}}",
    ]
    : [
      '$hasFinal=Test-Path -LiteralPath $finalPath;$hasTemp=Test-Path -LiteralPath $tempPath',
      "if($hasFinal){Assert-AgentRoadProvisionFile $finalPath $payload.expectedBytes $payload.expectedSha256 $true;if($hasTemp){throw 'duplicate provision entry'}}elseif($hasTemp){Assert-AgentRoadProvisionFile $tempPath $payload.expectedBytes $payload.expectedSha256 $false;Remove-Item -LiteralPath $tempPath -Force -ErrorAction Stop;if(Test-Path -LiteralPath $tempPath){throw 'provision cleanup failed'}}",
    ];
  return [
    ...provisionBasePrelude(payload, 8),
    ...administratorGuard(),
    ...restrictedAclFunctions(),
    ...provisionDirectoryFunctions(),
    ...provisionFileFunctions(),
    "$propertyNames=@($payload.PSObject.Properties.Name);if($propertyNames -cnotcontains 'entryType' -or $propertyNames -cnotcontains 'artifactId' -or $propertyNames -cnotcontains 'version' -or $propertyNames -cnotcontains 'expectedBytes' -or $propertyNames -cnotcontains 'expectedSha256' -or $payload.entryType -cnotin @('artifact','capsule') -or $payload.expectedBytes -isnot [int] -or $payload.expectedBytes -lt 1 -or $payload.expectedBytes -gt 268435456 -or $payload.expectedSha256 -isnot [string] -or $payload.expectedSha256 -cnotmatch '^[A-F0-9]{64}$' -or ($payload.entryType -ceq 'artifact' -and ($payload.artifactId -isnot [string] -or $payload.artifactId -cnotmatch '^[a-z][a-z0-9-]{0,63}$' -or $payload.version -isnot [string] -or $payload.version.Length -gt 64 -or $payload.version -cnotmatch '^(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)$')) -or ($payload.entryType -ceq 'capsule' -and ($null -ne $payload.artifactId -or $null -ne $payload.version))){throw 'invalid provision entry payload'}",
    'foreach($candidate in @($agentRoadRoot,$runtimeRoot,$stagingRoot,$operationRoot,$transactionRoot,$filesRoot)){Assert-AgentRoadProvisionDirectory $candidate}',
    ...provisionEntryStatements(),
    ...action,
    `[Console]::Out.Write('${marker}')`,
  ].join(';');
}

function provisionFinalizeWrapper(payload) {
  return provisionEntryWrapper(payload, 'finalize');
}

function provisionCleanupWrapper(payload) {
  return provisionEntryWrapper(payload, 'cleanup');
}

function exactRecoveryFields(value, fields) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || Object.keys(value).length !== fields.length
    || !fields.every((field) => Object.hasOwn(value, field))
  ) failInput();
  return value;
}

function recoveryBootMarker(value) {
  exactRecoveryFields(value, [
    'channel',
    'eventId',
    'eventRecordId',
    'markerDigest',
    'providerGuid',
    'schemaVersion',
    'startTime',
    'timeCreated',
    'version',
  ]);
  if (
    value.schemaVersion !== 1
    || value.providerGuid !== RECOVERY_BOOT_PROVIDER_GUID
    || value.channel !== 'System'
    || value.eventId !== 12
    || !Number.isInteger(value.version)
    || value.version < 0
    || value.version > 255
    || typeof value.eventRecordId !== 'string'
    || !/^(?:0|[1-9][0-9]{0,19})$/u.test(value.eventRecordId)
    || BigInt(value.eventRecordId) < 1n
    || BigInt(value.eventRecordId) > 18_446_744_073_709_551_615n
    || typeof value.timeCreated !== 'string'
    || !RECOVERY_TIMESTAMP_PATTERN.test(value.timeCreated)
    || new Date(value.timeCreated).toISOString() !== value.timeCreated
    || typeof value.startTime !== 'string'
    || !RECOVERY_TIMESTAMP_PATTERN.test(value.startTime)
    || new Date(value.startTime).toISOString() !== value.startTime
    || typeof value.markerDigest !== 'string'
    || !SHA256_PATTERN.test(value.markerDigest)
  ) failInput();
  const canonical = {
    schemaVersion: 1,
    providerGuid: value.providerGuid,
    channel: 'System',
    eventId: 12,
    version: value.version,
    eventRecordId: value.eventRecordId,
    timeCreated: value.timeCreated,
    startTime: value.startTime,
  };
  const digest = createHash('sha256')
    .update('AGENT_ROAD_WINDOWS_BOOT_EVENT_12_V1\0', 'utf8')
    .update(JSON.stringify(canonical), 'utf8')
    .digest('hex')
    .toUpperCase();
  if (value.markerDigest !== digest) failInput();
  return value;
}

function recoveryAcl(value) {
  exactRecoveryFields(value, [
    'accessRuleCount',
    'aclDigest',
    'administratorsFullControl',
    'canonical',
    'ownerSid',
    'protected',
    'systemFullControl',
  ]);
  if (
    value.ownerSid !== 'S-1-5-32-544'
    || value.protected !== true
    || value.canonical !== true
    || value.accessRuleCount !== 2
    || value.administratorsFullControl !== true
    || value.systemFullControl !== true
    || value.aclDigest !== RECOVERY_ACL_DIGEST
  ) failInput();
  return value;
}

function recoveryChildren(value, expected) {
  if (
    !Array.isArray(value)
    || value.length !== expected.length
    || value.some((entry, index) => entry !== expected[index])
  ) failInput();
}

function recoveryDirectory(value, expectedChildren) {
  exactRecoveryFields(value, [
    'acl',
    'directChildCount',
    'directChildren',
    'fileId',
    'volumeSerialNumber',
  ]);
  if (
    typeof value.volumeSerialNumber !== 'string'
    || !/^[A-F0-9]{16}$/u.test(value.volumeSerialNumber)
    || typeof value.fileId !== 'string'
    || !/^[A-F0-9]{32}$/u.test(value.fileId)
    || value.directChildCount !== expectedChildren.length
  ) failInput();
  recoveryAcl(value.acl);
  recoveryChildren(value.directChildren, expectedChildren);
  return value;
}

function recoveryPriorAttempt(value) {
  if (value === null) return null;
  exactRecoveryFields(value, ['attemptDigest', 'ticketId']);
  if (
    typeof value.ticketId !== 'string'
    || !RECOVERY_TICKET_ID_PATTERN.test(value.ticketId)
    || typeof value.attemptDigest !== 'string'
    || !SHA256_PATTERN.test(value.attemptDigest)
  ) failInput();
  return value;
}

function validateRecoveryInspectPayload(payload) {
  const value = decodeCanonicalPayload(payload);
  exactRecoveryFields(value, [
    'beforeBootMarker',
    'operationId',
    'protocolRevision',
    'schemaVersion',
  ]);
  if (
    value.schemaVersion !== 1
    || value.protocolRevision !== 1
    || typeof value.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(value.operationId)
  ) failInput();
  if (value.beforeBootMarker !== null) recoveryBootMarker(value.beforeBootMarker);
  return value;
}

function validateRecoveryApplyPayload(payload) {
  const value = decodeCanonicalPayload(payload);
  exactRecoveryFields(value, [
    'authorizedAttemptDigest',
    'expectedWindowsProof',
    'operationId',
    'protocolRevision',
    'schemaVersion',
  ]);
  if (
    value.schemaVersion !== 1
    || value.protocolRevision !== 1
    || typeof value.operationId !== 'string'
    || !OPERATION_ID_PATTERN.test(value.operationId)
    || typeof value.authorizedAttemptDigest !== 'string'
    || !SHA256_PATTERN.test(value.authorizedAttemptDigest)
  ) failInput();
  const proof = exactRecoveryFields(value.expectedWindowsProof, [
    'agentRoadAcl',
    'afterBootMarker',
    'beforeBootMarker',
    'classification',
    'operationDirectory',
    'priorAuthorizedAttempt',
    'runtimeDirectory',
    'stagingDirectory',
  ]);
  recoveryBootMarker(proof.beforeBootMarker);
  recoveryBootMarker(proof.afterBootMarker);
  if (
    BigInt(proof.afterBootMarker.eventRecordId) <= BigInt(proof.beforeBootMarker.eventRecordId)
    || proof.afterBootMarker.markerDigest === proof.beforeBootMarker.markerDigest
    || !['EMPTY_PRE_TRANSACTION', 'ALREADY_ABSENT'].includes(proof.classification)
  ) failInput();
  const empty = proof.classification === 'EMPTY_PRE_TRANSACTION';
  const prior = recoveryPriorAttempt(proof.priorAuthorizedAttempt);
  if ((empty && prior !== null) || (!empty && prior === null)) failInput();
  recoveryAcl(proof.agentRoadAcl);
  recoveryDirectory(proof.runtimeDirectory, ['staging']);
  recoveryDirectory(proof.stagingDirectory, empty ? [value.operationId] : []);
  if (empty) recoveryDirectory(proof.operationDirectory, []);
  else if (proof.operationDirectory !== null) failInput();
  const identities = [
    proof.runtimeDirectory,
    proof.stagingDirectory,
    proof.operationDirectory,
  ].filter((entry) => entry !== null).map((entry) => (
    `${entry.volumeSerialNumber}:${entry.fileId}`
  ));
  if (new Set(identities).size !== identities.length) failInput();
  return value;
}

const RECOVERY_NATIVE_INSPECT = String.raw`using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace AgentRoadRecovery {
[StructLayout(LayoutKind.Sequential)] public struct FILE_ID_128 {[MarshalAs(UnmanagedType.ByValArray,SizeConst=16)] public byte[] Identifier;}
[StructLayout(LayoutKind.Sequential)] public struct FILE_ID_INFO {public ulong VolumeSerialNumber;public FILE_ID_128 FileId;}
[StructLayout(LayoutKind.Sequential)] public struct FILE_ATTRIBUTE_TAG_INFO {public uint FileAttributes;public uint ReparseTag;}
public static class NativeMethods {
public const int FileAttributeTagInfo=9;
public const int FileIdInfo=18;
[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern SafeFileHandle CreateFileW(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
[DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] public static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,int informationClass,out FILE_ID_INFO information,uint size);
[DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] public static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,int informationClass,out FILE_ATTRIBUTE_TAG_INFO information,uint size);
}}
`;

const RECOVERY_NATIVE_APPLY = String.raw`using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace AgentRoadRecovery {
[StructLayout(LayoutKind.Sequential)] public struct FILE_ID_128 {[MarshalAs(UnmanagedType.ByValArray,SizeConst=16)] public byte[] Identifier;}
[StructLayout(LayoutKind.Sequential)] public struct FILE_ID_INFO {public ulong VolumeSerialNumber;public FILE_ID_128 FileId;}
[StructLayout(LayoutKind.Sequential)] public struct FILE_ATTRIBUTE_TAG_INFO {public uint FileAttributes;public uint ReparseTag;}
[StructLayout(LayoutKind.Sequential)] public struct FILE_DISPOSITION_INFO {public byte DeleteFile;}
public static class NativeMethods {
public const int FileAttributeTagInfo=9;
public const int FileIdInfo=18;
public const int FileDispositionInfo=4;
[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern SafeFileHandle CreateFileW(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
[DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] public static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,int informationClass,out FILE_ID_INFO information,uint size);
[DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] public static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,int informationClass,out FILE_ATTRIBUTE_TAG_INFO information,uint size);
[DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] public static extern bool SetFileInformationByHandle(SafeFileHandle handle,int informationClass,ref FILE_DISPOSITION_INFO information,uint size);
}}
`;

function inspectStageSource(stage, apply = false) {
  if (!WINDOWS_INSPECT_STAGES.includes(stage)) throw new Error('invalid inspect stage');
  return apply ? '' : `$script:agentRoadInspectStage='${stage}';`;
}

function recoveryPayloadPrelude(payload, apply) {
  const count = apply ? 5 : 4;
  const fields = apply
    ? "@('authorizedAttemptDigest','expectedWindowsProof','operationId','protocolRevision','schemaVersion')"
    : "@('beforeBootMarker','operationId','protocolRevision','schemaVersion')";
  const trap = apply
    ? "trap{if($deleteDispatched){[Environment]::Exit(74)};$code=[string]$_.Exception.Message;$known=@('RUNTIME_INPUT_INVALID','RUNTIME_BOOT_IDENTITY_UNAVAILABLE','RUNTIME_REBOOT_REQUIRED','RUNTIME_OPERATION_CONFLICT','RUNTIME_STATE_UNSUPPORTED','RUNTIME_ALREADY_RUNNING');if($code -cnotin $known){$code='RUNTIME_STATE_UNSUPPORTED'};$record=[pscustomobject][ordered]@{schemaVersion=1;error=$code};[Console]::Out.Write(($record|ConvertTo-Json -Compress));[Environment]::Exit(73)}"
    : "trap{$code=[string]$_.Exception.Message;$known=@('RUNTIME_INPUT_INVALID','RUNTIME_BOOT_IDENTITY_UNAVAILABLE','RUNTIME_REBOOT_REQUIRED','RUNTIME_OPERATION_CONFLICT','RUNTIME_STATE_UNSUPPORTED');if($code -cnotin $known){$code='RUNTIME_STATE_UNSUPPORTED'};$record=[pscustomobject][ordered]@{schemaVersion=2;error=$code;stage=$script:agentRoadInspectStage};[Console]::Out.Write(($record|ConvertTo-Json -Compress));[Environment]::Exit(73)}";
  return [
    "$ErrorActionPreference='Stop'",
    "$ProgressPreference='SilentlyContinue'",
    ...(apply ? ['$deleteDispatched=$false'] : []),
    ...(apply ? [] : [inspectStageSource('WINDOWS_INPUT')]),
    trap,
    "$utf8=New-Object Text.UTF8Encoding($false,$true)",
    `$payloadJson=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}'))`,
    '$payload=$payloadJson|ConvertFrom-Json -ErrorAction Stop',
    "function Assert-ExactRecord([object]$v,[string[]]$f,[string]$e){if($null -eq $v -or $v -isnot [pscustomobject]){throw $e};$n=@($v.PSObject.Properties.Name);if($n.Count -ne $f.Count){throw $e};for($i=0;$i -lt $f.Count;$i++){if([string]::CompareOrdinal([string]$n[$i],[string]$f[$i]) -ne 0){throw $e}}}",
    `Assert-ExactRecord $payload ${fields} 'RUNTIME_INPUT_INVALID'`,
    `if(@($payload.PSObject.Properties).Count -ne ${count} -or $payload.schemaVersion -isnot [int] -or $payload.schemaVersion -ne 1 -or $payload.protocolRevision -isnot [int] -or $payload.protocolRevision -ne 1 -or $payload.operationId -isnot [string] -or $payload.operationId -cnotmatch '^[a-f0-9]{32}$'){throw 'RUNTIME_INPUT_INVALID'}`,
  ];
}

function recoveryCommonSource(payload, apply) {
  const native = apply ? RECOVERY_NATIVE_APPLY : RECOVERY_NATIVE_INSPECT;
  return [
    ...recoveryPayloadPrelude(payload, apply),
    ...(apply ? [] : [inspectStageSource('WINDOWS_NATIVE')]),
    `Add-Type -TypeDefinition @'\n${native}'@\n`,
    "function Get-Sha([string]$domain,[string]$json){$h=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($h.ComputeHash($utf8.GetBytes($domain+[char]0+$json))).Replace('-','')}finally{$h.Dispose()}}",
    "function Get-MarkerJson([object]$m){return '{\"schemaVersion\":1,\"providerGuid\":\"'+[string]$m.providerGuid+'\",\"channel\":\"System\",\"eventId\":12,\"version\":'+[string]$m.version+',\"eventRecordId\":\"'+[string]$m.eventRecordId+'\",\"timeCreated\":\"'+[string]$m.timeCreated+'\",\"startTime\":\"'+[string]$m.startTime+'\"}'}",
    "function Assert-Marker([object]$m){Assert-ExactRecord $m @('channel','eventId','eventRecordId','markerDigest','providerGuid','schemaVersion','startTime','timeCreated','version') 'RUNTIME_INPUT_INVALID';if($m.schemaVersion -isnot [int] -or $m.schemaVersion -ne 1 -or $m.providerGuid -isnot [string] -or $m.providerGuid -cne '{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}' -or $m.channel -isnot [string] -or $m.channel -cne 'System' -or $m.eventId -isnot [int] -or $m.eventId -ne 12 -or $m.version -isnot [int] -or $m.version -lt 0 -or $m.version -gt 255 -or $m.eventRecordId -isnot [string] -or $m.eventRecordId -cnotmatch '^(?:0|[1-9][0-9]{0,19})$' -or $m.timeCreated -isnot [string] -or $m.timeCreated -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$' -or $m.startTime -isnot [string] -or $m.startTime -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$' -or $m.markerDigest -isnot [string] -or $m.markerDigest -cnotmatch '^[A-F0-9]{64}$'){throw 'RUNTIME_INPUT_INVALID'};$id=[uint64]0;if(-not [uint64]::TryParse($m.eventRecordId,[Globalization.NumberStyles]::None,[Globalization.CultureInfo]::InvariantCulture,[ref]$id) -or $id -eq 0){throw 'RUNTIME_INPUT_INVALID'};$j=Get-MarkerJson $m;if((Get-Sha 'AGENT_ROAD_WINDOWS_BOOT_EVENT_12_V1' $j) -cne $m.markerDigest){throw 'RUNTIME_INPUT_INVALID'}}",
    "function New-AclFact{return [pscustomobject][ordered]@{ownerSid='S-1-5-32-544';protected=$true;canonical=$true;accessRuleCount=2;administratorsFullControl=$true;systemFullControl=$true;aclDigest='DD88275C41BC223A8C77B8E2CA108226DDDE5F39D2B044AD84AEFB31B9643C44'}}",
    "function Assert-Acl([string]$path){" + inspectStageSource('WINDOWS_ACL', apply) + "try{$a=[IO.Directory]::GetAccessControl($path);$r=@($a.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]));$o=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value;if(-not $a.AreAccessRulesProtected -or -not $a.AreAccessRulesCanonical -or $o -cne 'S-1-5-32-544' -or $r.Count -ne 2){throw 0};$seen=@();$inherit=([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit);foreach($x in $r){$sid=[string]$x.IdentityReference.Value;if($x.IsInherited -or $sid -cnotin @('S-1-5-18','S-1-5-32-544') -or $seen -ccontains $sid -or $x.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $x.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $x.InheritanceFlags -ne $inherit -or $x.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None){throw 0};$seen+=$sid};if($seen -cnotcontains 'S-1-5-18' -or $seen -cnotcontains 'S-1-5-32-544'){throw 0};return New-AclFact}catch{throw 'RUNTIME_STATE_UNSUPPORTED'}}",
    "function Open-Directory([string]$path,[bool]$deleteAccess){" + inspectStageSource('WINDOWS_DIRECTORY_OPEN', apply) + "if([IO.Path]::GetFullPath($path) -cne $path){throw 'RUNTIME_STATE_UNSUPPORTED'};$access=[uint32](0x1 -bor 0x80);if($deleteAccess){$access=$access -bor 0x00010000};$h=[AgentRoadRecovery.NativeMethods]::CreateFileW($path,$access,0x3,[IntPtr]::Zero,3,0x02200000,[IntPtr]::Zero);if($h.IsInvalid){$h.Dispose();throw 'RUNTIME_STATE_UNSUPPORTED'};try{$tag=New-Object AgentRoadRecovery.FILE_ATTRIBUTE_TAG_INFO;if(-not [AgentRoadRecovery.NativeMethods]::GetFileInformationByHandleEx($h,[AgentRoadRecovery.NativeMethods]::FileAttributeTagInfo,[ref]$tag,[Runtime.InteropServices.Marshal]::SizeOf([type][AgentRoadRecovery.FILE_ATTRIBUTE_TAG_INFO])) -or ($tag.FileAttributes -band [IO.FileAttributes]::Directory) -eq 0 -or ($tag.FileAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'RUNTIME_STATE_UNSUPPORTED'};return $h}catch{$h.Dispose();throw}}",
    "function Get-Identity([object]$h){" + inspectStageSource('WINDOWS_IDENTITY', apply) + "$i=New-Object AgentRoadRecovery.FILE_ID_INFO;if(-not [AgentRoadRecovery.NativeMethods]::GetFileInformationByHandleEx($h,[AgentRoadRecovery.NativeMethods]::FileIdInfo,[ref]$i,[Runtime.InteropServices.Marshal]::SizeOf([type][AgentRoadRecovery.FILE_ID_INFO])) -or $null -eq $i.FileId.Identifier -or $i.FileId.Identifier.Count -ne 16){throw 'RUNTIME_STATE_UNSUPPORTED'};$v=$i.VolumeSerialNumber.ToString('X16',[Globalization.CultureInfo]::InvariantCulture);$b=New-Object Text.StringBuilder;foreach($x in $i.FileId.Identifier){$null=$b.Append($x.ToString('X2',[Globalization.CultureInfo]::InvariantCulture))};return @($v,$b.ToString())}",
    "function Get-DirectChildren([string]$path,[int]$maximum){" + inspectStageSource('WINDOWS_CHILDREN', apply) + "$values=New-Object Collections.Generic.List[string];$enumerator=[IO.Directory]::EnumerateFileSystemEntries($path).GetEnumerator();try{while($enumerator.MoveNext()){if($values.Count -ge $maximum){throw 'RUNTIME_STATE_UNSUPPORTED'};$name=[IO.Path]::GetFileName([string]$enumerator.Current);if([string]::IsNullOrEmpty($name)){throw 'RUNTIME_STATE_UNSUPPORTED'};$values.Add($name)}}finally{if($enumerator -is [IDisposable]){$enumerator.Dispose()}};return $values.ToArray()}",
    "function New-DirectoryFact([string]$path,[object]$handle,[string[]]$children){$identity=Get-Identity $handle;return [pscustomobject][ordered]@{volumeSerialNumber=$identity[0];fileId=$identity[1];acl=(Assert-Acl $path);directChildCount=$children.Count;directChildren=@($children)}}",
    "function Close-RecoveryState([object]$state){if($null -eq $state){return};foreach($name in @('operationHandle','stagingHandle','runtimeHandle','agentRoadHandle','programDataHandle')){$h=$state.$name;if($null -ne $h){$h.Dispose();$state.$name=$null}}}",
    "function Get-AgentRoadRecoveryState([bool]$deleteAccess){$program=$null;$agent=$null;$runtime=$null;$staging=$null;$operation=$null;try{$programPath='C:\\ProgramData';$agentPath='C:\\ProgramData\\AgentRoad';$runtimePath=[IO.Path]::Combine($agentPath,'runtime');$stagingPath=[IO.Path]::Combine($runtimePath,'staging');$operationPath=[IO.Path]::Combine($stagingPath,[string]$payload.operationId);$program=Open-Directory $programPath $false;$agent=Open-Directory $agentPath $false;$runtime=Open-Directory $runtimePath $false;$staging=Open-Directory $stagingPath $false;$programIdentity=Get-Identity $program;$agentIdentity=Get-Identity $agent;$agentAcl=Assert-Acl $agentPath;$runtimeChildren=@(Get-DirectChildren $runtimePath 1);if($runtimeChildren.Count -ne 1 -or [string]::CompareOrdinal([string]$runtimeChildren[0],'staging') -ne 0){throw 'RUNTIME_STATE_UNSUPPORTED'};$stagingChildren=@(Get-DirectChildren $stagingPath 1);$raw=$null;if($stagingChildren.Count -eq 0){$raw='CLEAN_ABSENT'}elseif($stagingChildren.Count -eq 1 -and [string]::CompareOrdinal([string]$stagingChildren[0],[string]$payload.operationId) -eq 0){$raw='EMPTY_PRE_TRANSACTION';$operation=Open-Directory $operationPath $deleteAccess;$operationChildren=@(Get-DirectChildren $operationPath 0)}elseif($stagingChildren.Count -eq 1 -and $stagingChildren[0] -cmatch '^[a-f0-9]{32}$'){throw 'RUNTIME_OPERATION_CONFLICT'}else{throw 'RUNTIME_STATE_UNSUPPORTED'};$runtimeFact=New-DirectoryFact $runtimePath $runtime $runtimeChildren;$stagingFact=New-DirectoryFact $stagingPath $staging $stagingChildren;$operationFact=if($null -eq $operation){$null}else{New-DirectoryFact $operationPath $operation $operationChildren};return [pscustomobject]@{rawClassification=$raw;agentRoadAcl=$agentAcl;runtimeDirectory=$runtimeFact;stagingDirectory=$stagingFact;operationDirectory=$operationFact;programDataHandle=$program;agentRoadHandle=$agent;runtimeHandle=$runtime;stagingHandle=$staging;operationHandle=$operation;programDataIdentity=$programIdentity;agentRoadIdentity=$agentIdentity;agentRoadPath=$agentPath;runtimePath=$runtimePath;stagingPath=$stagingPath;operationPath=$operationPath}}catch{foreach($h in @($operation,$staging,$runtime,$agent,$program)){if($null -ne $h){$h.Dispose()}};throw}}",
    "function Assert-ChildList([string[]]$actual,[string[]]$expected){if($actual.Count -ne $expected.Count){throw 'RUNTIME_STATE_UNSUPPORTED'};for($i=0;$i -lt $expected.Count;$i++){if([string]::CompareOrdinal([string]$actual[$i],[string]$expected[$i]) -ne 0){throw 'RUNTIME_STATE_UNSUPPORTED'}}}",
    "function Assert-RecoveryStateStable([object]$state){$programIdentity=Get-Identity $state.programDataHandle;$agentIdentity=Get-Identity $state.agentRoadHandle;if($programIdentity[0] -cne $state.programDataIdentity[0] -or $programIdentity[1] -cne $state.programDataIdentity[1] -or $agentIdentity[0] -cne $state.agentRoadIdentity[0] -or $agentIdentity[1] -cne $state.agentRoadIdentity[1]){throw 'RUNTIME_STATE_UNSUPPORTED'};$runtimeChildren=@(Get-DirectChildren $state.runtimePath 1);$stagingChildren=@(Get-DirectChildren $state.stagingPath 1);Assert-ChildList $runtimeChildren @($state.runtimeDirectory.directChildren);Assert-ChildList $stagingChildren @($state.stagingDirectory.directChildren);$runtimeFact=New-DirectoryFact $state.runtimePath $state.runtimeHandle $runtimeChildren;$stagingFact=New-DirectoryFact $state.stagingPath $state.stagingHandle $stagingChildren;if(($runtimeFact|ConvertTo-Json -Compress -Depth 8) -cne ($state.runtimeDirectory|ConvertTo-Json -Compress -Depth 8) -or ($stagingFact|ConvertTo-Json -Compress -Depth 8) -cne ($state.stagingDirectory|ConvertTo-Json -Compress -Depth 8) -or ((Assert-Acl $state.agentRoadPath)|ConvertTo-Json -Compress) -cne ($state.agentRoadAcl|ConvertTo-Json -Compress)){throw 'RUNTIME_STATE_UNSUPPORTED'};if($null -ne $state.operationHandle){$operationChildren=@(Get-DirectChildren $state.operationPath 0);$operationFact=New-DirectoryFact $state.operationPath $state.operationHandle $operationChildren;if(($operationFact|ConvertTo-Json -Compress -Depth 8) -cne ($state.operationDirectory|ConvertTo-Json -Compress -Depth 8)){throw 'RUNTIME_STATE_UNSUPPORTED'}}}",
    "function Convert-EventMarker([object]$event){try{if($null -eq $event -or $event.ProviderId.ToString('B').ToLowerInvariant() -cne '{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}' -or [string]$event.LogName -cne 'System' -or [int]$event.Id -ne 12 -or $null -eq $event.Version -or [int]$event.Version -lt 0 -or [int]$event.Version -gt 255 -or $null -eq $event.RecordId -or [uint64]$event.RecordId -eq 0 -or $null -eq $event.TimeCreated){throw 0};$xml=New-Object Xml.XmlDocument;$xml.XmlResolver=$null;$xml.LoadXml($event.ToXml());$nodes=@($xml.SelectNodes(\"/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data']\"));if($nodes.Count -lt 1 -or $nodes.Count -gt 64){throw 0};$start=@($nodes|Where-Object{$_.GetAttribute('Name') -ceq 'StartTime'});if($start.Count -ne 1){throw 0};$text=[string]$start[0].InnerText;if($text.Length -lt 20 -or $text.Length -gt 64 -or $text -cne $text.Trim() -or $text -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,7})?Z$'){throw 0};$dto=[DateTimeOffset]::Parse($text,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None);$created=([DateTime]$event.TimeCreated).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ',[Globalization.CultureInfo]::InvariantCulture);$started=$dto.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ',[Globalization.CultureInfo]::InvariantCulture);$m=[pscustomobject][ordered]@{schemaVersion=1;providerGuid='{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}';channel='System';eventId=12;version=[int]$event.Version;eventRecordId=([uint64]$event.RecordId).ToString([Globalization.CultureInfo]::InvariantCulture);timeCreated=$created;startTime=$started};$j=Get-MarkerJson $m;$m|Add-Member -NotePropertyName markerDigest -NotePropertyValue (Get-Sha 'AGENT_ROAD_WINDOWS_BOOT_EVENT_12_V1' $j);return $m}catch{throw 'RUNTIME_BOOT_IDENTITY_UNAVAILABLE'}}",
    "function Read-EventPair([string]$query,[bool]$reverse){$q=New-Object Diagnostics.Eventing.Reader.EventLogQuery('System',[Diagnostics.Eventing.Reader.PathType]::LogName,$query);$q.ReverseDirection=$reverse;$reader=New-Object Diagnostics.Eventing.Reader.EventLogReader($q);try{$first=$reader.ReadEvent();$second=$reader.ReadEvent();if($null -ne $first){$first};if($null -ne $second){$second}}finally{$reader.Dispose()}}",
    "function Read-LatestBootMarker{$query=\"*[System[Provider[@Guid='{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}'] and (EventID=12)]]\";try{$events=@(Read-EventPair $query $true);if($events.Count -lt 1 -or $null -eq $events[0]){throw 0};$first=Convert-EventMarker $events[0];if($events.Count -gt 1 -and $null -ne $events[1]){$second=Convert-EventMarker $events[1];if([uint64]$first.eventRecordId -le [uint64]$second.eventRecordId){throw 0}};return $first}catch{throw 'RUNTIME_BOOT_IDENTITY_UNAVAILABLE'}finally{foreach($event in @($events)){if($null -ne $event){$event.Dispose()}}}}",
    "function Get-BootMarker([object]$before){$latest=Read-LatestBootMarker;if($null -eq $before){return $latest};Assert-Marker $before;$id=[string]$before.eventRecordId;$query=\"*[System[Provider[@Guid='{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}'] and (EventID=12) and (EventRecordID=$id)]]\";try{$events=@(Read-EventPair $query $false);if($events.Count -ne 1 -or $null -eq $events[0]){throw 0};$prior=Convert-EventMarker $events[0];if((Get-MarkerJson $prior) -cne (Get-MarkerJson $before) -or $prior.markerDigest -cne $before.markerDigest){throw 0}}catch{throw 'RUNTIME_BOOT_IDENTITY_UNAVAILABLE'}finally{foreach($event in @($events)){if($null -ne $event){$event.Dispose()}}};if([uint64]$latest.eventRecordId -le [uint64]$before.eventRecordId -or $latest.markerDigest -ceq $before.markerDigest){throw 'RUNTIME_REBOOT_REQUIRED'};return $latest}",
    "function Assert-Administrator{$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=New-Object Security.Principal.WindowsPrincipal($identity);if(($identity.Name -split '\\\\')[-1] -cne 'AgentRoad' -or -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'RUNTIME_STATE_UNSUPPORTED'}}",
  ];
}

function recoveryWindowsPayloadValidators(apply) {
  const common = [
    "function Assert-AclPayload([object]$a){Assert-ExactRecord $a @('accessRuleCount','aclDigest','administratorsFullControl','canonical','ownerSid','protected','systemFullControl') 'RUNTIME_INPUT_INVALID';if($a.accessRuleCount -isnot [int] -or $a.accessRuleCount -ne 2 -or $a.aclDigest -isnot [string] -or $a.aclDigest -cne 'DD88275C41BC223A8C77B8E2CA108226DDDE5F39D2B044AD84AEFB31B9643C44' -or $a.administratorsFullControl -isnot [bool] -or -not $a.administratorsFullControl -or $a.canonical -isnot [bool] -or -not $a.canonical -or $a.ownerSid -isnot [string] -or $a.ownerSid -cne 'S-1-5-32-544' -or $a.protected -isnot [bool] -or -not $a.protected -or $a.systemFullControl -isnot [bool] -or -not $a.systemFullControl){throw 'RUNTIME_INPUT_INVALID'}}",
    "function Assert-DirectoryPayload([object]$d,[string[]]$children){Assert-ExactRecord $d @('acl','directChildCount','directChildren','fileId','volumeSerialNumber') 'RUNTIME_INPUT_INVALID';if($d.volumeSerialNumber -isnot [string] -or $d.volumeSerialNumber -cnotmatch '^[A-F0-9]{16}$' -or $d.fileId -isnot [string] -or $d.fileId -cnotmatch '^[A-F0-9]{32}$' -or $d.directChildCount -isnot [int] -or $d.directChildCount -ne $children.Count){throw 'RUNTIME_INPUT_INVALID'};Assert-AclPayload $d.acl;$actual=@($d.directChildren);if($actual.Count -ne $children.Count){throw 'RUNTIME_INPUT_INVALID'};for($i=0;$i -lt $children.Count;$i++){if($actual[$i] -isnot [string] -or [string]::CompareOrdinal([string]$actual[$i],[string]$children[$i]) -ne 0){throw 'RUNTIME_INPUT_INVALID'}}}",
    "function Assert-PriorAttempt([object]$p){Assert-ExactRecord $p @('attemptDigest','ticketId') 'RUNTIME_INPUT_INVALID';if($p.attemptDigest -isnot [string] -or $p.attemptDigest -cnotmatch '^[A-F0-9]{64}$' -or $p.ticketId -isnot [string] -or $p.ticketId -cnotmatch '^rct_[a-f0-9]{64}$'){throw 'RUNTIME_INPUT_INVALID'}}",
  ];
  if (!apply) {
    return [
      ...common,
      "if($null -ne $payload.beforeBootMarker){Assert-Marker $payload.beforeBootMarker}",
    ];
  }
  return [
    ...common,
    "if($payload.authorizedAttemptDigest -isnot [string] -or $payload.authorizedAttemptDigest -cnotmatch '^[A-F0-9]{64}$'){throw 'RUNTIME_INPUT_INVALID'}",
    "Assert-ExactRecord $payload.expectedWindowsProof @('afterBootMarker','agentRoadAcl','beforeBootMarker','classification','operationDirectory','priorAuthorizedAttempt','runtimeDirectory','stagingDirectory') 'RUNTIME_INPUT_INVALID'",
    '$expected=$payload.expectedWindowsProof',
    'Assert-Marker $expected.beforeBootMarker',
    'Assert-Marker $expected.afterBootMarker',
    "if([uint64]$expected.afterBootMarker.eventRecordId -le [uint64]$expected.beforeBootMarker.eventRecordId -or $expected.afterBootMarker.markerDigest -ceq $expected.beforeBootMarker.markerDigest -or $expected.classification -isnot [string] -or $expected.classification -cnotin @('EMPTY_PRE_TRANSACTION','ALREADY_ABSENT')){throw 'RUNTIME_INPUT_INVALID'}",
    '$empty=$expected.classification -ceq \'EMPTY_PRE_TRANSACTION\'',
    "if($empty){if($null -ne $expected.priorAuthorizedAttempt){throw 'RUNTIME_INPUT_INVALID'}}else{if($null -eq $expected.priorAuthorizedAttempt){throw 'RUNTIME_INPUT_INVALID'};Assert-PriorAttempt $expected.priorAuthorizedAttempt}",
    'Assert-AclPayload $expected.agentRoadAcl',
    "Assert-DirectoryPayload $expected.runtimeDirectory @('staging')",
    'if($empty){Assert-DirectoryPayload $expected.stagingDirectory @([string]$payload.operationId);if($null -eq $expected.operationDirectory){throw \'RUNTIME_INPUT_INVALID\'};Assert-DirectoryPayload $expected.operationDirectory @()}else{Assert-DirectoryPayload $expected.stagingDirectory @();if($null -ne $expected.operationDirectory){throw \'RUNTIME_INPUT_INVALID\'}}',
    "$identities=@([string]$expected.runtimeDirectory.volumeSerialNumber+':'+[string]$expected.runtimeDirectory.fileId,[string]$expected.stagingDirectory.volumeSerialNumber+':'+[string]$expected.stagingDirectory.fileId);if($empty){$identities+=@([string]$expected.operationDirectory.volumeSerialNumber+':'+[string]$expected.operationDirectory.fileId)};if(@($identities|Select-Object -Unique).Count -ne $identities.Count){throw 'RUNTIME_INPUT_INVALID'}",
    "function Normalize-Marker([object]$m){return [pscustomobject][ordered]@{schemaVersion=1;providerGuid=[string]$m.providerGuid;channel='System';eventId=12;version=[int]$m.version;eventRecordId=[string]$m.eventRecordId;timeCreated=[string]$m.timeCreated;startTime=[string]$m.startTime;markerDigest=[string]$m.markerDigest}}",
    "function Normalize-Acl([object]$a){return [pscustomobject][ordered]@{ownerSid='S-1-5-32-544';protected=$true;canonical=$true;accessRuleCount=2;administratorsFullControl=$true;systemFullControl=$true;aclDigest='DD88275C41BC223A8C77B8E2CA108226DDDE5F39D2B044AD84AEFB31B9643C44'}}",
    "function Normalize-Directory([object]$d){return [pscustomobject][ordered]@{volumeSerialNumber=[string]$d.volumeSerialNumber;fileId=[string]$d.fileId;acl=(Normalize-Acl $d.acl);directChildCount=[int]$d.directChildCount;directChildren=@($d.directChildren)}}",
    "function Assert-Same([object]$actual,[object]$wanted){$a=$actual|ConvertTo-Json -Compress -Depth 12;$w=$wanted|ConvertTo-Json -Compress -Depth 12;if($a -cne $w){throw 'RUNTIME_STATE_UNSUPPORTED'}}",
    "function Assert-ProofState([object]$state,[object]$marker){$raw=if($expected.classification -ceq 'EMPTY_PRE_TRANSACTION'){'EMPTY_PRE_TRANSACTION'}else{'CLEAN_ABSENT'};if($state.rawClassification -cne $raw){throw 'RUNTIME_STATE_UNSUPPORTED'};Assert-Same $marker (Normalize-Marker $expected.afterBootMarker);Assert-Same $state.agentRoadAcl (Normalize-Acl $expected.agentRoadAcl);Assert-Same $state.runtimeDirectory (Normalize-Directory $expected.runtimeDirectory);Assert-Same $state.stagingDirectory (Normalize-Directory $expected.stagingDirectory);if($empty){Assert-Same $state.operationDirectory (Normalize-Directory $expected.operationDirectory)}elseif($null -ne $state.operationDirectory){throw 'RUNTIME_STATE_UNSUPPORTED'}}",
  ];
}

function recoveryInspectWrapper(payload) {
  validateRecoveryInspectPayload(payload);
  return [
    ...recoveryCommonSource(payload, false),
    inspectStageSource('WINDOWS_VALIDATION'),
    ...recoveryWindowsPayloadValidators(false),
    inspectStageSource('WINDOWS_ADMIN'),
    'Assert-Administrator',
    '$state=$null',
    '$exitCode=0',
    'try{',
    inspectStageSource('WINDOWS_STATE'),
    '$state=Get-AgentRoadRecoveryState $false',
    inspectStageSource('WINDOWS_BOOT'),
    '$marker=Get-BootMarker $payload.beforeBootMarker',
    inspectStageSource('WINDOWS_STABILITY'),
    'Assert-RecoveryStateStable $state',
    inspectStageSource('WINDOWS_OUTPUT'),
    "$record=[pscustomobject][ordered]@{schemaVersion=1;rawClassification=[string]$state.rawClassification;bootMarker=$marker;agentRoadAcl=$state.agentRoadAcl;runtimeDirectory=$state.runtimeDirectory;stagingDirectory=$state.stagingDirectory;operationDirectory=$state.operationDirectory}",
    '[Console]::Out.Write(($record|ConvertTo-Json -Compress -Depth 12))',
    '}catch{',
    "$code=[string]$_.Exception.Message;$known=@('RUNTIME_INPUT_INVALID','RUNTIME_BOOT_IDENTITY_UNAVAILABLE','RUNTIME_REBOOT_REQUIRED','RUNTIME_OPERATION_CONFLICT','RUNTIME_STATE_UNSUPPORTED');if($code -cnotin $known){$code='RUNTIME_STATE_UNSUPPORTED'};$record=[pscustomobject][ordered]@{schemaVersion=2;error=$code;stage=$script:agentRoadInspectStage};[Console]::Out.Write(($record|ConvertTo-Json -Compress));$exitCode=73",
    '}finally{Close-RecoveryState $state}',
    '[Environment]::Exit($exitCode)',
  ].join(';');
}

function recoveryApplyWrapper(payload) {
  validateRecoveryApplyPayload(payload);
  return [
    ...recoveryCommonSource(payload, true),
    ...recoveryWindowsPayloadValidators(true),
    "function Enter-RecoveryMutex{$mutex=$null;try{$security=New-Object Security.AccessControl.MutexSecurity;$security.SetAccessRuleProtection($true,$false);$system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18');$admins=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544');$security.SetOwner($admins.Translate([Security.Principal.NTAccount]));foreach($sid in @($system,$admins)){$security.AddAccessRule((New-Object Security.AccessControl.MutexAccessRule($sid,[Security.AccessControl.MutexRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow)))};$created=$false;$mutex=New-Object Threading.Mutex($false,'Global\\AgentRoadRuntimeMutation',[ref]$created,$security);$actual=$mutex.GetAccessControl();$owner=$actual.GetOwner([Security.Principal.SecurityIdentifier]).Value;$rules=@($actual.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]));if(-not $actual.AreAccessRulesProtected -or -not $actual.AreAccessRulesCanonical -or $owner -cne 'S-1-5-32-544' -or $rules.Count -ne 2){throw 'RUNTIME_STATE_UNSUPPORTED'};$seen=@();foreach($rule in $rules){$sid=[string]$rule.IdentityReference.Value;if($rule.IsInherited -or $sid -cnotin @('S-1-5-18','S-1-5-32-544') -or $seen -ccontains $sid -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.MutexRights -ne [Security.AccessControl.MutexRights]::FullControl -or $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None){throw 'RUNTIME_STATE_UNSUPPORTED'};$seen+=$sid};if($seen -cnotcontains 'S-1-5-18' -or $seen -cnotcontains 'S-1-5-32-544'){throw 'RUNTIME_STATE_UNSUPPORTED'};try{$acquired=$mutex.WaitOne(0)}catch [System.Threading.AbandonedMutexException]{$acquired=$true};if(-not $acquired){throw 'RUNTIME_ALREADY_RUNNING'};return $mutex}catch{if($null -ne $mutex){$mutex.Dispose()};throw}}",
    'Assert-Administrator',
    '$mutex=$null',
    '$state=$null',
    '$post=$null',
    '$operationHandle=$null',
    '$exitCode=0',
    'try{',
    '$mutex=Enter-RecoveryMutex',
    '$state=Get-AgentRoadRecoveryState $empty',
    '$marker=Get-BootMarker $expected.beforeBootMarker',
    'Assert-RecoveryStateStable $state',
    'Assert-ProofState $state $marker',
    "if($empty){$operationHandle=$state.operationHandle;$identity=Get-Identity $operationHandle;if($identity[0] -cne $state.operationDirectory.volumeSerialNumber -or $identity[1] -cne $state.operationDirectory.fileId){throw 'RUNTIME_STATE_UNSUPPORTED'};$null=@(Get-DirectChildren $state.operationPath 0);$disposition=New-Object AgentRoadRecovery.FILE_DISPOSITION_INFO;$disposition.DeleteFile=1;$deleteDispatched=$true;$deleteSucceeded=[AgentRoadRecovery.NativeMethods]::SetFileInformationByHandle($operationHandle,[AgentRoadRecovery.NativeMethods]::FileDispositionInfo,[ref]$disposition,[Runtime.InteropServices.Marshal]::SizeOf([type][AgentRoadRecovery.FILE_DISPOSITION_INFO]));$deleteError=[Runtime.InteropServices.Marshal]::GetLastWin32Error();if(-not $deleteSucceeded){$deleteDispatched=$false;throw 'RUNTIME_STATE_UNSUPPORTED'};$operationHandle.Dispose();$operationHandle=$null;$state.operationHandle=$null;$post=Get-AgentRoadRecoveryState $false;if($post.rawClassification -cne 'CLEAN_ABSENT' -or $post.runtimeDirectory.volumeSerialNumber -cne $state.runtimeDirectory.volumeSerialNumber -or $post.runtimeDirectory.fileId -cne $state.runtimeDirectory.fileId -or $post.stagingDirectory.volumeSerialNumber -cne $state.stagingDirectory.volumeSerialNumber -or $post.stagingDirectory.fileId -cne $state.stagingDirectory.fileId){throw 'RUNTIME_COMPLETION_UNCERTAIN'};$result=[pscustomobject][ordered]@{schemaVersion=1;disposition='REMOVED'}}else{$result=[pscustomobject][ordered]@{schemaVersion=1;disposition='ALREADY_ABSENT'}}",
    '[Console]::Out.Write(($result|ConvertTo-Json -Compress))',
    '}catch{',
    "if($deleteDispatched){$exitCode=74}else{$code=[string]$_.Exception.Message;$known=@('RUNTIME_INPUT_INVALID','RUNTIME_BOOT_IDENTITY_UNAVAILABLE','RUNTIME_REBOOT_REQUIRED','RUNTIME_OPERATION_CONFLICT','RUNTIME_STATE_UNSUPPORTED','RUNTIME_ALREADY_RUNNING');if($code -cnotin $known){$code='RUNTIME_STATE_UNSUPPORTED'};$record=[pscustomobject][ordered]@{schemaVersion=1;error=$code};[Console]::Out.Write(($record|ConvertTo-Json -Compress));$exitCode=73}",
    '}finally{',
    'if($null -ne $operationHandle){$operationHandle.Dispose()}',
    'Close-RecoveryState $post',
    'Close-RecoveryState $state',
    'if($null -ne $mutex){try{$mutex.ReleaseMutex()}finally{$mutex.Dispose()}}',
    '}',
    '[Environment]::Exit($exitCode)',
  ].join(';');
}

function administratorProbeWrapper(payload) {
  validateProbePayload(payload);
  return [
    "$ErrorActionPreference='Stop'",
    "$ProgressPreference='SilentlyContinue'",
    `$payloadJson=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}'))`,
    '$payload=$payloadJson|ConvertFrom-Json',
    '$propertyNames=@($payload.PSObject.Properties.Name)',
    `if(@($payload.PSObject.Properties).Count -ne 2 -or $propertyNames -cnotcontains 'schemaVersion' -or $propertyNames -cnotcontains 'operationId' -or $payload.schemaVersion -isnot [int] -or $payload.schemaVersion -ne 1 -or $payload.operationId -isnot [string] -or $payload.operationId -cnotmatch '^[a-f0-9]{32}$'){throw 'invalid probe payload'}`,
    '$identity=[Security.Principal.WindowsIdentity]::GetCurrent()',
    '$principal=New-Object Security.Principal.WindowsPrincipal($identity)',
    `if(($identity.Name -split '\\\\')[-1] -cne 'AgentRoad' -or -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'administrator probe failed'}`,
    `[Console]::Out.Write('${PROBE_OUTPUT}')`,
  ].join(';');
}

export const WINDOWS_ADMINISTRATOR_PROBE_WRAPPER = Object.freeze(administratorProbeWrapper);
TRUSTED_WRAPPERS.add(WINDOWS_ADMINISTRATOR_PROBE_WRAPPER);

export const WINDOWS_EXEC_PREFLIGHT_WRAPPER = Object.freeze(execPreflightWrapper);
export const WINDOWS_EXEC_VERIFY_WRAPPER = Object.freeze(execVerifyWrapper);
export const WINDOWS_EXEC_INVOKE_WRAPPER = Object.freeze(execInvokeWrapper);
export const WINDOWS_RUNTIME_PROVISION_INVOKE_WRAPPER = Object.freeze(
  runtimeProvisionInvokeWrapper,
);
export const WINDOWS_EXEC_READ_RESULT_WRAPPER = Object.freeze(execReadResultWrapper);
export const WINDOWS_EXEC_CLEANUP_WRAPPER = Object.freeze(execCleanupWrapper);
export const WINDOWS_EXEC_FINALIZE_WRAPPER = Object.freeze(execFinalizeWrapper);
TRUSTED_WRAPPERS.add(WINDOWS_EXEC_PREFLIGHT_WRAPPER);
TRUSTED_WRAPPERS.add(WINDOWS_EXEC_VERIFY_WRAPPER);
TRUSTED_WRAPPERS.add(WINDOWS_EXEC_INVOKE_WRAPPER);
TRUSTED_WRAPPERS.add(WINDOWS_RUNTIME_PROVISION_INVOKE_WRAPPER);
TRUSTED_WRAPPERS.add(WINDOWS_EXEC_READ_RESULT_WRAPPER);
TRUSTED_WRAPPERS.add(WINDOWS_EXEC_CLEANUP_WRAPPER);
TRUSTED_WRAPPERS.add(WINDOWS_EXEC_FINALIZE_WRAPPER);

export const WINDOWS_PUT_PREFLIGHT_WRAPPER = Object.freeze(putPreflightWrapper);
export const WINDOWS_PUT_PREPARE_WRAPPER = Object.freeze(putPrepareWrapper);
export const WINDOWS_PUT_PUBLISH_WRAPPER = Object.freeze(putPublishWrapper);
export const WINDOWS_PUT_CLEANUP_WRAPPER = Object.freeze(putCleanupWrapper);
TRUSTED_WRAPPERS.add(WINDOWS_PUT_PREFLIGHT_WRAPPER);
TRUSTED_WRAPPERS.add(WINDOWS_PUT_PREPARE_WRAPPER);
TRUSTED_WRAPPERS.add(WINDOWS_PUT_PUBLISH_WRAPPER);
TRUSTED_WRAPPERS.add(WINDOWS_PUT_CLEANUP_WRAPPER);

export const WINDOWS_GET_PREPARE_WRAPPER = Object.freeze(getPrepareWrapper);
export const WINDOWS_GET_CLEANUP_WRAPPER = Object.freeze(getCleanupWrapper);
TRUSTED_WRAPPERS.add(WINDOWS_GET_PREPARE_WRAPPER);
TRUSTED_WRAPPERS.add(WINDOWS_GET_CLEANUP_WRAPPER);

export const WINDOWS_PROVISION_INIT_WRAPPER = Object.freeze(provisionInitWrapper);
export const WINDOWS_PROVISION_INSPECT_WRAPPER = Object.freeze(provisionInspectWrapper);
export const WINDOWS_PROVISION_FINALIZE_WRAPPER = Object.freeze(provisionFinalizeWrapper);
export const WINDOWS_PROVISION_CLEANUP_WRAPPER = Object.freeze(provisionCleanupWrapper);
TRUSTED_WRAPPERS.add(WINDOWS_PROVISION_INIT_WRAPPER);
TRUSTED_WRAPPERS.add(WINDOWS_PROVISION_INSPECT_WRAPPER);
TRUSTED_WRAPPERS.add(WINDOWS_PROVISION_FINALIZE_WRAPPER);
TRUSTED_WRAPPERS.add(WINDOWS_PROVISION_CLEANUP_WRAPPER);

export const WINDOWS_RUNTIME_RECOVERY_INSPECT_WRAPPER = Object.freeze(
  recoveryInspectWrapper,
);
export const WINDOWS_RUNTIME_RECOVERY_APPLY_WRAPPER = Object.freeze(
  recoveryApplyWrapper,
);
TRUSTED_WRAPPERS.add(WINDOWS_RUNTIME_RECOVERY_INSPECT_WRAPPER);
TRUSTED_WRAPPERS.add(WINDOWS_RUNTIME_RECOVERY_APPLY_WRAPPER);

export function powershellInvocation(wrapper, payload) {
  if (typeof wrapper !== 'function' || !TRUSTED_WRAPPERS.has(wrapper)) failInput();
  let script;
  try {
    script = wrapper(payload);
  } catch (error) {
    if (error?.code === 'REMOTE_INPUT_INVALID') throw error;
    failInput();
  }
  if (
    typeof script !== 'string'
    || script.length === 0
    || script.includes('\0')
    || script.length > MAX_POWERSHELL_SOURCE_BYTES
  ) failInput();
  for (let index = 0; index < script.length; index += 1) {
    if (script.charCodeAt(index) > 0x7f) failInput();
  }
  const source = Buffer.from(script, 'ascii');
  const encoded = source.toString('base64');
  const chunks = [];
  for (let offset = 0; offset < encoded.length; offset += POWERSHELL_FRAME_CHUNK_CHARS) {
    chunks.push(encoded.slice(offset, offset + POWERSHELL_FRAME_CHUNK_CHARS));
  }
  const stdin = [
    POWERSHELL_FRAME_MAGIC,
    `L:${source.length}`,
    `H:${createHash('sha256').update(source).digest('hex').toUpperCase()}`,
    `C:${chunks.length}`,
    ...chunks,
    'END',
    '',
  ].join('\r\n');
  if (Buffer.byteLength(stdin, 'ascii') > MAX_POWERSHELL_STDIN_BYTES) failInput();
  return Object.freeze({
    argv: POWERSHELL_STDIN_ARGV,
    stdin,
  });
}

function snapshotAddresses(input) {
  if (
    !Array.isArray(input)
    || isProxy(input)
    || !Object.isFrozen(input)
    || Object.getPrototypeOf(input) !== Array.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
    || input.length === 0
    || input.length > 8
    || Object.getOwnPropertyNames(input).length !== input.length + 1
  ) failInput();
  const addresses = [];
  for (let index = 0; index < input.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !canonicalAddress(descriptor.value)) failInput();
    addresses.push(descriptor.value);
  }
  if (new Set(addresses).size !== addresses.length) failInput();
  return Object.freeze(addresses);
}

function snapshotSession(input) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
    || !Object.isFrozen(input)
    || Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) failInput();
  const values = Object.create(null);
  for (const key of Object.getOwnPropertyNames(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!SESSION_FIELDS.has(key) || !descriptor || !Object.hasOwn(descriptor, 'value')) failInput();
    values[key] = descriptor.value;
  }
  if (
    !Object.hasOwn(values, 'addresses')
    || !Object.hasOwn(values, 'invokeSsh')
    || typeof values.invokeSsh !== 'function'
    || isProxy(values.invokeSsh)
  ) failInput();
  return Object.freeze({
    addresses: snapshotAddresses(values.addresses),
    invokeSsh: values.invokeSsh,
  });
}

function snapshotProcessResult(input) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || isProxy(input)
    || (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)
    || Object.getOwnPropertySymbols(input).length !== 0
  ) throw remoteError('REMOTE_CONNECTION_FAILED');
  const result = Object.create(null);
  for (const key of Object.getOwnPropertyNames(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!PROCESS_RESULT_FIELDS.has(key) || !descriptor || !Object.hasOwn(descriptor, 'value')) {
      throw remoteError('REMOTE_CONNECTION_FAILED');
    }
    result[key] = descriptor.value;
  }
  for (const required of ['exitCode', 'signal', 'stdout', 'stderr']) {
    if (!Object.hasOwn(result, required)) throw remoteError('REMOTE_CONNECTION_FAILED');
  }
  return result;
}

export function mapPreMutationProcessError(input) {
  if (input !== null && (typeof input === 'object' || typeof input === 'function') && !isProxy(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, 'code');
    if (descriptor && Object.hasOwn(descriptor, 'value') && descriptor.value === 'PROCESS_OUTPUT_LIMIT') {
      return remoteError('REMOTE_OUTPUT_LIMIT');
    }
  }
  return remoteError('REMOTE_CONNECTION_FAILED');
}

async function invokeAdministratorProbe(session, address) {
  let result;
  try {
    const invocation = powershellInvocation(
      WINDOWS_ADMINISTRATOR_PROBE_WRAPPER,
      encodeRemotePayload({ schemaVersion: 1, operationId: PROBE_OPERATION_ID }),
    );
    result = await session.invokeSsh(
      address,
      invocation.argv,
      { timeoutMs: 10_000, maxOutputBytes: 4096, stdinText: invocation.stdin },
    );
  } catch (error) {
    throw mapPreMutationProcessError(error);
  }
  let snapshot;
  try {
    snapshot = snapshotProcessResult(result);
  } catch {
    throw remoteError('REMOTE_CONNECTION_FAILED');
  }
  if (
    snapshot.exitCode !== 0
    || snapshot.signal !== null
    || snapshot.stdout !== PROBE_OUTPUT
    || snapshot.stderr !== ''
  ) throw remoteError('REMOTE_CONNECTION_FAILED');
  return address;
}

export async function probeWindowsAdministrator(inputSession, inputAddress) {
  const session = snapshotSession(inputSession);
  if (!canonicalAddress(inputAddress) || !session.addresses.includes(inputAddress)) failInput();
  return invokeAdministratorProbe(session, inputAddress);
}

export async function selectAddress(inputSession) {
  const session = snapshotSession(inputSession);
  for (const address of session.addresses) {
    try {
      await invokeAdministratorProbe(session, address);
      return address;
    } catch {
      // Read-only probes may fall back; no mutation has started yet.
    }
  }
  throw remoteError('REMOTE_CONNECTION_FAILED');
}
