import { randomUUID } from 'node:crypto';
import { mkdir, open } from 'node:fs/promises';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { trustedInput } from '../remote/remote-target.mjs';
import { selectAddress } from '../remote/windows-remote.mjs';
import { withTrustedSshSession } from '../ssh/trusted-ssh-session.mjs';
import { runProcess } from '../process/run-process.mjs';
import { buildStagedRetentionScript } from './staged-retention-windows.mjs';

function fail(code) { const error = new Error(code); error.code = code; throw error; }
export function retentionScriptInvocation(source) {
  if (typeof source !== 'string' || Buffer.byteLength(source) > 131_072) fail('RUNTIME_INPUT_INVALID');
  const encoded = gzipSync(Buffer.from(source)).toString('base64');
  if (encoded.length > 60_000) fail('RUNTIME_INPUT_INVALID');
  const loader = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$n=${encoded.length};$x=New-Object byte[] $n;$in=[Console]::OpenStandardInput();$offset=0;while($offset -lt $n){$got=$in.Read($x,$offset,$n-$offset);if($got -le 0){exit 88};$offset+=$got};$z=[Convert]::FromBase64String([Text.Encoding]::ASCII.GetString($x));$m=New-Object IO.MemoryStream(,$z);$g=New-Object IO.Compression.GZipStream($m,[IO.Compression.CompressionMode]::Decompress);$q=New-Object IO.MemoryStream;$buffer=New-Object byte[] 8192;while(($got=$g.Read($buffer,0,$buffer.Length)) -gt 0){if($q.Length+$got -gt 131072){exit 88};$q.Write($buffer,0,$got)};$g.Dispose();$m.Dispose();$text=[Text.Encoding]::UTF8.GetString($q.ToArray());$q.Dispose();& ([ScriptBlock]::Create($text))`;
  return Object.freeze({ argv: Object.freeze(['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
    '-EncodedCommand', Buffer.from(loader, 'utf16le').toString('base64')]), stdin: encoded });
}
export function parseStagedRetentionResponse(result) {
  if (result.exitCode !== 0 || result.signal !== null || result.stderr !== ''
    || typeof result.stdout !== 'string' || Buffer.byteLength(result.stdout) > 32_768) fail('RUNTIME_COMPLETION_UNCERTAIN');
  let value;
  try { value = JSON.parse(result.stdout); } catch { fail('RUNTIME_COMPLETION_UNCERTAIN'); }
  if (value === null || typeof value !== 'object' || Array.isArray(value)
    || JSON.stringify(value) !== result.stdout || Object.hasOwn(value, 'error')) fail('RUNTIME_COMPLETION_UNCERTAIN');
  return value;
}

// Every invocation has a private durable receipt before SSH. Raw output never
// goes to the terminal. Store consumption is a separate prerequisite for apply.
export async function executeStagedRetentionRemote({ target, bundle, input, captureRoot }) {
  const source = buildStagedRetentionScript(bundle, input);
  const invocation = retentionScriptInvocation(source);
  const directory = join(captureRoot, `retention-${input.mode}-${randomUUID()}`);
  await mkdir(directory, { mode: 0o700 });
  async function save(name, value) {
    const file = await open(join(directory, name), 'wx', 0o600);
    try { await file.writeFile(JSON.stringify(value) + '\n'); await file.sync(); } finally { await file.close(); }
    const parent = await open(directory, 'r');
    try { await parent.sync(); } finally { await parent.close(); }
  }
  await save('started.json', { mode: input.mode, executorDigest: bundle.executorDigest,
    proposalDigest: input.proposal?.proposalDigest ?? null, attemptDigest: input.attempt?.attemptDigest ?? null });
  let invoked = false;
  let process;
  try {
    process = await withTrustedSshSession(trustedInput(target, runProcess), async session => {
      const address = await selectAddress(session);
      await save('invoked.json', { mode: input.mode });
      invoked = true;
      return session.invokeSsh(address, invocation.argv, { stdinText: invocation.stdin,
        timeoutMs: 120_000, maxOutputBytes: 32_768 });
    });
    await save('terminal.json', { exitCode: process.exitCode, signal: process.signal, stdout: process.stdout, stderr: process.stderr });
  } catch {
    await save('stopped.json', { invoked, outcome: invoked ? 'UNKNOWN' : 'NOT_INVOKED' });
    fail(invoked ? 'RUNTIME_COMPLETION_UNCERTAIN' : 'RUNTIME_INVENTORY_FAILED');
  }
  return parseStagedRetentionResponse(process);
}
