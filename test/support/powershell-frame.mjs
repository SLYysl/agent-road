import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

export const POWERSHELL_FRAME_MAGIC = 'AGENT_ROAD_STDIN_V1';
export const POWERSHELL_FRAME_CHUNK_CHARS = 2048;

export function powerShellBootstrap(args) {
  assert.deepEqual(args.slice(0, 7), [
    'powershell.exe',
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-EncodedCommand',
  ]);
  assert.equal(args.length, 8);
  const bootstrap = Buffer.from(args[7], 'base64').toString('utf16le');
  assert.match(bootstrap, /^\$ProgressPreference='SilentlyContinue';/u);
  assert.doesNotMatch(bootstrap, /ReadToEnd/u);
  assert.match(bootstrap, /ReadLine/u);
  return bootstrap;
}

export function decodePowerShellFrame(stdin) {
  assert.equal(typeof stdin, 'string');
  const lines = stdin.split('\r\n');
  assert.equal(lines.pop(), '');
  assert.equal(lines.shift(), POWERSHELL_FRAME_MAGIC);

  const lengthMatch = /^L:([1-9][0-9]*)$/u.exec(lines.shift());
  const hashMatch = /^H:([A-F0-9]{64})$/u.exec(lines.shift());
  const countMatch = /^C:([1-9][0-9]*)$/u.exec(lines.shift());
  assert.ok(lengthMatch);
  assert.ok(hashMatch);
  assert.ok(countMatch);

  const expectedBytes = Number(lengthMatch[1]);
  assert.ok(expectedBytes <= 32 * 1024);
  const expectedBase64Length = 4 * Math.ceil(expectedBytes / 3);
  const expectedChunks = Math.ceil(expectedBase64Length / POWERSHELL_FRAME_CHUNK_CHARS);
  assert.equal(Number(countMatch[1]), expectedChunks);
  const chunks = lines.splice(0, expectedChunks);
  assert.equal(chunks.length, expectedChunks);
  assert.equal(lines.shift(), 'END');
  assert.deepEqual(lines, []);

  for (let index = 0; index < chunks.length; index += 1) {
    const expectedLength = index + 1 < chunks.length
      ? POWERSHELL_FRAME_CHUNK_CHARS
      : expectedBase64Length - (POWERSHELL_FRAME_CHUNK_CHARS * index);
    assert.equal(chunks[index].length, expectedLength);
    assert.match(chunks[index], /^[A-Za-z0-9+/]+={0,2}$/u);
    if (index + 1 < chunks.length) assert.doesNotMatch(chunks[index], /=/u);
  }

  const encoded = chunks.join('');
  const source = Buffer.from(encoded, 'base64');
  assert.equal(source.length, expectedBytes);
  assert.equal(source.toString('base64'), encoded);
  assert.equal(createHash('sha256').update(source).digest('hex').toUpperCase(), hashMatch[1]);
  assert.doesNotMatch(source.toString('latin1'), /[^\x01-\x7f]/u);
  return source.toString('ascii');
}

export function decodedPowerShell(args, options) {
  powerShellBootstrap(args);
  return decodePowerShellFrame(options.stdinText);
}
