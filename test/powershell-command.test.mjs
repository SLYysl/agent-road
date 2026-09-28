import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildPowerShellEnrollmentCommand,
  encodePowerShellCommand,
} from '../src/enrollment/powershell-command.mjs';

const COMMAND_PREFIX = 'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ';

function decodeCommand(command) {
  assert.ok(command.startsWith(COMMAND_PREFIX));
  return Buffer.from(command.slice(COMMAND_PREFIX.length), 'base64').toString('utf16le');
}

function decodePayload(script) {
  const encoded = script.match(/FromBase64String\('([^']+)'\)/)?.[1];
  assert.ok(encoded, 'script must contain a Base64 payload');
  return JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
}

function validPayload(overrides = {}) {
  return {
    controllerUrl: 'https://controller.example.test/enroll',
    deviceId: 'dev_abc123',
    token: 'single-use-token-1234',
    ...overrides,
  };
}

test('encodes a canonical allowlisted enrollment payload in a one-line PowerShell command', () => {
  const command = buildPowerShellEnrollmentCommand(validPayload({
    controllerUrl: 'https://CONTROLLER.example.test:443/enroll',
  }));
  const script = decodeCommand(command);

  assert.equal(command.includes('single-use-token'), false);
  assert.deepEqual(decodePayload(script), {
    controllerUrl: 'https://controller.example.test/enroll',
    deviceId: 'dev_abc123',
    token: 'single-use-token-1234',
  });
  assert.match(script, /\[Convert\]::FromBase64String/);
  assert.match(script, /Invoke-RestMethod/);
  assert.match(script, /-MaximumRedirection 0/);
  assert.match(script, /-TimeoutSec 30/);
  assert.match(script, /\$null -eq \$result/);
  assert.match(script, /\$result -is \[System\.Collections\.IEnumerable\]/);
  assert.match(script, /\$result -isnot \[pscustomobject\]/);
  assert.match(script, /\$result\.PSObject\.Properties\)\.Count -ne 2/);
  assert.match(script, /\$propertyNames -cnotcontains 'status'/);
  assert.match(script, /\$propertyNames -cnotcontains 'deviceId'/);
  assert.match(script, /\$result\.status -isnot \[string\]/);
  assert.match(script, /\$result\.deviceId -isnot \[string\]/);
  assert.match(script, /\$result\.status -cne 'accepted'/);
  assert.match(script, /\$result\.deviceId -cne \$payload\.deviceId/);
  assert.match(script, /throw 'invalid enrollment response'/);
  assert.match(script, /Write-Output 'Enrollment accepted'/);
  assert.doesNotMatch(script, /ConvertTo-Json/);
});

test('makes the token recoverable only by decoding the copied command', () => {
  const command = buildPowerShellEnrollmentCommand(validPayload());

  assert.doesNotMatch(command, /single-use-token/);
  assert.equal(decodePayload(decodeCommand(command)).token, 'single-use-token-1234');
});

test('reads each input primitive once and never serializes the caller object', () => {
  let controllerUrlReads = 0;
  let deviceIdReads = 0;
  let tokenReads = 0;
  const payload = {
    get controllerUrl() {
      controllerUrlReads += 1;
      return 'https://controller.example.test/enroll';
    },
    get deviceId() {
      deviceIdReads += 1;
      return deviceIdReads === 1 ? 'dev_abc123' : 'dev_changed';
    },
    get token() {
      tokenReads += 1;
      return tokenReads === 1 ? 'single-use-token-1234' : 'changed-token';
    },
    toJSON() {
      throw new Error('caller object must not be serialized');
    },
  };

  const script = decodeCommand(buildPowerShellEnrollmentCommand(payload));

  assert.deepEqual(decodePayload(script), {
    controllerUrl: 'https://controller.example.test/enroll',
    deviceId: 'dev_abc123',
    token: 'single-use-token-1234',
  });
  assert.deepEqual({ controllerUrlReads, deviceIdReads, tokenReads }, {
    controllerUrlReads: 1,
    deviceIdReads: 1,
    tokenReads: 1,
  });
});

test('rejects unsafe controller URLs', () => {
  for (const controllerUrl of [
    'http://controller.example.test/enroll',
    ' https://controller.example.test/enroll',
    'https://user:password@controller.example.test/enroll',
    'https://controller.example.test/enroll#fragment',
    'https://localhost/enroll',
    'https://localhost./enroll',
    'https://host.localhost/enroll',
    'https://host.localhost./enroll',
    'https://127.0.0.1/enroll',
    'https://127.12.34.56/enroll',
    'https://[::1]/enroll',
    'https://[::ffff:127.0.0.1]/enroll',
  ]) {
    assert.throws(() => buildPowerShellEnrollmentCommand(validPayload({ controllerUrl })));
  }
});

test('rejects a non-string controller URL', () => {
  assert.throws(
    () => buildPowerShellEnrollmentCommand(validPayload({ controllerUrl: new URL('https://controller.example.test/enroll') })),
    /controller URL must be a string/,
  );
});

test('allows LAN, Tailscale, and MagicDNS controller hosts', () => {
  for (const controllerUrl of [
    'https://192.168.1.10/enroll',
    'https://100.64.0.1/enroll',
    'https://controller.tailnet-name.ts.net/enroll',
  ]) {
    assert.match(buildPowerShellEnrollmentCommand(validPayload({ controllerUrl })), /^powershell\.exe /);
  }
});

test('enforces input bounds and keeps the largest valid command below the Windows command limit', () => {
  assert.throws(() => buildPowerShellEnrollmentCommand(validPayload({ deviceId: `dev_${'a'.repeat(61)}` })), /device id/);
  assert.throws(() => buildPowerShellEnrollmentCommand(validPayload({ token: 'a'.repeat(15) })), /enrollment token/);
  assert.throws(() => buildPowerShellEnrollmentCommand(validPayload({ token: 'a'.repeat(129) })), /enrollment token/);
  assert.throws(() => buildPowerShellEnrollmentCommand(validPayload({ controllerUrl: `https://example.test/${'a'.repeat(2028)}` })), /controller URL/);

  const command = buildPowerShellEnrollmentCommand(validPayload({
    controllerUrl: `https://example.test/${'a'.repeat(2027)}`,
    deviceId: `dev_${'a'.repeat(60)}`,
    token: 'a'.repeat(128),
  }));
  assert.ok(command.length <= 32767);
});

test('rejects a valid-length URL when canonicalization expands its encoded command past the Windows command limit', () => {
  const controllerUrl = `https://example.test/${'\uffff'.repeat(2027)}`;

  assert.equal(controllerUrl.length, 2048);
  assert.throws(
    () => buildPowerShellEnrollmentCommand(validPayload({ controllerUrl })),
    /PowerShell enrollment command exceeds 32767 characters/,
  );
});

test('shared PowerShell encoding accepts only bounded one-line-safe script text', () => {
  assert.equal(decodeCommand(encodePowerShellCommand("Write-Output 'ok'")), "Write-Output 'ok'");
  assert.throws(() => encodePowerShellCommand(null), /PowerShell script must be a string/);
  assert.throws(() => encodePowerShellCommand('x'.repeat(13_000)), /exceeds 32767 characters/);
});
