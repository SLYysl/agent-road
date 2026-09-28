const COMMAND_PREFIX = 'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand';
const MAX_CONTROLLER_URL_LENGTH = 2048;
const MAX_COMMAND_LENGTH = 32767;

export function encodePowerShellCommand(script) {
  if (typeof script !== 'string') {
    throw new TypeError('PowerShell script must be a string');
  }
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  const command = `${COMMAND_PREFIX} ${encoded}`;
  if (command.length > MAX_COMMAND_LENGTH) {
    throw new Error('PowerShell enrollment command exceeds 32767 characters');
  }
  return command;
}

function isLoopbackHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  return host === 'localhost'
    || host.endsWith('.localhost')
    || /^127(?:\.\d{1,3}){3}$/.test(host)
    || host === '::1'
    || host.startsWith('::ffff:');
}

function validateControllerUrl(value) {
  if (typeof value !== 'string') {
    throw new Error('controller URL must be a string');
  }
  if (value.trim() !== value) {
    throw new Error('controller URL must not contain leading or trailing whitespace');
  }
  if (value.length > MAX_CONTROLLER_URL_LENGTH) {
    throw new Error('controller URL must be at most 2048 characters');
  }

  const url = new URL(value);
  if (url.protocol !== 'https:') {
    throw new Error('controller URL must use HTTPS');
  }
  if (url.username || url.password) {
    throw new Error('controller URL must not include userinfo');
  }
  if (url.hash) {
    throw new Error('controller URL must not include a fragment');
  }
  if (isLoopbackHost(url.hostname)) {
    throw new Error('controller URL must not target a loopback host');
  }
  return url;
}

export function buildPowerShellEnrollmentCommand(payload) {
  const controllerUrlValue = payload.controllerUrl;
  const deviceId = payload.deviceId;
  const token = payload.token;
  const url = validateControllerUrl(controllerUrlValue);

  if (typeof deviceId !== 'string' || !/^dev_[a-z0-9]+$/.test(deviceId) || deviceId.length > 64) {
    throw new Error('invalid device id');
  }
  if (typeof token !== 'string' || token.length < 16 || token.length > 128) {
    throw new Error('invalid enrollment token');
  }

  const enrollmentPayload = { deviceId, token, controllerUrl: url.href };
  const payloadBase64 = Buffer.from(JSON.stringify(enrollmentPayload), 'utf8').toString('base64');
  const script = [
    "$ErrorActionPreference = 'Stop'",
    `$payloadJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payloadBase64}'))`,
    '$payload = $payloadJson | ConvertFrom-Json',
    "$result = Invoke-RestMethod -Method Post -Uri $payload.controllerUrl -ContentType 'application/json' -Body $payloadJson -MaximumRedirection 0 -TimeoutSec 30",
    "if ($null -eq $result -or $result -is [System.Collections.IEnumerable] -or $result -isnot [pscustomobject]) { throw 'invalid enrollment response' }",
    '$propertyNames = @($result.PSObject.Properties.Name)',
    "if (@($result.PSObject.Properties).Count -ne 2 -or $propertyNames -cnotcontains 'status' -or $propertyNames -cnotcontains 'deviceId' -or $result.status -isnot [string] -or $result.deviceId -isnot [string] -or $result.status -cne 'accepted' -or $result.deviceId -cne $payload.deviceId) { throw 'invalid enrollment response' }",
    "Write-Output 'Enrollment accepted'",
  ].join('; ');
  return encodePowerShellCommand(script);
}
