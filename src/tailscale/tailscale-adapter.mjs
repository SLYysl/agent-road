import { access, lstat, realpath } from 'node:fs/promises';
import { constants } from 'node:fs';
import { isIP } from 'node:net';

import { runProcess as defaultRunProcess } from '../process/run-process.mjs';

const EXECUTABLE_CANDIDATES = [
  '/Applications/Tailscale.app/Contents/MacOS/Tailscale',
  '/opt/homebrew/bin/tailscale',
  '/usr/local/bin/tailscale',
  '/usr/bin/tailscale',
];
const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/;
const MAX_DEVICE_ID_LENGTH = 64;
const MAX_TAILSCALE_IPS = 8;
const MAX_CONSENT_URL_LENGTH = 2048;
const MAX_CONSENT_OUTPUT_SCAN = 16 * 1024;
const RECONCILIATION_DELAY_MS = 1_250;
const SERVE_SETUP_TIMEOUT_MS = 10_000;

function fixedError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

async function defaultFsProbe(path) {
  try {
    const resolvedPath = await realpath(path);
    const stats = await lstat(resolvedPath);
    if (!stats.isFile() || stats.isSymbolicLink()) {
      return false;
    }
    await access(resolvedPath, constants.X_OK);
    return {
      isFile: true,
      isSymbolicLink: false,
      isExecutable: true,
      resolvedPath,
    };
  } catch {
    return false;
  }
}

function resolvedExecutablePath(probeResult) {
  if (probeResult === null || typeof probeResult !== 'object') {
    return null;
  }
  if (
    probeResult.isFile === true
    && probeResult.isSymbolicLink === false
    && probeResult.isExecutable === true
    && typeof probeResult.resolvedPath === 'string'
    && probeResult.resolvedPath.length > 0
    && !probeResult.resolvedPath.includes('\0')
    && probeResult.resolvedPath.startsWith('/')
  ) {
    return probeResult.resolvedPath;
  }
  return null;
}

function defaultSleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function validateInjectedExecutable(executable) {
  if (
    typeof executable !== 'string'
    || executable.length === 0
    || executable.includes('\0')
    || !executable.startsWith('/')
  ) {
    throw new TypeError('executable must be an absolute path without NUL bytes');
  }
  return executable;
}

function canonicalizeDnsName(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 253 || value !== value.trim()) {
    return null;
  }
  const withoutTerminalDot = value.endsWith('.') ? value.slice(0, -1) : value;
  const dnsName = withoutTerminalDot.toLowerCase();
  const labels = dnsName.split('.');
  if (
    labels.length < 3
    || labels.at(-2) !== 'ts'
    || labels.at(-1) !== 'net'
    || !labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
  ) {
    return null;
  }
  return dnsName;
}

function canonicalizeIpAddress(value) {
  if (typeof value !== 'string' || value !== value.trim()) {
    return null;
  }
  const family = isIP(value);
  if (family === 4) {
    return value;
  }
  if (family !== 6) {
    return null;
  }
  try {
    const canonical = new URL(`http://[${value}]/`).hostname;
    return canonical.startsWith('[') && canonical.endsWith(']') ? canonical.slice(1, -1) : null;
  } catch {
    return null;
  }
}

function canonicalizeTailscaleIPs(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_TAILSCALE_IPS) {
    return null;
  }
  const canonical = value.map(canonicalizeIpAddress);
  if (canonical.some((address) => address === null) || new Set(canonical).size !== canonical.length) {
    return null;
  }
  return canonical;
}

function parseRunningStatus(stdout) {
  if (typeof stdout !== 'string') {
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return null;
  }
  if (parsed === null || Array.isArray(parsed) || Object.getPrototypeOf(parsed) !== Object.prototype) {
    return null;
  }
  if (parsed.BackendState !== 'Running' || parsed.Self === null || typeof parsed.Self !== 'object' || Array.isArray(parsed.Self)) {
    return null;
  }
  const dnsName = canonicalizeDnsName(parsed.Self.DNSName);
  const tailscaleIPs = canonicalizeTailscaleIPs(parsed.Self.TailscaleIPs);
  if (dnsName === null || tailscaleIPs === null) {
    return null;
  }
  return { backendState: 'Running', dnsName, tailscaleIPs };
}

function parsePlainJsonObject(stdout) {
  if (typeof stdout !== 'string') {
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return null;
  }
  if (parsed === null || Array.isArray(parsed) || Object.getPrototypeOf(parsed) !== Object.prototype) {
    return null;
  }
  return parsed;
}

function isPlainObject(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function hasExactKeys(value, keys) {
  if (!isPlainObject(value)) return false;
  const actualKeys = Object.keys(value);
  return actualKeys.length === keys.length && actualKeys.every((key) => keys.includes(key));
}

function isExactOwnedServeConfig(config, { dnsName, localPort, path }) {
  if (!hasExactKeys(config, ['TCP', 'Web'])) {
    return false;
  }
  if (!hasExactKeys(config.TCP, ['443']) || !hasExactKeys(config.TCP['443'], ['HTTPS']) || config.TCP['443'].HTTPS !== true) {
    return false;
  }
  const hostPort = `${dnsName}:443`;
  if (!hasExactKeys(config.Web, [hostPort]) || !hasExactKeys(config.Web[hostPort], ['Handlers'])) {
    return false;
  }
  const handlers = config.Web[hostPort].Handlers;
  return (
    hasExactKeys(handlers, [path])
    && hasExactKeys(handlers[path], ['Proxy'])
    && handlers[path].Proxy === `http://127.0.0.1:${localPort}`
  );
}

function sharedStatusesAreExactlyEmpty(statuses) {
  return Object.keys(statuses.serve).length === 0 && Object.keys(statuses.funnel).length === 0;
}

function findConsentUrl(...outputs) {
  for (const output of outputs) {
    if (typeof output !== 'string') {
      continue;
    }
    const scanLength = Math.min(output.length, MAX_CONSENT_OUTPUT_SCAN);
    const scannedOutput = output.slice(0, scanLength);
    const hasUnscannedOutput = output.length > scanLength;
    const matches = scannedOutput.matchAll(/https:\/\/login\.tailscale\.com\/[^\s<>"']*/giu);
    for (const match of matches) {
      const candidate = match[0];
      const endOffset = match.index + candidate.length;
      if (
        candidate.length > MAX_CONSENT_URL_LENGTH
        || (hasUnscannedOutput && endOffset === scanLength)
        || /[.,;:!?\)\]\}]$/u.test(candidate)
      ) {
        continue;
      }
      try {
        const url = new URL(candidate);
        if (
          url.protocol === 'https:'
          && url.hostname === 'login.tailscale.com'
          && url.username === ''
          && url.password === ''
          && url.port === ''
          && url.href === candidate
        ) {
          return candidate;
        }
      } catch {
        // A consent URL is the only output permitted in the public error details.
      }
    }
  }
  return null;
}

function createConsentObserver() {
  const chunks = { stdout: [], stderr: [] };
  const sizes = { stdout: 0, stderr: 0 };
  return {
    onOutput(stream, chunk) {
      if ((stream !== 'stdout' && stream !== 'stderr') || sizes[stream] >= MAX_CONSENT_OUTPUT_SCAN) return;
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const observed = buffer.subarray(0, MAX_CONSENT_OUTPUT_SCAN - sizes[stream]);
      chunks[stream].push(Buffer.from(observed));
      sizes[stream] += observed.length;
    },
    url() {
      return findConsentUrl(
        Buffer.concat(chunks.stdout).toString('utf8'),
        Buffer.concat(chunks.stderr).toString('utf8'),
      );
    },
  };
}

function validateServeInput(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('serve input must be an object');
  }
  const { deviceId, localPort } = input;
  if (
    typeof deviceId !== 'string'
    || deviceId.length > MAX_DEVICE_ID_LENGTH
    || !DEVICE_ID_PATTERN.test(deviceId)
  ) {
    throw new TypeError('invalid device id');
  }
  if (!Number.isInteger(localPort) || localPort < 1 || localPort > 65535) {
    throw new TypeError('localPort must be an integer from 1 to 65535');
  }
  return { deviceId, localPort };
}

export class TailscaleAdapter {
  #runProcess;
  #executable;
  #fsProbe;
  #sleep;
  #resolvedExecutable;

  constructor({ runProcess = defaultRunProcess, executable, fsProbe = defaultFsProbe, sleep = defaultSleep } = {}) {
    if (typeof runProcess !== 'function') {
      throw new TypeError('runProcess must be a function');
    }
    if (typeof fsProbe !== 'function') {
      throw new TypeError('fsProbe must be a function');
    }
    if (typeof sleep !== 'function') {
      throw new TypeError('sleep must be a function');
    }
    this.#runProcess = runProcess;
    this.#executable = executable === undefined ? undefined : validateInjectedExecutable(executable);
    this.#fsProbe = fsProbe;
    this.#sleep = sleep;
  }

  async #resolveExecutable() {
    if (this.#resolvedExecutable !== undefined) {
      return this.#resolvedExecutable;
    }
    if (this.#executable !== undefined) {
      this.#resolvedExecutable = this.#executable;
      return this.#resolvedExecutable;
    }
    for (const candidate of EXECUTABLE_CANDIDATES) {
      try {
        const resolvedPath = resolvedExecutablePath(await this.#fsProbe(candidate));
        if (resolvedPath !== null) {
          this.#resolvedExecutable = resolvedPath;
          return resolvedPath;
        }
      } catch {
        // Try only the fixed candidate list; no PATH lookup is ever used.
      }
    }
    throw fixedError('TAILSCALE_NOT_AVAILABLE_ON_MAC');
  }

  async #readRouteStatuses(executable, errorCode) {
    const statuses = {};
    let failed = false;
    for (const command of ['serve', 'funnel']) {
      try {
        const result = await this.#runProcess(executable, [command, 'status', '--json']);
        if (result?.exitCode !== 0) {
          throw new Error('nonzero route status');
        }
        const parsed = parsePlainJsonObject(result.stdout);
        if (parsed === null) {
          throw new Error('malformed route status');
        }
        statuses[command] = parsed;
      } catch {
        failed = true;
      }
    }
    if (failed) throw fixedError(errorCode);
    return statuses;
  }

  async #assertNoExistingRoutes(executable) {
    const statuses = await this.#readRouteStatuses(executable, 'TAILSCALE_SERVE_STATUS_FAILED');
    if (!sharedStatusesAreExactlyEmpty(statuses)) {
      throw fixedError('TAILSCALE_SERVE_CONFLICT');
    }
  }

  async #removeOwnedPathAndVerifyEmpty(executable, path, errorCode) {
    let cleanupWasAmbiguous = false;
    try {
      await this.#runProcess(executable, [
        'serve',
        '--https=443',
        `--set-path=${path}`,
        'off',
      ]);
    } catch {
      cleanupWasAmbiguous = true;
    }
    if (cleanupWasAmbiguous) {
      try {
        await this.#sleep(RECONCILIATION_DELAY_MS);
      } catch {
        throw fixedError(errorCode);
      }
    }
    const statuses = await this.#readRouteStatuses(executable, errorCode);
    if (!sharedStatusesAreExactlyEmpty(statuses)) {
      throw fixedError(errorCode);
    }
  }

  async #cleanupFailedPostvalidation(executable, ownership) {
    await this.#removeOwnedPathAndVerifyEmpty(
      executable,
      ownership.path,
      'TAILSCALE_SERVE_RECONCILIATION_FAILED',
    );
  }

  async #reconcileAmbiguousSetup(executable, path) {
    try {
      await this.#sleep(RECONCILIATION_DELAY_MS);
    } catch {
      throw fixedError('TAILSCALE_SERVE_RECONCILIATION_FAILED');
    }
    await this.#removeOwnedPathAndVerifyEmpty(
      executable,
      path,
      'TAILSCALE_SERVE_RECONCILIATION_FAILED',
    );
  }

  async status() {
    const executable = await this.#resolveExecutable();
    let result;
    try {
      result = await this.#runProcess(executable, ['status', '--json']);
      if (result?.exitCode !== 0) {
        throw new Error('nonzero status');
      }
    } catch {
      throw fixedError('TAILSCALE_NOT_RUNNING_ON_MAC');
    }
    let status;
    try {
      status = parseRunningStatus(result.stdout);
    } catch {
      throw fixedError('TAILSCALE_NOT_RUNNING_ON_MAC');
    }
    if (status === null) {
      throw fixedError('TAILSCALE_NOT_RUNNING_ON_MAC');
    }
    return status;
  }

  async serve(input) {
    const { deviceId, localPort } = validateServeInput(input);
    const status = await this.status();
    const path = `/agent-road/v1/${deviceId}`;
    const executable = await this.#resolveExecutable();
    await this.#assertNoExistingRoutes(executable);
    let result;
    const consentObserver = createConsentObserver();
    try {
      result = await this.#runProcess(executable, [
        'serve',
        '--bg',
        '--https=443',
        `--set-path=${path}`,
        `http://127.0.0.1:${localPort}`,
      ], {
        timeoutMs: SERVE_SETUP_TIMEOUT_MS,
        onOutput: consentObserver.onOutput,
      });
    } catch {
      const consentUrl = consentObserver.url();
      await this.#reconcileAmbiguousSetup(executable, path);
      if (consentUrl !== null) {
        const error = fixedError('TAILSCALE_SERVE_AUTH_REQUIRED');
        error.details = consentUrl;
        throw error;
      }
      throw fixedError('TAILSCALE_SERVE_FAILED');
    }
    try {
      if (result?.exitCode !== 0) {
        const consentUrl = findConsentUrl(result?.stdout, result?.stderr);
        if (consentUrl !== null) {
          const error = fixedError('TAILSCALE_SERVE_AUTH_REQUIRED');
          error.details = consentUrl;
          throw error;
        }
        throw fixedError('TAILSCALE_SERVE_FAILED');
      }
    } catch (error) {
      if (error?.code === 'TAILSCALE_SERVE_AUTH_REQUIRED' || error?.code === 'TAILSCALE_SERVE_FAILED') {
        throw error;
      }
      throw fixedError('TAILSCALE_SERVE_FAILED');
    }

    const ownership = { dnsName: status.dnsName, localPort, path };
    let postvalidationPassed = false;
    try {
      const statuses = await this.#readRouteStatuses(executable, 'TAILSCALE_SERVE_POSTVALIDATION_FAILED');
      postvalidationPassed = (
        isExactOwnedServeConfig(statuses.serve, ownership)
        && isExactOwnedServeConfig(statuses.funnel, ownership)
      );
    } catch {
      // The fixed public error is emitted only after exact-path cleanup is verified.
    }
    if (!postvalidationPassed) {
      await this.#cleanupFailedPostvalidation(executable, ownership);
      throw fixedError('TAILSCALE_SERVE_POSTVALIDATION_FAILED');
    }

    let closeInFlight;
    let closeSucceeded = false;
    const close = () => {
      if (closeSucceeded) {
        return Promise.resolve();
      }
      if (closeInFlight === undefined) {
        closeInFlight = this.#removeOwnedPathAndVerifyEmpty(
          executable,
          path,
          'TAILSCALE_SERVE_CLEANUP_FAILED',
        );
        void closeInFlight.then(
          () => {
            closeSucceeded = true;
            closeInFlight = undefined;
          },
          () => {
            closeInFlight = undefined;
          },
        );
      }
      return closeInFlight;
    };

    return {
      baseUrl: `https://${status.dnsName}${path}`,
      path,
      localPort,
      close,
    };
  }
}
