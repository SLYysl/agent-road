import { validateDeviceRecord } from '../core/device-model.mjs';
import { createEnrollment } from './create-enrollment.mjs';

const DNS_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.ts\.net$/;
const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/;
const VERIFIED_CAPABILITIES = Object.freeze(['ssh', 'sftp', 'admin-powershell']);
const MIN_SESSION_TTL_MS = 5 * 60 * 1000;
const MAX_SESSION_TTL_MS = 30 * 60 * 1000;
const COMPLETION_KEYS = new Set([
  'protocolVersion',
  'deviceId',
  'target',
  'tailscaleAddresses',
  'sshHostKeys',
  'sshHostKeyFingerprints',
  'checkpoints',
]);
const COMPLETION_CHECKPOINTS = Object.freeze([
  'preflight',
  'tailscale',
  'openssh',
  'account',
  'firewall',
]);

function fixedError(code, details) {
  const error = new Error(code);
  error.code = code;
  if (details !== undefined) error.details = details;
  return error;
}

function ownDataProperty(value, key) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
}

function canonicalConsentUrl(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048 || /[\s\x00-\x1f\x7f]/.test(value)) {
    return undefined;
  }
  try {
    const url = new URL(value);
    return url.protocol === 'https:'
      && url.hostname === 'login.tailscale.com'
      && url.username === ''
      && url.password === ''
      && url.port === ''
      && url.href === value
      && value.startsWith('https://login.tailscale.com/')
      ? value
      : undefined;
  } catch {
    return undefined;
  }
}

function mapFailure(error, phase) {
  const code = ownDataProperty(error, 'code');
  if (code === 'TAILSCALE_SERVE_AUTH_REQUIRED') {
    return fixedError('TAILSCALE_SERVE_AUTH_REQUIRED', canonicalConsentUrl(ownDataProperty(error, 'details')));
  }
  if (code === 'ENROLLMENT_CANCELLED') return fixedError('BOOTSTRAP_FAILED');
  if (phase === 'ssh') return fixedError('SSH_VERIFY_FAILED');
  if (
    phase === 'preflight'
    && (code === 'TAILSCALE_NOT_AVAILABLE_ON_MAC' || code === 'TAILSCALE_NOT_RUNNING_ON_MAC')
  ) {
    return fixedError(code);
  }
  return fixedError('BOOTSTRAP_FAILED');
}

function throwIfAborted(signal) {
  if (signal?.aborted) throw fixedError('ENROLLMENT_CANCELLED');
}

function waitForCompletion(receiver, timeoutMs, signal) {
  throwIfAborted(signal);
  const waiting = receiver.waitForCompletion({ timeoutMs });
  if (!signal) return waiting;
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (operation, value) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', onAbort);
      operation(value);
    };
    const onAbort = () => finish(reject, fixedError('ENROLLMENT_CANCELLED'));
    signal.addEventListener('abort', onAbort, { once: true });
    Promise.resolve(waiting).then(
      (value) => finish(resolve, value),
      (error) => finish(reject, error),
    );
    if (signal.aborted) onAbort();
  });
}

function enterFinalPublicationBarrier(onCommitStart) {
  if (onCommitStart) onCommitStart();
}

function requireDependencies(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('invalid Windows enrollment dependencies');
  }
  const methods = [
    [value.tailscale, 'status'],
    [value.tailscale, 'serve'],
    [value.signer, 'getOrCreate'],
    [value.sshIdentity, 'getOrCreate'],
    [value.registry, 'add'],
    [value.registry, 'replace'],
    [value.tokenStore, 'issue'],
    [value.tokenStore, 'consume'],
    [value.tokenStore, 'revoke'],
  ];
  if (
    methods.some(([owner, method]) => typeof owner?.[method] !== 'function')
    || typeof value.startReceiver !== 'function'
    || typeof value.buildCommand !== 'function'
    || typeof value.verifySsh !== 'function'
    || typeof value.now !== 'function'
    || typeof value.createDeviceId !== 'function'
    || !(value.stageOneBytes instanceof Uint8Array)
    || typeof value.knownHostsPath !== 'function'
  ) throw new TypeError('invalid Windows enrollment dependencies');
  return value;
}

function validatedCompletionFailureRecord(device, completion, now) {
  if (
    completion === null
    || typeof completion !== 'object'
    || Array.isArray(completion)
    || Object.getPrototypeOf(completion) !== Object.prototype
    || Object.getOwnPropertySymbols(completion).length !== 0
    || Object.getOwnPropertyNames(completion).length !== COMPLETION_KEYS.size
    || Object.getOwnPropertyNames(completion).some((key) => !COMPLETION_KEYS.has(key))
  ) throw fixedError('BOOTSTRAP_FAILED');
  for (const key of COMPLETION_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(completion, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw fixedError('BOOTSTRAP_FAILED');
  }
  if (
    completion.protocolVersion !== 1
    || completion.deviceId !== device.id
    || !Array.isArray(completion.checkpoints)
    || completion.checkpoints.length !== COMPLETION_CHECKPOINTS.length
    || !COMPLETION_CHECKPOINTS.every((checkpoint, index) => completion.checkpoints[index] === checkpoint)
  ) throw fixedError('BOOTSTRAP_FAILED');
  return validateDeviceRecord({
    ...device,
    status: 'SSH_VERIFY_FAILED',
    capabilities: [],
    updatedAt: now().toISOString(),
    target: completion.target,
    transport: {
      tailscaleAddresses: completion.tailscaleAddresses,
      sshUsername: 'AgentRoad',
      sshHostKeys: completion.sshHostKeys,
      sshHostKeyFingerprints: completion.sshHostKeyFingerprints,
    },
  });
}

async function bestEffortFailureRecord(registry, device, status, now) {
  try {
    await registry.replace(validateDeviceRecord({ ...device, status, updatedAt: now().toISOString() }));
  } catch {
    // The stable public failure must not expose registry paths or payloads.
  }
}

export async function runWindowsEnrollment({
  displayName,
  timeoutMs,
  onCommand,
  onCommitStart,
  dependencies,
  signal,
}) {
  const deps = requireDependencies(dependencies);
  if (
    !Number.isSafeInteger(timeoutMs)
    || timeoutMs < MIN_SESSION_TTL_MS
    || timeoutMs > MAX_SESSION_TTL_MS
    || typeof onCommand !== 'function'
    || (onCommitStart !== undefined && typeof onCommitStart !== 'function')
    || (signal !== undefined && !(signal instanceof AbortSignal))
  ) {
    throw new TypeError('invalid Windows enrollment options');
  }

  let receiver;
  let serve;
  let enrollment;
  let completedFailureRecord;
  let connected;
  let exchanged = false;
  let phase = 'preflight';
  let coreError;
  try {
    throwIfAborted(signal);
    const status = await deps.tailscale.status();
    throwIfAborted(signal);
    if (
      status?.backendState !== 'Running'
      || typeof status.dnsName !== 'string'
      || !DNS_PATTERN.test(status.dnsName)
    ) throw fixedError('TAILSCALE_NOT_RUNNING_ON_MAC');

    const deviceId = deps.createDeviceId();
    if (typeof deviceId !== 'string' || !DEVICE_ID_PATTERN.test(deviceId)) {
      throw fixedError('BOOTSTRAP_FAILED');
    }
    const signingPublicKey = await deps.signer.getOrCreate();
    throwIfAborted(signal);
    const ssh = await deps.sshIdentity.getOrCreate(deviceId);
    throwIfAborted(signal);
    const trackedTokenStore = {
      issue: (...args) => deps.tokenStore.issue(...args),
      revoke: (...args) => deps.tokenStore.revoke(...args),
      consume: async (...args) => {
        const consumed = await deps.tokenStore.consume(...args);
        exchanged = true;
        return consumed;
      },
    };
    receiver = await deps.startReceiver({
      tokenStore: trackedTokenStore,
      completionTickets: deps.completionTickets,
      deviceId,
      sshPublicKey: ssh.publicKey,
      signer: deps.signer,
      stageOneBytes: deps.stageOneBytes,
      host: '127.0.0.1',
      port: 0,
      completionTtlMs: timeoutMs,
    });
    throwIfAborted(signal);
    serve = await deps.tailscale.serve({ deviceId, localPort: receiver.port });
    throwIfAborted(signal);
    const controllerBaseUrl = `https://${status.dnsName}/agent-road/v1/${deviceId}`;
    if (serve?.baseUrl !== controllerBaseUrl || typeof serve.close !== 'function') {
      throw fixedError('BOOTSTRAP_FAILED');
    }

    phase = 'bootstrap';
    enrollment = await createEnrollment({
      displayName,
      now: deps.now,
      createDeviceId: () => deviceId,
      registry: deps.registry,
      tokenStore: trackedTokenStore,
      buildCommand: deps.buildCommand,
      tokenTtlMs: timeoutMs,
      commandPayload: {
        controllerBaseUrl,
        signingPublicKey,
        releaseManifest: deps.releaseManifest,
      },
    });
    throwIfAborted(signal);
    onCommand(enrollment.command);
    throwIfAborted(signal);
    const completion = await waitForCompletion(receiver, timeoutMs, signal);
    throwIfAborted(signal);
    completedFailureRecord = validatedCompletionFailureRecord(
      enrollment.device,
      completion,
      deps.now,
    );

    phase = 'ssh';
    const verified = await deps.verifySsh({
      deviceId,
      address: completion.tailscaleAddresses,
      sshHostKeys: completion.sshHostKeys,
      sshHostKeyFingerprints: completion.sshHostKeyFingerprints,
      privateKeyPath: ssh.privateKeyPath,
      knownHostsPath: deps.knownHostsPath(deviceId),
    });
    throwIfAborted(signal);
    if (
      !completion.tailscaleAddresses.includes(verified?.address)
      || !Array.isArray(verified?.capabilities)
      || verified.capabilities.length !== VERIFIED_CAPABILITIES.length
      || !VERIFIED_CAPABILITIES.every((capability, index) => verified.capabilities[index] === capability)
    ) throw fixedError('SSH_VERIFY_FAILED');
    connected = validateDeviceRecord({
      ...completedFailureRecord,
      status: 'CONNECTED_SSH_ONLY',
      capabilities: [...VERIFIED_CAPABILITIES],
      updatedAt: deps.now().toISOString(),
    });
  } catch (error) {
    coreError = mapFailure(error, phase);
    if (enrollment && !exchanged) {
      try { await enrollment.revoke(); } catch { /* preserve the stable primary failure */ }
    }
    if (enrollment) {
      await bestEffortFailureRecord(
        deps.registry,
        completedFailureRecord ?? enrollment.device,
        coreError.code === 'SSH_VERIFY_FAILED' ? 'SSH_VERIFY_FAILED' : 'BOOTSTRAP_FAILED',
        deps.now,
      );
    }
  }

  const cleanupErrors = [];
  if (serve) {
    try { await serve.close(); } catch (error) { cleanupErrors.push(error); }
  }
  if (receiver) {
    try { await receiver.close(); } catch (error) { cleanupErrors.push(error); }
  }
  if (coreError) throw coreError;
  if (cleanupErrors.length > 0) {
    if (enrollment) {
      await bestEffortFailureRecord(
        deps.registry,
        completedFailureRecord ?? enrollment.device,
        'BOOTSTRAP_FAILED',
        deps.now,
      );
    }
    throw fixedError('BOOTSTRAP_FAILED');
  }
  if (signal?.aborted) {
    if (enrollment) {
      await bestEffortFailureRecord(
        deps.registry,
        completedFailureRecord ?? enrollment.device,
        'BOOTSTRAP_FAILED',
        deps.now,
      );
    }
    throw fixedError('BOOTSTRAP_FAILED');
  }

  try {
    phase = 'persistence';
    // Final publication commit point: AbortSignal changes are deliberately ignored after this call.
    enterFinalPublicationBarrier(onCommitStart);
    await deps.registry.replace(connected);
  } catch {
    if (enrollment) {
      await bestEffortFailureRecord(
        deps.registry,
        completedFailureRecord ?? enrollment.device,
        'BOOTSTRAP_FAILED',
        deps.now,
      );
    }
    throw fixedError('BOOTSTRAP_FAILED');
  }
  return connected;
}
