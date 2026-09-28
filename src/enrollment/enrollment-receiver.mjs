import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { isIP } from 'node:net';
import { performance } from 'node:perf_hooks';
import { isDeepStrictEqual } from 'node:util';

const MAX_BODY_BYTES = 64 * 1024;
const REQUEST_TIMEOUT_MS = 10_000;
const DEFAULT_COMPLETION_TTL_MS = 10 * 60 * 1000;
const MIN_COMPLETION_TTL_MS = 5 * 60 * 1000;
const MAX_COMPLETION_TTL_MS = 30 * 60 * 1000;
const MAX_STAGE_ONE_BYTES = 1024 * 1024;
const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/;
const MAX_DEVICE_ID_LENGTH = 64;
const TICKET_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const FINGERPRINT_PATTERN = /^SHA256:[A-Za-z0-9+/]{43}$/;
const SSH_KEY_PATTERN = /^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})(?: ([^\s\r\n\x00-\x1F\x7F](?:[^\r\n\x00-\x1F\x7F]*[^\s\r\n\x00-\x1F\x7F])?))?$/;
const SSH_ALGORITHM = Buffer.from('ssh-ed25519');
const CHECKPOINTS = Object.freeze(['preflight', 'tailscale', 'openssh', 'account', 'firewall']);
const EXCHANGE_FIELDS = new Set(['protocolVersion', 'deviceId', 'token']);
const COMPLETION_FIELDS = new Set([
  'protocolVersion',
  'deviceId',
  'completionTicket',
  'target',
  'tailscaleAddresses',
  'sshHostKeys',
  'sshHostKeyFingerprints',
  'checkpoints',
]);
const TARGET_FIELDS = new Set(['version', 'build', 'edition', 'architecture']);

function receiverError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function hashCompletionTicket(rawTicket) {
  return createHash('sha256').update(rawTicket, 'utf8').digest('hex');
}

function connectionExpired(state, monotonicNow) {
  if (!state || state.expired) return true;
  let currentTime;
  try {
    currentTime = monotonicNow();
  } catch {
    currentTime = Number.NaN;
  }
  if (
    !Number.isFinite(currentTime)
    || currentTime < state.acceptedAt
    || currentTime >= state.expiresAt
  ) {
    state.expired = true;
    state.socket.destroy();
    return true;
  }
  return false;
}

function isPlainObject(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function isValidDeviceId(value) {
  return typeof value === 'string'
    && value.length <= MAX_DEVICE_ID_LENGTH
    && DEVICE_ID_PATTERN.test(value);
}

function hasExactKeys(value, fields) {
  if (!isPlainObject(value)) return false;
  const keys = Object.keys(value);
  return keys.length === fields.size && keys.every((key) => fields.has(key));
}

function isBoundedString(value, maximum) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= maximum
    && value === value.trim()
    && !/[\r\n\x00-\x1F\x7F]/.test(value);
}

function isCanonicalIp(value) {
  if (typeof value !== 'string' || value !== value.trim()) return false;
  const family = isIP(value);
  if (family === 4) return true;
  if (family !== 6) return false;
  return new URL(`http://[${value}]/`).hostname === `[${value}]`;
}

function readSshString(bytes, offset) {
  if (offset > bytes.length - 4) return null;
  const length = bytes.readUInt32BE(offset);
  const start = offset + 4;
  if (length > bytes.length - start) return null;
  return { value: bytes.subarray(start, start + length), next: start + length };
}

function sshKeyBlob(value) {
  if (typeof value !== 'string' || value.length > 1024) return null;
  const match = SSH_KEY_PATTERN.exec(value);
  if (!match) return null;
  const bytes = Buffer.from(match[1], 'base64');
  if (bytes.toString('base64') !== match[1]) return null;
  const algorithm = readSshString(bytes, 0);
  if (!algorithm || !algorithm.value.equals(SSH_ALGORITHM)) return null;
  const publicKey = readSshString(bytes, algorithm.next);
  return publicKey !== null && publicKey.value.length === 32 && publicKey.next === bytes.length
    ? bytes
    : null;
}

function isValidSshKey(value) {
  return sshKeyBlob(value) !== null;
}

function isBoundedUniqueArray(value, maximum, validator) {
  return Array.isArray(value)
    && value.length > 0
    && value.length <= maximum
    && new Set(value).size === value.length
    && value.every(validator);
}

function validateExchange(value, deviceId, protocolVersion) {
  return hasExactKeys(value, EXCHANGE_FIELDS)
    && value.protocolVersion === protocolVersion
    && value.deviceId === deviceId
    && isBoundedString(value.token, 512);
}

function validateCompletion(value, deviceId, protocolVersion) {
  if (
    !hasExactKeys(value, COMPLETION_FIELDS)
    || value.protocolVersion !== protocolVersion
    || value.deviceId !== deviceId
    || typeof value.completionTicket !== 'string'
    || !TICKET_PATTERN.test(value.completionTicket)
    || Buffer.from(value.completionTicket, 'base64url').length !== 32
    || !hasExactKeys(value.target, TARGET_FIELDS)
    || !isBoundedString(value.target.version, 32)
    || !Number.isInteger(value.target.build)
    || value.target.build < 0
    || value.target.build > 99_999
    || !isBoundedString(value.target.edition, 64)
    || !isBoundedString(value.target.architecture, 16)
    || !isBoundedUniqueArray(value.tailscaleAddresses, 8, isCanonicalIp)
    || !isBoundedUniqueArray(value.sshHostKeys, 8, isValidSshKey)
    || !isBoundedUniqueArray(
      value.sshHostKeyFingerprints,
      8,
      (fingerprint) => typeof fingerprint === 'string' && FINGERPRINT_PATTERN.test(fingerprint),
    )
    || value.sshHostKeys.length !== value.sshHostKeyFingerprints.length
    || !Array.isArray(value.checkpoints)
    || value.checkpoints.length !== CHECKPOINTS.length
    || !value.checkpoints.every((checkpoint, index) => checkpoint === CHECKPOINTS[index])
  ) {
    return null;
  }
  if (!value.sshHostKeys.every((key, index) => {
    const blob = sshKeyBlob(key);
    const fingerprint = blob
      ? `SHA256:${createHash('sha256').update(blob).digest('base64').replace(/=+$/u, '')}`
      : null;
    return fingerprint === value.sshHostKeyFingerprints[index];
  })) {
    return null;
  }

  return Object.freeze({
    protocolVersion: 1,
    deviceId,
    target: Object.freeze({
      version: value.target.version,
      build: value.target.build,
      edition: value.target.edition,
      architecture: value.target.architecture,
    }),
    tailscaleAddresses: Object.freeze([...value.tailscaleAddresses]),
    sshHostKeys: Object.freeze([...value.sshHostKeys]),
    sshHostKeyFingerprints: Object.freeze([...value.sshHostKeyFingerprints]),
    checkpoints: Object.freeze([...value.checkpoints]),
  });
}

function jsonResponse(response, statusCode, value) {
  if (response.destroyed || response.writableEnded) return;
  const body = JSON.stringify(value);
  response.writeHead(statusCode, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    connection: 'close',
  });
  response.end(body);
}

function rawHeaderCount(request, wantedName) {
  let count = 0;
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index].toLowerCase() === wantedName) count += 1;
  }
  return count;
}

function validateBodyHeaders(request) {
  if (rawHeaderCount(request, 'content-type') !== 1) return { status: 400 };
  if (request.headers['content-type'] !== 'application/json') return { status: 400 };
  if (rawHeaderCount(request, 'content-length') !== 1) return { status: 400 };
  if (rawHeaderCount(request, 'transfer-encoding') !== 0) return { status: 400 };
  const value = request.headers['content-length'];
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) return { status: 400 };
  const length = Number(value);
  if (!Number.isSafeInteger(length)) return { status: 400 };
  if (length > MAX_BODY_BYTES) return { status: 413 };
  return { status: 200, length };
}

function readBody(request, expectedLength, connectionState, monotonicNow) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let received = 0;
    let settled = false;
    const finish = (operation, value) => {
      if (settled) return;
      settled = true;
      operation(value);
    };
    if (connectionExpired(connectionState, monotonicNow)) {
      finish(reject, receiverError('REQUEST_TIMEOUT'));
      request.destroy();
      return;
    }
    request.on('data', (chunk) => {
      if (connectionExpired(connectionState, monotonicNow)) {
        finish(reject, receiverError('REQUEST_TIMEOUT'));
        return;
      }
      received += chunk.length;
      if (received > expectedLength || received > MAX_BODY_BYTES) {
        finish(reject, receiverError('INVALID_BODY_LENGTH'));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => {
      if (connectionExpired(connectionState, monotonicNow)) {
        finish(reject, receiverError('REQUEST_TIMEOUT'));
      } else if (received !== expectedLength) {
        finish(reject, receiverError('INVALID_BODY_LENGTH'));
      } else {
        finish(resolve, Buffer.concat(chunks, received));
      }
    });
    request.on('aborted', () => finish(reject, receiverError('REQUEST_ABORTED')));
    request.on('error', () => finish(reject, receiverError('REQUEST_ERROR')));
  });
}

function skipJsonWhitespace(text, start) {
  let index = start;
  while (index < text.length && /[\u0009\u000a\u000d\u0020]/u.test(text[index])) index += 1;
  return index;
}

function scanJsonString(text, start) {
  let index = start + 1;
  while (index < text.length) {
    if (text[index] === '"') {
      const end = index + 1;
      return { end, value: JSON.parse(text.slice(start, end)) };
    }
    if (text[index] === '\\') {
      index += text[index + 1] === 'u' ? 6 : 2;
    } else {
      index += 1;
    }
  }
  return null;
}

function scanJsonValue(text, start, duplicateState) {
  let index = skipJsonWhitespace(text, start);
  if (text[index] === '"') return scanJsonString(text, index)?.end ?? text.length;
  if (text[index] === '[') {
    index = skipJsonWhitespace(text, index + 1);
    if (text[index] === ']') return index + 1;
    while (index < text.length) {
      index = skipJsonWhitespace(text, scanJsonValue(text, index, duplicateState));
      if (text[index] === ']') return index + 1;
      index = skipJsonWhitespace(text, index + 1);
    }
  }
  if (text[index] === '{') {
    const keys = new Set();
    index = skipJsonWhitespace(text, index + 1);
    if (text[index] === '}') return index + 1;
    while (index < text.length) {
      const key = scanJsonString(text, index);
      if (!key) return text.length;
      if (keys.has(key.value)) duplicateState.found = true;
      keys.add(key.value);
      index = skipJsonWhitespace(text, key.end);
      index = skipJsonWhitespace(text, index + 1);
      index = skipJsonWhitespace(text, scanJsonValue(text, index, duplicateState));
      if (text[index] === '}') return index + 1;
      index = skipJsonWhitespace(text, index + 1);
    }
  }
  while (index < text.length && !/[\s,\]}]/u.test(text[index])) index += 1;
  return index;
}

function parseJsonObject(bytes) {
  if (bytes.length === 0) return null;
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const value = JSON.parse(text);
    const duplicateState = { found: false };
    const end = skipJsonWhitespace(text, scanJsonValue(text, 0, duplicateState));
    return isPlainObject(value) && !duplicateState.found && end === text.length ? value : null;
  } catch {
    return null;
  }
}

function clientErrorResponse(socket) {
  if (!socket.writable || socket.destroyed) return;
  const body = '{"error":"invalid request"}';
  socket.end(
    `HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nCache-Control: no-store\r\n\r\n${body}`,
  );
}

export async function startEnrollmentReceiver(options) {
  if (!isPlainObject(options)) throw new TypeError('invalid enrollment receiver options');
  const {
    protocolVersion = 1,
    tokenStore,
    completionTickets,
    deviceId,
    sshPublicKey,
    signer,
    host = '127.0.0.1',
    port = 0,
    setRequestDeadline = setTimeout,
    clearRequestDeadline = clearTimeout,
    monotonicNow = () => performance.now(),
    completionTtlMs = DEFAULT_COMPLETION_TTL_MS,
  } = options;
  if (host !== '127.0.0.1') throw receiverError('ENROLLMENT_LOCALHOST_REQUIRED');
  if (
    ![1, 2].includes(protocolVersion)
    || !isValidDeviceId(deviceId)
    || !isValidSshKey(sshPublicKey)
    || !sshPublicKey.endsWith(` agent-road:${deviceId}`)
    || !tokenStore
    || typeof tokenStore.consume !== 'function'
    || !completionTickets
    || typeof completionTickets.issue !== 'function'
    || typeof completionTickets.consume !== 'function'
    || (protocolVersion === 1 && (!signer || typeof signer.sign !== 'function'))
    || !Number.isInteger(port)
    || port < 0
    || port > 65_535
    || typeof setRequestDeadline !== 'function'
    || typeof clearRequestDeadline !== 'function'
    || typeof monotonicNow !== 'function'
    || !Number.isSafeInteger(completionTtlMs)
    || completionTtlMs < MIN_COMPLETION_TTL_MS
    || completionTtlMs > MAX_COMPLETION_TTL_MS
  ) {
    throw new TypeError('invalid enrollment receiver options');
  }
  let bootstrapFields = {};
  if (protocolVersion === 2) {
    // Never accept or sign executable bootstrap material on the data-only receiver.
    if (options.stageOneBytes !== undefined || signer !== undefined) {
      throw new TypeError('native receiver refuses executable bootstrap options');
    }
  } else {
    if (!(options.stageOneBytes instanceof Uint8Array)) {
      throw new TypeError('invalid enrollment receiver options');
    }
    const stageOneBytes = Buffer.from(options.stageOneBytes ?? []);
    if (stageOneBytes.length === 0 || stageOneBytes.length > MAX_STAGE_ONE_BYTES) {
      throw new TypeError('invalid enrollment receiver options');
    }
    const stageOneBase64 = stageOneBytes.toString('base64');
    const stageOneSha256 = createHash('sha256').update(stageOneBytes).digest('hex');
    const stageOneSignatureBase64 = await signer.sign(stageOneBytes);
    if (
      typeof stageOneSignatureBase64 !== 'string'
      || stageOneSignatureBase64.length === 0
      || Buffer.from(stageOneSignatureBase64, 'base64').toString('base64') !== stageOneSignatureBase64
    ) {
      throw new TypeError('invalid enrollment receiver signature');
    }
    bootstrapFields = { stageOneBase64, stageOneSha256, stageOneSignatureBase64 };
  }

  let completionSnapshot = null;
  let completionCommit = null;
  let closed = false;
  let closePromise = null;
  const waiters = new Set();
  const sockets = new Set();
  const connectionStates = new WeakMap();
  let lastConnectionOrdinal = 0;

  const publishCompletion = (snapshot, ticketHash, connectionState) => {
    if (
      closed
      || connectionExpired(connectionState, monotonicNow)
      || completionSnapshot
    ) {
      return null;
    }
    completionSnapshot = snapshot;
    completionCommit = {
      ticketHash,
      snapshot,
      responseSettled: false,
      replayAfterOrdinal: null,
    };
    for (const waiter of waiters) {
      clearTimeout(waiter.timer);
      waiter.resolve(snapshot);
    }
    waiters.clear();
    return completionCommit;
  };

  const trackCommittedResponseSettlement = (commit, response, connectionState) => {
    let settled = false;
    const markSettled = () => {
      if (settled) return;
      settled = true;
      response.off('close', markSettled);
      if (completionCommit === commit && !commit.responseSettled) {
        commit.responseSettled = true;
        commit.replayAfterOrdinal = lastConnectionOrdinal;
      }
    };
    response.once('close', markSettled);
    if (response.destroyed || connectionState.cleaned) {
      markSettled();
    }
  };

  const exchangePath = '/exchange';
  const completionPath = '/complete';
  const server = createServer(async (request, response) => {
    const connectionState = connectionStates.get(request.socket);
    if (connectionExpired(connectionState, monotonicNow) || closed) {
      request.destroy();
      return;
    }
    const path = request.url;
    const isExchange = path === exchangePath;
    const isCompletion = path === completionPath;
    if (!isExchange && !isCompletion) {
      request.resume();
      jsonResponse(response, 404, { error: 'not found' });
      return;
    }
    if (request.method !== 'POST') {
      request.resume();
      jsonResponse(response, 405, { error: 'method not allowed' });
      return;
    }
    const headers = validateBodyHeaders(request);
    if (headers.status !== 200) {
      request.resume();
      jsonResponse(
        response,
        headers.status,
        { error: headers.status === 413 ? 'request body too large' : (isExchange ? 'invalid enrollment request' : 'invalid completion request') },
      );
      return;
    }

    let body;
    try {
      body = parseJsonObject(await readBody(
        request,
        headers.length,
        connectionState,
        monotonicNow,
      ));
    } catch {
      jsonResponse(response, 400, { error: isExchange ? 'invalid enrollment request' : 'invalid completion request' });
      return;
    }

    if (isExchange) {
      if (!validateExchange(body, deviceId, protocolVersion)) {
        jsonResponse(response, 400, { error: 'invalid enrollment request' });
        return;
      }
      try {
        if (closed || connectionExpired(connectionState, monotonicNow)) throw receiverError('ENROLLMENT_CLOSED');
        const consumed = await tokenStore.consume(body.token);
        if (closed || connectionExpired(connectionState, monotonicNow)) throw receiverError('ENROLLMENT_CLOSED');
        if (!consumed || consumed.deviceId !== deviceId) throw new Error('invalid token binding');
        const completionTicket = await completionTickets.issue(deviceId, completionTtlMs);
        if (closed || connectionExpired(connectionState, monotonicNow)) throw receiverError('ENROLLMENT_CLOSED');
        if (
          typeof completionTicket !== 'string'
          || !TICKET_PATTERN.test(completionTicket)
          || Buffer.from(completionTicket, 'base64url').length !== 32
        ) {
          throw new Error('invalid completion ticket');
        }
        if (closed || connectionExpired(connectionState, monotonicNow)) throw receiverError('ENROLLMENT_CLOSED');
        jsonResponse(response, 200, {
          protocolVersion,
          deviceId,
          sshPublicKey,
          ...bootstrapFields,
          completionTicket,
        });
      } catch {
        jsonResponse(response, 400, { error: 'invalid enrollment request' });
      }
      return;
    }

    const snapshot = validateCompletion(body, deviceId, protocolVersion);
    if (!snapshot) {
      jsonResponse(response, 400, { error: 'invalid completion request' });
      return;
    }
    const ticketHash = hashCompletionTicket(body.completionTicket);
    if (completionCommit) {
      const exactSettledReplay = (
        completionCommit.responseSettled
        && connectionState.ordinal > completionCommit.replayAfterOrdinal
        && !connectionExpired(connectionState, monotonicNow)
        && completionCommit.ticketHash === ticketHash
        && isDeepStrictEqual(completionCommit.snapshot, snapshot)
      );
      if (exactSettledReplay) {
        jsonResponse(response, 200, { protocolVersion, deviceId, accepted: true });
      } else {
        jsonResponse(response, 400, { error: 'invalid completion request' });
      }
      return;
    }
    let commit;
    try {
      if (closed || connectionExpired(connectionState, monotonicNow)) throw receiverError('ENROLLMENT_CLOSED');
      const consumed = await completionTickets.consume(body.completionTicket, deviceId);
      if (!consumed || consumed.deviceId !== deviceId) throw new Error('invalid ticket binding');
      commit = publishCompletion(snapshot, ticketHash, connectionState);
      if (!commit) throw new Error('completion not accepted');
    } catch {
      jsonResponse(response, 400, { error: 'invalid completion request' });
      return;
    }
    trackCommittedResponseSettlement(commit, response, connectionState);
    try {
      jsonResponse(response, 200, { protocolVersion, deviceId, accepted: true });
    } catch {
      response.destroy();
    }
  });
  server.requestTimeout = REQUEST_TIMEOUT_MS;
  server.headersTimeout = REQUEST_TIMEOUT_MS;
  server.maxRequestsPerSocket = 1;
  server.on('clientError', (_error, socket) => clientErrorResponse(socket));
  server.on('error', () => {});
  server.on('connection', (socket) => {
    let acceptedAt;
    try {
      acceptedAt = monotonicNow();
    } catch {
      acceptedAt = Number.NaN;
    }
    const state = {
      deadline: null,
      expired: !Number.isFinite(acceptedAt),
      cleaned: false,
      acceptedAt,
      expiresAt: acceptedAt + REQUEST_TIMEOUT_MS,
      socket,
      ordinal: ++lastConnectionOrdinal,
    };
    connectionStates.set(socket, state);
    sockets.add(socket);
    const cleanup = () => {
      if (state.cleaned) return;
      state.cleaned = true;
      try {
        clearRequestDeadline(state.deadline);
      } catch {
        // Socket cleanup is best-effort and must remain redacted.
      }
      sockets.delete(socket);
      connectionStates.delete(socket);
      socket.off('close', cleanup);
      socket.off('error', onSocketError);
    };
    const onSocketError = () => {
      cleanup();
      socket.destroy();
    };
    socket.once('close', cleanup);
    socket.once('error', onSocketError);
    if (state.expired) {
      socket.destroy();
      return;
    }
    try {
      state.deadline = setRequestDeadline(() => {
        if (state.cleaned) return;
        state.expired = true;
        socket.destroy();
      }, REQUEST_TIMEOUT_MS);
      state.deadline?.unref?.();
    } catch {
      state.expired = true;
      socket.destroy();
    }
  });

  await new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off('listening', onListening);
      reject(error);
    };
    const onListening = () => {
      server.off('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, host);
  });
  const address = server.address();
  if (!address || typeof address === 'string' || address.address !== host) {
    await new Promise((resolve) => server.close(resolve));
    throw receiverError('ENROLLMENT_LOCALHOST_REQUIRED');
  }

  return Object.freeze({
    port: address.port,
    waitForCompletion({ timeoutMs }) {
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
        return Promise.reject(new TypeError('invalid enrollment completion timeout'));
      }
      if (closed) return Promise.reject(receiverError('ENROLLMENT_CLOSED'));
      if (completionSnapshot) return Promise.resolve(completionSnapshot);
      return new Promise((resolve, reject) => {
        const waiter = { resolve, reject, timer: null };
        waiter.timer = setTimeout(() => {
          waiters.delete(waiter);
          reject(receiverError('ENROLLMENT_TIMEOUT'));
        }, timeoutMs);
        waiter.timer.unref?.();
        waiters.add(waiter);
      });
    },
    close() {
      if (closePromise) return closePromise;
      closed = true;
      for (const waiter of waiters) {
        clearTimeout(waiter.timer);
        waiter.reject(receiverError('ENROLLMENT_CLOSED'));
      }
      waiters.clear();
      closePromise = new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        for (const socket of sockets) socket.destroy();
      });
      return closePromise;
    },
  });
}
