import { homedir } from 'node:os';
import {
  dirname,
  isAbsolute,
  join,
  resolve,
} from 'node:path';

const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/u;
const RUNTIME_OPERATION_ID_PATTERN = /^[a-f0-9]{32}$/u;
const RUNTIME_RECOVERY_TICKET_ID_PATTERN = /^rct_[a-f0-9]{64}$/u;
const RUNTIME_RECOVERY_DIGEST_PATTERN = /^[A-F0-9]{64}$/u;
const MAX_RUNTIME_RECOVERY_PATH_BYTES = 4_096;
const IMMUTABLE_TEMPORARY_SUFFIX_BYTES = 41;

function runtimePathInputError() {
  const error = new TypeError('RUNTIME_INPUT_INVALID');
  error.code = 'RUNTIME_INPUT_INVALID';
  return error;
}

export function runtimeDeviceStatePath(runtimeDevicesRoot, deviceId) {
  if (
    typeof runtimeDevicesRoot !== 'string'
    || runtimeDevicesRoot.length === 0
    || Buffer.byteLength(runtimeDevicesRoot, 'utf8') > 4_096
    || !isAbsolute(runtimeDevicesRoot)
    || resolve(runtimeDevicesRoot) !== runtimeDevicesRoot
    || /[\r\n\x00-\x1f\x7f]/u.test(runtimeDevicesRoot)
    || typeof deviceId !== 'string'
    || deviceId.length > 64
    || !DEVICE_ID_PATTERN.test(deviceId)
  ) {
    throw runtimePathInputError();
  }
  return join(runtimeDevicesRoot, deviceId, 'state.json');
}

export function runtimeDeviceRecoveryPaths(runtimeDevicesRoot, deviceId, operationId, ticketId) {
  const hasTicket = ticketId !== undefined;
  if (
    typeof operationId !== 'string'
    || !RUNTIME_OPERATION_ID_PATTERN.test(operationId)
    || (hasTicket && (
      typeof ticketId !== 'string'
      || !RUNTIME_RECOVERY_TICKET_ID_PATTERN.test(ticketId)
    ))
  ) throw runtimePathInputError();
  const device = dirname(runtimeDeviceStatePath(runtimeDevicesRoot, deviceId));
  const recovery = join(device, 'recovery');
  const operation = join(recovery, 'operations', operationId);
  const legacyTickets = join(operation, 'tickets');
  const tickets = join(operation, 'tickets-v2');
  const authorizationSuccessors = join(operation, 'authorization-successors');
  const legacyAuthorizedDeleteAttempts = join(operation, 'authorized-delete-attempts');
  const authorizedDeleteAttempts = join(operation, 'authorized-delete-attempts-v2');
  const paths = {
    device,
    recovery,
    operation,
    bootObservation: join(operation, 'boot-observation.json'),
    legacyTickets,
    tickets,
    ticket: hasTicket ? join(tickets, `${ticketId}.json`) : null,
    authorizationSuccessors,
    legacyAuthorizedDeleteAttempts,
    authorizedDeleteAttempts,
    authorizedDeleteAttempt: hasTicket
      ? join(authorizedDeleteAttempts, `${ticketId}.json`)
      : null,
    recoveryCommit: join(operation, 'recovery-commit.json'),
  };
  const longestRecordPathBytes = Math.max(...[
    paths.bootObservation,
    paths.ticket,
    join(authorizationSuccessors, `${'a'.repeat(64)}.json`),
    paths.authorizedDeleteAttempt,
    paths.recoveryCommit,
  ].filter((path) => path !== null).map((path) => Buffer.byteLength(path, 'utf8')));
  if (longestRecordPathBytes + IMMUTABLE_TEMPORARY_SUFFIX_BYTES > MAX_RUNTIME_RECOVERY_PATH_BYTES) {
    throw runtimePathInputError();
  }
  return Object.freeze(paths);
}

export function runtimeRecoveryAuthorizationSuccessorPath(
  runtimeDevicesRoot,
  deviceId,
  operationId,
  parentDigest,
) {
  if (
    typeof parentDigest !== 'string'
    || !RUNTIME_RECOVERY_DIGEST_PATTERN.test(parentDigest)
  ) throw runtimePathInputError();
  const paths = runtimeDeviceRecoveryPaths(runtimeDevicesRoot, deviceId, operationId);
  return join(paths.authorizationSuccessors, `${parentDigest.toLowerCase()}.json`);
}

export function statePaths(env = process.env) {
  const root = resolve(env.AGENT_ROAD_HOME || join(homedir(), '.agent-road'));
  const runtimeRoot = join(root, 'runtime');

  return Object.freeze({
    root,
    devices: join(root, 'devices.json'),
    tokens: join(root, 'enrollment-tokens.json'),
    signingPrivateKey: join(root, 'identity', 'bootstrap-signing-private.pem'),
    signingPublicKey: join(root, 'identity', 'bootstrap-signing-public.json'),
    sshIdentities: join(root, 'identity', 'devices'),
    knownHosts: join(root, 'known-hosts'),
    runtimeRoot,
    runtimeArtifacts: join(runtimeRoot, 'artifacts'),
    runtimeDevices: join(runtimeRoot, 'devices'),
  });
}
