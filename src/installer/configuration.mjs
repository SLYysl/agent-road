import { pairingError } from '../pairing/protocol.mjs';
const FIELDS = ['schemaVersion', 'kind', 'pairingOrigin', 'deviceId', 'controllerBaseUrl', 'enrollmentToken', 'tailscaleAuthKey', 'expiresAt'];
function invalid() { throw pairingError('PAIR_CONFIGURATION_INVALID'); }
export function validateNativeConfiguration(value, { origin, now, expiresAt }) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== FIELDS.length || FIELDS.some(key => !Object.hasOwn(value, key))) invalid();
  if (value.schemaVersion !== 2 || value.kind !== 'agent-road-native-enrollment') invalid();
  if (typeof origin !== 'string' || !/^https:\/\/[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(origin)
    || new URL(origin).origin !== origin || value.pairingOrigin !== origin) invalid();
  if (typeof value.deviceId !== 'string' || !/^dev_[a-f0-9]{32}$/.test(value.deviceId)) invalid();
  if (typeof value.controllerBaseUrl !== 'string' || value.controllerBaseUrl.length > 2048) invalid();
  let url;
  try { url = new URL(value.controllerBaseUrl); } catch { invalid(); }
  if (url.protocol !== 'https:' || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.ts\.net$/.test(url.hostname)
    || url.username || url.password || url.port || url.search || url.hash
    || url.pathname !== `/agent-road/v1/${value.deviceId}` || url.href !== value.controllerBaseUrl) invalid();
  if (typeof value.enrollmentToken !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value.enrollmentToken)
    || typeof value.tailscaleAuthKey !== 'string' || !/^tskey-auth-[A-Za-z0-9_-]{10,500}$/.test(value.tailscaleAuthKey)) invalid();
  if (!Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(expiresAt)
    || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= now
    || value.expiresAt > expiresAt || value.expiresAt - now > 600000) invalid();
  // Contains credentials: return only to the authenticated claimant; never log.
  // Data acceptance does not mean setup ran or a device is connected.
  return Object.fromEntries(FIELDS.map(key => [key, value[key]]));
}
