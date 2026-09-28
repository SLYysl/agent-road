import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { randomBytes } from 'node:crypto';
import { pairingError } from './protocol.mjs';
export async function readPrivateText(path) {
  if (!isAbsolute(path ?? '')) throw pairingError('PAIR_CONFIG_INVALID');
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0 || stat.size > 16384) throw pairingError('PAIR_CONFIG_UNSAFE');
    const bytes = Buffer.alloc(16385); let length = 0;
    while (length < bytes.length) { const r = await file.read(bytes, length, bytes.length - length, null); if (!r.bytesRead) break; length += r.bytesRead; }
    if (length > 16384) throw pairingError('PAIR_CONFIG_INVALID');
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0,length)).trim();
  } finally { await file.close(); }
}
export async function loadPairingConfig(path, { controllerToken } = {}) {
  let value;
  try { value = JSON.parse(await readPrivateText(path)); } catch(error) { if(error.code?.startsWith('PAIR_'))throw error; throw pairingError('PAIR_CONFIG_REQUIRED'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).some(k=>!['origin','adminTokenFile','tailscaleAuthKeyFile','tailscaleApiTokenFile'].includes(k))
    || typeof value.origin !== 'string' || !/^https:\/\/[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(value.origin)
    || (value.adminTokenFile !== undefined && !isAbsolute(value.adminTokenFile))
    || (Object.hasOwn(value,'tailscaleAuthKeyFile') === Object.hasOwn(value,'tailscaleApiTokenFile'))
    || !isAbsolute(value.tailscaleAuthKeyFile??value.tailscaleApiTokenFile??'')) throw pairingError('PAIR_CONFIG_INVALID');
  const adminToken = controllerToken ?? (value.adminTokenFile ? await readPrivateText(value.adminTokenFile) : null);
  const authKey = value.tailscaleAuthKeyFile ? await readPrivateText(value.tailscaleAuthKeyFile) : null;
  const apiToken = value.tailscaleApiTokenFile ? await readPrivateText(value.tailscaleApiTokenFile) : null;
  if ((adminToken !== null && !/^[A-Za-z0-9_-]{43}$/.test(adminToken) && !/^ar1\.[a-f0-9]{32}\.[A-Za-z0-9_-]{43}$/.test(adminToken)) || (authKey!==null && !/^tskey-auth-[A-Za-z0-9_-]{10,500}$/.test(authKey))
    || (apiToken!==null && !/^tskey-api-[A-Za-z0-9_-]{10,500}$/.test(apiToken))) throw pairingError('PAIR_CONFIG_INVALID');
  return { origin:value.origin, adminToken, authKey, apiToken };
}
export function newPairIdentity() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return { code:Array.from(randomBytes(12),x=>alphabet[x%32]).join(''), ownerToken:randomBytes(32).toString('base64url') };
}
export async function pairRequest(origin, action, body, { adminToken, signal, fetchImpl = fetch, protocolVersion = 1 } = {}) {
  if (![1, 2].includes(protocolVersion)) throw pairingError('PAIR_PROTOCOL_UNSUPPORTED');
  const headers = {'content-type':'application/json'};
  if(adminToken)headers.authorization=`Bearer ${adminToken}`;
  try {
    const response=await fetchImpl(`${origin}/v${protocolVersion}/${action}`, {method:'POST',headers,body:JSON.stringify(body),redirect:'error',signal:signal?AbortSignal.any([signal,AbortSignal.timeout(20000)]):AbortSignal.timeout(20000)});
    const reader=response.body?.getReader(); let size=0;const chunks=[];
    if(!reader)throw pairingError('PAIR_RESPONSE_INVALID');
    while(true){const {value,done}=await reader.read();if(done)break;size+=value.length;if(size>40000){await reader.cancel();throw pairingError('PAIR_RESPONSE_INVALID');}chunks.push(value);}
    const result=JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if(!response.ok)throw pairingError(/^PAIR_[A-Z_]+$/.test(result?.code??'')?result.code:'PAIR_REQUEST_FAILED',response.status);
    return result;
  }catch(error){if(error.code?.startsWith('PAIR_'))throw error;throw pairingError('PAIR_REQUEST_UNCERTAIN');}
}
