import { pairingError } from './protocol.mjs';
const API='https://api.tailscale.com/api/v2/tailnet/-/keys';
const ID=/^[A-Za-z0-9_-]{1,128}$/;
export async function tailscaleKeyRequest(token, method, id, body, fetchImpl=fetch) {
  if(!/^tskey-api-[A-Za-z0-9_-]{10,500}$/.test(token??'') || (id!==undefined&&!ID.test(id)))throw pairingError('PAIR_CONFIG_INVALID');
  try {
    const response=await fetchImpl(API+(id===undefined?'':'/'+id),{
      method,headers:{authorization:`Bearer ${token}`,'content-type':'application/json'},
      ...(body?{body:JSON.stringify(body)}:{}),redirect:'error',signal:AbortSignal.timeout(20000),
    });
    if(method==='DELETE'&&(response.ok||response.status===404)){await response.body?.cancel();return;}
    if(!response.ok){await response.body?.cancel();throw pairingError('PAIR_TAILSCALE_REQUEST_FAILED');}
    const reader=response.body?.getReader();if(!reader)throw pairingError('PAIR_TAILSCALE_RESPONSE_INVALID');
    const chunks=[];let length=0;
    while(true){const r=await reader.read();if(r.done)break;length+=r.value.length;if(length>16384){await reader.cancel();throw pairingError('PAIR_TAILSCALE_RESPONSE_INVALID');}chunks.push(r.value);}
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  }catch(error){if(error.code?.startsWith('PAIR_'))throw error;throw pairingError('PAIR_TAILSCALE_REQUEST_UNCERTAIN');}
}
export async function createPairAuthKey(token, description, fetchImpl) {
  const result=await tailscaleKeyRequest(token,'POST',undefined,{
    capabilities:{devices:{create:{reusable:false,ephemeral:false,preauthorized:true}}},
    expirySeconds:900,description,
  },fetchImpl);
  if(!ID.test(result?.id??'')||!/^tskey-auth-[A-Za-z0-9_-]{10,500}$/.test(result?.key??''))throw pairingError('PAIR_TAILSCALE_RESPONSE_INVALID');
  return {id:result.id,key:result.key};
}
export async function revokePairAuthKey(token,id,fetchImpl){await tailscaleKeyRequest(token,'DELETE',id,undefined,fetchImpl);}
