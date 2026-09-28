// Serialized by the existing pairing Durable Object. No Supabase session is stored.
const PROJECT = 'https://vogebqydhebvvchwhvdb.supabase.co';
const TOKEN = /^ar1\.([a-f0-9]{32})\.([A-Za-z0-9_-]{43})$/;
export const authError = (code, status = 400) => Object.assign(new Error(code), { code, status });
const reply = (value, status = 200) => Response.json(value, { status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
const hash = async value => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))), b => b.toString(16).padStart(2,'0')).join('');
export async function boundedJson(response, limit = 16384) {
 const reader=response.body?.getReader(); if(!reader)throw authError('AUTH_INPUT_INVALID');
 const chunks=[];let size=0;
 while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>limit){await reader.cancel();throw authError('AUTH_INPUT_INVALID');}chunks.push(value);}
 const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
 try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw authError('AUTH_INPUT_INVALID');}
}
export async function accountUser(request, env, fetchImpl=fetch) {
 const token=(request.headers.get('authorization')??'').replace(/^Bearer /,'');
 if(token.startsWith('ar1.')||!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)||token.length>16384)throw authError('AUTH_REQUIRED',401);
 if(!/^sb_publishable_[A-Za-z0-9_-]+$/.test(env.SUPABASE_PUBLISHABLE_KEY??''))throw authError('AUTH_UNCONFIGURED',503);
 let response;try{response=await fetchImpl(PROJECT+'/auth/v1/user',{headers:{apikey:env.SUPABASE_PUBLISHABLE_KEY,Authorization:'Bearer '+token},redirect:'manual',signal:AbortSignal.timeout(8000)});}catch{throw authError('AUTH_UNAVAILABLE',503);}
 if(!response.ok){await response.body?.cancel();throw authError(response.status===401||response.status===403?'AUTH_REQUIRED':'AUTH_UNAVAILABLE',response.status===401||response.status===403?401:503);}
 const user=await boundedJson(response,65536);
 if(!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(user?.id??'')||user.role!=='authenticated'||user.aud!=='authenticated'||user.is_anonymous===true||!user.email_confirmed_at)throw authError('AUTH_REQUIRED',401);
 return {id:user.id, account:PROJECT+':'+user.id};
}
export async function cliSession(token, storage, now=Date.now(), pending=false) {
 const match=TOKEN.exec(token??'');if(!match)throw authError('AUTH_REQUIRED',401);
 const record=await storage.get('cli:'+match[1]);
 if(!record||record.hash!==await hash(token)||now<record.createdAt||now>=record.expiresAt||(!pending&&record.state!=='AUTHORIZED'))throw authError('AUTH_REQUIRED',401);
 return record;
}
export async function activeCliSession(id, storage, now=Date.now()) {
 const r=await storage.get('cli:'+id);
 return r?.state==='AUTHORIZED'&&now>=r.createdAt&&now<r.expiresAt?r:null;
}
const publicSession=r=>({id:r.id,name:r.name,state:r.state,createdAt:r.createdAt,expiresAt:r.expiresAt,account:r.account??null});
const fields={start:['token','name'],status:[],inspect:['code'],approve:['code'],deny:['code'],list:[],revoke:['id'],logout:[]};
export async function authRequest(request,env,storage,now=Date.now(),fetchImpl=fetch){
 try{
  const url=new URL(request.url),action=url.pathname.split('/').at(-1);
  if(request.method!=='POST'||url.search||url.pathname!=='/api/cli/'+action||!Object.hasOwn(fields,action))return reply({code:'AUTH_NOT_FOUND'},404);
  if(!(request.headers.get('content-type')??'').startsWith('application/json'))throw authError('AUTH_INPUT_INVALID');
  // Browser actions require same-site origin AND a server-validated account JWT.
  if(['inspect','approve','deny','list','revoke'].includes(action)&&request.headers.get('origin')!==env.PUBLIC_ORIGIN)throw authError('AUTH_ORIGIN_INVALID',403);
  const bucket=Math.floor(now/60000),rate=await storage.get('cli-rate');const count=rate?.bucket===bucket?rate.count+1:1;
  if(count>240)throw authError('AUTH_RATE_LIMITED',429);await storage.put('cli-rate',{bucket,count});
  const body=await boundedJson(request);
  if(!body||Array.isArray(body)||Object.keys(body).length!==fields[action].length||fields[action].some(k=>!Object.hasOwn(body,k)))throw authError('AUTH_INPUT_INVALID');
  const records=await storage.list({prefix:'cli:'});
  for(const [key,r]of records)if(now>=r.expiresAt){await storage.delete(key);records.delete(key);}
  const token=(request.headers.get('authorization')??'').replace(/^Bearer /,'');
  if(action==='start'){
   if(!/^sb_publishable_[A-Za-z0-9_-]+$/.test(env.SUPABASE_PUBLISHABLE_KEY??''))throw authError('AUTH_UNCONFIGURED',503);
   const match=TOKEN.exec(body.token??'');if(!match||typeof body.name!=='string'||!body.name.trim()||body.name.length>80||/[\x00-\x1f\x7f]/.test(body.name))throw authError('AUTH_INPUT_INVALID');
   const key='cli:'+match[1],prior=await storage.get(key);
   if(prior){if(now<prior.createdAt)throw authError('AUTH_CLOCK_INVALID',409);if(prior.hash!==await hash(body.token))throw authError('AUTH_CONFLICT',409);return reply({...publicSession(prior),code:prior.code});}
   if(records.size>=256)throw authError('AUTH_CAPACITY',429);
   const alphabet='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';const code=Array.from(crypto.getRandomValues(new Uint8Array(12)),n=>alphabet[n%32]).join('');
   if([...records.values()].some(r=>r.code===code))throw authError('AUTH_CONFLICT',409);
   const record={id:match[1],generation:crypto.randomUUID(),hash:await hash(body.token),name:body.name,state:'PENDING',code,createdAt:now,expiresAt:now+600000};
   await storage.put(key,record);return reply({...publicSession(record),code});
  }
  if(action==='status'||action==='logout'){
   const r=await cliSession(token,storage,now,true);
   if(action==='logout'){await storage.delete('cli:'+r.id);return reply({state:'REVOKED'});}
   return reply(publicSession(r));
  }
  const user=await accountUser(request,env,fetchImpl);
  if(action==='list')return reply({sessions:[...records.values()].filter(r=>r.account===user.account&&r.state==='AUTHORIZED').map(publicSession)});
  if(action==='revoke'){
   if(!/^[a-f0-9]{32}$/.test(body.id??''))throw authError('AUTH_INPUT_INVALID');
   const r=await storage.get('cli:'+body.id);if(!r||r.account!==user.account)throw authError('AUTH_NOT_FOUND',404);
   await storage.delete('cli:'+body.id);return reply({state:'REVOKED'});
  }
  if(!/^[A-HJ-NP-Z2-9]{12}$/.test(body.code??''))throw authError('AUTH_INPUT_INVALID');
  const r=[...records.values()].find(r=>r.code===body.code&&r.state==='PENDING'&&now>=r.createdAt);if(!r)throw authError('AUTH_EXPIRED_OR_USED',410);
  if(action==='inspect')return reply({name:r.name,code:r.code,expiresAt:r.expiresAt});
  if(action==='deny'){await storage.delete('cli:'+r.id);return reply({state:'DENIED'});}
  if([...records.values()].filter(record=>record.account===user.account&&record.state==='AUTHORIZED').length>=16)throw authError('AUTH_ACCOUNT_CAPACITY',429);
  r.state='AUTHORIZED';r.account=user.account;r.userId=user.id;r.expiresAt=now+30*86400000;r.code=null;
  await storage.put('cli:'+r.id,r);return reply(publicSession(r));
 }catch(error){return reply({code:/^AUTH_[A-Z_]+$/.test(error.code??'')?error.code:'AUTH_UNAVAILABLE'},/^AUTH_[A-Z_]+$/.test(error.code??'')?error.status:503);}
}
