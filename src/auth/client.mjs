import { randomBytes } from 'node:crypto';
import { mkdir, lstat, open, rename, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { hostname } from 'node:os';
import { spawn } from 'node:child_process';
import { statePaths } from '../core/paths.mjs';
import { readPrivateText } from '../pairing/client.mjs';
import { authError, boundedJson } from './service.mjs';
const DEFAULT_ORIGIN='https://agent-road.brahma-technologies.com';
export async function credentialPath(env=process.env){
 const dir=join(statePaths(env).root,'cli-auth');await mkdir(dir,{recursive:true,mode:0o700});
 const stat=await lstat(dir);if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid()||(stat.mode&0o077))throw authError('AUTH_STORAGE_UNSAFE');
 return join(dir,'credential.json');
}
export async function loadCliCredential(env=process.env){
 let record;try{record=JSON.parse(await readPrivateText(await credentialPath(env)));}catch(e){if(e.code==='ENOENT')throw authError('AUTH_LOGIN_REQUIRED',401);throw authError('AUTH_STORAGE_UNSAFE');}
 if(!/^ar1\.[a-f0-9]{32}\.[A-Za-z0-9_-]{43}$/.test(record.token??'')||record.origin!==DEFAULT_ORIGIN)throw authError('AUTH_STORAGE_UNSAFE');
 return record;
}
async function save(path,record){
 const tmp=path+'.'+randomBytes(8).toString('hex');const handle=await open(tmp,'wx',0o600);
 try{await handle.writeFile(JSON.stringify(record)+'\n');await handle.sync();}finally{await handle.close();}
 try{await rename(tmp,path);}catch(e){await unlink(tmp).catch(()=>{});throw e;}
}
export async function authCall(origin,action,body,token,fetchImpl=fetch){
 let response;try{response=await fetchImpl(origin+'/api/cli/'+action,{method:'POST',headers:{'content-type':'application/json',...(token?{authorization:'Bearer '+token}:{})},body:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(12000)});}catch{throw authError('AUTH_NETWORK_UNCERTAIN');}
 let result;try{result=await boundedJson(response);}catch{throw authError('AUTH_SERVICE_UNAVAILABLE');}
 if(!response.ok)throw authError(/^AUTH_[A-Z_]+$/.test(result?.code??'')?result.code:'AUTH_SERVICE_UNAVAILABLE',response.status);
 return result;
}
export async function runAuthCommand(command,args,env=process.env,io={},injected={}){
 const out=io.stdout??process.stdout,err=io.stderr??process.stderr;let lock,path;let cancelled=false;const stop=()=>{cancelled=true;};
 try{
  if(args.some(x=>x!=='--no-browser')||(command!=='login'&&args.length)||args.length>1)throw authError('AUTH_INPUT_INVALID');
  path=await credentialPath(env);lock=await open(path+'.lock','wx',0o600);process.on('SIGINT',stop);process.on('SIGTERM',stop);
  let credential;try{credential=await loadCliCredential(env);}catch(e){if(e.code!=='AUTH_LOGIN_REQUIRED')throw e;}
  const call=(action,body={},token=credential?.token)=>(injected.call??authCall)(DEFAULT_ORIGIN,action,body,token);
  if(command==='logout'){
   if(!credential){out.write('Not logged in.\n');return 0;}
   try{await call('logout');}catch(e){if(e.code!=='AUTH_REQUIRED')throw e;}
   await unlink(path);out.write('Controller authorization revoked; existing device SSH access is unchanged.\n');return 0;
  }
  if(command==='whoami'){
   if(!credential)throw authError('AUTH_LOGIN_REQUIRED',401);
   const r=await call('status');if(r.state!=='AUTHORIZED')throw authError('AUTH_LOGIN_REQUIRED',401);
   out.write(JSON.stringify({account:r.account,controllerId:r.id,expiresAt:r.expiresAt})+'\n');return 0;
  }
  if(!credential){credential={origin:DEFAULT_ORIGIN,token:'ar1.'+randomBytes(16).toString('hex')+'.'+randomBytes(32).toString('base64url')};await save(path,credential);}
  const started=await call('start',{token:credential.token,name:hostname().slice(0,80)});
  if(started.state==='AUTHORIZED'){out.write('Already authorized. Use agent-road whoami.\n');return 0;}
  if(started.state!=='PENDING'||!Number.isSafeInteger(started.expiresAt)||!/^[A-HJ-NP-Z2-9]{12}$/.test(started.code??''))throw authError('AUTH_RESPONSE_INVALID');
  const url=DEFAULT_ORIGIN+'/en/auth/cli?code='+started.code;
  out.write(`Open ${url}\nConfirm this code in the browser: ${started.code}\n`);
  if(!args.includes('--no-browser')){
   const browser=(injected.openBrowser??(url=>{const child=spawn('open',[url],{stdio:'ignore'});child.on('error',()=>{});child.unref();}));browser(url);
  }
  const deadline=Math.min(Date.now()+600000,started.expiresAt);
  while(Date.now()<deadline){
   await (injected.wait??(()=>new Promise(resolve=>setTimeout(resolve,3000))))();
   if(cancelled)throw authError('AUTH_CANCELLED');
   const r=await call('status');
   if(r.state==='AUTHORIZED'){out.write('Login authorized. Pairing still requires this controller’s own network configuration.\n');return 0;}
   if(r.state!=='PENDING')throw authError('AUTH_RESPONSE_INVALID');
  }
  throw authError('AUTH_EXPIRED');
 }catch(e){err.write((e.code==='EEXIST'?'AUTH_COMMAND_BUSY':/^AUTH_[A-Z_]+$/.test(e.code??'')?e.code:'AUTH_FAILED')+'\n');return 2;}
 finally{process.off('SIGINT',stop);process.off('SIGTERM',stop);if(lock){await lock.close();await unlink(path+'.lock').catch(()=>{});}}
}
