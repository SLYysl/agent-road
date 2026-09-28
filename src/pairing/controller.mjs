import { validateNativeConfiguration } from '../installer/configuration.mjs';
import { loadCliCredential, authCall } from '../auth/client.mjs';
import { buildJoinCommand } from './loader.mjs';
import { observePairDelivery } from './delivery-observation.mjs';
import { EventEmitter } from 'node:events';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { tmpdir } from 'node:os';
import { createInterface } from 'node:readline/promises';
import { parseArgs } from 'node:util';
import { statePaths } from '../core/paths.mjs';
import { buildWindowsPairedStageZeroCommand } from '../enrollment/windows-stage-zero.mjs';
import { loadPairingConfig, newPairIdentity, pairRequest } from './client.mjs';
import { createPairAuthKey, revokePairAuthKey } from './tailscale-key.mjs';
import { pairingError, validateBootstrap } from './protocol.mjs';

export async function runPairCommand(args, env = process.env, io = {}, injected = {}) {
  const stdout = io.stdout ?? process.stdout, stderr = io.stderr ?? process.stderr;
  let directory, bridge, pair, config, request, enrollmentExit, bridgeFailure, authKeyId, createAttempted = false, cleanupUncertain = false, protocolVersion = 1;
  const source = new EventEmitter(), cancellation = new AbortController();
  const stop = () => { cancellation.abort(); source.emit('SIGINT'); };
  const save = async(name,value) => { if(directory)await writeFile(join(directory,name),JSON.stringify(value)+'\n',{mode:0o600}); };
  try {
    const {values}=parseArgs({args,strict:true,options:{'native-preview':{type:'boolean',default:false},name:{type:'string',default:'New Windows PC'},config:{type:'string'},'timeout-minutes':{type:'string',default:'30'}}});
    protocolVersion = values['native-preview'] ? 2 : 1;
    if (protocolVersion === 2 && env.AGENT_ROAD_NATIVE_PREVIEW !== '1') throw pairingError('PAIR_NATIVE_PREVIEW_REQUIRED');
    if(!/^(?:[5-9]|[12][0-9]|30)$/.test(values['timeout-minutes']))throw pairingError('PAIR_INPUT_INVALID');
    let loggedIn;
    if (!values.config) {
      try { loggedIn = await loadCliCredential(env); } catch (error) { if (error.code !== 'AUTH_LOGIN_REQUIRED') throw pairingError('PAIR_LOGIN_REQUIRED', 401); }
    }
    try { config=await loadPairingConfig(values.config??join(statePaths(env).root,'pairing.json'), {controllerToken:loggedIn?.token}); }
    catch(error) { if (loggedIn && error.code === 'PAIR_CONFIG_REQUIRED') throw pairingError('PAIR_NETWORK_CONFIG_REQUIRED'); throw error; }
    if (loggedIn && config.origin !== loggedIn.origin) throw pairingError('PAIR_CONFIG_INVALID');
    if (!config.adminToken) {
      let credential;
      try { credential = await loadCliCredential(env); } catch { throw pairingError('PAIR_LOGIN_REQUIRED', 401); }
      if (credential.origin !== config.origin) throw pairingError('PAIR_CONFIG_INVALID');
      config.adminToken = credential.token;
    }
    if (config.adminToken?.startsWith('ar1.')) {
      try {
        const session = await (injected.authStatus ?? authCall)(config.origin, 'status', {}, config.adminToken);
        if (session.state !== 'AUTHORIZED') throw new Error('pending');
      } catch { throw pairingError('PAIR_LOGIN_REQUIRED', 401); }
    }
    if(!injected.confirm && !process.stdin.isTTY)throw pairingError('PAIR_INTERACTIVE_CONFIRMATION_REQUIRED');
    directory=await mkdtemp(join(tmpdir(),'agent-road-pair-'));
    pair=newPairIdentity();
    await save('request.json',{origin:config.origin,protocolVersion,...pair});
    process.on('SIGINT',stop);process.on('SIGTERM',stop);
    if(config.apiToken){
      await save('auth-key-create-started.json',{started:true,expirySeconds:900});
      const created=await (injected.createAuthKey??createPairAuthKey)(config.apiToken,`Agent Road ${pair.code}`);
      authKeyId=created.id;config.authKey=created.key;
      await save('auth-key-created.json',{id:authKeyId});
    }
    if(cancellation.signal.aborted)throw pairingError('PAIR_CANCELLED');
    const call=injected.request??pairRequest;
    request=(action,body)=>call(config.origin,action,body,{protocolVersion,signal:cancellation.signal,adminToken:action==='create'||config.adminToken?.startsWith('ar1.')?config.adminToken:undefined});
    const confirm=injected.confirm??(async(verification)=>{
      const terminal=createInterface({input:process.stdin,output:stderr});
      try{return (await terminal.question(`Enter the eight-digit code shown on Windows to approve: `,{signal:cancellation.signal})).trim()===verification;}
      finally{terminal.close();}
    });
    const poll=injected.poll??(()=>new Promise((resolve,reject)=>{
      const done=()=>{clearTimeout(timer);cancellation.signal.removeEventListener('abort',abort);resolve();};
      const abort=()=>{clearTimeout(timer);cancellation.signal.removeEventListener('abort',abort);reject(pairingError('PAIR_CANCELLED'));};
      const timer=setTimeout(done,2000);cancellation.signal.addEventListener('abort',abort,{once:true});
      if(cancellation.signal.aborted)abort();
    }));
    const {main,createProductionDependencies}=await import('../cli.mjs');
    const enroll=injected.enroll??main;
    const publish=async(command)=>{
      await save('create-started.json',{started:true});
      createAttempted=true;
      const created=await request('create',{code:pair.code,ownerToken:pair.ownerToken});
      await save('created.json',created);
      if(!Number.isSafeInteger(created.expiresAt) || created.expiresAt<=Date.now())throw pairingError('PAIR_RESPONSE_INVALID');
      if (protocolVersion === 2 && (created.protocolVersion !== 2 || created.deliveryKind !== 'configuration')) throw pairingError('PAIR_RESPONSE_INVALID');
      if (protocolVersion === 2) stdout.write(`AgentRoadNativeSetup.exe --pair ${pair.code} --accept-system-changes\n`);
      else stdout.write((created.codeInJoinUrl === true ? buildJoinCommand(config.origin, pair.code) : `irm ${config.origin}/join.ps1 | iex`)+'\n');
      stdout.write(`Pairing code: ${pair.code.match(/.{4}/g).join('-')}\n`);
      stderr.write(`PAIR_WAITING capture=${basename(directory)}\n`);
      const deadline=Math.min(Date.now()+600000,created.expiresAt);
      while(Date.now()<deadline){
        const status=await request('status',{code:pair.code,ownerToken:pair.ownerToken});
        await save('status.json',status);
        if(status.state==='CLAIMED'){
          if(!/^[a-f0-9]{64}$/.test(status.claim?.id??'')||!/^\d{8}$/.test(status.claim?.verification??''))throw pairingError('PAIR_RESPONSE_INVALID');
          if(!await confirm(status.claim.verification))throw pairingError('PAIR_APPROVAL_DECLINED');
          if (protocolVersion === 2) command = {...command,expiresAt:Math.min(command.expiresAt,created.expiresAt)};
          await save('approval-started.json',{claimId:status.claim.id});
          const approved=await request('approve',{code:pair.code,ownerToken:pair.ownerToken,claimId:status.claim.id,...(protocolVersion === 2 ? {configuration:validateNativeConfiguration(command,{origin:config.origin,now:Date.now(),expiresAt:created.expiresAt})} : {command})});
          if(approved.state!=='APPROVED')throw pairingError('PAIR_RESPONSE_INVALID');
          await save('approved.json',approved);
          stderr.write(protocolVersion === 2 ? 'PAIR_APPROVED: waiting for native configuration retrieval.\n' : 'PAIR_APPROVED: waiting for Windows to retrieve bootstrap.\n');
          const delivery=await observePairDelivery({request:()=>request('status',{code:pair.code,ownerToken:pair.ownerToken}),signal:cancellation.signal});
          await save('delivery-observation.json',delivery);
          if(delivery.state==='DELIVERED')stderr.write('PAIR_DELIVERED: retrieval confirmed; execution and enrollment are not yet confirmed.\n');
          if(delivery.state==='DELIVERY_UNCONFIRMED')stderr.write('PAIR_DELIVERY_UNCONFIRMED: inspect the original Windows attempt; do not replay or re-pair. Enrollment continues within its existing timeout.\n');
          return;
        }
        if(status.state!=='WAITING')throw pairingError('PAIR_RESPONSE_INVALID');
        await poll();
      }
      throw pairingError('PAIR_EXPIRED');
    };
    enrollmentExit=await enroll(['enroll','--name',values.name,'--timeout-minutes',values['timeout-minutes']],env,{
      ...io,signalSource:source,
      dependencyFactory:async()=>{
        const deps=await (injected.dependencies??createProductionDependencies)(env);
        if (protocolVersion === 1) return {...deps,buildCommand:options=>buildWindowsPairedStageZeroCommand(options,config.authKey)};
        return {...deps,
          startReceiver: ({signer,stageOneBytes,...options}) => deps.startReceiver({...options,protocolVersion:2}),
          buildCommand: options => 'AGENT_ROAD_NATIVE_CONFIGURATION:' + JSON.stringify(validateNativeConfiguration({
            schemaVersion:2,kind:'agent-road-native-enrollment',pairingOrigin:config.origin,
            deviceId:options.deviceId,controllerBaseUrl:options.controllerBaseUrl,enrollmentToken:options.token,
            tailscaleAuthKey:config.authKey,expiresAt:Date.now()+600000,
          },{origin:config.origin,now:Date.now(),expiresAt:Date.now()+600000})),
        };
      },
      stdout:{write(value){
        if(protocolVersion === 2 ? value.startsWith('AGENT_ROAD_NATIVE_CONFIGURATION:') : value.startsWith('powershell.exe ')){
          if(bridge)throw pairingError('PAIR_DUPLICATE_BOOTSTRAP');
          const command=protocolVersion === 2 ? JSON.parse(value.slice('AGENT_ROAD_NATIVE_CONFIGURATION:'.length)) : validateBootstrap(value.trim());
          bridge=publish(command).catch(error=>{bridgeFailure=error;stop();});
        }else {
          if (protocolVersion === 2 && value.startsWith('powershell.exe ')) throw pairingError('PAIR_PROTOCOL_UNSUPPORTED');
          stdout.write(value);
        }
      }},stderr,
    });
    cancellation.abort();
    if(bridge)await bridge;
    if(bridgeFailure)throw bridgeFailure;
    if(!bridge)throw pairingError('PAIR_ENROLLMENT_FAILED');
    await save('result.json',{enrollmentExit});
    return enrollmentExit;
  }catch(error){
    const code=/^PAIR_[A-Z_]+$/.test(error?.code??'')?error.code:'PAIR_FAILED';
    await save('stopped.json',{code});stderr.write(`${code}\n`);return 2;
  }finally{
    stop();process.off('SIGINT',stop);process.off('SIGTERM',stop);
    if(bridge)await bridge;
    if(createAttempted){
      try {
        const result=await (injected.request??pairRequest)(config.origin,'cancel',{code:pair.code,ownerToken:pair.ownerToken},{protocolVersion,adminToken:config.adminToken?.startsWith('ar1.')?config.adminToken:undefined});
        await save('cancelled.json',result);
      }catch(error){
        if(['PAIR_ALREADY_DELIVERED','PAIR_EXPIRED','PAIR_UNAVAILABLE'].includes(error.code)){
          await save('cancel-outcome.json',{code:error.code});
        }else{
          cleanupUncertain=true;
          await save('cleanup-uncertain.json',{code:'PAIR_CLEANUP_UNCERTAIN'});stderr.write('PAIR_CLEANUP_UNCERTAIN\n');
        }
      }
    }
    if(authKeyId){
      try{await (injected.revokeAuthKey??revokePairAuthKey)(config.apiToken,authKeyId);await save('auth-key-revoked.json',{id:authKeyId});}
      catch{cleanupUncertain=true;await save('auth-key-cleanup-uncertain.json',{id:authKeyId});stderr.write('PAIR_AUTH_KEY_CLEANUP_UNCERTAIN\n');}
    }
    if(config){config.authKey=null;config.adminToken=null;config.apiToken=null;}
    if(cleanupUncertain)return 2;
  }
}
