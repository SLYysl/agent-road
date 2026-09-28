// Explicit durable task control, separate from runtime provisioning and desktop control.
import {randomUUID} from 'node:crypto';
import {constants} from 'node:fs';
import {open,mkdtemp} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,basename,isAbsolute} from 'node:path';
import {buildJobControl,validateJobRequest} from '../jobs/background-task.mjs';
import {executeRemoteScript} from '../remote/remote-exec.mjs';
import {createProductionRuntimeDependencies} from '../runtime/production-runtime-dependencies.mjs';
import {runProcess} from '../process/run-process.mjs';
// Opt-in raw byte records avoid lossy decoding when a log tail splits UTF-8.
export function jobConsoleResponse(response, includeOutput = false) {
  if (includeOutput) return { ...response };
  const { stdout, stderr, ...summary } = response;
  return summary;
}

export async function run(argv, env = process.env, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  let exitCode = 0;
  const includeOutput=argv[0]==='logs' && argv.length===4 && argv[3]==='--include-output';
  const args=includeOutput?argv.slice(0,3):argv;
  const [action,deviceId,arg,timeout='3600',...extra]=args;
  let save;
  try {
    if(!/^dev_[a-z0-9]{1,60}$/.test(deviceId??'')||extra.length
      || (action!=='start'&&args.length!==3))throw Error('JOB_INPUT_INVALID');
    let source;
    const jobId=action==='start'?'job_'+randomUUID().replaceAll('-',''):arg;
    if(action==='start'){
      if(!isAbsolute(arg??'')||!/^[1-9][0-9]{0,4}$/.test(timeout)||Number(timeout)>86400)throw Error('JOB_INPUT_INVALID');
      const file=await open(arg,constants.O_RDONLY|constants.O_NOFOLLOW);
      try{
        const stat=await file.stat();if(!stat.isFile()||stat.size>65536)throw Error('JOB_INPUT_INVALID');
        const bytes=Buffer.alloc(65537);let bytesRead=0;
        while(bytesRead<bytes.length){const result=await file.read(bytes,bytesRead,bytes.length-bytesRead,null);if(!result.bytesRead)break;bytesRead+=result.bytesRead;}
        if(bytesRead>65536)throw Error('JOB_INPUT_INVALID');
        source=new TextDecoder('utf8',{fatal:true}).decode(bytes.subarray(0,bytesRead));
      }finally{await file.close();}
    }
    const request={action,jobId,source,timeoutSeconds:Number(timeout)};
    validateJobRequest(request);
    const script=await buildJobControl(request);
    const directory=await mkdtemp(join(tmpdir(),'agent-road-background-'));
    save=async(name,value)=>{const f=await open(join(directory,name),'wx',0o600);try{await f.writeFile(value);await f.sync();}finally{await f.close();}};
    await save('request.json',JSON.stringify({action,deviceId,jobId,timeoutSeconds:request.timeoutSeconds}));
    await save('control.ps1',script);
    // Print/save identity before any remote mutation; never automatically replay a start.
    stdout.write(JSON.stringify({jobId,capture:basename(directory)})+'\n');
    const prod=createProductionRuntimeDependencies(env);const target=await prod.loadTarget(deviceId);
    const result=await executeRemoteScript({target,scriptPath:join(directory,'control.ps1'),timeoutMs:60000,
      dependencies:{runProcess,operationId:()=>randomUUID().replaceAll('-',''),clock:()=>new Date()}});
    await save('execution.json',JSON.stringify(result));
    if(result.exitCode!==0){const code=result.stderr.trim();throw Error(/^JOB_[A-Z_]+$/.test(code)?code:'JOB_CONTROL_FAILED');}
    const response=JSON.parse(result.stdout);
    if(response.jobId!==jobId)throw Error('JOB_RESPONSE_INVALID');
    await save('response.json',JSON.stringify(response));
    // Default remains metadata-only; logs can explicitly include bounded byte records.
    stdout.write(JSON.stringify(jobConsoleResponse(response,includeOutput))+'\n');
  }catch(error){
    const raw=error.code??error.message;
    const code=/^(?:JOB|REMOTE|FILE|LOCAL|SSH_IDENTITY|DEVICE)_[A-Z_]+$/.test(raw??'')?raw:'JOB_CONTROL_FAILED';
    if(save)await save('stopped.json',JSON.stringify({code}));
    stderr.write(code+'\n');exitCode=2;
  }
  return exitCode;
}
