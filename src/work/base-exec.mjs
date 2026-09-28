// Explicit task execution against a previously observed, device-bound tool set.
import {randomUUID} from 'node:crypto';
import {constants} from 'node:fs';
import {lstat, mkdtemp, open} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {basename, isAbsolute, join} from 'node:path';
import {runProcess} from '../process/run-process.mjs';
import {executeRemoteScript} from '../remote/remote-exec.mjs';
import {createProductionRuntimeDependencies} from '../runtime/production-runtime-dependencies.mjs';
import {bindExistingTools, buildExistingTaskScript} from '../runtime/existing-task.mjs';

export async function run(argv, env = process.env, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  let exitCode = 0;
  const [deviceId, inspection, scriptPath, toolNames, timeoutSeconds = '300', ...extra]=argv;
  const fail=code=>{throw Object.assign(new Error(code),{code});};
  const safeCode=error=>/^(?:EXISTING_TASK|EXISTING_BASE|RUNTIME|REMOTE|FILE|LOCAL|PROCESS|DEVICE|SSH_IDENTITY)_[A-Z_]+$/.test(error?.code??'')
    ? error.code : 'EXISTING_TASK_FAILED';
  async function readBounded(path, maximum, privateFile=false) {
    const file=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW);
    try {
      const stat=await file.stat();
      if(!stat.isFile() || stat.size>maximum || (privateFile && (stat.uid!==process.getuid() || (stat.mode&0o077)!==0))) fail('EXISTING_TASK_INPUT_INVALID');
      const buffer=Buffer.alloc(maximum+1);
      let length=0;
      while(length<buffer.length){const {bytesRead}=await file.read(buffer,length,buffer.length-length,null);if(!bytesRead)break;length+=bytesRead;}
      if(length>maximum)fail('EXISTING_TASK_INPUT_INVALID');
      return new TextDecoder('utf-8',{fatal:true}).decode(buffer.subarray(0,length));
    } finally {await file.close();}
  }
  if(!/^dev_[a-z0-9]{1,60}$/.test(deviceId??'') || !isAbsolute(inspection??'') || !isAbsolute(scriptPath??'')
    || !/^(git|node|python|rg)(,(git|node|python|rg))*$/.test(toolNames??'')
    || !/^[1-9][0-9]{0,3}$/.test(timeoutSeconds) || Number(timeoutSeconds)>1800 || extra.length) {
    stderr.write('Usage: node tools/run-existing-task.mjs <device-id> <absolute-inspection-directory> <absolute-task.ps1> <git,node,python,rg subset> [timeout-seconds:1-1800]\n');
    exitCode=2;
  } else {
    let save;
    try {
      const stat=await lstat(inspection);
      if(!stat.isDirectory() || stat.uid!==process.getuid() || (stat.mode&0o077)!==0) fail('EXISTING_TASK_INPUT_INVALID');
      const context=JSON.parse(await readBounded(join(inspection,'context.json'),65536,true));
      const execution=JSON.parse(await readBounded(join(inspection,'execution.json'),131072,true));
      if(context.deviceId!==deviceId || execution.deviceId!==deviceId || execution.operation!=='exec'
        || execution.exitCode!==0 || execution.stderr!=='') fail('EXISTING_TASK_DEVICE_MISMATCH');
      const bindings=bindExistingTools(execution.stdout,toolNames.split(','));
      const source=await readBounded(scriptPath,65536);
      const wrapper=buildExistingTaskScript(bindings,source);
      const directory=await mkdtemp(join(tmpdir(),'agent-road-existing-task-'));
      save=async(name, value, raw=false)=>{
        const file=await open(join(directory,name),'wx',0o600);
        try{await file.writeFile(raw?value:JSON.stringify(value)+'\n');await file.sync();}finally{await file.close();}
      };
      await save('binding.json',{deviceId,bindings,inspection,timeoutSeconds:Number(timeoutSeconds)});
      await save('task.ps1',wrapper,true);
      stdout.write(JSON.stringify({capture:basename(directory)})+'\n');
      const dependencies=createProductionRuntimeDependencies(env);
      const target=await dependencies.loadTarget(deviceId);
      let step=0;
      const runner=async(command,args,options)=>{
        const index=++step;
        await save(`${index}-started.json`,{command:basename(command),timeoutMs:options.timeoutMs});
        try{
          const result=await runProcess(command,args,options);
          await save(`${index}-result.json`,{exitCode:result.exitCode,signal:result.signal,stdout:result.stdout,stderr:result.stderr});
          return result;
        }catch(error){await save(`${index}-failed.json`,{code:safeCode(error)});throw error;}
      };
      const result=await executeRemoteScript({target,scriptPath:join(directory,'task.ps1'),timeoutMs:Number(timeoutSeconds)*1000,
        dependencies:{runProcess:runner,operationId:()=>randomUUID().replaceAll('-',''),clock:()=>new Date()}});
      await save('execution.json',result);
      stdout.write(JSON.stringify({status:result.exitCode===0?'TASK_SUCCEEDED':'TASK_FAILED',exitCode:result.exitCode,
        tools:Object.keys(bindings),stdoutBytes:Buffer.byteLength(result.stdout),stderrBytes:Buffer.byteLength(result.stderr)})+'\n');
      exitCode=result.exitCode===0?0:1;
    }catch(error){const code=safeCode(error);if(save)await save('stopped.json',{code});stderr.write(code+'\n');exitCode=2;}
  }
  return exitCode;
}
