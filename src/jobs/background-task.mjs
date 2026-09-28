import {readFile} from 'node:fs/promises';
const idPattern=/^job_[a-f0-9]{32}$/;
export function validateJobRequest({action,jobId,source,timeoutSeconds=3600}) {
  if(!['start','status','logs','cancel','remove'].includes(action)||!idPattern.test(jobId??'')) throw new Error('JOB_INPUT_INVALID');
  if(action==='start' && (typeof source!=='string'||!source.trim()||source.includes('\0')||Buffer.byteLength(source)>65536
    ||!Number.isInteger(timeoutSeconds)||timeoutSeconds<1||timeoutSeconds>86400))throw new Error('JOB_INPUT_INVALID');
}
export async function buildJobControl(request) {
  validateJobRequest(request);
  const {action,jobId,source,timeoutSeconds=3600}=request;
  const files=action==='start'?{
    'worker.ps1':await readFile(new URL('./worker.ps1',import.meta.url),'utf8'),
    'runner.cs':await readFile(new URL('./runner.cs',import.meta.url),'utf8'),
    'task.ps1':source,
    'config.json':JSON.stringify({timeoutSeconds}),
  }:{};
  const payload=Buffer.from(JSON.stringify({action,jobId,files,timeoutSeconds})).toString('base64');
  const control=await readFile(new URL('./control.ps1',import.meta.url),'utf8');
  return `$request=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}'))|ConvertFrom-Json\n${control}`;
}
