import {assessExistingBase, parseExistingBase} from './existing-base.mjs';
const issued = new WeakSet();
function invalid() { throw Object.assign(new Error('EXISTING_TASK_BINDING_FAILED'), {code:'EXISTING_TASK_BINDING_FAILED'}); }

export function bindExistingTools(reportText, requested) {
  if (!Array.isArray(requested) || requested.length < 1 || requested.length > 4
    || new Set(requested).size !== requested.length
    || requested.some(tool => !['git','node','python','rg'].includes(tool))) invalid();
  const assessment=assessExistingBase(parseExistingBase(reportText));
  const bindings={};
  for (const tool of requested) {
    const result=assessment.tools.find(item => item.tool===tool);
    if (result.action !== 'reuse') invalid();
    const candidate=result.candidates.find(item => item.status==='verified'
      && (tool!=='python' || item.environmentModules));
    bindings[tool]=Object.freeze({path:candidate.path, sha256:candidate.sha256, version:candidate.version});
  }
  Object.freeze(bindings); issued.add(bindings); return bindings;
}

export function buildExistingTaskScript(bindings, source) {
  if (!issued.has(bindings) || typeof source !== 'string' || !source.trim()
    || source.includes('\0') || Buffer.byteLength(source)>65536) invalid();
  const payload=Buffer.from(JSON.stringify(bindings)).toString('base64');
  const script=Buffer.from(source).toString('base64');
  return `$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$OutputEncoding=New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding=$OutputEncoding
[Console]::InputEncoding=$OutputEncoding
$env:PYTHONIOENCODING='utf-8'
$binding=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}'))|ConvertFrom-Json
$handles=New-Object Collections.Generic.List[object]
$AgentRoadTools=@{}
try {
  foreach($entry in $binding.PSObject.Properties) {
    $candidate=$entry.Value
    $part=Get-Item -LiteralPath $candidate.path -Force -ErrorAction Stop
    if($part -isnot [IO.FileInfo]){throw 'EXISTING_TASK_TOOL_CHANGED'}
    while($null -ne $part){
      if(($part.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'EXISTING_TASK_TOOL_CHANGED'}
      if($part -is [IO.FileInfo]){$part=$part.Directory}else{$part=$part.Parent}
    }
    # Deny ordinary write/delete replacement through the end of this task.
    $handle=[IO.File]::Open($candidate.path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $handles.Add($handle)
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try{$hash=[BitConverter]::ToString($algorithm.ComputeHash($handle)).Replace('-','')}finally{$algorithm.Dispose()}
    if($hash -cne $candidate.sha256){throw 'EXISTING_TASK_TOOL_CHANGED'}
    $AgentRoadTools[$entry.Name]=$candidate.path
  }
} catch {
  foreach($handle in $handles){$handle.Dispose()}
  [Console]::Error.WriteLine('EXISTING_TASK_TOOL_CHANGED')
  exit 78
}
try {
  Remove-Item Env:NODE_OPTIONS,Env:NODE_PATH,Env:PYTHONHOME,Env:PYTHONPATH -ErrorAction SilentlyContinue
  $global:LASTEXITCODE=0
  & ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${script}'))))
  if(!$?){exit 1}
  exit $LASTEXITCODE
} finally {
  foreach($handle in $handles){$handle.Dispose()}
}
`;
}
