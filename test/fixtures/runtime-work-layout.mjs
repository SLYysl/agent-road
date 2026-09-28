import { readFile } from 'node:fs/promises';

// Run explicitly on Windows: real filesystem checks, no managed runtime mutation.
export async function buildRuntimeWorkLayoutFixture() {
  const source = await readFile(new URL('../../windows/runtime-provision-core.ps1', import.meta.url), 'utf8');
  const start = source.indexOf('function Get-AgentRoadTransaction {');
  const end = source.indexOf('function Assert-AgentRoadStagedTransaction {', start);
  if (start < 0 || end <= start) throw new Error('FIXTURE_BOUNDARY');
  return String.raw`$ErrorActionPreference='Stop'
function Assert-AgentRoadDirectoryNode($Path){if(-not [IO.Directory]::Exists($Path)){throw 'FIXTURE_DIRECTORY'}}
${source.slice(start, end)}
$root=Join-Path $env:TEMP ('ar-layout-'+[guid]::NewGuid().ToString('N'))
$script:RuntimeRoot=$root;$script:StagingRoot=Join-Path $root 'staging'
[IO.Directory]::CreateDirectory($script:StagingRoot)|Out-Null
try {
 $inv=[pscustomobject]@{operationId=('a'*32);manifestDigest=('B'*64)}
 $fresh=Get-AgentRoadTransaction $inv
 if([IO.Path]::GetFileName($fresh.workRoot) -cne 'work'){throw 'NEW_LAYOUT_FAILED'}
 $legacy=Join-Path $fresh.operationRoot ('work-'+$inv.manifestDigest)
 [IO.Directory]::CreateDirectory($legacy)|Out-Null
 $old=Get-AgentRoadTransaction $inv
 if($old.workRoot -cne $legacy){throw 'LEGACY_LAYOUT_FAILED'}
 [IO.Directory]::CreateDirectory($fresh.workRoot)|Out-Null
 $rejected=$false
 try{Get-AgentRoadTransaction $inv|Out-Null}catch{if($_.Exception.Message -ne 'RUNTIME_STATE_UNSUPPORTED'){throw};$rejected=$true}
 if(-not $rejected){throw 'COEXISTENCE_NOT_REJECTED'}
 [Console]::Out.Write('{"newLayout":true,"legacyLayout":true,"coexistenceRejected":true}')
}finally{[IO.Directory]::Delete($root,$true)}
`;
}
