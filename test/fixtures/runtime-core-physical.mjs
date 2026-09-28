import {readFile} from 'node:fs/promises';
import {gzipSync} from 'node:zlib';
// Explicit physical fixture: reads one enrolled, signed staged archive but all
// writes and executable checks occur in a fresh private temporary runtime.
export async function buildRuntimeCorePhysicalFixture({operationId,manifestDigest}) {
 if(!/^[a-f0-9]{32}$/.test(operationId)||!/^[A-F0-9]{64}$/.test(manifestDigest))throw Error('FIXTURE_INPUT');
 let source=await readFile(new URL('../../windows/runtime-provision-core.ps1',import.meta.url),'utf8');
 const marker='\n$lock = $null\n$capsule = $null';if(source.split(marker).length!==2)throw Error('FIXTURE_BOUNDARY');
 source=source.replace("$script:AgentRoadRoot = 'C:\\ProgramData\\AgentRoad'",'$script:AgentRoadRoot = $script:FixtureRoot')
  .replaceAll('Global\\AgentRoadRuntimeMutation','Global\\AgentRoadCorePhysicalFixture')
  .replace('    $failureCode = Get-AgentRoadFailureCode $_','    $script:FixtureErrorId=$_.FullyQualifiedErrorId; $script:FixtureErrorLine=$_.InvocationInfo.ScriptLineNumber; $script:FixtureErrorType=$_.Exception.GetBaseException().GetType().FullName; $script:FixtureErrorHResult=$_.Exception.GetBaseException().HResult\n    $failureCode = Get-AgentRoadFailureCode $_')
  .replace('    $stream = New-Object IO.FileStream(', '    $script:FixtureLastPath=$Path; $script:FixtureLastParentExists=[IO.Directory]::Exists([IO.Path]::GetDirectoryName($Path))\n    $stream = New-Object IO.FileStream(')
  .replace('[Console]::Out.Write($json)','$script:FixtureWireResult=$json')
  .replace(/\nexit \$exitCode\s*$/u,'\n');
 const setup=`
$script:BootstrapRoot='C:\\ProgramData\\AgentRoad\\bootstrap'
$script:BootstrapStageZeroJournalPath=Join-Path $script:BootstrapRoot 'stage-zero-journal.json'
function Read-AgentRoadInvocation {return [pscustomobject][ordered]@{schemaVersion=1;operationId='${operationId}';manifestDigest='${manifestDigest}'}}
$original='C:\\ProgramData\\AgentRoad\\runtime\\staging\\${operationId}\\${manifestDigest}'
Ensure-AgentRoadRestrictedDirectory $script:RuntimeRoot $script:AgentRoadRoot
Ensure-AgentRoadRestrictedDirectory $script:StagingRoot $script:RuntimeRoot
$operation=Join-Path $script:StagingRoot '${operationId}';Ensure-AgentRoadRestrictedDirectory $operation $script:StagingRoot
$transaction=Join-Path $operation '${manifestDigest}';Ensure-AgentRoadRestrictedDirectory $transaction $operation
$files=Join-Path $transaction 'files';Ensure-AgentRoadRestrictedDirectory $files $transaction
$bytes=[IO.File]::ReadAllBytes((Join-Path $original 'capsule.json'));Write-AgentRoadImmutableBytes (Join-Path $transaction 'capsule.json') $bytes
$c=$script:Utf8.GetString($bytes)|ConvertFrom-Json;$m=$c.manifestJson|ConvertFrom-Json;$name='powershell-7-'+$m.components[0].version+'.zip'
$inputFile=[IO.File]::OpenRead((Join-Path $original ('files\\'+$name)));$outputFile=New-AgentRoadRestrictedFileStream (Join-Path $files $name) 8192
try{$inputFile.CopyTo($outputFile);$outputFile.Flush($true)}finally{$outputFile.Dispose();$inputFile.Dispose()}
`;
 source=source.replace(marker,setup+marker);
 const encoded=gzipSync(Buffer.from(source)).toString('base64');
 return `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$script:FixtureRoot=Join-Path ([IO.Path]::GetPathRoot($env:ProgramData)) ('ARFixture-'+[guid]::NewGuid().ToString('N'));$script:FixtureErrorId=$null;$script:FixtureErrorLine=$null;$script:FixtureLastPath=$null;$script:FixtureLastParentExists=$null;$script:FixtureErrorType=$null;$script:FixtureErrorHResult=$null;$script:FixtureWireResult=$null
$security=New-Object Security.AccessControl.DirectorySecurity;$security.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)');$null=[IO.Directory]::CreateDirectory($script:FixtureRoot,$security)
try{
 $z=[Convert]::FromBase64String('${encoded}');$ms=New-Object IO.MemoryStream(,$z);$gz=New-Object IO.Compression.GZipStream($ms,[IO.Compression.CompressionMode]::Decompress);$out=New-Object IO.MemoryStream;$buf=New-Object byte[] 8192
 while(($n=$gz.Read($buf,0,$buf.Length)) -gt 0){if($out.Length+$n -gt 262144){throw 'FIXTURE_BOUND'};$out.Write($buf,0,$n)};$gz.Dispose();$ms.Dispose();$text=[Text.Encoding]::UTF8.GetString($out.ToArray());$out.Dispose()
 $fixtureScript=Join-Path $script:FixtureRoot 'core-fixture.ps1';[IO.File]::WriteAllText($fixtureScript,$text,(New-Object Text.UTF8Encoding($false)));$fileSecurity=New-Object Security.AccessControl.FileSecurity;$fileSecurity.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)');[IO.File]::SetAccessControl($fixtureScript,$fileSecurity)
 $pipeline=@(. $fixtureScript);$result=$script:FixtureWireResult|ConvertFrom-Json
 [Console]::Out.Write((@{isolated=$true;status=$result.status;failureCode=$result.failureCode;pipelineOutputCount=$pipeline.Count;errorId=$script:FixtureErrorId;errorLine=$script:FixtureErrorLine;errorType=$script:FixtureErrorType;errorHResult=$script:FixtureErrorHResult;lastPath=$script:FixtureLastPath;parentExists=$script:FixtureLastParentExists;activePointerExists=[IO.File]::Exists((Join-Path $script:FixtureRoot 'runtime\\state\\active.json'));completedPhases=@($script:Journal.completedPhases)}|ConvertTo-Json -Compress -Depth 4))
}finally{[IO.Directory]::Delete($script:FixtureRoot,$true)}`;
}
