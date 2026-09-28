import {readFile} from 'node:fs/promises';

export async function buildRuntimeZipEntryFixture() {
  const source = await readFile(new URL('../../windows/runtime-provision-core.ps1', import.meta.url), 'utf8');
  const start = source.indexOf('function Assert-AgentRoadZipEntry {');
  const end = source.indexOf('\nfunction Expand-AgentRoadPowerShellArchive', start);
  if (start < 0 || end < 0) throw Error('FIXTURE_BOUNDARY');
  return `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
Add-Type -AssemblyName System.IO.Compression
${source.slice(start, end)}
$memory=New-Object IO.MemoryStream
$writer=New-Object IO.Compression.ZipArchive($memory,[IO.Compression.ZipArchiveMode]::Create,$true)
$null=$writer.CreateEntry('first.txt');$null=$writer.CreateEntry('FIRST.TXT');$writer.Dispose();$memory.Position=0
$reader=New-Object IO.Compression.ZipArchive($memory,[IO.Compression.ZipArchiveMode]::Read,$true)
try {
 $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
 $record=Assert-AgentRoadZipEntry $reader.Entries[0] $seen
 if($record.relativePath -cne 'first.txt' -or $seen.Count -ne 1){throw 'FIXTURE_FIRST_ENTRY'}
 $rejected=$false
 try{$null=Assert-AgentRoadZipEntry $reader.Entries[1] $seen}catch{if($_.Exception.Message -cne 'RUNTIME_ARTIFACT_INVALID'){throw};$rejected=$true}
 if(-not $rejected){throw 'FIXTURE_DUPLICATE_ACCEPTED'}
 [Console]::Out.Write('{"firstEntryAccepted":true,"caseCollisionRejected":true}')
} finally {$reader.Dispose();$memory.Dispose()}`;
}
