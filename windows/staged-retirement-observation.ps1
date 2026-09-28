# Appended to the inventory definitions by staged-retirement-observation.mjs.
# Read-only: deliberately does not produce a recovery ticket or move any files.
try {
 $runtimeEntries = @(Get-AgentRoadDirectChildren $script:RuntimeRoot 2)
 if ($runtimeEntries.Count -ne 1 -or $runtimeEntries[0].Name -cne 'staging') { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $operationEntries = @(Get-AgentRoadDirectChildren $script:StagingRoot 2)
 if ($operationEntries.Count -ne 1 -or $operationEntries[0].Name -cne $retirementOperationId) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $operationRoot = [IO.Path]::Combine($script:StagingRoot, $retirementOperationId)
 $snapshot = Get-AgentRoadRuntimeStateSnapshot $script:RuntimeRoot
 $staged = Read-AgentRoadStagedOperation $operationRoot $retirementControllerKeyJson
 if ($null -eq $staged.capsuleRecord -or $staged.hasWork -or $staged.hasTemporary -or
     $snapshot.runtime.generationVerified -or @($snapshot.managedArtifacts).Count -ne 0 -or
     $snapshot.runtime.pendingOperationId -cne $retirementOperationId) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $transactions = @(Get-AgentRoadDirectChildren $operationRoot 2)
 if ($transactions.Count -ne 1 -or $transactions[0].Name -cne $staged.manifestDigest) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $transactionRoot = [IO.Path]::Combine($operationRoot, $staged.manifestDigest)
 $entries = @(Get-AgentRoadDirectChildren $transactionRoot 3)
 if ($entries.Count -ne 2 -or $entries.Name -cnotcontains 'capsule.json' -or $entries.Name -cnotcontains 'files') { throw 'RUNTIME_STATE_UNSUPPORTED' }
 $component = $staged.capsuleRecord.manifest.components[0]
 $filesRoot = [IO.Path]::Combine($transactionRoot, 'files')
 $files = @(Get-AgentRoadDirectChildren $filesRoot 2)
 if ($files.Count -ne 1 -or $files[0].Name -cne ('powershell-7-' + [string]$component.version + '.zip')) { throw 'RUNTIME_STATE_UNSUPPORTED' }
 Assert-AgentRoadFileNode $files[0].FullName ([long]$component.bytes) ([string]$component.sha256)
 $record = [pscustomobject][ordered]@{
  schemaVersion = 1
  capsuleBase64 = [Convert]::ToBase64String($staged.capsuleRecord.bytes)
  staged = [pscustomobject][ordered]@{
   operationId = $retirementOperationId
   manifestDigest = [string]$staged.capsuleRecord.capsule.manifestDigest
   generationDigest = [string]$staged.capsuleRecord.capsule.generationDigest
   capsuleSha256 = Get-AgentRoadBytesSha256 $staged.capsuleRecord.bytes
   archiveBytes = [long]$files[0].Length
   archiveSha256 = Get-AgentRoadSha256 $files[0].FullName
   hasWork = $false
   hasTemporary = $false
   onlyExpectedTransaction = $true
  }
 }
 [Console]::Out.Write(($record | ConvertTo-Json -Compress -Depth 5))
} catch {
 [Console]::Out.Write('{"schemaVersion":1,"error":"RUNTIME_STATE_UNSUPPORTED"}')
 exit 73
}
