# Definitions are composed with the strict inventory validators and mutation lock.
# Production paths are fixed by the builder. Fixture callers supply an isolated root.
function Close-RetentionHandles($Handles) {
 foreach($name in @('archive','capsule','files','transaction','retainedOperation','retainedRoot','operation','staging','runtime','agentRoad','programData')) {
  if($Handles.Contains($name) -and $null -ne $Handles[$name]) {$Handles[$name].Dispose();$Handles[$name]=$null}
 }
}
function Get-RetentionAclHash([string]$Path,[bool]$Directory) {
 $acl=if($Directory){[IO.Directory]::GetAccessControl($Path)}else{[IO.File]::GetAccessControl($Path)}
 return Get-AgentRoadBytesSha256 ($script:Utf8.GetBytes($acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)))
}
function Assert-RetentionChildren([string]$Path,[string[]]$Names) {
 $entries=@(Get-AgentRoadDirectChildren $Path ($Names.Count+1))
 if($entries.Count -ne $Names.Count){throw 'RUNTIME_STATE_UNSUPPORTED'}
 foreach($entry in $entries){if($Names -cnotcontains $entry.Name){throw 'RUNTIME_STATE_UNSUPPORTED'}}
}
function Open-RetentionDirectory($Context,[string]$Name,[bool]$DeleteAccess=$false) {
 $path=$Context.paths[$Name]
 $Context.handles[$Name]=[AgentRoadRetention.Native]::Open($path,$true,$DeleteAccess)
 if($Name -cne 'programData'){Assert-AgentRoadDirectoryNode $path}
}
function New-RetentionContext($Payload,[string]$AgentRoot) {
 if($Payload.state.operationId -cnotmatch '^[a-f0-9]{32}$' -or $Payload.state.manifestDigest -cnotmatch '^[A-F0-9]{64}$'){throw 'RUNTIME_INPUT_INVALID'}
 $paths=[ordered]@{programData=[IO.Path]::GetDirectoryName($AgentRoot);agentRoad=$AgentRoot}
 $paths.runtime=Join-Path $AgentRoot 'runtime';$paths.staging=Join-Path $paths.runtime 'staging'
 $paths.operation=Join-Path $paths.staging $Payload.state.operationId
 $paths.retainedRoot=Join-Path $AgentRoot 'retained-runtime'
 $paths.retainedOperation=Join-Path $paths.retainedRoot $Payload.state.operationId
 $context=[pscustomobject]@{paths=$paths;handles=[ordered]@{};payload=$Payload;keyJson=[string]$Payload.controllerPublicKeyJson}
 try {
  foreach($name in @('programData','agentRoad','runtime','staging','operation')){Open-RetentionDirectory $context $name}
  Assert-RetentionChildren $paths.runtime @('staging')
  Assert-RetentionChildren $paths.staging @([string]$Payload.state.operationId)
  foreach($name in @('retainedRoot','retainedOperation')) {
   if(Test-Path -LiteralPath $paths[$name]){Open-RetentionDirectory $context $name}
  }
  return $context
 }catch{Close-RetentionHandles $context.handles;throw}
}
function Get-RetentionDestination($Context) {
 $root=$null;$operation=$null
 if($Context.handles.Contains('retainedRoot')){$root=[AgentRoadRetention.Native]::Identity($Context.handles.retainedRoot)}
 if($Context.handles.Contains('retainedOperation')){$operation=[AgentRoadRetention.Native]::Identity($Context.handles.retainedOperation)}
 return [pscustomobject][ordered]@{rootIdentity=$root;operationIdentity=$operation}
}
function Read-RetentionTree($Context,[bool]$Retained,[bool]$DeleteAccess=$false) {
 $p=$Context.paths;$h=$Context.handles;$payload=$Context.payload
 $parent=if($Retained){$p.retainedOperation}else{$p.operation}
 Assert-RetentionChildren $parent @([string]$payload.state.manifestDigest)
 $p.transaction=Join-Path $parent $payload.state.manifestDigest
 if(-not $h.Contains('transaction') -or $null -eq $h.transaction){Open-RetentionDirectory $Context 'transaction' $DeleteAccess}
 Assert-AgentRoadDirectoryNode $p.transaction
 Assert-RetentionChildren $p.transaction @('capsule.json','files')
 $p.files=Join-Path $p.transaction 'files';Open-RetentionDirectory $Context 'files'
 $p.capsule=Join-Path $p.transaction 'capsule.json'
 $h.capsule=[AgentRoadRetention.Native]::Open($p.capsule,$false,$false)
 $capsule=Read-AgentRoadCapsule $p.capsule $payload.state.manifestDigest $payload.state.operationId $Context.keyJson
 if($capsule.manifest.deviceId -cne $payload.state.deviceId -or $capsule.capsule.generationDigest -cne $payload.state.generationDigest){throw 'RUNTIME_STATE_UNSUPPORTED'}
 $component=$capsule.manifest.components[0]
 $archiveName='powershell-7-'+[string]$component.version+'.zip'
 Assert-RetentionChildren $p.files @($archiveName)
 $p.archive=Join-Path $p.files $archiveName
 $h.archive=[AgentRoadRetention.Native]::Open($p.archive,$false,$false)
 Assert-AgentRoadFileNode $p.archive ([long]$component.bytes) ([string]$component.sha256)
 $ids=[ordered]@{};$acl=[ordered]@{}
 foreach($name in @('programData','agentRoad','runtime','staging','operation','transaction','files','capsule','archive')) {
  $ids[$name]=[AgentRoadRetention.Native]::Identity($h[$name])
  $acl[$name]=Get-RetentionAclHash $p[$name] ($name -cnotin @('capsule','archive'))
 }
 return [pscustomobject]@{capsule=$capsule;sourceIdentity=[pscustomobject]$ids;sourceAclSha256=[pscustomobject]$acl}
}
function Assert-RetentionBinding($Tree,$Evidence) {
 foreach($name in @('programData','agentRoad','runtime','staging','operation','transaction','files','capsule','archive')) {
  if($Tree.sourceIdentity.$name -cne $Evidence.sourceIdentity.$name -or $Tree.sourceAclSha256.$name -cne $Evidence.sourceAclSha256.$name){throw 'RUNTIME_STATE_UNSUPPORTED'}
 }
 $staged=$Evidence.assessmentInput.staged
 if((Get-AgentRoadBytesSha256 $Tree.capsule.bytes) -cne $staged.capsuleSha256 -or
    $Tree.capsule.manifest.components[0].sha256 -cne $staged.archiveSha256 -or
    $Tree.capsule.manifest.components[0].bytes -ne $staged.archiveBytes){throw 'RUNTIME_STATE_UNSUPPORTED'}
}
function Get-RetentionObservation($Context,$Tree) {
 $capsule=$Tree.capsule;$component=$capsule.manifest.components[0]
 $dest=Get-RetentionDestination $Context
 if($null -ne $dest.operationIdentity){Assert-RetentionChildren $Context.paths.retainedOperation @()}
 return [pscustomobject][ordered]@{
  schemaVersion=1;capsuleBase64=[Convert]::ToBase64String($capsule.bytes)
  staged=[pscustomobject][ordered]@{operationId=$Context.payload.state.operationId;manifestDigest=$capsule.capsule.manifestDigest;generationDigest=$capsule.capsule.generationDigest;capsuleSha256=(Get-AgentRoadBytesSha256 $capsule.bytes);archiveBytes=[long]$component.bytes;archiveSha256=[string]$component.sha256;hasWork=$false;hasTemporary=$false;onlyExpectedTransaction=$true}
  sourceIdentity=$Tree.sourceIdentity;sourceAclSha256=$Tree.sourceAclSha256
  destination=[pscustomobject][ordered]@{rootIdentity=$dest.rootIdentity;operationIdentity=$dest.operationIdentity;transactionAbsent=$true}
 }
}
function Assert-RetentionEnvironment($Expected) {
 $actual=Read-RetentionInventory
 foreach($name in @('os','version','build','edition','architecture','windowsPowerShellVersion','elevated')) {
  if($actual.platform.$name -cne $Expected.assessmentInput.secondInventory.platform.$name){throw 'RUNTIME_INVENTORY_CHANGED'}
 }
 if($actual.pendingReboot){throw 'RUNTIME_REBOOT_REQUIRED'}
 $manifest=$Expected.assessmentInput.capsuleJson|ConvertFrom-Json
 $manifest=$manifest.manifestJson|ConvertFrom-Json
 if($actual.interactiveSession -or -not $actual.platform.elevated -or
    $actual.freeBytes -lt ([long]$manifest.components[0].maximumExpandedBytes+268435456) -or
    $actual.runtime.generationVerified -or $actual.runtime.pendingOperationId -cne $Expected.assessmentInput.failedState.operationId -or
    @($actual.managedArtifacts).Count -ne 0){throw 'RUNTIME_INVENTORY_CHANGED'}
}
function Get-RetentionPostcheck($Context,$Tree,$Evidence) {
 Assert-RetentionBinding $Tree $Evidence
 $p=$Context.paths
 Assert-RetentionChildren $p.runtime @('staging');Assert-RetentionChildren $p.staging @([string]$Context.payload.state.operationId)
 Assert-RetentionChildren $p.operation @();Assert-RetentionChildren $p.retainedOperation @([string]$Context.payload.state.manifestDigest)
 $parents=[ordered]@{};$acl=[ordered]@{}
 foreach($name in @('programData','agentRoad','runtime','staging','operation')){$parents[$name]=$Tree.sourceIdentity.$name;$acl[$name]=$Tree.sourceAclSha256.$name}
 $dest=Get-RetentionDestination $Context
 foreach($name in @('rootIdentity','operationIdentity')) {
  if($null -ne $Evidence.destination.$name -and $dest.$name -cne $Evidence.destination.$name){throw 'RUNTIME_STATE_UNSUPPORTED'}
 }
 $ids=$Tree.sourceIdentity;$acls=$Tree.sourceAclSha256;$staged=$Evidence.assessmentInput.staged
 return [pscustomobject][ordered]@{
  source=$null;retained=[pscustomobject][ordered]@{transaction=$ids.transaction;files=$ids.files;capsule=$ids.capsule;archive=$ids.archive;capsuleSha256=$staged.capsuleSha256;archiveSha256=$staged.archiveSha256;archiveBytes=$staged.archiveBytes;transactionAclSha256=$acls.transaction;filesAclSha256=$acls.files;capsuleAclSha256=$acls.capsule;archiveAclSha256=$acls.archive}
  parents=[pscustomobject]$parents;parentAclSha256=[pscustomobject]$acl;destination=$dest
  targetBindingDigest=$Evidence.targetBindingDigest;executorDigest=$Evidence.executorDigest
  sourceOperationEmpty=$true;retainedOnlyExpectedTransaction=$true;runtimeOnlyStaging=$true;stagingOnlyExpectedOperation=$true
 }
}
function Invoke-StagedRetention($Payload,[string]$AgentRoot) {
 $context=$null;$lock=$null;$mutationStarted=$false
 try {
  $lock=Enter-AgentRoadMutationLock
  $context=New-RetentionContext $Payload $AgentRoot
  if($Payload.mode -ceq 'observe') {
   $tree=Read-RetentionTree $context $false
   return Get-RetentionObservation $context $tree
  }
  $evidence=$Payload.proposal.evidence
  if($Payload.mode -ceq 'reconcile') {
   Assert-RetentionChildren $context.paths.operation @()
   $tree=Read-RetentionTree $context $true
   return Get-RetentionPostcheck $context $tree $evidence
  }
  if($Payload.mode -cne 'apply'){throw 'RUNTIME_INPUT_INVALID'}
  if([DateTime]::UtcNow -ge [DateTime]::Parse($Payload.proposal.expiresAt).ToUniversalTime()){throw 'RUNTIME_INVENTORY_CHANGED'}
  Assert-RetentionEnvironment $evidence
  $tree=Read-RetentionTree $context $false $true
  Assert-RetentionBinding $tree $evidence
  $destination=Get-RetentionDestination $context
  foreach($name in @('rootIdentity','operationIdentity')){if($destination.$name -cne $evidence.destination.$name){throw 'RUNTIME_STATE_UNSUPPORTED'}}
  if($null -ne $destination.operationIdentity){Assert-RetentionChildren $context.paths.retainedOperation @()}
  # From the first directory creation onwards, every failure is uncertain. The
  # controller has already consumed its one durable attempt and must reconcile.
  $mutationStarted=$true
  foreach($name in @('retainedRoot','retainedOperation')) {
   if(-not $context.handles.Contains($name)) {
    [AgentRoadRetention.Native]::CreateRestrictedDirectory($context.paths[$name])
    Open-RetentionDirectory $context $name
   }
  }
  Assert-RetentionChildren $context.paths.retainedOperation @()
  $target=Join-Path $context.paths.retainedOperation $Payload.state.manifestDigest
  # Windows forbids renaming a directory while descendant handles remain open.
  # Retain all ancestor and source-transaction handles and the mutation mutex.
  foreach($name in @('archive','capsule','files')){$context.handles[$name].Dispose();$context.handles[$name]=$null}
  [AgentRoadRetention.Native]::Rename($context.handles.transaction,$target)
  $tree=Read-RetentionTree $context $true
  return Get-RetentionPostcheck $context $tree $evidence
 }catch{
  if($mutationStarted){throw 'RUNTIME_COMPLETION_UNCERTAIN'}
  $code=[string]$_.Exception.Message
  if($code -cnotin @('RUNTIME_INPUT_INVALID','RUNTIME_STATE_UNSUPPORTED','RUNTIME_REBOOT_REQUIRED','RUNTIME_INVENTORY_CHANGED','RUNTIME_ALREADY_RUNNING')){$code='RUNTIME_STATE_UNSUPPORTED'}
  throw $code
 }finally{
  if($null -ne $context){Close-RetentionHandles $context.handles}
  Exit-AgentRoadMutationLock $lock
 }
}
