# Narrow pre-transaction maintenance: retain an empty scaffold, never delete it.
# Composed with inventory validators, retention native handles and mutation lock.
function Read-EmptyStageTree($Context,[bool]$Retained,[bool]$Rename=$false) {
 $p=$Context.paths;$h=$Context.handles
 $parent=if($Retained){$p.retainedOperation}else{$p.operation}
 Assert-RetentionChildren $parent @([string]$Context.payload.state.manifestDigest)
 $p.transaction=Join-Path $parent $Context.payload.state.manifestDigest
 if(-not $h.Contains('transaction') -or $null -eq $h.transaction){Open-RetentionDirectory $Context 'transaction' $Rename}
 Assert-AgentRoadDirectoryNode $p.transaction
 Assert-RetentionChildren $p.transaction @('files')
 $p.files=Join-Path $p.transaction 'files';Open-RetentionDirectory $Context 'files'
 Assert-RetentionChildren $p.files @()
 $ids=[ordered]@{};$acls=[ordered]@{}
 foreach($name in @('programData','agentRoad','runtime','staging','operation','transaction','files')) {
  $ids[$name]=[AgentRoadRetention.Native]::Identity($h[$name])
  $acls[$name]=Get-RetentionAclHash $p[$name] $true
 }
 return [pscustomobject][ordered]@{identities=[pscustomobject]$ids;acls=[pscustomobject]$acls}
}
function Assert-EmptyStageProof($Tree,$Proof) {
 foreach($name in @('programData','agentRoad','runtime','staging','operation','transaction','files')) {
  if($Tree.identities.$name -cne $Proof.tree.identities.$name -or $Tree.acls.$name -cne $Proof.tree.acls.$name){throw 'RUNTIME_INVENTORY_CHANGED'}
 }
}
function Invoke-EmptyStageRetention($Payload,[string]$AgentRoot) {
 $context=$null;$lock=$null;$mutated=$false
 try {
  $lock=Enter-AgentRoadMutationLock
  $context=New-RetentionContext $Payload $AgentRoot
  $dest=Get-RetentionDestination $context
  if($Payload.mode -ceq 'reconcile') {
   Assert-RetentionChildren $context.paths.operation @()
   $tree=Read-EmptyStageTree $context $true
   Assert-EmptyStageProof $tree $Payload.proof
   return [pscustomobject]@{status='RETAINED';runtimeRecovered=$false;nextStep='EMPTY_OPERATION_RECOVERY'}
  }
  # No existing destination namespace is admitted, including another attempt.
  if($null -ne $dest.rootIdentity){throw 'RUNTIME_STATE_UNSUPPORTED'}
  $tree=Read-EmptyStageTree $context $false ($Payload.mode -ceq 'apply')
  $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
  if($Payload.mode -ceq 'observe'){return [pscustomobject]@{tree=$tree;bootUtc=$boot;destinationAbsent=$true}}
  if($Payload.mode -cne 'apply'){throw 'RUNTIME_INPUT_INVALID'}
  if($boot -cne $Payload.proof.bootUtc -or [DateTime]::UtcNow -ge [DateTime]::Parse($Payload.expiresAt).ToUniversalTime()){throw 'RUNTIME_INVENTORY_CHANGED'}
  Assert-EmptyStageProof $tree $Payload.proof
  $mutated=$true
  foreach($name in @('retainedRoot','retainedOperation')) {
   [AgentRoadRetention.Native]::CreateRestrictedDirectory($context.paths[$name])
   Open-RetentionDirectory $context $name
  }
  Assert-RetentionChildren $context.paths.retainedOperation @()
  $target=Join-Path $context.paths.retainedOperation $Payload.state.manifestDigest
  $context.handles.files.Dispose();$context.handles.files=$null
  [AgentRoadRetention.Native]::Rename($context.handles.transaction,$target)
  Assert-RetentionChildren $context.paths.operation @()
  $tree=Read-EmptyStageTree $context $true
  Assert-EmptyStageProof $tree $Payload.proof
  return [pscustomobject]@{status='RETAINED';runtimeRecovered=$false;nextStep='EMPTY_OPERATION_RECOVERY'}
 }catch{if($mutated){throw 'RUNTIME_COMPLETION_UNCERTAIN'};throw}
 finally{if($null -ne $context){Close-RetentionHandles $context.handles};Exit-AgentRoadMutationLock $lock}
}
