function Read-AgentRoadBootstrapDeviceId {return [string]$fixtureData.fixture.assessmentInput.failedState.deviceId}
function Read-RetentionInventory {return $fixtureData.fixture.assessmentInput.secondInventory}
function Write-FixtureFile([string]$Path,[byte[]]$Bytes) {
 [IO.File]::WriteAllBytes($Path,$Bytes)
 $security=New-Object Security.AccessControl.FileSecurity
 $security.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
 [IO.File]::SetAccessControl($Path,$security)
}
function Invoke-RetentionFixtureHook($Context,[string]$Target,[string]$When) {
 if($When -ceq 'before' -and $script:scenario -ceq 'changed-during-gap'){[IO.File]::WriteAllText($Context.paths.archive,'changed')}
 if($When -ceq 'before' -and $script:scenario -ceq 'destination-race'){[AgentRoadRetention.Native]::CreateRestrictedDirectory($Target)}
 if($When -ceq 'before' -and $script:scenario -ceq 'acl-during-gap'){
  $acl=[IO.File]::GetAccessControl($Context.paths.archive);$sid=New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Allow)))
  [IO.File]::SetAccessControl($Context.paths.archive,$acl)
 }
 if($When -ceq 'before' -and $script:scenario -ceq 'parent-replacement'){
  $denied=$false;try{[IO.Directory]::Move($Context.paths.operation,$Context.paths.operation+'-replaced')}catch{$denied=$true}
  if(-not $denied){throw 'FIXTURE_PARENT_NOT_PINNED'}
 }
 if($When -ceq 'after' -and $script:scenario -ceq 'lost-ack'){throw 'TEST_LOST_ACK'}
}
$root=Join-Path $env:TEMP ('agent-road-retention-executor-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($root)
$results=[ordered]@{};$stage='SETUP'
try {
 foreach($script:scenario in @('success','existing-destination','parent-identity','wrong-acl','changed-content','extra-entry','changed-during-gap','acl-during-gap','parent-replacement','destination-race','lost-ack')) {
  $stage=$script:scenario
  $case=Join-Path $root $script:scenario;[AgentRoadRetention.Native]::CreateRestrictedDirectory($case)
  $agent=Join-Path $case 'AgentRoad';[AgentRoadRetention.Native]::CreateRestrictedDirectory($agent)
  $runtime=Join-Path $agent 'runtime';[AgentRoadRetention.Native]::CreateRestrictedDirectory($runtime)
  $staging=Join-Path $runtime 'staging';[AgentRoadRetention.Native]::CreateRestrictedDirectory($staging)
  $state=$fixtureData.fixture.assessmentInput.failedState
  $operation=Join-Path $staging $state.operationId;[AgentRoadRetention.Native]::CreateRestrictedDirectory($operation)
  $transaction=Join-Path $operation $state.manifestDigest;[AgentRoadRetention.Native]::CreateRestrictedDirectory($transaction)
  $files=Join-Path $transaction 'files';[AgentRoadRetention.Native]::CreateRestrictedDirectory($files)
  $manifest=($fixtureData.fixture.assessmentInput.capsuleJson|ConvertFrom-Json).manifestJson|ConvertFrom-Json
  $archive=Join-Path $files ('powershell-7-'+$manifest.components[0].version+'.zip')
  Write-FixtureFile (Join-Path $transaction 'capsule.json') ($script:Utf8.GetBytes($fixtureData.fixture.assessmentInput.capsuleJson))
  Write-FixtureFile $archive ([Convert]::FromBase64String($fixtureData.archiveBase64))
  $payload=[pscustomobject]@{mode='observe';state=$state;controllerPublicKeyJson=$fixtureData.keyJson;proposal=$null;attempt=$null}
  $observed=Invoke-StagedRetention $payload $agent
  $evidence=($fixtureData.fixture|ConvertTo-Json -Compress -Depth 16)|ConvertFrom-Json
  $evidence.sourceIdentity=$observed.sourceIdentity;$evidence.sourceAclSha256=$observed.sourceAclSha256;$evidence.destination=$observed.destination
  $payload.proposal=[pscustomobject]@{evidence=$evidence;expiresAt=[DateTime]::UtcNow.AddMinutes(5).ToString('o')}
  $payload.mode='apply'
  if($script:scenario -ceq 'existing-destination') {
   $r=Join-Path $agent 'retained-runtime';[AgentRoadRetention.Native]::CreateRestrictedDirectory($r)
  }
  if($script:scenario -ceq 'parent-identity'){$evidence.sourceIdentity.operation='0'*16+':'+'0'*32}
  if($script:scenario -ceq 'wrong-acl') {
   $acl=[IO.File]::GetAccessControl($archive)
   $sid=New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
   $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Allow)))
   [IO.File]::SetAccessControl($archive,$acl)
  }
  if($script:scenario -ceq 'changed-content'){[IO.File]::WriteAllText($archive,'changed')}
  if($script:scenario -ceq 'extra-entry'){Write-FixtureFile (Join-Path $transaction 'extra') ([byte[]]@(1))}
  $result=$null;$errorCode=$null
  try{$result=Invoke-StagedRetention $payload $agent}catch{$errorCode=[string]$_.Exception.Message}
  if($script:scenario -cin @('success','parent-replacement')) {
   if($null -eq $result -or -not $result.sourceOperationEmpty -or $result.retained.transaction -cne $evidence.sourceIdentity.transaction){throw 'FIXTURE_SUCCESS_MISSING'}
   $payload.mode='reconcile';$post=Invoke-StagedRetention $payload $agent
   if(($post|ConvertTo-Json -Compress -Depth 12) -cne ($result|ConvertTo-Json -Compress -Depth 12)){throw 'FIXTURE_POSTCHECK_CHANGED'}
  } elseif($script:scenario -ceq 'lost-ack') {
   if($errorCode -cne 'RUNTIME_COMPLETION_UNCERTAIN'){throw 'FIXTURE_UNCERTAINTY_MISSING'}
   $payload.mode='reconcile';$post=Invoke-StagedRetention $payload $agent
   if(-not $post.sourceOperationEmpty -or $post.retained.archiveSha256 -cne $evidence.assessmentInput.staged.archiveSha256){throw 'FIXTURE_RECONCILE_FAILED'}
  } elseif($script:scenario -cin @('changed-during-gap','acl-during-gap','destination-race')) {
   if($errorCode -cne 'RUNTIME_COMPLETION_UNCERTAIN'){throw 'FIXTURE_UNCERTAINTY_MISSING'}
   $payload.mode='reconcile';$rejected=$false;try{$null=Invoke-StagedRetention $payload $agent}catch{$rejected=$true}
   if(-not $rejected){throw 'FIXTURE_BAD_RECONCILE_ACCEPTED'}
  } else {
   if($errorCode -cne 'RUNTIME_STATE_UNSUPPORTED' -or -not [IO.Directory]::Exists($transaction)){throw 'FIXTURE_PRECONDITION_NOT_REJECTED'}
  }
  $results[$script:scenario]=$true
 }
 [Console]::Out.Write((@{isolated=$true;allPassed=$true;cases=$results}|ConvertTo-Json -Compress))
}catch{
 $errorCode=[string]$_.Exception.Message
 if($errorCode -cnotmatch '^(RUNTIME_[A-Z_]+|FIXTURE_[A-Z_]+)$'){$errorCode='FIXTURE_FAILED'}
 [Console]::Out.Write((@{isolated=$true;allPassed=$false;stage=$stage;code=$errorCode;line=$_.InvocationInfo.ScriptLineNumber;cases=$results}|ConvertTo-Json -Compress))
}finally{[IO.Directory]::Delete($root,$true)}
