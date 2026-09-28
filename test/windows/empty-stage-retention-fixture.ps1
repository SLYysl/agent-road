# Run composed with the production empty-stage bundle, inside a unique fixture root.
$fixture=Join-Path 'C:\ProgramData' ('AgentRoad-EmptyStage-Test-'+[guid]::NewGuid().ToString('N'))
$operation='a'*32;$manifest='B'*64;$results=[ordered]@{}
function Enter-AgentRoadMutationLock {return $null}
function Exit-AgentRoadMutationLock($Lock) {}
try {
 foreach($scenario in @('empty','file','unexpected-child','changed-proof','destination-conflict')) {
  $root=Join-Path $fixture $scenario
  foreach($path in @($fixture,$root,(Join-Path $root 'runtime'),(Join-Path $root 'runtime\staging'),(Join-Path $root ('runtime\staging\'+$operation)),(Join-Path $root ('runtime\staging\'+$operation+'\'+$manifest)),(Join-Path $root ('runtime\staging\'+$operation+'\'+$manifest+'\files')))) {
   if(-not (Test-Path -LiteralPath $path)){[AgentRoadRetention.Native]::CreateRestrictedDirectory($path)}
  }
  $transaction=Join-Path $root ('runtime\staging\'+$operation+'\'+$manifest)
  $p=[pscustomobject]@{mode='observe';state=[pscustomobject]@{operationId=$operation;manifestDigest=$manifest};controllerPublicKeyJson='';proof=$null;expiresAt=[DateTime]::UtcNow.AddMinutes(5).ToString('o')}
  if($scenario -ceq 'file'){[IO.File]::WriteAllText((Join-Path $transaction 'files\sentinel'),'keep')}
  if($scenario -ceq 'unexpected-child'){[IO.Directory]::CreateDirectory((Join-Path $transaction 'other'))|Out-Null}
  if($scenario -cin @('file','unexpected-child')) {
   $rejected=$false;try{$null=Invoke-EmptyStageRetention $p $root}catch{$rejected=$true}
   $results[$scenario]=$rejected -and (Test-Path -LiteralPath $transaction)
   continue
  }
  $p.proof=Invoke-EmptyStageRetention $p $root;$p.mode='apply'
  if($scenario -ceq 'changed-proof'){$p.proof.tree.identities.files='0'*49}
  if($scenario -ceq 'destination-conflict'){[AgentRoadRetention.Native]::CreateRestrictedDirectory((Join-Path $root 'retained-runtime'))}
  if($scenario -ceq 'empty') {
   $first=Invoke-EmptyStageRetention $p $root;$p.mode='reconcile';$second=Invoke-EmptyStageRetention $p $root
   $results[$scenario]=($first.status -ceq 'RETAINED' -and $second.status -ceq 'RETAINED' -and -not (Test-Path -LiteralPath $transaction) -and (Test-Path -LiteralPath (Join-Path $root ('retained-runtime\'+$operation+'\'+$manifest+'\files'))))
  } else {
   $rejected=$false;try{$null=Invoke-EmptyStageRetention $p $root}catch{$rejected=$true}
   $results[$scenario]=$rejected -and (Test-Path -LiteralPath $transaction)
  }
 }
 [Console]::Out.Write((@{cases=$results;allPassed=(@($results.Values|Where-Object{$_ -ne $true}).Count -eq 0)}|ConvertTo-Json -Compress))
} finally {if(Test-Path -LiteralPath $fixture){[IO.Directory]::Delete($fixture,$true)}}
