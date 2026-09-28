$git = & $AgentRoadTools.git --version
if ($LASTEXITCODE -ne 0 -or $git -notmatch '^git version ') { throw 'TASK_GIT_FAILED' }
$node = & $AgentRoadTools.node -p '6*7'
if ($LASTEXITCODE -ne 0 -or $node -ne '42') { throw 'TASK_NODE_FAILED' }
$python = & $AgentRoadTools.python -I -B -c 'print(sum([20,22]))'
if ($LASTEXITCODE -ne 0 -or  $python -ne 42) { throw 'TASK_PYTHON_FAILED' }
@{git=$true; node=$true; python=$true; value=42}|ConvertTo-Json -Compress
