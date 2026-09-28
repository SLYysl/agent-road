# Observation only. No installs, PATH changes, registry writes or runtime activation.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$items = New-Object Collections.Generic.List[object]
$seen = @{}
function Add-Candidate($Tool, $Path, $Source) {
  if (!$Path -or $seen.ContainsKey($Path) -or !(Test-Path -LiteralPath $Path -PathType Leaf)) { return }
  if ($Path -like 'C:\ProgramData\AgentRoad\*') { return }
  if ($items.Count -ge 32) { throw 'EXISTING_BASE_LIMIT' }
  $seen[$Path] = $true
  $items.Add(@{ tool=$Tool; path=$Path; source=$Source })
}
function Assert-RegularPath($Path) {
  $part = Get-Item -LiteralPath $Path -Force
  while ($null -ne $part) {
    if (($part.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'EXISTING_BASE_REPARSE' }
    if ($part -is [IO.FileInfo]) { $part=$part.Directory } else { $part=$part.Parent }
  }
}
function Invoke-Probe($Path, $Arguments) {
  $info = New-Object Diagnostics.ProcessStartInfo
  $info.FileName=$Path; $info.Arguments=$Arguments
  $info.UseShellExecute=$false; $info.CreateNoWindow=$true
  $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
  # Node version probes must not load inherited startup code.
  foreach ($key in @('NODE_OPTIONS','NODE_PATH','PYTHONHOME','PYTHONPATH')) { $info.EnvironmentVariables.Remove($key) }
  $process = [Diagnostics.Process]::Start($info)
  try {
    $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
    if (!$process.WaitForExit(5000)) {
      $process.Kill(); [void]$process.WaitForExit(1000)
      throw 'EXISTING_BASE_TIMEOUT'
    }
    if (!$stdout.Wait(1000) -or !$stderr.Wait(1000)) { throw 'EXISTING_BASE_OUTPUT' }
    if ($process.ExitCode -ne 0 -or $stderr.Result.Length -ne 0 -or $stdout.Result.Length -gt 4096) { throw 'EXISTING_BASE_PROBE' }
    return $stdout.Result.Trim()
  } finally { $process.Dispose() }
}
try {
  foreach ($tool in @('git','node','python','rg')) {
    foreach ($command in @(Get-Command ($tool+'.exe') -CommandType Application -All -ErrorAction SilentlyContinue)) {
      Add-Candidate $tool $command.Source 'path'
    }
  }
  $roots=@(@{path=$env:ProgramFiles; source='machine'}, @{path=${env:ProgramFiles(x86)}; source='machine'}, @{path='C:\ProgramData\chocolatey'; source='machine'})
  $users=@(Get-ChildItem 'C:\Users' -Directory -ErrorAction Stop)
  if ($users.Count -gt 32) { throw 'EXISTING_BASE_LIMIT' }
  foreach ($user in $users) {
    foreach ($tail in @('AppData\Local','scoop','.cargo','.local','AppData\Roaming\npm')) {
      $roots+=@{path=(Join-Path $user.FullName $tail); source='user-profile'}
    }
  }
  $patterns=@{
    git=@('Git\cmd\git.exe','Programs\Git\cmd\git.exe','apps\git\current\cmd\git.exe')
    node=@('nodejs\node.exe','Programs\nodejs\node.exe','apps\nodejs*\current\node.exe')
    python=@('Python*\python.exe','Programs\Python\Python*\python.exe','Python\pythoncore-*\python.exe','apps\python\current\python.exe')
    rg=@('bin\rg.exe','apps\ripgrep\current\rg.exe','node_modules\@openai\codex\vendor\x86_64-pc-windows-msvc\path\rg.exe','Programs\Microsoft VS Code\resources\app\node_modules.asar.unpacked\@vscode\ripgrep\bin\rg.exe','Microsoft VS Code\resources\app\node_modules\@vscode\ripgrep\bin\rg.exe','Programs\Microsoft VS Code\resources\app\node_modules\@vscode\ripgrep\bin\rg.exe')
  }
  foreach ($root in $roots) {
    if (!$root.path) { continue }
    foreach ($tool in @('git','node','python','rg')) {
      foreach ($pattern in $patterns[$tool]) {
        foreach ($file in @(Get-ChildItem (Join-Path $root.path $pattern) -File -ErrorAction SilentlyContinue)) {
          Add-Candidate $tool $file.FullName $root.source
        }
      }
    }
  }
  $results=New-Object Collections.Generic.List[object]
  foreach ($item in $items) {
    $row=@{tool=$item.tool; path=$item.path; source=$item.source; status='unavailable'; version=$null; sha256=$null; environmentModules=$false; reason='PROBE_FAILED'}
    if ($item.path -like '*\WindowsApps\*') { $row.status='store-alias'; $row.reason='STORE_ALIAS' }
    else {
      try {
        Assert-RegularPath $item.path
        $before=(Get-FileHash -LiteralPath $item.path -Algorithm SHA256).Hash
        $modules=$false
        switch ($item.tool) {
          'git' {
            $output=Invoke-Probe $item.path '--version'
            if ($output -notmatch '^git version (\d+\.\d+\.\d+(?:\.windows\.\d+)?)$') { throw 'EXISTING_BASE_VERSION' }
            $version=$Matches[1]
          }
          'rg' {
            $output=Invoke-Probe $item.path '--version'
            if ($output -notmatch '^ripgrep (\d+\.\d+\.\d+)(?:\s|$)') { throw 'EXISTING_BASE_VERSION' }
            $version=$Matches[1]
          }
          'node' {
            $output=(Invoke-Probe $item.path '-p "JSON.stringify({version:process.versions.node,platform:process.platform,arch:process.arch,value:6*7})"')|ConvertFrom-Json
            if ($output.platform -ne 'win32' -or $output.arch -ne 'x64' -or $output.value -ne 42) { throw 'EXISTING_BASE_PLATFORM' }
            $version=$output.version
          }
          'python' {
            $output=(Invoke-Probe $item.path '-I -B -c "import sys,json,struct,importlib.util; print(json.dumps(dict(version=sys.version.split()[0],platform=sys.platform,bits=struct.calcsize(''P'')*8,modules=all(importlib.util.find_spec(m) is not None for m in [''venv'',''ensurepip'',''pip'']))))"')|ConvertFrom-Json
            if ($output.platform -ne 'win32' -or $output.bits -ne 64) { throw 'EXISTING_BASE_PLATFORM' }
            $version=$output.version; $modules=($output.modules -eq $true)
          }
        }
        Assert-RegularPath $item.path
        $after=(Get-FileHash -LiteralPath $item.path -Algorithm SHA256).Hash
        if ($before -cne $after) { throw 'EXISTING_BASE_CHANGED' }
        if ($version -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}(?:\.windows\.\d{1,3})?$') { throw 'EXISTING_BASE_VERSION' }
        $row.status='verified'; $row.reason=$null; $row.version=$version; $row.sha256=$after; $row.environmentModules=$modules
      } catch {
        $code=$_.Exception.Message
        if ($code -in @('EXISTING_BASE_REPARSE','EXISTING_BASE_TIMEOUT','EXISTING_BASE_OUTPUT','EXISTING_BASE_PROBE','EXISTING_BASE_VERSION','EXISTING_BASE_PLATFORM','EXISTING_BASE_CHANGED')) {
          $row.reason=$code.Substring(14)
        }
      }
    }
    $results.Add($row)
  }
  @{schemaVersion=1; candidates=@($results.ToArray())}|ConvertTo-Json -Compress -Depth 5
} catch {
  [Console]::Error.WriteLine('EXISTING_BASE_DISCOVERY_FAILED')
  exit 1
}
