#requires -Version 5.1
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$script:Utf8 = New-Object Text.UTF8Encoding($false, $true)
$script:InputByteLimit = 256
$script:FieldNameByteLimit = 256
$script:FieldByteLimit = 8192
$script:NestedItemLimit = 256
$script:RecordFieldLimit = 64
$script:ValueDepthLimit = 8
$script:RecordByteLimit = 16384
$script:SurfaceByteLimit = 131072
$script:OutputByteLimit = 8192
$script:SurfaceDomainText = 'AgentRoad.RuntimeBaseline.Surface.v1\0'
$script:AgentRoadAccount = 'AgentRoad'
$script:TaskNamespace = '\AgentRoad\'
$script:SurfaceLimits = [ordered]@{
  'account-environment' = 128
  'account-profile-identity' = 4
  'command-resolution' = 32
  'external-sentinel-acls' = 16
  'firewall-profiles' = 3
  'firewall-rules' = 32
  'machine-environment' = 256
  'scheduled-tasks' = 64
  'service-definitions' = 16
}
$script:CommandNames = @(
  'git.exe'
  'node.exe'
  'powershell.exe'
  'pwsh.exe'
  'py.exe'
  'python.exe'
)
$script:FixedServiceNames = @('sshd', 'Tailscale')
$script:ServiceValueNames = @(
  'DelayedAutoStart'
  'DependOnGroup'
  'DependOnService'
  'ErrorControl'
  'FailureActions'
  'FailureActionsOnNonCrashFailures'
  'Group'
  'ImagePath'
  'ObjectName'
  'RequiredPrivileges'
  'ServiceSidType'
  'Start'
  'Tag'
  'Type'
)
$script:FirewallRuleNames = @('AgentRoad-OpenSSH-Tailscale', 'OpenSSH-Server-In-TCP')
$script:TailscaleFirewallDisplayIdentity = 'Tailscale-In'
$script:FirewallServiceIdentities = @('sshd', 'Tailscale')
$script:FirewallProgramNames = @('sshd.exe', 'tailscale.exe', 'tailscaled.exe', 'tailscale-ipn.exe')
$script:ExternalSentinelPaths = @(
  'C:\ProgramData\AgentRoad'
  'C:\ProgramData\AgentRoad\bootstrap'
  'C:\ProgramData\AgentRoad\ssh'
  'C:\ProgramData\AgentRoad\ssh\authorized_keys'
  'C:\ProgramData\AgentRoad\tasks'
  'C:\ProgramData\AgentRoad\transfers'
  'C:\ProgramData\ssh'
  'C:\ProgramData\ssh\sshd_config'
)

function Read-AgentRoadBoundedInput {
  $stream = [Console]::OpenStandardInput()
  $buffer = New-Object byte[] ($script:InputByteLimit + 1)
  $offset = 0
  while ($offset -lt $buffer.Length) {
    $read = $stream.Read($buffer, $offset, $buffer.Length - $offset)
    if ($read -eq 0) { break }
    $offset += $read
  }
  if ($offset -lt 1 -or $offset -gt $script:InputByteLimit) { throw 'RUNTIME_INVENTORY_FAILED' }
  $bytes = New-Object byte[] $offset
  [Array]::Copy($buffer, 0, $bytes, 0, $offset)
  [Array]::Clear($buffer, 0, $buffer.Length)
  return ,$bytes
}

function Read-AgentRoadProtocolInput {
  param([Parameter(Mandatory = $true)][byte[]]$Bytes)
  $raw = $script:Utf8.GetString($Bytes)
  if ($raw.IndexOf([char]0) -ge 0 -or $raw.IndexOf("`r") -ge 0 -or $raw.IndexOf("`n") -ge 0) {
    throw 'RUNTIME_INVENTORY_FAILED'
  }
  $value = ConvertFrom-Json -InputObject $raw
  $names = @($value.PSObject.Properties | ForEach-Object { [string]$_.Name })
  if (
    $names.Count -ne 3 -or
    $names[0] -cne 'schemaVersion' -or
    $names[1] -cne 'protocolRevision' -or
    $names[2] -cne 'hmacKeyBase64' -or
    [int]$value.schemaVersion -ne 1 -or
    [int]$value.protocolRevision -ne 1 -or
    $value.hmacKeyBase64 -isnot [string] -or
    [string]$value.hmacKeyBase64 -cnotmatch '^[A-Za-z0-9+/]{43}=$'
  ) { throw 'RUNTIME_INVENTORY_FAILED' }
  $key = [Convert]::FromBase64String([string]$value.hmacKeyBase64)
  if ($key.Length -ne 32 -or [Convert]::ToBase64String($key) -cne [string]$value.hmacKeyBase64) {
    [Array]::Clear($key, 0, $key.Length)
    throw 'RUNTIME_INVENTORY_FAILED'
  }
  $canonical = ConvertTo-Json -Compress -InputObject ([ordered]@{
    schemaVersion = 1
    protocolRevision = 1
    hmacKeyBase64 = [string]$value.hmacKeyBase64
  })
  if ($canonical -cne $raw) {
    [Array]::Clear($key, 0, $key.Length)
    throw 'RUNTIME_INVENTORY_FAILED'
  }
  $raw = $null
  $value = $null
  return ,$key
}

function Assert-AgentRoadBoundedValue {
  param(
    [AllowNull()][object]$Value,
    [int]$Depth = 0
  )
  if ($Depth -gt $script:ValueDepthLimit) { throw 'RUNTIME_INVENTORY_FAILED' }
  if ($null -eq $Value) { return }
  if ($Value -is [string]) {
    if ($script:Utf8.GetByteCount([string]$Value) -gt $script:FieldByteLimit) {
      throw 'RUNTIME_INVENTORY_FAILED'
    }
    return
  }
  if ($Value -is [Collections.IDictionary]) {
    if ($Value.Count -gt $script:RecordFieldLimit) { throw 'RUNTIME_INVENTORY_FAILED' }
    foreach ($entry in $Value.GetEnumerator()) {
      if (
        $entry.Key -isnot [string] -or
        $script:Utf8.GetByteCount([string]$entry.Key) -gt $script:FieldNameByteLimit
      ) {
        throw 'RUNTIME_INVENTORY_FAILED'
      }
      Assert-AgentRoadBoundedValue $entry.Value ($Depth + 1)
    }
    return
  }
  if ($Value -is [Collections.IEnumerable]) {
    $items = @($Value)
    if ($items.Count -gt $script:NestedItemLimit) { throw 'RUNTIME_INVENTORY_FAILED' }
    foreach ($item in $items) { Assert-AgentRoadBoundedValue $item ($Depth + 1) }
    return
  }
  if (
    $Value -is [bool] -or
    $Value -is [byte] -or
    $Value -is [sbyte] -or
    $Value -is [int16] -or
    $Value -is [uint16] -or
    $Value -is [int32] -or
    $Value -is [uint32] -or
    $Value -is [int64] -or
    $Value -is [uint64]
  ) { return }
  throw 'RUNTIME_INVENTORY_FAILED'
}

function Convert-AgentRoadRecordToJson {
  param([Parameter(Mandatory = $true)][Collections.IDictionary]$Record)
  Assert-AgentRoadBoundedValue $Record
  $json = ConvertTo-Json -Compress -Depth 12 -InputObject $Record
  $bytes = $script:Utf8.GetBytes($json)
  if ($bytes.Length -lt 2 -or $bytes.Length -gt $script:RecordByteLimit) {
    [Array]::Clear($bytes, 0, $bytes.Length)
    throw 'RUNTIME_INVENTORY_FAILED'
  }
  [Array]::Clear($bytes, 0, $bytes.Length)
  return $json
}

function Convert-AgentRoadRecords {
  param(
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Records,
    [Parameter(Mandatory = $true)][int]$Limit,
    [Parameter(Mandatory = $true)][string]$Id
  )
  $jsonRecords = New-Object 'Collections.Generic.List[string]'
  foreach ($record in $Records) {
    if ($null -eq $record -or $record -isnot [Collections.IDictionary]) {
      throw 'RUNTIME_INVENTORY_FAILED'
    }
    $jsonRecords.Add((Convert-AgentRoadRecordToJson $record))
  }
  $ordered = $jsonRecords.ToArray()
  [Array]::Sort($ordered, [StringComparer]::Ordinal)
  $unique = New-Object 'Collections.Generic.List[string]'
  $prior = $null
  foreach ($record in $ordered) {
    if ($null -eq $prior -or -not [StringComparer]::Ordinal.Equals($prior, $record)) {
      $unique.Add($record)
      $prior = $record
    }
  }
  if ($unique.Count -gt $Limit) { throw 'RUNTIME_INVENTORY_FAILED' }
  $bytesUsed = 8 + $script:Utf8.GetByteCount($Id) + $script:Utf8.GetByteCount([string]$unique.Count)
  foreach ($record in $unique) {
    $bytesUsed += 4 + $script:Utf8.GetByteCount($record)
    if ($bytesUsed -gt $script:SurfaceByteLimit) { throw 'RUNTIME_INVENTORY_FAILED' }
  }
  return $unique.ToArray()
}

function Add-AgentRoadHmacBytes {
  param(
    [Parameter(Mandatory = $true)][Security.Cryptography.HMACSHA256]$Hmac,
    [Parameter(Mandatory = $true)][byte[]]$Bytes
  )
  if ($Bytes.Length -eq 0) { return }
  $output = New-Object byte[] $Bytes.Length
  try {
    $null = $Hmac.TransformBlock($Bytes, 0, $Bytes.Length, $output, 0)
  } finally {
    [Array]::Clear($output, 0, $output.Length)
  }
}

function Add-AgentRoadHmacFrame {
  param(
    [Parameter(Mandatory = $true)][Security.Cryptography.HMACSHA256]$Hmac,
    [Parameter(Mandatory = $true)][string]$Value
  )
  $bytes = $script:Utf8.GetBytes($Value)
  if ([uint64]$bytes.Length -gt [uint32]::MaxValue) {
    [Array]::Clear($bytes, 0, $bytes.Length)
    throw 'RUNTIME_INVENTORY_FAILED'
  }
  [byte[]]$length = @(
    [byte](($bytes.Length -shr 24) -band 255),
    [byte](($bytes.Length -shr 16) -band 255),
    [byte](($bytes.Length -shr 8) -band 255),
    [byte]($bytes.Length -band 255)
  )
  try {
    Add-AgentRoadHmacBytes $Hmac $length
    Add-AgentRoadHmacBytes $Hmac $bytes
  } finally {
    [Array]::Clear($length, 0, $length.Length)
    [Array]::Clear($bytes, 0, $bytes.Length)
  }
}

function New-AgentRoadSurface {
  param(
    [Parameter(Mandatory = $true)][string]$Id,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Records,
    [Parameter(Mandatory = $true)][byte[]]$Key
  )
  if (-not $script:SurfaceLimits.Contains($Id)) { throw 'RUNTIME_INVENTORY_FAILED' }
  $canonical = @(Convert-AgentRoadRecords $Records ([int]$script:SurfaceLimits[$Id]) $Id)
  if ($Id -ceq 'firewall-profiles' -and $canonical.Count -ne 3) {
    throw 'RUNTIME_INVENTORY_FAILED'
  }
  $hmac = New-Object Security.Cryptography.HMACSHA256(,$Key)
  try {
    $domain = $script:Utf8.GetBytes($script:SurfaceDomainText.Replace('\0', [string][char]0))
    try { Add-AgentRoadHmacBytes $hmac $domain } finally { [Array]::Clear($domain, 0, $domain.Length) }
    Add-AgentRoadHmacFrame $hmac $Id
    Add-AgentRoadHmacFrame $hmac ([string]$canonical.Count)
    foreach ($record in $canonical) { Add-AgentRoadHmacFrame $hmac $record }
    $empty = New-Object byte[] 0
    $null = $hmac.TransformFinalBlock($empty, 0, 0)
    $mac = ([BitConverter]::ToString($hmac.Hash)).Replace('-', '')
    return [ordered]@{ id = $Id; count = $canonical.Count; mac = $mac }
  } finally {
    $hmac.Dispose()
  }
}

function Get-AgentRoadOrdinalStrings {
  param([AllowNull()][AllowEmptyCollection()][object[]]$Values)
  $strings = New-Object 'Collections.Generic.List[string]'
  foreach ($value in @($Values)) {
    if ($null -ne $value) { $strings.Add([string]$value) }
  }
  $result = $strings.ToArray()
  [Array]::Sort($result, [StringComparer]::Ordinal)
  $unique = New-Object 'Collections.Generic.List[string]'
  $prior = $null
  foreach ($value in $result) {
    if ($null -eq $prior -or -not [StringComparer]::Ordinal.Equals($prior, $value)) {
      $unique.Add($value)
      $prior = $value
    }
  }
  return ,$unique.ToArray()
}

function Convert-AgentRoadEnum {
  param([AllowNull()][object]$Value)
  if ($null -eq $Value) { return -1 }
  if ($Value -is [bool]) { if ([bool]$Value) { return 1 } else { return 0 } }
  try { return [Convert]::ToInt32($Value, [Globalization.CultureInfo]::InvariantCulture) } catch {
    throw 'RUNTIME_INVENTORY_FAILED'
  }
}

function Get-AgentRoadProperty {
  param(
    [Parameter(Mandatory = $true)][AllowNull()][object]$Object,
    [Parameter(Mandatory = $true)][string]$Name,
    [AllowNull()][object]$Default = $null
  )
  if ($null -eq $Object) { return $Default }
  $property = $Object.PSObject.Properties[$Name]
  if ($null -eq $property) { return $Default }
  return $property.Value
}

function Convert-AgentRoadRegistryValue {
  param([AllowNull()][object]$Value)
  if ($null -eq $Value) { return '__NULL__' }
  if ($Value -is [byte[]]) { return ([BitConverter]::ToString($Value)).Replace('-', '') }
  if ($Value -is [string[]]) {
    $strings = @($Value | ForEach-Object { [string]$_ })
    [Array]::Sort($strings, [StringComparer]::Ordinal)
    $unique = New-Object 'Collections.Generic.List[string]'
    $prior = $null
    foreach ($entry in $strings) {
      if ($null -eq $prior -or -not [StringComparer]::Ordinal.Equals($prior, $entry)) {
        $unique.Add($entry)
        $prior = $entry
      }
    }
    return ,$unique.ToArray()
  }
  if ($Value -is [string]) { return [string]$Value }
  if ($Value -is [int] -or $Value -is [uint32] -or $Value -is [long] -or $Value -is [uint64]) {
    return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
  }
  throw 'RUNTIME_INVENTORY_FAILED'
}

function Read-AgentRoadRegistryValues {
  param(
    [Parameter(Mandatory = $true)][AllowNull()][Microsoft.Win32.RegistryKey]$Key,
    [Parameter(Mandatory = $true)][string]$MissingState
  )
  if ($null -eq $Key) { return @([ordered]@{ recordType = 'sentinel'; state = $MissingState }) }
  $names = @($Key.GetValueNames())
  [Array]::Sort($names, [StringComparer]::Ordinal)
  $records = New-Object 'Collections.Generic.List[object]'
  foreach ($name in $names) {
    $records.Add([ordered]@{
      recordType = 'value'
      name = [string]$name
      valueKind = [int]($Key.GetValueKind($name))
      value = Convert-AgentRoadRegistryValue ($Key.GetValue(
        $name,
        $null,
        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
      ))
    })
  }
  return $records.ToArray()
}

function Get-AgentRoadMachineEnvironmentRecords {
  $base = $null
  $key = $null
  try {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
      [Microsoft.Win32.RegistryHive]::LocalMachine,
      [Microsoft.Win32.RegistryView]::Registry64
    )
    $key = $base.OpenSubKey(
      'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
      $false
    )
    return @(Read-AgentRoadRegistryValues $key 'MACHINE_ENVIRONMENT_KEY_MISSING')
  } finally {
    if ($null -ne $key) { $key.Dispose() }
    if ($null -ne $base) { $base.Dispose() }
  }
}

function Get-AgentRoadAccountFacts {
  $accounts = @(Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True AND Name='AgentRoad'")
  if ($accounts.Count -gt 1) { throw 'RUNTIME_INVENTORY_FAILED' }
  if ($accounts.Count -eq 0) {
    return [ordered]@{
      sid = $null
      records = @([ordered]@{ recordType = 'sentinel'; state = 'ACCOUNT_MISSING' })
    }
  }
  $account = $accounts[0]
  $sid = [string]$account.SID
  if ($sid -notmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$') { throw 'RUNTIME_INVENTORY_FAILED' }
  $administratorSid = New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'
  $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
  try {
    if ([string]$currentIdentity.User.Value -cne $sid) { throw 'RUNTIME_INVENTORY_FAILED' }
    $administratorMember = ([Security.Principal.WindowsPrincipal]$currentIdentity).IsInRole($administratorSid)
  } finally {
    $currentIdentity.Dispose()
  }
  $records = New-Object 'Collections.Generic.List[object]'
  $records.Add([ordered]@{
    recordType = 'account'
    sid = $sid
    name = [string]$account.Name
    domain = [string]$account.Domain
    localAccount = [bool]$account.LocalAccount
    disabled = [bool]$account.Disabled
    accountType = [uint32]$account.AccountType
    administratorMember = [bool]$administratorMember
  })
  $base = $null
  $profile = $null
  try {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
      [Microsoft.Win32.RegistryHive]::LocalMachine,
      [Microsoft.Win32.RegistryView]::Registry64
    )
    $profile = $base.OpenSubKey(
      ('SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $sid),
      $false
    )
    if ($null -eq $profile) {
      $records.Add([ordered]@{ recordType = 'profile-sentinel'; sid = $sid; state = 'PROFILE_KEY_MISSING' })
    } else {
      $profilePath = $profile.GetValue(
        'ProfileImagePath',
        '__MISSING__',
        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
      )
      $flags = $profile.GetValue('Flags', -1, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
      $records.Add([ordered]@{
        recordType = 'profile'
        sid = $sid
        profileImagePath = [string]$profilePath
        flags = [int64]$flags
      })
    }
  } finally {
    if ($null -ne $profile) { $profile.Dispose() }
    if ($null -ne $base) { $base.Dispose() }
  }
  return [ordered]@{ sid = $sid; records = $records.ToArray() }
}

function Get-AgentRoadAccountEnvironmentRecords {
  param([AllowNull()][string]$Sid)
  if ($null -eq $Sid) {
    return @([ordered]@{ recordType = 'sentinel'; state = 'ACCOUNT_MISSING' })
  }
  $base = $null
  $hive = $null
  $environment = $null
  try {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
      [Microsoft.Win32.RegistryHive]::Users,
      [Microsoft.Win32.RegistryView]::Registry64
    )
    $hive = $base.OpenSubKey($Sid, $false)
    if ($null -eq $hive) {
      return @([ordered]@{ recordType = 'sentinel'; state = 'HIVE_UNMOUNTED' })
    }
    $environment = $hive.OpenSubKey('Environment', $false)
    return @(Read-AgentRoadRegistryValues $environment 'ENVIRONMENT_KEY_MISSING')
  } finally {
    if ($null -ne $environment) { $environment.Dispose() }
    if ($null -ne $hive) { $hive.Dispose() }
    if ($null -ne $base) { $base.Dispose() }
  }
}

function Get-AgentRoadCommandResolutionRecords {
  $records = New-Object 'Collections.Generic.List[object]'
  foreach ($name in $script:CommandNames) {
    $commands = @(Get-Command -Name $name -CommandType Application -All -ErrorAction SilentlyContinue)
    if ($commands.Count -eq 0) {
      $records.Add([ordered]@{ command = $name; recordType = 'missing'; rank = -1; winner = $false })
      continue
    }
    $rank = 0
    foreach ($command in $commands) {
      $path = Get-AgentRoadProperty $command 'Path' $null
      if ($null -eq $path) { $path = Get-AgentRoadProperty $command 'Source' '__MISSING__' }
      $records.Add([ordered]@{
        command = $name
        recordType = 'application'
        rank = $rank
        winner = ($rank -eq 0)
        path = [string]$path
      })
      $rank += 1
    }
  }
  return $records.ToArray()
}

function Get-AgentRoadServiceDefinitionRecords {
  $records = New-Object 'Collections.Generic.List[object]'
  $found = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  $base = $null
  $servicesRoot = $null
  try {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
      [Microsoft.Win32.RegistryHive]::LocalMachine,
      [Microsoft.Win32.RegistryView]::Registry64
    )
    $servicesRoot = $base.OpenSubKey('SYSTEM\CurrentControlSet\Services', $false)
    if ($null -eq $servicesRoot) { throw 'RUNTIME_INVENTORY_FAILED' }
    $names = @($servicesRoot.GetSubKeyNames() | Where-Object {
      $_ -ieq 'sshd' -or $_ -ieq 'Tailscale' -or $_ -match '^(?i:AgentRoad(?:-|$))'
    })
    foreach ($name in $names) {
      $serviceKey = $null
      try {
        $serviceKey = $servicesRoot.OpenSubKey([string]$name, $false)
        if ($null -eq $serviceKey) { throw 'RUNTIME_INVENTORY_FAILED' }
        $null = $found.Add([string]$name)
        $actualValueNames = @($serviceKey.GetValueNames())
        $values = New-Object 'Collections.Generic.List[object]'
        foreach ($valueName in $script:ServiceValueNames) {
          $matches = @($actualValueNames | Where-Object { [string]$_ -ieq $valueName })
          if ($matches.Count -gt 1) { throw 'RUNTIME_INVENTORY_FAILED' }
          if ($matches.Count -eq 0) {
            $values.Add([ordered]@{ name = $valueName; state = 'MISSING' })
            continue
          }
          $values.Add([ordered]@{
            name = $valueName
            state = 'PRESENT'
            valueKind = [int]($serviceKey.GetValueKind([string]$matches[0]))
            value = Convert-AgentRoadRegistryValue ($serviceKey.GetValue(
              [string]$matches[0],
              $null,
              [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            ))
          })
        }
        $records.Add([ordered]@{
          recordType = 'service'
          name = [string]$name
          values = $values.ToArray()
        })
      } finally {
        if ($null -ne $serviceKey) { $serviceKey.Dispose() }
      }
    }
    foreach ($name in $script:FixedServiceNames) {
      if (-not $found.Contains($name)) {
        $records.Add([ordered]@{ recordType = 'missing'; name = $name })
      }
    }
  } finally {
    if ($null -ne $servicesRoot) { $servicesRoot.Dispose() }
    if ($null -ne $base) { $base.Dispose() }
  }
  return $records.ToArray()
}

function Get-AgentRoadScheduledTaskRecords {
  $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
    ([string]$_.TaskPath).StartsWith(
      $script:TaskNamespace,
      [StringComparison]::OrdinalIgnoreCase
    )
  })
  $records = New-Object 'Collections.Generic.List[object]'
  foreach ($task in $tasks) {
    $taskPath = [string]$task.TaskPath
    if (-not $taskPath.StartsWith($script:TaskNamespace, [StringComparison]::OrdinalIgnoreCase)) {
      throw 'RUNTIME_INVENTORY_FAILED'
    }
    $xml = Export-ScheduledTask `
      -TaskName ([string]$task.TaskName) `
      -TaskPath $taskPath `
      -ErrorAction Stop
    if ($xml -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$xml)) {
      throw 'RUNTIME_INVENTORY_FAILED'
    }
    if ($script:Utf8.GetByteCount([string]$xml) -gt $script:FieldByteLimit) {
      throw 'RUNTIME_INVENTORY_FAILED'
    }
    $document = New-Object Xml.XmlDocument
    $document.PreserveWhitespace = $false
    $document.XmlResolver = $null
    $document.LoadXml([string]$xml)
    $volatileNodes = @($document.SelectNodes(
      "/*[local-name()='Task']/*[local-name()='RegistrationInfo']/*[local-name()='Date' or local-name()='Description' or local-name()='Documentation']"
    ))
    foreach ($node in $volatileNodes) { $null = $node.ParentNode.RemoveChild($node) }
    $records.Add([ordered]@{
      recordType = 'task'
      taskPath = $taskPath
      taskName = [string]$task.TaskName
      definitionXml = [string]$document.OuterXml
    })
  }
  return $records.ToArray()
}

function Get-AgentRoadFirewallRuleRecords {
  $rules = @(Get-NetFirewallRule -PolicyStore 'PersistentStore')
  $candidates = New-Object 'Collections.Generic.List[object]'
  foreach ($rule in @($rules | Where-Object {
    ([string]$_.Name -cin $script:FirewallRuleNames) -or
    ([string]$_.Name -match '^(?i:AgentRoad(?:-|$))') -or
    ([string]$_.DisplayName -ceq $script:TailscaleFirewallDisplayIdentity)
  })) { $candidates.Add($rule) }
  $serviceIdentityFilters = @(Get-NetFirewallServiceFilter -PolicyStore 'PersistentStore' | Where-Object {
    $service = [string](Get-AgentRoadProperty $_ 'Service' '')
    $service -cin $script:FirewallServiceIdentities -or $service -match '^(?i:AgentRoad(?:-|$))'
  })
  foreach ($filter in $serviceIdentityFilters) {
    foreach ($rule in @($filter | Get-NetFirewallRule -ErrorAction Stop)) { $candidates.Add($rule) }
  }
  $applicationIdentityFilters = @(Get-NetFirewallApplicationFilter -PolicyStore 'PersistentStore' | Where-Object {
    $program = [string](Get-AgentRoadProperty $_ 'Program' '')
    $matchesProgram = $false
    if (-not [string]::IsNullOrWhiteSpace($program) -and $program -ine 'Any') {
      try { $matchesProgram = [IO.Path]::GetFileName($program) -cin $script:FirewallProgramNames } catch {}
    }
    $matchesProgram
  })
  foreach ($filter in $applicationIdentityFilters) {
    foreach ($rule in @($filter | Get-NetFirewallRule -ErrorAction Stop)) { $candidates.Add($rule) }
  }
  $selected = New-Object 'Collections.Generic.List[object]'
  $seen = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  foreach ($rule in $candidates) {
    $name = [string]$rule.Name
    if ([string]::IsNullOrWhiteSpace($name)) { throw 'RUNTIME_INVENTORY_FAILED' }
    if ($seen.Add($name)) { $selected.Add($rule) }
  }
  if ($selected.Count -gt [int]$script:SurfaceLimits['firewall-rules']) {
    throw 'RUNTIME_INVENTORY_FAILED'
  }
  $records = New-Object 'Collections.Generic.List[object]'
  foreach ($rule in $selected) {
    $ports = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule)
    $addresses = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule)
    $applications = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule)
    $services = @(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule)
    $interfaceTypes = @(Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $rule)
    $interfaces = @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule)
    $records.Add([ordered]@{
      recordType = 'firewall-rule'
      name = [string]$rule.Name
      enabled = Convert-AgentRoadEnum $rule.Enabled
      direction = Convert-AgentRoadEnum $rule.Direction
      action = Convert-AgentRoadEnum $rule.Action
      profile = Convert-AgentRoadEnum $rule.Profile
      edgeTraversalPolicy = Convert-AgentRoadEnum $rule.EdgeTraversalPolicy
      protocol = Get-AgentRoadOrdinalStrings @($ports | ForEach-Object {
        Get-AgentRoadProperty $_ 'Protocol' $null
      })
      localPort = Get-AgentRoadOrdinalStrings @($ports | ForEach-Object { Get-AgentRoadProperty $_ 'LocalPort' $null })
      remotePort = Get-AgentRoadOrdinalStrings @($ports | ForEach-Object { Get-AgentRoadProperty $_ 'RemotePort' $null })
      icmpType = Get-AgentRoadOrdinalStrings @($ports | ForEach-Object { Get-AgentRoadProperty $_ 'IcmpType' $null })
      dynamicTransport = Get-AgentRoadOrdinalStrings @($ports | ForEach-Object { Get-AgentRoadProperty $_ 'DynamicTransport' $null })
      localAddress = Get-AgentRoadOrdinalStrings @($addresses | ForEach-Object { Get-AgentRoadProperty $_ 'LocalAddress' $null })
      remoteAddress = Get-AgentRoadOrdinalStrings @($addresses | ForEach-Object { Get-AgentRoadProperty $_ 'RemoteAddress' $null })
      program = Get-AgentRoadOrdinalStrings @($applications | ForEach-Object { Get-AgentRoadProperty $_ 'Program' $null })
      package = Get-AgentRoadOrdinalStrings @($applications | ForEach-Object { Get-AgentRoadProperty $_ 'Package' $null })
      service = Get-AgentRoadOrdinalStrings @($services | ForEach-Object { Get-AgentRoadProperty $_ 'Service' $null })
      interfaceType = Get-AgentRoadOrdinalStrings @($interfaceTypes | ForEach-Object {
        foreach ($value in @(Get-AgentRoadProperty $_ 'InterfaceType' $null)) {
          if ($null -ne $value) { [string](Convert-AgentRoadEnum $value) }
        }
      })
      interfaceAlias = Get-AgentRoadOrdinalStrings @($interfaces | ForEach-Object { Get-AgentRoadProperty $_ 'InterfaceAlias' $null })
    })
  }
  return $records.ToArray()
}

function Get-AgentRoadFirewallProfileRecords {
  $profiles = @(Get-NetFirewallProfile -PolicyStore 'PersistentStore')
  $selected = @($profiles | Where-Object { [string]$_.Name -cin @('Domain', 'Private', 'Public') })
  if ($selected.Count -ne 3) { throw 'RUNTIME_INVENTORY_FAILED' }
  $records = New-Object 'Collections.Generic.List[object]'
  foreach ($profile in $selected) {
    $records.Add([ordered]@{
      recordType = 'firewall-profile'
      name = [string]$profile.Name
      enabled = Convert-AgentRoadEnum (Get-AgentRoadProperty $profile 'Enabled' $null)
      defaultInboundAction = Convert-AgentRoadEnum (Get-AgentRoadProperty $profile 'DefaultInboundAction' $null)
      defaultOutboundAction = Convert-AgentRoadEnum (Get-AgentRoadProperty $profile 'DefaultOutboundAction' $null)
      allowInboundRules = Convert-AgentRoadEnum (Get-AgentRoadProperty $profile 'AllowInboundRules' $null)
      allowLocalFirewallRules = Convert-AgentRoadEnum (Get-AgentRoadProperty $profile 'AllowLocalFirewallRules' $null)
      allowLocalIPsecRules = Convert-AgentRoadEnum (Get-AgentRoadProperty $profile 'AllowLocalIPsecRules' $null)
      notifyOnListen = Convert-AgentRoadEnum (Get-AgentRoadProperty $profile 'NotifyOnListen' $null)
      enableStealthModeForIPsec = Convert-AgentRoadEnum (Get-AgentRoadProperty $profile 'EnableStealthModeForIPsec' $null)
      logAllowed = Convert-AgentRoadEnum (Get-AgentRoadProperty $profile 'LogAllowed' $null)
      logBlocked = Convert-AgentRoadEnum (Get-AgentRoadProperty $profile 'LogBlocked' $null)
      logIgnored = Convert-AgentRoadEnum (Get-AgentRoadProperty $profile 'LogIgnored' $null)
    })
  }
  return $records.ToArray()
}

function Get-AgentRoadExplicitAclRules {
  param([Parameter(Mandatory = $true)][Security.AccessControl.FileSystemSecurity]$Acl)
  $rules = @($Acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
  $records = New-Object 'Collections.Generic.List[string]'
  foreach ($rule in $rules) {
    $sid = [string]$rule.IdentityReference.Value
    $json = Convert-AgentRoadRecordToJson ([ordered]@{
      sid = $sid
      accessType = [int]$rule.AccessControlType
      rights = [string][int64]$rule.FileSystemRights
      inheritance = [int]$rule.InheritanceFlags
      propagation = [int]$rule.PropagationFlags
    })
    $records.Add($json)
  }
  $result = $records.ToArray()
  [Array]::Sort($result, [StringComparer]::Ordinal)
  $unique = New-Object 'Collections.Generic.List[string]'
  $prior = $null
  foreach ($record in $result) {
    if ($null -eq $prior -or -not [StringComparer]::Ordinal.Equals($prior, $record)) {
      $unique.Add($record)
      $prior = $record
    }
  }
  return $unique.ToArray()
}

function Get-AgentRoadExternalAclRecords {
  $records = New-Object 'Collections.Generic.List[object]'
  foreach ($path in $script:ExternalSentinelPaths) {
    if (-not (Test-Path -LiteralPath $path)) {
      $records.Add([ordered]@{ path = $path; recordType = 'missing' })
      continue
    }
    $item = Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw 'RUNTIME_INVENTORY_FAILED'
    }
    $acl = Get-Acl -LiteralPath $path
    $confirmedItem = Get-Item -LiteralPath $path -Force
    if (
      ($confirmedItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
      [bool]$confirmedItem.PSIsContainer -ne [bool]$item.PSIsContainer
    ) { throw 'RUNTIME_INVENTORY_FAILED' }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $records.Add([ordered]@{
      path = $path
      recordType = 'acl'
      nodeType = if ($item.PSIsContainer) { 'directory' } else { 'file' }
      reparsePoint = $false
      ownerSid = [string]$owner
      protected = [bool]$acl.AreAccessRulesProtected
      canonical = [bool]$acl.AreAccessRulesCanonical
      explicitRules = @(Get-AgentRoadExplicitAclRules $acl)
    })
  }
  return $records.ToArray()
}

$inputBytes = $null
$keyBytes = $null
$exitCode = 42
try {
  $inputBytes = Read-AgentRoadBoundedInput
  $keyBytes = Read-AgentRoadProtocolInput $inputBytes
  [Array]::Clear($inputBytes, 0, $inputBytes.Length)
  $inputBytes = $null

  $accountFacts = Get-AgentRoadAccountFacts
  $surfaces = @(
    New-AgentRoadSurface 'account-environment' @(Get-AgentRoadAccountEnvironmentRecords $accountFacts.sid) $keyBytes
    New-AgentRoadSurface 'account-profile-identity' @($accountFacts.records) $keyBytes
    New-AgentRoadSurface 'command-resolution' @(Get-AgentRoadCommandResolutionRecords) $keyBytes
    New-AgentRoadSurface 'external-sentinel-acls' @(Get-AgentRoadExternalAclRecords) $keyBytes
    New-AgentRoadSurface 'firewall-profiles' @(Get-AgentRoadFirewallProfileRecords) $keyBytes
    New-AgentRoadSurface 'firewall-rules' @(Get-AgentRoadFirewallRuleRecords) $keyBytes
    New-AgentRoadSurface 'machine-environment' @(Get-AgentRoadMachineEnvironmentRecords) $keyBytes
    New-AgentRoadSurface 'scheduled-tasks' @(Get-AgentRoadScheduledTaskRecords) $keyBytes
    New-AgentRoadSurface 'service-definitions' @(Get-AgentRoadServiceDefinitionRecords) $keyBytes
  )
  if ($surfaces.Count -ne 9) { throw 'RUNTIME_INVENTORY_FAILED' }
  $result = [ordered]@{
    schemaVersion = 1
    protocolRevision = 1
    surfaces = $surfaces
  }
  $json = ConvertTo-Json -Compress -Depth 8 -InputObject $result
  if ($script:Utf8.GetByteCount($json) -gt $script:OutputByteLimit) {
    throw 'RUNTIME_INVENTORY_FAILED'
  }
  [Console]::Out.Write($json)
  $exitCode = 0
} catch {
  $exitCode = 42
} finally {
  if ($null -ne $inputBytes) { [Array]::Clear($inputBytes, 0, $inputBytes.Length) }
  if ($null -ne $keyBytes) { [Array]::Clear($keyBytes, 0, $keyBytes.Length) }
}
exit $exitCode
