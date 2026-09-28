[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [pscustomobject]$Configuration
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$script:BootstrapRoot = 'C:\ProgramData\AgentRoad\bootstrap'
$script:JournalPath = Join-Path $script:BootstrapRoot 'journal.json'
$script:LockPath = Join-Path $script:BootstrapRoot 'bootstrap.lock'
$script:SshRoot = 'C:\ProgramData\AgentRoad\ssh'
$script:AuthorizedKeyPath = 'C:\ProgramData\AgentRoad\ssh\authorized_keys'
$script:SshDataRoot = 'C:\ProgramData\ssh'
$script:SshdConfigPath = 'C:\ProgramData\ssh\sshd_config'
$script:FirewallName = 'AgentRoad-OpenSSH-Tailscale'
$script:Journal = $null
$script:BootstrapLock = $null
$script:ConfigChanged = $false
$script:CapabilityInstalledByAgentRoad = $false
$script:TailscaleAddresses = @()
$script:SupersedingHealthy = $false

if ($null -eq ('AgentRoad.NativeRunner' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace AgentRoad {
  public sealed class NativeResult {
    public int ExitCode;
    public string Stdout;
    public string Stderr;
    public string Failure;
  }

  public sealed class ServiceRecoveryResult {
    public uint ResetPeriod;
    public string RebootMessage;
    public string Command;
    public int[] ActionTypes;
    public uint[] Delays;
    public bool FailureActionsOnNonCrashFailures;
    public string Failure;
  }

  public static class NativeRunner {
    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SERVICE_QUERY_CONFIG = 0x0001;
    private const uint SERVICE_CONFIG_FAILURE_ACTIONS = 2;
    private const uint SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 4;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;

    [StructLayout(LayoutKind.Sequential)]
    private struct SC_ACTION {
      public int Type;
      public uint Delay;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SERVICE_FAILURE_ACTIONS {
      public uint ResetPeriod;
      public IntPtr RebootMessage;
      public IntPtr Command;
      public uint ActionCount;
      public IntPtr Actions;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_FAILURE_ACTIONS_FLAG {
      [MarshalAs(UnmanagedType.Bool)]
      public bool Enabled;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr manager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceConfig2(IntPtr service, uint infoLevel, IntPtr buffer, uint bufferSize, out uint bytesNeeded);

    [DllImport("advapi32.dll")]
    private static extern bool CloseServiceHandle(IntPtr handle);

    private static ServiceRecoveryResult ServiceRecoveryFailure() {
      return new ServiceRecoveryResult { Failure = "SERVICE_RECOVERY_QUERY_FAILED" };
    }

    public static ServiceRecoveryResult QueryServiceRecovery(string serviceName) {
      IntPtr manager = IntPtr.Zero;
      IntPtr service = IntPtr.Zero;
      IntPtr actionsBuffer = IntPtr.Zero;
      IntPtr flagBuffer = IntPtr.Zero;
      try {
        if (String.IsNullOrEmpty(serviceName)) return ServiceRecoveryFailure();
        manager = OpenSCManager(null, null, SC_MANAGER_CONNECT);
        if (manager == IntPtr.Zero) return ServiceRecoveryFailure();
        service = OpenService(manager, serviceName, SERVICE_QUERY_CONFIG);
        if (service == IntPtr.Zero) return ServiceRecoveryFailure();

        uint bytesNeeded;
        bool first = QueryServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, IntPtr.Zero, 0, out bytesNeeded);
        if (first || Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER || bytesNeeded == 0 || bytesNeeded > 65536) return ServiceRecoveryFailure();
        actionsBuffer = Marshal.AllocHGlobal((int)bytesNeeded);
        if (!QueryServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, actionsBuffer, bytesNeeded, out bytesNeeded)) return ServiceRecoveryFailure();
        SERVICE_FAILURE_ACTIONS actions = (SERVICE_FAILURE_ACTIONS)Marshal.PtrToStructure(actionsBuffer, typeof(SERVICE_FAILURE_ACTIONS));
        if (actions.ActionCount > 16 || (actions.ActionCount > 0 && actions.Actions == IntPtr.Zero)) return ServiceRecoveryFailure();

        int count = (int)actions.ActionCount;
        int[] actionTypes = new int[count];
        uint[] delays = new uint[count];
        int actionSize = Marshal.SizeOf(typeof(SC_ACTION));
        for (int index = 0; index < count; index++) {
          SC_ACTION action = (SC_ACTION)Marshal.PtrToStructure(IntPtr.Add(actions.Actions, index * actionSize), typeof(SC_ACTION));
          actionTypes[index] = action.Type;
          delays[index] = action.Delay;
        }

        int flagSize = Marshal.SizeOf(typeof(SERVICE_FAILURE_ACTIONS_FLAG));
        flagBuffer = Marshal.AllocHGlobal(flagSize);
        uint flagBytes;
        if (!QueryServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, flagBuffer, (uint)flagSize, out flagBytes)) return ServiceRecoveryFailure();
        SERVICE_FAILURE_ACTIONS_FLAG flag = (SERVICE_FAILURE_ACTIONS_FLAG)Marshal.PtrToStructure(flagBuffer, typeof(SERVICE_FAILURE_ACTIONS_FLAG));

        return new ServiceRecoveryResult {
          ResetPeriod = actions.ResetPeriod,
          RebootMessage = actions.RebootMessage == IntPtr.Zero ? String.Empty : Marshal.PtrToStringUni(actions.RebootMessage),
          Command = actions.Command == IntPtr.Zero ? String.Empty : Marshal.PtrToStringUni(actions.Command),
          ActionTypes = actionTypes,
          Delays = delays,
          FailureActionsOnNonCrashFailures = flag.Enabled
        };
      } catch { return ServiceRecoveryFailure(); }
      finally {
        if (flagBuffer != IntPtr.Zero) Marshal.FreeHGlobal(flagBuffer);
        if (actionsBuffer != IntPtr.Zero) Marshal.FreeHGlobal(actionsBuffer);
        if (service != IntPtr.Zero) CloseServiceHandle(service);
        if (manager != IntPtr.Zero) CloseServiceHandle(manager);
      }
    }

    private sealed class JsonScan {
      private readonly string Text;
      private int Index;
      public bool Duplicate;
      public JsonScan(string text) { Text = text; }
      private void White() { while (Index < Text.Length && Char.IsWhiteSpace(Text[Index])) Index++; }
      private string StringValue() {
        if (Index >= Text.Length || Text[Index++] != '"') throw new FormatException();
        var value = new StringBuilder();
        while (Index < Text.Length) {
          char current = Text[Index++];
          if (current == '"') return value.ToString();
          if (current != '\\') { if (current < 0x20) throw new FormatException(); value.Append(current); continue; }
          if (Index >= Text.Length) throw new FormatException();
          char escape = Text[Index++];
          if (escape == 'u') {
            if (Index > Text.Length - 4) throw new FormatException();
            value.Append((char)Int32.Parse(Text.Substring(Index, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
            Index += 4;
          } else {
            const string escaped = "\"\\/bfnrt";
            const string decoded = "\"\\/\b\f\n\r\t";
            int position = escaped.IndexOf(escape);
            if (position < 0) throw new FormatException();
            value.Append(decoded[position]);
          }
        }
        throw new FormatException();
      }
      private void Value() {
        White();
        if (Index >= Text.Length) throw new FormatException();
        if (Text[Index] == '{') { ObjectValue(); return; }
        if (Text[Index] == '[') { ArrayValue(); return; }
        if (Text[Index] == '"') { StringValue(); return; }
        int start = Index;
        while (Index < Text.Length && ",]} \t\r\n".IndexOf(Text[Index]) < 0) Index++;
        if (Index == start) throw new FormatException();
      }
      private void ObjectValue() {
        Index++; White();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (Index < Text.Length && Text[Index] == '}') { Index++; return; }
        while (true) {
          White(); string name = StringValue(); if (!names.Add(name)) Duplicate = true;
          White(); if (Index >= Text.Length || Text[Index++] != ':') throw new FormatException();
          Value(); White();
          if (Index < Text.Length && Text[Index] == '}') { Index++; return; }
          if (Index >= Text.Length || Text[Index++] != ',') throw new FormatException();
        }
      }
      private void ArrayValue() {
        Index++; White();
        if (Index < Text.Length && Text[Index] == ']') { Index++; return; }
        while (true) {
          Value(); White();
          if (Index < Text.Length && Text[Index] == ']') { Index++; return; }
          if (Index >= Text.Length || Text[Index++] != ',') throw new FormatException();
        }
      }
      public bool InvalidOrDuplicate() {
        try { White(); Value(); White(); return Index != Text.Length || Duplicate; } catch { return true; }
      }
    }

    public static bool HasDuplicateJsonKeys(string json) { return new JsonScan(json).InvalidOrDuplicate(); }

    private sealed class DrainState {
      public readonly object Gate = new object();
      public readonly Process Process;
      public int Bytes;
      public bool Exceeded;
      public DrainState(Process process) { Process = process; }
    }

    private static async Task<string> Drain(System.IO.StreamReader reader, DrainState state) {
      var builder = new StringBuilder();
      var buffer = new char[4096];
      while (true) {
        int count = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
        if (count == 0) return builder.ToString();
        int bytes = Encoding.UTF8.GetByteCount(buffer, 0, count);
        lock (state.Gate) {
          if (state.Bytes > 65536 - bytes) {
            state.Exceeded = true;
            KillTree(state.Process);
            return String.Empty;
          }
          state.Bytes += bytes;
          builder.Append(buffer, 0, count);
        }
      }
    }

    private static void KillTree(Process process) {
      try {
        string taskkill = System.IO.Path.Combine(Environment.GetEnvironmentVariable("SystemRoot"), "System32", "taskkill.exe");
        var start = new ProcessStartInfo(taskkill, "/PID " + process.Id + " /T /F");
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        using (var killer = Process.Start(start)) {
          if (killer != null) {
            var state = new DrainState(killer);
            Task<string> stdout = Drain(killer.StandardOutput, state);
            Task<string> stderr = Drain(killer.StandardError, state);
            if (!killer.WaitForExit(3000)) { try { killer.Kill(); } catch {}; killer.WaitForExit(1000); }
            try { Task.WaitAll(new Task[] { stdout, stderr }, 1000); } catch {}
          }
        }
      } catch {}
      try { if (!process.HasExited) process.Kill(); } catch {}
    }

    public static NativeResult Run(string filePath, string arguments, int timeoutMilliseconds) {
      var start = new ProcessStartInfo(filePath, arguments);
      start.UseShellExecute = false;
      start.CreateNoWindow = true;
      start.RedirectStandardOutput = true;
      start.RedirectStandardError = true;
      using (var process = new Process()) {
        process.StartInfo = start;
        if (!process.Start()) return new NativeResult { Failure = "NATIVE_PROCESS_FAILED" };
        var state = new DrainState(process);
        Task<string> stdout = Drain(process.StandardOutput, state);
        Task<string> stderr = Drain(process.StandardError, state);
        if (!process.WaitForExit(timeoutMilliseconds)) {
          KillTree(process);
          process.WaitForExit(5000);
          try { Task.WaitAll(new Task[] { stdout, stderr }, 5000); } catch {}
          return new NativeResult { Failure = "NATIVE_PROCESS_TIMEOUT" };
        }
        if (!Task.WaitAll(new Task[] { stdout, stderr }, 5000)) return new NativeResult { Failure = "NATIVE_PROCESS_FAILED" };
        if (state.Exceeded) return new NativeResult { Failure = "NATIVE_PROCESS_OUTPUT_LIMIT" };
        return new NativeResult { ExitCode = process.ExitCode, Stdout = stdout.Result, Stderr = stderr.Result };
      }
    }
  }
}
'@
}

function Invoke-AgentRoadNative {
  param([string]$FilePath, [string[]]$Arguments, [int]$TimeoutSeconds = 30)
  if ([string]::IsNullOrWhiteSpace($FilePath) -or $TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 300) { throw 'NATIVE_PROCESS_INVALID' }
  $escaped = foreach ($argument in $Arguments) {
    if ($null -eq $argument -or $argument.IndexOf([char]0) -ge 0 -or $argument.Contains('"')) { throw 'NATIVE_PROCESS_INVALID' }
    '"' + $argument + '"'
  }
  try { $result = [AgentRoad.NativeRunner]::Run($FilePath,($escaped -join ' '),$TimeoutSeconds * 1000) } catch { throw 'NATIVE_PROCESS_FAILED' }
  if ($null -ne $result.Failure) { throw $result.Failure }
  return [pscustomobject]@{ ExitCode = $result.ExitCode; Stdout = $result.Stdout; Stderr = $result.Stderr }
}

function Assert-AgentRoadExactConfiguration {
  if ($null -eq $Configuration) { throw 'CONFIGURATION_INVALID' }
  $names = @($Configuration.PSObject.Properties.Name)
  $required = @('protocolVersion','deviceId','controllerBaseUrl','completionTicket','sshPublicKey')
  if (@($Configuration.PSObject.Properties).Count -ne 5) { throw 'CONFIGURATION_INVALID' }
  foreach ($name in $required) { if ($names -cnotcontains $name) { throw 'CONFIGURATION_INVALID' } }
  if ($Configuration.protocolVersion -isnot [int] -or $Configuration.protocolVersion -ne 1) { throw 'CONFIGURATION_INVALID' }
  if ($Configuration.deviceId -isnot [string] -or $Configuration.deviceId -cnotmatch '^dev_[a-z0-9]+$' -or $Configuration.deviceId.Length -gt 64) { throw 'CONFIGURATION_INVALID' }
  if ($Configuration.controllerBaseUrl -isnot [string] -or $Configuration.controllerBaseUrl.Length -gt 2048) { throw 'CONFIGURATION_INVALID' }
  $uri = $null
  if (-not [Uri]::TryCreate($Configuration.controllerBaseUrl, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -cne 'https' -or $uri.Query -or $uri.Fragment -or $uri.UserInfo -or $uri.AbsolutePath -cne ('/agent-road/v1/' + $Configuration.deviceId)) { throw 'CONFIGURATION_INVALID' }
  if ($Configuration.completionTicket -isnot [string] -or $Configuration.completionTicket -cnotmatch '^[A-Za-z0-9_-]{43}$') { throw 'CONFIGURATION_INVALID' }
  if ($Configuration.sshPublicKey -isnot [string] -or $Configuration.sshPublicKey.Length -gt 1024 -or $Configuration.sshPublicKey -cne $Configuration.sshPublicKey.Trim() -or $Configuration.sshPublicKey -cnotmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n\x00-\x1F\x7F]+)?$') { throw 'CONFIGURATION_INVALID' }
  $parts = $Configuration.sshPublicKey.Split(' ',3)
  try { $blob = [Convert]::FromBase64String($parts[1]) } catch { throw 'CONFIGURATION_INVALID' }
  if ([Convert]::ToBase64String($blob) -cne $parts[1] -or $blob.Length -ne 51) { throw 'CONFIGURATION_INVALID' }
  $algorithmLength = [Net.IPAddress]::NetworkToHostOrder([BitConverter]::ToInt32($blob,0))
  $keyLength = [Net.IPAddress]::NetworkToHostOrder([BitConverter]::ToInt32($blob,15))
  if ($algorithmLength -ne 11 -or [Text.Encoding]::ASCII.GetString($blob,4,11) -cne 'ssh-ed25519' -or $keyLength -ne 32) { throw 'CONFIGURATION_INVALID' }
}

function Assert-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'ADMIN_REQUIRED' }
}

function Get-AgentRoadSystemFacts {
  $os = Get-CimInstance -ClassName Win32_OperatingSystem
  $build = 0
  if (-not [int]::TryParse([string]$os.BuildNumber, [ref]$build) -or $build -lt 17763) { throw 'UNSUPPORTED_WINDOWS_BUILD' }
  [pscustomobject]@{
    version = [string]$os.Version
    build = $build
    edition = ([string]$os.Caption).Trim()
    architecture = [string]$env:PROCESSOR_ARCHITECTURE
  }
}

function Set-AgentRoadRestrictedAcl {
  param([string]$Path,[string]$ValidationPrefix = '')
  if ($ValidationPrefix -cnotin @('','host-key-1')) { throw 'BOOTSTRAP_STATE_INVALID' }
  $container = Test-Path -LiteralPath $Path -PathType Container
  $administratorGrant = if ($container) { '*S-1-5-32-544:(OI)(CI)F' } else { '*S-1-5-32-544:F' }
  $systemGrant = if ($container) { '*S-1-5-18:(OI)(CI)F' } else { '*S-1-5-18:F' }
  $aclResult = Invoke-AgentRoadNative "$env:SystemRoot\System32\icacls.exe" @($Path,'/inheritance:r','/grant:r',$administratorGrant,$systemGrant) 30
  if ($aclResult.ExitCode -ne 0) { throw 'ACL_CONFIGURATION_FAILED' }
  if ($ValidationPrefix -ceq 'host-key-1') { Record-AgentRoadValidation 'host-key-1-acl-granted' }
  try {
    $aclAfterGrant = Get-Acl -LiteralPath $Path
    $accessRules = @($aclAfterGrant.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]))
  } catch { throw 'ACL_CONFIGURATION_FAILED' }
  if ($accessRules.Count -gt 64) { throw 'ACL_CONFIGURATION_FAILED' }
  $allowedSids = @('S-1-5-18','S-1-5-32-544')
  $untrustedSids = @()
  foreach ($rule in $accessRules) {
    $sid = [string]$rule.IdentityReference.Value
    if ($sid -cnotmatch '^S-\d+(?:-\d+)+$') { throw 'ACL_CONFIGURATION_FAILED' }
    if ($allowedSids -cnotcontains $sid) { $untrustedSids += $sid }
  }
  $untrustedSids = @($untrustedSids | Sort-Object -Unique)
  if ($untrustedSids.Count -gt 64) { throw 'ACL_CONFIGURATION_FAILED' }
  if ($untrustedSids.Count -gt 0) {
    $removeArguments = @($Path,'/remove') + @($untrustedSids | ForEach-Object { '*' + $_ })
    $removeResult = Invoke-AgentRoadNative "$env:SystemRoot\System32\icacls.exe" $removeArguments 30
    if ($removeResult.ExitCode -ne 0) { throw 'ACL_CONFIGURATION_FAILED' }
  }
  $ownerResult = Invoke-AgentRoadNative "$env:SystemRoot\System32\icacls.exe" @($Path,'/setowner','*S-1-5-32-544') 30
  if ($ownerResult.ExitCode -ne 0) { throw 'ACL_CONFIGURATION_FAILED' }
  if ($ValidationPrefix -ceq 'host-key-1') { Record-AgentRoadValidation 'host-key-1-owner-set' }
  $verifyResult = Invoke-AgentRoadNative "$env:SystemRoot\System32\icacls.exe" @($Path,'/verify') 30
  if ($verifyResult.ExitCode -ne 0) { throw 'ACL_CONFIGURATION_FAILED' }
  if ($ValidationPrefix -ceq 'host-key-1') { Record-AgentRoadValidation 'host-key-1-acl-verified' }
  Assert-AgentRoadRestrictedAcl $Path
}

function Assert-AgentRoadRestrictedAcl {
  param([string]$Path)
  $acl = Get-Acl -LiteralPath $Path
  $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if (-not $acl.AreAccessRulesProtected -or -not $acl.AreAccessRulesCanonical -or $ownerSid -cne 'S-1-5-32-544' -or @($acl.Access).Count -ne 2) { throw 'ACL_CONFIGURATION_FAILED' }
  $allowed = @('S-1-5-18','S-1-5-32-544')
  $observed = @()
  $container = Test-Path -LiteralPath $Path -PathType Container
  foreach ($rule in $acl.Access) {
    $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    $expectedInheritance = if ($container) { [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit } else { [Security.AccessControl.InheritanceFlags]::None }
    if ($allowed -cnotcontains $sid -or $rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $rule.InheritanceFlags -ne $expectedInheritance -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { throw 'ACL_CONFIGURATION_FAILED' }
    $observed += $sid
  }
  foreach ($sid in $allowed) { if ($observed -cnotcontains $sid) { throw 'ACL_CONFIGURATION_FAILED' } }
}

function Get-AgentRoadWriteRightsMask {
  $mask = [Security.AccessControl.FileSystemRights]::WriteData
  $mask = $mask -bor [Security.AccessControl.FileSystemRights]::AppendData
  $mask = $mask -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
  $mask = $mask -bor [Security.AccessControl.FileSystemRights]::WriteAttributes
  $mask = $mask -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
  $mask = $mask -bor [Security.AccessControl.FileSystemRights]::Delete
  $mask = $mask -bor [Security.AccessControl.FileSystemRights]::ChangePermissions
  $mask = $mask -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
  return $mask
}

function Assert-AgentRoadSecureSshAcl {
  param([string]$Path)
  Assert-AgentRoadNoUnprivilegedWrite $Path
  $acl = Get-Acl -LiteralPath $Path
  if (-not $acl.AreAccessRulesProtected) { throw 'ACL_CONFIGURATION_FAILED' }
  $trustedWriters = @()
  $writeRights = Get-AgentRoadWriteRightsMask
  foreach ($rule in $acl.Access) {
    if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and ($rule.FileSystemRights -band $writeRights) -ne 0) {
      $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
      if ($sid -cin @('S-1-5-18','S-1-5-32-544')) { $trustedWriters += $sid }
    }
  }
  foreach ($sid in @('S-1-5-18','S-1-5-32-544')) { if ($trustedWriters -cnotcontains $sid) { throw 'ACL_CONFIGURATION_FAILED' } }
}

function Assert-AgentRoadEmptySshDataRoot {
  Assert-AgentRoadSafePath $script:SshDataRoot $true
  if (-not (Test-Path -LiteralPath $script:SshDataRoot -PathType Container)) { throw 'OPENSSH_INSTALL_FAILED' }
  Assert-AgentRoadSecureSshAcl $script:SshDataRoot
  if (@(Get-ChildItem -LiteralPath $script:SshDataRoot -Force -ErrorAction Stop).Count -ne 0) { throw 'OPENSSH_INSTALL_FAILED' }
}

function Assert-AgentRoadNoUnprivilegedWrite {
  param([string]$Path)
  Assert-AgentRoadSafePath $Path $true
  $acl = Get-Acl -LiteralPath $Path
  $trusted = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
  $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($ownerSid -cnotin $trusted -or -not $acl.AreAccessRulesCanonical) { throw 'ACL_CONFIGURATION_FAILED' }
  $writeRights = Get-AgentRoadWriteRightsMask
  foreach ($rule in $acl.Access) {
    if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and ($rule.FileSystemRights -band $writeRights) -ne 0) {
      $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
      if ($sid -cnotin $trusted) { throw 'ACL_CONFIGURATION_FAILED' }
    }
  }
}

function Assert-AgentRoadSafePath {
  param([string]$Path,[bool]$MustExist)
  if (-not (Test-Path -LiteralPath $Path)) { if ($MustExist) { throw 'BOOTSTRAP_STATE_INVALID' }; return }
  $item = Get-Item -LiteralPath $Path -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'BOOTSTRAP_STATE_INVALID' }
}

function Assert-AgentRoadSafeFile {
  param([string]$Path,[bool]$RequireRestrictedAcl)
  Assert-AgentRoadSafePath $Path $true
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'BOOTSTRAP_STATE_INVALID' }
  $links = Invoke-AgentRoadNative "$env:SystemRoot\System32\fsutil.exe" @('hardlink','list',$Path) 30
  if ($links.ExitCode -ne 0 -or @(($links.Stdout -split '\r?\n') | Where-Object { $_.Trim().Length -gt 0 }).Count -ne 1) { throw 'BOOTSTRAP_STATE_INVALID' }
  if ($RequireRestrictedAcl) { Assert-AgentRoadRestrictedAcl $Path }
}

function Enter-AgentRoadBootstrapLock {
  Assert-AgentRoadSafePath 'C:\ProgramData' $true
  Assert-AgentRoadSafePath 'C:\ProgramData\AgentRoad' $false
  [IO.Directory]::CreateDirectory('C:\ProgramData\AgentRoad') | Out-Null
  Assert-AgentRoadSafePath 'C:\ProgramData\AgentRoad' $true
  Set-AgentRoadRestrictedAcl 'C:\ProgramData\AgentRoad'
  Assert-AgentRoadSafePath $script:BootstrapRoot $false
  [IO.Directory]::CreateDirectory($script:BootstrapRoot) | Out-Null
  Assert-AgentRoadSafePath $script:BootstrapRoot $true
  Set-AgentRoadRestrictedAcl $script:BootstrapRoot
  if (-not (Test-Path -LiteralPath $script:LockPath)) {
    try { $seed = [IO.File]::Open($script:LockPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None); $seed.Dispose(); Set-AgentRoadRestrictedAcl $script:LockPath } catch { throw 'BOOTSTRAP_ALREADY_RUNNING' }
  }
  Assert-AgentRoadSafeFile $script:LockPath $true
  try { $lock = [IO.File]::Open($script:LockPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None) } catch { throw 'BOOTSTRAP_ALREADY_RUNNING' }
  if ($lock.Length -ne 0) { $lock.Dispose(); throw 'BOOTSTRAP_STATE_INVALID' }
  return $lock
}

function New-AgentRoadJournal {
  [pscustomobject]@{
    schemaVersion = 1
    status = 'running'
    checkpoints = @()
    changes = @()
    facts = $null
    validations = @()
    failureCode = $null
    rollbackStatus = 'not-attempted'
    updatedAt = [DateTime]::UtcNow.ToString('o')
  }
}

function Test-AgentRoadExactKeys {
  param([object]$Value,[string[]]$Keys)
  if ($null -eq $Value -or $Value -isnot [pscustomobject] -or @($Value.PSObject.Properties).Count -ne $Keys.Count) { return $false }
  $names = @($Value.PSObject.Properties.Name)
  foreach ($key in $Keys) { if ($names -cnotcontains $key) { return $false } }
  return $true
}

function Test-AgentRoadStableFailure {
  param([object]$Code)
  return $Code -is [string] -and $Code -cin @('ADMIN_REQUIRED','UNSUPPORTED_WINDOWS_BUILD','CONFIGURATION_INVALID','BOOTSTRAP_ALREADY_RUNNING','BOOTSTRAP_STATE_INVALID','TAILSCALE_LOGIN_REQUIRED','OPENSSH_INSTALL_FAILED','SSHD_CONFIG_INVALID','SSHD_START_FAILED','FIREWALL_CONFIG_FAILED','COMPLETION_REJECTED','COMPLETION_UNCERTAIN','INTERNAL_ERROR')
}

function Get-AgentRoadFileSha256 {
  param([string]$Path)
  $stream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose(); $stream.Dispose() }
}

function Get-AgentRoadAclSha256 {
  param([string]$Path)
  $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes((Get-Acl -LiteralPath $Path).Sddl)
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose(); [Array]::Clear($bytes,0,$bytes.Length) }
}

function Assert-AgentRoadChange {
  param([pscustomobject]$Change)
  if ($null -eq $Change -or $Change -isnot [pscustomobject] -or @($Change.PSObject.Properties.Name) -cnotcontains 'action' -or $Change.action -isnot [string]) { throw 'BOOTSTRAP_STATE_INVALID' }
  $changeKeys = if ($Change.action -ceq 'restoreFile') { @('action','path','backupPath','expectedSha256','expectedAclSha256') } elseif ($Change.action -ceq 'preserveEmptyDirectory') { @('action','path','backupPath','expectedAclSha256') } else { @('action','path','backupPath') }
  if (-not (Test-AgentRoadExactKeys $Change $changeKeys)) { throw 'BOOTSTRAP_STATE_INVALID' }
  if ($Change.action -isnot [string] -or $Change.path -isnot [string] -or $Change.path.Length -gt 260) { throw 'BOOTSTRAP_STATE_INVALID' }
  switch -CaseSensitive ($Change.action) {
    'restoreFile' {
      if ($Change.path -cnotin @('C:\ProgramData\AgentRoad\ssh\authorized_keys','C:\ProgramData\ssh\sshd_config') -or $Change.backupPath -isnot [string] -or $Change.backupPath -cnotmatch '^C:\\ProgramData\\AgentRoad\\bootstrap\\backups\\[a-f0-9]{32}\.bak$') { throw 'BOOTSTRAP_STATE_INVALID' }
      $backupRoot = Join-Path $script:BootstrapRoot 'backups'
      Assert-AgentRoadSafePath $backupRoot $true
      Assert-AgentRoadRestrictedAcl $backupRoot
      Assert-AgentRoadSafeFile $Change.backupPath $true
      $backupItem = Get-Item -LiteralPath $Change.backupPath
      if ($backupItem.Length -lt 0 -or $backupItem.Length -gt 1048576) { throw 'BOOTSTRAP_STATE_INVALID' }
      if ($Change.expectedSha256 -isnot [string] -or $Change.expectedSha256 -cnotmatch '^[a-f0-9]{64}$' -or $Change.expectedAclSha256 -isnot [string] -or $Change.expectedAclSha256 -cnotmatch '^[a-f0-9]{64}$' -or (Get-AgentRoadFileSha256 $Change.backupPath) -cne $Change.expectedSha256) { throw 'BOOTSTRAP_STATE_INVALID' }
    }
    'removeFile' { if ($Change.path -cnotin @('C:\ProgramData\AgentRoad\ssh\authorized_keys','C:\ProgramData\ssh\sshd_config','C:\ProgramData\ssh\ssh_host_rsa_key','C:\ProgramData\ssh\ssh_host_rsa_key.pub','C:\ProgramData\ssh\ssh_host_ecdsa_key','C:\ProgramData\ssh\ssh_host_ecdsa_key.pub','C:\ProgramData\ssh\ssh_host_ed25519_key','C:\ProgramData\ssh\ssh_host_ed25519_key.pub') -or $null -ne $Change.backupPath) { throw 'BOOTSTRAP_STATE_INVALID' } }
    'removeDirectory' { if ($Change.path -cnotin @('C:\ProgramData\AgentRoad\ssh','C:\ProgramData\ssh') -or $null -ne $Change.backupPath) { throw 'BOOTSTRAP_STATE_INVALID' } }
    'preserveEmptyDirectory' { if ($Change.path -cne 'C:\ProgramData\ssh' -or $null -ne $Change.backupPath -or $Change.expectedAclSha256 -isnot [string] -or $Change.expectedAclSha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'BOOTSTRAP_STATE_INVALID' } }
    'removeUser' { if ($Change.path -cne 'AgentRoad' -or $null -ne $Change.backupPath) { throw 'BOOTSTRAP_STATE_INVALID' } }
    'removeAdminMember' { if ($Change.path -cne 'AgentRoad' -or $null -ne $Change.backupPath) { throw 'BOOTSTRAP_STATE_INVALID' } }
    'removeFirewall' { if ($Change.path -cne 'AgentRoad-OpenSSH-Tailscale' -or $null -ne $Change.backupPath) { throw 'BOOTSTRAP_STATE_INVALID' } }
    'restoreFirewallEnabled' { if ($Change.path -cne 'OpenSSH-Server-In-TCP' -or $Change.backupPath -cne 'True') { throw 'BOOTSTRAP_STATE_INVALID' } }
    'removeOpenSshCapability' { if ($Change.path -cne 'OpenSSH.Server~~~~0.0.1.0' -or $Change.backupPath -cne 'NotPresent') { throw 'BOOTSTRAP_STATE_INVALID' } }
    'restoreService' { if ($Change.path -cnotin @('Auto','Manual','Disabled') -or $Change.backupPath -isnot [string] -or $Change.backupPath -cnotin @('Running','Stopped')) { throw 'BOOTSTRAP_STATE_INVALID' } }
    'restoreServiceRecovery' { if ($Change.path -cne 'sshd' -or $Change.backupPath -cne 'unset') { throw 'BOOTSTRAP_STATE_INVALID' } }
    default { throw 'BOOTSTRAP_STATE_INVALID' }
  }
}

function Assert-AgentRoadJournal {
  param([pscustomobject]$Journal)
  $keys = @('schemaVersion','status','checkpoints','changes','facts','validations','failureCode','rollbackStatus','updatedAt')
  if (-not (Test-AgentRoadExactKeys $Journal $keys) -or $Journal.schemaVersion -isnot [int] -or $Journal.schemaVersion -ne 1) { throw 'BOOTSTRAP_STATE_INVALID' }
  if ($Journal.status -isnot [string] -or $Journal.status -cnotin @('running','failed','rolledBack','completion-pending','complete')) { throw 'BOOTSTRAP_STATE_INVALID' }
  if ($Journal.checkpoints -isnot [Array] -or $Journal.checkpoints.Count -gt 5) { throw 'BOOTSTRAP_STATE_INVALID' }
  $allowedCheckpoints = @('preflight','tailscale','openssh','account','firewall')
  for ($index = 0; $index -lt $Journal.checkpoints.Count; $index++) { if ($Journal.checkpoints[$index] -isnot [string] -or $Journal.checkpoints[$index] -cne $allowedCheckpoints[$index]) { throw 'BOOTSTRAP_STATE_INVALID' } }
  if ($Journal.changes -isnot [Array] -or $Journal.changes.Count -gt 32) { throw 'BOOTSTRAP_STATE_INVALID' }
  foreach ($change in $Journal.changes) { Assert-AgentRoadChange $change }
  if ($null -ne $Journal.facts) {
    if (-not (Test-AgentRoadExactKeys $Journal.facts @('version','build','edition','architecture')) -or $Journal.facts.version -isnot [string] -or $Journal.facts.version -cnotmatch '^\d+(?:\.\d+){2,3}$' -or $Journal.facts.version.Length -gt 32 -or $Journal.facts.build -isnot [int] -or $Journal.facts.build -lt 17763 -or $Journal.facts.build -gt 99999 -or $Journal.facts.edition -isnot [string] -or $Journal.facts.edition -cne $Journal.facts.edition.Trim() -or $Journal.facts.edition.Length -lt 1 -or $Journal.facts.edition.Length -gt 64 -or $Journal.facts.edition -match '[\x00-\x1F\x7F]' -or $Journal.facts.architecture -isnot [string] -or $Journal.facts.architecture -cnotmatch '^[A-Za-z0-9_-]{1,16}$') { throw 'BOOTSTRAP_STATE_INVALID' }
  }
  if ($Journal.validations -isnot [Array] -or $Journal.validations.Count -gt 32) { throw 'BOOTSTRAP_STATE_INVALID' }
  $allowedValidations = @('account-entered','authorized-key-entered','ssh-data-entered','host-keys-entered','host-keys-inputs-valid','host-keys-generation-valid','host-key-1-present','host-key-1-safe','host-key-1-sized','host-key-1-acl-granted','host-key-1-owner-set','host-key-1-acl-verified','host-key-1-acl-set','host-key-1-valid','host-key-2-valid','host-key-3-valid','host-key-4-valid','host-key-5-valid','host-key-6-valid','sshd-config-entered','sshd-config-input-valid','sshd-config-candidate-written','sshd-config-candidate-acl-set','sshd-config-syntax-valid','sshd-config-listeners-valid','sshd-config-block-valid','sshd-config-candidate-selected','sshd-config-published','sshd-config-postconditions-valid','sshd-config-valid','rollback-succeeded','rollback-failed')
  if (@($Journal.validations | Select-Object -Unique).Count -ne $Journal.validations.Count) { throw 'BOOTSTRAP_STATE_INVALID' }
  foreach ($validation in $Journal.validations) { if ($validation -isnot [string] -or $allowedValidations -cnotcontains $validation) { throw 'BOOTSTRAP_STATE_INVALID' } }
  if ($null -ne $Journal.failureCode -and -not (Test-AgentRoadStableFailure $Journal.failureCode)) { throw 'BOOTSTRAP_STATE_INVALID' }
  if ($Journal.rollbackStatus -isnot [string] -or $Journal.rollbackStatus -cnotin @('not-attempted','pending','succeeded','failed')) { throw 'BOOTSTRAP_STATE_INVALID' }
  if ($Journal.updatedAt -isnot [string] -or $Journal.updatedAt -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$') { throw 'BOOTSTRAP_STATE_INVALID' }
  try { if ([DateTime]::Parse($Journal.updatedAt).ToUniversalTime().ToString('o') -cne $Journal.updatedAt) { throw 'BOOTSTRAP_STATE_INVALID' } } catch { throw 'BOOTSTRAP_STATE_INVALID' }
  if ($Journal.status -eq 'complete' -and ($Journal.checkpoints.Count -ne 5 -or $null -ne $Journal.failureCode)) { throw 'BOOTSTRAP_STATE_INVALID' }
  if ($Journal.status -cin @('failed','rolledBack') -and -not (Test-AgentRoadStableFailure $Journal.failureCode)) { throw 'BOOTSTRAP_STATE_INVALID' }
  if ($Journal.status -cin @('running','complete') -and ($null -ne $Journal.failureCode -or $Journal.rollbackStatus -cne 'not-attempted')) { throw 'BOOTSTRAP_STATE_INVALID' }
  if ($Journal.status -eq 'completion-pending' -and ($Journal.checkpoints.Count -ne 5 -or $Journal.rollbackStatus -cne 'not-attempted' -or $Journal.failureCode -cnotin @($null,'COMPLETION_UNCERTAIN'))) { throw 'BOOTSTRAP_STATE_INVALID' }
  if ($Journal.status -eq 'failed' -and $Journal.rollbackStatus -cnotin @('pending','failed')) { throw 'BOOTSTRAP_STATE_INVALID' }
  if ($Journal.status -eq 'rolledBack' -and ($Journal.rollbackStatus -cne 'succeeded' -or $Journal.changes.Count -ne 0 -or $Journal.checkpoints.Count -ne 0)) { throw 'BOOTSTRAP_STATE_INVALID' }
}

function Read-AgentRoadJournal {
  if (-not (Test-Path -LiteralPath $script:JournalPath)) { return New-AgentRoadJournal }
  Assert-AgentRoadSafeFile $script:JournalPath $true
  $item = Get-Item -LiteralPath $script:JournalPath
  if ($item.Length -lt 2 -or $item.Length -gt 65536) { throw 'BOOTSTRAP_STATE_INVALID' }
  try {
    $journalText = [IO.File]::ReadAllText($script:JournalPath,(New-Object Text.UTF8Encoding($false,$true)))
    if ([AgentRoad.NativeRunner]::HasDuplicateJsonKeys($journalText)) { throw 'BOOTSTRAP_STATE_INVALID' }
    $journal = $journalText | ConvertFrom-Json
  } catch { throw 'BOOTSTRAP_STATE_INVALID' }
  Assert-AgentRoadJournal $journal
  if ($journal.status -cin @('rolledBack','complete')) { return New-AgentRoadJournal }
  return $journal
}

function Write-AgentRoadJournal {
  param([pscustomobject]$Journal)
  $Journal.updatedAt = [DateTime]::UtcNow.ToString('o')
  Assert-AgentRoadJournal $Journal
  $json = $Journal | ConvertTo-Json -Depth 8 -Compress
  if ($json -match '(?i)completionTicket|password|private.?key|credential|secret') { throw 'BOOTSTRAP_STATE_INVALID' }
  $temp = Join-Path $script:BootstrapRoot ('.journal-' + [Guid]::NewGuid().ToString('N') + '.tmp')
  try {
    [IO.File]::WriteAllText($temp,$json,(New-Object Text.UTF8Encoding($false)))
    Set-AgentRoadRestrictedAcl $temp
    if (Test-Path -LiteralPath $script:JournalPath) {
      Assert-AgentRoadSafeFile $script:JournalPath $true
      $replaceBackup = Join-Path $script:BootstrapRoot ('.journal-backup-' + [Guid]::NewGuid().ToString('N') + '.tmp')
      [IO.File]::Replace($temp,$script:JournalPath,$replaceBackup,$true)
      Remove-Item -LiteralPath $replaceBackup -Force
    } else { Move-Item -LiteralPath $temp -Destination $script:JournalPath -Force }
    Assert-AgentRoadSafeFile $script:JournalPath $true
  } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force } }
}

function Complete-AgentRoadCheckpoint {
  param([string]$Name)
  $allowed = @('preflight','tailscale','openssh','account','firewall')
  if ($script:Journal.checkpoints.Count -ge $allowed.Count -or $Name -cne $allowed[$script:Journal.checkpoints.Count]) { throw 'BOOTSTRAP_STATE_INVALID' }
  $script:Journal.checkpoints = @($script:Journal.checkpoints) + $Name
  Write-AgentRoadJournal $script:Journal
}

function Record-AgentRoadValidation {
  param([string]$Name)
  $allowed = @('account-entered','authorized-key-entered','ssh-data-entered','host-keys-entered','host-keys-inputs-valid','host-keys-generation-valid','host-key-1-present','host-key-1-safe','host-key-1-sized','host-key-1-acl-granted','host-key-1-owner-set','host-key-1-acl-verified','host-key-1-acl-set','host-key-1-valid','host-key-2-valid','host-key-3-valid','host-key-4-valid','host-key-5-valid','host-key-6-valid','sshd-config-entered','sshd-config-input-valid','sshd-config-candidate-written','sshd-config-candidate-acl-set','sshd-config-syntax-valid','sshd-config-listeners-valid','sshd-config-block-valid','sshd-config-candidate-selected','sshd-config-published','sshd-config-postconditions-valid')
  if ($Name -cnotin $allowed) { throw 'BOOTSTRAP_STATE_INVALID' }
  if (@($script:Journal.validations) -ccontains $Name) { return }
  if ($script:Journal.validations.Count -ge 32) { throw 'BOOTSTRAP_STATE_INVALID' }
  $script:Journal.validations = @($script:Journal.validations) + $Name
  Write-AgentRoadJournal $script:Journal
}

function Add-AgentRoadChange {
  param([pscustomobject]$Change)
  Assert-AgentRoadChange $Change
  if ($script:Journal.changes.Count -ge 32) { throw 'BOOTSTRAP_STATE_INVALID' }
  $script:Journal.changes = @($script:Journal.changes) + $Change
  Write-AgentRoadJournal $script:Journal
}

function Backup-AgentRoadFile {
  param([string]$Path)
  Assert-AgentRoadSafePath $Path $false
  $backupRoot = Join-Path $script:BootstrapRoot 'backups'
  Assert-AgentRoadSafePath $backupRoot $false
  [IO.Directory]::CreateDirectory($backupRoot) | Out-Null
  Assert-AgentRoadSafePath $backupRoot $true
  Set-AgentRoadRestrictedAcl $backupRoot
  if (Test-Path -LiteralPath $Path -PathType Leaf) {
    $backup = Join-Path $backupRoot ([Guid]::NewGuid().ToString('N') + '.bak')
    Assert-AgentRoadSafeFile $Path $false
    if ((Get-Item -LiteralPath $Path).Length -gt 1048576) { throw 'BOOTSTRAP_STATE_INVALID' }
    $expectedSha256 = Get-AgentRoadFileSha256 $Path
    $expectedAclSha256 = Get-AgentRoadAclSha256 $Path
    Copy-Item -LiteralPath $Path -Destination $backup
    Set-AgentRoadRestrictedAcl $backup
    Assert-AgentRoadSafeFile $backup $true
    if ((Get-AgentRoadFileSha256 $backup) -cne $expectedSha256) { throw 'BOOTSTRAP_STATE_INVALID' }
    Add-AgentRoadChange ([pscustomobject]@{ action = 'restoreFile'; path = $Path; backupPath = $backup; expectedSha256 = $expectedSha256; expectedAclSha256 = $expectedAclSha256 })
    return $backup
  }
  if ($null -eq (@($script:Journal.changes) | Where-Object { $_.action -ceq 'removeFile' -and $_.path -ceq $Path } | Select-Object -First 1)) { Add-AgentRoadChange ([pscustomobject]@{ action = 'removeFile'; path = $Path; backupPath = $null }) }
  return $null
}

function New-AgentRoadPassword {
  try {
    Add-Type -AssemblyName System.Web -ErrorAction Stop
    $plain = [System.Web.Security.Membership]::GeneratePassword(32,8) + 'aA1!'
  } catch {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes); $plain = [Convert]::ToBase64String($bytes) + 'aA1!' } finally { $rng.Dispose(); [Array]::Clear($bytes,0,$bytes.Length) }
  }
  try { return ConvertTo-SecureString $plain -AsPlainText -Force } finally { $plain = $null }
}

function Ensure-AgentRoadAccount {
  $user = Get-LocalUser -Name 'AgentRoad' -ErrorAction SilentlyContinue
  $ownedByTransaction = $null -ne (@($script:Journal.changes) | Where-Object { $_.action -ceq 'removeUser' -and $_.path -ceq 'AgentRoad' } | Select-Object -First 1)
  if ($null -ne $user -and -not $ownedByTransaction -and -not $script:SupersedingHealthy) { throw 'ACCOUNT_INVALID' }
  if ($null -eq $user) {
    Add-AgentRoadChange ([pscustomobject]@{ action = 'removeUser'; path = 'AgentRoad'; backupPath = $null })
    $password = New-AgentRoadPassword
    try { New-LocalUser -Name 'AgentRoad' -Password $password -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword | Out-Null } finally { $password = $null }
    $user = Get-LocalUser -Name 'AgentRoad'
  }
  if (-not $user.Enabled -or $user.Name -cne 'AgentRoad' -or ($null -ne $user.PrincipalSource -and [string]$user.PrincipalSource -cne 'Local')) { throw 'ACCOUNT_INVALID' }
  $admins = Get-LocalGroup -SID 'S-1-5-32-544'
  $member = Get-LocalGroupMember -Group $admins -ErrorAction SilentlyContinue | Where-Object { $_.SID -eq $user.SID }
  if ($null -eq $member) {
    Add-AgentRoadChange ([pscustomobject]@{ action = 'removeAdminMember'; path = 'AgentRoad'; backupPath = $null })
    Add-LocalGroupMember -Group $admins -Member $user | Out-Null
  }
}

function Set-AgentRoadFileBytesAtomically {
  param([string]$Path,[byte[]]$Bytes,[object]$PreservedAcl = $null)
  $directory = Split-Path -Parent $Path
  Assert-AgentRoadSafePath $directory $false
  [IO.Directory]::CreateDirectory($directory) | Out-Null
  Assert-AgentRoadSafePath $directory $true
  $candidate = Join-Path $directory ('.agent-road-' + [Guid]::NewGuid().ToString('N') + '.tmp')
  try {
    [IO.File]::WriteAllBytes($candidate,$Bytes)
    if ($null -eq $PreservedAcl) { Set-AgentRoadRestrictedAcl $candidate } else { Set-Acl -LiteralPath $candidate -AclObject $PreservedAcl }
    if (Test-Path -LiteralPath $Path) {
      $replaceBackup = Join-Path $directory ('.replace-' + [Guid]::NewGuid().ToString('N') + '.tmp')
      [IO.File]::Replace($candidate,$Path,$replaceBackup,$true)
      Remove-Item -LiteralPath $replaceBackup -Force
    } else { Move-Item -LiteralPath $candidate -Destination $Path }
    if ($null -eq $PreservedAcl) { Set-AgentRoadRestrictedAcl $Path } else { Set-Acl -LiteralPath $Path -AclObject $PreservedAcl }
  } finally { if (Test-Path -LiteralPath $candidate) { Remove-Item -LiteralPath $candidate -Force } }
}

function Initialize-AgentRoadSshData {
  Assert-AgentRoadSafePath $script:SshDataRoot $false
  if (-not (Test-Path -LiteralPath $script:SshDataRoot)) {
    Add-AgentRoadChange ([pscustomobject]@{ action = 'removeDirectory'; path = $script:SshDataRoot; backupPath = $null })
    [IO.Directory]::CreateDirectory($script:SshDataRoot) | Out-Null
    Set-AgentRoadRestrictedAcl $script:SshDataRoot
  } else {
    if (-not (Test-Path -LiteralPath $script:SshDataRoot -PathType Container)) { throw 'SSHD_CONFIG_INVALID' }
    Assert-AgentRoadSecureSshAcl $script:SshDataRoot
  }
  Assert-AgentRoadSecureSshAcl $script:SshDataRoot
  if (Test-Path -LiteralPath $script:SshdConfigPath) {
    Assert-AgentRoadSafeFile $script:SshdConfigPath $false
    Assert-AgentRoadSecureSshAcl $script:SshdConfigPath
    if ((Get-Item -LiteralPath $script:SshdConfigPath).Length -gt 1048576) { throw 'SSHD_CONFIG_INVALID' }
    return
  }
  $defaultConfig = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd_config_default'
  if (-not (Test-Path -LiteralPath $defaultConfig -PathType Leaf)) { throw 'SSHD_CONFIG_INVALID' }
  Assert-AgentRoadNoUnprivilegedWrite $defaultConfig
  if ((Get-Item -LiteralPath $defaultConfig).Length -lt 1 -or (Get-Item -LiteralPath $defaultConfig).Length -gt 1048576) { throw 'SSHD_CONFIG_INVALID' }
  $defaultBytes = [IO.File]::ReadAllBytes($defaultConfig)
  Backup-AgentRoadFile $script:SshdConfigPath | Out-Null
  Set-AgentRoadFileBytesAtomically $script:SshdConfigPath $defaultBytes
  Assert-AgentRoadSafeFile $script:SshdConfigPath $true
  Assert-AgentRoadSecureSshAcl $script:SshdConfigPath
  $script:ConfigChanged = $true
}

function Ensure-AgentRoadHostKeys {
  $keygen = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
  if (-not (Test-Path -LiteralPath $keygen -PathType Leaf)) { throw 'OPENSSH_INSTALL_FAILED' }
  Assert-AgentRoadSafePath $keygen $true
  $hostKeyPaths = @(
    'C:\ProgramData\ssh\ssh_host_rsa_key','C:\ProgramData\ssh\ssh_host_rsa_key.pub',
    'C:\ProgramData\ssh\ssh_host_ecdsa_key','C:\ProgramData\ssh\ssh_host_ecdsa_key.pub',
    'C:\ProgramData\ssh\ssh_host_ed25519_key','C:\ProgramData\ssh\ssh_host_ed25519_key.pub'
  )
  $missing = @($hostKeyPaths | Where-Object { -not (Test-Path -LiteralPath $_) })
  foreach ($path in $hostKeyPaths) {
    if (Test-Path -LiteralPath $path) {
      Assert-AgentRoadSafeFile $path $false
      Assert-AgentRoadSecureSshAcl $path
    }
  }
  foreach ($path in $missing) {
    if ($null -eq (@($script:Journal.changes) | Where-Object { $_.action -ceq 'removeFile' -and $_.path -ceq $path } | Select-Object -First 1)) { Add-AgentRoadChange ([pscustomobject]@{ action = 'removeFile'; path = $path; backupPath = $null }) }
  }
  Record-AgentRoadValidation 'host-keys-inputs-valid'
  if ($missing.Count -gt 0) {
    $generated = Invoke-AgentRoadNative $keygen @('-A') 60
    if ($generated.ExitCode -ne 0) { throw 'SSHD_START_FAILED' }
  }
  Record-AgentRoadValidation 'host-keys-generation-valid'
  $hostKeyValidationNames = @('host-key-1-valid','host-key-2-valid','host-key-3-valid','host-key-4-valid','host-key-5-valid','host-key-6-valid')
  for ($index = 0; $index -lt $hostKeyPaths.Count; $index++) {
    $path = $hostKeyPaths[$index]
    if ($index -eq 0 -and (Test-Path -LiteralPath $path -PathType Leaf)) { Record-AgentRoadValidation 'host-key-1-present' }
    Assert-AgentRoadSafeFile $path $false
    if ($index -eq 0) { Record-AgentRoadValidation 'host-key-1-safe' }
    if ((Get-Item -LiteralPath $path).Length -lt 1 -or (Get-Item -LiteralPath $path).Length -gt 16384) { throw 'SSHD_START_FAILED' }
    if ($index -eq 0) { Record-AgentRoadValidation 'host-key-1-sized' }
    if ($missing -ccontains $path) {
      if ($index -eq 0) { Set-AgentRoadRestrictedAcl $path 'host-key-1' } else { Set-AgentRoadRestrictedAcl $path }
    }
    if ($index -eq 0) { Record-AgentRoadValidation 'host-key-1-acl-set' }
    Assert-AgentRoadSecureSshAcl $path
    Record-AgentRoadValidation $hostKeyValidationNames[$index]
  }
}

function Ensure-AgentRoadAuthorizedKey {
  Assert-AgentRoadSafePath 'C:\ProgramData\AgentRoad' $true
  Assert-AgentRoadSafePath $script:SshRoot $false
  if (-not (Test-Path -LiteralPath $script:SshRoot)) { Add-AgentRoadChange ([pscustomobject]@{ action = 'removeDirectory'; path = $script:SshRoot; backupPath = $null }) }
  [IO.Directory]::CreateDirectory($script:SshRoot) | Out-Null
  Assert-AgentRoadSafePath $script:SshRoot $true
  Set-AgentRoadRestrictedAcl $script:SshRoot
  Assert-AgentRoadSafePath $script:AuthorizedKeyPath $false
  $desired = $Configuration.sshPublicKey.Trim() + "`r`n"
  if (Test-Path -LiteralPath $script:AuthorizedKeyPath) {
    Assert-AgentRoadSafeFile $script:AuthorizedKeyPath $true
    if ((Get-Item -LiteralPath $script:AuthorizedKeyPath).Length -gt 2048) { throw 'SSHD_CONFIG_INVALID' }
    if ([IO.File]::ReadAllText($script:AuthorizedKeyPath) -ceq $desired) { return }
  }
  Backup-AgentRoadFile $script:AuthorizedKeyPath | Out-Null
  Set-AgentRoadFileBytesAtomically $script:AuthorizedKeyPath ((New-Object Text.UTF8Encoding($false)).GetBytes($desired))
}

function Ensure-AgentRoadOpenSshCapability {
  $script:CapabilityInstalledByAgentRoad = $null -ne (@($script:Journal.changes) | Where-Object { $_.action -ceq 'removeOpenSshCapability' } | Select-Object -First 1)
  $capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
  if ($capability.State -ne 'Installed') {
    if ([string]$capability.State -cne 'NotPresent') { throw 'OPENSSH_INSTALL_FAILED' }
    if (Test-Path -LiteralPath $script:SshDataRoot) {
      Assert-AgentRoadEmptySshDataRoot
      if ($null -eq (@($script:Journal.changes) | Where-Object { $_.action -ceq 'preserveEmptyDirectory' } | Select-Object -First 1)) {
        Add-AgentRoadChange ([pscustomobject]@{ action = 'preserveEmptyDirectory'; path = $script:SshDataRoot; backupPath = $null; expectedAclSha256 = Get-AgentRoadAclSha256 $script:SshDataRoot })
      }
    }
    if (@(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue).Count -ne 0) { throw 'FIREWALL_CONFIG_FAILED' }
    Add-AgentRoadChange ([pscustomobject]@{ action = 'removeOpenSshCapability'; path = 'OpenSSH.Server~~~~0.0.1.0'; backupPath = 'NotPresent' })
    try { Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null } catch { throw 'OPENSSH_INSTALL_FAILED' }
    $script:CapabilityInstalledByAgentRoad = $true
  }
  if ($script:CapabilityInstalledByAgentRoad) {
    $broadRules = @(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)
    if ($broadRules.Count -gt 1) { throw 'FIREWALL_CONFIG_FAILED' }
    if ($broadRules.Count -eq 1 -and [string]$broadRules[0].Enabled -ceq 'True') {
      Disable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction Stop | Out-Null
    }
    if ($broadRules.Count -eq 1 -and [string](Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction Stop).Enabled -cne 'False') { throw 'FIREWALL_CONFIG_FAILED' }
  }
  $sshd = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
  if (-not (Test-Path -LiteralPath $sshd -PathType Leaf)) { throw 'OPENSSH_INSTALL_FAILED' }
}

function Test-AgentRoadConfiguredListenAddresses {
  param([string]$ConfigPath)
  try {
    if ($script:TailscaleAddresses.Count -lt 1 -or $script:TailscaleAddresses.Count -gt 8) { return $false }
    $configured = @(
      [IO.File]::ReadAllLines($ConfigPath) |
        ForEach-Object { if ($_ -match '^[ \t]*ListenAddress[ \t]+([^ \t#]+)[ \t]*(?:#.*)?$') { $Matches[1] } } |
        Sort-Object -Unique
    )
    $expected = @($script:TailscaleAddresses | Sort-Object -Unique)
    if ($configured.Count -ne $expected.Count) { return $false }
    for ($index = 0; $index -lt $expected.Count; $index++) { if ([string]$configured[$index] -cne [string]$expected[$index]) { return $false } }
    return $true
  } catch { return $false }
}

function Test-AgentRoadSshPolicyCompatibility {
  param([string]$ConfigPath = 'C:\ProgramData\ssh\sshd_config',[bool]$RecordDiagnostics = $false)
  try {
    $sshd = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
    $syntax = Invoke-AgentRoadNative $sshd @('-t','-f',$ConfigPath) 30
    if ($syntax.ExitCode -ne 0) { return $false }
    if ($RecordDiagnostics) { Record-AgentRoadValidation 'sshd-config-syntax-valid' }
    if (-not (Test-AgentRoadConfiguredListenAddresses $ConfigPath)) { return $false }
    if ($RecordDiagnostics) { Record-AgentRoadValidation 'sshd-config-listeners-valid' }

    # Win32-OpenSSH cannot reliably evaluate another local account's Match
    # Group token from an interactive administrator process. Validate the exact
    # Agent Road-owned block here; SYSTEM service startup and the pinned Mac SSH
    # probe are the authoritative runtime policy checks.
    $configText = [IO.File]::ReadAllText($ConfigPath)
    $ownedBlocks = [Text.RegularExpressions.Regex]::Matches($configText,'(?ms)^# BEGIN AGENT ROAD\r?\n.*?^# END AGENT ROAD[ \t]*\r?$')
    if ($ownedBlocks.Count -ne 1) { return $false }
    $ownedBlock = $ownedBlocks[0]
    if ($configText.Substring(0,$ownedBlock.Index) -match '(?im)^[ \t]*Match[ \t]+') { return $false }
    $withoutOwnedBlock = $configText.Remove($ownedBlock.Index,$ownedBlock.Length)
    if ($withoutOwnedBlock -match '(?im)^[ \t]*(?:Include|AllowUsers|DenyUsers|AllowGroups|DenyGroups|AuthorizedKeysCommand(?:User)?|TrustedUserCAKeys|AuthorizedPrincipals(?:CommandUser|Command|File))[ \t]+' -or $withoutOwnedBlock -match '(?im)^[ \t]*Match[ \t]+[^\r\n#]*\bUser\b') { return $false }

    $actualLines = @($ownedBlock.Value.TrimEnd("`r") -split '\r?\n')
    $listenLines = @($script:TailscaleAddresses | Sort-Object -Unique | ForEach-Object { 'ListenAddress ' + $_ })
    foreach ($challengeDirective in @('KbdInteractiveAuthentication no','ChallengeResponseAuthentication no')) {
      $expectedLines = @('# BEGIN AGENT ROAD') + $listenLines + @(
        'Match User agentroad',
        '    AuthorizedKeysFile C:\ProgramData\AgentRoad\ssh\authorized_keys',
        '    PubkeyAuthentication yes',
        '    AuthenticationMethods publickey',
        '    PasswordAuthentication no',
        ('    ' + $challengeDirective),
        '# END AGENT ROAD'
      )
      if ($actualLines.Count -ne $expectedLines.Count) { continue }
      $same = $true
      for ($index = 0; $index -lt $expectedLines.Count; $index++) {
        if ([string]$actualLines[$index] -cne [string]$expectedLines[$index]) { $same = $false; break }
      }
      if ($same) {
        if ($RecordDiagnostics) { Record-AgentRoadValidation 'sshd-config-block-valid' }
        return $true
      }
    }
    return $false
  } catch { return $false }
}

function Ensure-AgentRoadSshdConfiguration {
  $sshd = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
  if (-not (Test-Path -LiteralPath $sshd -PathType Leaf)) { throw 'OPENSSH_INSTALL_FAILED' }
  Assert-AgentRoadSafeFile $script:SshdConfigPath $false
  Assert-AgentRoadSecureSshAcl $script:SshdConfigPath
  if ((Get-Item -LiteralPath $script:SshdConfigPath).Length -gt 1048576) { throw 'SSHD_CONFIG_INVALID' }
  $bytes = [IO.File]::ReadAllBytes($script:SshdConfigPath)
  $encoding = New-Object Text.UTF8Encoding($false,$true)
  try { $text = $encoding.GetString($bytes) } catch { throw 'SSHD_CONFIG_INVALID' }
  $newline = if ($text.Contains("`r`n")) { "`r`n" } else { "`n" }
  if (($text -split '# BEGIN AGENT ROAD').Count -gt 2 -or ($text -split '# END AGENT ROAD').Count -gt 2) { throw 'SSHD_CONFIG_INVALID' }
  $text = [Text.RegularExpressions.Regex]::Replace($text,'(?ms)^[ \t]*# BEGIN AGENT ROAD\r?\n.*?^[ \t]*# END AGENT ROAD(?:\r?\n)?','')
  if ($text -match '(?m)^[ \t]*# (?:BEGIN|END) AGENT ROAD') { throw 'SSHD_CONFIG_INVALID' }
  if ($text -match '(?im)^[ \t]*(?:Include|AllowUsers|DenyUsers|AllowGroups|DenyGroups|AuthorizedKeysCommand(?:User)?|TrustedUserCAKeys|AuthorizedPrincipals(?:CommandUser|Command|File))[ \t]+' -or $text -match '(?im)^[ \t]*Match[ \t]+[^\r\n#]*\bUser\b') { throw 'SSHD_CONFIG_INVALID' }
  $activeListenAddresses = @($text -split '\r?\n' | Where-Object { $_ -match '^[ \t]*ListenAddress[ \t]+' })
  if ($activeListenAddresses.Count -ne 0 -or $script:TailscaleAddresses.Count -lt 1 -or $script:TailscaleAddresses.Count -gt 8) { throw 'SSHD_CONFIG_INVALID' }
  $listenLines = @($script:TailscaleAddresses | Sort-Object -Unique | ForEach-Object { $address = $_; 'ListenAddress ' + $address })
  $firstMatch = [Text.RegularExpressions.Regex]::Match($text,'(?im)^[ \t]*Match[ \t]+')
  Record-AgentRoadValidation 'sshd-config-input-valid'
  $candidatePath = Join-Path $script:SshDataRoot ('.agent-road-sshd-' + [Guid]::NewGuid().ToString('N') + '.tmp')
  $candidateText = $null
  try {
    foreach ($challengeDirective in @('KbdInteractiveAuthentication no','ChallengeResponseAuthentication no')) {
      $blockLines = @('# BEGIN AGENT ROAD') + @($listenLines) + @(
        'Match User agentroad',
        '    AuthorizedKeysFile C:\ProgramData\AgentRoad\ssh\authorized_keys',
        '    PubkeyAuthentication yes',
        '    AuthenticationMethods publickey',
        '    PasswordAuthentication no',
        ('    ' + $challengeDirective),
        '# END AGENT ROAD',''
      )
      $block = $blockLines -join $newline
      $trialText = if ($firstMatch.Success) { $text.Insert($firstMatch.Index,$block) } else { $text.TrimEnd("`r","`n") + $newline + $block }
      [IO.File]::WriteAllText($candidatePath,$trialText,(New-Object Text.UTF8Encoding($false)))
      Record-AgentRoadValidation 'sshd-config-candidate-written'
      Set-AgentRoadRestrictedAcl $candidatePath
      Record-AgentRoadValidation 'sshd-config-candidate-acl-set'
      if (Test-AgentRoadSshPolicyCompatibility $candidatePath $true) { $candidateText = $trialText; break }
    }
    if ($null -eq $candidateText) { throw 'SSHD_CONFIG_INVALID' }
    Record-AgentRoadValidation 'sshd-config-candidate-selected'
    if ([IO.File]::ReadAllText($script:SshdConfigPath) -cne $candidateText) {
      $preservedAcl = Get-Acl -LiteralPath $script:SshdConfigPath
      Backup-AgentRoadFile $script:SshdConfigPath | Out-Null
      Set-AgentRoadFileBytesAtomically $script:SshdConfigPath ((New-Object Text.UTF8Encoding($false)).GetBytes($candidateText)) $preservedAcl
      $script:ConfigChanged = $true
    }
    Record-AgentRoadValidation 'sshd-config-published'
    Assert-AgentRoadSafeFile $script:SshdConfigPath $false
    Assert-AgentRoadSecureSshAcl $script:SshdConfigPath
    if (-not (Test-AgentRoadSshPolicyCompatibility $script:SshdConfigPath)) { throw 'SSHD_CONFIG_INVALID' }
    Record-AgentRoadValidation 'sshd-config-postconditions-valid'
    if (@($script:Journal.validations) -cnotcontains 'sshd-config-valid') { $script:Journal.validations = @($script:Journal.validations) + 'sshd-config-valid' }
    Write-AgentRoadJournal $script:Journal
  } finally { if (Test-Path -LiteralPath $candidatePath) { Remove-Item -LiteralPath $candidatePath -Force } }
}

function Test-AgentRoadSshdServiceDefinition {
  param([object]$Details)
  try {
    if ($null -eq $Details -or [string]$Details.Name -cne 'sshd' -or [string]$Details.StartName -cne 'LocalSystem') { return $false }
    $expectedPath = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
    $actualPath = [Environment]::ExpandEnvironmentVariables([string]$Details.PathName).Trim()
    if ($actualPath.Length -ge 2 -and $actualPath[0] -eq [char]34 -and $actualPath[$actualPath.Length - 1] -eq [char]34) { $actualPath = $actualPath.Substring(1,$actualPath.Length - 2) }
    return $actualPath -ieq $expectedPath
  } catch { return $false }
}

function Get-AgentRoadSshdRecoveryState {
  try {
    $state = [AgentRoad.NativeRunner]::QueryServiceRecovery('sshd')
    if ($null -eq $state -or $null -ne $state.Failure -or $null -eq $state.ActionTypes -or $null -eq $state.Delays) { throw 'SSHD_START_FAILED' }
    return $state
  } catch { throw 'SSHD_START_FAILED' }
}

function Test-AgentRoadSshdRecoveryStateUnset {
  param([object]$State)
  try {
    return $null -ne $State -and [uint32]$State.ResetPeriod -eq 0 -and $State.RebootMessage -is [string] -and [string]::IsNullOrEmpty($State.RebootMessage) -and $State.Command -is [string] -and [string]::IsNullOrEmpty($State.Command) -and @($State.ActionTypes).Count -eq 0 -and @($State.Delays).Count -eq 0 -and -not [bool]$State.FailureActionsOnNonCrashFailures
  } catch { return $false }
}

function Test-AgentRoadSshdRecoveryStateDesired {
  param([object]$State)
  try {
    if ($null -eq $State -or [uint32]$State.ResetPeriod -ne 86400 -or $State.RebootMessage -isnot [string] -or -not [string]::IsNullOrEmpty($State.RebootMessage) -or $State.Command -isnot [string] -or -not [string]::IsNullOrEmpty($State.Command) -or @($State.ActionTypes).Count -ne 3 -or @($State.Delays).Count -ne 3 -or -not [bool]$State.FailureActionsOnNonCrashFailures) { return $false }
    $expectedDelays = @(5000,15000,30000)
    for ($index = 0; $index -lt 3; $index++) { if ([int]$State.ActionTypes[$index] -ne 1 -or [uint32]$State.Delays[$index] -ne $expectedDelays[$index]) { return $false } }
    return $true
  } catch { return $false }
}

function Test-AgentRoadSshdRecoveryUnset {
  try { return Test-AgentRoadSshdRecoveryStateUnset (Get-AgentRoadSshdRecoveryState) } catch { return $false }
}

function Test-AgentRoadSshdRecoveryDesired {
  try { return Test-AgentRoadSshdRecoveryStateDesired (Get-AgentRoadSshdRecoveryState) } catch { return $false }
}

function Ensure-AgentRoadSshdRecovery {
  if (Test-AgentRoadSshdRecoveryDesired) { return }
  if (-not (Test-AgentRoadSshdRecoveryUnset)) { throw 'SSHD_START_FAILED' }
  $capabilityOwned = $script:CapabilityInstalledByAgentRoad -or $null -ne (@($script:Journal.changes) | Where-Object { $_.action -ceq 'removeOpenSshCapability' } | Select-Object -First 1)
  $recordedRecoveryChange = @($script:Journal.changes | Where-Object { $_.action -ceq 'restoreServiceRecovery' } | Select-Object -First 1)
  if (-not $capabilityOwned -and $recordedRecoveryChange.Count -eq 0) { Add-AgentRoadChange ([pscustomobject]@{ action = 'restoreServiceRecovery'; path = 'sshd'; backupPath = 'unset' }) }
  $sc = Join-Path $env:SystemRoot 'System32\sc.exe'
  $failure = Invoke-AgentRoadNative $sc @('failure','sshd','reset=','86400','actions=','restart/5000/restart/15000/restart/30000') 30
  if ($failure.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($failure.Stderr)) { throw 'SSHD_START_FAILED' }
  $flag = Invoke-AgentRoadNative $sc @('failureflag','sshd','1') 30
  if ($flag.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($flag.Stderr) -or -not (Test-AgentRoadSshdRecoveryDesired)) { throw 'SSHD_START_FAILED' }
}

function Clear-AgentRoadSshdRecovery {
  $sc = Join-Path $env:SystemRoot 'System32\sc.exe'
  $failure = Invoke-AgentRoadNative $sc @('failure','sshd','reset=','0','actions=','') 30
  if ($failure.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($failure.Stderr)) { throw 'ROLLBACK_INCOMPLETE' }
  $flag = Invoke-AgentRoadNative $sc @('failureflag','sshd','0') 30
  if ($flag.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($flag.Stderr) -or -not (Test-AgentRoadSshdRecoveryUnset)) { throw 'ROLLBACK_INCOMPLETE' }
}

function Ensure-AgentRoadSshdService {
  $capabilityOwned = $script:CapabilityInstalledByAgentRoad -or $null -ne (@($script:Journal.changes) | Where-Object { $_.action -ceq 'removeOpenSshCapability' } | Select-Object -First 1)
  $configMutationRecorded = $null -ne (@($script:Journal.changes) | Where-Object { $_.path -ceq $script:SshdConfigPath -and $_.action -cin @('restoreFile','removeFile') } | Select-Object -First 1)
  $needsConfigActivation = $script:ConfigChanged -or $configMutationRecorded
  $recordedServiceChange = @($script:Journal.changes | Where-Object { $_.action -ceq 'restoreService' } | Select-Object -First 1)
  $service = Get-Service -Name 'sshd' -ErrorAction Stop
  $prior = Get-CimInstance Win32_Service -Filter "Name='sshd'"
  if (-not (Test-AgentRoadSshdServiceDefinition $prior)) { throw 'SSHD_START_FAILED' }
  if ($prior.StartMode -cne 'Auto' -or $service.Status -ne 'Running' -or $needsConfigActivation) {
    if (-not $capabilityOwned -and $recordedServiceChange.Count -eq 0) { Add-AgentRoadChange ([pscustomobject]@{ action = 'restoreService'; path = [string]$prior.StartMode; backupPath = [string]$service.Status }) }
    Set-Service -Name 'sshd' -StartupType Automatic
    if ($service.Status -eq 'Running' -and $needsConfigActivation) { Restart-Service -Name 'sshd' -Force -ErrorAction Stop }
    elseif ($service.Status -ne 'Running') { Start-Service -Name 'sshd' -ErrorAction Stop }
  }
  $service = Get-Service -Name 'sshd' -ErrorAction Stop
  $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(20))
  if ($service.Status -ne 'Running' -or -not (Test-AgentRoadSshPolicyCompatibility $script:SshdConfigPath) -or -not (Test-AgentRoadListenerPostcondition)) {
    if ((Get-Service -Name 'sshd' -ErrorAction SilentlyContinue).Status -eq 'Running') {
      Stop-Service -Name 'sshd' -Force -ErrorAction Stop
      (Get-Service -Name 'sshd' -ErrorAction Stop).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(20))
    }
    if (-not (Test-AgentRoadPort22Unbound)) { throw 'SSHD_START_FAILED' }
    throw 'SSHD_START_FAILED'
  }
  $script:ConfigChanged = $false
}

function Test-AgentRoadPortExplicitlyIncludes22 {
  param([object]$LocalPort)
  foreach ($entry in @($LocalPort)) {
    $value = [string]$entry
    if ($value -ceq '22') { return $true }
    if ($value -match '^(\d+)-(\d+)$' -and [int]$Matches[1] -le 22 -and [int]$Matches[2] -ge 22) { return $true }
  }
  return $false
}

function Get-AgentRoadExplicitSshAllowRules {
  $matches = @()
  $sshd = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
  foreach ($rule in @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)) {
    if ([string]$rule.Direction -cne 'Inbound' -or [string]$rule.Action -cne 'Allow' -or [string]$rule.Enabled -cne 'True') { continue }
    $applications = @($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
    $services = @($rule | Get-NetFirewallServiceFilter -ErrorAction Stop)
    $explicitProgram = $applications.Count -eq 1 -and [string]$applications[0].Program -ine 'Any' -and [Environment]::ExpandEnvironmentVariables([string]$applications[0].Program) -ieq $sshd
    $explicitService = $services.Count -eq 1 -and [string]$services[0].Service -ine 'Any' -and [string]$services[0].Service -ieq 'sshd'
    $explicitPort = $false
    foreach ($port in @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)) {
      if ([string]$port.Protocol -cin @('TCP','6') -and [string]$port.LocalPort -cne 'Any' -and (Test-AgentRoadPortExplicitlyIncludes22 $port.LocalPort)) { $explicitPort = $true; break }
    }
    if ($explicitProgram -or $explicitService -or $explicitPort) { $matches += $rule }
  }
  return @($matches)
}

function Test-AgentRoadMicrosoftOpenSshRule {
  param([object]$Rule)
  try {
    if ($null -eq $Rule -or [string]$Rule.Name -cne 'OpenSSH-Server-In-TCP' -or [string]$Rule.Direction -cne 'Inbound' -or [string]$Rule.Action -cne 'Allow' -or [string]$Rule.Profile -cnotin @('Any','Private')) { return $false }
    $port = @($Rule | Get-NetFirewallPortFilter -ErrorAction Stop)
    $address = @($Rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
    $application = @($Rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
    $service = @($Rule | Get-NetFirewallServiceFilter -ErrorAction Stop)
    $sshd = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
    $systemRootSshd = '%SystemRoot%\system32\OpenSSH\sshd.exe'
    $program = if ($application.Count -eq 1) { [string]$application[0].Program } else { $null }
    return $port.Count -eq 1 -and [string]$port[0].Protocol -cin @('TCP','6') -and [string]$port[0].LocalPort -ceq '22' -and [string]$port[0].RemotePort -ceq 'Any' -and $address.Count -eq 1 -and [string]$address[0].LocalAddress -ceq 'Any' -and [string]$address[0].RemoteAddress -ceq 'Any' -and $application.Count -eq 1 -and ($program -ceq 'Any' -or $program -ieq $sshd -or $program -ieq $systemRootSshd) -and $service.Count -eq 1 -and [string]$service[0].Service -ceq 'Any'
  } catch { return $false }
}

function Test-AgentRoadPort22Unbound {
  try { return @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalPort -eq 22 }).Count -eq 0 } catch { return $false }
}

function Assert-AgentRoadFirewallPreflight {
  $ownedByName = @(Get-NetFirewallRule -Name $script:FirewallName -ErrorAction SilentlyContinue)
  $ownedByDisplay = @(Get-NetFirewallRule -DisplayName $script:FirewallName -ErrorAction SilentlyContinue)
  $ownedPresent = $ownedByName.Count -gt 0 -or $ownedByDisplay.Count -gt 0
  $ownedRecorded = $null -ne (@($script:Journal.changes) | Where-Object { $_.action -ceq 'removeFirewall' -and $_.path -ceq $script:FirewallName } | Select-Object -First 1)
  if ($ownedPresent -and ($ownedByName.Count -ne 1 -or $ownedByDisplay.Count -ne 1 -or [string]$ownedByDisplay[0].Name -cne $script:FirewallName -or -not (Test-AgentRoadScopedFirewallRule) -or (-not $script:SupersedingHealthy -and -not $ownedRecorded))) { throw 'FIREWALL_CONFIG_FAILED' }
  $microsoft = @(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)
  if ($microsoft.Count -gt 1 -or ($microsoft.Count -eq 1 -and -not (Test-AgentRoadMicrosoftOpenSshRule $microsoft[0]))) { throw 'FIREWALL_CONFIG_FAILED' }
  foreach ($rule in @(Get-AgentRoadExplicitSshAllowRules)) {
    if ([string]$rule.Name -ceq $script:FirewallName -and (Test-AgentRoadScopedFirewallRule)) { continue }
    if ([string]$rule.Name -ceq 'OpenSSH-Server-In-TCP' -and (Test-AgentRoadMicrosoftOpenSshRule $rule)) { continue }
    throw 'FIREWALL_CONFIG_FAILED'
  }
  if ($script:SupersedingHealthy) {
    if ($ownedByName.Count -eq 1 -and (Test-AgentRoadFirewallPostcondition)) { return }
    throw 'FIREWALL_CONFIG_FAILED'
  }
  $freshCapability = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
  $existingService = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
  if ([string]$freshCapability.State -ceq 'NotPresent' -and $null -eq $existingService) { return }
  if ([string]$freshCapability.State -ceq 'Installed' -and $null -ne $existingService -and [string]$existingService.Status -ceq 'Stopped') {
    $serviceDetails = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
    if ([string]$serviceDetails.StartMode -cin @('Manual','Disabled') -and (Test-AgentRoadPort22Unbound)) { return }
  }
  throw 'FIREWALL_CONFIG_FAILED'
}

function Assert-AgentRoadFirewallProfiles {
  $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
  if ($profiles.Count -ne 3) { throw 'FIREWALL_CONFIG_FAILED' }
  foreach ($name in @('Domain','Private','Public')) {
    $matches = @($profiles | Where-Object { [string]$_.Name -ceq $name })
    if ($matches.Count -ne 1) { throw 'FIREWALL_CONFIG_FAILED' }
    $profile = $matches[0]
    if ([string]$profile.Enabled -cne 'True' -or [string]$profile.DefaultInboundAction -cne 'Block' -or [string]$profile.AllowInboundRules -cne 'True' -or [string]$profile.AllowLocalFirewallRules -cne 'True') { throw 'FIREWALL_CONFIG_FAILED' }
    if (@($profile.DisabledInterfaceAliases | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -ne 0) { throw 'FIREWALL_CONFIG_FAILED' }
  }
}

function Test-AgentRoadFirewallPostcondition {
  try {
    Assert-AgentRoadSshTransportIsolation
    if (-not (Test-AgentRoadScopedFirewallRule)) { return $false }
    $microsoft = @(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)
    if ($microsoft.Count -gt 1 -or ($microsoft.Count -eq 1 -and (-not (Test-AgentRoadMicrosoftOpenSshRule $microsoft[0]) -or [string]$microsoft[0].Enabled -cne 'False'))) { return $false }
    $effective = @(Get-AgentRoadExplicitSshAllowRules)
    $owned = @($effective | Where-Object { [string]$_.Name -ceq $script:FirewallName })
    if ($owned.Count -ne 1) { return $false }
    foreach ($rule in $effective) {
      if ([string]$rule.Name -ceq $script:FirewallName) { continue }
      return $false
    }
    return $true
  } catch { return $false }
}

function Test-AgentRoadTailnetRemoteAddresses {
  param([object[]]$Addresses)
  if (@($Addresses).Count -ne 2) { return $false }
  $values = @($Addresses | ForEach-Object { [string]$_ } | Sort-Object -Unique)
  if ($values.Count -ne 2) { return $false }
  $ipv4 = @($values | Where-Object { $_ -cin @('100.64.0.0/10','100.64.0.0/255.192.0.0') })
  $ipv6 = @($values | Where-Object { $_ -ieq 'fd7a:115c:a1e0::/48' })
  return $ipv4.Count -eq 1 -and $ipv6.Count -eq 1
}

function Test-AgentRoadCurrentLocalAddresses {
  param([object[]]$Addresses)
  $actual = @($Addresses | ForEach-Object { [string]$_ } | Sort-Object -Unique)
  $expected = @($script:TailscaleAddresses | ForEach-Object { [string]$_ } | Sort-Object -Unique)
  if ($actual.Count -ne $expected.Count -or $actual.Count -lt 1) { return $false }
  for ($index = 0; $index -lt $expected.Count; $index++) { if ($actual[$index] -cne $expected[$index]) { return $false } }
  return $true
}

function Get-AgentRoadNetNatStaticMappings {
  try {
    return @(Get-NetNatStaticMapping -ErrorAction Stop)
  } catch {
    $missingClass = $_.Exception -is [Microsoft.Management.Infrastructure.CimException] -and [string]$_.FullyQualifiedErrorId -match '(?i)\b0x80041010\b'
    if ($missingClass) { return @() }
    throw
  }
}

function Test-AgentRoadScopedFirewallRule {
  try {
    $byName = @(Get-NetFirewallRule -Name $script:FirewallName -ErrorAction Stop)
    $byDisplay = @(Get-NetFirewallRule -DisplayName $script:FirewallName -ErrorAction Stop)
    if ($byName.Count -ne 1 -or $byDisplay.Count -ne 1 -or [string]$byDisplay[0].Name -cne $script:FirewallName) { return $false }
    $rule = $byName[0]
    $port = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
    $address = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
    $application = @($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
    $service = @($rule | Get-NetFirewallServiceFilter -ErrorAction Stop)
    $interface = @($rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop)
    $sshd = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
    $program = if ($application.Count -eq 1) { [Environment]::ExpandEnvironmentVariables([string]$application[0].Program) } else { $null }
    return [string]$rule.Name -ceq $script:FirewallName -and [string]$rule.DisplayName -ceq $script:FirewallName -and [string]$rule.Direction -ceq 'Inbound' -and [string]$rule.Action -ceq 'Allow' -and [string]$rule.Enabled -ceq 'True' -and [string]$rule.Profile -ceq 'Any' -and [string]$rule.EdgeTraversalPolicy -ceq 'Block' -and $port.Count -eq 1 -and [string]$port[0].Protocol -ceq 'TCP' -and [string]$port[0].LocalPort -ceq '22' -and [string]$port[0].RemotePort -ceq 'Any' -and $address.Count -eq 1 -and (Test-AgentRoadCurrentLocalAddresses @($address[0].LocalAddress)) -and (Test-AgentRoadTailnetRemoteAddresses @($address[0].RemoteAddress)) -and $application.Count -eq 1 -and $program -ieq $sshd -and $service.Count -eq 1 -and [string]$service[0].Service -ieq 'sshd' -and $interface.Count -eq 1 -and [string]$interface[0].InterfaceType -ceq 'Any'
  } catch { return $false }
}

function Ensure-AgentRoadFirewallRule {
  $byDisplay = @(Get-NetFirewallRule -DisplayName $script:FirewallName -ErrorAction SilentlyContinue)
  $byName = @(Get-NetFirewallRule -Name $script:FirewallName -ErrorAction SilentlyContinue)
  if ($byDisplay.Count -gt 0 -or $byName.Count -gt 0) {
    if ($byDisplay.Count -ne 1 -or $byName.Count -ne 1 -or [string]$byDisplay[0].Name -cne $script:FirewallName -or -not (Test-AgentRoadScopedFirewallRule)) { throw 'FIREWALL_CONFIG_FAILED' }
    return
  }
  Add-AgentRoadChange ([pscustomobject]@{ action = 'removeFirewall'; path = $script:FirewallName; backupPath = $null })
  $sshd = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
  New-NetFirewallRule -Name 'AgentRoad-OpenSSH-Tailscale' -DisplayName 'AgentRoad-OpenSSH-Tailscale' -Direction Inbound -Action Allow -Enabled True -Profile Any -Protocol TCP -LocalPort 22 -LocalAddress @($script:TailscaleAddresses) -RemoteAddress @('100.64.0.0/10','fd7a:115c:a1e0::/48') -Program $sshd -Service 'sshd' -EdgeTraversalPolicy Block | Out-Null
  if (-not (Test-AgentRoadScopedFirewallRule)) { throw 'FIREWALL_CONFIG_FAILED' }
}

function Ensure-AgentRoadFirewallBoundary {
  Assert-AgentRoadSshTransportIsolation
  Ensure-AgentRoadFirewallRule
  $rules = @(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)
  if ($rules.Count -gt 1) { throw 'FIREWALL_CONFIG_FAILED' }
  if ($rules.Count -eq 1) {
    if (-not (Test-AgentRoadMicrosoftOpenSshRule $rules[0])) { throw 'FIREWALL_CONFIG_FAILED' }
    if ([string]$rules[0].Enabled -ceq 'True') {
      if (-not $script:CapabilityInstalledByAgentRoad -and $null -eq (@($script:Journal.changes) | Where-Object { $_.action -ceq 'restoreFirewallEnabled' } | Select-Object -First 1)) { Add-AgentRoadChange ([pscustomobject]@{ action = 'restoreFirewallEnabled'; path = 'OpenSSH-Server-In-TCP'; backupPath = 'True' }) }
      Disable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction Stop | Out-Null
    }
  }
  Assert-AgentRoadFirewallProfiles
  if (-not (Test-AgentRoadFirewallPostcondition)) { throw 'FIREWALL_CONFIG_FAILED' }
}

function Get-AgentRoadTailscaleAddresses {
  $tailscale = 'C:\Program Files\Tailscale\tailscale.exe'
  if (-not (Test-Path -LiteralPath $tailscale -PathType Leaf)) { throw 'TAILSCALE_LOGIN_REQUIRED' }
  Assert-AgentRoadSafePath $tailscale $true
  $result = Invoke-AgentRoadNative $tailscale @('ip') 30
  if ($result.ExitCode -ne 0) { throw 'TAILSCALE_LOGIN_REQUIRED' }
  $addresses = @()
  foreach ($line in ($result.Stdout -split '\r?\n')) {
    $parsed = $null
    if ([Net.IPAddress]::TryParse($line.Trim(),[ref]$parsed)) { $addresses += $parsed.ToString() }
  }
  $addresses = @($addresses | Select-Object -Unique | Sort-Object)
  if ($addresses.Count -lt 1 -or $addresses.Count -gt 8) { throw 'TAILSCALE_LOGIN_REQUIRED' }
  return $addresses
}

function Assert-AgentRoadSshTransportIsolation {
  if ($script:TailscaleAddresses.Count -lt 1 -or $script:TailscaleAddresses.Count -gt 8) { throw 'FIREWALL_CONFIG_FAILED' }
  $tailscaleInterfaceIndexes = @()
  foreach ($address in $script:TailscaleAddresses) {
    $matches = @(Get-NetIPAddress -IPAddress $address -ErrorAction Stop)
    if ($matches.Count -ne 1) { throw 'FIREWALL_CONFIG_FAILED' }
    $tailscaleInterfaceIndexes += [uint32]$matches[0].InterfaceIndex
  }
  $tailscaleInterfaceIndexes = @($tailscaleInterfaceIndexes | Sort-Object -Unique)
  if ($tailscaleInterfaceIndexes.Count -lt 1 -or $tailscaleInterfaceIndexes.Count -gt 4) { throw 'FIREWALL_CONFIG_FAILED' }
  foreach ($interface in @(Get-NetIPInterface -ErrorAction Stop)) {
    if ([uint32]$interface.InterfaceIndex -in $tailscaleInterfaceIndexes) { continue }
    if ([string]$interface.WeakHostReceive -ceq 'Enabled' -or [string]$interface.Forwarding -ceq 'Enabled') { throw 'FIREWALL_CONFIG_FAILED' }
  }

  $portProxyRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy'
  if (Test-Path -LiteralPath $portProxyRoot) {
    foreach ($key in @(Get-ChildItem -LiteralPath $portProxyRoot -Recurse -ErrorAction Stop)) {
      foreach ($property in @($key.Property)) {
        $target = [string](Get-ItemPropertyValue -LiteralPath $key.PSPath -Name $property -ErrorAction Stop)
        if ([string]$property -match '(?:^|/)22$' -or $target -match '(?:^|/)22$') { throw 'FIREWALL_CONFIG_FAILED' }
      }
    }
  }

  if ($null -ne (Get-Command Get-NetNatStaticMapping -ErrorAction SilentlyContinue)) {
    foreach ($mapping in @(Get-AgentRoadNetNatStaticMappings)) {
      if ([string]$mapping.Protocol -cin @('TCP','6') -and ([uint16]$mapping.ExternalPort -eq 22 -or [uint16]$mapping.InternalPort -eq 22)) { throw 'FIREWALL_CONFIG_FAILED' }
    }
  }
}

function Test-AgentRoadTailscalePostcondition {
  try { return @(Get-AgentRoadTailscaleAddresses).Count -ge 1 } catch { return $false }
}

function Test-AgentRoadOpenSshPostcondition {
  try {
    $capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
    $sshd = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
    if ($capability.State -ne 'Installed' -or -not (Test-Path -LiteralPath $sshd -PathType Leaf)) { return $false }
    Assert-AgentRoadSafePath $sshd $true
    return $true
  } catch { return $false }
}

function Test-AgentRoadAccountPostcondition {
  try {
    $user = Get-LocalUser -Name 'AgentRoad' -ErrorAction Stop
    if (-not $user.Enabled -or ($null -ne $user.PrincipalSource -and [string]$user.PrincipalSource -cne 'Local')) { return $false }
    $admins = Get-LocalGroup -SID 'S-1-5-32-544'
    if ($null -eq (Get-LocalGroupMember -Group $admins -ErrorAction Stop | Where-Object { $_.SID -eq $user.SID })) { return $false }
    Assert-AgentRoadSafeFile $script:AuthorizedKeyPath $true
    if ((Get-Item -LiteralPath $script:AuthorizedKeyPath).Length -gt 2048) { return $false }
    $desired = $Configuration.sshPublicKey.Trim() + "`r`n"
    if ([IO.File]::ReadAllText($script:AuthorizedKeyPath) -cne $desired) { return $false }
    Assert-AgentRoadSafeFile $script:SshdConfigPath $false
    Assert-AgentRoadSecureSshAcl $script:SshdConfigPath
    if ((Get-Item -LiteralPath $script:SshdConfigPath).Length -gt 1048576) { return $false }
    $configText = [IO.File]::ReadAllText($script:SshdConfigPath)
    if (($configText -split '# BEGIN AGENT ROAD').Count -ne 2 -or ($configText -split '# END AGENT ROAD').Count -ne 2) { return $false }
    return Test-AgentRoadSshPolicyCompatibility $script:SshdConfigPath
  } catch { return $false }
}

function Test-AgentRoadServicePostcondition {
  try {
    $service = Get-Service -Name 'sshd' -ErrorAction Stop
    $details = Get-CimInstance Win32_Service -Filter "Name='sshd'"
    return $service.Status -eq 'Running' -and $details.StartMode -eq 'Auto' -and (Test-AgentRoadSshdServiceDefinition $details) -and (Test-AgentRoadSshdRecoveryDesired) -and (Test-AgentRoadListenerPostcondition)
  } catch { return $false }
}

function Test-AgentRoadListenerPostcondition {
  try {
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction Stop)
    $details = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
    if (-not (Test-AgentRoadSshdServiceDefinition $details) -or [uint32]$details.ProcessId -eq 0) { return $false }
    foreach ($listener in $listeners) { if ([uint32]$listener.OwningProcess -ne [uint32]$details.ProcessId) { return $false } }
    $actual = @($listeners.LocalAddress | Select-Object -Unique | Sort-Object)
    $expected = @($script:TailscaleAddresses | Select-Object -Unique | Sort-Object)
    if ($actual.Count -ne $expected.Count -or $actual.Count -lt 1) { return $false }
    for ($index = 0; $index -lt $expected.Count; $index++) { if ([string]$actual[$index] -cne [string]$expected[$index]) { return $false } }
    return $true
  } catch { return $false }
}

function Test-AgentRoadCheckpointPostcondition {
  param([string]$Name,[pscustomobject]$Facts)
  switch ($Name) {
    'preflight' { return $null -ne $script:Journal.facts -and $script:Journal.facts.version -ceq $Facts.version -and $script:Journal.facts.build -eq $Facts.build -and $script:Journal.facts.edition -ceq $Facts.edition -and $script:Journal.facts.architecture -ceq $Facts.architecture }
    'tailscale' { return Test-AgentRoadTailscalePostcondition }
    'openssh' { return Test-AgentRoadOpenSshPostcondition }
    'account' { return (Test-AgentRoadOpenSshPostcondition) -and (Test-AgentRoadAccountPostcondition) }
    'firewall' { return (Test-AgentRoadServicePostcondition) -and (Test-AgentRoadFirewallPostcondition) }
    default { return $false }
  }
}

function Reset-AgentRoadTransaction {
  param([pscustomobject]$Facts)
  $script:Journal = New-AgentRoadJournal
  $script:Journal.facts = $Facts
  Write-AgentRoadJournal $script:Journal
}

function Test-AgentRoadPriorAuthorizedKey {
  param([string]$Text)
  if ($Text -cnotmatch '^ssh-ed25519 ([A-Za-z0-9+/]+={0,2}) agent-road:(dev_[a-z0-9]+)\r?\n$') { return $false }
  try { $blob = [Convert]::FromBase64String($Matches[1]) } catch { return $false }
  if ([Convert]::ToBase64String($blob) -cne $Matches[1] -or $blob.Length -ne 51) { return $false }
  $algorithmLength = [Net.IPAddress]::NetworkToHostOrder([BitConverter]::ToInt32($blob,0))
  $keyLength = [Net.IPAddress]::NetworkToHostOrder([BitConverter]::ToInt32($blob,15))
  return $algorithmLength -eq 11 -and [Text.Encoding]::ASCII.GetString($blob,4,11) -ceq 'ssh-ed25519' -and $keyLength -eq 32
}

function Test-AgentRoadSupersessionBaseline {
  try {
    Assert-AgentRoadJournal $script:Journal
    if ($script:TailscaleAddresses.Count -eq 0) { $script:TailscaleAddresses = @(Get-AgentRoadTailscaleAddresses) }
    if ($script:Journal.status -cne 'completion-pending' -or $script:Journal.failureCode -cne 'COMPLETION_UNCERTAIN' -or $script:Journal.checkpoints.Count -ne 5) { return $false }
    $user = Get-LocalUser -Name 'AgentRoad' -ErrorAction Stop
    if (-not $user.Enabled -or $user.Name -cne 'AgentRoad' -or ($null -ne $user.PrincipalSource -and [string]$user.PrincipalSource -cne 'Local')) { return $false }
    $admins = Get-LocalGroup -SID 'S-1-5-32-544'
    if ($null -eq (Get-LocalGroupMember -Group $admins -ErrorAction Stop | Where-Object { $_.SID -eq $user.SID })) { return $false }
    Assert-AgentRoadSafeFile $script:AuthorizedKeyPath $true
    if ((Get-Item -LiteralPath $script:AuthorizedKeyPath).Length -gt 2048 -or -not (Test-AgentRoadPriorAuthorizedKey ([IO.File]::ReadAllText($script:AuthorizedKeyPath)))) { return $false }
    Assert-AgentRoadSafeFile $script:SshdConfigPath $false
    Assert-AgentRoadSecureSshAcl $script:SshdConfigPath
    if (-not (Test-AgentRoadOpenSshPostcondition) -or -not (Test-AgentRoadSshPolicyCompatibility $script:SshdConfigPath) -or -not (Test-AgentRoadServicePostcondition) -or -not (Test-AgentRoadFirewallPostcondition) -or -not (Test-AgentRoadTailscalePostcondition)) { return $false }
    Assert-AgentRoadFirewallProfiles
    $hostKeys = Get-AgentRoadHostKeys
    return $hostKeys.keys.Count -ge 1 -and $hostKeys.fingerprints.Count -eq $hostKeys.keys.Count
  } catch { return $false }
}

function Reset-AgentRoadSupersedingTransaction {
  param([pscustomobject]$Facts)
  if (-not (Test-AgentRoadSupersessionBaseline)) { throw 'COMPLETION_UNCERTAIN' }
  $script:SupersedingHealthy = $true
  $oldChanges = @($script:Journal.changes)
  $oldBackups = @($oldChanges | Where-Object { $_.action -ceq 'restoreFile' } | Select-Object -ExpandProperty backupPath -Unique)
  if ($oldBackups.Count -gt 32) { throw 'COMPLETION_UNCERTAIN' }
  $backupRoot = Join-Path $script:BootstrapRoot 'backups'
  $backupItems = @()
  if (Test-Path -LiteralPath $backupRoot) {
    Assert-AgentRoadSafePath $backupRoot $true
    Assert-AgentRoadRestrictedAcl $backupRoot
    $backupItems = @(Get-ChildItem -LiteralPath $backupRoot -Force -ErrorAction Stop)
    if ($backupItems.Count -gt 64) { throw 'COMPLETION_UNCERTAIN' }
    foreach ($item in $backupItems) {
      Assert-AgentRoadSafeFile $item.FullName $true
      if ([string]$item.Name -cnotmatch '^[a-f0-9]{32}\.bak$') { throw 'COMPLETION_UNCERTAIN' }
    }
  }
  foreach ($path in $oldBackups) { if (@($backupItems | Where-Object { $_.FullName -ceq $path }).Count -ne 1) { throw 'COMPLETION_UNCERTAIN' } }
  $script:Journal = New-AgentRoadJournal
  $script:Journal.facts = $Facts
  Write-AgentRoadJournal $script:Journal
  foreach ($item in $backupItems) { Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop }
  if (Test-Path -LiteralPath $backupRoot) {
    if (@(Get-ChildItem -LiteralPath $backupRoot -Force -ErrorAction Stop).Count -ne 0) { throw 'COMPLETION_UNCERTAIN' }
    [IO.Directory]::Delete($backupRoot,$false)
  }
}

function Get-AgentRoadHostKeys {
  $keygen = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
  Assert-AgentRoadSafePath 'C:\ProgramData\ssh' $true
  $keys = @()
  $fingerprints = @()
  foreach ($path in @(Get-ChildItem -LiteralPath 'C:\ProgramData\ssh' -Filter 'ssh_host_*_key.pub' -File | Sort-Object Name | Select-Object -ExpandProperty FullName)) {
    Assert-AgentRoadSafeFile $path $false
    Assert-AgentRoadSecureSshAcl $path
    if ((Get-Item -LiteralPath $path).Length -gt 2048) { throw 'SSHD_START_FAILED' }
    $line = ([IO.File]::ReadAllText($path)).Trim()
    if ($line -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n]+)?$') { continue }
    $result = Invoke-AgentRoadNative $keygen @('-lf',$path,'-E','sha256') 30
    if ($result.ExitCode -ne 0 -or $result.Stdout -notmatch '(?:^|\s)(SHA256:[A-Za-z0-9+/]{43})(?:\s|$)') { throw 'SSHD_START_FAILED' }
    $keys += $line
    $fingerprints += $Matches[1]
  }
  if ($keys.Count -lt 1 -or $keys.Count -gt 8) { throw 'SSHD_START_FAILED' }
  [pscustomobject]@{ keys = $keys; fingerprints = $fingerprints }
}

function Get-AgentRoadCompletionHttpStatus {
  param([object]$ErrorRecord)
  if ($null -eq $ErrorRecord -or $null -eq $ErrorRecord.Exception -or $ErrorRecord.Exception -isnot [Net.WebException]) { return $null }
  $webResponse = $ErrorRecord.Exception.Response
  if ($null -eq $webResponse) { return $null }
  try {
    if ($webResponse -isnot [Net.HttpWebResponse]) { return $null }
    return [int]$webResponse.StatusCode
  } finally { try { $webResponse.Close() } catch {} }
}

function Compare-AgentRoadBytes {
  param([byte[]]$Left,[byte[]]$Right)
  if ($null -eq $Left -or $null -eq $Right -or $Left.Length -ne $Right.Length) { return $false }
  for ($index = 0; $index -lt $Left.Length; $index++) { if ($Left[$index] -ne $Right[$index]) { return $false } }
  return $true
}

function Invoke-AgentRoadCompletionRequest {
  param([string]$Uri,[byte[]]$BodyBytes,[byte[]]$ExpectedAckBytes)
  $request = $null
  $requestStream = $null
  $response = $null
  $responseStream = $null
  try {
    $request = [Net.HttpWebRequest][Net.WebRequest]::Create($Uri)
    $request.Method = 'POST'
    $request.ContentType = 'application/json'
    $request.Accept = 'application/json'
    $request.AllowAutoRedirect = $false
    $request.Timeout = 30000
    $request.ReadWriteTimeout = 30000
    $request.ContentLength = $BodyBytes.Length
    $requestStream = $request.GetRequestStream()
    $requestStream.Write($BodyBytes,0,$BodyBytes.Length)
    $requestStream.Close()
    $requestStream = $null
    try { $response = [Net.HttpWebResponse]$request.GetResponse() } catch {
      return [pscustomobject]@{ StatusCode = Get-AgentRoadCompletionHttpStatus $_; AckValid = $false }
    }
    $statusCode = [int]$response.StatusCode
    if ($statusCode -ne 200) { return [pscustomobject]@{ StatusCode = $statusCode; AckValid = $false } }
    if ([string]$response.ContentType -cne 'application/json' -or $response.ContentLength -lt -1 -or $response.ContentLength -gt 1024 -or ($response.ContentLength -ge 0 -and $response.ContentLength -ne $ExpectedAckBytes.Length)) { return [pscustomobject]@{ StatusCode = 200; AckValid = $false } }
    $responseStream = $response.GetResponseStream()
    if (-not $responseStream.CanTimeout) { throw 'COMPLETION_TRANSPORT_UNBOUNDED' }
    $buffer = New-Object byte[] 1025
    $total = 0
    $readTimer = [Diagnostics.Stopwatch]::StartNew()
    while ($total -lt $buffer.Length) {
      $remainingMilliseconds = 30000 - [int]$readTimer.ElapsedMilliseconds
      if ($remainingMilliseconds -le 0) { throw 'COMPLETION_TRANSPORT_TIMEOUT' }
      $responseStream.ReadTimeout = $remainingMilliseconds
      $read = $responseStream.Read($buffer,$total,$buffer.Length - $total)
      if ($read -eq 0) { break }
      $total += $read
      if ($total -gt $ExpectedAckBytes.Length) { return [pscustomobject]@{ StatusCode = 200; AckValid = $false } }
    }
    if ($total -gt 1024 -or ($response.ContentLength -ge 0 -and $total -ne $response.ContentLength)) { return [pscustomobject]@{ StatusCode = 200; AckValid = $false } }
    $actual = New-Object byte[] $total
    [Array]::Copy($buffer,$actual,$total)
    $strictUtf8 = New-Object Text.UTF8Encoding($false,$true)
    try { $null = $strictUtf8.GetString($actual) } catch { return [pscustomobject]@{ StatusCode = 200; AckValid = $false } }
    return [pscustomobject]@{ StatusCode = 200; AckValid = (Compare-AgentRoadBytes $actual $ExpectedAckBytes) }
  } catch {
    return [pscustomobject]@{ StatusCode = $null; AckValid = $false }
  } finally {
    if ($null -ne $responseStream) { try { $responseStream.Close() } catch {} }
    if ($null -ne $response) { try { $response.Close() } catch {} }
    if ($null -ne $requestStream) { try { $requestStream.Close() } catch {} }
    if ($null -ne $request) { try { $request.Abort() } catch {} }
  }
}

function Send-AgentRoadCompletion {
  param([pscustomobject]$Facts,[pscustomobject]$HostKeys)
  if ($Facts.version.Length -lt 1 -or $Facts.version.Length -gt 32 -or $Facts.edition.Length -lt 1 -or $Facts.edition.Length -gt 64 -or $Facts.architecture.Length -lt 1 -or $Facts.architecture.Length -gt 16) { throw 'SSHD_START_FAILED' }
  $addresses = @($script:TailscaleAddresses | Select-Object -Unique | Sort-Object)
  if ($addresses.Count -lt 1 -or $addresses.Count -gt 8) { throw 'SSHD_START_FAILED' }
  $bodyObject = [ordered]@{
    protocolVersion = 1
    deviceId = $Configuration.deviceId
    completionTicket = $Configuration.completionTicket
    target = $Facts
    tailscaleAddresses = $addresses
    sshHostKeys = @($HostKeys.keys)
    sshHostKeyFingerprints = @($HostKeys.fingerprints)
    checkpoints = @('preflight','tailscale','openssh','account','firewall')
  }
  $body = $bodyObject | ConvertTo-Json -Depth 5 -Compress
  $utf8 = New-Object Text.UTF8Encoding($false,$true)
  $bodyBytes = $utf8.GetBytes($body)
  $expectedAck = '{"protocolVersion":1,"deviceId":"' + $Configuration.deviceId + '","accepted":true}'
  $expectedAckBytes = $utf8.GetBytes($expectedAck)
  try {
    $script:Journal.status = 'completion-pending'
    $script:Journal.failureCode = $null
    $script:Journal.rollbackStatus = 'not-attempted'
    Write-AgentRoadJournal $script:Journal
    $confirmed = $false
    $rejected = $false
    $sawUncertain = $false
    for ($attempt = 1; $attempt -le 3; $attempt++) {
      $result = Invoke-AgentRoadCompletionRequest ($Configuration.controllerBaseUrl + '/complete') $bodyBytes $expectedAckBytes
      $httpStatus = $result.StatusCode
      if ($null -eq $httpStatus) { $sawUncertain = $true }
      elseif ($result.StatusCode -eq 200 -and $result.AckValid) { $confirmed = $true; break }
      elseif ($result.StatusCode -eq 200 -and -not $result.AckValid) {
        $sawUncertain = $true
      }
      elseif ($httpStatus -ge 500 -and $httpStatus -le 599) { $sawUncertain = $true }
      elseif ($httpStatus -ge 400 -and $httpStatus -le 499) {
        if (-not $sawUncertain) { $rejected = $true; break }
      } elseif (-not $sawUncertain) {
        $rejected = $true
        break
      }
      if ($attempt -lt 3) { Start-Sleep -Seconds 1 }
    }
    if ($rejected) {
      $script:Journal.status = 'failed'
      $script:Journal.failureCode = 'COMPLETION_REJECTED'
      $script:Journal.rollbackStatus = 'pending'
      Write-AgentRoadJournal $script:Journal
      throw 'COMPLETION_REJECTED'
    }
    if (-not $confirmed -and -not $rejected) {
      $script:Journal.status = 'completion-pending'
      $script:Journal.failureCode = 'COMPLETION_UNCERTAIN'
      Write-AgentRoadJournal $script:Journal
      throw 'COMPLETION_UNCERTAIN'
    }
    $script:Journal.status = 'complete'
    $script:Journal.failureCode = $null
    $script:Journal.rollbackStatus = 'not-attempted'
    $pendingChanges = @($script:Journal.changes)
    $script:Journal.changes = @()
    try { Write-AgentRoadJournal $script:Journal } catch {
      $script:Journal.status = 'completion-pending'
      $script:Journal.failureCode = 'COMPLETION_UNCERTAIN'
      $script:Journal.changes = $pendingChanges
      try { Write-AgentRoadJournal $script:Journal } catch {}
      throw 'COMPLETION_UNCERTAIN'
    }
  } finally {
    if ($null -ne $bodyBytes) { [Array]::Clear($bodyBytes,0,$bodyBytes.Length) }
    if ($null -ne $expectedAckBytes) { [Array]::Clear($expectedAckBytes,0,$expectedAckBytes.Length) }
    $body = $null
    $expectedAck = $null
    $bodyObject.completionTicket = $null
    $Configuration.completionTicket = $null
  }
}

function Test-AgentRoadRollbackPostcondition {
  param([pscustomobject]$Change)
  try {
    Assert-AgentRoadChange $Change
    switch -CaseSensitive ($Change.action) {
      'restoreFile' {
        Assert-AgentRoadSafeFile $Change.path $false
        if ((Get-Item -LiteralPath $Change.path).Length -gt 1048576) { return $false }
        if ($Change.path -ceq $script:AuthorizedKeyPath) { Assert-AgentRoadRestrictedAcl $Change.path }
        return (Get-AgentRoadFileSha256 $Change.path) -ceq $Change.expectedSha256 -and (Get-AgentRoadFileSha256 $Change.backupPath) -ceq $Change.expectedSha256 -and (Get-AgentRoadAclSha256 $Change.path) -ceq $Change.expectedAclSha256
      }
      'removeFile' { return -not (Test-Path -LiteralPath $Change.path) }
      'removeDirectory' { return -not (Test-Path -LiteralPath $Change.path) }
      'preserveEmptyDirectory' { Assert-AgentRoadEmptySshDataRoot; return (Get-AgentRoadAclSha256 $Change.path) -ceq $Change.expectedAclSha256 -and @(Get-ChildItem -LiteralPath $Change.path -Force -ErrorAction Stop).Count -eq 0 }
      'removeUser' { return @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.Name -ceq 'AgentRoad' }).Count -eq 0 }
      'removeAdminMember' {
        $user = Get-LocalUser -Name 'AgentRoad' -ErrorAction Stop
        $group = Get-LocalGroup -SID 'S-1-5-32-544'
        return $null -eq (Get-LocalGroupMember -Group $group -ErrorAction Stop | Where-Object { $_.SID -eq $user.SID })
      }
      'removeFirewall' { return @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.Name -ceq $script:FirewallName -or $_.DisplayName -ceq $script:FirewallName }).Count -eq 0 }
      'restoreFirewallEnabled' { $rule = @(Get-NetFirewallRule -Name $Change.path -ErrorAction Stop); return $rule.Count -eq 1 -and [string]$rule[0].Enabled -ceq 'True' -and (Test-AgentRoadMicrosoftOpenSshRule $rule[0]) }
      'removeOpenSshCapability' { return (Get-WindowsCapability -Online -Name $Change.path).State -eq $Change.backupPath -and @(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue).Count -eq 0 }
      'restoreService' {
        $service = Get-Service -Name 'sshd' -ErrorAction Stop
        $details = Get-CimInstance Win32_Service -Filter "Name='sshd'"
        return [string]$details.StartMode -ceq $Change.path -and [string]$service.Status -ceq $Change.backupPath
      }
      'restoreServiceRecovery' { return Test-AgentRoadSshdRecoveryUnset }
      default { return $false }
    }
  } catch { return $false }
}

function Remove-AgentRoadOwnedOpenSshCapability {
  param([pscustomobject]$Change)
  Assert-AgentRoadChange $Change
  if ($Change.action -cne 'removeOpenSshCapability') { throw 'ROLLBACK_INCOMPLETE' }
  $broadRules = @(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)
  if ($broadRules.Count -gt 1) { throw 'ROLLBACK_INCOMPLETE' }
  if ($broadRules.Count -eq 1 -and [string]$broadRules[0].Enabled -ceq 'True') { Disable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction Stop | Out-Null }
  if ($broadRules.Count -eq 1 -and [string](Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction Stop).Enabled -cne 'False') { throw 'ROLLBACK_INCOMPLETE' }
  $service = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
  if ($null -ne $service -and $service.Status -ne 'Stopped') {
    Stop-Service -Name 'sshd' -Force -ErrorAction Stop
    (Get-Service -Name 'sshd' -ErrorAction Stop).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(20))
  }
  if ($null -ne (Get-Service -Name 'sshd' -ErrorAction SilentlyContinue) -and (Get-Service -Name 'sshd' -ErrorAction Stop).Status -ne 'Stopped') { throw 'ROLLBACK_INCOMPLETE' }
  $capability = Get-WindowsCapability -Online -Name $Change.path
  if ($capability.State -eq 'Installed') { Remove-WindowsCapability -Online -Name $Change.path | Out-Null }
  if ((Get-WindowsCapability -Online -Name $Change.path).State -ne $Change.backupPath) { throw 'ROLLBACK_INCOMPLETE' }
  $remainingBroadRules = @(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)
  if ($remainingBroadRules.Count -gt 1) { throw 'ROLLBACK_INCOMPLETE' }
  if ($remainingBroadRules.Count -eq 1) { Remove-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction Stop }
  if (-not (Test-AgentRoadRollbackPostcondition $Change)) { throw 'ROLLBACK_INCOMPLETE' }
}

function Remove-AgentRoadOwnedSshDataRoot {
  param([bool]$PreserveRoot,[string]$ExpectedAclSha256)
  if (-not (Test-Path -LiteralPath $script:SshDataRoot)) { return }
  Assert-AgentRoadSafePath $script:SshDataRoot $true
  if (-not (Test-Path -LiteralPath $script:SshDataRoot -PathType Container)) { throw 'ROLLBACK_INCOMPLETE' }
  if ($PreserveRoot) { Assert-AgentRoadSecureSshAcl $script:SshDataRoot } else { Assert-AgentRoadRestrictedAcl $script:SshDataRoot }
  $children = @(Get-ChildItem -LiteralPath $script:SshDataRoot -Force -ErrorAction Stop)
  if ($children.Count -gt 32) { throw 'ROLLBACK_INCOMPLETE' }
  $knownFilePattern = '^(?:sshd_config|ssh_host_(?:rsa|ecdsa|ed25519)_key(?:\.pub)?|sshd\.pid|sshd\.log)$'
  $logFiles = @()
  $logDirectories = @()
  foreach ($child in $children) {
    if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'ROLLBACK_INCOMPLETE' }
    if ($child.PSIsContainer) {
      if ([string]$child.Name -cne 'logs') { throw 'ROLLBACK_INCOMPLETE' }
      Assert-AgentRoadSafePath $child.FullName $true
      Assert-AgentRoadNoUnprivilegedWrite $child.FullName
      $logs = @(Get-ChildItem -LiteralPath $child.FullName -Force -ErrorAction Stop)
      if ($logs.Count -gt 16) { throw 'ROLLBACK_INCOMPLETE' }
      foreach ($log in $logs) {
        if ($log.PSIsContainer -or ($log.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or [string]$log.Name -cnotmatch '^sshd\.log(?:\.[0-9]{1,3})?$' -or $log.Length -gt 10485760) { throw 'ROLLBACK_INCOMPLETE' }
        Assert-AgentRoadSafeFile $log.FullName $false
      }
      $logFiles += $logs
      $logDirectories += $child
      continue
    }
    if ([string]$child.Name -cnotmatch $knownFilePattern -or $child.Length -gt 10485760) { throw 'ROLLBACK_INCOMPLETE' }
    Assert-AgentRoadSafeFile $child.FullName $false
  }
  foreach ($child in @($children | Where-Object { -not $_.PSIsContainer })) { Remove-Item -LiteralPath $child.FullName -Force -ErrorAction Stop }
  foreach ($log in $logFiles) { Remove-Item -LiteralPath $log.FullName -Force -ErrorAction Stop }
  foreach ($directory in $logDirectories) { [IO.Directory]::Delete($directory.FullName,$false) }
  if (-not $PreserveRoot) {
    [IO.Directory]::Delete($script:SshDataRoot,$false)
    if (Test-Path -LiteralPath $script:SshDataRoot) { throw 'ROLLBACK_INCOMPLETE' }
  } elseif ([string]::IsNullOrEmpty($ExpectedAclSha256) -or (Get-AgentRoadAclSha256 $script:SshDataRoot) -cne $ExpectedAclSha256 -or @(Get-ChildItem -LiteralPath $script:SshDataRoot -Force -ErrorAction Stop).Count -ne 0) { throw 'ROLLBACK_INCOMPLETE' }
}

function Restore-AgentRoadChanges {
  Assert-AgentRoadJournal $script:Journal
  $script:Journal.rollbackStatus = 'pending'
  $metadataFailed = $false
  try { Write-AgentRoadJournal $script:Journal } catch { $metadataFailed = $true }
  $changes = @($script:Journal.changes)
  [Array]::Reverse($changes)
  $serviceChanges = @($changes | Where-Object { $_.action -ceq 'restoreService' })
  $serviceRecoveryChanges = @($changes | Where-Object { $_.action -ceq 'restoreServiceRecovery' })
  $firewallRestoreChanges = @($changes | Where-Object { $_.action -ceq 'restoreFirewallEnabled' })
  $ownedCapabilityChanges = @($changes | Where-Object { $_.action -ceq 'removeOpenSshCapability' })
  $ownedSshDataRoots = @($changes | Where-Object { $_.action -ceq 'removeDirectory' -and $_.path -ceq $script:SshDataRoot })
  $preservedSshDataRoots = @($changes | Where-Object { $_.action -ceq 'preserveEmptyDirectory' })
  $rollbackFailed = $metadataFailed
  $ownedCapabilityRollbackSucceeded = $ownedCapabilityChanges.Count -le 1 -and $ownedSshDataRoots.Count -le 1 -and $preservedSshDataRoots.Count -le 1 -and -not ($ownedSshDataRoots.Count -eq 1 -and $preservedSshDataRoots.Count -eq 1)
  if ($ownedCapabilityChanges.Count -eq 1) {
    try {
      Remove-AgentRoadOwnedOpenSshCapability $ownedCapabilityChanges[0]
      $preserveRoot = $preservedSshDataRoots.Count -eq 1
      $expectedRootAcl = if ($preserveRoot) { [string]$preservedSshDataRoots[0].expectedAclSha256 } else { $null }
      Remove-AgentRoadOwnedSshDataRoot $preserveRoot $expectedRootAcl
    } catch { $ownedCapabilityRollbackSucceeded = $false }
  }
  if (-not $ownedCapabilityRollbackSucceeded) { $rollbackFailed = $true }
  if ($ownedCapabilityRollbackSucceeded) {
    foreach ($change in $changes) {
      if ($change.action -cin @('restoreService','restoreServiceRecovery','restoreFirewallEnabled','removeOpenSshCapability')) { continue }
      try {
        Assert-AgentRoadChange $change
        switch -CaseSensitive ([string]$change.action) {
          'restoreFile' {
            Assert-AgentRoadSafePath (Split-Path -Parent $change.path) $true
            Assert-AgentRoadSafePath $change.path $false
            Copy-Item -LiteralPath $change.backupPath -Destination $change.path -Force
          }
          'removeFile' { if (Test-Path -LiteralPath $change.path) { Remove-Item -LiteralPath $change.path -Force -ErrorAction Stop } }
          'removeDirectory' { if (Test-Path -LiteralPath $change.path) { [IO.Directory]::Delete($change.path,$false) } }
          'preserveEmptyDirectory' { }
          'removeUser' { if (@(Get-LocalUser -ErrorAction Stop | Where-Object { $_.Name -ceq $change.path }).Count -gt 0) { Remove-LocalUser -Name $change.path -ErrorAction Stop } }
          'removeAdminMember' { $group = Get-LocalGroup -SID 'S-1-5-32-544'; Remove-LocalGroupMember -Group $group -Member $change.path -ErrorAction Stop }
          'removeFirewall' { Remove-NetFirewallRule -Name $change.path -ErrorAction Stop }
        }
      } catch {}
      if (-not (Test-AgentRoadRollbackPostcondition $change)) { $rollbackFailed = $true }
    }
  }
  foreach ($change in $serviceRecoveryChanges) {
    try {
      Assert-AgentRoadChange $change
      Clear-AgentRoadSshdRecovery
    } catch {}
    if (-not (Test-AgentRoadRollbackPostcondition $change)) { $rollbackFailed = $true }
  }
  foreach ($change in $serviceChanges) {
    try {
      Assert-AgentRoadChange $change
      if ($change.path -eq 'Disabled') { Set-Service -Name 'sshd' -StartupType Disabled }
      elseif ($change.path -eq 'Manual') { Set-Service -Name 'sshd' -StartupType Manual }
      else { Set-Service -Name 'sshd' -StartupType Automatic }
      if ($change.backupPath -eq 'Running') {
        if (Test-Path -LiteralPath $script:SshdConfigPath) {
          $sshd = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
          $restoredSyntax = Invoke-AgentRoadNative $sshd @('-t','-f',$script:SshdConfigPath) 30
          if ($restoredSyntax.ExitCode -ne 0) { throw 'ROLLBACK_INCOMPLETE' }
        }
        if ((Get-Service -Name 'sshd' -ErrorAction Stop).Status -eq 'Running') { Restart-Service -Name 'sshd' -Force -ErrorAction Stop } else { Start-Service -Name 'sshd' -ErrorAction Stop }
        (Get-Service -Name 'sshd' -ErrorAction Stop).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(20))
      } else {
        Stop-Service -Name 'sshd' -Force -ErrorAction Stop
        (Get-Service -Name 'sshd' -ErrorAction Stop).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(20))
      }
    } catch {}
    if (-not (Test-AgentRoadRollbackPostcondition $change)) { $rollbackFailed = $true }
  }
  if (-not $rollbackFailed) {
    foreach ($change in $firewallRestoreChanges) {
      try {
        Assert-AgentRoadChange $change
        $rule = @(Get-NetFirewallRule -Name $change.path -ErrorAction Stop)
        if ($rule.Count -ne 1 -or -not (Test-AgentRoadMicrosoftOpenSshRule $rule[0])) { throw 'ROLLBACK_INCOMPLETE' }
        Enable-NetFirewallRule -Name $change.path -ErrorAction Stop | Out-Null
      } catch {}
      if (-not (Test-AgentRoadRollbackPostcondition $change)) { $rollbackFailed = $true }
    }
  }
  $script:Journal.status = if ($rollbackFailed) { 'failed' } else { 'rolledBack' }
  $script:Journal.rollbackStatus = if ($rollbackFailed) { 'failed' } else { 'succeeded' }
  $rollbackValidation = if ($rollbackFailed) { 'rollback-failed' } else { 'rollback-succeeded' }
  if (@($script:Journal.validations) -cnotcontains $rollbackValidation) { $script:Journal.validations = @($script:Journal.validations) + $rollbackValidation }
  if (-not $rollbackFailed) { $script:Journal.changes = @(); $script:Journal.checkpoints = @() }
  Write-AgentRoadJournal $script:Journal
  if ($rollbackFailed) { throw 'ROLLBACK_INCOMPLETE' }
}

$failureCode = $null
try {
  Assert-AgentRoadExactConfiguration
  Assert-Administrator
  $facts = Get-AgentRoadSystemFacts
  $script:BootstrapLock = Enter-AgentRoadBootstrapLock
  $script:Journal = Read-AgentRoadJournal
  if ($script:Journal.status -eq 'completion-pending' -and $script:Journal.failureCode -eq 'COMPLETION_UNCERTAIN') {
    Reset-AgentRoadSupersedingTransaction $facts
  }
  if ($script:Journal.status -eq 'failed') {
    Restore-AgentRoadChanges
    Reset-AgentRoadTransaction $facts
  }
  foreach ($checkpoint in @($script:Journal.checkpoints)) {
    if (-not (Test-AgentRoadCheckpointPostcondition $checkpoint $facts)) {
      if ($script:Journal.status -eq 'completion-pending') {
        $script:Journal.failureCode = 'COMPLETION_UNCERTAIN'
        Write-AgentRoadJournal $script:Journal
        throw 'COMPLETION_UNCERTAIN'
      }
      $script:Journal.status = 'failed'
      $script:Journal.failureCode = 'BOOTSTRAP_STATE_INVALID'
      $script:Journal.rollbackStatus = 'pending'
      Write-AgentRoadJournal $script:Journal
      Restore-AgentRoadChanges
      Reset-AgentRoadTransaction $facts
      break
    }
  }
  if (@($script:Journal.checkpoints) -cnotcontains 'preflight') {
    $script:Journal.facts = $facts
    Write-AgentRoadJournal $script:Journal
    Complete-AgentRoadCheckpoint 'preflight'
  }
  if (@($script:Journal.checkpoints) -cnotcontains 'tailscale') {
    $failureCode = 'TAILSCALE_LOGIN_REQUIRED'
    if (-not (Test-AgentRoadTailscalePostcondition)) { throw 'TAILSCALE_LOGIN_REQUIRED' }
    Complete-AgentRoadCheckpoint 'tailscale'
  }
  $script:TailscaleAddresses = @(Get-AgentRoadTailscaleAddresses)

  $failureCode = 'FIREWALL_CONFIG_FAILED'
  Assert-AgentRoadSshTransportIsolation
  Assert-AgentRoadFirewallProfiles
  Assert-AgentRoadFirewallPreflight

  if (@($script:Journal.checkpoints) -cnotcontains 'openssh') {
    $failureCode = 'OPENSSH_INSTALL_FAILED'
    Write-Output 'Agent Road: checking/installing OpenSSH (Windows Update may take several minutes)'
    Ensure-AgentRoadOpenSshCapability
    if (-not (Test-AgentRoadOpenSshPostcondition)) { throw 'OPENSSH_INSTALL_FAILED' }
    Complete-AgentRoadCheckpoint 'openssh'
    Write-Output 'Agent Road: OpenSSH checkpoint complete'
  }

  $failureCode = 'FIREWALL_CONFIG_FAILED'
  Ensure-AgentRoadFirewallBoundary

  if (@($script:Journal.checkpoints) -cnotcontains 'account') {
    $failureCode = 'SSHD_CONFIG_INVALID'
    Record-AgentRoadValidation 'account-entered'
    Ensure-AgentRoadAccount
    Record-AgentRoadValidation 'authorized-key-entered'
    Ensure-AgentRoadAuthorizedKey
    Record-AgentRoadValidation 'ssh-data-entered'
    Initialize-AgentRoadSshData
    Record-AgentRoadValidation 'host-keys-entered'
    Ensure-AgentRoadHostKeys
    Record-AgentRoadValidation 'sshd-config-entered'
    Ensure-AgentRoadSshdConfiguration
    if (-not (Test-AgentRoadAccountPostcondition)) { throw 'SSHD_CONFIG_INVALID' }
    Complete-AgentRoadCheckpoint 'account'
  }

  if (@($script:Journal.checkpoints) -cnotcontains 'firewall') {
    $failureCode = 'FIREWALL_CONFIG_FAILED'
    Ensure-AgentRoadFirewallBoundary
    if (-not (Test-AgentRoadFirewallPostcondition)) { throw 'FIREWALL_CONFIG_FAILED' }
    Assert-AgentRoadFirewallProfiles
    $failureCode = 'SSHD_START_FAILED'
    Ensure-AgentRoadSshdRecovery
    Ensure-AgentRoadSshdService
    if (-not (Test-AgentRoadServicePostcondition)) { throw 'SSHD_START_FAILED' }
    Complete-AgentRoadCheckpoint 'firewall'
  }

  $failureCode = 'SSHD_START_FAILED'
  $hostKeys = Get-AgentRoadHostKeys
  Send-AgentRoadCompletion $facts $hostKeys
  Write-Output 'AGENT_ROAD_STAGE_ONE_COMPLETE'
} catch {
  $exceptionCode = [string]$_.Exception.Message
  $primaryCode = if (Test-AgentRoadStableFailure $exceptionCode) { $exceptionCode } elseif (Test-AgentRoadStableFailure $failureCode) { $failureCode } elseif ($null -ne $script:Journal -and (Test-AgentRoadStableFailure $script:Journal.failureCode)) { $script:Journal.failureCode } else { 'INTERNAL_ERROR' }
  if ($null -ne $script:Journal -and $script:Journal.status -eq 'completion-pending') {
    $script:Journal.failureCode = 'COMPLETION_UNCERTAIN'
    $script:Journal.rollbackStatus = 'not-attempted'
    try { Write-AgentRoadJournal $script:Journal } catch {}
    try { $Configuration.completionTicket = $null } catch {}
    throw ('AGENT_ROAD_BOOTSTRAP_FAILED:' + 'COMPLETION_UNCERTAIN')
  }
  $rollbackIncomplete = $null -ne $script:Journal -and $script:Journal.rollbackStatus -eq 'failed'
  if ($null -ne $script:Journal) {
    $script:Journal.status = 'failed'
    $script:Journal.failureCode = $primaryCode
    $script:Journal.rollbackStatus = 'pending'
    try { Write-AgentRoadJournal $script:Journal } catch { $rollbackIncomplete = $true }
    try { Restore-AgentRoadChanges; $rollbackIncomplete = $false } catch { $rollbackIncomplete = $true; try { $script:Journal.status = 'failed'; $script:Journal.failureCode = $primaryCode; $script:Journal.rollbackStatus = 'failed'; Write-AgentRoadJournal $script:Journal } catch {} }
  }
  try { $Configuration.completionTicket = $null } catch {}
  $suffix = if ($rollbackIncomplete) { ':ROLLBACK_INCOMPLETE' } else { '' }
  throw ('AGENT_ROAD_BOOTSTRAP_FAILED:' + $primaryCode + $suffix)
} finally {
  if ($null -ne $script:BootstrapLock) { try { $script:BootstrapLock.Dispose() } catch {}; $script:BootstrapLock = $null }
}
