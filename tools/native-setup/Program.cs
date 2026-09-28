using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using Microsoft.Win32;

internal static partial class Program {
    const string Capability = "OpenSSH.Server~~~~0.0.1.0";
    const string RuleName = "AgentRoad-Native-Preview-Block-SSH";
    static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AgentRoadNativeSetupPreview");
    static readonly string SshRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ssh");
    static string PriorEmptySshDirectoryAcl;
    static string DirectoryAcl(string path) { return Directory.GetAccessControl(path).GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group); }
    static string InspectEmptyDirectory(string path) {
        FileAttributes attributes;
        try { attributes = File.GetAttributes(path); }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
        if ((attributes & FileAttributes.ReparsePoint) != 0) Stop("REPARSE_PATH_REFUSED");
        if ((attributes & FileAttributes.Directory) == 0) Stop("EXISTING_SSH_DATA_REFUSED");
        for (var dir = new DirectoryInfo(path); dir != null; dir = dir.Parent)
            if (dir.Exists && (dir.Attributes & FileAttributes.ReparsePoint) != 0) Stop("REPARSE_PATH_REFUSED");
        if (Directory.GetFileSystemEntries(path).Length != 0) Stop("EXISTING_SSH_DATA_REFUSED");
        return DirectoryAcl(path);
    }
    static long? LastQueryMs;
    static int? LastQueryExitCode;
    static bool IsAdmin() { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
    static void Stop(string code) { throw new InvalidOperationException(code); }
    static bool RebootPending() {
        using (var cbs = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"))
        using (var update = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"))
        using (var session = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager")) {
            if (cbs != null || update != null) return true;
            var pending = session == null ? null : session.GetValue("PendingFileRenameOperations") as string[];
            if (pending != null) foreach (var entry in pending) if (!String.IsNullOrEmpty(entry)) return true;
            return false;
        }
    }
    static string ParseState(string text) {
        var matches = Regex.Matches(text, @"^\s*State\s*:\s*(Installed|Not Present|Install Pending)\s*$", RegexOptions.Multiline);
        return matches.Count == 1 ? matches[0].Groups[1].Value : "UNKNOWN";
    }
    static string Query() {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "Dism.exe"), "/English /Online /Get-CapabilityInfo /CapabilityName:" + Capability) {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        using (var p = new Process { StartInfo = start }) {
            var output = new StringBuilder(); var sync = new object(); bool overflow = false;
            p.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) lock(sync) { if (output.Length + e.Data.Length < 65536) output.AppendLine(e.Data); else overflow = true; } };
            p.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e) { /* Never publish raw servicing output. */ };
            LastQueryMs = null; LastQueryExitCode = null;
            p.Start(); var elapsed = Stopwatch.StartNew(); p.BeginOutputReadLine(); p.BeginErrorReadLine();
            bool exited = p.WaitForExit(180000);
            LastQueryMs = elapsed.ElapsedMilliseconds;
            if (!exited) Stop("QUERY_UNCERTAIN");
            p.WaitForExit(); LastQueryExitCode = p.ExitCode;
            if (p.ExitCode != 0 || overflow) Stop("QUERY_FAILED");
            return ParseState(output.ToString());
        }
    }
    static void AssertFreshMachine() {
        foreach (var service in ServiceController.GetServices()) using(service) if (service.ServiceName.Equals("sshd", StringComparison.OrdinalIgnoreCase)) Stop("EXISTING_SSH_REFUSED");
        foreach (var endpoint in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners()) if (endpoint.Port == 22) Stop("PORT_22_IN_USE");
        PriorEmptySshDirectoryAcl = InspectEmptyDirectory(SshRoot);
        dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true));
        foreach (int profile in new[] { 1, 2, 4 }) if (!(bool)policy.FirewallEnabled[profile]) Stop("FIREWALL_DISABLED");
        foreach (dynamic rule in policy.Rules) if ((string)rule.Name == RuleName || (string)rule.Name == "OpenSSH-Server-In-TCP") Stop("EXISTING_FIREWALL_RULE_REFUSED");
    }
    static void CreateJournal() {
        for (var dir = new DirectoryInfo(Root); dir != null; dir = dir.Parent)
            if (dir.Exists && (dir.Attributes & FileAttributes.ReparsePoint) != 0) Stop("REPARSE_PATH_REFUSED");
        if (Directory.Exists(Root) || File.Exists(Root)) Stop("PRIOR_ATTEMPT_REQUIRES_INSPECTION");
        var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        Directory.CreateDirectory(Root, acl);
        // CreateNew arbitrates competing attempts; an existing journal is never reused.
        using (var f = new FileStream(Path.Combine(Root, "journal.jsonl"), FileMode.CreateNew, FileAccess.Write, FileShare.Read)) f.Flush(true);
    }
    static void Record(string state, int? exitCode) {
        var entry = new Dictionary<string, object> { { "schemaVersion", 1 }, { "utc", DateTime.UtcNow.ToString("o") }, { "state", state }, { "dismExitCode", exitCode }, { "remoteAccessReady", false }, { "priorEmptySshDirectoryAcl", PriorEmptySshDirectoryAcl } };
        byte[] bytes = Encoding.UTF8.GetBytes(new JavaScriptSerializer().Serialize(entry) + "\n");
        using (var f = new FileStream(Path.Combine(Root, "journal.jsonl"), FileMode.Append, FileAccess.Write, FileShare.Read)) { f.Write(bytes, 0, bytes.Length); f.Flush(true); }
    }
    static bool BlockPresent(dynamic policy) {
        int count = 0;
        foreach (dynamic rule in policy.Rules) if ((string)rule.Name == RuleName) {
            count++;
            if (!(bool)rule.Enabled || (int)rule.Action != 0 || (int)rule.Direction != 1 || (int)rule.Protocol != 6
                || (string)rule.LocalPorts != "22" || (int)rule.Profiles != Int32.MaxValue
                || (string)rule.RemoteAddresses != "*" || (string)rule.LocalAddresses != "*") return false;
        }
        return count == 1;
    }
    static void BlockInbound() {
        dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true));
        dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true));
        rule.Name = RuleName; rule.Description = "Agent Road native setup preview: keep SSH closed until scoped setup is verified.";
        rule.Protocol = 6; rule.LocalPorts = "22"; rule.LocalAddresses = "*"; rule.RemoteAddresses = "*";
        rule.Direction = 1; rule.Action = 0; rule.Profiles = Int32.MaxValue; rule.Enabled = true;
        policy.Rules.Add(rule);
        if (!BlockPresent(policy)) Stop("FIREWALL_BLOCK_UNCONFIRMED");
    }
    static int Install() {
        if (!IsAdmin()) Stop("ADMIN_REQUIRED");
        if (RebootPending()) Stop("REBOOT_REQUIRED");
        if (Directory.Exists(Root) || File.Exists(Root)) Stop("PRIOR_ATTEMPT_REQUIRES_INSPECTION");
        string before = Query();
        if (before == "Installed") { Emit("ALREADY_PRESENT", null); return 0; }
        if (before != "Not Present") Stop("CAPABILITY_STATE_UNSUPPORTED");
        AssertFreshMachine(); CreateJournal();
        try {
            Record("BLOCK_INTENT", null); BlockInbound(); Record("BLOCK_VERIFIED", null);
            Record("INSTALL_INTENT", null);
            var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "Dism.exe"), "/Online /Add-Capability /CapabilityName:" + Capability + " /NoRestart /Quiet") { UseShellExecute = false, CreateNoWindow = true };
            using (var p = Process.Start(start)) {
                Record("INSTALL_STARTED", null);
                if (!p.WaitForExit(1200000)) { Record("INSTALL_UNCERTAIN", null); Emit("INSTALL_UNCERTAIN", null); return 2; }
                int code = p.ExitCode; Record("INSTALL_EXITED", code);
                dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true));
                if (!BlockPresent(policy)) Stop("FIREWALL_BLOCK_UNCONFIRMED");
                if (code == 3010) { Record("REBOOT_REQUIRED", code); Emit("REBOOT_REQUIRED", code); return 3; }
                if (code != 0) { Record("INSTALL_FAILED", code); Emit("INSTALL_FAILED", code); return 2; }
                if (Query() != "Installed") Stop("INSTALL_POSTCONDITION_FAILED");
                if (PriorEmptySshDirectoryAcl != null && (!Directory.Exists(SshRoot) || DirectoryAcl(SshRoot) != PriorEmptySshDirectoryAcl)) Stop("SSH_DIRECTORY_ACL_CHANGED");
                using (var service = new ServiceController("sshd")) if (service.Status != ServiceControllerStatus.Stopped) Stop("UNEXPECTED_RUNNING_SERVICE");
                Record("CAPABILITY_INSTALLED_SSH_BLOCKED", code); Emit("CAPABILITY_INSTALLED_SSH_BLOCKED", code); return 0;
            }
        } catch { Record("STOPPED_REQUIRES_INSPECTION", null); throw; }
    }
    static string FailureType;
    static int? FailureHResult;
    static void Emit(string state, int? code) {
        Console.WriteLine(new JavaScriptSerializer().Serialize(new { schemaVersion = 1, state = state, dismExitCode = code, queryDurationMs = LastQueryMs, queryExitCode = LastQueryExitCode, nativeOperation = LastNativeOperation, nativeExitCode = LastNativeExitCode, failureCategory = NativeFailureCategory, failureType = FailureType, failureHResult = FailureHResult, remoteAccessReady = false }));
    }
    static int Main(string[] args) {
        try {
            if (args.Length == 1 && args[0] == "--native-inspect") return InspectNative();
            if (args.Length == 2 && args[0] == "--install-tailscale" && args[1] == "--accept-system-changes") return InstallTailscale();
            if (args.Length == 2 && args[0] == "--resume-tailscale-download" && args[1] == "--accept-system-changes") return InstallTailscale(true);
            if (args.Length == 2 && args[0] == "--retain-unconfigured-attempt" && args[1] == "--accept-system-changes") return RetainUnconfiguredAttempt();
            if (args.Length == 2 && args[0] == "--retain-unjoined-attempt" && args[1] == "--accept-system-changes") return RetainUnconfiguredAttempt(true);
            if (args.Length == 3 && args[0] == "--pair" && args[2] == "--accept-system-changes") return NativePair(args[1]);
            if (args.Length == 1 && args[0] == "--native-preflight") { NativePreflight(); Emit("NATIVE_PREREQUISITES_READY", null); return 0; }
            if (args.Length == 1 && args[0] == "--self-test") {
                if (!NativeSelfTest()) return 2;
                if (ParseState("State : Installed\r\n") != "Installed" || ParseState("State : Not Present\r\n") != "Not Present"
                    || ParseState("State : Unknown\r\n") != "UNKNOWN" || ParseState("State : Installed\nState : Not Present") != "UNKNOWN") return 2;
                string fixture = Path.Combine(Path.GetTempPath(), "agent-road-native-selftest-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(fixture);
                string file = Path.Combine(fixture, "owned-fixture.txt");
                try {
                    if (InspectEmptyDirectory(fixture) != DirectoryAcl(fixture)) return 2;
                    File.WriteAllText(file, "test fixture");
                    bool refused = false;
                    try { InspectEmptyDirectory(fixture); } catch (InvalidOperationException e) { refused = e.Message == "EXISTING_SSH_DATA_REFUSED"; }
                    if (!refused || !File.Exists(file)) return 2;
                } finally { if (File.Exists(file)) File.Delete(file); Directory.Delete(fixture, false); }
                Emit("PARSER_SELF_TEST_PASSED", null); return 0;
            }
            if (args.Length == 1 && args[0] == "--inspect") {
                if (!IsAdmin()) Stop("ADMIN_REQUIRED");
                Console.WriteLine(new JavaScriptSerializer().Serialize(new { schemaVersion = 1, state = Query(), queryDurationMs = LastQueryMs, queryExitCode = LastQueryExitCode, rebootPending = RebootPending(), priorAttempt = Directory.Exists(Root), remoteAccessReady = false })); return 0;
            }
            if (args.Length == 2 && args[0] == "--install-openssh" && args[1] == "--accept-system-changes") return Install();
            Emit("EXPLICIT_ACTION_REQUIRED", null); return 2;
        } catch (Exception e) {
            FailureType=e.GetType().Name;FailureHResult=e.HResult;
            string code = e is InvalidOperationException && Regex.IsMatch(e.Message, "^[A-Z_]+$") ? e.Message : "NATIVE_SETUP_FAILED";
            Emit(code, null); return 2;
        }
    }
}
