using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

internal static partial class Program {
    static readonly string NativeRoot=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"AgentRoad");
    static readonly string NativeJournalRoot=Path.Combine(NativeRoot,"bootstrap-native");
    static readonly string TailscaleExe=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),@"Tailscale\tailscale.exe");
    const string NativeAllow="AgentRoad-Native-SSH-Tailnet";
    const string NativeOutsideBlock="AgentRoad-Native-SSH-Block-Outside-Tailnet";
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct UserInfo1 { public string name; public string password; public uint passwordAge; public uint privilege; public string home; public string comment; public uint flags; public string script; }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct GroupMember3 { public string name; }
    [DllImport("Netapi32.dll",CharSet=CharSet.Unicode)] static extern uint NetUserAdd(string server,uint level,ref UserInfo1 user,out uint parameterError);
    [DllImport("Netapi32.dll",CharSet=CharSet.Unicode)] static extern uint NetUserGetInfo(string server,string user,uint level,out IntPtr buffer);
    [DllImport("Netapi32.dll")] static extern uint NetApiBufferFree(IntPtr buffer);
    [DllImport("Netapi32.dll",CharSet=CharSet.Unicode)] static extern uint NetLocalGroupAddMembers(string server,string group,uint level,ref GroupMember3 member,uint count);
    static void SafePath(string path) {
        string current=Path.GetFullPath(path);
        while(current!=null) {
            try { if((File.GetAttributes(current)&FileAttributes.ReparsePoint)!=0) Stop("REPARSE_PATH_REFUSED"); }
            catch(FileNotFoundException){} catch(DirectoryNotFoundException){}
            current=Path.GetDirectoryName(current);
        }
    }
    static void TrustedWriteAcl(string path) {
        SafePath(path);
        FileSystemSecurity acl=Directory.Exists(path)?(FileSystemSecurity)Directory.GetAccessControl(path):File.GetAccessControl(path);
        var allowed=new HashSet<string>{"S-1-5-18","S-1-5-32-544",new NTAccount("NT SERVICE","TrustedInstaller").Translate(typeof(SecurityIdentifier)).Value};
        if(!allowed.Contains(acl.GetOwner(typeof(SecurityIdentifier)).Value))Stop("NATIVE_PATH_OWNER_UNSAFE");
        var writes=FileSystemRights.Write|FileSystemRights.Delete|FileSystemRights.DeleteSubdirectoriesAndFiles|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership;
        foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))
            if(rule.AccessControlType==AccessControlType.Allow && (rule.PropagationFlags&PropagationFlags.InheritOnly)==0
                && ((rule.FileSystemRights&writes)!=0 || (unchecked((uint)rule.FileSystemRights)&0x50000000)!=0)
                && !allowed.Contains(rule.IdentityReference.Value))Stop("NATIVE_PATH_WRITABLE");
    }
    static void CreateExclusivePrivateDirectory(string path) {
        SafePath(path);string temp=path+"-new-"+Guid.NewGuid().ToString("N");
        Directory.CreateDirectory(temp,PrivateDirectoryAcl());
        try {TrustedWriteAcl(temp);Directory.Move(temp,path);}finally{if(Directory.Exists(temp))Directory.Delete(temp,false);}
    }
    static DirectorySecurity PrivateDirectoryAcl() {
        var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);
        foreach(var type in new[]{WellKnownSidType.LocalSystemSid,WellKnownSidType.BuiltinAdministratorsSid})
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(type,null),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null));return acl;
    }
    static void PrivateFile(string path) {
        SafePath(path);var acl=new FileSecurity();acl.SetAccessRuleProtection(true,false);
        foreach(var type in new[]{WellKnownSidType.LocalSystemSid,WellKnownSidType.BuiltinAdministratorsSid})
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(type,null),FileSystemRights.FullControl,AccessControlType.Allow));
        acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null));File.SetAccessControl(path,acl);
    }
    static void NewPrivateFile(string path,string text) {
        SafePath(path);using(var f=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {
            byte[] b=new UTF8Encoding(false).GetBytes(text);f.Write(b,0,b.Length);f.Flush(true);
        } PrivateFile(path);
    }
    static int? LastNativeExitCode;
    static string LastNativeOperation;
    static string NativeFailureCategory;
    static string RunFixed(string exe,string arguments,int milliseconds,bool allowExitOne=false) {
        LastNativeExitCode=null;NativeFailureCategory=null;LastNativeOperation=Path.GetFileName(exe);
        TrustedWriteAcl(exe);var start=new ProcessStartInfo(exe,arguments){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        using(var p=new Process{StartInfo=start}) {
            var output=new StringBuilder();var sync=new object();bool overflow=false;int streamsEnded=0;
            p.OutputDataReceived+=delegate(object sender,DataReceivedEventArgs e){if(e.Data==null){Interlocked.Increment(ref streamsEnded);return;}if(e.Data!=null)lock(sync){if(output.Length+e.Data.Length<65536)output.AppendLine(e.Data);else overflow=true;}};
            p.ErrorDataReceived+=delegate(object sender,DataReceivedEventArgs e){
                if(e.Data==null)Interlocked.Increment(ref streamsEnded);
                else if(exe==TailscaleExe && Regex.IsMatch(e.Data,"invalid.*(?:auth.?key|key)|(?:auth.?key|key).*(?:expired|not found|invalid)",RegexOptions.IgnoreCase))NativeFailureCategory="TAILSCALE_AUTH_REJECTED";
            };
            p.Start();p.BeginOutputReadLine();p.BeginErrorReadLine();
            if(!p.WaitForExit(milliseconds))Stop("NATIVE_OPERATION_UNCERTAIN_DO_NOT_REPLAY");
            LastNativeExitCode=p.ExitCode;var drain=Stopwatch.StartNew();
            while(Interlocked.CompareExchange(ref streamsEnded,0,0)<2 && drain.ElapsedMilliseconds<3000)Thread.Sleep(10);
            if(streamsEnded!=2)Stop("NATIVE_OPERATION_UNCERTAIN_DO_NOT_REPLAY");if((p.ExitCode!=0&&!(allowExitOne&&p.ExitCode==1))||overflow)Stop("NATIVE_OPERATION_FAILED");return output.ToString();
        }
    }
    static string Q(string path) { if(path.Contains("\"")||path.Contains("\r")||path.Contains("\n"))Stop("NATIVE_PATH_INVALID");return "\""+path+"\""; }
    [StructLayout(LayoutKind.Sequential)]
    struct NativeSystemInfo { public ushort architecture; public ushort reserved; public uint pageSize; public IntPtr minimum; public IntPtr maximum; public UIntPtr mask; public uint processors; public uint processorType; public uint granularity; public ushort level; public ushort revision; }
    [DllImport("kernel32.dll")] static extern void GetNativeSystemInfo(out NativeSystemInfo info);
    static int NativeBuild;
    static string NativeEdition;
    static void NativePreflight(bool retainedRoot=false) {
        if(!IsAdmin())Stop("ADMIN_REQUIRED");
        if(RebootPending())Stop("REBOOT_REQUIRED");
        NativeSystemInfo system;GetNativeSystemInfo(out system);
        if(system.architecture!=9)Stop("NATIVE_ARCHITECTURE_UNSUPPORTED");
        using(var key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion")) {
            if(key==null || !Int32.TryParse(Convert.ToString(key.GetValue("CurrentBuildNumber")),out NativeBuild) || NativeBuild<22000)Stop("NATIVE_WINDOWS_UNSUPPORTED");
            NativeEdition=Convert.ToString(key.GetValue("EditionID"));
            if(!Regex.IsMatch(NativeEdition,"^[A-Za-z0-9 ]{1,100}$"))Stop("NATIVE_WINDOWS_METADATA_INVALID");
        }
        SafePath(NativeRoot);SafePath(SshRoot);SafePath(TailscaleExe);
        if(!retainedRoot && (File.Exists(NativeRoot)||Directory.Exists(NativeRoot)))Stop("PRIOR_NATIVE_ATTEMPT_REQUIRES_INSPECTION");
        if(!File.Exists(TailscaleExe))Stop("TAILSCALE_INSTALL_REQUIRED");
        if(Query()!="Installed")Stop("OPENSSH_INSTALL_REQUIRED");
        using(var svc=new ServiceController("sshd")) if(svc.Status!=ServiceControllerStatus.Stopped)Stop("EXISTING_SSH_REFUSED");
        InspectEmptyDirectory(SshRoot);
        if(Directory.Exists(SshRoot))TrustedWriteAcl(SshRoot);
        TrustedWriteAcl(TailscaleExe);TrustedWriteAcl(Path.GetDirectoryName(TailscaleExe));
        VerifyTailscaleSignature(TailscaleExe);
        foreach(var ep in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners())if(ep.Port==22)Stop("PORT_22_IN_USE");
        IntPtr buffer;uint state=NetUserGetInfo(null,"AgentRoad",0,out buffer);if(buffer!=IntPtr.Zero)NetApiBufferFree(buffer);
        if(state!=2221)Stop("EXISTING_ACCOUNT_OR_QUERY_FAILED");
        dynamic policy=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2",true));
        foreach(int profile in new[]{1,2,4})if(!(bool)policy.FirewallEnabled[profile])Stop("FIREWALL_DISABLED");
        foreach(dynamic rule in policy.Rules)if((string)rule.Name==NativeAllow||(string)rule.Name==NativeOutsideBlock)Stop("EXISTING_FIREWALL_RULE_REFUSED");
        using(var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\sshd")) {
            string image=key==null?"":Convert.ToString(key.GetValue("ImagePath"));
            if(!String.Equals(Environment.ExpandEnvironmentVariables(image).Trim('"'),Path.Combine(Environment.SystemDirectory,@"OpenSSH\sshd.exe"),StringComparison.OrdinalIgnoreCase))Stop("SSHD_SERVICE_DEFINITION_INVALID");
        }
        var ts=ParseJson(RunFixed(TailscaleExe,"status --json",20000,true));
        if(Text(ts,"BackendState")!="NeedsLogin")Stop("TAILSCALE_EXISTING_IDENTITY_REFUSED");
    }
    static int RetainUnconfiguredAttempt(bool unjoined=false) {
        if(!IsAdmin())Stop("ADMIN_REQUIRED");
        TrustedWriteAcl(NativeRoot);TrustedWriteAcl(NativeJournalRoot);
        var rootEntries=Directory.GetFileSystemEntries(NativeRoot);
        var journalEntries=Directory.GetFileSystemEntries(NativeJournalRoot);
        string journal=Path.Combine(NativeJournalRoot,"journal.jsonl");
        if(rootEntries.Length!=1 || rootEntries[0]!=NativeJournalRoot || journalEntries.Length!=(unjoined?2:1)
            || !new HashSet<string>(journalEntries,StringComparer.OrdinalIgnoreCase).Contains(journal))Stop("NATIVE_ATTEMPT_HAS_OTHER_STATE");
        if(unjoined) {
            string auth=Path.Combine(NativeJournalRoot,"tailscale-auth-key");
            if(!new HashSet<string>(journalEntries,StringComparer.OrdinalIgnoreCase).Contains(auth))Stop("NATIVE_ATTEMPT_HAS_OTHER_STATE");
            TrustedWriteAcl(auth);
        }
        TrustedWriteAcl(journal);
        if(new FileInfo(journal).Length>65536)Stop("NATIVE_JOURNAL_INVALID");
        string last=null;int lines=0;bool joinIntent=false;
        foreach(string line in File.ReadAllLines(journal))if(line.Length>0) {
            var item=ParseJson(line);Exact(item,"schemaVersion","utc","state","remoteAccessReady");
            last=Text(item,"state");lines++;if(last=="TAILSCALE_JOIN_INTENT")joinIntent=true;
            if(Number(item,"schemaVersion")!=1 || !(item["remoteAccessReady"] is bool) || (bool)item["remoteAccessReady"]
                || (last!="CLAIM_INTENT" && last!="CLAIMED" && last!="STOPPED_REQUIRES_INSPECTION"
                    && !(unjoined && (last=="CONFIGURATION_RECEIVED" || last=="SSH_BLOCK_INTENT" || last=="SSH_BLOCK_VERIFIED" || last=="TAILSCALE_JOIN_INTENT"))))Stop("NATIVE_ATTEMPT_MAY_HAVE_CONFIGURED_SYSTEM");
        }
        if(lines<2 || last!="STOPPED_REQUIRES_INSPECTION" || (unjoined && !joinIntent))Stop("NATIVE_ATTEMPT_NOT_STOPPED");
        NativePreflight(true);
        if(unjoined) {
            Thread.Sleep(2000);
            var ts=ParseJson(RunFixed(TailscaleExe,"status --json",20000,true));
            if(Text(ts,"BackendState")!="NeedsLogin")Stop("TAILSCALE_EXISTING_IDENTITY_REFUSED");
        }
        // Keep every byte and original ACL. The prior controller invitation must be cancelled first.
        string retained=NativeRoot+"-unconfigured-"+Guid.NewGuid().ToString("N");
        Directory.Move(NativeRoot,retained);
        Console.WriteLine(Json.Serialize(new{schemaVersion=1,state="UNCONFIGURED_ATTEMPT_RETAINED",retainedDirectory=retained,remoteAccessReady=false}));return 0;
    }
    static void CreateNativeJournal() {
        SafePath(NativeRoot);
        if(Directory.Exists(NativeRoot)||File.Exists(NativeRoot))Stop("PRIOR_NATIVE_ATTEMPT_REQUIRES_INSPECTION");
        CreateExclusivePrivateDirectory(NativeRoot);
        Directory.CreateDirectory(NativeJournalRoot,PrivateDirectoryAcl());
        NewPrivateFile(Path.Combine(NativeJournalRoot,"journal.jsonl"),"");
    }
    static void NativeRecord(string state) {
        string path=Path.Combine(NativeJournalRoot,"journal.jsonl");SafePath(path);
        byte[] b=Encoding.UTF8.GetBytes(Json.Serialize(new{schemaVersion=1,utc=DateTime.UtcNow.ToString("o"),state=state,remoteAccessReady=false})+"\n");
        using(var f=new FileStream(path,FileMode.Append,FileAccess.Write,FileShare.Read)){f.Write(b,0,b.Length);f.Flush(true);}
        Console.Error.WriteLine(state);
    }
    static void NativeUser() {
        NativeRecord("ACCOUNT_CREATE_INTENT");
        var info=new UserInfo1{name="AgentRoad",password=RandomToken()+"aA1!",privilege=1,comment="Agent Road native remote access",flags=0x10201};
        uint parameter;uint result=NetUserAdd(null,1,ref info,out parameter);info.password=null;
        if(result!=0)Stop("NATIVE_ACCOUNT_CREATE_FAILED");NativeRecord("ACCOUNT_CREATED");
        string group=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null).Translate(typeof(NTAccount)).Value;
        group=group.Substring(group.IndexOf('\\')+1);var member=new GroupMember3{name=Environment.MachineName+"\\AgentRoad"};
        if(NetLocalGroupAddMembers(null,group,3,ref member,1)!=0)Stop("NATIVE_ACCOUNT_GROUP_FAILED");
        NativeRecord("ACCOUNT_CONFIGURED");
    }
    static string TailnetAddress() {
        string ip=RunFixed(TailscaleExe,"ip -4",20000).Trim();IPAddress address;
        if(!IPAddress.TryParse(ip,out address)||address.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork||address.ToString()!=ip)Stop("TAILSCALE_ADDRESS_INVALID");
        var b=address.GetAddressBytes();if(b[0]!=100||b[1]<64||b[1]>127)Stop("TAILSCALE_ADDRESS_INVALID");return ip;
    }
    static void AddNativeRule(string name,int action,string local,string remote) {
        dynamic policy=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2",true));
        dynamic rule=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule",true));
        rule.Name=name;rule.Protocol=6;rule.LocalPorts="22";rule.LocalAddresses=local;rule.RemoteAddresses=remote;
        rule.Direction=1;rule.Action=action;rule.Profiles=Int32.MaxValue;rule.Enabled=true;policy.Rules.Add(rule);
        VerifyNativeRule(name,action,local,remote);
    }
    static bool AddressExpression(string actual,string expected) {
        if(actual==expected)return true;
        if(expected=="100.64.0.0/10")return actual=="100.64.0.0/255.192.0.0"||actual=="100.64.0.0-100.127.255.255";
        if(expected=="*")return actual=="*";
        if(expected.IndexOf(',')<0)return actual==expected+"/255.255.255.255";
        string ipv6="::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
        var wanted=new HashSet<string>(expected.Replace(ipv6,"::/0").Split(','),StringComparer.Ordinal);
        var got=new HashSet<string>(actual.Replace("::/::","::/0").Replace(ipv6,"::/0").Split(','),StringComparer.Ordinal);
        return got.Count==3 && got.SetEquals(wanted);
    }
    static void VerifyNativeRule(string name,int action,string local,string remote) {
        dynamic policy=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2",true));int count=0;
        foreach(dynamic saved in policy.Rules)if((string)saved.Name==name){
            count++;
            if(!(bool)saved.Enabled||(int)saved.Action!=action||(int)saved.Direction!=1||(int)saved.Protocol!=6
                ||(string)saved.LocalPorts!="22"||(int)saved.Profiles!=Int32.MaxValue
                ||!AddressExpression((string)saved.LocalAddresses,local)||!AddressExpression((string)saved.RemoteAddresses,remote))Stop("NATIVE_FIREWALL_UNCONFIRMED");
        }
        if(count!=1)Stop("NATIVE_FIREWALL_UNCONFIRMED");
    }
    static int InspectNative() {
        if(!IsAdmin())Stop("ADMIN_REQUIRED");
        string state="NO_NATIVE_ATTEMPT",journal=Path.Combine(NativeJournalRoot,"journal.jsonl");
        if(File.Exists(journal)) {
            TrustedWriteAcl(NativeRoot);TrustedWriteAcl(NativeJournalRoot);TrustedWriteAcl(journal);
            var info=new FileInfo(journal);if(info.Length>65536)Stop("NATIVE_JOURNAL_INVALID");
            foreach(string line in File.ReadAllLines(journal))if(line.Length>0){var item=ParseJson(line);state=Text(item,"state");if(!Regex.IsMatch(state,"^[A-Z_]+$"))Stop("NATIVE_JOURNAL_INVALID");}
        }
        string serviceState="ABSENT";foreach(var service in ServiceController.GetServices())using(service)if(service.ServiceName.Equals("sshd",StringComparison.OrdinalIgnoreCase))serviceState=service.Status.ToString();
        Console.WriteLine(Json.Serialize(new{schemaVersion=1,state=state,rebootPending=RebootPending(),tailscaleInstalled=File.Exists(TailscaleExe),sshdState=serviceState,remoteAccessReady=false,controllerVerificationRequired=true}));return 0;
    }

    static string RuntimeDeviceBinding(string id,DateTime updatedAt) {
        return Json.Serialize(new{schemaVersion=1,phase="stage-zero",deviceId=id,
            updatedAt=updatedAt.ToString("o"),checkpoints=new[]{"preflight"}});
    }
    static int ConfigureNative(Dictionary<string,object> c,long expiry) {
        ValidateConfiguration(c,EpochMs(),expiry);
        if(Number(c,"expiresAt")-EpochMs()<180000)Stop("NATIVE_CONFIGURATION_TOO_CLOSE_TO_EXPIRY");
        dynamic policy=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2",true));
        if(!BlockPresent(policy)){NativeRecord("SSH_BLOCK_INTENT");BlockInbound();}NativeRecord("SSH_BLOCK_VERIFIED");
        string authPath=Path.Combine(NativeJournalRoot,"tailscale-auth-key");
        NewPrivateFile(authPath,Text(c,"tailscaleAuthKey"));
        NativeRecord("TAILSCALE_JOIN_INTENT");
        bool joinExited=false;
        try{RunFixed(TailscaleExe,"up --unattended --accept-routes=false --auth-key="+Q("file:"+authPath),120000);joinExited=true;}
        finally{if(joinExited)File.Delete(authPath);}
        string ip=TailnetAddress();NativeRecord("TAILSCALE_JOINED");
        // The accepted configuration authorized this attempt before expiry; the controller enforces token TTL.
        string endpoint=Text(c,"controllerBaseUrl"), id=Text(c,"deviceId");
        NativeRecord("EXCHANGE_INTENT");
        var exchange=Post(endpoint+"/exchange",new{protocolVersion=2,deviceId=id,token=Text(c,"enrollmentToken")});
        Exact(exchange,"protocolVersion","deviceId","sshPublicKey","completionTicket");
        if(Number(exchange,"protocolVersion")!=2||Text(exchange,"deviceId")!=id||!Regex.IsMatch(Text(exchange,"completionTicket"),"^[A-Za-z0-9_-]{43}$"))Stop("NATIVE_RESPONSE_INVALID");
        string publicKey=ValidatePublicKey(Text(exchange,"sshPublicKey"),id);
        NativeRecord("EXCHANGED");NativeUser();
        string keys=Path.Combine(NativeRoot,"ssh");Directory.CreateDirectory(keys,PrivateDirectoryAcl());
        NewPrivateFile(Path.Combine(keys,"authorized_keys"),publicKey+"\n");
        if(!Directory.Exists(SshRoot))CreateExclusivePrivateDirectory(SshRoot);
        TrustedWriteAcl(SshRoot);InspectEmptyDirectory(SshRoot);
        string hostKey=Path.Combine(SshRoot,"ssh_host_ed25519_key");NativeRecord("HOST_KEY_CREATE_INTENT");
        RunFixed(Path.Combine(Environment.SystemDirectory,@"OpenSSH\ssh-keygen.exe"),"-t ed25519 -f "+Q(hostKey)+" -N \"\"",60000);
        PrivateFile(hostKey);PrivateFile(hostKey+".pub");
        string config=Path.Combine(SshRoot,"sshd_config");
        NewPrivateFile(config,"Port 22\nListenAddress "+ip+"\nHostKey "+hostKey.Replace('\\','/')+"\nPubkeyAuthentication yes\nAuthenticationMethods publickey\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitEmptyPasswords no\nAllowUsers agentroad\nAuthorizedKeysFile "+Path.Combine(keys,"authorized_keys").Replace('\\','/')+"\nSubsystem sftp sftp-server.exe\n");
        string sshd=Path.Combine(Environment.SystemDirectory,@"OpenSSH\sshd.exe");RunFixed(sshd,"-t -f "+Q(config),30000);
        NativeRecord("SSH_CONFIGURATION_VALIDATED");
        // Preserve the existing core runtime's device-binding record format.
        // Native execution provenance remains in bootstrap-native/journal.jsonl.
        string bootstrap=Path.Combine(NativeRoot,"bootstrap");
        CreateExclusivePrivateDirectory(bootstrap);
        NewPrivateFile(Path.Combine(bootstrap,"stage-zero-journal.json"),RuntimeDeviceBinding(id,DateTime.UtcNow));
        NativeRecord("RUNTIME_DEVICE_BINDING_WRITTEN");
        NativeRecord("FIREWALL_SCOPE_INTENT");
        AddNativeRule(NativeOutsideBlock,0,"*","0.0.0.0-100.63.255.255,100.128.0.0-255.255.255.255,::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
        AddNativeRule(NativeAllow,1,ip,"100.64.0.0/10");
        if(!BlockPresent(policy))Stop("FIREWALL_BLOCK_UNCONFIRMED");
        NativeRecord("SERVICE_START_INTENT");
        TrustedWriteAcl(SshRoot);TrustedWriteAcl(config);TrustedWriteAcl(hostKey);TrustedWriteAcl(hostKey+".pub");
        RunFixed(Path.Combine(Environment.SystemDirectory,"sc.exe"),"config sshd start= auto depend= Tailscale",30000);
        RunFixed(Path.Combine(Environment.SystemDirectory,"sc.exe"),"failure sshd reset= 86400 actions= restart/5000/restart/10000/restart/30000",30000);
        RunFixed(Path.Combine(Environment.SystemDirectory,"sc.exe"),"failureflag sshd 1",30000);
        using(var service=new ServiceController("sshd")){service.Start();service.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(30));}
        int listeners=0;var listenerWait=Stopwatch.StartNew();
        do {
            listeners=0;
            foreach(var ep in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners())if(ep.Port==22){if(ep.Address.ToString()!=ip)Stop("UNEXPECTED_SSH_LISTENER");listeners++;}
            if(listeners==1)break;Thread.Sleep(200);
        } while(listenerWait.ElapsedMilliseconds<10000);
        if(listeners!=1)Stop("SSH_LISTENER_UNCONFIRMED");
        NativeRecord("SCOPED_LISTENER_VERIFIED");
        // Remove only the known prerequisite block after fixed policy and listener validation.
        foreach(int profile in new[]{1,2,4})if(!(bool)policy.FirewallEnabled[profile])Stop("FIREWALL_DISABLED");
        VerifyNativeRule(NativeOutsideBlock,0,"*","0.0.0.0-100.63.255.255,100.128.0.0-255.255.255.255,::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
        VerifyNativeRule(NativeAllow,1,ip,"100.64.0.0/10");
        policy.Rules.Remove(RuleName);
        foreach(dynamic rule in policy.Rules)if((string)rule.Name==RuleName)Stop("SSH_BLOCK_RELEASE_UNCONFIRMED");
        VerifyNativeRule(NativeOutsideBlock,0,"*","0.0.0.0-100.63.255.255,100.128.0.0-255.255.255.255,::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
        VerifyNativeRule(NativeAllow,1,ip,"100.64.0.0/10");
        NativeRecord("SSH_BLOCK_RELEASED");
        string hostPublic=File.ReadAllText(hostKey+".pub").Trim();string[] parts=hostPublic.Split(' ');
        if(parts.Length<2||parts[0]!="ssh-ed25519")Stop("NATIVE_SSH_KEY_INVALID");
        string canonicalHost=parts[0]+" "+parts[1];string fingerprint;
        using(var sha=SHA256.Create())fingerprint="SHA256:"+Convert.ToBase64String(sha.ComputeHash(Convert.FromBase64String(parts[1]))).TrimEnd('=');
        int build=NativeBuild;string edition=NativeEdition;
        var completion=new{protocolVersion=2,deviceId=id,completionTicket=Text(exchange,"completionTicket"),target=new{version="10.0."+build,build=build,edition=edition,architecture="AMD64"},tailscaleAddresses=new[]{ip},sshHostKeys=new[]{canonicalHost},sshHostKeyFingerprints=new[]{fingerprint},checkpoints=new[]{"preflight","tailscale","openssh","account","firewall"}};
        // Retain the exact body privately for reconciliation; never retry automatically.
        NewPrivateFile(Path.Combine(NativeJournalRoot,"completion.json"),Json.Serialize(completion));
        NativeRecord("COMPLETION_INTENT");var accepted=Post(endpoint+"/complete",completion);
        Exact(accepted,"protocolVersion","deviceId","accepted");
        if(Number(accepted,"protocolVersion")!=2||Text(accepted,"deviceId")!=id||!(accepted["accepted"] is bool)||!(bool)accepted["accepted"])Stop("NATIVE_RESPONSE_INVALID");
        NativeRecord("COMPLETION_ACCEPTED");Emit("NATIVE_CONFIGURED_AWAIT_CONTROLLER_VERIFICATION",null);return 0;
    }
}
