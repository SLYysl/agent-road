using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

internal static partial class Program {
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
    struct TrustFile { public uint size; public string path; public IntPtr handle; public IntPtr subject; }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
    struct TrustData { public uint size; public IntPtr callback; public IntPtr client; public uint ui; public uint revocation; public uint choice; public IntPtr file; public uint stateAction; public IntPtr state; public IntPtr url; public uint flags; public uint context; public IntPtr signature; }
    [DllImport("wintrust.dll",ExactSpelling=true,CharSet=CharSet.Unicode)] static extern int WinVerifyTrust(IntPtr window,ref Guid action,ref TrustData data);
    static void VerifyTailscaleSignature(string path) {
        var file=new TrustFile{size=(uint)Marshal.SizeOf(typeof(TrustFile)),path=path};
        IntPtr pointer=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TrustFile)));
        try {
            Marshal.StructureToPtr(file,pointer,false);
            var data=new TrustData{size=(uint)Marshal.SizeOf(typeof(TrustData)),ui=2,choice=1,file=pointer};
            var action=new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
            if(WinVerifyTrust(new IntPtr(-1),ref action,ref data)!=0)Stop("TAILSCALE_SIGNATURE_UNTRUSTED");
            using(var certificate=new X509Certificate2(X509Certificate.CreateFromSignedFile(path)))
                if(certificate.GetNameInfo(X509NameType.SimpleName,false)!="Tailscale Inc.")Stop("TAILSCALE_PUBLISHER_INVALID");
        } finally { Marshal.DestroyStructure(pointer,typeof(TrustFile));Marshal.FreeHGlobal(pointer); }
    }
    static int InstallTailscale(bool resumeDownload=false) {
        if(!IsAdmin())Stop("ADMIN_REQUIRED");
        if(RebootPending())Stop("REBOOT_REQUIRED");
        if(File.Exists(TailscaleExe)){TrustedWriteAcl(TailscaleExe);VerifyTailscaleSignature(TailscaleExe);Emit("TAILSCALE_ALREADY_PRESENT",null);return 0;}
        string directory=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"AgentRoadNativeTailscalePrerequisite");
        if(resumeDownload) {
            TrustedWriteAcl(directory);
            var entries=Directory.GetFileSystemEntries(directory);
            string attempt=Path.Combine(directory,"attempt.json");
            if(entries.Length!=1 || entries[0]!=attempt)Stop("TAILSCALE_RESUME_NOT_DOWNLOAD_ONLY");
            TrustedWriteAcl(attempt);
            if(new FileInfo(attempt).Length>4096)Stop("TAILSCALE_JOURNAL_INVALID");
            var prior=ParseJson(File.ReadAllText(attempt));
            Exact(prior,"schemaVersion","state","remoteAccessReady");
            if(Number(prior,"schemaVersion")!=1 || Text(prior,"state")!="DOWNLOAD_INTENT"
                || !(prior["remoteAccessReady"] is bool) || (bool)prior["remoteAccessReady"])Stop("TAILSCALE_JOURNAL_INVALID");
        } else {
            if(File.Exists(directory)||Directory.Exists(directory))Stop("PRIOR_TAILSCALE_ATTEMPT_REQUIRES_INSPECTION");
            CreateExclusivePrivateDirectory(directory);
        }
        string path=Path.Combine(directory,"tailscale-setup-full-1.98.9.exe");
        if(!resumeDownload)NewPrivateFile(Path.Combine(directory,"attempt.json"),Json.Serialize(new{schemaVersion=1,state="DOWNLOAD_INTENT",remoteAccessReady=false}));
        // .NET Framework captures SecurityProtocol when the request is constructed.
        ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;
        var request=(HttpWebRequest)WebRequest.Create("https://pkgs.tailscale.com/stable/tailscale-setup-full-1.98.9.exe");
        request.Timeout=30000;request.ReadWriteTimeout=30000;request.AllowAutoRedirect=false;
        using(var response=(HttpWebResponse)request.GetResponse()) {
            if(response.StatusCode!=HttpStatusCode.OK)Stop("TAILSCALE_DOWNLOAD_FAILED");
            using(var source=response.GetResponseStream())using(var dest=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {
                var bytes=new byte[65536];int count;var elapsed=Stopwatch.StartNew();
                while((count=source.Read(bytes,0,bytes.Length))>0){if(dest.Length+count>200*1024*1024||elapsed.ElapsedMilliseconds>600000)Stop("TAILSCALE_DOWNLOAD_LIMIT");dest.Write(bytes,0,count);}dest.Flush(true);
            }
        }
        PrivateFile(path);string hash;using(var sha=SHA256.Create())using(var file=File.OpenRead(path))hash=BitConverter.ToString(sha.ComputeHash(file)).Replace("-","").ToLowerInvariant();
        if(hash!="b3f7e15eb33b90f0686d6037453a0c680c3553b55deca649b56b6b05635c9e7b")Stop("TAILSCALE_HASH_MISMATCH");
        VerifyTailscaleSignature(path);
        NewPrivateFile(Path.Combine(directory,"install-intent.json"),Json.Serialize(new{schemaVersion=1,state="INSTALL_INTENT",sha256=hash}));
        // Fixed official installer; timeout never kills it or repeats installation.
        try {
            LastNativeOperation=Path.GetFileName(path);LastNativeExitCode=null;
            using(var process=Process.Start(new ProcessStartInfo(path,"/quiet /norestart"){UseShellExecute=false,CreateNoWindow=true})) {
                if(!process.WaitForExit(600000))Stop("NATIVE_OPERATION_UNCERTAIN_DO_NOT_REPLAY");
                LastNativeExitCode=process.ExitCode;if(process.ExitCode!=0)Stop("NATIVE_OPERATION_FAILED");
            }
        }
        catch(InvalidOperationException) {
            if(LastNativeExitCode!=3010)throw;
            NewPrivateFile(Path.Combine(directory,"reboot-required.json"),Json.Serialize(new{schemaVersion=1,state="REBOOT_REQUIRED",installerExitCode=3010}));
            Emit("REBOOT_REQUIRED",null);return 3;
        }
        if(!File.Exists(TailscaleExe))Stop("TAILSCALE_INSTALL_POSTCONDITION_FAILED");
        TrustedWriteAcl(TailscaleExe);VerifyTailscaleSignature(TailscaleExe);
        bool reboot=RebootPending();
        NewPrivateFile(Path.Combine(directory,"installed.json"),Json.Serialize(new{schemaVersion=1,state="INSTALLED",rebootPending=reboot,remoteAccessReady=false}));
        Emit(reboot?"REBOOT_REQUIRED":"TAILSCALE_INSTALLED",null);return reboot?3:0;
    }
}
