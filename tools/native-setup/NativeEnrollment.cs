using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

internal static partial class Program {
    const string PairOrigin = "https://agent-road.brahma-technologies.com";
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 65536, RecursionLimit = 12 };
    static readonly DateTime Epoch=new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc);
    static Stopwatch PairClock;
    static long PairServerEpoch;
    static long EpochMs() { return PairClock==null ? (long)(DateTime.UtcNow-Epoch).TotalMilliseconds : PairServerEpoch+PairClock.ElapsedMilliseconds; }
    static DateTime ServerDate(string text) {
        DateTime server;
        if(!DateTime.TryParseExact(text,"r",System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AdjustToUniversal|System.Globalization.DateTimeStyles.AssumeUniversal,out server))Stop("NATIVE_CLOCK_UNVERIFIED");
        return server;
    }
    static long ServerAnchor(string date,DateTime local,long requestDuration) {
        var server=ServerDate(date);
        if(Math.Abs((local-server).TotalSeconds)>300)Stop("NATIVE_CLOCK_SKEW_SYNC_WINDOWS_TIME");
        // HTTP Date is second precision. Round forward and include request latency,
        // so a slow response cannot extend the server's fixed expiry.
        return (long)(server-Epoch).TotalMilliseconds+1000+requestDuration;
    }
    static string RandomToken() { var b = new byte[32]; using(var r = RandomNumberGenerator.Create()) r.GetBytes(b); return Convert.ToBase64String(b).TrimEnd('=').Replace('+','-').Replace('/','_'); }
    static void Exact(Dictionary<string,object> o, params string[] fields) {
        if (o == null || o.Count != fields.Length) Stop("NATIVE_RESPONSE_INVALID");
        foreach(string field in fields) if (!o.ContainsKey(field)) Stop("NATIVE_RESPONSE_INVALID");
    }
    static string Text(Dictionary<string,object> o, string key) { object v; if (!o.TryGetValue(key,out v) || !(v is string)) Stop("NATIVE_RESPONSE_INVALID"); return (string)v; }
    static long Number(Dictionary<string,object> o, string key) { object v; if (!o.TryGetValue(key,out v) || (!(v is int) && !(v is long))) Stop("NATIVE_RESPONSE_INVALID"); return Convert.ToInt64(v); }
    // Validate JSON grammar first, then independently reject duplicate object keys at every depth.
    static Dictionary<string,object> ParseJson(string text) {
        var result = Json.DeserializeObject(text) as Dictionary<string,object>;
        int offset = 0; ScanJson(text,ref offset); Space(text,ref offset);
        if (result == null || offset != text.Length) Stop("NATIVE_RESPONSE_INVALID");
        return result;
    }
    static void Space(string s, ref int p) { while(p<s.Length && " \r\n\t".IndexOf(s[p])>=0) p++; }
    static string ScanString(string s, ref int p) {
        int start=p++;
        while(p<s.Length) { char c=s[p++]; if(c=='"') return Json.Deserialize<string>(s.Substring(start,p-start)); if(c=='\\') p++; }
        Stop("NATIVE_RESPONSE_INVALID"); return null;
    }
    static void ScanJson(string s, ref int p) {
        Space(s,ref p); if(p>=s.Length) Stop("NATIVE_RESPONSE_INVALID");
        if(s[p]=='"') { ScanString(s,ref p); return; }
        if(s[p]=='{') {
            p++; Space(s,ref p); var keys=new HashSet<string>(StringComparer.Ordinal);
            if(s[p]=='}') {p++;return;}
            while(p<s.Length) {
                if(s[p]!='"' || !keys.Add(ScanString(s,ref p))) Stop("NATIVE_RESPONSE_INVALID");
                Space(s,ref p); if(s[p++]!=':') Stop("NATIVE_RESPONSE_INVALID"); ScanJson(s,ref p); Space(s,ref p);
                if(s[p]=='}') {p++;return;} if(s[p++]!=',') Stop("NATIVE_RESPONSE_INVALID"); Space(s,ref p);
            }
        } else if(s[p]=='[') {
            p++; Space(s,ref p); if(s[p]==']'){p++;return;}
            while(p<s.Length) { ScanJson(s,ref p); Space(s,ref p); if(s[p]==']'){p++;return;} if(s[p++]!=',') Stop("NATIVE_RESPONSE_INVALID"); }
        } else { while(p<s.Length && ",]} \r\n\t".IndexOf(s[p])<0)p++; return; }
        Stop("NATIVE_RESPONSE_INVALID");
    }
    static Dictionary<string,object> Post(string url, object body) {
        byte[] bytes=Encoding.UTF8.GetBytes(Json.Serialize(body));
        ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;
        ServicePointManager.Expect100Continue=false;
        var req=(HttpWebRequest)WebRequest.Create(url);
        req.Method="POST"; req.ContentType="application/json"; req.ContentLength=bytes.Length;
        req.AllowAutoRedirect=false; req.Timeout=20000; req.ReadWriteTimeout=20000; req.KeepAlive=false;
        var requestClock=Stopwatch.StartNew();
        try {
            using(var stream=req.GetRequestStream()) stream.Write(bytes,0,bytes.Length);
            using(var response=(HttpWebResponse)req.GetResponse()) {
                if(response.StatusCode!=HttpStatusCode.OK || !(response.ContentType??"").StartsWith("application/json",StringComparison.OrdinalIgnoreCase)) Stop("NATIVE_RESPONSE_INVALID");
                if(url==PairOrigin+"/v2/claim") {
                    PairServerEpoch=ServerAnchor(response.Headers["Date"],DateTime.UtcNow,requestClock.ElapsedMilliseconds);
                    PairClock=Stopwatch.StartNew();
                }
                using(var stream=response.GetResponseStream()) using(var output=new MemoryStream()) {
                    var buffer=new byte[4096]; int count; var elapsed=Stopwatch.StartNew();
                    while((count=stream.Read(buffer,0,buffer.Length))>0) { if(output.Length+count>65536 || elapsed.ElapsedMilliseconds>20000) Stop("NATIVE_RESPONSE_INVALID"); output.Write(buffer,0,count); }
                    return ParseJson(new UTF8Encoding(false,true).GetString(output.ToArray()));
                }
            }
        } catch(WebException error) {
            using(var response=error.Response as HttpWebResponse) {
                if(response!=null && (int)response.StatusCode>=400 && (int)response.StatusCode<500)Stop("NATIVE_REQUEST_REJECTED_DO_NOT_REPLAY");
            }
            Stop("NATIVE_REQUEST_UNCERTAIN_DO_NOT_REPLAY");return null;
        } catch(InvalidOperationException) { throw; }
        catch(Exception) {Stop("NATIVE_REQUEST_UNCERTAIN_DO_NOT_REPLAY");return null;}
        finally { Array.Clear(bytes,0,bytes.Length); }
    }
    static void ValidateConfiguration(Dictionary<string,object> c, long now, long invitationExpiry) {
        Exact(c,"schemaVersion","kind","pairingOrigin","deviceId","controllerBaseUrl","enrollmentToken","tailscaleAuthKey","expiresAt");
        if(Number(c,"schemaVersion")!=2 || Text(c,"kind")!="agent-road-native-enrollment" || Text(c,"pairingOrigin")!=PairOrigin) Stop("NATIVE_CONFIGURATION_INVALID");
        string id=Text(c,"deviceId"); string endpoint=Text(c,"controllerBaseUrl"); Uri uri;
        if(!Regex.IsMatch(id,"^dev_[a-f0-9]{32}$") || endpoint.Length>2048 || !Uri.TryCreate(endpoint,UriKind.Absolute,out uri)
            || uri.Scheme!="https" || uri.UserInfo!="" || !uri.IsDefaultPort || uri.Query!="" || uri.Fragment!=""
            || !Regex.IsMatch(uri.Host,"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\\.ts\\.net$")
            || endpoint!="https://"+uri.Host+"/agent-road/v1/"+id) Stop("NATIVE_CONFIGURATION_INVALID");
        if(!Regex.IsMatch(Text(c,"enrollmentToken"),"^[A-Za-z0-9_-]{43}$") || !Regex.IsMatch(Text(c,"tailscaleAuthKey"),"^tskey-auth-[A-Za-z0-9_-]{10,500}$")) Stop("NATIVE_CONFIGURATION_INVALID");
        long expiry=Number(c,"expiresAt"); if(expiry<=now || expiry>invitationExpiry || expiry-now>600000) Stop("NATIVE_CONFIGURATION_EXPIRED");
    }
    static string ValidatePublicKey(string text, string id) {
        var match=Regex.Match(text,"^ssh-ed25519 ([A-Za-z0-9+/]+={0,2}) agent-road:"+Regex.Escape(id)+"$");
        if(!match.Success) Stop("NATIVE_SSH_KEY_INVALID");
        byte[] blob=Convert.FromBase64String(match.Groups[1].Value);
        byte[] prefix={0,0,0,11,115,115,104,45,101,100,50,53,53,49,57,0,0,0,32};
        if(blob.Length!=51 || Convert.ToBase64String(blob)!=match.Groups[1].Value) Stop("NATIVE_SSH_KEY_INVALID");
        for(int i=0;i<prefix.Length;i++) if(blob[i]!=prefix[i]) Stop("NATIVE_SSH_KEY_INVALID");
        return text;
    }
    static bool NativeSelfTest() {
        var fixedTime=new DateTime(2026,9,22,12,0,0,DateTimeKind.Utc);
        string date=fixedTime.ToString("r",System.Globalization.CultureInfo.InvariantCulture);
        if(ServerAnchor(date,fixedTime.AddMinutes(-3),200)!=(long)(fixedTime-Epoch).TotalMilliseconds+1200)return false;
        bool clockRefused=false;try{ServerAnchor(date,fixedTime.AddMinutes(-6),0);}catch{clockRefused=true;}if(!clockRefused)return false;
        clockRefused=false;try{ServerAnchor("invalid",fixedTime,0);}catch{clockRefused=true;}if(!clockRefused)return false;
        long now=EpochMs();
        var c=ParseJson(Json.Serialize(new {schemaVersion=2,kind="agent-road-native-enrollment",pairingOrigin=PairOrigin,deviceId="dev_"+new string('a',32),controllerBaseUrl="https://controller.example.ts.net/agent-road/v1/dev_"+new string('a',32),enrollmentToken=new string('a',43),tailscaleAuthKey="tskey-auth-"+new string('b',20),expiresAt=now+60000}));
        ValidateConfiguration(c,now,now+60000);
        foreach(string bad in new[]{"{\"a\":1,\"a\":2}","{\"x\":{\"a\":1,\"\\u0061\":2}}"}) {
            bool refused=false;try{ParseJson(bad);}catch{refused=true;}if(!refused)return false;
        }
        c["controllerBaseUrl"]="https://evil.example/agent-road/v1/dev_"+new string('a',32);
        bool invalid=false;try{ValidateConfiguration(c,now,now+60000);}catch{invalid=true;}return invalid;
    }
    static void CheckPairClock() {
        ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;
        var request=(HttpWebRequest)WebRequest.Create(PairOrigin+"/");
        request.Method="HEAD";request.AllowAutoRedirect=false;request.Timeout=20000;
        using(var response=(HttpWebResponse)request.GetResponse()) {
            ServerAnchor(response.Headers["Date"],DateTime.UtcNow,0);
        }
    }
    static int NativePair(string code) {
        if(!IsAdmin()) Stop("ADMIN_REQUIRED");
        if(!Regex.IsMatch(code,"^[A-HJ-NP-Z2-9]{12}$")) Stop("PAIR_INPUT_INVALID");
        NativePreflight();
        CheckPairClock();
        Console.Error.WriteLine("This grants the approved controller administrator remote command/file access. Tailscale will join its network. Type YES to continue:");
        if(Console.ReadLine()!="YES") Stop("PAIR_CONSENT_DECLINED");
        CreateNativeJournal();
        try {
            NativeRecord("CLAIM_INTENT");
            string clientToken=RandomToken(); var claimBody=new {code=code,clientToken=clientToken};
            var claim=Post(PairOrigin+"/v2/claim",claimBody); Exact(claim,"state","verification","expiresAt");
            if(Text(claim,"state")!="CLAIMED" || !Regex.IsMatch(Text(claim,"verification"),"^[0-9]{8}$")) Stop("NATIVE_RESPONSE_INVALID");
            long expiry=Number(claim,"expiresAt"); if(expiry<=EpochMs() || expiry-EpochMs()>600000) Stop("NATIVE_CONFIGURATION_EXPIRED");
            Console.WriteLine("Verify this code on your Mac: "+Text(claim,"verification"));
            NativeRecord("CLAIMED"); Dictionary<string,object> configuration=null;
            var timer=Stopwatch.StartNew();
            while(timer.ElapsedMilliseconds<600000 && EpochMs()<expiry) {
                var delivery=Post(PairOrigin+"/v2/receive",claimBody);
                if(Text(delivery,"state")=="PENDING") {Exact(delivery,"state");Thread.Sleep(2000);continue;}
                Exact(delivery,"state","protocolVersion","configuration");
                if(Text(delivery,"state")!="DELIVERED" || Number(delivery,"protocolVersion")!=2) Stop("NATIVE_RESPONSE_INVALID");
                configuration=delivery["configuration"] as Dictionary<string,object>;
                ValidateConfiguration(configuration,EpochMs(),expiry); break;
            }
            if(configuration==null) Stop("PAIR_EXPIRED");
            NativeRecord("CONFIGURATION_RECEIVED");
            return ConfigureNative(configuration,expiry);
        } catch { try {NativeRecord("STOPPED_REQUIRES_INSPECTION");}catch{} throw; }
    }
}
