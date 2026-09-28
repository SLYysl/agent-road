using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Threading;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace AgentRoad {
  public sealed class BackgroundResult {
    public string Status;
    public int? ExitCode;
  }
  public static class BackgroundRunner {
    [StructLayout(LayoutKind.Sequential)] struct Limits {
      public long ProcessTime, JobTime;
      public uint Flags;
      public UIntPtr Minimum, Maximum;
      public uint Active;
      public UIntPtr Affinity;
      public uint Priority, Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] struct Accounting {
      public long User, Kernel, PeriodUser, PeriodKernel;
      public uint Faults, Total, Active, Terminated;
    }
    [StructLayout(LayoutKind.Sequential)] struct IOCounts {
      public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes;
    }
    [StructLayout(LayoutKind.Sequential)] struct Extended {
      public Limits Basic;
      public IOCounts IO;
      public UIntPtr ProcessMemory, JobMemory, PeakProcess, PeakJob;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Startup {
      public int Size;
      public string Reserved, Desktop, Title;
      public int X,Y,XSize,YSize,XCount,YCount,Fill,Flags;
      public short Show,ReservedSize;
      public IntPtr Reserved2, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo {
      public IntPtr Process, Thread;
      public uint Pid,Tid;
    }
    [StructLayout(LayoutKind.Sequential)] struct Security {
      public int Length;
      public IntPtr Descriptor;
      public int Inherit;
    }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr a,string n);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr j,int c,ref Extended i,uint l);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr j,int c,out Accounting info,uint size,IntPtr returned);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr j,IntPtr p);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr j,uint c);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr p,uint c);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,StringBuilder cmd,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref Startup s,out ProcessInfo p);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFile(string path,uint access,uint share,ref Security sa,uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr t);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h,uint ms);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr p,out uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    static void Check(bool result) { if(!result)throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static IntPtr FileHandle(string path,uint access,uint creation) {
      var sa=new Security {Length=Marshal.SizeOf(typeof(Security)),Inherit=1};
      var h=CreateFile(path,access,3,ref sa,creation,128,IntPtr.Zero);
      if(h==new IntPtr(-1))throw new Win32Exception(Marshal.GetLastWin32Error());
      return h;
    }
    public static BackgroundResult Run(string dir,int seconds) {
      IntPtr job=IntPtr.Zero,output=IntPtr.Zero,error=IntPtr.Zero,input=IntPtr.Zero;
      var process=new ProcessInfo();
      bool assigned=false;
      try {
        job=CreateJobObject(IntPtr.Zero,null);Check(job!=IntPtr.Zero);
        var limits=new Extended();limits.Basic.Flags=0x2000; // Kill all members when the last handle closes.
        Check(SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf(typeof(Extended))));
        output=FileHandle(Path.Combine(dir,"stdout.log"),0x40000000,1);
        error=FileHandle(Path.Combine(dir,"stderr.log"),0x40000000,1);
        input=FileHandle("NUL",0x80000000,3);
        var startup=new Startup {Size=Marshal.SizeOf(typeof(Startup)),Flags=0x100,Input=input,Output=output,Error=error};
        string exe=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),@"WindowsPowerShell\v1.0\powershell.exe");
        var command=new StringBuilder("\""+exe+"\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \""+Path.Combine(dir,"task.ps1")+"\"");
        // The task cannot execute until containment is installed successfully.
        Check(CreateProcess(exe,command,IntPtr.Zero,IntPtr.Zero,true,0x08000004,IntPtr.Zero,dir,ref startup,out process));
        Check(AssignProcessToJobObject(job,process.Process));assigned=true;
        Check(ResumeThread(process.Thread)!=UInt32.MaxValue);
        CloseHandle(process.Thread);process.Thread=IntPtr.Zero;
        CloseHandle(output);output=IntPtr.Zero;CloseHandle(error);error=IntPtr.Zero;CloseHandle(input);input=IntPtr.Zero;
        var clock=Stopwatch.StartNew();
        string status=null;uint code=0;
        while(true) {
          uint wait=WaitForSingleObject(process.Process,100);
          if(wait==0){Check(GetExitCodeProcess(process.Process,out code));status=code==0?"SUCCEEDED":"FAILED";break;}
          if(wait!=258)throw new Win32Exception();
          if(File.Exists(Path.Combine(dir,"cancel.request")))status="CANCELLED";
          else if(clock.Elapsed.TotalSeconds>=seconds)status="TIMED_OUT";
          else if(new FileInfo(Path.Combine(dir,"stdout.log")).Length+new FileInfo(Path.Combine(dir,"stderr.log")).Length>4*1024*1024)status="OUTPUT_LIMIT";
          if(status!=null){Check(TerminateJobObject(job,1));Check(WaitForSingleObject(process.Process,10000)==0);break;}
        }
        if(new FileInfo(Path.Combine(dir,"stdout.log")).Length+new FileInfo(Path.Combine(dir,"stderr.log")).Length>4*1024*1024)status="OUTPUT_LIMIT";
        // Also dispose descendants left behind by a script which exited normally.
        Check(TerminateJobObject(job,1));
        var stopped=Stopwatch.StartNew();
        while(true) {
          Accounting accounting;
          Check(QueryInformationJobObject(job,1,out accounting,(uint)Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero));
          if(accounting.Active==0)break;
          if(stopped.Elapsed.TotalSeconds>10)throw new Exception("JOB_STOP_UNCERTAIN");
          Thread.Sleep(50);
        }
        return new BackgroundResult {Status=status,ExitCode=(status=="SUCCEEDED"||status=="FAILED")?(int?)unchecked((int)code):null};
      } finally {
        if(process.Process!=IntPtr.Zero&&!assigned)TerminateProcess(process.Process,1);
        if(job!=IntPtr.Zero)CloseHandle(job);
        if(process.Thread!=IntPtr.Zero)CloseHandle(process.Thread);
        if(process.Process!=IntPtr.Zero)CloseHandle(process.Process);
        if(output!=IntPtr.Zero)CloseHandle(output);
        if(error!=IntPtr.Zero)CloseHandle(error);
        if(input!=IntPtr.Zero)CloseHandle(input);
      }
    }
  }
}
