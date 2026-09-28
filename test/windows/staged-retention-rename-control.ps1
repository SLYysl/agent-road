$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace AgentRoadRetention {
 [StructLayout(LayoutKind.Sequential)] public struct FileId { public ulong Volume; [MarshalAs(UnmanagedType.ByValArray,SizeConst=16)] public byte[] Id; }
 [StructLayout(LayoutKind.Sequential)] public struct Tag { public uint Attributes; public uint ReparseTag; }
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct RenameInfo { public uint Flags; public IntPtr Root; public uint Length; public char Name; }
 public static class Native {
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,int info,out FileId value,uint size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,int info,out Tag value,uint size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle handle,int info,IntPtr value,uint size);
  public static SafeFileHandle Open(string path,bool directory,bool rename) {
   uint access=directory?0x81u:0x80000000u; if(rename)access|=0x10000u;
   SafeFileHandle h=CreateFileW(path,access,directory?3u:5u,IntPtr.Zero,3,0x00200000u|(directory?0x02000000u:0u),IntPtr.Zero);
   if(h.IsInvalid){h.Dispose();throw new IOException("OPEN_"+Marshal.GetLastWin32Error());}
   try { Tag t; if(!GetFileInformationByHandleEx(h,9,out t,(uint)Marshal.SizeOf(typeof(Tag))) || (t.Attributes&0x400)!=0 || ((t.Attributes&0x10)!=0)!=directory)throw new IOException("NODE_TYPE");return h; }catch{h.Dispose();throw;}
  }
  public static string Identity(SafeFileHandle h) { FileId id;if(!GetFileInformationByHandleEx(h,18,out id,(uint)Marshal.SizeOf(typeof(FileId))))throw new IOException("IDENTITY");return id.Volume.ToString("X16")+":"+BitConverter.ToString(id.Id).Replace("-",""); }
  public static void Rename(SafeFileHandle h,string destination) {
   if(IntPtr.Size!=8 || Path.GetFullPath(destination)!=destination)throw new IOException("PATH");
   byte[] name=Encoding.Unicode.GetBytes(destination);int offset=(int)Marshal.OffsetOf(typeof(RenameInfo),"Name");int size=offset+name.Length+2;
   IntPtr buffer=Marshal.AllocHGlobal(size);
   try {for(int i=0;i<size;i++)Marshal.WriteByte(buffer,i,0);Marshal.WriteInt32(buffer,(int)Marshal.OffsetOf(typeof(RenameInfo),"Length"),name.Length);Marshal.Copy(name,0,IntPtr.Add(buffer,offset),name.Length);if(!SetFileInformationByHandle(h,3,buffer,(uint)size))throw new IOException("RENAME_"+Marshal.GetLastWin32Error());}finally{Marshal.FreeHGlobal(buffer);}
  }
 }
}
'@

$root=Join-Path $env:TEMP ('agent-road-retention-control-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($root)
$results=@{}
try {
 foreach($scenario in @('closed-child','destination-conflict','source-replacement','changed-child')) {
  $case=Join-Path $root $scenario;$source=Join-Path $case 'source';$target=Join-Path $case 'target'
  $null=[IO.Directory]::CreateDirectory($source)
  $data=Join-Path $source 'data';[IO.File]::WriteAllText($data,'original')
  $dir=$null;$file=$null
  try {
   $dir=[AgentRoadRetention.Native]::Open($source,$true,$true)
   $file=[AgentRoadRetention.Native]::Open($data,$false,$false)
   $dirId=[AgentRoadRetention.Native]::Identity($dir);$fileId=[AgentRoadRetention.Native]::Identity($file)
   $before=(Get-FileHash -LiteralPath $data -Algorithm SHA256).Hash
   $file.Dispose();$file=$null
   if($scenario -ceq 'destination-conflict') {
    $null=[IO.Directory]::CreateDirectory($target);[IO.File]::WriteAllText((Join-Path $target 'sentinel'),'keep')
    $rejected=$false;try{[AgentRoadRetention.Native]::Rename($dir,$target)}catch{$rejected=$true}
    $results[$scenario]=($rejected -and [IO.File]::ReadAllText($data) -ceq 'original' -and [IO.File]::ReadAllText((Join-Path $target 'sentinel')) -ceq 'keep')
   } elseif($scenario -ceq 'source-replacement') {
    $rejected=$false;try{[IO.Directory]::Move($source,(Join-Path $case 'foreign'))}catch{$rejected=$true}
    $results[$scenario]=($rejected -and $dirId -ceq [AgentRoadRetention.Native]::Identity($dir))
   } else {
    if($scenario -ceq 'changed-child'){[IO.File]::WriteAllText($data,'changed')}
    [AgentRoadRetention.Native]::Rename($dir,$target)
    $file=[AgentRoadRetention.Native]::Open((Join-Path $target 'data'),$false,$false)
    $identity=($dirId -ceq [AgentRoadRetention.Native]::Identity($dir) -and $fileId -ceq [AgentRoadRetention.Native]::Identity($file))
    $content=($before -ceq (Get-FileHash -LiteralPath (Join-Path $target 'data') -Algorithm SHA256).Hash)
    $results[$scenario]=($identity -and ($content -eq ($scenario -ceq 'closed-child')))
   }
  } finally {if($null-ne$file){$file.Dispose()};if($null-ne$dir){$dir.Dispose()}}
 }
 [Console]::Out.Write((@{isolated=$true;cases=$results;allPassed=(@($results.Values|Where-Object{$_ -ne $true}).Count -eq 0)}|ConvertTo-Json -Compress))
} catch {[Console]::Out.Write('{"isolated":true,"failed":true}')} finally {[IO.Directory]::Delete($root,$true)}
