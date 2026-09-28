using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace AgentRoadRetention {
 [StructLayout(LayoutKind.Sequential)] public struct FileId { public ulong Volume; [MarshalAs(UnmanagedType.ByValArray,SizeConst=16)] public byte[] Id; }
 [StructLayout(LayoutKind.Sequential)] public struct Tag { public uint Attributes; public uint ReparseTag; }
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct RenameInfo { public uint Flags; public IntPtr Root; public uint Length; public char Name; }
 [StructLayout(LayoutKind.Sequential)] public struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int Inherit; }
 public static class Native {
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text,uint revision,out IntPtr descriptor,out uint size);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateDirectoryW(string path,ref SecurityAttributes attributes);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
  public static void CreateRestrictedDirectory(string path) {
   IntPtr descriptor; uint length;
   if(!ConvertStringSecurityDescriptorToSecurityDescriptorW("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",1,out descriptor,out length))throw new IOException("DIRECTORY_SECURITY");
   try { SecurityAttributes attributes=new SecurityAttributes();attributes.Length=Marshal.SizeOf(typeof(SecurityAttributes));attributes.Descriptor=descriptor;
    if(!CreateDirectoryW(path,ref attributes))throw new IOException("DIRECTORY_CREATE_"+Marshal.GetLastWin32Error());
   }finally{LocalFree(descriptor);}
  }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,int info,out FileId value,uint size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,int info,out Tag value,uint size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle handle,int info,IntPtr value,uint size);
  public static SafeFileHandle Open(string path,bool directory,bool rename) {
   uint access=directory?0x81u:0x80000000u; if(rename)access|=0x10000u;
   SafeFileHandle h=CreateFileW(path,access,directory?3u:1u,IntPtr.Zero,3,0x00200000u|(directory?0x02000000u:0u),IntPtr.Zero);
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
