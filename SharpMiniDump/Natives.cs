using System;
using System.Runtime.InteropServices;

namespace SharpMiniDump
{
    class Natives
    {
        public const int FILE_MAP_READ =  0x0004;
        public const int FILE_READ_DATA = 0x0001;     // file & pipe
        public const int FILE_WRITE_DATA = 0x0002;     // file & pipe
        public const int FILE_APPEND_DATA = 0x0004;     // file
        public const int FILE_READ_EA = 0x0008;     // file & directory
        public const int FILE_WRITE_EA = 0x0010;     // file & directory
        public const int FILE_READ_ATTRIBUTES = 0x0080;     // all
        public const int FILE_WRITE_ATTRIBUTES = 0x0100;     // all
        public const int FILE_OVERWRITE_IF = 0x00000005;
        public const int FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
        public const int MAXIMUM_ALLOWED = 0x02000000;

        public const long READ_CONTROL = 0x00020000;
        public const long SYNCHRONIZE = 0x00100000;
        public const long STANDARD_RIGHTS_WRITE = READ_CONTROL;

        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY = 0x0008;
        public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
        public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
        public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
        public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
        public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID);

        public const UInt32 SE_PRIVILEGE_ENABLED = 0x2;

        public const long FILE_GENERIC_READ = STANDARD_RIGHTS_READ |
          FILE_READ_DATA |
          FILE_READ_ATTRIBUTES |
          FILE_READ_EA |
          SYNCHRONIZE;

        public const long FILE_GENERIC_WRITE = STANDARD_RIGHTS_WRITE |
          FILE_WRITE_DATA |
          FILE_WRITE_ATTRIBUTES |
          FILE_WRITE_EA |
          FILE_APPEND_DATA |
          SYNCHRONIZE;
                
        public const int FILE_ATTRIBUTE_NORMAL = 0x00000080;

        public struct WIN_VER_INFO
        {
            public string chOSMajorMinor;
            public long dwBuildNumber;
            public UNICODE_STRING ProcName;
            public IntPtr hTargetPID;
            public string lpApiCall;
            public int SystemCall;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct OSVERSIONINFOEXW
        {
            public int dwOSVersionInfoSize;
            public int dwMajorVersion;
            public int dwMinorVersion;
            public int dwBuildNumber;
            public int dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
            public UInt16 wServicePackMajor;
            public UInt16 wServicePackMinor;
            public UInt16 wSuiteMask;
            public byte wProductType;
            public byte wReserved;
        }
               
        [StructLayout(LayoutKind.Sequential)]
        public struct LARGE_INTEGER
        {
            public UInt32 LowPart;
            public UInt32 HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public UInt32 HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privileges;
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IO_STATUS_BLOCK
        {
            public uint status;
            public IntPtr information;
        }

        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public ulong Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public ulong Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        public enum NTSTATUS : uint
        {
            // Success
            Success = 0x00000000
        }

        public struct TOKEN_ELEVATION {
            public int TokenIsElevated;
        }

        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            TokenIsAppContainer,
            TokenCapabilities,
            TokenAppContainerSid,
            TokenAppContainerNumber,
            TokenUserClaimAttributes,
            TokenDeviceClaimAttributes,
            TokenRestrictedUserClaimAttributes,
            TokenRestrictedDeviceClaimAttributes,
            TokenDeviceGroups,
            TokenRestrictedDeviceGroups,
            TokenSecurityAttributes,
            TokenIsRestricted,
            MaxTokenInfoClass
        }

        public enum PSS_CAPTURE_FLAGS {
            PSS_CAPTURE_NONE,
            PSS_CAPTURE_VA_CLONE,
            PSS_CAPTURE_RESERVED_00000002,
            PSS_CAPTURE_HANDLES,
            PSS_CAPTURE_HANDLE_NAME_INFORMATION,
            PSS_CAPTURE_HANDLE_BASIC_INFORMATION,
            PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION,
            PSS_CAPTURE_HANDLE_TRACE,
            PSS_CAPTURE_THREADS,
            PSS_CAPTURE_THREAD_CONTEXT,
            PSS_CAPTURE_THREAD_CONTEXT_EXTENDED,
            PSS_CAPTURE_RESERVED_00000400,
            PSS_CAPTURE_VA_SPACE,
            PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION,
            PSS_CAPTURE_IPT_TRACE,
            PSS_CREATE_BREAKAWAY_OPTIONAL,
            PSS_CREATE_BREAKAWAY,
            PSS_CREATE_FORCE_BREAKAWAY,
            PSS_CREATE_USE_VM_ALLOCATIONS,
            PSS_CREATE_MEASURE_PERFORMANCE,
            PSS_CREATE_RELEASE_SECTION
        }

        public enum MINIDUMP_CALLBACK_TYPE : uint
        {
            ModuleCallback,
            ThreadCallback,
            ThreadExCallback,
            IncludeThreadCallback,
            IncludeModuleCallback,
            MemoryCallback,
            CancelCallback,
            WriteKernelMinidumpCallback,
            KernelMinidumpStatusCallback,
            RemoveMemoryCallback,
            IncludeVmRegionCallback,
            IoStartCallback,
            IoWriteAllCallback,
            IoFinishCallback,
            ReadMemoryFailureCallback,
            SecondaryFlagsCallback,
            IsProcessSnapshotCallback,
            VmStartCallback,
            VmQueryCallback,
            VmPreReadCallback,
            VmPostReadCallback
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public unsafe struct MINIDUMP_THREAD_CALLBACK
        {
            public uint ThreadId;
            public IntPtr ThreadHandle;
            public fixed byte Context[1232];
            public uint SizeOfContext;
            public ulong StackBase;
            public ulong StackEnd;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_THREAD_EX_CALLBACK
        {
            public MINIDUMP_THREAD_CALLBACK BasePart;
            public ulong BackingStoreBase;
            public ulong BackingStoreEnd;
        }
                       
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct VS_FIXEDFILEINFO
        {
            public uint dwSignature;
            public uint dwStrucVersion;
            public uint dwFileVersionMS;
            public uint dwFileVersionLS;
            public uint dwProductVersionMS;
            public uint dwProductVersionLS;
            public uint dwFileFlagsMask;
            public uint dwFileFlags;
            public uint dwFileOS;
            public uint dwFileType;
            public uint dwFileSubtype;
            public uint dwFileDateMS;
            public uint dwFileDateLS;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_MODULE_CALLBACK
        {
            public IntPtr FullPath; // This is a PCWSTR
            public ulong BaseOfImage;
            public uint SizeOfImage;
            public uint CheckSum;
            public uint TimeDateStamp;
            public VS_FIXEDFILEINFO VersionInfo;
            public IntPtr CvRecord;
            public uint SizeOfCvRecord;
            public IntPtr MiscRecord;
            public uint SizeOfMiscRecord;
        }

        public struct MINIDUMP_INCLUDE_THREAD_CALLBACK
        {
            public uint ThreadId;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_INCLUDE_MODULE_CALLBACK
        {
            public ulong BaseOfImage;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_IO_CALLBACK
        {
            public IntPtr Handle;
            public ulong Offset;
            public IntPtr Buffer;
            public uint BufferBytes;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_READ_MEMORY_FAILURE_CALLBACK
        {
            public ulong Offset;
            public uint Bytes;
            public int FailureStatus; // HRESULT
        }

        [Flags]
        public enum MINIDUMP_SECONDARY_FLAGS : uint
        {
            MiniSecondaryWithoutPowerInfo = 0x00000001
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct MINIDUMP_CALLBACK_INPUT
        {

        const int CallbackTypeOffset = 4 + 8;

            const int UnionOffset = CallbackTypeOffset + 4;

            [FieldOffset(0)]
            public uint ProcessId;
            [FieldOffset(4)]
            public IntPtr ProcessHandle;
            [FieldOffset(CallbackTypeOffset)]
            public MINIDUMP_CALLBACK_TYPE CallbackType;

            [FieldOffset(UnionOffset)]
            public int Status; // HRESULT
            [FieldOffset(UnionOffset)]
            public MINIDUMP_THREAD_CALLBACK Thread;
            [FieldOffset(UnionOffset)]
            public MINIDUMP_THREAD_EX_CALLBACK ThreadEx;
            [FieldOffset(UnionOffset)]
            public MINIDUMP_MODULE_CALLBACK Module;
            [FieldOffset(UnionOffset)]
            public MINIDUMP_INCLUDE_THREAD_CALLBACK IncludeThread;
            [FieldOffset(UnionOffset)]
            public MINIDUMP_INCLUDE_MODULE_CALLBACK IncludeModule;
            [FieldOffset(UnionOffset)]
            public MINIDUMP_IO_CALLBACK Io;
            [FieldOffset(UnionOffset)]
            public MINIDUMP_READ_MEMORY_FAILURE_CALLBACK ReadMemoryFailure;
            [FieldOffset(UnionOffset)]
            public MINIDUMP_SECONDARY_FLAGS SecondaryFlags;
        }

        public enum STATE : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000
        }

        public enum TYPE : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000
        }

        [Flags]
        public enum PROTECT : uint
        {
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,

            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_MEMORY_INFO
        {
            public ulong BaseAddress;
            public ulong AllocationBase;
            public uint AllocationProtect;
            public uint __alignment1;
            public ulong RegionSize;
            public STATE State;
            public PROTECT Protect;
            public TYPE Type;
            public uint __alignment2;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MemoryCallbackOutput
        {
            public ulong MemoryBase;
            public uint MemorySize;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct CancelCallbackOutput
        {
            [MarshalAs(UnmanagedType.Bool)]
            public bool CheckCancel;
            [MarshalAs(UnmanagedType.Bool)]
            public bool Cancel;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MemoryInfoCallbackOutput
        {
            public MINIDUMP_MEMORY_INFO VmRegion;
            [MarshalAs(UnmanagedType.Bool)]
            public bool Continue;
        }

        [Flags]
        public enum THREAD_WRITE_FLAGS : uint
        {
            ThreadWriteThread = 0x0001,
            ThreadWriteStack = 0x0002,
            ThreadWriteContext = 0x0004,
            ThreadWriteBackingStore = 0x0008,
            ThreadWriteInstructionWindow = 0x0010,
            ThreadWriteThreadData = 0x0020,
            ThreadWriteThreadInfo = 0x0040
        }

        [Flags]
        public enum MODULE_WRITE_FLAGS : uint
        {
            ModuleWriteModule = 0x0001,
            ModuleWriteDataSeg = 0x0002,
            ModuleWriteMiscRecord = 0x0004,
            ModuleWriteCvRecord = 0x0008,
            ModuleReferencedByMemory = 0x0010,
            ModuleWriteTlsData = 0x0020,
            ModuleWriteCodeSegs = 0x0040
        }

        [StructLayout(LayoutKind.Explicit, Pack = 4)]
        public struct MINIDUMP_CALLBACK_OUTPUT
        {
            [FieldOffset(0)]
            public MODULE_WRITE_FLAGS ModuleWriteFlags;
            [FieldOffset(0)]
            public THREAD_WRITE_FLAGS ThreadWriteFlags;
            [FieldOffset(0)]
            public uint SecondaryFlags;
            [FieldOffset(0)]
            public MemoryCallbackOutput Memory;
            [FieldOffset(0)]
            public CancelCallbackOutput Cancel;
            [FieldOffset(0)]
            public IntPtr Handle;
            [FieldOffset(0)]
            public MemoryInfoCallbackOutput MemoryInfo;
            [FieldOffset(0)]
            public int Status; // HRESULT
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool MINIDUMP_CALLBACK_ROUTINE(
            [In] IntPtr CallbackParam,
            [In] ref MINIDUMP_CALLBACK_INPUT CallbackInput,
            [In, Out] ref MINIDUMP_CALLBACK_OUTPUT CallbackOutput
            );

        public struct MINIDUMP_CALLBACK_INFORMATION
        {
            public MINIDUMP_CALLBACK_ROUTINE CallbackRoutine;
            public IntPtr CallbackParam;
        }
                
        private static IntPtr GetNtDll()
        {

            return LoadLibrary("ntdll.dll");

        }
                
        public static int NtFilterToken(IntPtr TokenHandle, uint Flags, IntPtr SidsToDisable, IntPtr PrivilegesToDelete, IntPtr RestrictedSids, ref IntPtr hToken)
        {
            IntPtr proc = GetProcAddress(GetNtDll(), "NtFilterToken");
            NativeSysCall.Delegates.NtFilterToken NtSetInformationToken = (NativeSysCall.Delegates.NtFilterToken)Marshal.GetDelegateForFunctionPointer(proc, typeof(NativeSysCall.Delegates.NtFilterToken));
            return NtFilterToken(TokenHandle, Flags, SidsToDisable, PrivilegesToDelete, RestrictedSids, ref hToken);
        }
        
        private static IntPtr GetKernel32()
        {

            return LoadLibrary("Kernel32.dll");

        }

        private static IntPtr GetKernelbase()
        {

            return LoadLibrary("Kernelbase.dll");

        }

        private static IntPtr GetAdvapi32()
        {

            return LoadLibrary("Advapi32.dll");

        }

        private static IntPtr GetDbgcore()
        {

            return LoadLibrary("dbgcore.dll");

        }
       
        public static bool RtlGetVersion(ref OSVERSIONINFOEXW lpVersionInformation)
        {
            IntPtr proc = GetProcAddress(GetNtDll(), "RtlGetVersion");
            NativeSysCall.Delegates.RtlGetVersion RtlGetVersion = (NativeSysCall.Delegates.RtlGetVersion)Marshal.GetDelegateForFunctionPointer(proc, typeof(NativeSysCall.Delegates.RtlGetVersion));
            return RtlGetVersion(ref lpVersionInformation);
        }
                
        public static UInt32 LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref Natives.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle)
        {
            IntPtr proc = GetProcAddress(GetNtDll(), "LdrLoadDll");
            NativeSysCall.Delegates.LdrLoadDll LdrLoadDll = (NativeSysCall.Delegates.LdrLoadDll)Marshal.GetDelegateForFunctionPointer(proc, typeof(NativeSysCall.Delegates.LdrLoadDll));
            return (uint)LdrLoadDll(PathToFile, dwFlags, ref ModuleFileName, ref ModuleHandle);
        }

        public static void RtlInitUnicodeString(ref Natives.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString)
        {
            IntPtr proc = GetProcAddress(GetNtDll(), "RtlInitUnicodeString");
            NativeSysCall.Delegates.RtlInitUnicodeString RtlInitUnicodeString = (NativeSysCall.Delegates.RtlInitUnicodeString)Marshal.GetDelegateForFunctionPointer(proc, typeof(NativeSysCall.Delegates.RtlInitUnicodeString));
            RtlInitUnicodeString(ref DestinationString, SourceString);
        }

        public static  bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength)
        {
            IntPtr proc = GetProcAddress(GetKernelbase(), "GetTokenInformation");
            NativeSysCall.Delegates.GetTokenInformation GetTokenInformation = (NativeSysCall.Delegates.GetTokenInformation)Marshal.GetDelegateForFunctionPointer(proc, typeof(NativeSysCall.Delegates.GetTokenInformation));
            return GetTokenInformation( TokenHandle,  TokenInformationClass,  TokenInformation,  TokenInformationLength, out  ReturnLength);
        }

        public static bool OpenProcessToken(IntPtr hProcess, UInt32 dwDesiredAccess, out IntPtr hToken)
        {
            IntPtr proc = GetProcAddress(GetKernelbase(), "OpenProcessToken");
            NativeSysCall.Delegates.OpenProcessToken OpenProcessToken = (NativeSysCall.Delegates.OpenProcessToken)Marshal.GetDelegateForFunctionPointer(proc, typeof(NativeSysCall.Delegates.OpenProcessToken));
            return OpenProcessToken( hProcess,  dwDesiredAccess, out  hToken);
        }

        public static bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, IntPtr hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam)
        {
            IntPtr proc = GetProcAddress(GetDbgcore(), "MiniDumpWriteDump");
            NativeSysCall.Delegates.MiniDumpWriteDump MiniDumpWriteDump = (NativeSysCall.Delegates.MiniDumpWriteDump)Marshal.GetDelegateForFunctionPointer(proc, typeof(NativeSysCall.Delegates.MiniDumpWriteDump));
            return MiniDumpWriteDump( hProcess,  ProcessId,  hFile,  DumpType,  ExceptionParam,  UserStreamParam,  CallbackParam);
        }

        public static bool LookupPrivilegeValue(String lpSystemName, String lpName, ref LUID luid)
        {
            IntPtr proc = GetProcAddress(GetAdvapi32(), "LookupPrivilegeValueA");
            NativeSysCall.Delegates.LookupPrivilegeValue LookupPrivilegeValue = (NativeSysCall.Delegates.LookupPrivilegeValue)Marshal.GetDelegateForFunctionPointer(proc, typeof(NativeSysCall.Delegates.LookupPrivilegeValue));
            return LookupPrivilegeValue( lpSystemName,  lpName, ref  luid);
        }

        public static  bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, UInt32 BufferLengthInBytes, ref TOKEN_PRIVILEGES PreviousState, out UInt32 ReturnLengthInBytes)
        {
            IntPtr proc = GetProcAddress(GetAdvapi32(), "AdjustTokenPrivileges");
            NativeSysCall.Delegates.AdjustTokenPrivileges AdjustTokenPrivileges = (NativeSysCall.Delegates.AdjustTokenPrivileges)Marshal.GetDelegateForFunctionPointer(proc, typeof(NativeSysCall.Delegates.AdjustTokenPrivileges));
            return AdjustTokenPrivileges( TokenHandle,  DisableAllPrivileges, ref  NewState,  BufferLengthInBytes, ref  PreviousState, out  ReturnLengthInBytes);
        }

        public static int PssCaptureSnapshot(IntPtr ProcessHandle, PSS_CAPTURE_FLAGS CaptureFlags, int ThreadContextFlags, ref IntPtr SnapshotHandle)
        {
            IntPtr proc = GetProcAddress(GetKernel32(), "PssCaptureSnapshot");
            NativeSysCall.Delegates.PssCaptureSnapshot PssCaptureSnapshot = (NativeSysCall.Delegates.PssCaptureSnapshot)Marshal.GetDelegateForFunctionPointer(proc, typeof(NativeSysCall.Delegates.PssCaptureSnapshot));
            return PssCaptureSnapshot( ProcessHandle,  CaptureFlags,  ThreadContextFlags, ref SnapshotHandle);
        }

        public static IntPtr GetProcAddress(IntPtr hModule, string procName)
        {
            return CustomLoadLibrary.GetExportAddress(hModule, procName);
        }
        
        public static IntPtr LoadLibrary(string name)
        {
            return CustomLoadLibrary.GetDllAddress(name, true);
        }
    }
}
