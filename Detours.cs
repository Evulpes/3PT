using System;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Data;
using System.Windows.Threading;
using _3PT;
using System.Windows;

public class Detours : NativeMethods
{
    public static DataTable packetTable = new DataTable
    {
        Columns =
        {
            "Method", "Data", "Length", "Time"
        }
    };
    public class W32Send
    {
        internal static Process p3cx;
        internal static int sendOffset;
        internal static int ws2ModIndex;
        public static bool detour = true;

        //From send to -19
        public class JmpToCallDetour
        {
            internal static readonly byte[] assembly =
            {
                    0xeb, 0xeb,                                     //jmp -19;
            };
            internal static readonly byte[] originalInstructions = new byte[]
            {
                0x53,                                           //push ebx
                0x56,                                           //push esi
            };
            internal const int Offset = 0x8;
        }

        //From -19 to detour
        public class CallDetour
        {
            internal static readonly byte[] assembly =
            {
                    0xb8, 0x00, 0x00, 0x00, 0x00,                   //mov eax, 0x0 ;address of detour
                    0xff, 0xe0                                      //jmp eax
            };

            internal const int StartOfMovInstruction = 1;
            internal static readonly int EndOfMovInstruction = assembly.Length - 2;
        }

        public class Detour
        {
            internal static readonly byte[] assembly =
            {
                0xb8, 0x00, 0x00, 0x00, 0x00,                    //mov eax, 0x0          ;address of storage
                #region BorrowedFlow
                0x53,                                           //push ebx
                0x56,                                           //push esi
                #endregion
                0x8b, 0x4d, 0x10,                               //mov ecx, [ebp+0x10]   ;length
                0x89, 0x48, 0x01,                               //mov [eax+1], ecx      ;this only allows for a max length of 255, as the [eax+2] will overwrite it
                0x8b, 0x4d, 0x0c,                               //mov ecx, [ebp+0xc]    ;buffer*
                0x89, 0x48, 0x05,                               //mov [eax+5], ecx
                0xc6, 0x00, 0x01,                               //mov byte ptr [eax], 0x1
                0x80, 0x38, 0x00,                               //cmp byte ptr [eax], 0x0
                0x75, 0xfb,                                     //jne -3;
                0xba, 0x00,0x00, 0x00, 0x00,                    //mov edx, 0x0
                0xff, 0xe2                                      //jmp edx
            };

            internal const int JNEOffset = 0x19;
            internal static readonly int StartOfMovEaxInstruction = 1;
            internal static readonly int EndOfMovEaxInstruction = 4;
            internal static readonly int StartOfMovEdxInstruction = assembly.Length - 6;
            internal static readonly int EndOfMovEdxInstruction = assembly.Length - 2;

        }
        //ToDo: Rename this
        internal static readonly int PageSize = 0x1000;
    }


    public static Task DetourWs2Send()
    {
        //ToDo: Add handling
        W32Send.p3cx = Process.GetProcessesByName("3CXWin8Phone").FirstOrDefault();
        W32Send.ws2ModIndex = GetModuleIndex(W32Send.p3cx.Modules, "WS2_32");
        if (W32Send.ws2ModIndex == -1)
        {
            Debug.WriteLine("Module not found");
            return null;
        }

        IntPtr hWinsock = Libloaderapi.LoadLibraryA("WS2_32");
        if (hWinsock == IntPtr.Zero)
            return null;

        IntPtr sendFunc = Libloaderapi.GetProcAddress(hWinsock, "send");
        if (sendFunc == IntPtr.Zero)
            return null;

        W32Send.sendOffset = (int)sendFunc - (int)hWinsock;
        Libloaderapi.FreeLibrary(hWinsock);

        //The address of the detour
        int detourAddr = (int)Memoryapi.VirtualAllocEx(W32Send.p3cx.Handle, IntPtr.Zero, (uint)W32Send.Detour.assembly.Length, Winnt.AllocationType.MEM_COMMIT, Winnt.MemoryProtection.PAGE_EXECUTE_READWRITE);
        byte[] detourAddrArr = BitConverter.GetBytes(detourAddr);

        //The address of the memory storage
        int storageAddr = (int)Memoryapi.VirtualAllocEx(W32Send.p3cx.Handle, IntPtr.Zero, (uint)W32Send.PageSize, Winnt.AllocationType.MEM_COMMIT, Winnt.MemoryProtection.PAGE_EXECUTE_READWRITE);
        byte[] storageAddrArr = BitConverter.GetBytes(storageAddr);

        //Patching the detour-calling function with the detour address
        for (int i = W32Send.CallDetour.StartOfMovInstruction; i < W32Send.CallDetour.EndOfMovInstruction; i++)
            W32Send.CallDetour.assembly[i] = detourAddrArr[i - 1];


        //Patching the detour function with the storage address
        for (int i = W32Send.Detour.StartOfMovEaxInstruction; i <= W32Send.Detour.EndOfMovEaxInstruction; i++)
            W32Send.Detour.assembly[i] = storageAddrArr[i - 1];

        //Patching the detour function with the return address
        byte[] returnAddr = BitConverter.GetBytes((int)W32Send.p3cx.Modules[W32Send.ws2ModIndex].BaseAddress + W32Send.sendOffset + 0xA);
        for (int i = W32Send.Detour.StartOfMovEdxInstruction, x = 0; i < W32Send.Detour.EndOfMovEdxInstruction; i++, x++)
            W32Send.Detour.assembly[i] = returnAddr[x];

        //Detouring the send function to the detour calling function
        IntPtr jmpToDetourAddr = W32Send.p3cx.Modules[W32Send.ws2ModIndex].BaseAddress + W32Send.sendOffset + W32Send.JmpToCallDetour.Offset;
        if (!Memoryapi.WriteProcessMemory(W32Send.p3cx.Handle, jmpToDetourAddr, W32Send.JmpToCallDetour.assembly, W32Send.JmpToCallDetour.assembly.Length, out IntPtr _))
        {
            Debug.WriteLine(Marshal.GetLastWin32Error());
            return null;
        };

        //Writing the detour call
        if (!Memoryapi.WriteProcessMemory(W32Send.p3cx.Handle, (jmpToDetourAddr - 19), W32Send.CallDetour.assembly, W32Send.CallDetour.assembly.Length, out IntPtr _))
        {
            Debug.WriteLine(Marshal.GetLastWin32Error());
            return null;
        };

        //Writing the detour
        if (!Memoryapi.WriteProcessMemory(W32Send.p3cx.Handle, (IntPtr)detourAddr, W32Send.Detour.assembly, W32Send.Detour.assembly.Length, out IntPtr _))
        {
            Debug.WriteLine(Marshal.GetLastWin32Error());
            return null;
        }

        Task DetourTask = new Task(() =>
        {
            while (W32Send.detour)
            {
                byte[] data = new byte[W32Send.PageSize];

                if (!Memoryapi.ReadProcessMemory(W32Send.p3cx.Handle, (IntPtr)storageAddr, data, W32Send.PageSize, out _))
                    Debug.WriteLine(Marshal.GetLastWin32Error());

                //IF the byte is signalled
                if (data[0] == 1)
                {
                    //Memoryapi.ReadProcessMemory(p.Handle)
                    SocketData sd = new SocketData()
                    {
                        length = BitConverter.ToInt32(data.Skip(1).Take(4).ToArray(), 0),
                        bufferPtr = new byte[4],

                    };
                    sd.bufferCont = new byte[sd.length];

                    Array.Copy(data, 5, sd.bufferPtr, 0, sizeof(int));
                    int bufferPtrAddr = BitConverter.ToInt32(sd.bufferPtr, 0);
                    if (!Memoryapi.ReadProcessMemory(W32Send.p3cx.Handle, (IntPtr)bufferPtrAddr, sd.bufferCont, sd.length, out IntPtr _))
                        Debug.Write(Marshal.GetLastWin32Error());

#if DEBUG
                    Trace.Write($"Socket Length {sd.length}\n");
                    Trace.Write($"Socket Payload {Encoding.ASCII.GetString(sd.bufferCont, 0, sd.length)}\n"); //Debug uses ascii so messages will be omitted
                    Trace.Write("\n");
#endif
                    //ToDo: USE THE CORRECT CODE HERE, UPDATE IT.
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        packetTable.Rows.Add("ws32_32.send", BitConverter.ToString(sd.bufferCont), sd.length, "NYI");
                    });


                    Memoryapi.WriteProcessMemory(W32Send.p3cx.Handle, (IntPtr)storageAddr, new byte[] { 0x0 }, 0x1, out IntPtr _);
                }
            }
            //Remove the detour
            IntPtr origInstrAddr = W32Send.p3cx.Modules[W32Send.ws2ModIndex].BaseAddress + W32Send.sendOffset + W32Send.JmpToCallDetour.Offset;
            //Remove the detour jmp
            if(!Memoryapi.WriteProcessMemory(W32Send.p3cx.Handle, origInstrAddr, W32Send.JmpToCallDetour.originalInstructions, W32Send.JmpToCallDetour.originalInstructions.Length, out IntPtr _))
                ;//ToDo: Do something here

            //Remove the jne instruction incase the comparison is mid-check.
            if(!Memoryapi.WriteProcessMemory(W32Send.p3cx.Handle, (IntPtr)(detourAddr + W32Send.Detour.JNEOffset), new byte[] { 0x90, 0x90 }, 0x2, out IntPtr _ ))
                ;//ToDo: Do something here

            //ToDo: free memory of allocated pages.
            int me = 5;
        });
        return DetourTask;
    }


    private struct SocketData
    {
        public byte[] bufferCont;
        public byte[] bufferPtr;
        public int length;
    }
    private static int GetModuleIndex(ProcessModuleCollection pMods, string modName)
    {
        for (int i = 0; i < pMods.Count; i++)
        {
            if (pMods[i].ModuleName.Contains(modName))
                return i;
        }
        return -1;
    }
    public enum Offsets
    {
        logFunc = 0xF030,       //3cxTunnel.dll
    }
}
public class NativeMethods
{
    protected static class Handleapi
    {
        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);
    }
    protected static class Libloaderapi
    {
        [DllImport("Kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibraryA([MarshalAs(UnmanagedType.LPStr)]string lpFileName);

        [DllImport("Kernel32", SetLastError = true)]
        public static extern bool FreeLibrary(IntPtr hLibModule);

        [DllImport("Kernel32", SetLastError = true, CharSet = CharSet.Ansi, ExactSpelling = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpprocName);
    }
    protected static class Memoryapi
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, Winnt.AllocationType flAllocationType, Winnt.MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

    }
    protected static class Processthreadsapi
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("Kernel32", SetLastError = true)]
        public static extern IntPtr OpenProcess(Winnt.ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int processId);
    }
    protected static class Winnt
    {
        public enum AllocationType
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000,
        }
        public enum ProcessAccessFlags
        {
            PROCESS_ALL_ACCESS = 0xFFFF,
        }
        public enum MemoryProtection : uint
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
            PAGE_WRITECOMBINE = 0x400,

        }
    }

}