using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Runtime.InteropServices;
using System.Diagnostics;



namespace _3PT
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            Detours.DetourWs2Send();
           
        }
    }
    public class Detours : NativeMethods
    {
        private class W32Send
        {
            //From send to -19
            public class JmpToCallDetour
            {
                internal static readonly byte[] assembly =
                {
                    0xeb, 0xeb,                                     //jmp -19;
                };
            }

            public class CallDetour
            {
                internal static readonly byte[] assembly =
                {
                    0xb8, 0x00, 0x00, 0x00, 0x00,                   //mov eax, 0x0 ;address of detour
                    0xff, 0xe0                                      //jmp eax
                };
                internal const int CALLDETOUR_START_OF_MOV_INSTRUCTION = 1;
                internal static readonly int CALLDETOUR_END_OF_MOV_INSTRUCTION = assembly.Length - 2;
            }
            //From -19 to detour

            public class Detour
            {
                internal static readonly byte[] assembly =
                {
                0xb8, 0x00,0x00, 0x00, 0x00,                    //mov eax, 0x0          ;address of storage
                #region BorrowedFlow
                0x53,                                           //push ebx
                0x56,                                           //push esi
                #endregion
                0x8b, 0x4d, 0x10,                               //mov ecx, [ebp+0x10]   ;length
                0x89, 0x48, 0x01,                               //mov [eax+1], ecx      ;this only allows for a max length of 255, as the [eax+2] will overwrite it
                0x8b, 0x4d, 0x0c,                               //mov ecx, [ebp+0xc]    ;buffer*
                0x89, 0x48, 0x02,                               //mov [eax+2], ecx
                0xc6, 0x00, 0x01,                               //mov byte ptr [eax], 0x1
                0x80, 0x38, 0x00,                               //cmp byte ptr [eax], 0x0
                0x75, 0xfb,                                     //jne -3;
                0xba, 0x00,0x00, 0x00, 0x00,                    //mov edx, 0x0
                0xff, 0xe2                                      //jmp edx
            };
                internal static readonly int DETOUR_START_OF_MOV_EAX_INSTRUCTION = 1;
                internal static readonly int DETOUR_END_OF_MOV_EAX_INSTRUCTION = 4;
                internal static readonly int DETOUR_START_OF_MOV_EDX_INSTRUCTION = assembly.Length - 6;
                internal static readonly int DETOUR_END_OF_MOV_EDX_INSTRUCTION = assembly.Length - 2;

            }


            internal static readonly int OUR_PAGE_SIZE = 0x1000;
        }

       
        public static void DetourWs2Send()
        {
            
            Process p = Process.GetProcessesByName("3CXWin8Phone").FirstOrDefault();

            int mIndex = GetModuleIndex(p.Modules, "WS2_32");
            if (mIndex == -1)
            {
                Debug.WriteLine("Module not found");
                return;
            }

            //The address of the detour
            int detourAddr = (int)Memoryapi.VirtualAllocEx(p.Handle, IntPtr.Zero, (uint)W32Send.Detour.assembly.Length, Winnt.AllocationType.MEM_COMMIT, Winnt.MemoryProtection.PAGE_EXECUTE_READWRITE);
            byte[] detourAddrArr = BitConverter.GetBytes(detourAddr);

            //The address of the memory storage
            int storageAddr = (int)Memoryapi.VirtualAllocEx(p.Handle, IntPtr.Zero, (uint)W32Send.OUR_PAGE_SIZE, Winnt.AllocationType.MEM_COMMIT, Winnt.MemoryProtection.PAGE_EXECUTE_READWRITE);
            byte[] storageAddrArr = BitConverter.GetBytes(storageAddr);

            //Patching the detour-calling function with the detour address
            for (int i = W32Send.CallDetour.CALLDETOUR_START_OF_MOV_INSTRUCTION; i < W32Send.CallDetour.CALLDETOUR_END_OF_MOV_INSTRUCTION; i++)
                W32Send.CallDetour.assembly[i] = detourAddrArr[i - 1];


            //Patching the detour function with the storage address
            for (int i = W32Send.Detour.DETOUR_START_OF_MOV_EAX_INSTRUCTION; i <= W32Send.Detour.DETOUR_END_OF_MOV_EAX_INSTRUCTION; i++)
                W32Send.Detour.assembly[i] = storageAddrArr[i - 1];

            //Patching the detour function with the return address
            byte[] returnAddr = BitConverter.GetBytes((int)p.Modules[mIndex].BaseAddress + (int)Offsets.sendFunc + 0xA);

            int x = 0;
            for (int i = W32Send.Detour.DETOUR_START_OF_MOV_EDX_INSTRUCTION; i < W32Send.Detour.DETOUR_END_OF_MOV_EDX_INSTRUCTION; i++, x++)
                W32Send.Detour.assembly[i] = returnAddr[x];


            //Detouring the send function to the detour calling function
            IntPtr jmpToDetourAddr = p.Modules[mIndex].BaseAddress + (int)Offsets.sendFunc + 0x8;
            if (!Memoryapi.WriteProcessMemory(p.Handle, jmpToDetourAddr, W32Send.JmpToCallDetour.assembly, W32Send.JmpToCallDetour.assembly.Length, out IntPtr _))
            {
                Debug.WriteLine(Marshal.GetLastWin32Error());
                return;
            };

            //Writing the detour call
            if (!Memoryapi.WriteProcessMemory(p.Handle, (jmpToDetourAddr - 19), W32Send.CallDetour.assembly, W32Send.CallDetour.assembly.Length, out IntPtr _))
            {
                Debug.WriteLine(Marshal.GetLastWin32Error());
                return;
            };

            //Writing the detour
            if (!Memoryapi.WriteProcessMemory(p.Handle, (IntPtr)detourAddr, W32Send.Detour.assembly, W32Send.Detour.assembly.Length, out IntPtr _))
            {
                Debug.WriteLine(Marshal.GetLastWin32Error());
                return;
            }

            //poc loop -- make and return a running thread
            while (true)
            {
                byte[] data = new byte[255];

                if (!Memoryapi.ReadProcessMemory(p.Handle, (IntPtr)storageAddr, data, W32Send.OUR_PAGE_SIZE, out _))
                    Debug.WriteLine(Marshal.GetLastWin32Error());


                if (data[0] == 1)
                {
                    //Memoryapi.ReadProcessMemory(p.Handle)
                    SocketData sd = new SocketData()
                    {
                        length = data[1],
                        bufferPtr = new byte[4],
                        bufferCont = new byte[data[1]],
                    };
                    //4 bytes as 32-bit, ptr only 4 bytes max
                    Array.Copy(data, 2, sd.bufferPtr, 0, sizeof(int));
                    int bufferPtrAddr = BitConverter.ToInt32(sd.bufferPtr, 0);
                    IntPtr buffTest = (IntPtr)bufferPtrAddr;
                    if (!Memoryapi.ReadProcessMemory(p.Handle, buffTest, sd.bufferCont, sd.length, out IntPtr _))
                        Debug.Write(Marshal.GetLastWin32Error());


      
                }
            }

        }
        

        public struct SocketData
        {
            public byte[] bufferCont;
            public byte[] bufferPtr;
            public int length;
        }
        public static int GetModuleIndex(ProcessModuleCollection pMods, string modName)
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
            sendFunc = 0x5750,      //Add Byte Scanning -- PC
            sendFunc2 = 0x14CF0,    //Add Byte Scanning -- laptop
        }
    }
    public class NativeMethods
    {
        public static class Handleapi
        {
            [DllImport("kernel32.dll")]
            public static extern bool CloseHandle(IntPtr hObject);
        }
        public static class Memoryapi
        {
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, Winnt.AllocationType flAllocationType, Winnt.MemoryProtection flProtect);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        }
        public static class Processthreadsapi
        {
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

            [DllImport("Kernel32", SetLastError = true)]
            public static extern IntPtr OpenProcess(Winnt.ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int processId);
        }
        public static class Winnt
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
}
