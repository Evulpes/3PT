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
            ReverseTBA.DetourWs2Send();
        }
    }
    public class ReverseTBA : NativeMethods
    {
        //From send to -19
        private static readonly byte[] jmpToCallDetour = 
        {
            0xeb, 0xeb,                                     //jmp -19;
        };
        //From -19 to detour
        private static readonly byte[] callDetour =
        {
            0xb8, 0x00,0x00,0x00,0x00,                      //mov eax, 0x0
            0xff, 0xe0                                      //jmp eax
        };

        private static readonly byte[] detour =
        {

            0x80, 0x38, 0x00,                               //cmp byte ptr [eax], 0x0
            0x75, 0xfb,                                     //jne -3;
        };

        public static void DetourWs2Send()
        {
            Process p = Process.GetProcessesByName("3CXWin8Phone").FirstOrDefault();

            int mIndex = GetModuleIndex(p.Modules, "WS2_32");
            if(mIndex == -1)
            {
                Debug.WriteLine("Module not found");
                return;
            }
            
            //The address where the detour work happens
            int detourAddr = (int)Memoryapi.VirtualAllocEx(p.Handle, IntPtr.Zero, 0x20, Winnt.AllocationType.MEM_COMMIT, Winnt.MemoryProtection.PAGE_EXECUTE_READWRITE);
            byte[] detourAddrArr = BitConverter.GetBytes(detourAddr);

            //Patching the calling function, for the detour, with the detour address
            for (int i = 1; i < callDetour.Length-2; i++)
                callDetour[i] = detourAddrArr[i - 1];
            

            //Detouring the send function to the detour calling function
            IntPtr jmpToDetourAddr = p.Modules[mIndex].BaseAddress + (int)Offsets.sendFunc2 + 0x8;
            if (!Memoryapi.WriteProcessMemory(p.Handle, jmpToDetourAddr, jmpToCallDetour, jmpToCallDetour.Length, out IntPtr _))
            {
                Debug.WriteLine(Marshal.GetLastWin32Error());
                return;
            };

            //Writing the detour call
            if (!Memoryapi.WriteProcessMemory(p.Handle, (jmpToDetourAddr - 19), callDetour, callDetour.Length, out IntPtr _))
            {
                Debug.WriteLine(Marshal.GetLastWin32Error());
                return;
            };


        }
        public static int GetModuleIndex(ProcessModuleCollection pMods, string modName)
        {
            for (int i = 0; i < pMods.Count; i++)
            {
                if (pMods[i].ModuleName.Contains(modName))
                {
                    return i;
                }
            }
            return -1;
        }
        public enum Offsets
        {
            logFunc = 0xF030,       //3cxTunnel.dll
            sendFunc = 0x5750,      //Add Byte Scanning
            sendFunc2 = 0x14CF0,    //Add Byte Scanning
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
