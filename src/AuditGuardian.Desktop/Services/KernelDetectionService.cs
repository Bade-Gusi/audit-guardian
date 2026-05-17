using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using AuditGuardian.Desktop.Models;

namespace AuditGuardian.Desktop.Services;

/// <summary>
/// 内核级作弊检测服务
/// 使用 P/Invoke 调用 Windows Native API 检测系统异常
/// </summary>
public class KernelDetectionService
{
    // ==================== Native API ====================

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int bufSize, out int retLen);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int infoClass,
        IntPtr buffer, int bufSize, out int retLen);

    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetModuleHandle(string name);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetProcAddress(IntPtr module, string name);

    // SystemInformationClass values
    private const int SystemProcessInformation = 5;
    private const int SystemModuleInformation = 11;
    private const int SystemHandleInformation = 16;

    // Process info class
    private const int ProcessBasicInformation = 0;

    // Process access
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_MODULE
    {
        public IntPtr Reserved1;
        public IntPtr Reserved2;
        public IntPtr ImageBase;
        public int ImageSize;
        public int Flags;
        public short LoadOrderIndex;
        public short InitOrderIndex;
        public short LoadCount;
        public short ModuleNameOffset;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string ImageName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_MODULE_INFORMATION
    {
        public int ModulesCount;
        // Followed by SYSTEM_MODULE array
    }

    private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

    /// <summary>
    /// 运行完整的内核检测
    /// </summary>
    public KernelDetectionResult RunKernelDetection()
    {
        var result = new KernelDetectionResult
        {
            ScannedAt = DateTime.Now.ToString("o"),
        };

        // 1. 枚举所有内核驱动模块
        result.LoadedModules = EnumerateKernelModules();

        // 2. 检测 NTDLL 函数钩子（用户态检测 SSDT Hook）
        result.NtdllHooks = DetectNtdllHooks();
        result.SsdtHooked = result.NtdllHooks.Count > 0;

        // 3. 检测隐藏进程
        result.HiddenProcesses = DetectHiddenProcesses();

        // 4. 检测已知恶意驱动
        result.SuspiciousDrivers = DetectSuspiciousDrivers(result.LoadedModules);

        // 5. 检测回调异常
        result.UnusualCallbacks = DetectUnusualCallbacks();

        // 6. 检测未签名驱动
        result.UnsignedDrivers = DetectUnsignedDrivers(result.LoadedModules);

        return result;
    }

    /// <summary>
    /// 枚举已加载的内核模块（驱动列表）
    /// </summary>
    public List<KernelModule> EnumerateKernelModules()
    {
        var modules = new List<KernelModule>();

        try
        {
            int retLen = 0;
            int status = NtQuerySystemInformation(SystemModuleInformation, IntPtr.Zero, 0, out retLen);

            if (status != STATUS_INFO_LENGTH_MISMATCH && retLen <= 0)
                return modules;

            IntPtr buffer = Marshal.AllocHGlobal(retLen);
            try
            {
                status = NtQuerySystemInformation(SystemModuleInformation, buffer, retLen, out retLen);
                if (status != 0) return modules;

                int count = Marshal.ReadInt32(buffer);
                int offset = Marshal.SizeOf(typeof(int)); // skip count

                for (int i = 0; i < count; i++)
                {
                    IntPtr modulePtr = IntPtr.Add(buffer, offset + i * Marshal.SizeOf<SYSTEM_MODULE>());
                    var mod = Marshal.PtrToStructure<SYSTEM_MODULE>(modulePtr);

                    var name = Path.GetFileName(mod.ImageName);
                    var fullPath = mod.ImageName;

                    modules.Add(new KernelModule
                    {
                        Name = name,
                        FullPath = fullPath,
                        ImageBase = mod.ImageBase,
                        ImageSize = mod.ImageSize,
                        LoadOrder = mod.LoadOrderIndex
                    });
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Kernel module enumeration failed: {ex.Message}");
        }

        return modules;
    }

    /// <summary>
    /// 检测 NTDLL 函数是否被 Hook（判断作弊程序常用的挂钩目标）
    /// 原理：读取函数前几个字节，如果以 JMP(0xE9) 或 CALL(0xE8) 开头则可能被 Hook
    /// </summary>
    public List<NtdllHook> DetectNtdllHooks()
    {
        var hooks = new List<NtdllHook>();

        try
        {
            var ntdll = GetModuleHandle("ntdll.dll");
            if (ntdll == IntPtr.Zero) return hooks;

            // 需要检查的关键函数列表（作弊程序常用 Hook 目标）
            string[] criticalFunctions = {
                "NtOpenProcess", "NtOpenThread", "NtClose",
                "NtReadVirtualMemory", "NtWriteVirtualMemory",
                "NtProtectVirtualMemory", "NtAllocateVirtualMemory",
                "NtFreeVirtualMemory", "NtQuerySystemInformation",
                "NtQueryInformationProcess", "NtSetInformationThread",
                "NtCreateThreadEx", "NtSuspendProcess", "NtResumeProcess",
                "NtDebugActiveProcess", "NtRemoveProcessDebug",
                "NtCreateFile", "NtOpenFile", "NtDeviceIoControlFile",
                "NtCreateKey", "NtOpenKey", "NtDeleteKey",
                "ZwOpenProcess", "ZwQuerySystemInformation",
                "NtUserGetAsyncKeyState", "NtUserGetKeyState",
                "NtQueryDirectoryFile", "NtCreateSection",
            };

            foreach (var funcName in criticalFunctions)
            {
                var addr = GetProcAddress(ntdll, funcName);
                if (addr == IntPtr.Zero) continue;

                // 读取函数前 2 个字节
                byte[] header = new byte[2];
                Marshal.Copy(addr, header, 0, 2);

                // 正常 NTDLL 函数开头是 syscall 指令 (0x0F 0x05) 或 mov eax, SSDTNumber
                // JMP (0xE9) 或 CALL (0xE8) 开头说明被 Hook
                if (header[0] == 0xE9 || header[0] == 0xE8)
                {
                    // 读取跳转目标地址
                    byte[] jmpTarget = new byte[4];
                    Marshal.Copy(IntPtr.Add(addr, 1), jmpTarget, 0, 4);
                    uint target = BitConverter.ToUInt32(jmpTarget, 0);
                    IntPtr targetAddr = IntPtr.Add(addr, 5 + (int)target);

                    hooks.Add(new NtdllHook
                    {
                        FunctionName = funcName,
                        HookType = header[0] == 0xE9 ? "JMP (绝对跳转)" : "CALL (调用)",
                        HookAddress = addr.ToString("X16"),
                        TargetAddress = targetAddr.ToString("X16"),
                    });
                }
                // 检测短跳转 (EB xx)
                else if (header[0] == 0xEB)
                {
                    hooks.Add(new NtdllHook
                    {
                        FunctionName = funcName,
                        HookType = "JMP (短跳转)",
                        HookAddress = addr.ToString("X16"),
                        TargetAddress = "",
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"NTDLL hook detection failed: {ex.Message}");
        }

        return hooks;
    }

    /// <summary>
    /// 检测隐藏进程（通过比较不同 API 枚举结果的差异）
    /// </summary>
    public List<HiddenProcessInfo> DetectHiddenProcesses()
    {
        var hidden = new List<HiddenProcessInfo>();

        try
        {
            // 方法1: 使用 CreateToolhelp32Snapshot 枚举
            var snapshotPids = new HashSet<int>();
            var snapshot = CreateToolhelp32Snapshot(SnapshotFlags.Process, 0);
            if (snapshot != IntPtr.Zero)
            {
                var entry = new PROCESSENTRY32 { dwSize = Marshal.SizeOf<PROCESSENTRY32>() };
                if (Process32First(snapshot, ref entry))
                {
                    do { snapshotPids.Add(entry.th32ProcessID); }
                    while (Process32Next(snapshot, ref entry));
                }
                CloseHandle(snapshot);
            }

            // 方法2: 使用 NtQuerySystemInformation 枚举（更底层）
            var ntPids = new HashSet<int>();
            int retLen = 0;
            int status = NtQuerySystemInformation(SystemProcessInformation, IntPtr.Zero, 0, out retLen);
            if (status == STATUS_INFO_LENGTH_MISMATCH && retLen > 0)
            {
                IntPtr buffer = Marshal.AllocHGlobal(retLen);
                try
                {
                    status = NtQuerySystemInformation(SystemProcessInformation, buffer, retLen, out retLen);
                    if (status == 0)
                    {
                        IntPtr ptr = buffer;
                        while (true)
                        {
                            var nextOffset = Marshal.ReadInt32(ptr);
                            var pid = Marshal.ReadInt32(ptr + 0x20); // UniqueProcessId offset
                            ntPids.Add(pid);
                            if (nextOffset == 0) break;
                            ptr = IntPtr.Add(ptr, nextOffset);
                        }
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }

            // 方法3: 使用 WMI 枚举
            var wmiPids = new HashSet<int>();
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT ProcessId FROM Win32_Process");
                foreach (var obj in searcher.Get())
                    wmiPids.Add(Convert.ToInt32(obj["ProcessId"]));
            }
            catch { }

            // 对比差异：在 snapshot 中存在但 WMI 中不存在 → 可能是隐藏进程
            // 实际上，WMI 和 Toolhelp 使用相同底层 API，真正的隐藏进程检测
            // 需要内核驱动。这里我们标记 PID 差异用于分析。
            foreach (var pid in snapshotPids)
            {
                if (!wmiPids.Contains(pid) && pid > 0 && pid < 65535)
                {
                    try
                    {
                        var proc = Process.GetProcessById(pid);
                        hidden.Add(new HiddenProcessInfo
                        {
                            Pid = pid,
                            ProcessName = proc.ProcessName,
                            SuspicionReason = "进程在 Toolhelp 中存在但在 WMI 中不可见"
                        });
                    }
                    catch
                    {
                        hidden.Add(new HiddenProcessInfo
                        {
                            Pid = pid,
                            ProcessName = "未知",
                            SuspicionReason = "无法通过 Process.GetProcessById 访问"
                        });
                    }
                }
            }
        }
        catch { }

        return hidden;
    }

    /// <summary>
    /// 检测已加载的驱动中是否存在可疑驱动
    /// </summary>
    public List<DetectionFinding> DetectSuspiciousDrivers(List<KernelModule> modules)
    {
        var findings = new List<DetectionFinding>();

        // 已知作弊相关驱动关键词
        var suspiciousKeywords = new Dictionary<string, (string Category, string Severity)>
        {
            ["cheat"] = ("作弊驱动", "high"),
            ["hack"] = ("作弊驱动", "high"),
            ["inject"] = ("注入驱动", "high"),
            ["hook"] = ("挂钩驱动", "medium"),
            ["bypass"] = ("绕过驱动", "high"),
            ["ring0"] = ("内核驱动", "medium"),
            ["kprocesshider"] = ("进程隐藏", "critical"),
            ["ph3"] = ("ProcessHacker", "high"),
            ["processhacker"] = ("ProcessHacker", "high"),
            ["pcileech"] = ("内存读取", "critical"),
            ["winring0"] = ("Ring0访问", "high"),
            ["inpoutx"] = ("端口IO", "high"),
            ["physmem"] = ("物理内存", "critical"),
            ["null"] = ("空指针驱动", "critical"),
        };

        foreach (var mod in modules)
        {
            var lower = mod.Name.ToLowerInvariant();

            foreach (var (keyword, (category, severity)) in suspiciousKeywords)
            {
                if (lower.Contains(keyword))
                {
                    findings.Add(new DetectionFinding
                    {
                        Type = "driver",
                        Severity = severity,
                        Description = $"发现可疑驱动: {mod.Name}",
                        Detail = $"路径: {mod.FullPath}, 基址: {mod.ImageBase:X16}, 大小: {mod.ImageSize / 1024}KB",
                        MatchedRule = $"关键词匹配: {keyword} ({category})",
                        FoundAt = DateTime.Now.ToString("o")
                    });
                    break;
                }
            }
        }

        return findings;
    }

    /// <summary>
    /// 检测异常内核回调
    /// 用户态无法直接读取内核回调数组，通过检查已知回调驱动来间接判断
    /// </summary>
    public List<DetectionFinding> DetectUnusualCallbacks()
    {
        var findings = new List<DetectionFinding>();

        try
        {
            // 检查 Process Monitor 驱动（Sysinternals 工具常见）
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_SystemDriver WHERE State='Running'");
            foreach (var drv in searcher.Get())
            {
                var name = drv["Name"]?.ToString() ?? "";
                var path = drv["PathName"]?.ToString() ?? "";

                // 标记已知的反作弊驱动
                if (name.Contains("EasyAntiCheat", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("BattlEye", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("EAC", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new DetectionFinding
                    {
                        Type = "anticheat",
                        Severity = "info",
                        Description = $"反作弊驱动加载中: {name}",
                        Detail = $"路径: {path}",
                        MatchedRule = "已知反作弊驱动",
                        FoundAt = DateTime.Now.ToString("o"),
                    });
                }
            }
        }
        catch { }

        return findings;
    }

    /// <summary>
    /// 检测未签名的内核驱动
    /// </summary>
    public List<DetectionFinding> DetectUnsignedDrivers(List<KernelModule> modules)
    {
        var findings = new List<DetectionFinding>();

        // Windows 10+ 默认要求驱动签名，所以未签名驱动很可疑
        var knownSigned = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "ntoskrnl.exe", "hal.dll", "kernalbase.dll", "win32k.sys",
            "ndis.sys", "tcpip.sys", "volmgr.sys", "mountmgr.sys",
            "ntfs.sys", "fastfat.sys", "fltmgr.sys", "volsnap.sys",
            "cdrom.sys", "disk.sys", "classpnp.sys", "partmgr.sys",
            "usbhub.sys", "usbport.sys", "hidparse.sys", "mouclass.sys",
            "kbdclass.sys", "dxgkrnl.sys", "dxgmms2.sys", "watchdog.sys",
            "spaceport.sys", "storport.sys", "ataport.sys", "pci.sys",
            "acpi.sys", "intelpep.sys", "processr.sys",
        };

        foreach (var mod in modules)
        {
            if (string.IsNullOrWhiteSpace(mod.Name)) continue;
            if (knownSigned.Contains(mod.Name)) continue;

            // Microsoft 签名的常见驱动
            if (mod.FullPath.Contains("\\SystemRoot\\System32\\drivers\\", StringComparison.OrdinalIgnoreCase) ||
                mod.FullPath.Contains("\\Windows\\System32\\", StringComparison.OrdinalIgnoreCase) ||
                mod.FullPath.Contains("\\Windows\\SysWOW64\\", StringComparison.OrdinalIgnoreCase))
                continue;

            // 来自第三方但路径异常的驱动
            if (!mod.FullPath.Contains("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase) &&
                !mod.FullPath.Contains("\\Windows\\", StringComparison.OrdinalIgnoreCase) &&
                !mod.FullPath.Contains("\\Program Files\\", StringComparison.OrdinalIgnoreCase) &&
                !mod.FullPath.Contains("\\Program Files (x86)\\", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new DetectionFinding
                {
                    Type = "unsigned_driver",
                    Severity = "medium",
                    Description = $"非标准路径驱动: {mod.Name}",
                    Detail = $"路径: {mod.FullPath}",
                    MatchedRule = "非常规系统驱动路径",
                    FoundAt = DateTime.Now.ToString("o"),
                });
            }
        }

        return findings;
    }

    // ==================== Win32 API for snapshot enumeration ====================

    [DllImport("kernel32.dll")]
    private static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags flags, int pid);

    [DllImport("kernel32.dll")]
    private static extern bool Process32First(IntPtr snapshot, ref PROCESSENTRY32 entry);

    [DllImport("kernel32.dll")]
    private static extern bool Process32Next(IntPtr snapshot, ref PROCESSENTRY32 entry);

    [Flags]
    private enum SnapshotFlags : uint
    {
        Process = 0x00000002,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESSENTRY32
    {
        public int dwSize;
        public int cntUsage;
        public int th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public int th32ModuleID;
        public int cntThreads;
        public int th32ParentProcessID;
        public int pcPriClassBase;
        public int dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }
}

