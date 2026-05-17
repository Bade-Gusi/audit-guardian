using AuditGuardian.Desktop.Models;

namespace AuditGuardian.Desktop.Services;

public class HardwareService
{
    private readonly CollectorRunner _runner;

    public HardwareService(CollectorRunner runner)
    {
        _runner = runner;
    }

    public async Task<HardwareData> CollectHardwareAsync()
    {
        return await _runner.RunCollectorAsync<HardwareData>(
            "HardwareCollector/HardwareCollector.exe");
    }

    private static readonly Dictionary<string, string> PropNameMap = new()
    {
        // CPU
        ["Name"] = "名称", ["NumberOfCores"] = "核心数", ["MaxClockSpeed"] = "最大频率",
        ["ProcessorId"] = "处理器ID", ["Manufacturer"] = "制造商", ["Caption"] = "描述",
        ["NumberOfLogicalProcessors"] = "逻辑处理器数",
        // GPU
        ["AdapterRAM"] = "显存大小", ["DriverVersion"] = "驱动版本", ["VideoProcessor"] = "视频处理器",
        ["VideoModeDescription"] = "显示模式",
        // Motherboard
        ["Product"] = "产品型号", ["SerialNumber"] = "序列号", ["Version"] = "版本",
        // Disk
        ["Model"] = "型号", ["Size"] = "容量", ["InterfaceType"] = "接口类型", ["MediaType"] = "介质类型",
        // Network
        ["MACAddress"] = "MAC地址", ["Speed"] = "速度", ["AdapterType"] = "适配器类型",
        ["NetEnabled"] = "已启用",
        // RAM
        ["Capacity"] = "容量", ["Speed"] = "频率", ["PartNumber"] = "零件号", ["MemoryType"] = "内存类型",
        // Common
        ["Status"] = "状态", ["Health"] = "健康状况",
    };

    /// <summary>
    /// Fallback: collect hardware directly via WMI when the collector EXE isn't available.
    /// </summary>
    public HardwareData CollectHardwareDirect()
    {
        var data = new HardwareData
        {
            MachineHash = GetMachineHash(),
            Categories = new List<HardwareCategory>(),
            SpoofDetection = new SpoofDetection()
        };

        // CPU
        data.Categories.Add(new HardwareCategory
        {
            Category = "cpu", Label = "CPU 处理器", Icon = "cpu", Status = "normal",
            Properties = GetWmiProperties("Win32_Processor", new[] { "Name", "NumberOfCores", "MaxClockSpeed", "ProcessorId" })
        });

        // GPU
        data.Categories.Add(new HardwareCategory
        {
            Category = "gpu", Label = "GPU 显卡", Icon = "monitor", Status = "normal",
            Properties = GetWmiProperties("Win32_VideoController", new[] { "Name", "AdapterRAM", "DriverVersion" })
        });

        // Motherboard
        data.Categories.Add(new HardwareCategory
        {
            Category = "motherboard", Label = "主板", Icon = "circuit-board", Status = "normal",
            Properties = GetWmiProperties("Win32_BaseBoard", new[] { "Manufacturer", "Product", "SerialNumber" })
        });

        // Disk
        data.Categories.Add(new HardwareCategory
        {
            Category = "disk", Label = "硬盘", Icon = "hard-drive", Status = "normal",
            Properties = GetWmiProperties("Win32_DiskDrive", new[] { "Model", "Size", "SerialNumber", "InterfaceType" })
        });

        // Network
        data.Categories.Add(new HardwareCategory
        {
            Category = "network", Label = "网卡", Icon = "wifi", Status = "normal",
            Properties = GetWmiProperties("Win32_NetworkAdapter", new[] { "Name", "MACAddress", "Speed" }, "NetEnabled=True")
        });

        // RAM
        data.Categories.Add(new HardwareCategory
        {
            Category = "ram", Label = "内存", Icon = "memory", Status = "normal",
            Properties = GetWmiProperties("Win32_PhysicalMemory", new[] { "Capacity", "Speed", "Manufacturer", "PartNumber" })
        });

        return data;
    }

    private List<HardwareProperty> GetWmiProperties(string className, string[] properties, string? filter = null)
    {
        var result = new List<HardwareProperty>();
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT {string.Join(",", properties)} FROM {className}" +
                (filter != null ? $" WHERE {filter}" : ""));
            foreach (var obj in searcher.Get())
            {
                foreach (var prop in properties)
                {
                    var val = obj[prop]?.ToString() ?? "";
                    result.Add(new HardwareProperty
                    {
                        Name = PropNameMap.GetValueOrDefault(prop, prop),
                        Value = val,
                        IsSpoofed = false
                    });
                }
            }
        }
        catch (Exception ex)
        {
            result.Add(new HardwareProperty { Name = "Error", Value = ex.Message });
        }
        return result;
    }

    private static string GetMachineHash()
    {
        // Simple machine fingerprint from hardware
        var parts = new List<string>();
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT ProcessorId FROM Win32_Processor");
            foreach (var obj in searcher.Get())
                parts.Add(obj["ProcessorId"]?.ToString() ?? "");
        }
        catch { }
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT SerialNumber FROM Win32_BaseBoard");
            foreach (var obj in searcher.Get())
                parts.Add(obj["SerialNumber"]?.ToString() ?? "");
        }
        catch { }

        var raw = string.Join("-", parts);
        if (string.IsNullOrWhiteSpace(raw)) raw = "UNKNOWN";
        // Return a simple hash
        return Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(raw)))[..16];
    }
}
