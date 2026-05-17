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
                        Name = prop,
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
