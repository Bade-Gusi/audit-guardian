using System.Management;
using System.Text.Json;

namespace HardwareCollector;

class Program
{
    static void Main(string[] args)
    {
        Console.Error.WriteLine("{\"progress\": 0, \"status\": \"Starting hardware collection...\"}");

        var result = new Dictionary<string, object>
        {
            ["machine_hash"] = GetMachineHash(),
            ["categories"] = new List<object>(),
            ["change_history"] = new List<object>(),
            ["spoof_detection"] = new Dictionary<string, object>
            {
                ["has_spoofed"] = false,
                ["details"] = new List<string>()
            }
        };

        // Collect CPU info
        Console.Error.WriteLine("{\"progress\": 15, \"status\": \"Collecting CPU info...\"}");
        var cpuProps = GetWmiProperties("Win32_Processor", new[] {
            "Name", "NumberOfCores", "NumberOfLogicalProcessors",
            "MaxClockSpeed", "ProcessorId", "Manufacturer", "Caption"
        });
        ((List<object>)result["categories"]).Add(new Dictionary<string, object>
        {
            ["category"] = "cpu",
            ["label"] = "CPU 处理器",
            ["icon"] = "cpu",
            ["properties"] = cpuProps,
            ["status"] = "normal"
        });

        // Collect GPU info
        Console.Error.WriteLine("{\"progress\": 30, \"status\": \"Collecting GPU info...\"}");
        var gpuProps = GetWmiProperties("Win32_VideoController", new[] {
            "Name", "AdapterRAM", "DriverVersion",
            "VideoProcessor", "VideoModeDescription"
        });
        ((List<object>)result["categories"]).Add(new Dictionary<string, object>
        {
            ["category"] = "gpu",
            ["label"] = "GPU 显卡",
            ["icon"] = "monitor",
            ["properties"] = gpuProps,
            ["status"] = "normal"
        });

        // Collect Motherboard info
        Console.Error.WriteLine("{\"progress\": 45, \"status\": \"Collecting motherboard info...\"}");
        var mbProps = GetWmiProperties("Win32_BaseBoard", new[] {
            "Manufacturer", "Product", "SerialNumber", "Version"
        });
        ((List<object>)result["categories"]).Add(new Dictionary<string, object>
        {
            ["category"] = "motherboard",
            ["label"] = "主板",
            ["icon"] = "circuit-board",
            ["properties"] = mbProps,
            ["status"] = "normal"
        });

        // Collect Disk info
        Console.Error.WriteLine("{\"progress\": 60, \"status\": \"Collecting disk info...\"}");
        var diskProps = GetWmiProperties("Win32_DiskDrive", new[] {
            "Model", "Size", "SerialNumber", "InterfaceType", "MediaType"
        });
        ((List<object>)result["categories"]).Add(new Dictionary<string, object>
        {
            ["category"] = "disk",
            ["label"] = "硬盘",
            ["icon"] = "hard-drive",
            ["properties"] = diskProps,
            ["status"] = "normal"
        });

        // Collect Network adapter info
        Console.Error.WriteLine("{\"progress\": 75, \"status\": \"Collecting network info...\"}");
        var netProps = GetWmiProperties("Win32_NetworkAdapter", new[] {
            "Name", "MACAddress", "Speed",
            "AdapterType", "NetEnabled"
        }, filter: "NetEnabled=True");
        ((List<object>)result["categories"]).Add(new Dictionary<string, object>
        {
            ["category"] = "network",
            ["label"] = "网卡",
            ["icon"] = "wifi",
            ["properties"] = netProps,
            ["status"] = "normal"
        });

        // Collect RAM info
        Console.Error.WriteLine("{\"progress\": 90, \"status\": \"Collecting memory info...\"}");
        var ramProps = GetWmiProperties("Win32_PhysicalMemory", new[] {
            "Capacity", "Speed", "Manufacturer",
            "PartNumber", "SerialNumber", "MemoryType"
        });
        ((List<object>)result["categories"]).Add(new Dictionary<string, object>
        {
            ["category"] = "ram",
            ["label"] = "内存",
            ["icon"] = "memory",
            ["properties"] = ramProps,
            ["status"] = "normal"
        });

        Console.Error.WriteLine("{\"progress\": 100, \"status\": \"Hardware collection complete.\"}");

        // Output the full JSON result
        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions
        {
            WriteIndented = false,
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        });
        Console.WriteLine(json);
    }

    static List<Dictionary<string, object>> GetWmiProperties(string className, string[] properties, string? filter = null)
    {
        var results = new List<Dictionary<string, object>>();
        try
        {
            var query = $"SELECT {string.Join(",", properties)} FROM {className}";
            if (!string.IsNullOrEmpty(filter))
                query += $" WHERE {filter}";

            using var searcher = new ManagementObjectSearcher(query);
            foreach (var obj in searcher.Get())
            {
                var item = new Dictionary<string, object>();
                foreach (var prop in properties)
                {
                    var value = obj[prop];
                    item[ToSnakeCase(prop)] = value?.ToString() ?? "";
                    item["is_spoofed"] = false;
                    item["name"] = prop;
                }
                results.Add(item);
            }
        }
        catch (Exception ex)
        {
            results.Add(new Dictionary<string, object>
            {
                ["name"] = "Error",
                ["value"] = $"Failed to query {className}: {ex.Message}",
                ["is_spoofed"] = false
            });
        }
        return results;
    }

    static string GetMachineHash()
    {
        // TODO: Combine hardware serials into a SHA256 hash
        return "placeholder-machine-hash";
    }

    static string ToSnakeCase(string input)
    {
        return string.Concat(input.Select((c, i) =>
            i > 0 && char.IsUpper(c) ? "_" + char.ToLower(c).ToString() : char.ToLower(c).ToString()));
    }
}
