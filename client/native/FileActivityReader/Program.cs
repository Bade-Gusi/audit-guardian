using System.Text.Json;
using Microsoft.Win32;

namespace FileActivityReader;

class Program
{
    static void Main(string[] args)
    {
        Console.Error.WriteLine("{\"progress\": 0, \"status\": \"Reading file activity...\"}");

        var activities = new List<Dictionary<string, object>>();

        // 1. Read Recent Items
        Console.Error.WriteLine("{\"progress\": 10, \"status\": \"Reading Recent Items...\"}");
        try
        {
            var recentDir = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
            if (Directory.Exists(recentDir))
            {
                var files = Directory.GetFiles(recentDir);
                foreach (var file in files.Take(200))
                {
                    activities.Add(new Dictionary<string, object>
                    {
                        ["activity_type"] = "accessed",
                        ["file_path"] = file,
                        ["timestamp"] = File.GetLastAccessTime(file).ToString("o"),
                        ["process_name"] = "",
                        ["source"] = "recent_files",
                        ["detail"] = ""
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"{{\"progress\": 10, \"status\": \"Recent Items error: {ex.Message}\"}}");
        }

        // 2. Read USB History from Registry
        Console.Error.WriteLine("{\"progress\": 30, \"status\": \"Reading USB history...\"}");
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR");
            if (key != null)
            {
                foreach (var deviceName in key.GetSubKeyNames())
                {
                    using var deviceKey = key.OpenSubKey(deviceName);
                    if (deviceKey != null)
                    {
                        activities.Add(new Dictionary<string, object>
                        {
                            ["activity_type"] = "usb_plug",
                            ["file_path"] = deviceName,
                            ["timestamp"] = "",
                            ["process_name"] = "",
                            ["source"] = "usb",
                            ["detail"] = $"USB Device: {deviceName}"
                        });

                        foreach (var sn in deviceKey.GetSubKeyNames())
                        {
                            activities.Add(new Dictionary<string, object>
                            {
                                ["activity_type"] = "usb_detail",
                                ["file_path"] = $"{deviceName}\\{sn}",
                                ["timestamp"] = "",
                                ["process_name"] = "",
                                ["source"] = "usb",
                                ["detail"] = $"Serial: {sn}"
                            });
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"{{\"progress\": 30, \"status\": \"USB history error: {ex.Message}\"}}");
        }

        // 3. Read Shellbags from Registry (MRU)
        Console.Error.WriteLine("{\"progress\": 50, \"status\": \"Reading Shellbags...\"}");
        try
        {
            var sid = GetCurrentUserSid();
            if (sid != null)
            {
                using var key = Registry.Users.OpenSubKey($@"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs");
                // Note: Shellbags require binary MRU parsing; simplified here
                Console.Error.WriteLine("{\"progress\": 50, \"status\": \"Shellbags MRU key found\"}");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"{{\"progress\": 50, \"status\": \"Shellbags error: {ex.Message}\"}}");
        }

        // 4. Read Prefetch directory
        Console.Error.WriteLine("{\"progress\": 70, \"status\": \"Reading Prefetch files...\"}");
        try
        {
            var prefetchDir = @"C:\Windows\Prefetch";
            if (Directory.Exists(prefetchDir))
            {
                var files = Directory.GetFiles(prefetchDir, "*.pf");
                foreach (var file in files.Take(300))
                {
                    var fileName = Path.GetFileNameWithoutExtension(file);
                    activities.Add(new Dictionary<string, object>
                    {
                        ["activity_type"] = "process_run",
                        ["file_path"] = file,
                        ["timestamp"] = File.GetLastAccessTime(file).ToString("o"),
                        ["process_name"] = fileName,
                        ["source"] = "prefetch",
                        ["detail"] = $"Last run: {File.GetLastAccessTime(file)}"
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"{{\"progress\": 70, \"status\": \"Prefetch error: {ex.Message}\"}}");
        }

        Console.Error.WriteLine("{\"progress\": 100, \"status\": \"File activity collection complete.\"}");

        var result = new Dictionary<string, object>
        {
            ["total_events"] = activities.Count,
            ["time_range"] = new Dictionary<string, object>
            {
                ["start"] = "",
                ["end"] = DateTime.Now.ToString("o")
            },
            ["events"] = activities,
            ["summary"] = new Dictionary<string, object>
            {
                ["by_type"] = activities.GroupBy(a => a["source"]?.ToString() ?? "unknown")
                    .ToDictionary(g => g.Key, g => g.Count()),
                ["by_date"] = new Dictionary<string, object>()
            }
        };

        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions
        {
            WriteIndented = false,
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        });
        Console.WriteLine(json);
    }

    static string? GetCurrentUserSid()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Volatile Environment");
            return key?.GetValue("UserSid")?.ToString();
        }
        catch
        {
            return null;
        }
    }
}
