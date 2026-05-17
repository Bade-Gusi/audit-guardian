using System.Diagnostics;
using System.Text.Json;

namespace EventLogCollector;

class Program
{
    static void Main(string[] args)
    {
        int sinceDays = 30;
        if (args.Length > 0 && args[0] == "--since" && args.Length > 1)
            int.TryParse(args[1], out sinceDays);

        var sinceTime = DateTime.Now.AddDays(-sinceDays);

        Console.Error.WriteLine($"{{\"progress\": 0, \"status\": \"Reading event logs since {sinceDays} days ago...\"}}");

        var events = new List<Dictionary<string, object>>();
        string[] logNames = { "System", "Security", "Application", "Microsoft-Windows-Sysmon/Operational" };
        int totalLogs = logNames.Length;
        int processed = 0;

        foreach (var logName in logNames)
        {
            try
            {
                using var log = new EventLog(logName);
                int entryCount = log.Entries.Count;
                int threshold = Math.Max(1, entryCount / 100); // progress every ~1%

                Console.Error.WriteLine($"{{\"progress\": {(processed * 100 / totalLogs)}, \"status\": \"Reading {logName} ({entryCount} entries)...\"}}");

                for (int i = 0; i < entryCount; i++)
                {
                    var entry = log.Entries[i];
                    if (entry.TimeGenerated >= sinceTime)
                    {
                        events.Add(new Dictionary<string, object>
                        {
                            ["log_name"] = logName,
                            ["event_id"] = entry.InstanceId,
                            ["timestamp"] = entry.TimeGenerated.ToString("o"),
                            ["level"] = entry.EntryType.ToString(),
                            ["source"] = entry.Source,
                            ["category"] = entry.CategoryNumber,
                            ["user_name"] = entry.UserName ?? "",
                            ["description"] = entry.Message?.Length > 500
                                ? entry.Message[..500] + "..."
                                : (entry.Message ?? ""),
                        });
                    }

                    // Progress reporting
                    if (i % threshold == 0 && threshold > 0)
                    {
                        var progress = (processed * 100 / totalLogs) + (i * 100 / (entryCount * totalLogs));
                        Console.Error.WriteLine($"{{\"progress\": {Math.Min(progress, 99)}, \"status\": \"Processing {logName}...\"}}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"{{\"progress\": {(processed * 100 / totalLogs)}, \"status\": \"Error reading {logName}: {ex.Message}\"}}");
            }
            processed++;
        }

        Console.Error.WriteLine("{\"progress\": 100, \"status\": \"Event log collection complete.\"}");

        var result = new Dictionary<string, object>
        {
            ["total_events"] = events.Count,
            ["time_range"] = new Dictionary<string, object>
            {
                ["start"] = sinceTime.ToString("o"),
                ["end"] = DateTime.Now.ToString("o")
            },
            ["events"] = events,
            ["summary"] = new Dictionary<string, object>
            {
                ["by_type"] = events.GroupBy(e => e["source"]?.ToString() ?? "unknown")
                    .ToDictionary(g => g.Key, g => g.Count()),
                ["by_date"] = events.GroupBy(e => {
                    var ts = e["timestamp"]?.ToString() ?? "";
                    return ts.Length >= 10 ? ts[..10] : "unknown";
                }).ToDictionary(g => g.Key, g => g.Count())
            }
        };

        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions
        {
            WriteIndented = false,
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        });
        Console.WriteLine(json);
    }
}
