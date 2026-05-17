using System.Diagnostics.Eventing.Reader;
using Microsoft.Win32;
using AuditGuardian.Desktop.Models;

namespace AuditGuardian.Desktop.Services;

public class EventLogService
{
    private readonly CollectorRunner _runner;
    public event Action<int, string>? Progress; // progress %, status text

    public EventLogService(CollectorRunner runner)
    {
        _runner = runner;
    }

    /// <summary>
    /// Read ALL Windows Event Logs in parallel for speed.
    /// Each log read on background thread, results merged.
    /// </summary>
    public EventLogData CollectAllLogs(int sinceDays = 7, int maxPerLog = 2000)
    {
        var now = DateTime.Now;
        var since = now.AddDays(-sinceDays);
        var allEvents = new List<TimelineEvent>();
        var lockObj = new object();

        var logNames = GetAvailableLogNames();
        int total = logNames.Count;
        int completed = 0;

        Progress?.Invoke(0, $"发现 {total} 个日志源，并行读取中...");

        // Read logs in parallel with a max concurrency
        Parallel.ForEach(logNames, new ParallelOptions { MaxDegreeOfParallelism = 4 }, logName =>
        {
            int count = 0;
            try
            {
                // Use local time in the query (EventLog stores local time)
                var query = new EventLogQuery(logName, PathType.LogName,
                    $"*[System[TimeCreated[timeline(@System.Time) >= '{since:yyyy-MM-ddTHH:mm:ss}']]]")
                { ReverseDirection = true };

                using var reader = new EventLogReader(query);
                EventRecord? record;
                while ((record = reader.ReadEvent()) != null && count < maxPerLog)
                {
                    using (record) { count++; }
                }

                // Read again to process
                using var reader2 = new EventLogReader(query);
                int processed = 0;
                while ((record = reader2.ReadEvent()) != null && processed < maxPerLog)
                {
                    using (record)
                    {
                        processed++;
                        var te = ConvertToTimelineEvent(record, logName);
                        lock (lockObj) { allEvents.Add(te); }
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                lock (lockObj)
                {
                    allEvents.Add(new TimelineEvent
                    {
                        LogName = logName, EventId = 0,
                        Timestamp = ToLocalString(now),
                        Level = "Warning", Source = "AccessDenied",
                        Description = $"需要管理员权限读取 {logName}"
                    });
                }
            }
            catch { /* skip unreadable logs */ }

            Interlocked.Increment(ref completed);
            var pct = completed * 100 / total;
            Progress?.Invoke(pct, $"读取 {logName} ({count} 条)...");
        });

        // Prefetch & USB
        Progress?.Invoke(95, "读取 Prefetch 和 USB 历史...");
        allEvents.AddRange(ReadPrefetch());
        allEvents.AddRange(GetUsbHistory());

        Progress?.Invoke(100, "完成");

        allEvents = allEvents.OrderByDescending(e => e.Timestamp).ToList();

        return new EventLogData
        {
            TotalEvents = allEvents.Count,
            TimeRange = new TimeRange { Start = ToLocalString(since), End = ToLocalString(now) },
            Events = allEvents,
            Summary = new EventSummary
            {
                ByType = allEvents.GroupBy(e => e.Source ?? "unknown")
                    .ToDictionary(g => g.Key, g => g.Count()),
                ByDate = allEvents.GroupBy(e => e.Timestamp.Length >= 10 ? e.Timestamp[..10] : "unknown")
                    .ToDictionary(g => g.Key, g => g.Count())
            }
        };
    }

    private static string ToLocalString(DateTime dt) =>
        dt.ToString("yyyy-MM-ddTHH:mm:ss");

    private List<string> GetAvailableLogNames()
    {
        var names = new List<string>();
        try { using var session = new EventLogSession(); names.AddRange(session.GetLogNames()); }
        catch { names.AddRange(new[] { "Application", "System", "Security" }); }

        var priority = new[] {
            "Security", "System", "Application",
            "Windows PowerShell",
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-TaskScheduler/Operational",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-AppLocker/EXE and DLL",
            "Setup",
        };

        return priority.Where(p => names.Any(n =>
            n.Equals(p, StringComparison.OrdinalIgnoreCase)))
            .Concat(names.Where(n => !priority.Any(p =>
                n.Equals(p, StringComparison.OrdinalIgnoreCase))))
            .Distinct()
            .ToList();
    }

    private TimelineEvent ConvertToTimelineEvent(EventRecord record, string logName)
    {
        var te = new TimelineEvent
        {
            LogName = ShortLogName(logName),
            EventId = record.Id,
            Timestamp = record.TimeCreated.HasValue
                ? ToLocalString(record.TimeCreated.Value)
                : ToLocalString(DateTime.Now),
            Level = record.Level switch { 1 => "Critical", 2 => "Error", 3 => "Warning", _ => "Information" },
            Source = record.ProviderName ?? "",
            Description = FormatEventDescription(record)
        };

        // Mark severity based on Event ID for Security logs
        if (logName.Equals("Security", StringComparison.OrdinalIgnoreCase))
        {
            te.Severity = record.Id switch
            {
                4625 or 4648 or 4771 or 4776 or 4777 => "warning",    // Failed logon
                4672 or 4673 => "warning",                            // Special privileges
                4719 => "warning",                                    // Audit policy change
                4720 or 4722 or 4723 or 4724 or 4725 or 4726 => "warning", // User changes
                4732 or 4733 or 4756 or 4757 => "warning",            // Group membership
                1100 or 1102 => "warning",                            // Log cleared
                5145 => "warning",                                     // Network access
                _ => "info"
            };
        }
        // PowerShell operational logs are often interesting
        else if (logName.Contains("PowerShell", StringComparison.OrdinalIgnoreCase) && record.Id == 4104)
        {
            te.Severity = "warning"; // Script block logging
        }

        return te;
    }

    private string FormatEventDescription(EventRecord record)
    {
        try
        {
            var desc = record.FormatDescription();
            if (!string.IsNullOrWhiteSpace(desc))
                return desc.Length > 300 ? desc[..300] + "..." : desc;

            var parts = new List<string>();
            if (record.Properties != null)
                foreach (var prop in record.Properties)
                {
                    var val = prop?.Value?.ToString();
                    if (!string.IsNullOrWhiteSpace(val) && val.Length < 200)
                        parts.Add(val);
                }
            return parts.Count > 0 ? string.Join(" | ", parts.Take(5)) : $"[{record.ProviderName}] ID {record.Id}";
        }
        catch { return $"[{record.ProviderName}] ID {record.Id}"; }
    }

    private static string ShortLogName(string full)
    {
        if (full.Length <= 20) return full;
        if (full.Contains('-'))
        {
            var parts = full.Split('-');
            return parts.Length >= 2 ? $"{parts[^2]}-{parts[^1]}" : full;
        }
        return full[..Math.Min(full.Length, 20)];
    }

    // ==================== PREFETCH ====================

    public List<TimelineEvent> ReadPrefetch()
    {
        var result = new List<TimelineEvent>();
        try
        {
            var dir = @"C:\Windows\Prefetch";
            if (!Directory.Exists(dir)) return result;
            foreach (var file in Directory.GetFiles(dir, "*.pf").Take(300))
            {
                var name = Path.GetFileNameWithoutExtension(file);
                var dashIdx = name.LastIndexOf('-');
                if (dashIdx > 0) name = name[..dashIdx];
                result.Add(new TimelineEvent
                {
                    LogName = "Prefetch", EventId = 0,
                    Timestamp = ToLocalString(File.GetLastWriteTime(file)),
                    Level = "Information", Source = "Prefetch",
                    Description = $"程序运行: {name}", Severity = "info"
                });
            }
        }
        catch (UnauthorizedAccessException)
        {
            result.Add(new TimelineEvent { LogName = "Prefetch", Level = "Warning", Source = "AccessDenied",
                Description = "需要管理员权限读取 Prefetch" });
        }
        catch { }
        return result;
    }

    // ==================== USB ====================

    public List<TimelineEvent> GetUsbHistory()
    {
        var result = new List<TimelineEvent>();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR");
            if (key == null) return result;
            foreach (var device in key.GetSubKeyNames())
            {
                using var devKey = key.OpenSubKey(device);
                if (devKey == null) continue;
                foreach (var sn in devKey.GetSubKeyNames())
                {
                    using var snKey = devKey.OpenSubKey(sn);
                    var name = snKey?.GetValue("FriendlyName")?.ToString() ?? device;
                    result.Add(new TimelineEvent
                    {
                        LogName = "USB", EventId = 1001,
                        Timestamp = ToLocalString(DateTime.Now),
                        Level = "Information", Source = "USBSTOR",
                        Description = $"USB设备: {name}",
                        Severity = "info"
                    });
                }
            }
        }
        catch { }
        return result;
    }

    // ==================== LEGACY ====================

    public async Task<EventLogData> CollectEventLogsAsync(int sinceDays = 7)
    {
        try { return await _runner.RunCollectorAsync<EventLogData>("EventLogCollector/EventLogCollector.exe", $"--since {sinceDays}"); }
        catch { return CollectAllLogs(sinceDays); }
    }

    public EventLogData CollectEventLogsDirect(int sinceDays = 7) => CollectAllLogs(sinceDays);
}
