using System.Diagnostics.Eventing.Reader;
using Microsoft.Win32;
using AuditGuardian.Desktop.Models;

namespace AuditGuardian.Desktop.Services;

public class EventLogService
{
    private readonly CollectorRunner _runner;

    public EventLogService(CollectorRunner runner)
    {
        _runner = runner;
    }

    /// <summary>
    /// Read ALL Windows Event Logs using EventLogReader (modern .NET API).
    /// Covers System, Security, Application + all Applications and Services Logs
    /// (PowerShell, Sysmon, TaskScheduler, TerminalServices, etc.)
    /// </summary>
    public EventLogData CollectAllLogs(int sinceDays = 7, int maxPerLog = 5000)
    {
        var since = DateTime.UtcNow.AddDays(-sinceDays);
        var allEvents = new List<TimelineEvent>();

        // 1. Enumerate all available event logs
        var logNames = GetAvailableLogNames();
        int totalLogs = logNames.Count;
        int processed = 0;

        foreach (var logName in logNames)
        {
            processed++;
            try
            {
                var query = new EventLogQuery(logName, PathType.LogName, $"*[System[TimeCreated[timeline(@System.Time) >= '{since:yyyy-MM-ddTHH:mm:ss}Z']]]")
                {
                    ReverseDirection = true
                };

                using var reader = new EventLogReader(query);
                int count = 0;
                EventRecord? record;
                while ((record = reader.ReadEvent()) != null && count < maxPerLog)
                {
                    using (record)
                    {
                        count++;
                        allEvents.Add(ConvertToTimelineEvent(record, logName));
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                // Security log often requires admin - skip gracefully
                allEvents.Add(new TimelineEvent
                {
                    LogName = logName,
                    EventId = 0,
                    Timestamp = DateTime.UtcNow.ToString("o"),
                    Level = "Warning",
                    Source = "AccessDenied",
                    Description = $"需要管理员权限读取 {logName}"
                });
            }
            catch (Exception ex)
            {
                // Skip logs that can't be read
                System.Diagnostics.Debug.WriteLine($"Cannot read {logName}: {ex.Message}");
            }
        }

        // 2. Read Prefetch files for execution history
        var prefetchEvents = ReadPrefetch();
        allEvents.AddRange(prefetchEvents);

        // 3. Read USB history
        var usbEvents = GetUsbHistory();
        allEvents.AddRange(usbEvents);

        // Sort by timestamp descending
        allEvents = allEvents.OrderByDescending(e => e.Timestamp).ToList();

        return new EventLogData
        {
            TotalEvents = allEvents.Count,
            TimeRange = new TimeRange { Start = since.ToString("o"), End = DateTime.UtcNow.ToString("o") },
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

    private List<string> GetAvailableLogNames()
    {
        var names = new List<string>();

        try
        {
            using var session = new EventLogSession();
            var logNames = session.GetLogNames();
            names.AddRange(logNames);
        }
        catch
        {
            // Fallback: just try the standard logs
            names.AddRange(new[] { "Application", "System", "Security" });
        }

        // Prioritize important channels
        var priority = new[] {
            "Security", "System", "Application",
            "Windows PowerShell",
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-TaskScheduler/Operational",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "Microsoft-Windows-Security-Auditing",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-AppLocker/EXE and DLL",
            "Microsoft-Windows-CodeIntegrity/Operational",
            "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
            "Setup",
            "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
            "Microsoft-Windows-SmbClient/Security",
            "Microsoft-Windows-DNS-Client/Operational"
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
            LogName = logName,
            EventId = record.Id,
            Timestamp = record.TimeCreated?.ToString("o") ?? DateTime.UtcNow.ToString("o"),
            Level = record.Level switch
            {
                1 => "Critical",
                2 => "Error",
                3 => "Warning",
                4 => "Information",
                0 => "Information",
                _ => "Information"
            },
            Source = record.ProviderName ?? "",
            Category = (int)(record.Task ?? 0),
            Description = FormatEventDescription(record)
        };

        // Extract user name from event data if available
        try
        {
            if (record.Properties != null)
            {
                // Security events often have user data in specific indices
                foreach (var prop in record.Properties)
                {
                    var val = prop?.Value?.ToString() ?? "";
                    if (val.StartsWith("S-1-") || val.StartsWith("DESKTOP") || val.Contains("\\"))
                    {
                        te.UserName = val;
                        break;
                    }
                }
            }
        }
        catch { }

        // For Security log events, mark with severity based on well-known Event IDs
        if (logName.Equals("Security", StringComparison.OrdinalIgnoreCase))
        {
            te.Severity = record.Id switch
            {
                4624 or 4634 or 4647 or 4648 => "info",      // Logon/Logoff
                4625 => "warning",                            // Failed logon
                4672 or 4673 or 4674 => "warning",            // Special privileges
                4688 or 4689 => "info",                       // Process creation
                4698 or 4699 or 4700 or 4701 => "info",      // Scheduled tasks
                4702 or 4703 => "warning",
                4719 => "warning",                            // Audit policy change
                4720 or 4722 or 4723 or 4724 or 4725 => "warning", // User account changes
                4732 or 4733 or 4756 or 4757 => "warning",   // Group membership
                5140 or 5142 or 5143 or 5144 or 5145 => "info", // Network share
                5156 or 5157 or 5158 => "info",               // Firewall
                1100 or 1102 => "warning",                    // Event log cleared
                _ => te.Severity
            };
        }

        return te;
    }

    private string FormatEventDescription(EventRecord record)
    {
        try
        {
            var desc = record.FormatDescription();
            if (!string.IsNullOrWhiteSpace(desc))
                return desc.Length > 500 ? desc[..500] + "..." : desc;

            // Fallback: build description from properties
            var parts = new List<string>();
            if (record.Properties != null)
            {
                foreach (var prop in record.Properties)
                {
                    var val = prop?.Value?.ToString();
                    if (!string.IsNullOrWhiteSpace(val) && val.Length < 200)
                        parts.Add(val);
                }
            }

            if (parts.Count > 0)
                return string.Join(" | ", parts.Take(5));

            return $"[{record.ProviderName}] Event ID {record.Id}";
        }
        catch
        {
            return $"[{record.ProviderName}] Event ID {record.Id}";
        }
    }

    // ==================== PREFETCH READER ====================

    public List<TimelineEvent> ReadPrefetch()
    {
        var result = new List<TimelineEvent>();
        try
        {
            var prefetchDir = @"C:\Windows\Prefetch";
            if (!Directory.Exists(prefetchDir)) return result;

            var files = Directory.GetFiles(prefetchDir, "*.pf");
            foreach (var file in files.Take(500))
            {
                var name = Path.GetFileNameWithoutExtension(file);
                // Parse the app name (before the hash/run count)
                var appName = name;
                var dashIdx = name.LastIndexOf('-');
                if (dashIdx > 0) appName = name[..dashIdx];

                result.Add(new TimelineEvent
                {
                    LogName = "Prefetch",
                    EventId = 0,
                    Timestamp = File.GetLastWriteTimeUtc(file).ToString("o"),
                    Level = "Information",
                    Source = "Prefetch",
                    Description = $"程序运行: {appName}",
                    Severity = "info",
                    Category = 1000
                });
            }
        }
        catch (UnauthorizedAccessException)
        {
            result.Add(new TimelineEvent
            {
                LogName = "Prefetch",
                EventId = 0, Timestamp = DateTime.UtcNow.ToString("o"),
                Level = "Warning", Source = "AccessDenied",
                Description = "需要管理员权限读取 Prefetch 目录"
            });
        }
        catch { }
        return result;
    }

    // ==================== USB HISTORY ====================

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
                    var friendlyName = snKey?.GetValue("FriendlyName")?.ToString() ?? device;
                    var hwId = (snKey?.GetValue("HardwareID") as string[])?.FirstOrDefault() ?? "";

                    result.Add(new TimelineEvent
                    {
                        LogName = "USB",
                        EventId = 1001,
                        Timestamp = DateTime.UtcNow.ToString("o"),
                        Level = "Information",
                        Source = "USBSTOR",
                        Description = $"USB设备: {friendlyName} [序列号: {sn}]",
                        Severity = "info"
                    });
                }
            }
        }
        catch { }
        return result;
    }

    // ==================== LEGACY API (for backward compat) ====================

    public async Task<EventLogData> CollectEventLogsAsync(int sinceDays = 7)
    {
        try
        {
            return await _runner.RunCollectorAsync<EventLogData>(
                "EventLogCollector/EventLogCollector.exe", $"--since {sinceDays}");
        }
        catch
        {
            return CollectAllLogs(sinceDays);
        }
    }

    public EventLogData CollectEventLogsDirect(int sinceDays = 7)
    {
        return CollectAllLogs(sinceDays);
    }
}
