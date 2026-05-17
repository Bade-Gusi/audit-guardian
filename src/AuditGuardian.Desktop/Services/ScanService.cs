using System.Diagnostics;
using System.Management;
using System.Text.Json;
using AuditGuardian.Desktop.Models;

namespace AuditGuardian.Desktop.Services;

public class ScanService
{
    private readonly string _signaturesDir;

    public ScanService()
    {
        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        // Try various paths to find signature files
        string[] possiblePaths =
        {
            Path.Combine(baseDir, "..", "..", "..", "..", "..", "client", "resources", "signatures"),
            Path.Combine(baseDir, "..", "..", "..", "..", "..", "resources", "signatures"),
            Path.Combine(baseDir, "resources", "signatures"),
        };

        _signaturesDir = possiblePaths.FirstOrDefault(Directory.Exists) ?? baseDir;
    }

    public event Action<int, string>? Progress;

    public async Task<ScanResult> RunFullScanAsync()
    {
        var findings = new List<ScanFinding>();
        var totalChecks = 0;

        // Load signature databases
        var processBlacklist = LoadSignatures("process_blacklist.json");
        var driverBlacklist = LoadSignatures("driver_blacklist.json");

        // 1. Process scan
        Progress?.Invoke(10, "扫描进程...");
        var processes = Process.GetProcesses();
        totalChecks += processes.Length;
        foreach (var proc in processes)
        {
            try
            {
                var match = processBlacklist.FirstOrDefault(s =>
                    s.Patterns.Any(p => MatchesPattern(proc.ProcessName, p)));
                if (match != null)
                {
                    findings.Add(new ScanFinding
                    {
                        Type = "process",
                        Severity = match.Severity,
                        Description = $"可疑进程: {proc.ProcessName}.exe",
                        MatchedRule = $"process_name:{match.Name}",
                        FoundAt = DateTime.Now.ToString("o"),
                        Status = "running"
                    });
                }
            }
            catch { /* access denied to some processes */ }
        }

        // 2. Service scan
        Progress?.Invoke(30, "扫描服务...");
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, PathName, State FROM Win32_Service");
            foreach (var svc in searcher.Get())
            {
                totalChecks++;
                var name = svc["Name"]?.ToString() ?? "";
                var path = svc["PathName"]?.ToString() ?? "";
                var match = driverBlacklist.FirstOrDefault(s =>
                    s.Patterns.Any(p => MatchesPattern(name, p) || MatchesPattern(path, p)));
                if (match != null)
                {
                    findings.Add(new ScanFinding
                    {
                        Type = "service",
                        Severity = match.Severity,
                        Description = $"可疑服务: {name}",
                        MatchedRule = $"service_pattern:{match.Name}",
                        FoundAt = DateTime.Now.ToString("o"),
                        Status = "installed"
                    });
                }
            }
        }
        catch { }

        // 3. Driver/module scan
        Progress?.Invoke(50, "扫描内核模块...");
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, State, PathName FROM Win32_SystemDriver");
            foreach (var drv in searcher.Get())
            {
                totalChecks++;
                var name = drv["Name"]?.ToString() ?? "";
                var match = driverBlacklist.FirstOrDefault(s =>
                    s.Patterns.Any(p => MatchesPattern(name, p)));
                if (match != null)
                {
                    findings.Add(new ScanFinding
                    {
                        Type = "driver",
                        Severity = match.Severity,
                        Description = $"可疑驱动: {name}",
                        MatchedRule = $"driver_pattern:{match.Name}",
                        FoundAt = DateTime.Now.ToString("o"),
                        Status = "installed"
                    });
                }
            }
        }
        catch { }

        // 4. Registry scan
        Progress?.Invoke(70, "扫描注册表...");
        totalChecks += ScanRegistryRunKeys(findings);

        // 5. Network connections
        Progress?.Invoke(85, "扫描网络连接...");
        totalChecks += ScanNetworkConnections(findings);

        // 6. Kernel-level detection (NTDLL hooks, hidden processes, suspicious drivers)
        Progress?.Invoke(90, "内核层检测...");
        var kernel = new KernelDetectionService();
        var kernelResult = kernel.RunKernelDetection();

        // Add NTDLL hooks
        foreach (var hook in kernelResult.NtdllHooks)
        {
            findings.Add(new ScanFinding
            {
                Type = "kernel_hook",
                Severity = "high",
                Description = $"NTDLL 函数被 Hook: {hook.FunctionName} ({hook.HookType})",
                MatchedRule = $"ntdll_hook:{hook.FunctionName}",
                FoundAt = hook.HookAddress,
                Status = "persistent"
            });
        }

        // Add suspicious drivers
        foreach (var drv in kernelResult.SuspiciousDrivers)
        {
            findings.Add(new ScanFinding
            {
                Type = "kernel_driver",
                Severity = drv.Severity,
                Description = drv.Description,
                MatchedRule = drv.MatchedRule,
                FoundAt = DateTime.Now.ToString("o"),
                Status = "installed"
            });
        }

        // Add unsigned driver warnings
        foreach (var drv in kernelResult.UnsignedDrivers)
        {
            findings.Add(new ScanFinding
            {
                Type = "unsigned_driver",
                Severity = "medium",
                Description = drv.Description,
                MatchedRule = drv.MatchedRule,
                FoundAt = DateTime.Now.ToString("o"),
                Status = "installed"
            });
        }

        // Add hidden processes
        foreach (var hp in kernelResult.HiddenProcesses)
        {
            findings.Add(new ScanFinding
            {
                Type = "hidden_process",
                Severity = "critical",
                Description = $"隐藏进程: PID {hp.Pid} ({hp.ProcessName}) - {hp.SuspicionReason}",
                MatchedRule = "hidden_process_detection",
                FoundAt = DateTime.Now.ToString("o"),
                Status = "running"
            });
        }

        totalChecks += kernelResult.LoadedModules.Count;

        Progress?.Invoke(100, "扫描完成");

        return new ScanResult
        {
            ScannedAt = DateTime.Now.ToString("o"),
            TotalChecks = totalChecks,
            Findings = findings,
            Summary = new ScanSummary
            {
                Critical = findings.Count(f => f.Severity == "critical"),
                High = findings.Count(f => f.Severity == "high"),
                Medium = findings.Count(f => f.Severity == "medium"),
                Low = findings.Count(f => f.Severity == "low"),
            }
        };
    }

    private List<SignatureEntry> LoadSignatures(string filename)
    {
        try
        {
            var path = Path.Combine(_signaturesDir, filename);
            if (!File.Exists(path)) return new List<SignatureEntry>();

            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<List<SignatureEntry>>(json) ?? new();
        }
        catch
        {
            return new List<SignatureEntry>();
        }
    }

    private static bool MatchesPattern(string input, string pattern)
    {
        if (string.IsNullOrEmpty(input) || string.IsNullOrEmpty(pattern))
            return false;

        // Simple wildcard: convert * to .* for regex
        var regex = "^" + System.Text.RegularExpressions.Regex.Escape(pattern)
            .Replace("\\*", ".*") + "$";
        return System.Text.RegularExpressions.Regex.IsMatch(input, regex,
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }

    private int ScanRegistryRunKeys(List<ScanFinding> findings)
    {
        int count = 0;
        string[] runKeyPaths =
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        };

        foreach (var keyPath in runKeyPaths)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath);
                if (key != null) count += key.ValueCount;

                using var cuKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(keyPath);
                if (cuKey != null) count += cuKey.ValueCount;
            }
            catch { }
        }
        return count;
    }

    private int ScanNetworkConnections(List<ScanFinding> findings)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM MSFT_NetTCPConnection");
            return searcher.Get().Count;
        }
        catch { return 0; }
    }
}
