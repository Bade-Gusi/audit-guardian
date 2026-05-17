namespace AuditGuardian.Desktop.Models;

public class KernelDetectionResult
{
    public string ScannedAt { get; set; } = "";
    public bool SsdtHooked { get; set; }
    public List<KernelModule> LoadedModules { get; set; } = new();
    public List<NtdllHook> NtdllHooks { get; set; } = new();
    public List<HiddenProcessInfo> HiddenProcesses { get; set; } = new();
    public List<DetectionFinding> SuspiciousDrivers { get; set; } = new();
    public List<DetectionFinding> UnusualCallbacks { get; set; } = new();
    public List<DetectionFinding> UnsignedDrivers { get; set; } = new();

    public int TotalRiskItems =>
        NtdllHooks.Count + HiddenProcesses.Count +
        SuspiciousDrivers.Count + UnsignedDrivers.Count;
}

public class KernelModule
{
    public string Name { get; set; } = "";
    public string FullPath { get; set; } = "";
    public IntPtr ImageBase { get; set; }
    public int ImageSize { get; set; }
    public short LoadOrder { get; set; }
}

public class NtdllHook
{
    public string FunctionName { get; set; } = "";
    public string HookType { get; set; } = "";
    public string HookAddress { get; set; } = "";
    public string TargetAddress { get; set; } = "";
}

public class HiddenProcessInfo
{
    public int Pid { get; set; }
    public string ProcessName { get; set; } = "";
    public string SuspicionReason { get; set; } = "";
}

public class DetectionFinding
{
    public string Type { get; set; } = "";
    public string Severity { get; set; } = "medium";
    public string Description { get; set; } = "";
    public string Detail { get; set; } = "";
    public string MatchedRule { get; set; } = "";
    public string FoundAt { get; set; } = "";
}
