using System.Text.Json.Serialization;

namespace AuditGuardian.Desktop.Models;

public class ScanSummary
{
    [JsonPropertyName("critical")] public int Critical { get; set; }
    [JsonPropertyName("high")] public int High { get; set; }
    [JsonPropertyName("medium")] public int Medium { get; set; }
    [JsonPropertyName("low")] public int Low { get; set; }
}

public class ScanFinding
{
    [JsonPropertyName("type")] public string Type { get; set; } = "";
    [JsonPropertyName("severity")] public string Severity { get; set; } = "";
    [JsonPropertyName("description")] public string Description { get; set; } = "";
    [JsonPropertyName("matched_rule")] public string MatchedRule { get; set; } = "";
    [JsonPropertyName("found_at")] public string FoundAt { get; set; } = "";
    [JsonPropertyName("status")] public string Status { get; set; } = "";
}

public class KernelChecks
{
    [JsonPropertyName("ssdt_hooked")] public bool SsdtHooked { get; set; }
    [JsonPropertyName("ssdt_hooks")] public List<object> SsdtHooks { get; set; } = new();
    [JsonPropertyName("unusual_callbacks")] public List<object> UnusualCallbacks { get; set; } = new();
    [JsonPropertyName("filter_drivers")] public List<object> FilterDrivers { get; set; } = new();
}

public class ScanResult
{
    [JsonPropertyName("scanned_at")] public string ScannedAt { get; set; } = "";
    [JsonPropertyName("total_checks")] public int TotalChecks { get; set; }
    [JsonPropertyName("findings")] public List<ScanFinding> Findings { get; set; } = new();
    [JsonPropertyName("kernel_checks")] public KernelChecks? KernelChecks { get; set; }
    [JsonPropertyName("summary")] public ScanSummary? Summary { get; set; }
}

public class SignatureEntry
{
    public string Name { get; set; } = "";
    public List<string> Patterns { get; set; } = new();
    public List<string> Hashes { get; set; } = new();
    public string Severity { get; set; } = "medium";
    public string Category { get; set; } = "";
    public string Description { get; set; } = "";
}
