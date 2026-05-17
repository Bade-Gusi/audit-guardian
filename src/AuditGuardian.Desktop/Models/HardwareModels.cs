using System.Text.Json.Serialization;

namespace AuditGuardian.Desktop.Models;

public class HardwareProperty
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("value")] public string Value { get; set; } = "";
    [JsonPropertyName("is_spoofed")] public bool IsSpoofed { get; set; }
}

public class HardwareCategory
{
    [JsonPropertyName("category")] public string Category { get; set; } = "";
    [JsonPropertyName("label")] public string Label { get; set; } = "";
    [JsonPropertyName("icon")] public string Icon { get; set; } = "";
    [JsonPropertyName("properties")] public List<HardwareProperty> Properties { get; set; } = new();
    [JsonPropertyName("status")] public string Status { get; set; } = "normal";
}

public class HardwareChange
{
    [JsonPropertyName("category")] public string Category { get; set; } = "";
    [JsonPropertyName("property")] public string Property { get; set; } = "";
    [JsonPropertyName("old_value")] public string OldValue { get; set; } = "";
    [JsonPropertyName("new_value")] public string NewValue { get; set; } = "";
    [JsonPropertyName("changed_at")] public string ChangedAt { get; set; } = "";
    [JsonPropertyName("change_type")] public string ChangeType { get; set; } = "";
}

public class SpoofDetection
{
    [JsonPropertyName("has_spoofed")] public bool HasSpoofed { get; set; }
    [JsonPropertyName("details")] public List<string> Details { get; set; } = new();
}

public class HardwareData
{
    [JsonPropertyName("machine_hash")] public string MachineHash { get; set; } = "";
    [JsonPropertyName("categories")] public List<HardwareCategory> Categories { get; set; } = new();
    [JsonPropertyName("change_history")] public List<HardwareChange> ChangeHistory { get; set; } = new();
    [JsonPropertyName("spoof_detection")] public SpoofDetection SpoofDetection { get; set; } = new();
}
