using System.Text.Json.Serialization;

namespace AuditGuardian.Desktop.Models;

public class TimelineEvent
{
    [JsonPropertyName("log_name")] public string LogName { get; set; } = "";
    [JsonPropertyName("event_id")] public long EventId { get; set; }
    [JsonPropertyName("timestamp")] public string Timestamp { get; set; } = "";
    [JsonPropertyName("level")] public string Level { get; set; } = "Information";
    [JsonPropertyName("source")] public string Source { get; set; } = "";
    [JsonPropertyName("category")] public int Category { get; set; }
    [JsonPropertyName("user_name")] public string UserName { get; set; } = "";
    [JsonPropertyName("description")] public string Description { get; set; } = "";
    [JsonPropertyName("severity")] public string Severity { get; set; } = "info";
}

public class FileActivityEvent
{
    [JsonPropertyName("activity_type")] public string ActivityType { get; set; } = "";
    [JsonPropertyName("file_path")] public string FilePath { get; set; } = "";
    [JsonPropertyName("timestamp")] public string Timestamp { get; set; } = "";
    [JsonPropertyName("process_name")] public string ProcessName { get; set; } = "";
    [JsonPropertyName("source")] public string Source { get; set; } = "";
    [JsonPropertyName("detail")] public string Detail { get; set; } = "";
}

public class EventSummary
{
    [JsonPropertyName("by_type")] public Dictionary<string, int> ByType { get; set; } = new();
    [JsonPropertyName("by_date")] public Dictionary<string, int> ByDate { get; set; } = new();
}

public class EventLogData
{
    [JsonPropertyName("total_events")] public int TotalEvents { get; set; }
    [JsonPropertyName("time_range")] public TimeRange? TimeRange { get; set; }
    [JsonPropertyName("events")] public List<TimelineEvent> Events { get; set; } = new();
    [JsonPropertyName("summary")] public EventSummary? Summary { get; set; }
}

public class FileActivityData
{
    [JsonPropertyName("total_events")] public int TotalEvents { get; set; }
    [JsonPropertyName("time_range")] public TimeRange? TimeRange { get; set; }
    [JsonPropertyName("events")] public List<FileActivityEvent> Events { get; set; } = new();
    [JsonPropertyName("summary")] public EventSummary? Summary { get; set; }
}

public class TimeRange
{
    [JsonPropertyName("start")] public string Start { get; set; } = "";
    [JsonPropertyName("end")] public string End { get; set; } = "";
}

public class AggregatedTimelineItem
{
    public string Timestamp { get; set; } = "";
    public string Type { get; set; } = "";
    public string Source { get; set; } = "";
    public string Severity { get; set; } = "info";
    public string Description { get; set; } = "";
    public string Detail { get; set; } = "";
}
