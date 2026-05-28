using System.Text.Json;
using System.Text.Json.Serialization;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Evidence.Formatters;

/// <summary>
/// Formatter for exporting findings in JSON format compatible with SIEM systems.
/// </summary>
public class JsonFormatter : IEvidenceFormatter
{
    public string FileExtension => ".json";
    
    public string ContentType => "application/json";

    public string Format(AnalysisResult result, string originalLog)
    {
        var jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        var exportModel = new JsonExportModel
        {
            Metadata = new ExportMetadata
            {
                ToolName = "VulcansTrace Linux Edition",
                Version = typeof(JsonFormatter).Assembly.GetName().Version?.ToString() ?? "unknown",
                ExportTimestamp = DateTime.UtcNow,
                OriginalLogLines = result.TotalLines,
                ParsedEvents = result.ParsedLines,
                AnalysisTimeRange = new TimeRange
                {
                    Start = result.TimeRangeStart,
                    End = result.TimeRangeEnd
                }
            },
            Findings = result.Findings.Select(f => new FindingExportModel
            {
                Id = f.Id.ToString(),
                Category = f.Category,
                Severity = f.Severity.ToString(),
                SourceHost = f.SourceHost,
                Target = f.Target,
                TimeRangeStart = f.TimeRangeStart,
                TimeRangeEnd = f.TimeRangeEnd,
                ShortDescription = f.ShortDescription,
                Details = f.Details
            }).ToArray(),
            ParseErrors = result.ParseErrors.ToArray(),
            Warnings = result.Warnings.ToArray()
        };

        return JsonSerializer.Serialize(exportModel, jsonOptions);
    }
}

/// <summary>
/// Model for JSON export structure
/// </summary>
public class JsonExportModel
{
    public ExportMetadata Metadata { get; set; } = new();
    public FindingExportModel[] Findings { get; set; } = Array.Empty<FindingExportModel>();
    public string[] ParseErrors { get; set; } = Array.Empty<string>();
    public string[] Warnings { get; set; } = Array.Empty<string>();
}

public class ExportMetadata
{
    public string ToolName { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public DateTime ExportTimestamp { get; set; }
    public int OriginalLogLines { get; set; }
    public int ParsedEvents { get; set; }
    public TimeRange AnalysisTimeRange { get; set; } = new();
}

public class TimeRange
{
    public DateTime Start { get; set; }
    public DateTime End { get; set; }
}

public class FindingExportModel
{
    public string Id { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string SourceHost { get; set; } = string.Empty;
    public string Target { get; set; } = string.Empty;
    public DateTime TimeRangeStart { get; set; }
    public DateTime TimeRangeEnd { get; set; }
    public string ShortDescription { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
}