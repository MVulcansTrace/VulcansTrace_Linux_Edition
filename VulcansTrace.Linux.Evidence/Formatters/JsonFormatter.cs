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
        => Format(result, originalLog, DateTime.UtcNow);

    public string Format(AnalysisResult result, string originalLog, DateTime exportTimestampUtc)
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
                ExportTimestamp = NormalizeUtc(exportTimestampUtc),
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
                RuleId = f.RuleId,
                Category = f.Category,
                Severity = f.Severity.ToString(),
                Confidence = f.Confidence.ToString(),
                EvidenceSignals = f.EvidenceSignals.Select(s => new EvidenceSignalExportModel
                {
                    Name = s.Name,
                    Source = s.Source,
                    Explanation = s.Explanation
                }).ToArray(),
                SourceHost = f.SourceHost,
                Target = f.Target,
                TimeRangeStart = f.TimeRangeStart,
                TimeRangeEnd = f.TimeRangeEnd,
                ShortDescription = f.ShortDescription,
                Details = f.Details,
                CisMappings = f.CisMappings.Select(m => new CisMappingExportModel
                {
                    ControlId = m.ControlId,
                    ControlName = m.ControlName,
                    WhyItMatters = m.WhyItMatters,
                    BenchmarkReference = m.BenchmarkReference
                }).ToArray(),
                MitreTechniques = f.MitreTechniques.Select(m => new MitreTechniqueExportModel
                {
                    TechniqueId = m.TechniqueId,
                    TechniqueName = m.TechniqueName,
                    Tactic = m.Tactic,
                    WhyItMatters = m.WhyItMatters
                }).ToArray()
            }).ToArray(),
            ParseErrors = result.ParseErrors.ToArray(),
            Warnings = result.Warnings.ToArray(),
            RiskScorecard = result.RiskScorecard == null ? null : new RiskScorecardExportModel
            {
                NumericScore = result.RiskScorecard.NumericScore,
                LetterGrade = result.RiskScorecard.LetterGrade,
                SummaryStatus = result.RiskScorecard.SummaryStatus,
                TotalFindings = result.RiskScorecard.TotalFindings,
                ByCategory = result.RiskScorecard.ByCategory.Select(c => new CategoryRiskExportModel
                {
                    Category = c.Category,
                    FindingCount = c.FindingCount,
                    AverageSeverity = c.AverageSeverity,
                    TotalDeduction = c.TotalDeduction
                }).ToArray()
            }
        };

        return JsonSerializer.Serialize(exportModel, jsonOptions);
    }

    private static DateTime NormalizeUtc(DateTime value) =>
        value.Kind switch
        {
            DateTimeKind.Utc => value,
            DateTimeKind.Local => value.ToUniversalTime(),
            _ => DateTime.SpecifyKind(value, DateTimeKind.Utc)
        };
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
    public RiskScorecardExportModel? RiskScorecard { get; set; }
}

public class RiskScorecardExportModel
{
    public double NumericScore { get; set; }
    public string LetterGrade { get; set; } = string.Empty;
    public string SummaryStatus { get; set; } = string.Empty;
    public int TotalFindings { get; set; }
    public CategoryRiskExportModel[] ByCategory { get; set; } = Array.Empty<CategoryRiskExportModel>();
}

public class CategoryRiskExportModel
{
    public string Category { get; set; } = string.Empty;
    public int FindingCount { get; set; }
    public double AverageSeverity { get; set; }
    public double TotalDeduction { get; set; }
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
    public string? RuleId { get; set; }
    public string Category { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Confidence { get; set; } = string.Empty;
    public EvidenceSignalExportModel[] EvidenceSignals { get; set; } = Array.Empty<EvidenceSignalExportModel>();
    public string SourceHost { get; set; } = string.Empty;
    public string Target { get; set; } = string.Empty;
    public DateTime TimeRangeStart { get; set; }
    public DateTime TimeRangeEnd { get; set; }
    public string ShortDescription { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
    public CisMappingExportModel[] CisMappings { get; set; } = Array.Empty<CisMappingExportModel>();
    public MitreTechniqueExportModel[] MitreTechniques { get; set; } = Array.Empty<MitreTechniqueExportModel>();
}

public class MitreTechniqueExportModel
{
    public string TechniqueId { get; set; } = string.Empty;
    public string TechniqueName { get; set; } = string.Empty;
    public string Tactic { get; set; } = string.Empty;
    public string WhyItMatters { get; set; } = string.Empty;
}

public class CisMappingExportModel
{
    public string ControlId { get; set; } = string.Empty;
    public string ControlName { get; set; } = string.Empty;
    public string WhyItMatters { get; set; } = string.Empty;
    public string? BenchmarkReference { get; set; }
}

public class EvidenceSignalExportModel
{
    public string Name { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string Explanation { get; set; } = string.Empty;
}
