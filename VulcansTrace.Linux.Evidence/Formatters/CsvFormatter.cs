using System.Globalization;
using System.Text;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Evidence.Formatters;

/// <summary>
/// Formats analysis results as CSV (Comma-Separated Values).
/// </summary>
/// <remarks>
/// Produces RFC 4180-compliant CSV with proper quoting and escaping.
/// </remarks>
public sealed class CsvFormatter : IEvidenceFormatter
{
    /// <summary>
    /// Converts analysis results to CSV format.
    /// </summary>
    /// <param name="result">The analysis result to format.</param>
    /// <returns>A string containing the findings in CSV format.</returns>
    public string ToCsv(AnalysisResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("RuleId,Category,Severity,SourceHost,Target,TimeStart,TimeEnd,ShortDescription,CisControlIds,CisBenchmarkReferences,CisWhyItMatters,MitreTechniqueIds,MitreTechniqueNames,MitreTactics");

        foreach (var f in result.Findings)
        {
            var cisIds = string.Join("; ", f.CisMappings.Select(m => m.ControlId));
            var cisBenchmarks = string.Join("; ", f.CisMappings.Select(m => m.BenchmarkReference).Where(r => !string.IsNullOrWhiteSpace(r)));
            var cisWhy = string.Join("; ", f.CisMappings.Select(m => m.WhyItMatters));
            var mitreIds = string.Join("; ", f.MitreTechniques.Select(m => m.TechniqueId));
            var mitreNames = string.Join("; ", f.MitreTechniques.Select(m => m.TechniqueName));
            var mitreTactics = string.Join("; ", f.MitreTechniques.Select(m => m.Tactic));
            var fields = new[]
            {
                f.RuleId ?? string.Empty,
                f.Category,
                f.Severity.ToString(),
                f.SourceHost,
                f.Target,
                f.TimeRangeStart.ToString("o", CultureInfo.InvariantCulture),
                f.TimeRangeEnd.ToString("o", CultureInfo.InvariantCulture),
                f.ShortDescription,
                cisIds,
                cisBenchmarks,
                cisWhy,
                mitreIds,
                mitreNames,
                mitreTactics
            };

            sb.AppendLine(string.Join(",", fields.Select(Escape)));
        }

        if (!string.IsNullOrWhiteSpace(result.CapabilityReport))
        {
            sb.AppendLine();
            sb.AppendLine("DataSources");
            sb.AppendLine(Escape(result.CapabilityReport));
        }

        if (result.Warnings.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Warnings");
            foreach (var warning in result.Warnings)
            {
                sb.AppendLine(Escape(warning));
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Formats active suppressions as a CSV string.
    /// </summary>
    public string ToSuppressionCsv(AnalysisResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("RuleId,Target,Fingerprint,Reason,CreatedAt,ExpiresAt,ReviewDate");

        foreach (var s in result.ActiveSuppressions)
        {
            var fields = new[]
            {
                s.RuleId,
                s.Target,
                s.Fingerprint ?? "",
                s.Reason,
                s.CreatedAt.ToString("o", CultureInfo.InvariantCulture),
                s.ExpiresAt?.ToString("o", CultureInfo.InvariantCulture) ?? "",
                s.ReviewDate?.ToString("o", CultureInfo.InvariantCulture) ?? ""
            };
            sb.AppendLine(string.Join(",", fields.Select(Escape)));
        }

        return sb.ToString();
    }

    string IEvidenceFormatter.Format(AnalysisResult result, string originalLog) => ToCsv(result);

    string IEvidenceFormatter.FileExtension => ".csv";

    string IEvidenceFormatter.ContentType => "text/csv";

    private static string Escape(string value)
    {
        if (value == null) return "";
        var sanitized = value;
        if (!string.IsNullOrEmpty(sanitized))
        {
            var trimmedStart = sanitized.TrimStart(' ', '\t', '\r', '\n');
            if (StartsWithFormulaPrefix(sanitized) ||
                StartsWithFormulaPrefix(trimmedStart) ||
                sanitized[0] == '\t' ||
                sanitized[0] == '\r' ||
                sanitized[0] == '\n')
            {
                sanitized = "'" + sanitized;
            }
        }

        if (sanitized.Contains('"') || sanitized.Contains(',') || sanitized.Contains('\n') || sanitized.Contains('\r'))
        {
            var escaped = sanitized.Replace("\"", "\"\"");
            return $"\"{escaped}\"";
        }

        return sanitized;
    }

    private static bool StartsWithFormulaPrefix(string value)
    {
        return value.Length > 0 && (value[0] == '=' || value[0] == '+' || value[0] == '-' || value[0] == '@');
    }
}
