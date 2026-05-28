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
        sb.AppendLine("Category,Severity,SourceHost,Target,TimeStart,TimeEnd,ShortDescription");

        foreach (var f in result.Findings)
        {
            var fields = new[]
            {
                f.Category,
                f.Severity.ToString(),
                f.SourceHost,
                f.Target,
                f.TimeRangeStart.ToString("o", CultureInfo.InvariantCulture),
                f.TimeRangeEnd.ToString("o", CultureInfo.InvariantCulture),
                f.ShortDescription
            };

            sb.AppendLine(string.Join(",", fields.Select(Escape)));
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
