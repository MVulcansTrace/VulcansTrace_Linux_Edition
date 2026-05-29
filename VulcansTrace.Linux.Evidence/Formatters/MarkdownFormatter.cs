using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Evidence.Formatters;

/// <summary>
/// Formats analysis results as Markdown.
/// </summary>
/// <remarks>
/// Produces GitHub-flavored Markdown with tables and proper escaping of special characters.
/// </remarks>
public sealed class MarkdownFormatter : IEvidenceFormatter
{
    /// <summary>
    /// Converts analysis results to Markdown format.
    /// </summary>
    /// <param name="result">The analysis result to format.</param>
    /// <returns>A string containing the analysis summary and findings in Markdown format.</returns>
    public string ToMarkdown(AnalysisResult result)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("# VulcansTrace Analysis Summary");
        sb.AppendLine();

        sb.AppendLine($"* Total lines: {result.TotalLines}");
        sb.AppendLine($"* Parsed lines: {result.ParsedLines}");

        if (result.TimeRangeStart != DateTime.MinValue && result.TimeRangeEnd != DateTime.MinValue)
        {
            sb.AppendLine($"* Time range: {result.TimeRangeStart:O} – {result.TimeRangeEnd:O}");
        }

        if (result.Warnings.Count > 0)
        {
            sb.AppendLine($"* Warnings: {result.Warnings.Count}");
        }

        sb.AppendLine();
        sb.AppendLine("## Warnings");
        if (result.Warnings.Count == 0)
        {
            sb.AppendLine("* None");
        }
        else
        {
            foreach (var warning in result.Warnings)
            {
                sb.AppendLine($"* {Escape(warning)}");
            }
        }
        sb.AppendLine();
        sb.AppendLine("## Findings by Severity");
        var bySeverity = result.Findings.GroupBy(f => f.Severity)
            .OrderByDescending(g => g.Key);

        foreach (var g in bySeverity)
        {
            sb.AppendLine($"* {g.Key}: {g.Count()}");
        }

        if (result.SuppressedCount > 0 || result.ActiveSuppressions.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("## Suppression Notes");
            sb.AppendLine($"* Suppressed findings: {result.SuppressedCount}");
            sb.AppendLine($"* Active suppressions: {result.ActiveSuppressions.Count}");
            if (result.ActiveSuppressions.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("| Rule ID | Target | Reason | Created | Expires | Review |");
                sb.AppendLine("|---------|--------|--------|---------|---------|--------|");
                foreach (var s in result.ActiveSuppressions)
                {
                    var expires = s.ExpiresAt.HasValue ? s.ExpiresAt.Value.ToString("yyyy-MM-dd") : "Never";
                    var review = s.ReviewDate.HasValue ? s.ReviewDate.Value.ToString("yyyy-MM-dd") : "Never";
                    sb.AppendLine($"| {Escape(s.RuleId)} | {Escape(s.Target)} | {Escape(s.Reason)} | {s.CreatedAt:yyyy-MM-dd} | {expires} | {review} |");
                }
            }
        }

        sb.AppendLine();
        sb.AppendLine("## Findings");
        sb.AppendLine();
        sb.AppendLine("| Rule ID | Category | Severity | Source | Target | Start | End | Description |");
        sb.AppendLine("|---------|----------|----------|--------|--------|-------|-----|-------------|");

        foreach (var f in result.Findings)
        {
            sb.AppendLine($"| {Escape(f.RuleId ?? string.Empty)} | {Escape(f.Category)} | {Escape(f.Severity.ToString())} | {Escape(f.SourceHost)} | {Escape(f.Target)} | {Escape(f.TimeRangeStart.ToString("O"))} | {Escape(f.TimeRangeEnd.ToString("O"))} | {Escape(f.ShortDescription)} |");
        }

        return sb.ToString();
    }

    string IEvidenceFormatter.Format(AnalysisResult result, string originalLog) => ToMarkdown(result);

    string IEvidenceFormatter.FileExtension => ".md";

    string IEvidenceFormatter.ContentType => "text/markdown";

    private static string Escape(string value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        // Replace newlines to avoid breaking table rows, and encode raw HTML.
        var sanitized = value
            .Replace("\r\n", " / ")
            .Replace("\n", " / ")
            .Replace("&", "&amp;")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;");

        // Escape markdown special characters used in tables and emphasis
        string[] specials = ["\\", "|", "*", "_", "`", "[", "]"];
        foreach (var s in specials)
        {
            sanitized = sanitized.Replace(s, $"\\{s}");
        }

        return sanitized;
    }
}
