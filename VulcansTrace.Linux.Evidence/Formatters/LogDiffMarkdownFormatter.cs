using System.Text;
using VulcansTrace.Linux.Engine.LogDiff;

namespace VulcansTrace.Linux.Evidence.Formatters;

/// <summary>
/// Formats a <see cref="LogDiffResult"/> as a Markdown unified diff report.
/// </summary>
public sealed class LogDiffMarkdownFormatter
{
    /// <summary>
    /// Converts the log diff result to Markdown format.
    /// </summary>
    /// <param name="result">The diff result to format.</param>
    /// <param name="baselineLabel">Optional label for the baseline file.</param>
    /// <param name="incidentLabel">Optional label for the incident file.</param>
    /// <returns>A Markdown string.</returns>
    public string ToMarkdown(LogDiffResult result, string baselineLabel = "Baseline", string incidentLabel = "Incident")
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Log Diff Report");
        sb.AppendLine();
        sb.AppendLine($"* **{baselineLabel}**: {result.BaselineTimeRangeStart:O} – {result.BaselineTimeRangeEnd:O}");
        sb.AppendLine($"* **{incidentLabel}**: {result.IncidentTimeRangeStart:O} – {result.IncidentTimeRangeEnd:O}");
        sb.AppendLine();
        sb.AppendLine($"**Summary**: {result.Narrative}");
        sb.AppendLine();

        sb.AppendLine("## Connection Pattern Diff");
        sb.AppendLine();
        sb.AppendLine("| State | Connection | Protocol | Count Δ | Baseline Actions | Incident Actions | First Seen (Baseline) | First Seen (Incident) |");
        sb.AppendLine("|-------|------------|----------|---------|------------------|------------------|-----------------------|-----------------------|");

        foreach (var evt in result.Events)
        {
            var stateEmoji = evt.State switch
            {
                LogDiffState.Added => "🟥 +",
                LogDiffState.Removed => "🟩 −",
                LogDiffState.Changed => "🟡 ~",
                LogDiffState.Unchanged => "⬜ =",
                _ => "?"
            };

            var connection = evt.ConnectionKey;
            var baselineActions = FormatActions(evt.BaselineActions);
            var incidentActions = FormatActions(evt.IncidentActions);
            var baselineFirst = evt.BaselineFirstSeen == DateTime.MinValue ? "—" : evt.BaselineFirstSeen.ToString("O");
            var incidentFirst = evt.IncidentFirstSeen == DateTime.MinValue ? "—" : evt.IncidentFirstSeen.ToString("O");

            sb.AppendLine($"| {stateEmoji} | {Escape(connection)} | {Escape(evt.Protocol)} | {Escape(evt.CountDelta)} | {Escape(baselineActions)} | {Escape(incidentActions)} | {Escape(baselineFirst)} | {Escape(incidentFirst)} |");
        }

        if (result.Findings.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("## Finding Diff");
            sb.AppendLine();
            sb.AppendLine("| State | Category | Severity | Source | Target | Description |");
            sb.AppendLine("|-------|----------|----------|--------|--------|-------------|");

            foreach (var f in result.Findings)
            {
                var stateEmoji = f.State switch
                {
                    LogDiffState.Added => "🟥 +",
                    LogDiffState.Removed => "🟩 −",
                    LogDiffState.Changed => "🟡 ~",
                    LogDiffState.Unchanged => "⬜ =",
                    _ => "?"
                };

                var severity = f.State == LogDiffState.Changed
                    ? $"{f.OldSeverity} → {f.NewSeverity}"
                    : f.Finding.Severity.ToString();

                sb.AppendLine($"| {stateEmoji} | {Escape(f.Finding.Category)} | {Escape(severity)} | {Escape(f.Finding.SourceHost)} | {Escape(f.Finding.Target)} | {Escape(f.Finding.ShortDescription)} |");
            }
        }

        return sb.ToString();
    }

    private static string FormatActions(IReadOnlyDictionary<string, int> actions)
    {
        if (actions.Count == 0) return "—";
        return string.Join(", ", actions.OrderByDescending(kvp => kvp.Value).Select(kvp => $"{kvp.Key} ({kvp.Value})"));
    }

    private static string Escape(string value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        var sanitized = value
            .Replace("\r\n", " / ")
            .Replace("\n", " / ")
            .Replace("&", "&amp;")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;");

        string[] specials = ["\\", "|", "*", "_", "`", "[", "]"];
        foreach (var s in specials)
        {
            sanitized = sanitized.Replace(s, $"\\{s}");
        }

        return sanitized;
    }
}
