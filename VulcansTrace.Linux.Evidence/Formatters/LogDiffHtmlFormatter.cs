using System.Text;
using VulcansTrace.Linux.Engine.LogDiff;

namespace VulcansTrace.Linux.Evidence.Formatters;

/// <summary>
/// Formats a <see cref="LogDiffResult"/> as a styled HTML diff report.
/// </summary>
public sealed class LogDiffHtmlFormatter
{
    /// <summary>
    /// Converts the log diff result to a complete HTML document.
    /// </summary>
    /// <param name="result">The diff result to format.</param>
    /// <param name="baselineLabel">Optional label for the baseline file.</param>
    /// <param name="incidentLabel">Optional label for the incident file.</param>
    /// <returns>An HTML string.</returns>
    public string ToHtml(LogDiffResult result, string baselineLabel = "Baseline", string incidentLabel = "Incident")
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html><head><meta charset=\"utf-8\" />");
        sb.AppendLine("<title>VulcansTrace Log Diff</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("body { background:#111; color:#eee; font-family:Segoe UI,Arial,sans-serif; margin:24px; }");
        sb.AppendLine("table { border-collapse:collapse; width:100%; margin-top:12px; }");
        sb.AppendLine("th,td { border:1px solid #444; padding:6px 8px; text-align:left; }");
        sb.AppendLine("th { background:#222; color:#cbd5e1; }");
        sb.AppendLine(".added { background:#3f1515; color:#fecaca; }");
        sb.AppendLine(".removed { background:#142f1f; color:#bbf7d0; }");
        sb.AppendLine(".changed { background:#3f2e14; color:#fde047; }");
        sb.AppendLine(".unchanged { opacity:0.45; }");
        sb.AppendLine(".badge { display:inline-block; padding:4px 10px; border-radius:4px; font-weight:bold; font-size:12px; margin-right:8px; }");
        sb.AppendLine(".badge-added { background:#3f1515; color:#fecaca; border:1px solid #7f1d1d; }");
        sb.AppendLine(".badge-removed { background:#142f1f; color:#bbf7d0; border:1px solid #166534; }");
        sb.AppendLine(".badge-changed { background:#3f2e14; color:#fde047; border:1px solid #854d0e; }");
        sb.AppendLine(".badge-unchanged { background:#1e293b; color:#94a3b8; border:1px solid #334155; }");
        sb.AppendLine("</style></head><body>");
        sb.AppendLine("<h1>🔍 Log Diff Report</h1>");

        sb.AppendLine("<p>");
        sb.AppendLine($"<strong>{HtmlEncode(baselineLabel)}</strong>: {result.BaselineTimeRangeStart:O} – {result.BaselineTimeRangeEnd:O}<br/>");
        sb.AppendLine($"<strong>{HtmlEncode(incidentLabel)}</strong>: {result.IncidentTimeRangeStart:O} – {result.IncidentTimeRangeEnd:O}");
        sb.AppendLine("</p>");

        sb.AppendLine("<p>");
        sb.AppendLine($"<span class=\"badge badge-added\">+ {result.AddedCount} Added</span>");
        sb.AppendLine($"<span class=\"badge badge-removed\">− {result.RemovedCount} Removed</span>");
        sb.AppendLine($"<span class=\"badge badge-changed\">~ {result.ChangedCount} Changed</span>");
        sb.AppendLine($"<span class=\"badge badge-unchanged\">= {result.UnchangedCount} Unchanged</span>");
        sb.AppendLine("</p>");

        sb.AppendLine($"<p><strong>Summary:</strong> {HtmlEncode(result.Narrative)}</p>");

        sb.AppendLine("<h2>Connection Pattern Diff</h2>");
        sb.AppendLine("<table>");
        sb.AppendLine("<tr><th>State</th><th>Connection</th><th>Protocol</th><th>Count Δ</th><th>Baseline Actions</th><th>Incident Actions</th><th>Baseline Range</th><th>Incident Range</th></tr>");

        foreach (var evt in result.Events)
        {
            var cssClass = evt.State switch
            {
                LogDiffState.Added => "added",
                LogDiffState.Removed => "removed",
                LogDiffState.Changed => "changed",
                LogDiffState.Unchanged => "unchanged",
                _ => ""
            };

            var stateLabel = evt.State switch
            {
                LogDiffState.Added => "+ Added",
                LogDiffState.Removed => "− Removed",
                LogDiffState.Changed => "~ Changed",
                LogDiffState.Unchanged => "= Unchanged",
                _ => "?"
            };

            var connection = evt.ConnectionKey;
            var baselineActions = FormatActions(evt.BaselineActions);
            var incidentActions = FormatActions(evt.IncidentActions);
            var baselineRange = evt.BaselineFirstSeen == DateTime.MinValue ? "—" : $"{evt.BaselineFirstSeen:O} – {evt.BaselineLastSeen:O}";
            var incidentRange = evt.IncidentFirstSeen == DateTime.MinValue ? "—" : $"{evt.IncidentFirstSeen:O} – {evt.IncidentLastSeen:O}";

            sb.AppendLine($"<tr class=\"{cssClass}\">");
            sb.AppendLine($"<td>{HtmlEncode(stateLabel)}</td>");
            sb.AppendLine($"<td>{HtmlEncode(connection)}</td>");
            sb.AppendLine($"<td>{HtmlEncode(evt.Protocol)}</td>");
            sb.AppendLine($"<td>{HtmlEncode(evt.CountDelta)}</td>");
            sb.AppendLine($"<td>{HtmlEncode(baselineActions)}</td>");
            sb.AppendLine($"<td>{HtmlEncode(incidentActions)}</td>");
            sb.AppendLine($"<td>{HtmlEncode(baselineRange)}</td>");
            sb.AppendLine($"<td>{HtmlEncode(incidentRange)}</td>");
            sb.AppendLine("</tr>");
        }

        sb.AppendLine("</table>");

        if (result.Findings.Count > 0)
        {
            sb.AppendLine("<h2>Finding Diff</h2>");
            sb.AppendLine("<table>");
            sb.AppendLine("<tr><th>State</th><th>Category</th><th>Severity</th><th>Source</th><th>Target</th><th>Description</th></tr>");

            foreach (var f in result.Findings)
            {
                var cssClass = f.State switch
                {
                    LogDiffState.Added => "added",
                    LogDiffState.Removed => "removed",
                    LogDiffState.Changed => "changed",
                    LogDiffState.Unchanged => "unchanged",
                    _ => ""
                };

                var stateLabel = f.State switch
                {
                    LogDiffState.Added => "+ Added",
                    LogDiffState.Removed => "− Removed",
                    LogDiffState.Changed => "~ Changed",
                    LogDiffState.Unchanged => "= Unchanged",
                    _ => "?"
                };

                var severity = f.State == LogDiffState.Changed
                    ? $"{f.OldSeverity} → {f.NewSeverity}"
                    : f.Finding.Severity.ToString();

                sb.AppendLine($"<tr class=\"{cssClass}\">");
                sb.AppendLine($"<td>{HtmlEncode(stateLabel)}</td>");
                sb.AppendLine($"<td>{HtmlEncode(f.Finding.Category)}</td>");
                sb.AppendLine($"<td>{HtmlEncode(severity)}</td>");
                sb.AppendLine($"<td>{HtmlEncode(f.Finding.SourceHost)}</td>");
                sb.AppendLine($"<td>{HtmlEncode(f.Finding.Target)}</td>");
                sb.AppendLine($"<td>{HtmlEncode(f.Finding.ShortDescription)}</td>");
                sb.AppendLine("</tr>");
            }

            sb.AppendLine("</table>");
        }

        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    private static string FormatActions(IReadOnlyDictionary<string, int> actions)
    {
        if (actions.Count == 0) return "—";
        return string.Join(", ", actions.OrderByDescending(kvp => kvp.Value).Select(kvp => $"{kvp.Key} ({kvp.Value})"));
    }

    private static string HtmlEncode(string value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;
        return System.Net.WebUtility.HtmlEncode(value);
    }
}
