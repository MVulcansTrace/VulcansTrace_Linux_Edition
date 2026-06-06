using System.Text;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Evidence.Formatters;

/// <summary>
/// Formats analysis results as a styled HTML report.
/// </summary>
/// <remarks>
/// Generates a dark-themed HTML document with findings table and summary statistics.
/// All user-provided content is HTML-encoded to prevent XSS.
/// </remarks>
public sealed class HtmlFormatter : IEvidenceFormatter
{
    /// <summary>
    /// Converts analysis results to a complete HTML document.
    /// </summary>
    /// <param name="result">The analysis result to format.</param>
    /// <returns>A string containing the complete HTML document.</returns>
    public string ToHtml(AnalysisResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html><head><meta charset=\"utf-8\" />");
        sb.AppendLine("<title>VulcansTrace Report</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("body { background:#111; color:#eee; font-family:Segoe UI,Arial,sans-serif; }");
        sb.AppendLine("table { border-collapse:collapse; width:100%; }");
        sb.AppendLine("th,td { border:1px solid #444; padding:4px 6px; }");
        sb.AppendLine("th { background:#222; }");
        sb.AppendLine("</style></head><body>");
        sb.AppendLine("<h1>VulcansTrace Analysis Report</h1>");

        sb.AppendLine("<ul>");
        sb.AppendLine($"<li>Total lines: {result.TotalLines}</li>");
        sb.AppendLine($"<li>Parsed lines: {result.ParsedLines}</li>");
        if (result.ParseErrorCount > 0)
        {
            sb.AppendLine($"<li>Parse errors: {result.ParseErrorCount}</li>");
        }
        if (result.TimeRangeStart != DateTime.MinValue && result.TimeRangeEnd != DateTime.MinValue)
        {
            sb.AppendLine($"<li>Time range: {result.TimeRangeStart:O} – {result.TimeRangeEnd:O}</li>");
        }
        if (result.Warnings.Count > 0)
        {
            sb.AppendLine($"<li>Warnings: {result.Warnings.Count}</li>");
        }
        sb.AppendLine("</ul>");

        if (!string.IsNullOrWhiteSpace(result.CapabilityReport))
        {
            sb.AppendLine("<h2>Data Sources</h2>");
            sb.AppendLine($"<p>{System.Net.WebUtility.HtmlEncode(result.CapabilityReport)}</p>");
        }

        sb.AppendLine("<h2>Warnings</h2>");
        if (result.Warnings.Count == 0)
        {
            sb.AppendLine("<p>None</p>");
        }
        else
        {
            sb.AppendLine("<ul>");
            foreach (var warning in result.Warnings)
            {
                sb.AppendLine($"<li>{System.Net.WebUtility.HtmlEncode(warning)}</li>");
            }
            sb.AppendLine("</ul>");
        }

        if (result.SuppressedCount > 0 || result.ActiveSuppressions.Count > 0)
        {
            sb.AppendLine("<h2>Suppression Notes</h2>");
            sb.AppendLine("<ul>");
            sb.AppendLine($"<li>Suppressed findings: {result.SuppressedCount}</li>");
            sb.AppendLine($"<li>Active suppressions: {result.ActiveSuppressions.Count}</li>");
            sb.AppendLine("</ul>");
            if (result.ActiveSuppressions.Count > 0)
            {
                sb.AppendLine("<table>");
                sb.AppendLine("<tr><th>Rule ID</th><th>Target</th><th>Fingerprint</th><th>Reason</th><th>Created</th><th>Expires</th><th>Review</th></tr>");
                foreach (var s in result.ActiveSuppressions)
                {
                    sb.AppendLine("<tr>");
                    sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(s.RuleId)}</td>");
                    sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(s.Target)}</td>");
                    sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(s.Fingerprint ?? string.Empty)}</td>");
                    sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(s.Reason)}</td>");
                    sb.AppendLine($"<td>{s.CreatedAt:yyyy-MM-dd}</td>");
                    sb.AppendLine($"<td>{(s.ExpiresAt.HasValue ? s.ExpiresAt.Value.ToString("yyyy-MM-dd") : "Never")}</td>");
                    sb.AppendLine($"<td>{(s.ReviewDate.HasValue ? s.ReviewDate.Value.ToString("yyyy-MM-dd") : "Never")}</td>");
                    sb.AppendLine("</tr>");
                }
                sb.AppendLine("</table>");
            }
        }

        sb.AppendLine("<h2>Findings</h2>");
        sb.AppendLine("<table>");
        sb.AppendLine("<tr><th>Rule ID</th><th>Category</th><th>Severity</th><th>Count</th><th>Representative Targets</th><th>Risk Drivers</th><th>Confidence</th><th>Evidence Signals</th><th>Source</th><th>Target</th><th>Start</th><th>End</th><th>Description</th><th>CIS Control</th><th>CIS Benchmark</th><th>MITRE Technique</th></tr>");

        foreach (var f in result.Findings)
        {
            var cisIds = string.Join("; ", f.CisMappings.Select(m => m.ControlId));
            var cisBenchmarks = string.Join("; ", f.CisMappings.Select(m => m.BenchmarkReference).Where(r => !string.IsNullOrWhiteSpace(r)));
            var mitreIds = string.Join("; ", f.MitreTechniques.Select(m => $"{m.TechniqueId} ({m.TechniqueName})"));
            var signals = string.Join("; ", f.EvidenceSignals.Select(s => s.Name));
            var representativeTargets = string.Join("; ", f.RepresentativeTargets);
            var riskDrivers = string.Join("; ", f.RiskDrivers);
            sb.AppendLine("<tr>");
            var groupBadge = f.GroupedCount > 1 ? $"×{f.GroupedCount}" : string.Empty;
            sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(f.RuleId ?? string.Empty)}</td>");
            sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(f.Category)}</td>");
            sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(f.Severity.ToString())}</td>");
            sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(groupBadge)}</td>");
            sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(representativeTargets)}</td>");
            sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(riskDrivers)}</td>");
            sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(f.Confidence.ToString())}</td>");
            sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(signals)}</td>");
            sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(f.SourceHost)}</td>");
            sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(f.Target)}</td>");
            sb.AppendLine($"<td>{f.TimeRangeStart:O}</td>");
            sb.AppendLine($"<td>{f.TimeRangeEnd:O}</td>");
            sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(f.ShortDescription)}</td>");
            sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(cisIds)}</td>");
            sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(cisBenchmarks)}</td>");
            sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(mitreIds)}</td>");
            sb.AppendLine("</tr>");
        }

        sb.AppendLine("</table>");

        var distinctCis = result.Findings
            .SelectMany(f => f.CisMappings)
            .Distinct()
            .ToList();

        if (distinctCis.Count > 0)
        {
            sb.AppendLine("<h2>Compliance Context</h2>");
            sb.AppendLine("<table>");
            sb.AppendLine("<tr><th>CIS Control</th><th>Name</th><th>Why It Matters</th><th>Benchmark Reference</th></tr>");
            foreach (var m in distinctCis)
            {
                sb.AppendLine("<tr>");
                sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(m.ControlId)}</td>");
                sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(m.ControlName)}</td>");
                sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(m.WhyItMatters)}</td>");
                sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(m.BenchmarkReference ?? "—")}</td>");
                sb.AppendLine("</tr>");
            }
            sb.AppendLine("</table>");
        }

        var distinctMitre = result.Findings
            .SelectMany(f => f.MitreTechniques)
            .Distinct()
            .ToList();

        if (distinctMitre.Count > 0)
        {
            sb.AppendLine("<h2>MITRE ATT&CK Context</h2>");
            sb.AppendLine("<table>");
            sb.AppendLine("<tr><th>Technique ID</th><th>Name</th><th>Tactic</th><th>Why It Matters</th></tr>");
            foreach (var m in distinctMitre)
            {
                sb.AppendLine("<tr>");
                sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(m.TechniqueId)}</td>");
                sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(m.TechniqueName)}</td>");
                sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(m.Tactic)}</td>");
                sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(m.WhyItMatters)}</td>");
                sb.AppendLine("</tr>");
            }
            sb.AppendLine("</table>");
        }

        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    string IEvidenceFormatter.Format(AnalysisResult result, string originalLog) => ToHtml(result);

    string IEvidenceFormatter.FileExtension => ".html";

    string IEvidenceFormatter.ContentType => "text/html";
}
