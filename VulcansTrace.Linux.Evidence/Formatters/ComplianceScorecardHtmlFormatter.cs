using System.Text;
using VulcansTrace.Linux.Core.Compliance;

namespace VulcansTrace.Linux.Evidence.Formatters;

/// <summary>
/// Formats a compliance scorecard as a manager-friendly HTML report.
/// </summary>
public sealed class ComplianceScorecardHtmlFormatter
{
    /// <summary>
    /// Converts a compliance scorecard to a complete HTML document.
    /// </summary>
    public string ToHtml(ComplianceScorecard scorecard)
    {
        ArgumentNullException.ThrowIfNull(scorecard);
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html><head><meta charset=\"utf-8\" />");
        sb.AppendLine("<title>CIS Compliance Scorecard</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("body { background:#111; color:#eee; font-family:Segoe UI,Arial,sans-serif; margin:24px; }");
        sb.AppendLine("h1 { margin-bottom:4px; }");
        sb.AppendLine(".subtitle { color:#94a3b8; margin-bottom:24px; }");
        sb.AppendLine(".score-box { display:inline-block; padding:16px 32px; border-radius:12px; text-align:center; margin-bottom:24px; }");
        sb.AppendLine(".score-pass { background:#064e3b; border:2px solid #10b981; }");
        sb.AppendLine(".score-warn { background:#451a03; border:2px solid #f59e0b; }");
        sb.AppendLine(".score-fail { background:#450a0a; border:2px solid #ef4444; }");
        sb.AppendLine(".score-number { font-size:48px; font-weight:bold; line-height:1; }");
        sb.AppendLine(".score-pass .score-number { color:#34d399; }");
        sb.AppendLine(".score-warn .score-number { color:#fbbf24; }");
        sb.AppendLine(".score-fail .score-number { color:#f87171; }");
        sb.AppendLine(".score-label { font-size:14px; text-transform:uppercase; margin-top:4px; }");
        sb.AppendLine("table { border-collapse:collapse; width:100%; margin-top:16px; }");
        sb.AppendLine("th,td { border:1px solid #444; padding:8px 12px; text-align:left; }");
        sb.AppendLine("th { background:#1e293b; color:#94a3b8; font-weight:600; }");
        sb.AppendLine("tr:nth-child(even) { background:#1a1a1a; }");
        sb.AppendLine(".badge { display:inline-block; padding:3px 10px; border-radius:999px; font-size:12px; font-weight:600; text-transform:uppercase; }");
        sb.AppendLine(".badge-pass { background:#064e3b; color:#34d399; }");
        sb.AppendLine(".badge-warn { background:#451a03; color:#fbbf24; }");
        sb.AppendLine(".badge-fail { background:#450a0a; color:#f87171; }");
        sb.AppendLine(".trend { margin-top:24px; }");
        sb.AppendLine(".trend-bar { display:flex; align-items:flex-end; gap:4px; height:80px; margin-top:8px; }");
        sb.AppendLine(".trend-col { flex:1; background:#334155; border-radius:4px 4px 0 0; min-height:4px; position:relative; }");
        sb.AppendLine(".trend-col:hover { background:#60a5fa; }");
        sb.AppendLine(".trend-tooltip { position:absolute; bottom:100%; left:50%; transform:translateX(-50%); background:#0f172a; border:1px solid #334155; padding:4px 8px; border-radius:4px; font-size:11px; white-space:nowrap; display:none; }");
        sb.AppendLine(".trend-col:hover .trend-tooltip { display:block; }");
        sb.AppendLine("</style></head><body>");

        sb.AppendLine("<h1>CIS Compliance Scorecard</h1>");
        sb.AppendLine($"<p class=\"subtitle\">Generated {scorecard.GeneratedAt:yyyy-MM-dd HH:mm} UTC</p>");

        var scoreClass = scorecard.SummaryStatus switch
        {
            "Pass" => "score-pass",
            "Warn" => "score-warn",
            _ => "score-fail"
        };

        sb.AppendLine($"<div class=\"score-box {scoreClass}\">");
        sb.AppendLine($"<div class=\"score-number\">{scorecard.OverallScore:F1}%</div>");
        sb.AppendLine($"<div class=\"score-label\">{System.Net.WebUtility.HtmlEncode(scorecard.SummaryStatus)}</div>");
        sb.AppendLine("</div>");

        sb.AppendLine("<h2>Control Families</h2>");
        sb.AppendLine("<table>");
        sb.AppendLine("<tr><th>Family</th><th>Total</th><th>Passed</th><th>Failed</th><th>Crashed</th><th>Suppressed</th><th>Score</th><th>Status</th></tr>");

        foreach (var family in scorecard.FamilyScores)
        {
            var badgeClass = family.Status switch
            {
                "Pass" => "badge-pass",
                "Warn" => "badge-warn",
                _ => "badge-fail"
            };

            sb.AppendLine("<tr>");
            sb.AppendLine($"<td><strong>{System.Net.WebUtility.HtmlEncode(family.FamilyName)}</strong><br/><span style=\"color:#64748b;font-size:12px;\">CIS {System.Net.WebUtility.HtmlEncode(family.FamilyId)}</span></td>");
            sb.AppendLine($"<td>{family.TotalControls}</td>");
            sb.AppendLine($"<td>{family.PassedControls}</td>");
            sb.AppendLine($"<td>{family.FailedControls}</td>");
            sb.AppendLine($"<td>{family.CrashedControls}</td>");
            sb.AppendLine($"<td>{family.SuppressedControls}</td>");
            sb.AppendLine($"<td>{family.ScorePercentage:F1}%</td>");
            sb.AppendLine($"<td><span class=\"badge {badgeClass}\">{System.Net.WebUtility.HtmlEncode(family.Status)}</span></td>");
            sb.AppendLine("</tr>");
        }

        sb.AppendLine("</table>");

        if (scorecard.Trend.Count > 0)
        {
            sb.AppendLine("<div class=\"trend\">");
            sb.AppendLine("<h2>Trend (Last Audits)</h2>");

            var maxScore = scorecard.Trend.Max(t => t.OverallScore);
            if (maxScore < 1) maxScore = 100;

            sb.AppendLine("<div class=\"trend-bar\">");
            foreach (var point in scorecard.Trend)
            {
                var heightPct = Math.Max(4, (int)(point.OverallScore / maxScore * 100));
                var barColor = point.OverallScore >= 100 ? "#10b981" : point.OverallScore >= ComplianceScorecard.WarnThreshold ? "#f59e0b" : "#ef4444";
                sb.AppendLine($"<div class=\"trend-col\" style=\"height:{heightPct}%;background:{barColor};\">");
                sb.AppendLine($"<div class=\"trend-tooltip\">{point.Timestamp:MM-dd HH:mm}<br/>{point.OverallScore:F1}%</div>");
                sb.AppendLine("</div>");
            }
            sb.AppendLine("</div>");

            sb.AppendLine("<table style=\"margin-top:12px;width:auto;\">");
            sb.AppendLine("<tr><th>Date</th><th>Score</th></tr>");
            foreach (var point in scorecard.Trend)
            {
                sb.AppendLine($"<tr><td>{point.Timestamp:yyyy-MM-dd HH:mm}</td><td>{point.OverallScore:F1}%</td></tr>");
            }
            sb.AppendLine("</table>");

            sb.AppendLine("</div>");
        }

        sb.AppendLine("</body></html>");
        return sb.ToString();
    }
}
