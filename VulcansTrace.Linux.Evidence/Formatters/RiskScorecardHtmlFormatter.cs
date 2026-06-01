using System.Text;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Evidence.Formatters;

/// <summary>
/// Formats a risk scorecard as a manager-friendly HTML report.
/// </summary>
public sealed class RiskScorecardHtmlFormatter
{
    /// <summary>
    /// Converts a risk scorecard to a complete HTML document.
    /// </summary>
    public string ToHtml(RiskScorecard scorecard)
    {
        ArgumentNullException.ThrowIfNull(scorecard);
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html><head><meta charset=\"utf-8\" />");
        sb.AppendLine("<title>Risk Scorecard</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("body { background:#111; color:#eee; font-family:Segoe UI,Arial,sans-serif; margin:24px; }");
        sb.AppendLine("h1 { margin-bottom:4px; }");
        sb.AppendLine(".subtitle { color:#94a3b8; margin-bottom:24px; }");
        sb.AppendLine(".grade-box { display:inline-block; padding:16px 32px; border-radius:12px; text-align:center; margin-bottom:24px; }");
        sb.AppendLine(".grade-a { background:#064e3b; border:2px solid #10b981; }");
        sb.AppendLine(".grade-b { background:#1e3a8a; border:2px solid #3b82f6; }");
        sb.AppendLine(".grade-c { background:#451a03; border:2px solid #f59e0b; }");
        sb.AppendLine(".grade-d { background:#431407; border:2px solid #fb923c; }");
        sb.AppendLine(".grade-f { background:#450a0a; border:2px solid #ef4444; }");
        sb.AppendLine(".grade-letter { font-size:48px; font-weight:bold; line-height:1; }");
        sb.AppendLine(".grade-a .grade-letter { color:#34d399; }");
        sb.AppendLine(".grade-b .grade-letter { color:#60a5fa; }");
        sb.AppendLine(".grade-c .grade-letter { color:#fbbf24; }");
        sb.AppendLine(".grade-d .grade-letter { color:#fb923c; }");
        sb.AppendLine(".grade-f .grade-letter { color:#f87171; }");
        sb.AppendLine(".grade-label { font-size:14px; text-transform:uppercase; margin-top:4px; }");
        sb.AppendLine("table { border-collapse:collapse; width:100%; margin-top:16px; }");
        sb.AppendLine("th,td { border:1px solid #444; padding:8px 12px; text-align:left; }");
        sb.AppendLine("th { background:#1e293b; color:#94a3b8; font-weight:600; }");
        sb.AppendLine("tr:nth-child(even) { background:#1a1a1a; }");
        sb.AppendLine("</style></head><body>");

        sb.AppendLine("<h1>Risk Scorecard</h1>");
        sb.AppendLine($"<p class=\"subtitle\">Generated {scorecard.GeneratedAt:yyyy-MM-dd HH:mm} UTC</p>");

        var gradeClass = scorecard.LetterGrade switch
        {
            "A" => "grade-a",
            "B" => "grade-b",
            "C" => "grade-c",
            "D" => "grade-d",
            _ => "grade-f"
        };

        sb.AppendLine($"<div class=\"grade-box {gradeClass}\">");
        sb.AppendLine($"<div class=\"grade-letter\">{System.Net.WebUtility.HtmlEncode(scorecard.LetterGrade)}</div>");
        sb.AppendLine($"<div class=\"grade-label\">{scorecard.NumericScore:F1} &mdash; {System.Net.WebUtility.HtmlEncode(scorecard.SummaryStatus)}</div>");
        sb.AppendLine("</div>");

        sb.AppendLine($"<p>Total risk-relevant findings: <strong>{scorecard.TotalFindings}</strong></p>");

        if (scorecard.ByCategory.Count > 0)
        {
            sb.AppendLine("<h2>Risk by Category</h2>");
            sb.AppendLine("<table>");
            sb.AppendLine("<tr><th>Category</th><th>Findings</th><th>Avg Severity</th><th>Deduction</th></tr>");

            foreach (var category in scorecard.ByCategory)
            {
                sb.AppendLine("<tr>");
                sb.AppendLine($"<td><strong>{System.Net.WebUtility.HtmlEncode(category.Category)}</strong></td>");
                sb.AppendLine($"<td>{category.FindingCount}</td>");
                sb.AppendLine($"<td>{category.AverageSeverity:F1}</td>");
                sb.AppendLine($"<td>{category.TotalDeduction:F1}</td>");
                sb.AppendLine("</tr>");
            }

            sb.AppendLine("</table>");
        }

        sb.AppendLine("</body></html>");
        return sb.ToString();
    }
}
