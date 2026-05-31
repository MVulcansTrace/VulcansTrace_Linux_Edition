using System.Text;
using VulcansTrace.Linux.Core.Compliance;

namespace VulcansTrace.Linux.Evidence.Formatters;

/// <summary>
/// Formats a compliance scorecard as GitHub-flavored Markdown.
/// </summary>
public sealed class ComplianceScorecardMarkdownFormatter
{
    /// <summary>
    /// Converts a compliance scorecard to Markdown format.
    /// </summary>
    public string ToMarkdown(ComplianceScorecard scorecard)
    {
        ArgumentNullException.ThrowIfNull(scorecard);
        var sb = new StringBuilder();
        sb.AppendLine("# CIS Compliance Scorecard");
        sb.AppendLine();
        sb.AppendLine($"*Generated {scorecard.GeneratedAt:yyyy-MM-dd HH:mm} UTC*");
        sb.AppendLine();

        var statusEmoji = scorecard.SummaryStatus switch
        {
            "Pass" => "✅",
            "Warn" => "⚠️",
            _ => "❌"
        };

        sb.AppendLine($"## Overall Score: {scorecard.OverallScore:F1}% {statusEmoji} {scorecard.SummaryStatus}");
        sb.AppendLine();

        sb.AppendLine("## Control Families");
        sb.AppendLine();
        sb.AppendLine("| Family | CIS Chapter | Total | Passed | Failed | Crashed | Suppressed | Score | Status |");
        sb.AppendLine("|--------|-------------|-------|--------|--------|---------|------------|-------|--------|");

        foreach (var family in scorecard.FamilyScores)
        {
            var statusEmojiRow = family.Status switch
            {
                "Pass" => "✅ Pass",
                "Warn" => "⚠️ Warn",
                _ => "❌ Fail"
            };

            sb.AppendLine($"| {Escape(family.FamilyName)} | {family.FamilyId} | {family.TotalControls} | {family.PassedControls} | {family.FailedControls} | {family.CrashedControls} | {family.SuppressedControls} | {family.ScorePercentage:F1}% | {statusEmojiRow} |");
        }

        sb.AppendLine();

        if (scorecard.Trend.Count > 0)
        {
            sb.AppendLine("## Trend (Last Audits)");
            sb.AppendLine();
            sb.AppendLine("| Date | Score |");
            sb.AppendLine("|------|-------|");
            foreach (var point in scorecard.Trend)
            {
                var trendEmoji = point.OverallScore >= 100 ? "✅" : point.OverallScore >= ComplianceScorecard.WarnThreshold ? "⚠️" : "❌";
                sb.AppendLine($"| {point.Timestamp:yyyy-MM-dd HH:mm} | {point.OverallScore:F1}% {trendEmoji} |");
            }
            sb.AppendLine();
        }

        return sb.ToString();
    }

    private static string Escape(string value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        var sanitized = value
            .Replace("\r\n", " ")
            .Replace("\r", " ")
            .Replace("\n", " ")
            .Replace("\t", " ")
            .Replace("|", "\\|");

        return sanitized;
    }
}
