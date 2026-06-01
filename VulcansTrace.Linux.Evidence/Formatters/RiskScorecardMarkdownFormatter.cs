using System.Text;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Evidence.Formatters;

/// <summary>
/// Formats a risk scorecard as GitHub-flavored Markdown.
/// </summary>
public sealed class RiskScorecardMarkdownFormatter
{
    /// <summary>
    /// Converts a risk scorecard to Markdown format.
    /// </summary>
    public string ToMarkdown(RiskScorecard scorecard)
    {
        ArgumentNullException.ThrowIfNull(scorecard);
        var sb = new StringBuilder();
        sb.AppendLine("# Risk Scorecard");
        sb.AppendLine();
        sb.AppendLine($"*Generated {scorecard.GeneratedAt:yyyy-MM-dd HH:mm} UTC*");
        sb.AppendLine();

        var statusEmoji = scorecard.LetterGrade switch
        {
            "A" => "✅",
            "B" => "ℹ️",
            "C" => "⚠️",
            "D" => "🔶",
            _ => "❌"
        };

        sb.AppendLine($"## Overall Grade: {scorecard.LetterGrade} ({scorecard.NumericScore:F1}) {statusEmoji} {scorecard.SummaryStatus}");
        sb.AppendLine();
        sb.AppendLine($"**Total risk-relevant findings:** {scorecard.TotalFindings}");
        sb.AppendLine();

        if (scorecard.ByCategory.Count > 0)
        {
            sb.AppendLine("## Risk by Category");
            sb.AppendLine();
            sb.AppendLine("| Category | Findings | Avg Severity | Deduction |");
            sb.AppendLine("|----------|----------|--------------|-----------|");

            foreach (var category in scorecard.ByCategory)
            {
                sb.AppendLine($"| {Escape(category.Category)} | {category.FindingCount} | {category.AverageSeverity:F1} | {category.TotalDeduction:F1} |");
            }

            sb.AppendLine();
        }

        return sb.ToString();
    }

    private static string Escape(string value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        return value
            .Replace("\r\n", " ")
            .Replace("\r", " ")
            .Replace("\n", " ")
            .Replace("\t", " ")
            .Replace("|", "\\|");
    }
}
