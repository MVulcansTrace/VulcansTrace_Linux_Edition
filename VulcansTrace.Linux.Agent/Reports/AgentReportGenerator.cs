using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Converts an <see cref="AgentResult"/> into an <see cref="AnalysisResult"/> that can be consumed
/// by the existing <see cref="Evidence.EvidenceBuilder"/> and formatters.
/// </summary>
public sealed class AgentReportGenerator
{
    /// <summary>
    /// Merges agent findings and optional log analysis findings into a single <see cref="AnalysisResult"/>.
    /// </summary>
    /// <param name="agentResult">The agent audit result.</param>
    /// <returns>An analysis result compatible with existing evidence and formatting infrastructure.</returns>
    public AnalysisResult ToAnalysisResult(AgentResult agentResult)
    {
        var allFindings = new List<Finding>(agentResult.AgentFindings);
        var allWarnings = new List<string>(agentResult.Warnings);
        int totalLines = 0;
        int parsedLines = 0;
        int parseErrorCount = 0;
        int skippedLineCount = 0;

        if (agentResult.LogAnalysisResult != null)
        {
            allFindings.AddRange(agentResult.LogAnalysisResult.Findings);
            allWarnings.AddRange(agentResult.LogAnalysisResult.Warnings);
            totalLines = agentResult.LogAnalysisResult.TotalLines;
            parsedLines = agentResult.LogAnalysisResult.ParsedLines;
            parseErrorCount = agentResult.LogAnalysisResult.ParseErrorCount;
            skippedLineCount = agentResult.LogAnalysisResult.SkippedLineCount;
        }

        // Deduplicate by deterministic Id
        var deduped = allFindings.GroupBy(f => f.Id).Select(g => g.First()).ToList();

        return new AnalysisResult
        {
            TotalLines = totalLines,
            ParsedLines = parsedLines,
            ParseErrorCount = parseErrorCount,
            SkippedLineCount = skippedLineCount,
            ParseErrors = agentResult.LogAnalysisResult?.ParseErrors ?? Array.Empty<string>(),
            Entries = agentResult.LogAnalysisResult?.Entries ?? Array.Empty<UnifiedEvent>(),
            Findings = deduped,
            Warnings = allWarnings,
            TimeRangeStart = agentResult.UtcTimestamp,
            TimeRangeEnd = agentResult.UtcTimestamp
        };
    }
}
