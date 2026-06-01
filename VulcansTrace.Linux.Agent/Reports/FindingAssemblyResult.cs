using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

internal sealed record FindingAssemblyResult(
    IReadOnlyList<Finding> AgentFindings,
    IReadOnlyList<(string RuleId, Finding Finding)> HistoryEntries,
    IReadOnlyList<RuleResult> RuleResults,
    int SuppressedCount,
    IReadOnlyList<string> Warnings);
