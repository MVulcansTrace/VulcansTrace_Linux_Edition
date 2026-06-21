using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

internal sealed record AgentResultFinalizationRequest(
    AgentIntent Intent,
    IReadOnlyList<Finding> AgentFindings,
    AnalysisResult? LogAnalysisResult,
    IReadOnlyList<string> Warnings,
    string Summary,
    IReadOnlyList<RuleResult> RuleResults,
    int PassedCount,
    int FailedCount,
    int SuppressedCount,
    int CrashedCount,
    string CapabilityReport,
    IReadOnlyList<DataSourceCapability> DataSourceCapabilities,
    IReadOnlyList<AttackChain> AttackChains,
    IReadOnlyList<(string RuleId, Finding Finding)> HistoryEntries);
