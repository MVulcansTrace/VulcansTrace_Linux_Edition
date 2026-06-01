using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

internal sealed record AgentLogAnalysisResult(AnalysisResult? AnalysisResult, IReadOnlyList<string> Warnings);
