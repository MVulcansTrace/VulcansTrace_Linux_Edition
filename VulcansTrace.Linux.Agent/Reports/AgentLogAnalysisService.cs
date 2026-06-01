using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;

namespace VulcansTrace.Linux.Agent.Reports;

internal sealed class AgentLogAnalysisService
{
    private readonly Func<string, CancellationToken, AnalysisResult>? _analyze;

    public AgentLogAnalysisService(SentryAnalyzer? sentryAnalyzer, AnalysisProfileProvider? profileProvider)
        : this(
            sentryAnalyzer != null && profileProvider != null
                ? (rawLog, ct) => sentryAnalyzer.Analyze(rawLog, IntensityLevel.Medium, ct)
                : null)
    {
    }

    internal AgentLogAnalysisService(Func<string, CancellationToken, AnalysisResult>? analyze)
    {
        _analyze = analyze;
    }

    public async Task<AgentLogAnalysisResult> AnalyzeAsync(string? rawLog, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(rawLog) || _analyze == null)
        {
            return new AgentLogAnalysisResult(null, Array.Empty<string>());
        }

        ct.ThrowIfCancellationRequested();

        try
        {
            var result = await Task.Run(() => _analyze(rawLog, ct), ct);
            return new AgentLogAnalysisResult(result, Array.Empty<string>());
        }
        catch (Exception ex)
        {
            return new AgentLogAnalysisResult(null, new[] { $"Log analysis failed: {ex.Message}" });
        }
    }
}
