using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class AgentLogAnalysisServiceTests
{
    [Fact]
    public async Task AnalyzeAsync_NoRawLog_SkipsAnalysis()
    {
        var called = false;
        var service = new AgentLogAnalysisService((_, _) =>
        {
            called = true;
            return new AnalysisResult();
        });

        var result = await service.AnalyzeAsync("   ", CancellationToken.None);

        Assert.False(called);
        Assert.Null(result.AnalysisResult);
        Assert.Empty(result.Warnings);
    }

    [Fact]
    public async Task AnalyzeAsync_MissingAnalyzerDependencies_SkipsAnalysis()
    {
        var service = new AgentLogAnalysisService(sentryAnalyzer: null, profileProvider: null);

        var result = await service.AnalyzeAsync("raw log", CancellationToken.None);

        Assert.Null(result.AnalysisResult);
        Assert.Empty(result.Warnings);
    }

    [Fact]
    public async Task AnalyzeAsync_AnalyzerAvailable_ReturnsAnalysisResult()
    {
        var expected = new AnalysisResult { TotalLines = 3, ParsedLines = 2 };
        string? observedRawLog = null;
        var service = new AgentLogAnalysisService((rawLog, _) =>
        {
            observedRawLog = rawLog;
            return expected;
        });

        var result = await service.AnalyzeAsync("raw log", CancellationToken.None);

        Assert.Same(expected, result.AnalysisResult);
        Assert.Empty(result.Warnings);
        Assert.Equal("raw log", observedRawLog);
    }

    [Fact]
    public async Task AnalyzeAsync_AnalyzerThrows_ReturnsWarning()
    {
        var service = new AgentLogAnalysisService((_, _) => throw new InvalidOperationException("boom"));

        var result = await service.AnalyzeAsync("raw log", CancellationToken.None);

        Assert.Null(result.AnalysisResult);
        Assert.Contains("Log analysis failed: boom", result.Warnings);
    }

    [Fact]
    public async Task AnalyzeAsync_CanceledBeforeAnalysis_PropagatesCancellation()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var service = new AgentLogAnalysisService((_, _) => new AnalysisResult());

        await Assert.ThrowsAsync<OperationCanceledException>(() => service.AnalyzeAsync("raw log", cts.Token));
    }
}
