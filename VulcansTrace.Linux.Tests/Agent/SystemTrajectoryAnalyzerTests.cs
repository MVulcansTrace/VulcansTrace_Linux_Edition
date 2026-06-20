using VulcansTrace.Linux.Agent.Analysis;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class SystemTrajectoryAnalyzerTests
{
    private readonly SystemTrajectoryAnalyzer _analyzer = new();

    [Fact]
    public void Analyze_NoHistory_ReturnsInsufficientHistory()
    {
        var finding = CreateFinding("FW-001", Severity.High);
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase);

        var trajectory = _analyzer.Analyze(new[] { finding }, history);

        Assert.Equal(TrajectoryDirection.InsufficientHistory, trajectory.Direction);
        Assert.False(trajectory.HasEnoughHistory);
    }

    [Fact]
    public void Analyze_SingleRuleWithHistory_ReturnsInsufficientHistory()
    {
        var finding = CreateFinding("FW-001", Severity.High);
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = CreateEntry("FW-001", Severity.Medium, Severity.High, RuleStatusTrend.Worsening)
        };

        var trajectory = _analyzer.Analyze(new[] { finding }, history);

        Assert.Equal(TrajectoryDirection.InsufficientHistory, trajectory.Direction);
    }

    [Fact]
    public void Analyze_TwoImproving_ReturnsImproving()
    {
        var findings = new[]
        {
            CreateFinding("FW-001", Severity.High),
            CreateFinding("SSH-002", Severity.Medium)
        };
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = CreateEntry("FW-001", Severity.High, Severity.Low, RuleStatusTrend.Improving),
            ["SSH-002"] = CreateEntry("SSH-002", Severity.Medium, Severity.High, RuleStatusTrend.Improving)
        };

        var trajectory = _analyzer.Analyze(findings, history);

        Assert.Equal(TrajectoryDirection.Improving, trajectory.Direction);
        Assert.Equal(2, trajectory.ImprovingCount);
        Assert.True(trajectory.WeightedDelta > 0);
    }

    [Fact]
    public void Analyze_TwoWorsening_ReturnsWorsening()
    {
        var findings = new[]
        {
            CreateFinding("FW-001", Severity.High),
            CreateFinding("SSH-002", Severity.Critical)
        };
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = CreateEntry("FW-001", Severity.Low, Severity.High, RuleStatusTrend.Worsening),
            ["SSH-002"] = CreateEntry("SSH-002", Severity.High, Severity.Critical, RuleStatusTrend.Worsening)
        };

        var trajectory = _analyzer.Analyze(findings, history);

        Assert.Equal(TrajectoryDirection.Worsening, trajectory.Direction);
        Assert.Equal(2, trajectory.WorseningCount);
        Assert.True(trajectory.WeightedDelta < 0);
    }

    [Fact]
    public void Analyze_MixedWithSeverityWeighting_ReturnsCorrectDirection()
    {
        var findings = new[]
        {
            CreateFinding("FW-001", Severity.Low),
            CreateFinding("SSH-002", Severity.Critical)
        };
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            // Improving but low weight: +1
            ["FW-001"] = CreateEntry("FW-001", Severity.Medium, Severity.Low, RuleStatusTrend.Improving),
            // Worsening and critical weight: -4
            ["SSH-002"] = CreateEntry("SSH-002", Severity.High, Severity.Critical, RuleStatusTrend.Worsening)
        };

        var trajectory = _analyzer.Analyze(findings, history);

        Assert.Equal(TrajectoryDirection.Worsening, trajectory.Direction);
        Assert.True(trajectory.WeightedDelta < 0);
    }

    [Fact]
    public void Analyze_VerifiedFixedAbsentRule_CountsAsImproving()
    {
        var findings = new[]
        {
            CreateFinding("SSH-002", Severity.High)
        };
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = CreateEntry(
                "FW-001",
                Severity.High,
                Severity.High,
                RuleStatusTrend.Stable,
                lastVerifiedFixedUtc: DateTime.UtcNow.AddHours(-1)),
            ["SSH-002"] = CreateEntry("SSH-002", Severity.High, Severity.High, RuleStatusTrend.Stable)
        };

        var trajectory = _analyzer.Analyze(findings, history);

        Assert.Equal(TrajectoryDirection.Improving, trajectory.Direction);
        Assert.Contains("FW-001", trajectory.ImprovingRuleIds);
        Assert.Equal(1, trajectory.ImprovingCount);
        Assert.Equal(1, trajectory.StableCount);
    }

    [Fact]
    public void Analyze_StableRules_ReturnsStable()
    {
        var findings = new[]
        {
            CreateFinding("FW-001", Severity.High),
            CreateFinding("SSH-002", Severity.Medium)
        };
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = CreateEntry("FW-001", Severity.High, Severity.High, RuleStatusTrend.Stable),
            ["SSH-002"] = CreateEntry("SSH-002", Severity.Medium, Severity.Medium, RuleStatusTrend.Stable)
        };

        var trajectory = _analyzer.Analyze(findings, history);

        Assert.Equal(TrajectoryDirection.Stable, trajectory.Direction);
        Assert.Equal(2, trajectory.StableCount);
        Assert.Equal(0, trajectory.WeightedDelta);
    }

    [Fact]
    public void Analyze_RuleNotInHistory_IsIgnored()
    {
        var findings = new[]
        {
            CreateFinding("FW-001", Severity.High),
            CreateFinding("UNKNOWN-001", Severity.Critical)
        };
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = CreateEntry("FW-001", Severity.High, Severity.High, RuleStatusTrend.Stable)
        };

        var trajectory = _analyzer.Analyze(findings, history);

        Assert.Equal(TrajectoryDirection.InsufficientHistory, trajectory.Direction);
    }

    private static Finding CreateFinding(string ruleId, Severity severity)
    {
        var now = DateTime.UtcNow;
        return new Finding
        {
            RuleId = ruleId,
            Category = "Test",
            Severity = severity,
            SourceHost = "localhost",
            Target = "target",
            ShortDescription = $"Finding {ruleId}",
            Details = "Details",
            TimeRangeStart = now,
            TimeRangeEnd = now
        };
    }

    private static RuleMemoryEntry CreateEntry(
        string ruleId,
        Severity previous,
        Severity current,
        RuleStatusTrend trend,
        DateTime? lastVerifiedFixedUtc = null)
    {
        var now = DateTime.UtcNow;
        return new RuleMemoryEntry
        {
            RuleId = ruleId,
            Category = "Test",
            FirstSeenUtc = now.AddDays(-2),
            LastSeenUtc = now,
            SeverityHistory = new[]
            {
                new RuleSeveritySnapshot { UtcTimestamp = now.AddDays(-1), Severity = previous },
                new RuleSeveritySnapshot { UtcTimestamp = now, Severity = current }
            },
            Trend = trend,
            LastSeverity = current,
            LastVerifiedFixedUtc = lastVerifiedFixedUtc
        };
    }
}
