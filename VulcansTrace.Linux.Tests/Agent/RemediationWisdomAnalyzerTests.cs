using VulcansTrace.Linux.Agent.Analysis;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class RemediationWisdomAnalyzerTests
{
    private readonly RemediationWisdomAnalyzer _analyzer = new();

    [Fact]
    public void Analyze_NoCycles_ReturnsEmpty()
    {
        var finding = CreateFinding("FW-001", Severity.High);
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = new RuleMemoryEntry
            {
                RuleId = "FW-001",
                RemediationCycles = Array.Empty<RemediationCycle>()
            }
        };

        var wisdom = _analyzer.Analyze(new[] { finding }, history);

        Assert.Empty(wisdom);
    }

    [Fact]
    public void Analyze_SingleCycle_ReturnsEmpty()
    {
        var finding = CreateFinding("FW-001", Severity.High);
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = new RuleMemoryEntry
            {
                RuleId = "FW-001",
                RemediationCycles = new[]
                {
                    new RemediationCycle
                    {
                        AttemptedUtc = DateTime.UtcNow.AddDays(-7),
                        VerifiedFixedUtc = DateTime.UtcNow.AddDays(-6),
                        ReturnedUtc = DateTime.UtcNow.AddDays(-5),
                        CycleNumber = 1
                    }
                }
            }
        };

        var wisdom = _analyzer.Analyze(new[] { finding }, history);

        Assert.Empty(wisdom);
    }

    [Fact]
    public void Analyze_TwoClosedCycles_ReturnsWisdom()
    {
        var finding = CreateFinding("SSH-002", Severity.High);
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["SSH-002"] = new RuleMemoryEntry
            {
                RuleId = "SSH-002",
                RemediationCycles = new[]
                {
                    new RemediationCycle
                    {
                        AttemptedUtc = DateTime.UtcNow.AddDays(-14),
                        VerifiedFixedUtc = DateTime.UtcNow.AddDays(-13),
                        ReturnedUtc = DateTime.UtcNow.AddDays(-12),
                        CycleNumber = 1
                    },
                    new RemediationCycle
                    {
                        AttemptedUtc = DateTime.UtcNow.AddDays(-7),
                        VerifiedFixedUtc = DateTime.UtcNow.AddDays(-6),
                        ReturnedUtc = DateTime.UtcNow.AddDays(-5),
                        CycleNumber = 2
                    }
                }
            }
        };

        var wisdom = _analyzer.Analyze(new[] { finding }, history);

        Assert.Single(wisdom);
        Assert.Equal("SSH-002", wisdom[0].RuleId);
        Assert.Equal(2, wisdom[0].CycleCount);
        Assert.Contains("config-management", wisdom[0].Guidance);
    }

    [Fact]
    public void Analyze_OpenCycleNotCounted()
    {
        var finding = CreateFinding("FW-001", Severity.High);
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = new RuleMemoryEntry
            {
                RuleId = "FW-001",
                RemediationCycles = new[]
                {
                    new RemediationCycle
                    {
                        AttemptedUtc = DateTime.UtcNow.AddDays(-7),
                        VerifiedFixedUtc = DateTime.UtcNow.AddDays(-6),
                        ReturnedUtc = DateTime.UtcNow.AddDays(-5),
                        CycleNumber = 1
                    },
                    new RemediationCycle
                    {
                        AttemptedUtc = DateTime.UtcNow.AddDays(-3),
                        VerifiedFixedUtc = DateTime.UtcNow.AddDays(-2),
                        ReturnedUtc = null,
                        CycleNumber = 2
                    }
                }
            }
        };

        var wisdom = _analyzer.Analyze(new[] { finding }, history);

        Assert.Empty(wisdom);
    }

    [Fact]
    public void Analyze_MultipleFindingsSameRule_DedupesToSingleWisdom()
    {
        var findings = new[]
        {
            CreateFinding("SSH-002", Severity.High),
            CreateFinding("SSH-002", Severity.Critical)
        };
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["SSH-002"] = new RuleMemoryEntry
            {
                RuleId = "SSH-002",
                RemediationCycles = new[]
                {
                    new RemediationCycle
                    {
                        AttemptedUtc = DateTime.UtcNow.AddDays(-14),
                        VerifiedFixedUtc = DateTime.UtcNow.AddDays(-13),
                        ReturnedUtc = DateTime.UtcNow.AddDays(-12),
                        CycleNumber = 1
                    },
                    new RemediationCycle
                    {
                        AttemptedUtc = DateTime.UtcNow.AddDays(-7),
                        VerifiedFixedUtc = DateTime.UtcNow.AddDays(-6),
                        ReturnedUtc = DateTime.UtcNow.AddDays(-5),
                        CycleNumber = 2
                    }
                }
            }
        };

        var wisdom = _analyzer.Analyze(findings, history);

        Assert.Single(wisdom);
        Assert.Equal("SSH-002", wisdom[0].RuleId);
    }

    [Fact]
    public void Analyze_NotCurrentlyFailing_ReturnsEmpty()
    {
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = new RuleMemoryEntry
            {
                RuleId = "FW-001",
                RemediationCycles = new[]
                {
                    new RemediationCycle
                    {
                        AttemptedUtc = DateTime.UtcNow.AddDays(-7),
                        VerifiedFixedUtc = DateTime.UtcNow.AddDays(-6),
                        ReturnedUtc = DateTime.UtcNow.AddDays(-5),
                        CycleNumber = 1
                    },
                    new RemediationCycle
                    {
                        AttemptedUtc = DateTime.UtcNow.AddDays(-3),
                        VerifiedFixedUtc = DateTime.UtcNow.AddDays(-2),
                        ReturnedUtc = DateTime.UtcNow.AddDays(-1),
                        CycleNumber = 2
                    }
                }
            }
        };

        var wisdom = _analyzer.Analyze(Array.Empty<Finding>(), history);

        Assert.Empty(wisdom);
    }

    private static Finding CreateFinding(string ruleId, Severity severity)
    {
        return new Finding
        {
            RuleId = ruleId,
            Category = "Test",
            Severity = severity,
            SourceHost = "localhost",
            Target = "target",
            ShortDescription = $"Finding {ruleId}",
            Details = "Details",
            TimeRangeStart = DateTime.UtcNow,
            TimeRangeEnd = DateTime.UtcNow
        };
    }
}
