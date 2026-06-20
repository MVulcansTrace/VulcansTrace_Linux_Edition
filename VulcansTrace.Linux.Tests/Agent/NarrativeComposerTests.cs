using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class NarrativeComposerTests
{
    private readonly NarrativeComposer _composer = new();

    [Fact]
    public void Compose_NoFindings_ReturnsCleanSummary()
    {
        var result = new AgentResult { AgentFindings = Array.Empty<Finding>() };

        var narrative = _composer.Compose(result, new Dictionary<string, RuleMemoryEntry>(), new EntityFrame());

        Assert.Contains("No active findings", narrative.Summary);
        Assert.Empty(narrative.SourceIds);
    }

    [Fact]
    public void Compose_WithFindings_ListsKeyFindings()
    {
        var result = new AgentResult
        {
            AgentFindings = new[]
            {
                CreateFinding("FW-001", "Firewall", Severity.High),
                CreateFinding("SSH-002", "SSH", Severity.Critical)
            }
        };

        var narrative = _composer.Compose(result, new Dictionary<string, RuleMemoryEntry>(), new EntityFrame());

        Assert.Contains("FW-001", narrative.KeyFindingsParagraph);
        Assert.Contains("SSH-002", narrative.KeyFindingsParagraph);
        Assert.Contains("FW-001", narrative.SourceIds);
        Assert.Contains("SSH-002", narrative.SourceIds);
    }

    [Fact]
    public void Compose_WithCorrelations_AddsCorrelationsParagraph()
    {
        var finding1 = CreateFinding("FW-002", "Firewall", Severity.High);
        var finding2 = CreateFinding("SSH-002", "SSH", Severity.High);
        var result = new AgentResult
        {
            AgentFindings = new[] { finding1, finding2 },
            PostureCorrelations = new[]
            {
                new PostureCorrelation
                {
                    PatternId = "POSTURE-001",
                    RuleIdA = "FW-002",
                    RuleIdB = "SSH-002",
                    Narrative = "FW-002 plus SSH-002 is a straight path to root.",
                    CombinedSeverity = Severity.Critical,
                    FindingIds = new[] { finding1.Id, finding2.Id }
                }
            }
        };

        var narrative = _composer.Compose(result, new Dictionary<string, RuleMemoryEntry>(), new EntityFrame());

        Assert.Contains("FW-002 plus SSH-002 is a straight path to root.", narrative.CorrelationsParagraph);
        Assert.Contains("POSTURE-001", narrative.SourceIds);
    }

    [Fact]
    public void Compose_WithMemory_AddsMemoryParagraph()
    {
        var finding = CreateFinding("FW-001", "Firewall", Severity.High);
        var result = new AgentResult
        {
            AgentFindings = new[] { finding },
            UtcTimestamp = DateTime.UtcNow
        };

        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = new RuleMemoryEntry
            {
                RuleId = "FW-001",
                Category = "Firewall",
                FirstSeenUtc = DateTime.UtcNow.AddDays(-14),
                LastSeenUtc = DateTime.UtcNow,
                SeverityHistory = new[]
                {
                    new RuleSeveritySnapshot { UtcTimestamp = DateTime.UtcNow.AddDays(-14), Severity = Severity.High },
                    new RuleSeveritySnapshot { UtcTimestamp = DateTime.UtcNow, Severity = Severity.High }
                },
                Trend = RuleStatusTrend.Stable,
                LastSeverity = Severity.High
            }
        };

        var narrative = _composer.Compose(result, history, new EntityFrame());

        Assert.Contains("Continuity", narrative.MemoryParagraph);
        Assert.Contains("FW-001", narrative.MemoryParagraph);
        Assert.Contains("2 weeks ago", narrative.MemoryParagraph);
        Assert.Contains("FW-001", narrative.SourceIds);
    }

    [Fact]
    public void Compose_NoMemory_DoesNotFabricateContinuity()
    {
        var finding = CreateFinding("FW-001", "Firewall", Severity.High);
        var result = new AgentResult { AgentFindings = new[] { finding } };

        var narrative = _composer.Compose(result, new Dictionary<string, RuleMemoryEntry>(), new EntityFrame());

        Assert.DoesNotContain("first seen", narrative.FullText, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compose_WithRemediationAttempt_AddsAttemptSentence()
    {
        var finding = CreateFinding("FW-001", "Firewall", Severity.High);
        var result = new AgentResult
        {
            AgentFindings = new[] { finding },
            UtcTimestamp = DateTime.UtcNow
        };

        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = new RuleMemoryEntry
            {
                RuleId = "FW-001",
                Category = "Firewall",
                FirstSeenUtc = DateTime.UtcNow.AddDays(-14),
                LastSeenUtc = DateTime.UtcNow,
                SeverityHistory = new[]
                {
                    new RuleSeveritySnapshot { UtcTimestamp = DateTime.UtcNow.AddDays(-14), Severity = Severity.High },
                    new RuleSeveritySnapshot { UtcTimestamp = DateTime.UtcNow, Severity = Severity.High }
                },
                Trend = RuleStatusTrend.Stable,
                LastSeverity = Severity.High,
                LastRemediationAttemptUtc = DateTime.UtcNow.AddDays(-3)
            }
        };

        var narrative = _composer.Compose(result, history, new EntityFrame());

        Assert.Contains("A remediation was attempted 3 days ago.", narrative.MemoryParagraph);
    }

    [Fact]
    public void Compose_WithVerifiedFixedAndReturned_AddsVerifiedSentence()
    {
        var finding = CreateFinding("FW-001", "Firewall", Severity.High);
        var result = new AgentResult
        {
            AgentFindings = new[] { finding },
            UtcTimestamp = DateTime.UtcNow
        };

        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = new RuleMemoryEntry
            {
                RuleId = "FW-001",
                Category = "Firewall",
                FirstSeenUtc = DateTime.UtcNow.AddDays(-14),
                LastSeenUtc = DateTime.UtcNow,
                SeverityHistory = new[]
                {
                    new RuleSeveritySnapshot { UtcTimestamp = DateTime.UtcNow.AddDays(-14), Severity = Severity.High },
                    new RuleSeveritySnapshot { UtcTimestamp = DateTime.UtcNow, Severity = Severity.High }
                },
                Trend = RuleStatusTrend.Stable,
                LastSeverity = Severity.High,
                LastVerifiedFixedUtc = DateTime.UtcNow.AddDays(-10)
            }
        };

        var narrative = _composer.Compose(result, history, new EntityFrame());

        Assert.Contains("It was verified fixed 1 week ago but has returned.", narrative.MemoryParagraph);
    }

    [Fact]
    public void Compose_CorrelationTraceability_HoldsEvenWithIdFreeTemplate()
    {
        var finding1 = CreateFinding("FW-002", "Firewall", Severity.High);
        var finding2 = CreateFinding("SSH-002", "SSH", Severity.High);
        var result = new AgentResult
        {
            AgentFindings = new[] { finding1, finding2 },
            PostureCorrelations = new[]
            {
                new PostureCorrelation
                {
                    PatternId = "POSTURE-001",
                    RuleIdA = "FW-002",
                    RuleIdB = "SSH-002",
                    Narrative = "These two rules together are a straight path to root.",
                    CombinedSeverity = Severity.Critical,
                    FindingIds = new[] { finding1.Id, finding2.Id }
                }
            }
        };

        var narrative = _composer.Compose(result, new Dictionary<string, RuleMemoryEntry>(), new EntityFrame());

        Assert.Contains("[FW-002 + SSH-002]", narrative.CorrelationsParagraph);

        // Every non-empty paragraph except the generic next-steps paragraph must cite a source.
        var paragraphs = new[]
        {
            narrative.KeyFindingsParagraph,
            narrative.CorrelationsParagraph,
            narrative.MemoryParagraph
        }.Where(p => !string.IsNullOrWhiteSpace(p));

        foreach (var paragraph in paragraphs)
        {
            var hasSource = narrative.SourceIds.Any(id => paragraph.Contains(id, StringComparison.OrdinalIgnoreCase));
            Assert.True(hasSource, $"Paragraph does not cite a source id: {paragraph}");
        }
    }

    [Fact]
    public void Compose_WithTrajectory_AddsTrajectoryParagraph()
    {
        var finding1 = CreateFinding("FW-001", "Firewall", Severity.High);
        var finding2 = CreateFinding("SSH-002", "SSH", Severity.Medium);
        var result = new AgentResult
        {
            AgentFindings = new[] { finding1, finding2 },
            SystemTrajectory = new SystemTrajectory
            {
                Direction = TrajectoryDirection.Worsening,
                ImprovingCount = 0,
                WorseningCount = 2,
                StableCount = 0,
                WeightedDelta = -7,
                WorseningRuleIds = new[] { "FW-001", "SSH-002" }
            }
        };

        var narrative = _composer.Compose(result, new Dictionary<string, RuleMemoryEntry>(), new EntityFrame());

        Assert.Contains("Trajectory", narrative.TrajectoryParagraph);
        Assert.Contains("worsening", narrative.TrajectoryParagraph);
        Assert.Contains("FW-001", narrative.TrajectoryParagraph);
        Assert.Contains("SSH-002", narrative.TrajectoryParagraph);
        Assert.Contains("FW-001", narrative.SourceIds);
        Assert.Contains("SSH-002", narrative.SourceIds);
    }

    [Fact]
    public void Compose_InsufficientHistory_DoesNotAddTrajectoryParagraph()
    {
        var finding = CreateFinding("FW-001", "Firewall", Severity.High);
        var result = new AgentResult
        {
            AgentFindings = new[] { finding },
            SystemTrajectory = new SystemTrajectory
            {
                Direction = TrajectoryDirection.InsufficientHistory,
                ImprovingCount = 0,
                WorseningCount = 0,
                StableCount = 0
            }
        };

        var narrative = _composer.Compose(result, new Dictionary<string, RuleMemoryEntry>(), new EntityFrame());

        Assert.Empty(narrative.TrajectoryParagraph);
        Assert.DoesNotContain("Trajectory", narrative.FullText);
    }

    [Fact]
    public void Compose_TrajectoryWithManyRules_AppendsEllipsis()
    {
        var result = new AgentResult
        {
            AgentFindings = Array.Empty<Finding>(),
            SystemTrajectory = new SystemTrajectory
            {
                Direction = TrajectoryDirection.Worsening,
                ImprovingCount = 0,
                WorseningCount = 5,
                StableCount = 0,
                WeightedDelta = -10,
                WorseningRuleIds = new[] { "R-001", "R-002", "R-003", "R-004", "R-005" }
            }
        };

        var narrative = _composer.Compose(result, new Dictionary<string, RuleMemoryEntry>(), new EntityFrame());

        Assert.Contains("…", narrative.TrajectoryParagraph);
    }

    [Fact]
    public void Compose_WithProactiveAlert_AddsProactiveAlertsParagraph()
    {
        var finding = CreateFinding("FW-001", "Firewall", Severity.High);
        var result = new AgentResult
        {
            AgentFindings = new[] { finding },
            ProactiveAlerts = new[]
            {
                new ProactiveAlert
                {
                    RuleId = "FW-001",
                    DaysSinceVerifiedFixed = 3,
                    CurrentSeverity = Severity.High,
                    Guidance = "Check firewall startup scripts."
                }
            }
        };

        var narrative = _composer.Compose(result, new Dictionary<string, RuleMemoryEntry>(), new EntityFrame());

        Assert.Contains("Proactive alerts", narrative.ProactiveAlertsParagraph);
        Assert.Contains("FW-001", narrative.ProactiveAlertsParagraph);
        Assert.Contains("returned after being verified fixed", narrative.ProactiveAlertsParagraph);
        Assert.Contains("firewall startup", narrative.ProactiveAlertsParagraph);
        Assert.Contains("FW-001", narrative.SourceIds);
    }

    [Fact]
    public void Compose_NoProactiveAlerts_DoesNotAddProactiveAlertsParagraph()
    {
        var finding = CreateFinding("FW-001", "Firewall", Severity.High);
        var result = new AgentResult
        {
            AgentFindings = new[] { finding },
            ProactiveAlerts = Array.Empty<ProactiveAlert>()
        };

        var narrative = _composer.Compose(result, new Dictionary<string, RuleMemoryEntry>(), new EntityFrame());

        Assert.Empty(narrative.ProactiveAlertsParagraph);
        Assert.DoesNotContain("Proactive alerts", narrative.FullText);
    }

    [Fact]
    public void Compose_WithAttackChains_AddsAttackChainsParagraph()
    {
        var finding1 = CreateFinding("FW-002", "Firewall", Severity.High);
        var finding2 = CreateFinding("SSH-002", "SSH", Severity.High);
        var result = new AgentResult
        {
            AgentFindings = new[] { finding1, finding2 },
            AttackChains = new[]
            {
                new AttackChain
                {
                    Links = new[]
                    {
                        new AttackChainLink
                        {
                            RuleId = "FW-002",
                            FindingId = finding1.Id,
                            StageName = "Reconnaissance",
                            Severity = Severity.High,
                            MitreTechniqueIds = new[] { "T1595" }
                        },
                        new AttackChainLink
                        {
                            RuleId = "SSH-002",
                            FindingId = finding2.Id,
                            StageName = "Credential Access",
                            Severity = Severity.High,
                            MitreTechniqueIds = new[] { "T1110" }
                        }
                    },
                    Narrative = "This is one attack chain: [FW-002] exposed → [SSH-002] brute-force. Fix any one link and the chain breaks.",
                    RuleIds = new[] { "FW-002", "SSH-002" },
                    SourcePatternIds = new[] { "POSTURE-001" }
                }
            }
        };

        var narrative = _composer.Compose(result, new Dictionary<string, RuleMemoryEntry>(), new EntityFrame());

        Assert.Contains("Attack chain", narrative.AttackChainsParagraph);
        Assert.Contains("FW-002", narrative.AttackChainsParagraph);
        Assert.Contains("SSH-002", narrative.AttackChainsParagraph);
        Assert.Contains("FW-002", narrative.SourceIds);
        Assert.Contains("SSH-002", narrative.SourceIds);
        Assert.Contains("POSTURE-001", narrative.SourceIds);
    }

    [Fact]
    public void Compose_NoAttackChains_DoesNotAddAttackChainsParagraph()
    {
        var finding = CreateFinding("FW-001", "Firewall", Severity.High);
        var result = new AgentResult
        {
            AgentFindings = new[] { finding },
            AttackChains = Array.Empty<AttackChain>()
        };

        var narrative = _composer.Compose(result, new Dictionary<string, RuleMemoryEntry>(), new EntityFrame());

        Assert.Empty(narrative.AttackChainsParagraph);
        Assert.DoesNotContain("Attack chain", narrative.FullText);
    }

    [Fact]
    public void Compose_WithRemediationWisdom_AddsRemediationWisdomParagraph()
    {
        var finding = CreateFinding("SSH-002", "SSH", Severity.High);
        var result = new AgentResult
        {
            AgentFindings = new[] { finding },
            RemediationWisdom = new[]
            {
                new RemediationWisdom
                {
                    RuleId = "SSH-002",
                    CycleCount = 3,
                    LastVerifiedFixedUtc = DateTime.UtcNow.AddDays(-3),
                    Guidance = "A one-time fix won't hold here. Check your playbooks."
                }
            }
        };

        var narrative = _composer.Compose(result, new Dictionary<string, RuleMemoryEntry>(), new EntityFrame());

        Assert.Contains("Remediation pattern", narrative.RemediationWisdomParagraph);
        Assert.Contains("SSH-002", narrative.RemediationWisdomParagraph);
        Assert.Contains("3 times", narrative.RemediationWisdomParagraph);
        Assert.Contains("SSH-002", narrative.SourceIds);
    }

    [Fact]
    public void Compose_NoRemediationWisdom_DoesNotAddRemediationWisdomParagraph()
    {
        var finding = CreateFinding("FW-001", "Firewall", Severity.High);
        var result = new AgentResult
        {
            AgentFindings = new[] { finding },
            RemediationWisdom = Array.Empty<RemediationWisdom>()
        };

        var narrative = _composer.Compose(result, new Dictionary<string, RuleMemoryEntry>(), new EntityFrame());

        Assert.Empty(narrative.RemediationWisdomParagraph);
        Assert.DoesNotContain("Remediation pattern", narrative.FullText);
    }

    private static Finding CreateFinding(string ruleId, string category, Severity severity)
    {
        var now = DateTime.UtcNow;
        return new Finding
        {
            RuleId = ruleId,
            Category = category,
            Severity = severity,
            SourceHost = "localhost",
            Target = "target",
            ShortDescription = $"Finding {ruleId}",
            Details = "Details",
            TimeRangeStart = now,
            TimeRangeEnd = now
        };
    }
}
