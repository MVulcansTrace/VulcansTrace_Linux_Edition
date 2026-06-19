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
