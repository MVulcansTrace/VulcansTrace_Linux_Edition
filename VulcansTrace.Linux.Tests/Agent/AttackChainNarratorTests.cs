using VulcansTrace.Linux.Agent.Analysis;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class AttackChainNarratorTests
{
    private readonly AttackChainNarrator _narrator = new();

    [Fact]
    public void BuildChains_NoMappedRules_ReturnsEmpty()
    {
        var findings = new[]
        {
            CreateFinding("UNKNOWN-001", Severity.High)
        };

        var chains = _narrator.BuildChains(findings, Array.Empty<PostureCorrelation>());

        Assert.Empty(chains);
    }

    [Fact]
    public void BuildChains_SingleMappedRule_ReturnsEmpty()
    {
        var findings = new[]
        {
            CreateFinding("FW-002", Severity.High)
        };

        var chains = _narrator.BuildChains(findings, Array.Empty<PostureCorrelation>());

        Assert.Empty(chains);
    }

    [Fact]
    public void BuildChains_TwoOrderedStagesWithoutCorrelation_ReturnsEmpty()
    {
        var findings = new[]
        {
            CreateFinding("FW-002", Severity.High),
            CreateFinding("SSH-002", Severity.High)
        };

        var chains = _narrator.BuildChains(findings, Array.Empty<PostureCorrelation>());

        Assert.Empty(chains);
    }

    [Fact]
    public void BuildChains_ThreeStages_BuildsOrderedChain()
    {
        var findings = new[]
        {
            CreateFinding("SSH-001", Severity.Critical),
            CreateFinding("SSH-002", Severity.High),
            CreateFinding("FW-002", Severity.High)
        };

        var correlations = new[] { CreateCorrelation("POSTURE-001", findings[2], findings[1]) };

        var chains = _narrator.BuildChains(findings, correlations);

        Assert.Single(chains);
        Assert.Equal(3, chains[0].Links.Count);
        Assert.Equal("FW-002", chains[0].Links[0].RuleId);
        Assert.Equal("SSH-002", chains[0].Links[1].RuleId);
        Assert.Equal("SSH-001", chains[0].Links[2].RuleId);
    }

    [Fact]
    public void BuildChains_CorrelatedPair_PrioritizesCorrelationInChain()
    {
        var finding1 = CreateFinding("FW-002", Severity.High);
        var finding2 = CreateFinding("SSH-002", Severity.High);
        var findings = new[] { finding1, finding2 };
        var correlations = new[] { CreateCorrelation("POSTURE-001", finding1, finding2) };

        var chains = _narrator.BuildChains(findings, correlations);

        Assert.Single(chains);
        Assert.Equal(2, chains[0].Links.Count);
        Assert.Contains("POSTURE-001", chains[0].SourcePatternIds);
    }

    [Fact]
    public void BuildChains_WildcardRule_MatchesPortRules()
    {
        var finding1 = CreateFinding("FW-004", Severity.Critical);
        var finding2 = CreateFinding("PORT-022", Severity.High);
        var findings = new[]
        {
            finding1,
            finding2
        };
        var correlations = new[] { CreateCorrelation("POSTURE-002", finding1, finding2) };

        var chains = _narrator.BuildChains(findings, correlations);

        Assert.Single(chains);
        Assert.Equal(2, chains[0].Links.Count);
        Assert.Contains("PORT-022", chains[0].Links.Select(l => l.RuleId));
    }

    [Fact]
    public void BuildChains_UnorderedStages_DoesNotForceChain()
    {
        // Two execution-stage rules should not chain together.
        var findings = new[]
        {
            CreateFinding("SSH-001", Severity.Critical),
            CreateFinding("SSH-005", Severity.Critical)
        };

        var chains = _narrator.BuildChains(findings, Array.Empty<PostureCorrelation>());

        Assert.Empty(chains);
    }

    [Fact]
    public void BuildChains_ManyOrderedLinks_BuildsSingleCoherentChain()
    {
        var fw002 = CreateFinding("FW-002", Severity.High);
        var ssh002 = CreateFinding("SSH-002", Severity.High);
        var fw004 = CreateFinding("FW-004", Severity.Critical);
        var port022 = CreateFinding("PORT-022", Severity.High);
        var findings = new[]
        {
            fw002,
            ssh002,
            fw004,
            port022
        };
        var correlations = new[]
        {
            CreateCorrelation("POSTURE-001", fw002, ssh002),
            CreateCorrelation("POSTURE-002", fw004, port022)
        };

        var chains = _narrator.BuildChains(findings, correlations);

        Assert.Equal(2, chains.Count);
        Assert.All(chains, chain => Assert.True(chain.Links.Count >= 2));
        Assert.NotEqual(
            chains[0].Narrative.Split(':')[0],
            chains[1].Narrative.Split(':')[0]);
    }

    [Fact]
    public void BuildChains_ContinuationGraph_CanBranchFromSeed()
    {
        var fw002 = CreateFinding("FW-002", Severity.High);
        var ssh002 = CreateFinding("SSH-002", Severity.High);
        var ssh001 = CreateFinding("SSH-001", Severity.Critical);
        var ssh005 = CreateFinding("SSH-005", Severity.Critical);
        var findings = new[] { fw002, ssh002, ssh001, ssh005 };
        var correlations = new[] { CreateCorrelation("POSTURE-001", fw002, ssh002) };

        var chains = _narrator.BuildChains(findings, correlations);

        Assert.Equal(2, chains.Count);
        Assert.Contains(chains, c => c.RuleIds.SequenceEqual(new[] { "FW-002", "SSH-002", "SSH-001" }));
        Assert.Contains(chains, c => c.RuleIds.SequenceEqual(new[] { "FW-002", "SSH-002", "SSH-005" }));
    }

    [Fact]
    public void BuildChains_CitesMitreTechniques()
    {
        var finding1 = CreateFinding("FW-002", Severity.High, mitreIds: new[] { "T1595" });
        var finding2 = CreateFinding("SSH-002", Severity.High, mitreIds: new[] { "T1110" });
        var findings = new[]
        {
            finding1,
            finding2
        };
        var correlations = new[] { CreateCorrelation("POSTURE-001", finding1, finding2) };

        var chains = _narrator.BuildChains(findings, correlations);

        Assert.Single(chains);
        Assert.Contains("T1595", chains[0].Narrative);
        Assert.Contains("T1110", chains[0].Narrative);
    }

    [Fact]
    public void BuildChains_MultipleFindingsSameRule_DedupesToSingleLink()
    {
        var finding1 = CreateFinding("FW-002", Severity.High);
        var finding2 = CreateFinding("FW-002", Severity.Medium);
        var finding3 = CreateFinding("SSH-002", Severity.Critical);
        var findings = new[]
        {
            finding1,
            finding2,
            finding3
        };
        var correlations = new[] { CreateCorrelation("POSTURE-001", finding1, finding3) };

        var chains = _narrator.BuildChains(findings, correlations);

        Assert.Single(chains);
        Assert.Equal(2, chains[0].Links.Count);
        Assert.Single(chains[0].Links, l => l.RuleId == "FW-002");
        Assert.Equal(Severity.High, chains[0].Links.Single(l => l.RuleId == "FW-002").Severity);
    }

    [Fact]
    public void BuildChains_UserUidZeroNarrativeDoesNotDescribePasswordPolicy()
    {
        var finding1 = CreateFinding("USER-001", Severity.Critical);
        var finding2 = CreateFinding("SSH-002", Severity.High);
        var findings = new[] { finding1, finding2 };
        var correlations = new[] { CreateCorrelation("POSTURE-003", finding1, finding2) };

        var chains = _narrator.BuildChains(findings, correlations);

        Assert.Single(chains);
        Assert.Contains("UID-0", chains[0].Narrative);
        Assert.DoesNotContain("weak password policy", chains[0].Narrative, StringComparison.OrdinalIgnoreCase);
    }

    private static Finding CreateFinding(string ruleId, Severity severity, string[]? mitreIds = null)
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
            TimeRangeEnd = now,
            MitreTechniques = (mitreIds ?? Array.Empty<string>())
                .Select(id => new MitreTechnique { TechniqueId = id, TechniqueName = id, Tactic = "Test" })
                .ToList()
        };
    }

    private static PostureCorrelation CreateCorrelation(string patternId, Finding findingA, Finding findingB)
    {
        return new PostureCorrelation
        {
            PatternId = patternId,
            RuleIdA = findingA.RuleId!,
            RuleIdB = findingB.RuleId!,
            Narrative = "Test correlation",
            CombinedSeverity = Severity.Critical,
            FindingIds = new[] { findingA.Id, findingB.Id }
        };
    }
}
