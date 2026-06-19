using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using Xunit;

namespace VulcansTrace.Linux.Tests.Engine;

public class PostureCorrelatorTests
{
    private readonly PostureCorrelator _correlator = new();

    [Fact]
    public void Correlate_EmptyFindings_ReturnsEmpty()
    {
        var result = _correlator.Correlate(Array.Empty<Finding>());

        Assert.Empty(result);
    }

    [Fact]
    public void Correlate_Fw002AndSsh002_ReturnsPosture001()
    {
        var findings = new[]
        {
            CreateFinding("FW-002", "Firewall", Severity.High),
            CreateFinding("SSH-002", "SSH", Severity.High)
        };

        var result = _correlator.Correlate(findings);

        Assert.Single(result);
        var correlation = result[0];
        Assert.Equal("POSTURE-001", correlation.PatternId);
        Assert.Equal("FW-002", correlation.RuleIdA);
        Assert.Equal("SSH-002", correlation.RuleIdB);
        Assert.Equal(Severity.Critical, correlation.CombinedSeverity);
        Assert.Contains("FW-002", correlation.Narrative);
        Assert.Contains("SSH-002", correlation.Narrative);
        Assert.Contains(correlation.FindingIds[0], findings.Select(f => f.Id));
    }

    [Fact]
    public void Correlate_MissingPair_ReturnsEmpty()
    {
        var findings = new[]
        {
            CreateFinding("FW-002", "Firewall", Severity.High)
        };

        var result = _correlator.Correlate(findings);

        Assert.Empty(result);
    }

    [Fact]
    public void Correlate_WildcardPattern_MatchesPortRules()
    {
        var findings = new[]
        {
            CreateFinding("FW-004", "Firewall", Severity.Critical),
            CreateFinding("PORT-022", "Port", Severity.High)
        };

        var result = _correlator.Correlate(findings);

        Assert.Single(result);
        Assert.Equal("POSTURE-002", result[0].PatternId);
        Assert.Equal("PORT-022", result[0].RuleIdB);
    }

    [Fact]
    public void Correlate_DoesNotCorrelateFindingWithItself()
    {
        // A malformed input where both findings have the same rule ID and content.
        var finding = CreateFinding("FW-002", "Firewall", Severity.High);
        var findings = new[] { finding, finding };

        var result = _correlator.Correlate(findings);

        Assert.Empty(result);
    }

    [Fact]
    public void Correlate_CustomPattern_UsesProvidedRegistry()
    {
        var customPattern = new PostureCorrelationPattern
        {
            PatternId = "CUSTOM-001",
            RuleIdA = "TEST-001",
            RuleIdB = "TEST-002",
            CombinedSeverity = Severity.High,
            NarrativeTemplate = "{RuleIdA} plus {RuleIdB} is bad."
        };

        var correlator = new PostureCorrelator(new[] { customPattern });
        var findings = new[]
        {
            CreateFinding("TEST-001", "Test", Severity.Medium),
            CreateFinding("TEST-002", "Test", Severity.Medium)
        };

        var result = correlator.Correlate(findings);

        Assert.Single(result);
        Assert.Equal("CUSTOM-001", result[0].PatternId);
        Assert.Equal("TEST-001 plus TEST-002 is bad.", result[0].Narrative);
    }



    [Fact]
    public void Correlate_MultipleFindingsPerRule_Deduplicates()
    {
        var findings = new[]
        {
            CreateFinding("FW-002", "Firewall", Severity.High),
            CreateFinding("FW-002", "Firewall", Severity.High),
            CreateFinding("SSH-002", "SSH", Severity.High),
            CreateFinding("SSH-002", "SSH", Severity.High)
        };

        var result = _correlator.Correlate(findings);

        Assert.Single(result);
        Assert.Equal("POSTURE-001", result[0].PatternId);
    }

    [Fact]
    public void Correlate_IgnoresFindingsWithoutRuleId()
    {
        var findings = new[]
        {
            new Finding
            {
                Category = "Unknown",
                Severity = Severity.High,
                SourceHost = "localhost",
                Target = "target",
                ShortDescription = "No rule id",
                Details = "Details",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow
            },
            CreateFinding("SSH-002", "SSH", Severity.High)
        };

        var result = _correlator.Correlate(findings);

        Assert.Empty(result);
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
