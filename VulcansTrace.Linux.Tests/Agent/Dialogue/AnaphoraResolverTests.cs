using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Dialogue;

public class AnaphoraResolverTests
{
    private readonly AnaphoraResolver _resolver = new();

    [Fact]
    public void Resolve_ExplicitRuleId_DoesNotTreatAsAnaphora()
    {
        var context = new DialogueContext();
        var resolution = _resolver.Resolve("explain FW-001", context.SnapshotEntities());

        Assert.False(resolution.HasAnaphora);
        Assert.Equal("FW-001", resolution.RuleId);
    }

    [Fact]
    public void Resolve_Ordinal_ResolvesToFindingWithoutAnaphoraFlag()
    {
        var context = new DialogueContext();
        var findings = new[]
        {
            CreateFinding("TEST-001", "Firewall"),
            CreateFinding("TEST-002", "SSH"),
            CreateFinding("TEST-003", "Container")
        };
        context.RememberAudit(
            new AgentResult { Intent = AgentIntent.FullAudit, AgentFindings = findings },
            AgentIntent.FullAudit,
            findings.Select(f => (f.RuleId ?? "", f)));

        // RankFindings sorts by severity, then category, so ordering is
        // Container (TEST-003), Firewall (TEST-001), SSH (TEST-002).
        var resolution = _resolver.Resolve("explain the third one", context.SnapshotEntities());

        Assert.False(resolution.HasAnaphora);
        Assert.Equal("TEST-002", resolution.RuleId);
        Assert.Equal(3, resolution.Ordinal);
    }

    [Fact]
    public void Resolve_ItAfterExplanation_ResolvesToLastFinding()
    {
        var context = new DialogueContext();
        var finding = CreateFinding("TEST-001", "Firewall");
        context.FocusFinding(finding);

        var resolution = _resolver.Resolve("how do I fix it", context.SnapshotEntities());

        Assert.True(resolution.HasAnaphora);
        Assert.Equal("TEST-001", resolution.RuleId);
        Assert.Null(resolution.Category);
        Assert.Same(finding, resolution.Finding);
    }

    [Fact]
    public void Resolve_CategoryReference_ResolvesToLastCategory()
    {
        var context = new DialogueContext();
        context.FocusCategory("SSH");

        var resolution = _resolver.Resolve("show only the SSH ones", context.SnapshotEntities());

        Assert.True(resolution.HasAnaphora);
        Assert.Equal("ssh", resolution.Category);
    }

    [Fact]
    public void Resolve_NoReference_ReturnsEmpty()
    {
        var context = new DialogueContext();
        var resolution = _resolver.Resolve("run a full audit", context.SnapshotEntities());

        Assert.False(resolution.HasAnaphora);
        Assert.Null(resolution.RuleId);
        Assert.Null(resolution.Category);
    }

    [Theory]
    [InlineData("explain the 0th finding")]
    [InlineData("explain the 5th finding")]
    public void Resolve_InvalidOrdinal_ReturnsEmpty(string query)
    {
        var context = new DialogueContext();
        var findings = new[]
        {
            CreateFinding("TEST-001", "Firewall")
        };
        context.RememberAudit(
            new AgentResult { Intent = AgentIntent.FullAudit, AgentFindings = findings },
            AgentIntent.FullAudit,
            findings.Select(f => (f.RuleId ?? "", f)));

        var resolution = _resolver.Resolve(query, context.SnapshotEntities());

        Assert.Equal(ReferenceResolution.Empty, resolution);
    }

    private static Finding CreateFinding(string ruleId, string category)
    {
        var now = DateTime.UtcNow;
        return new Finding
        {
            RuleId = ruleId,
            Category = category,
            Severity = Severity.High,
            SourceHost = "localhost",
            Target = "target",
            ShortDescription = "Test finding",
            Details = "Details",
            TimeRangeStart = now,
            TimeRangeEnd = now
        };
    }
}
