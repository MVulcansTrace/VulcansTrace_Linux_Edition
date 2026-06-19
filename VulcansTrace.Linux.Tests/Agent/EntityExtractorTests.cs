using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class EntityExtractorTests
{
    private readonly EntityExtractor _extractor = new();

    [Theory]
    [InlineData("explain FW-001", "FW-001")]
    [InlineData("fix fw-001 and SSH-002", "FW-001")]
    [InlineData("what about PORT-003?", "PORT-003")]
    public void Extract_RuleId_FindsFirstRuleId(string query, string expected)
    {
        var frame = _extractor.Extract(query);

        Assert.Contains(expected, frame.RuleIds);
    }

    [Fact]
    public void Extract_MultipleRuleIds_ReturnsAll()
    {
        var frame = _extractor.Extract("compare FW-001 and SSH-002");

        Assert.Equal(2, frame.RuleIds.Count);
        Assert.Contains("FW-001", frame.RuleIds);
        Assert.Contains("SSH-002", frame.RuleIds);
    }

    [Fact]
    public void Extract_SessionId_FindsSessionId()
    {
        var frame = _extractor.Extract("verify session abc12345");

        Assert.Equal("abc12345", frame.SessionId);
    }

    [Theory]
    [InlineData("show only firewall issues", "firewall")]
    [InlineData("fix the ssh config", "ssh")]
    [InlineData("any container problems?", "container")]
    public void Extract_Category_FindsCategory(string query, string expected)
    {
        var frame = _extractor.Extract(query);

        Assert.Contains(expected, frame.Categories);
    }

    [Theory]
    [InlineData("show critical findings", Severity.Critical)]
    [InlineData("fix high ssh issues", Severity.High)]
    [InlineData("any medium or low items?", Severity.Medium)]
    [InlineData("list info findings", Severity.Info)]
    public void Extract_Severity_FindsSeverity(string query, Severity expected)
    {
        var frame = _extractor.Extract(query);

        Assert.Equal(expected, frame.SeverityFilter);
    }

    [Theory]
    [InlineData("findings from last week", 7)]
    [InlineData("changes in last 3 days", 3)]
    [InlineData("what happened today", 1)]
    public void Extract_TimeWindow_FindsDuration(string query, int expectedDays)
    {
        var frame = _extractor.Extract(query);

        Assert.Equal(TimeSpan.FromDays(expectedDays), frame.TimeWindow);
    }

    [Theory]
    [InlineData("fix FW-001", AgentIntent.FixFinding)]
    [InlineData("remediate SSH-002", AgentIntent.StartRemediation)]
    [InlineData("verify session abc12345", AgentIntent.VerifyRemediation)]
    [InlineData("explain FW-001", AgentIntent.ExplainFinding)]
    public void Extract_RemediationVerb_FindsVerb(string query, AgentIntent expected)
    {
        var frame = _extractor.Extract(query);

        Assert.Equal(expected, frame.RemediationVerb);
    }

    [Theory]
    [InlineData("explain the third one", 3)]
    [InlineData("fix the 5th finding", 5)]
    [InlineData("what about the first?", 1)]
    public void Extract_Ordinal_FindsOrdinal(string query, int expected)
    {
        var frame = _extractor.Extract(query);

        Assert.Equal(expected, frame.OrdinalReference);
    }

    [Fact]
    public void Extract_ComplexQuery_PopulatesMultipleEntities()
    {
        var frame = _extractor.Extract("fix the high ssh findings from last week");

        Assert.Contains("ssh", frame.Categories);
        Assert.Equal(Severity.High, frame.SeverityFilter);
        Assert.Equal(TimeSpan.FromDays(7), frame.TimeWindow);
        Assert.Equal(AgentIntent.FixFinding, frame.RemediationVerb);
    }

    [Fact]
    public void Extract_MultiWordCategory_FindsCategory()
    {
        var frame = _extractor.Extract("show threat intel issues");

        Assert.Contains("threat intel", frame.Categories);
    }

    [Theory]
    [InlineData("resume session abc12345", AgentIntent.ResumeRemediation)]
    [InlineData("continue session abc12345", AgentIntent.ResumeRemediation)]
    public void Extract_ResumeVerb_FindsVerb(string query, AgentIntent expected)
    {
        var frame = _extractor.Extract(query);

        Assert.Equal(expected, frame.RemediationVerb);
    }

    [Fact]
    public void Extract_VerbRequiresWordBoundary()
    {
        var frame = _extractor.Extract("what about FW-001, should I checksum it?");

        Assert.Null(frame.RemediationVerb);
    }

    [Fact]
    public void Extract_MultiWordPhraseRequiresWordBoundary()
    {
        var frame = _extractor.Extract("walk me throughs are boring");

        Assert.Null(frame.RemediationVerb);
    }

    [Fact]
    public void Extract_EmptyQuery_ReturnsEmptyFrame()
    {
        var frame = _extractor.Extract("   ");

        Assert.False(frame.HasEntities);
        Assert.Empty(frame.RuleIds);
        Assert.Empty(frame.Categories);
        Assert.Null(frame.SessionId);
        Assert.Null(frame.SeverityFilter);
        Assert.Null(frame.TimeWindow);
        Assert.Null(frame.RemediationVerb);
    }
}
