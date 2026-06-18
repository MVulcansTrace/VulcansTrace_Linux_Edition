using VulcansTrace.Linux.Agent.Dialogue;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Dialogue;

public class EntityExtractorTests
{
    private readonly EntityExtractor _extractor = new();

    [Theory]
    [InlineData("explain FW-001", "FW-001")]
    [InlineData("fix PORT-002 please", "PORT-002")]
    [InlineData("no rule id here", null)]
    public void ExtractRuleId_ReturnsExpected(string query, string? expected)
    {
        Assert.Equal(expected, _extractor.ExtractRuleId(query));
    }

    [Theory]
    [InlineData("verify session abc12345", "abc12345")]
    [InlineData("resume 12345678", "12345678")]
    [InlineData("no session", null)]
    public void ExtractSessionId_ReturnsExpected(string query, string? expected)
    {
        Assert.Equal(expected, _extractor.ExtractSessionId(query));
    }

    [Theory]
    [InlineData("explain the first one", 1)]
    [InlineData("fix the 3rd finding", 3)]
    [InlineData("show the second issue", 2)]
    [InlineData("no ordinal here", null)]
    public void ExtractOrdinal_ReturnsExpected(string query, int? expected)
    {
        Assert.Equal(expected, _extractor.ExtractOrdinal(query));
    }

    [Theory]
    [InlineData("show firewall issues", "firewall")]
    [InlineData("check ssh", "ssh")]
    [InlineData("any containers?", "container")]
    [InlineData("hello world", null)]
    [InlineData("check my ssh service", "ssh")]
    [InlineData("check suid files", "suid")]
    [InlineData("world-writable files", "world-writable")]
    public void ExtractCategory_ReturnsExpected(string query, string? expected)
    {
        Assert.Equal(expected, _extractor.ExtractCategory(query));
    }

    [Theory]
    [InlineData("fix it", true)]
    [InlineData("explain that one", true)]
    [InlineData("verify it", true)]
    [InlineData("what should I fix first", false)]
    [InlineData("audit", false)]
    [InlineData("fix first", false)]
    [InlineData("explain the audit it", true)]
    public void HasAnaphora_RespectsWordBoundaries(string query, bool expected)
    {
        Assert.Equal(expected, _extractor.HasAnaphora(query));
    }
}
