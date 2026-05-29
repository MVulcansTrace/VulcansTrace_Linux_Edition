using VulcansTrace.Linux.Agent.Explanations;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class ExplanationProviderTests
{
    private readonly ExplanationProvider _provider = new();

    [Fact]
    public void GetExplanation_KnownKey_ReturnsFilledTemplate()
    {
        var vars = new Dictionary<string, string> { ["policy"] = "ACCEPT" };
        var result = _provider.GetExplanation("FW-001", vars);

        Assert.Contains("ACCEPT", result);
        Assert.Contains("What we found", result);
    }

    [Fact]
    public void GetExplanation_UnknownKey_ReturnsFallbackMessage()
    {
        var result = _provider.GetExplanation("UNKNOWN-999", new Dictionary<string, string>());

        Assert.Contains("UNKNOWN-999", result);
    }

    [Fact]
    public void GetExplanation_MissingVariable_ShowsPlaceholder()
    {
        var result = _provider.GetExplanation("FW-002", new Dictionary<string, string>());

        // Should still render template without crashing, missing var appears as [varname] or empty
        Assert.Contains("What we found", result);
    }

    [Fact]
    public void GetExplanation_MultipleVariables_AllReplaced()
    {
        var vars = new Dictionary<string, string>
        {
            ["port"] = "3306",
            ["process"] = "mysqld"
        };
        var result = _provider.GetExplanation("PORT-003", vars);

        Assert.Contains("3306", result);
        Assert.Contains("mysqld", result);
    }
}
