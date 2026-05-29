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

    [Fact]
    public void GetStructuredExplanation_KnownKey_ReturnsAllSections()
    {
        var vars = new Dictionary<string, string> { ["policy"] = "ACCEPT" };
        var result = _provider.GetStructuredExplanation("FW-001", vars);

        Assert.Contains("ACCEPT", result.WhatWasFound);
        Assert.NotEmpty(result.WhyItMatters);
        Assert.NotEmpty(result.SuggestedNextAction);
        Assert.NotEmpty(result.Confidence);
        Assert.NotEqual(result.Confidence, result.Caveats);
    }

    [Fact]
    public void GetStructuredExplanation_UnknownKey_ReturnsFallback()
    {
        var result = _provider.GetStructuredExplanation("UNKNOWN-999", new Dictionary<string, string>());

        Assert.Contains("UNKNOWN-999", result.WhatWasFound);
    }

    [Fact]
    public void ParseStructuredFromText_FilledTemplate_ReturnsSections()
    {
        var text = """
            **What we found:** Policy is ACCEPT.

            **Why this matters:** It exposes the system.

            **How to verify:** Run `iptables -L`.

            **Suggested next action:** Change to DROP.

            **Risk level:** HIGH

            **Confidence / caveat:** High confidence.
            """;

        var result = _provider.ParseStructuredFromText(text);

        Assert.Contains("ACCEPT", result.WhatWasFound);
        Assert.Contains("exposes", result.WhyItMatters);
        Assert.Contains("iptables", result.HowToVerify);
        Assert.Contains("DROP", result.SuggestedNextAction);
        Assert.Contains("HIGH", result.Confidence);
        Assert.Contains("High confidence", result.Caveats);
    }

    [Fact]
    public void ParseStructuredFromText_CombinedConfidenceCaveat_SplitsWithoutDuplicating()
    {
        var text = """
            **Confidence / caveat:** Moderate confidence — verify cloud firewall rules too.
            """;

        var result = _provider.ParseStructuredFromText(text);

        Assert.Equal("Moderate confidence", result.Confidence);
        Assert.Equal("verify cloud firewall rules too.", result.Caveats);
    }
}
