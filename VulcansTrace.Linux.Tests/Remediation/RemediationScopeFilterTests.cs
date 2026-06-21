using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Tests.Remediation;

public class RemediationScopeFilterTests
{
    [Fact]
    public void ParsePrefixes_NullOrEmpty_ReturnsEmpty()
    {
        Assert.Empty(RemediationScopeFilter.ParsePrefixes(null));
        Assert.Empty(RemediationScopeFilter.ParsePrefixes(""));
        Assert.Empty(RemediationScopeFilter.ParsePrefixes("   "));
    }

    [Fact]
    public void ParsePrefixes_TrimsUppercasesAndDeDuplicates()
    {
        var prefixes = RemediationScopeFilter.ParsePrefixes("FW, kern ,fw, ssh");
        Assert.Equal(new[] { "FW", "KERN", "SSH" }, prefixes);
    }

    [Fact]
    public void Apply_NoPrefixes_ReturnsAllFindings()
    {
        var findings = new[] { Finding("FW-001"), Finding("SSH-002"), Finding(null) };
        var result = RemediationScopeFilter.Apply(findings, null);
        Assert.Equal(3, result.Count);

        var empty = RemediationScopeFilter.Apply(findings, Array.Empty<string>());
        Assert.Equal(3, empty.Count);
    }

    [Fact]
    public void Apply_MatchesNamespaceToken_KeepingOnlyScopedFindings()
    {
        var findings = new[] { Finding("FW-001"), Finding("FW-002"), Finding("SSH-001"), Finding("KERN-001") };

        var result = RemediationScopeFilter.Apply(findings, new[] { "FW" });

        Assert.Equal(2, result.Count);
        Assert.All(result, f => Assert.StartsWith("FW-", f.RuleId));
    }

    [Fact]
    public void Apply_PrefixDoesNotMatchAcrossNamespaces()
    {
        // A short prefix must not span namespaces: "K" matches neither KERN nor K8S.
        var findings = new[] { Finding("KERN-001"), Finding("K8S-002") };

        var result = RemediationScopeFilter.Apply(findings, new[] { "K" });

        Assert.Empty(result);
    }

    [Fact]
    public void Apply_PrefixMatchesTokenRegardlessOfFollowingSeparator()
    {
        var findings = new[] { Finding("FW-001"), Finding("FW_LOG-002"), Finding("FWID-003") };

        // "FW" matches the leading token of "FW-001" and "FW_LOG-002" but not "FWID-003".
        var result = RemediationScopeFilter.Apply(findings, new[] { "FW" });

        Assert.Equal(2, result.Count);
        Assert.DoesNotContain(result, f => f.RuleId == "FWID-003");
    }

    [Fact]
    public void Apply_NullOrWhitespaceRuleIdExcludedWhenScoped()
    {
        var findings = new[] { Finding("FW-001"), Finding(null), Finding("   ") };

        var result = RemediationScopeFilter.Apply(findings, new[] { "FW" });

        Assert.Single(result);
        Assert.Equal("FW-001", result[0].RuleId);
    }

    [Fact]
    public void Apply_SupportsMultiplePrefixes()
    {
        var findings = new[] { Finding("FW-001"), Finding("SSH-001"), Finding("KERN-001") };

        var result = RemediationScopeFilter.Apply(findings, new[] { "FW", "SSH" });

        Assert.Equal(2, result.Count);
    }

    private static Finding Finding(string? ruleId) => new()
    {
        RuleId = ruleId,
        Category = "Test",
        Severity = Severity.High,
        SourceHost = "localhost",
        Target = "t",
        ShortDescription = ruleId + " finding",
        Details = "details",
        TimeRangeStart = new DateTime(2026, 6, 20, 0, 0, 0, DateTimeKind.Utc),
        TimeRangeEnd = new DateTime(2026, 6, 20, 0, 0, 0, DateTimeKind.Utc)
    };
}
