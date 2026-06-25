using System;
using System.Collections.Generic;
using System.Linq;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Scanners;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Reports;

public class WarningInterpreterTests
{
    private readonly WarningInterpreter _interpreter = new();

    [Fact]
    public void Interpret_LowercasePermissionDenied_CollapsesIntoFriendlyMessage()
    {
        var warnings = new[] { "permission denied reading process details" };

        var result = _interpreter.Interpret(AgentIntent.FullAudit, warnings, Array.Empty<DataSourceCapability>());

        var friendly = Assert.Single(result);
        Assert.Equal(WarningCategory.PermissionDenied, friendly.Category);
        Assert.Contains("blocked by permissions", friendly.Message, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(friendly.Suggestion);
    }

    [Fact]
    public void Interpret_MultiplePermissionWarnings_CollapsesWithCount()
    {
        var warnings = new[]
        {
            "find: '/root': Permission denied",
            "find: '/proc': Permission denied",
        };

        var result = _interpreter.Interpret(AgentIntent.FullAudit, warnings, Array.Empty<DataSourceCapability>());

        var friendly = Assert.Single(result);
        Assert.Equal(2, friendly.Count);
        Assert.Contains("2 checks were blocked", friendly.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("root", friendly.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("ss: command not found", "ss")]
    [InlineData("iptables is not available", "iptables")]
    [InlineData("systemctl is not available (non-systemd system?)", "systemctl")]
    public void Interpret_MissingTool_WarnsAboutTool(string warning, string expectedTool)
    {
        var result = _interpreter.Interpret(AgentIntent.FullAudit, new[] { warning }, Array.Empty<DataSourceCapability>());

        var friendly = Assert.Single(result);
        Assert.Equal(WarningCategory.MissingTool, friendly.Category);
        Assert.Contains(expectedTool, friendly.Message, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(friendly.Suggestion);
    }

    [Fact]
    public void Interpret_SshMissingConfig_CollapsesIntoSshMissingToolMessage()
    {
        var warnings = new[] { "SSH config scan skipped: no sshd_config found." };

        var result = _interpreter.Interpret(AgentIntent.SshCheck, warnings, Array.Empty<DataSourceCapability>());

        var friendly = Assert.Single(result);
        Assert.Equal(WarningCategory.MissingTool, friendly.Category);
        Assert.Contains("sshd_config", friendly.Message, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(friendly.Suggestion);
    }

    [Fact]
    public void Interpret_ScannerError_SummarizesWithoutRawText()
    {
        var warnings = new[] { "YARA scan produced an unexpected internal error." };

        var result = _interpreter.Interpret(AgentIntent.YaraCheck, warnings, Array.Empty<DataSourceCapability>());

        var friendly = Assert.Single(result);
        Assert.Equal(WarningCategory.ScannerError, friendly.Category);
        Assert.Contains("scanner returned", friendly.Message, StringComparison.OrdinalIgnoreCase);
        // Scanner errors collapse raw text away, so the message must not point the user at a
        // "warnings banner for raw details": that UI does not exist, and the details were
        // deliberately summarized out of the message.
        Assert.Null(friendly.Suggestion);
    }

    [Fact]
    public void Interpret_MixedWarnings_GroupsByCategory()
    {
        var warnings = new List<string>
        {
            "permission denied reading /etc/shadow",
            "ss: command not found",
            "Filesystem scan: no interesting config found",
        };

        var result = _interpreter.Interpret(AgentIntent.FullAudit, warnings, Array.Empty<DataSourceCapability>()).ToList();

        Assert.Equal(3, result.Count);
        Assert.Contains(result, r => r.Category == WarningCategory.PermissionDenied);
        Assert.Contains(result, r => r.Category == WarningCategory.MissingTool);
        Assert.Contains(result, r => r.Category == WarningCategory.ConfigurationMissing);
    }

    [Fact]
    public void Interpret_NoIssuesFound_NotMisclassifiedAsConfigMissing()
    {
        // The greedy "no " + "found" predicate previously swallowed benign empty-result phrasing
        // into ConfigurationMissing. It now falls through to the default ScannerError bucket.
        var result = _interpreter.Interpret(AgentIntent.FullAudit, new[] { "no issues found" }, Array.Empty<DataSourceCapability>());

        var friendly = Assert.Single(result);
        Assert.Equal(WarningCategory.ScannerError, friendly.Category);
        Assert.DoesNotContain(result, r => r.Category == WarningCategory.ConfigurationMissing);
    }

    [Fact]
    public void Interpret_FirewallMissingNft_NamesNftablesOnly()
    {
        // When only one backend is missing, the message names it instead of always saying
        // "iptables or nftables".
        var result = _interpreter.Interpret(AgentIntent.FirewallCheck, new[] { "nftables is not available" }, Array.Empty<DataSourceCapability>());

        var friendly = Assert.Single(result);
        Assert.Equal(WarningCategory.MissingTool, friendly.Category);
        Assert.Contains("nftables", friendly.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("iptables", friendly.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Interpret_FirewallScanPrefix_NamesBackendAndIsNotDropped()
    {
        // A "Firewall scan: iptables failed …" warning in a non-FirewallCheck audit was previously
        // dropped entirely (prefix matched the outer gate but the redundant inner gate rejected it,
        // and "firewall" sat in the covered set so the generic branch skipped it too). It now names
        // the concrete backend and always surfaces.
        var result = _interpreter.Interpret(
            AgentIntent.FullAudit,
            new[] { "Firewall scan: iptables failed (not installed)." },
            Array.Empty<DataSourceCapability>());

        var friendly = Assert.Single(result);
        Assert.Equal(WarningCategory.MissingTool, friendly.Category);
        Assert.Contains("iptables installed", friendly.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("nftables", friendly.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Interpret_FirewallBothBackends_NamesBoth()
    {
        var warnings = new[]
        {
            "Firewall scan: iptables failed (not installed).",
            "Firewall scan: nftables failed (not installed).",
        };

        var result = _interpreter.Interpret(AgentIntent.FirewallCheck, warnings, Array.Empty<DataSourceCapability>());

        var friendly = Assert.Single(result);
        Assert.Equal(WarningCategory.MissingTool, friendly.Category);
        Assert.Contains("iptables or nftables installed", friendly.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Interpret_PermissionDeniedNonPathQuote_OmitsJunkArea()
    {
        // A quoted span without a path separator ("'man sudoers'") must not surface as a junk
        // "Affected areas:" token.
        var result = _interpreter.Interpret(
            AgentIntent.FullAudit,
            new[] { "Permission denied (see 'man sudoers' for help)" },
            Array.Empty<DataSourceCapability>());

        var friendly = Assert.Single(result);
        Assert.Equal(WarningCategory.PermissionDenied, friendly.Category);
        Assert.Equal(1, friendly.Count);
        Assert.DoesNotContain("Affected areas", friendly.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("man sudoers", friendly.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Interpret_PermissionDeniedPrefersPathQuoteOverJunkQuote()
    {
        // When a path-bearing quote and a non-path quote both appear, the path is chosen.
        var result = _interpreter.Interpret(
            AgentIntent.FullAudit,
            new[] { "Permission denied reading '/etc/shadow' (see 'man sudoers')" },
            Array.Empty<DataSourceCapability>());

        var friendly = Assert.Single(result);
        Assert.Equal(WarningCategory.PermissionDenied, friendly.Category);
        Assert.Contains("Affected areas", friendly.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("etc", friendly.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("man sudoers", friendly.Message, StringComparison.OrdinalIgnoreCase);
    }
}
