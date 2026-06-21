using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class QueryParserTests
{
    private readonly QueryParser _parser = new();

    [Theory]
    [InlineData("is my system secure?", AgentIntent.FullAudit)]
    [InlineData("run a full check", AgentIntent.FullAudit)]
    [InlineData("health check", AgentIntent.FullAudit)]
    [InlineData("audit everything", AgentIntent.FullAudit)]
    [InlineData("check my firewall", AgentIntent.FirewallCheck)]
    [InlineData("how's my iptables", AgentIntent.FirewallCheck)]
    [InlineData("nftables rules", AgentIntent.FirewallCheck)]
    [InlineData("who am I talking to?", AgentIntent.NetworkCheck)]
    [InlineData("show connections", AgentIntent.NetworkCheck)]
    [InlineData("network traffic", AgentIntent.NetworkCheck)]
    [InlineData("what's running?", AgentIntent.ServiceCheck)]
    [InlineData("check services", AgentIntent.ServiceCheck)]
    [InlineData("systemctl daemons", AgentIntent.ServiceCheck)]
    [InlineData("what ports are open?", AgentIntent.PortCheck)]
    [InlineData("check open ports", AgentIntent.PortCheck)]
    [InlineData("listening ports", AgentIntent.PortCheck)]
    [InlineData("check my ssh", AgentIntent.SshCheck)]
    [InlineData("how's my sshd config", AgentIntent.SshCheck)]
    [InlineData("ssh hardening", AgentIntent.SshCheck)]
    [InlineData("check file permissions", AgentIntent.FilePermissionCheck)]
    [InlineData("are my permissions secure", AgentIntent.FilePermissionCheck)]
    [InlineData("chmod shadow", AgentIntent.FilePermissionCheck)]
    [InlineData("show file permission findings", AgentIntent.FilePermissionCheck)]
    [InlineData("explain this finding", AgentIntent.ExplainFinding)]
    [InlineData("what does this mean", AgentIntent.ExplainFinding)]
    [InlineData("what changed since the last audit", AgentIntent.ShowChanges)]
    [InlineData("difference since last time", AgentIntent.ShowChanges)]
    [InlineData("why is this critical", AgentIntent.ExplainCritical)]
    [InlineData("critical findings", AgentIntent.ExplainCritical)]
    [InlineData("show only firewall issues", AgentIntent.FilterCategory)]
    [InlineData("prove FW-002", AgentIntent.ShowEvidence)]
    [InlineData("show me the evidence", AgentIntent.ShowEvidence)]
    [InlineData("show me the evidence for FW-002", AgentIntent.ShowEvidence)]
    [InlineData("show evidence for it", AgentIntent.ShowEvidence)]
    [InlineData("what triggered FW-002", AgentIntent.ShowEvidence)]
    [InlineData("why was this flagged", AgentIntent.ShowEvidence)]
    [InlineData("show sources for the SSH finding", AgentIntent.ShowEvidence)]
    [InlineData("what should I fix first", AgentIntent.PrioritizeRemediation)]
    [InlineData("remediation plan", AgentIntent.PrioritizeRemediation)]
    [InlineData("fix FW-001", AgentIntent.FixFinding)]
    [InlineData("remediate PORT-002", AgentIntent.StartRemediation)]
    [InlineData("guided fix FW-001", AgentIntent.StartRemediation)]
    [InlineData("verify session abc12345", AgentIntent.VerifyRemediation)]
    [InlineData("resolve SSH-003", AgentIntent.FixFinding)]
    [InlineData("what should I fix", AgentIntent.PrioritizeRemediation)]
    [InlineData("which findings are suppressed", AgentIntent.ListSuppressed)]
    [InlineData("suppressed", AgentIntent.ListSuppressed)]
    [InlineData("set baseline", AgentIntent.SetBaseline)]
    [InlineData("save baseline", AgentIntent.SetBaseline)]
    [InlineData("mark as baseline", AgentIntent.SetBaseline)]
    [InlineData("check drift", AgentIntent.CheckDrift)]
    [InlineData("baseline drift", AgentIntent.CheckDrift)]
    [InlineData("changed from baseline", AgentIntent.CheckDrift)]
    [InlineData("show baseline", AgentIntent.ShowBaseline)]
    [InlineData("view baseline", AgentIntent.ShowBaseline)]
    [InlineData("what is my baseline", AgentIntent.ShowBaseline)]
    [InlineData("check my kernel hardening", AgentIntent.KernelCheck)]
    [InlineData("sysctl settings", AgentIntent.KernelCheck)]
    [InlineData("is secure boot enabled", AgentIntent.KernelCheck)]
    [InlineData("kernel modules", AgentIntent.KernelCheck)]
    [InlineData("check my logging", AgentIntent.LoggingAuditCheck)]
    [InlineData("rsyslog status", AgentIntent.LoggingAuditCheck)]
    [InlineData("journald config", AgentIntent.LoggingAuditCheck)]
    [InlineData("auditd rules", AgentIntent.LoggingAuditCheck)]
    [InlineData("logrotate setup", AgentIntent.LoggingAuditCheck)]
    [InlineData("log forwarding", AgentIntent.LoggingAuditCheck)]
    [InlineData("syslog forwarding", AgentIntent.LoggingAuditCheck)]
    [InlineData("check my cron jobs", AgentIntent.CronJobCheck)]
    [InlineData("crontab audit", AgentIntent.CronJobCheck)]
    [InlineData("scheduled jobs", AgentIntent.CronJobCheck)]
    [InlineData("check package vulnerabilities", AgentIntent.PackageVulnerabilityCheck)]
    [InlineData("security updates", AgentIntent.PackageVulnerabilityCheck)]
    [InlineData("cve scan", AgentIntent.PackageVulnerabilityCheck)]
    [InlineData("apt upgradeable", AgentIntent.PackageVulnerabilityCheck)]
    [InlineData("patch status", AgentIntent.PackageVulnerabilityCheck)]
    [InlineData("what's my risk grade", AgentIntent.RiskScore)]
    [InlineData("show risk score", AgentIntent.RiskScore)]
    [InlineData("how risky is my system", AgentIntent.RiskScore)]
    [InlineData("overall risk assessment", AgentIntent.RiskScore)]
    [InlineData("help", AgentIntent.Help)]
    [InlineData("what can you do", AgentIntent.Help)]
    [InlineData("capabilities", AgentIntent.Help)]
    [InlineData("list sessions", AgentIntent.ListRemediationSessions)]
    [InlineData("show sessions", AgentIntent.ListRemediationSessions)]
    [InlineData("session history", AgentIntent.ListRemediationSessions)]
    [InlineData("my sessions", AgentIntent.ListRemediationSessions)]
    [InlineData("resume session abc12345", AgentIntent.ResumeRemediation)]
    [InlineData("continue session 1234abcd", AgentIntent.ResumeRemediation)]
    [InlineData("open session deadbeef", AgentIntent.ResumeRemediation)]
    [InlineData("add note to session abc12345 changed firewall policy", AgentIntent.AddSessionNote)]
    [InlineData("session note abc12345 confirmed console access", AgentIntent.AddSessionNote)]
    [InlineData("note for step FW-001 backup saved", AgentIntent.AddStepNote)]
    [InlineData("step note FW-001 applied fix", AgentIntent.AddStepNote)]
    [InlineData("check threat intel", AgentIntent.ThreatIntelCheck)]
    [InlineData("show me threat intel", AgentIntent.ThreatIntelCheck)]
    [InlineData("show me iocs", AgentIntent.ThreatIntelCheck)]
    [InlineData("run a yara scan", AgentIntent.YaraCheck)]
    [InlineData("check for malware signatures", AgentIntent.YaraCheck)]
    [InlineData("yara rule match", AgentIntent.YaraCheck)]
    [InlineData("check running processes", AgentIntent.ProcessRuntimeCheck)]
    [InlineData("process runtime check", AgentIntent.ProcessRuntimeCheck)]
    [InlineData("memory injection", AgentIntent.ProcessRuntimeCheck)]
    [InlineData("ld preload check", AgentIntent.ProcessRuntimeCheck)]
    [InlineData("deleted binary", AgentIntent.ProcessRuntimeCheck)]
    public void Parse_VariousQueries_ReturnsExpectedIntent(string query, AgentIntent expected)
    {
        var result = _parser.Parse(query);
        Assert.Equal(expected, result.Intent);
    }

    [Fact]
    public void Parse_UnknownQuery_ReturnsHelp()
    {
        var result = _parser.Parse("tell me a joke");
        Assert.Equal(AgentIntent.Help, result.Intent);
        Assert.Equal(0.0, result.Confidence);
    }

    [Fact]
    public void Parse_EmptyString_ReturnsHelp()
    {
        var result = _parser.Parse("");
        Assert.Equal(AgentIntent.Help, result.Intent);
    }

    [Fact]
    public void Parse_Whitespace_ReturnsHelp()
    {
        var result = _parser.Parse("   ");
        Assert.Equal(AgentIntent.Help, result.Intent);
    }

    [Fact]
    public void Parse_CaseInsensitive_MatchesCorrectly()
    {
        var result = _parser.Parse("CHECK MY FIREWALL");
        Assert.Equal(AgentIntent.FirewallCheck, result.Intent);
    }

    [Theory]
    [InlineData("explain FW-001", "FW-001")]
    [InlineData("what does PORT-002 mean", "PORT-002")]
    [InlineData("explain fw-001", "fw-001")]
    [InlineData("explain the ssh rule", "ssh")]
    [InlineData("why is firewall flagged", "firewall")]
    [InlineData("explain finding FW-003", "FW-003")]
    public void Parse_ExplainFinding_WithReference_ReturnsTargetReference(string query, string expectedReference)
    {
        var result = _parser.Parse(query);
        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Equal(expectedReference, result.TargetReference);
    }

    [Theory]
    [InlineData("fix FW-001", "FW-001")]
    [InlineData("resolve FILE-003", "FILE-003")]
    public void Parse_FixFinding_WithReference_ReturnsTargetReference(string query, string expectedReference)
    {
        var result = _parser.Parse(query);
        Assert.Equal(AgentIntent.FixFinding, result.Intent);
        Assert.Equal(expectedReference, result.TargetReference);
    }

    [Theory]
    [InlineData("resolve")]
    public void Parse_FixFinding_WithoutReference_ReturnsNullTargetReference(string query)
    {
        var result = _parser.Parse(query);
        Assert.Equal(AgentIntent.FixFinding, result.Intent);
        Assert.Null(result.TargetReference);
    }

    [Theory]
    [InlineData("remediate port-002", "port-002")]
    [InlineData("guided fix FW-001", "FW-001")]
    public void Parse_StartRemediation_WithReference_ReturnsTargetReference(string query, string expectedReference)
    {
        var result = _parser.Parse(query);
        Assert.Equal(AgentIntent.StartRemediation, result.Intent);
        Assert.Equal(expectedReference, result.TargetReference);
    }

    [Fact]
    public void Parse_StartRemediation_WithoutReference_ReturnsNullTargetReference()
    {
        var result = _parser.Parse("remediate");
        Assert.Equal(AgentIntent.StartRemediation, result.Intent);
        Assert.Null(result.TargetReference);
    }

    [Fact]
    public void Parse_VerifyRemediation_WithSessionId_ReturnsTargetReference()
    {
        var result = _parser.Parse("verify remediation abc12345");
        Assert.Equal(AgentIntent.VerifyRemediation, result.Intent);
        Assert.Equal("abc12345", result.TargetReference);
    }

    [Theory]
    [InlineData("resume session abc12345", "abc12345")]
    [InlineData("continue session 1234abcd", "1234abcd")]
    [InlineData("open session deadbeef", "deadbeef")]
    public void Parse_ResumeRemediation_WithSessionId_ReturnsTargetReference(string query, string expectedReference)
    {
        var result = _parser.Parse(query);
        Assert.Equal(AgentIntent.ResumeRemediation, result.Intent);
        Assert.Equal(expectedReference, result.TargetReference);
    }

    [Fact]
    public void Parse_ResumeRemediation_WithoutSessionId_ReturnsNullTargetReference()
    {
        var result = _parser.Parse("resume session");
        Assert.Equal(AgentIntent.ResumeRemediation, result.Intent);
        Assert.Null(result.TargetReference);
    }

    [Theory]
    [InlineData("add note to session abc12345 changed firewall policy", "abc12345")]
    [InlineData("session note deadbeef confirmed console access", "deadbeef")]
    public void Parse_AddSessionNote_WithSessionId_ReturnsTargetReference(string query, string expectedReference)
    {
        var result = _parser.Parse(query);
        Assert.Equal(AgentIntent.AddSessionNote, result.Intent);
        Assert.Equal(expectedReference, result.TargetReference);
    }

    [Theory]
    [InlineData("note for step FW-001 abc12345 backup saved", "abc12345")]
    [InlineData("step note TEST-001 deadbeef applied fix", "deadbeef")]
    public void Parse_AddStepNote_WithSessionId_ReturnsSessionIdAsTargetReference(string query, string expectedReference)
    {
        var result = _parser.Parse(query);
        Assert.Equal(AgentIntent.AddStepNote, result.Intent);
        Assert.Equal(expectedReference, result.TargetReference);
    }

    [Fact]
    public void Parse_AddStepNote_WithoutSessionId_ReturnsRuleIdAsTargetReference()
    {
        var result = _parser.Parse("note for step FW-001 backup saved");
        Assert.Equal(AgentIntent.AddStepNote, result.Intent);
        Assert.Equal("FW-001", result.TargetReference);
    }

    [Fact]
    public void Parse_FixKeywordAlone_ReturnsHelp()
    {
        var result = _parser.Parse("fix");
        Assert.Equal(AgentIntent.Help, result.Intent);
    }

    [Theory]
    [InlineData("explain this finding")]
    [InlineData("what does this mean")]
    [InlineData("why is this flagged")]
    public void Parse_ExplainFinding_WithoutReference_ReturnsNullTargetReference(string query)
    {
        var result = _parser.Parse(query);
        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Null(result.TargetReference);
    }

    [Theory]
    [InlineData("check my firewall")]
    [InlineData("what ports are open?")]
    public void Parse_NonExplainFinding_NeverReturnsTargetReference(string query)
    {
        var result = _parser.Parse(query);
        Assert.Null(result.TargetReference);
    }

    [Theory]
    [InlineData("show only firewall issues", "firewall")]
    [InlineData("filter network findings", "network")]
    [InlineData("only ssh findings", "ssh")]
    [InlineData("filter permission issues", "permission")]
    [InlineData("show only kernel findings", "kernel")]
    public void Parse_FilterCategory_WithReference_ReturnsCategoryReference(string query, string expectedReference)
    {
        var result = _parser.Parse(query);
        Assert.Equal(AgentIntent.FilterCategory, result.Intent);
        Assert.Equal(expectedReference, result.TargetReference);
    }

    [Fact]
    public void Parse_FilterCategory_WithoutReference_ReturnsNullTargetReference()
    {
        var result = _parser.Parse("show only issues");
        Assert.Equal(AgentIntent.FilterCategory, result.Intent);
        Assert.Null(result.TargetReference);
    }

    [Fact]
    public void Parse_FilterCategory_PortIssues_ReturnsPortCheck()
    {
        // "port" scores higher than filter keywords, so this is treated as a fresh port audit
        var result = _parser.Parse("just show port issues");
        Assert.Equal(AgentIntent.PortCheck, result.Intent);
    }

    [Fact]
    public void Parse_AmbiguousQuery_ReturnsAlternativesAndLowConfidence()
    {
        var result = _parser.Parse("check firewall ports");

        Assert.True(result.IsAmbiguous);
        Assert.Equal(AgentIntent.PortCheck, result.Intent);
        Assert.Contains(AgentIntent.FirewallCheck, result.AlternativeIntents ?? Array.Empty<AgentIntent>());
        Assert.InRange(result.Confidence, 0.0, 1.0);
    }

    [Fact]
    public void Parse_UnambiguousQuery_ReturnsNoAlternatives()
    {
        var result = _parser.Parse("check my firewall");

        Assert.False(result.IsAmbiguous);
        Assert.Empty(result.AlternativeIntents ?? Array.Empty<AgentIntent>());
        Assert.Equal(1.0, result.Confidence);
    }

    [Fact]
    public void Parse_BlankQuery_PreservesRawQuery()
    {
        var result = _parser.Parse("   ");

        Assert.Equal(AgentIntent.Help, result.Intent);
        Assert.Equal("   ", result.RawQuery);
    }

    [Fact]
    public void Parse_AddSessionNote_ReturnsHighConfidence()
    {
        // Use a query with minimal competing keywords
        var result = _parser.Parse("add note changed policy");

        Assert.Equal(AgentIntent.AddSessionNote, result.Intent);
        Assert.True(result.Confidence >= 0.5);
        Assert.False(result.IsAmbiguous);
        Assert.Empty(result.AlternativeIntents ?? Array.Empty<AgentIntent>());
    }

    [Fact]
    public void Parse_AddStepNote_ReturnsHighConfidence()
    {
        var result = _parser.Parse("note for step FW-001 abc12345 backup saved");

        Assert.Equal(AgentIntent.AddStepNote, result.Intent);
        Assert.True(result.Confidence >= 0.5);
        Assert.False(result.IsAmbiguous);
        Assert.Empty(result.AlternativeIntents ?? Array.Empty<AgentIntent>());
    }

    [Fact]
    public void Parse_AddNoteKeywords_DoNotCollideWithNoteIntents()
    {
        // "note" alone should NOT match AddSessionNote (no keywords match)
        var result = _parser.Parse("note");
        Assert.Equal(AgentIntent.Help, result.Intent);

        // "session" contains "ss" which matches PortCheck — verify it does NOT match AddSessionNote
        var sessionResult = _parser.Parse("session");
        Assert.NotEqual(AgentIntent.AddSessionNote, sessionResult.Intent);
        Assert.NotEqual(AgentIntent.AddStepNote, sessionResult.Intent);

        // "step" alone should match Help (no strong match)
        var stepResult = _parser.Parse("step");
        Assert.Equal(AgentIntent.Help, stepResult.Intent);
    }

    [Fact]
    public void Parse_AddSessionNote_WithoutSessionId_ReturnsNullTargetReference()
    {
        var result = _parser.Parse("add note changed policy");

        Assert.Equal(AgentIntent.AddSessionNote, result.Intent);
        Assert.Null(result.TargetReference);
    }

    [Fact]
    public void Parse_PopulatesEntityFrameWithRuleId()
    {
        var result = _parser.Parse("explain FW-001");

        Assert.Single(result.Entities.RuleIds);
        Assert.Contains("FW-001", result.Entities.RuleIds);
        Assert.Equal(AgentIntent.ExplainFinding, result.Entities.RemediationVerb);
    }

    [Fact]
    public void Parse_NoKeywordScore_StillPopulatesEntityFrame()
    {
        var result = _parser.Parse("verify finding TEST-001");

        Assert.Equal(AgentIntent.Help, result.Intent);
        Assert.Single(result.Entities.RuleIds);
        Assert.Contains("TEST-001", result.Entities.RuleIds);
        Assert.Equal(AgentIntent.VerifyRemediation, result.Entities.RemediationVerb);
    }

    [Fact]
    public void Parse_PopulatesEntityFrameWithMultipleEntities()
    {
        var result = _parser.Parse("fix the high ssh findings from last week");

        Assert.Empty(result.Entities.RuleIds);
        Assert.Contains("ssh", result.Entities.Categories);
        Assert.Equal(Severity.High, result.Entities.SeverityFilter);
        Assert.Equal(TimeSpan.FromDays(7), result.Entities.TimeWindow);
        Assert.Equal(AgentIntent.FixFinding, result.Entities.RemediationVerb);
    }

    [Fact]
    public void Parse_PopulatesEntityFrameWithSessionId()
    {
        var result = _parser.Parse("verify session abc12345");

        Assert.Equal("abc12345", result.Entities.SessionId);
        Assert.Equal(AgentIntent.VerifyRemediation, result.Entities.RemediationVerb);
    }

    [Fact]
    public void Parse_PopulatesEntityFrameWithOrdinal()
    {
        var result = _parser.Parse("explain the third one");

        Assert.Equal(3, result.Entities.OrdinalReference);
    }

    [Fact]
    public void Parse_EntityFrameEmptyForUnknownQuery()
    {
        var result = _parser.Parse("tell me a joke");

        Assert.False(result.Entities.HasEntities);
    }

    [Fact]
    public void Parse_CategorySuggestionQueries_RoundTripToExpectedIntent()
    {
        // Every chip query produced by IntentCategoryMap.GetSuggestionQuery must parse back to the
        // category's own audit intent, otherwise the blind-spot chip triggers the wrong (or no) audit.
        foreach (var category in IntentCategoryMap.AllCategories)
        {
            var expected = IntentCategoryMap.GetIntent(category!)!.Value;
            var query = IntentCategoryMap.GetSuggestionQuery(category!);

            var parsed = _parser.Parse(query);

            Assert.True(parsed.Intent == expected,
                $"chip query '{query}' for category '{category}' parsed to {parsed.Intent}, expected {expected}");
        }
    }

    [Fact]
    public void Parse_CheckSsh_IsNotAmbiguous()
    {
        // The SSH chip uses "check ssh config" (not "check ssh") so it outranks the PortCheck "ss"
        // substring match inside "ssh" and resolves unambiguously to SshCheck.
        var parsed = _parser.Parse(IntentCategoryMap.GetSuggestionQuery("SSH"));

        Assert.Equal(AgentIntent.SshCheck, parsed.Intent);
        Assert.False(parsed.IsAmbiguous);
    }

    [Fact]
    public void Parse_ShowMeTheEvidence_RoutesToShowEvidenceNotFilterCategory()
    {
        // Regression: "show me" (FilterCategory, w3) and "evidence" (ShowEvidence, w3) used to tie,
        // and last-wins scoring handed the win to FilterCategory. ShowEvidence must now win.
        var parsed = _parser.Parse("show me the evidence");

        Assert.Equal(AgentIntent.ShowEvidence, parsed.Intent);
    }

    [Fact]
    public void Parse_WhatTriggeredTheAudit_DoesNotResolveAuditAsCategoryTarget()
    {
        // "audit" is a meta-word about the process, not a finding category; it must not be extracted
        // as the target (which previously mis-resolved to an arbitrary finding mentioning "audit").
        var parsed = _parser.Parse("what triggered the audit");

        Assert.Equal(AgentIntent.ShowEvidence, parsed.Intent);
        Assert.True(string.IsNullOrEmpty(parsed.TargetReference));
    }
}
