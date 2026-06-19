using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Dialogue;

public class DialogueManagerTests
{
    private readonly DialogueManager _manager = new();

    [Fact]
    public void Resolve_EmptyContext_ParsesDirectly()
    {
        var context = new DialogueContext();
        var result = _manager.Resolve("check my firewall", context);

        Assert.Equal(AgentIntent.FirewallCheck, result.Intent);
    }

    [Fact]
    public void Resolve_AfterAudit_WhatChangedRemainsShowChanges()
    {
        var context = new DialogueContext();
        context.RememberAudit(
            new AgentResult { Intent = AgentIntent.FullAudit, AgentFindings = Array.Empty<Finding>() },
            AgentIntent.FullAudit,
            Array.Empty<(string, Finding)>());

        var result = _manager.Resolve("what changed since the last audit", context);

        Assert.Equal(AgentIntent.ShowChanges, result.Intent);
    }

    [Fact]
    public void Resolve_AfterExplanation_FixItBecomesFixFinding()
    {
        var context = new DialogueContext();
        var finding = CreateFinding("FW-001", "Firewall");
        context.RememberResult(new AgentResult
        {
            Intent = AgentIntent.ExplainFinding,
            AgentFindings = new[] { finding }
        });
        context.FocusFinding(finding, finding.RuleId);

        var result = _manager.Resolve("how do I fix it", context);

        Assert.Equal(AgentIntent.FixFinding, result.Intent);
        Assert.Equal("FW-001", result.TargetReference);
    }

    [Fact]
    public void Resolve_AmbiguousQuery_MarksAmbiguous()
    {
        var context = new DialogueContext();
        var result = _manager.Resolve("check firewall ports", context);

        Assert.True(result.IsAmbiguous || result.Intent == AgentIntent.Help);
    }

    [Theory]
    [InlineData("check my ssh service", AgentIntent.SshCheck)]
    [InlineData("check suid files", AgentIntent.FilesystemAuditCheck)]
    public void Resolve_SpecificCategoryBeatsGenericAmbiguity(string query, AgentIntent expected)
    {
        var context = new DialogueContext();
        var result = _manager.Resolve(query, context);

        Assert.Equal(expected, result.Intent);
        Assert.False(result.IsAmbiguous);
    }

    [Fact]
    public void PushTurn_RecordsTurn()
    {
        var context = new DialogueContext();
        var query = _manager.Resolve("check my firewall", context);
        _manager.PushTurn(context, "check my firewall", query);

        Assert.Single(context.History);
        Assert.Equal(AgentIntent.FirewallCheck, context.History[0].ResolvedIntent);
    }

    /// <summary>
    /// Regression test for the "check FW-001" intent hijack bug.
    ///
    /// BUG HISTORY (fixed 2026-06):
    /// EntityExtractor.RemediationVerbKeywords contained ["check"] = VerifyRemediation.
    /// When a user typed "check FW-001", EnrichWithEntityFrame (DialogueManager.cs:86-95)
    /// saw the RemediationVerb and overrode Help -> VerifyRemediation, regardless of
    /// conversation context. The user meant "show me FW-001's status" but got shoved
    /// into remediation verification instead.
    ///
    /// WHY THIS TEST EXISTS (and the IntentInferenceEngine version doesn't suffice):
    /// The IntentInferenceEngineTests version skips EnrichWithEntityFrame entirely.
    /// It calls _engine.Infer() directly, so if someone re-adds "check" to
    /// RemediationVerbKeywords, that test still passes. This test calls
    /// DialogueManager.Resolve(), which runs the full pipeline including
    /// EnrichWithEntityFrame — so it catches the regression at the actual source.
    /// </summary>
    [Fact]
    public void Resolve_CheckWithRuleIdDoesNotBecomeVerifyRemediation()
    {
        var context = new DialogueContext();

        // Fresh audit context — NOT remediation. This is a user who just
        // ran an audit and wants to check on a specific finding's status.
        context.RememberResult(new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            AgentFindings = Array.Empty<Finding>()
        });

        // The exact query that triggered the original bug.
        var query = _manager.Resolve("check FW-001", context);

        // The fix: "check" is no longer in RemediationVerbKeywords, so
        // EnrichWithEntityFrame does NOT override Help to VerifyRemediation.
        // If this assertion fails, someone re-added an ambiguous keyword
        // (like "check") to EntityExtractor.RemediationVerbKeywords.
        Assert.NotEqual(AgentIntent.VerifyRemediation, query.Intent);
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
