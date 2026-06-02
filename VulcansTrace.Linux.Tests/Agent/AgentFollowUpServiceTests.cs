using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class AgentFollowUpServiceTests
{
    [Fact]
    public async Task ShowChangesAsync_SkipsCurrentHistoryEntryAndComparesPreviousAudit()
    {
        var state = new AgentAuditState();
        var currentFinding = CreateFinding("FW-002", "0.0.0.0/0", Severity.Critical);
        var currentTimestamp = new DateTime(2026, 1, 2, 0, 0, 0, DateTimeKind.Utc);
        var currentResult = new AgentResult
        {
            Intent = AgentIntent.FirewallCheck,
            UtcTimestamp = currentTimestamp,
            AgentFindings = new[] { currentFinding }
        };
        state.RememberAudit(currentResult, AgentIntent.FirewallCheck, new[] { ("FW-002", currentFinding) });

        var historyStore = new InMemoryAuditHistoryStore();
        historyStore.Append(ToHistoryEntry("current", currentTimestamp, AgentIntent.FirewallCheck, currentFinding));
        historyStore.Append(new AuditHistoryEntry
        {
            SnapshotId = "previous",
            TimestampUtc = currentTimestamp.AddDays(-1),
            Intent = AgentIntent.FirewallCheck,
            SnapshotFindings = Array.Empty<AuditSnapshotFinding>()
        });
        var service = CreateService(state, historyStore: historyStore);

        var result = await service.HandleFollowUpAsync(new AgentQuery(AgentIntent.ShowChanges), CancellationToken.None);

        Assert.Equal(AgentIntent.ShowChanges, result.Intent);
        Assert.NotNull(result.AuditDiff);
        Assert.Single(result.AuditDiff.NewFindings);
        var finding = Assert.Single(result.AgentFindings);
        Assert.Equal("FW-002", finding.RuleId);
        Assert.Equal("Change", finding.Category);
    }

    [Fact]
    public async Task FilterCategoryAsync_NoPreviousResult_RunsFallbackAuditAndRestoresState()
    {
        var state = new AgentAuditState();
        var fallbackFinding = CreateFinding("SSH-001", "sshd_config", Severity.High) with { Category = "SSH" };
        var fallbackResult = new AgentResult
        {
            Intent = AgentIntent.SshCheck,
            AgentFindings = new[] { fallbackFinding }
        };
        var calls = new List<AgentIntent>();
        var service = CreateService(
            state,
            runAudit: (intent, _, _) =>
            {
                calls.Add(intent);
                return Task.FromResult(fallbackResult);
            });

        var result = await service.HandleFollowUpAsync(new AgentQuery(AgentIntent.FilterCategory, "ssh"), CancellationToken.None);

        Assert.Equal(AgentIntent.FilterCategory, result.Intent);
        Assert.Same(fallbackFinding, result.AgentFindings[0]);
        Assert.Equal(AgentIntent.SshCheck, Assert.Single(calls));
        Assert.Null(state.LastResult);
    }

    [Fact]
    public async Task ListSuppressedAsync_ReportsSuppressedRuleResults()
    {
        var state = new AgentAuditState();
        var suppressed = RuleResult.Fail("FW-001", "Firewall", "FW-001", "Allow-all firewall rule", Severity.High, "0.0.0.0/0")
            with { Status = RuleStatus.Suppressed };
        var result = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            RuleResults = new[] { suppressed }
        };
        state.RememberAudit(result, AgentIntent.FullAudit, Array.Empty<(string, Finding)>());
        var suppressionStore = new InMemorySuppressionStore();
        suppressionStore.Add(new SuppressionEntry { RuleId = "FW-001", Target = "0.0.0.0/0" });
        var service = CreateService(state, suppressionStore: suppressionStore);

        var followUp = await service.HandleFollowUpAsync(new AgentQuery(AgentIntent.ListSuppressed), CancellationToken.None);

        Assert.Equal(AgentIntent.ListSuppressed, followUp.Intent);
        Assert.Contains("Suppressed Findings (1)", followUp.Summary);
        Assert.Contains("[FW-001]", followUp.Summary);
        Assert.Contains("Total active suppressions in store: 1", followUp.Summary);
    }

    [Fact]
    public async Task RiskScoreAsync_ReturnsLastRiskScorecard()
    {
        var state = new AgentAuditState();
        var finding = CreateFinding("TEST-001", "target", Severity.High);
        var risk = new RiskScorecard
        {
            NumericScore = 72.5,
            LetterGrade = "C",
            SummaryStatus = "Elevated",
            TotalFindings = 1
        };
        var result = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            AgentFindings = new[] { finding },
            Warnings = new[] { "warning" },
            RiskScorecard = risk
        };
        state.RememberAudit(result, AgentIntent.FullAudit, new[] { ("TEST-001", finding) });
        var service = CreateService(state);

        var followUp = await service.HandleFollowUpAsync(new AgentQuery(AgentIntent.RiskScore), CancellationToken.None);

        Assert.Equal(AgentIntent.RiskScore, followUp.Intent);
        Assert.Same(risk, followUp.RiskScorecard);
        Assert.Same(finding, followUp.AgentFindings[0]);
        Assert.Equal("warning", Assert.Single(followUp.Warnings));
        Assert.Contains("Risk Grade: C", followUp.Summary);
    }

    [Fact]
    public async Task FixFinding_NoLastResult_ReturnsGuidanceMessage()
    {
        var state = new AgentAuditState();
        var service = CreateService(state);

        var result = await service.HandleFollowUpAsync(
            new AgentQuery(AgentIntent.FixFinding, "FW-001"),
            CancellationToken.None);

        Assert.Equal(AgentIntent.FixFinding, result.Intent);
        Assert.Contains("Run an audit first", result.Summary);
        Assert.Empty(result.AgentFindings);
    }

    [Fact]
    public async Task FixFinding_NoTargetReference_ReturnsPromptMessage()
    {
        var state = new AgentAuditState();
        var finding = CreateFinding("FW-001", "0.0.0.0/0", Severity.High);
        var audit = new AgentResult
        {
            Intent = AgentIntent.FirewallCheck,
            AgentFindings = new[] { finding }
        };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", finding) });
        var service = CreateService(state);

        var result = await service.HandleFollowUpAsync(
            new AgentQuery(AgentIntent.FixFinding),
            CancellationToken.None);

        Assert.Equal(AgentIntent.FixFinding, result.Intent);
        Assert.Contains("Please specify which finding to fix", result.Summary);
        Assert.Empty(result.AgentFindings);
    }

    [Fact]
    public async Task FixFinding_UnknownReference_ReturnsNotFoundMessage()
    {
        var state = new AgentAuditState();
        var finding = CreateFinding("FW-001", "0.0.0.0/0", Severity.High);
        var audit = new AgentResult
        {
            Intent = AgentIntent.FirewallCheck,
            AgentFindings = new[] { finding }
        };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", finding) });
        var service = CreateService(state);

        var result = await service.HandleFollowUpAsync(
            new AgentQuery(AgentIntent.FixFinding, "NONEXISTENT-999"),
            CancellationToken.None);

        Assert.Equal(AgentIntent.FixFinding, result.Intent);
        Assert.Contains("couldn't find finding **NONEXISTENT-999**", result.Summary);
        Assert.Empty(result.AgentFindings);
    }

    [Fact]
    public async Task FixFinding_ValidReference_ReturnsInteractiveRemediationPlan()
    {
        var state = new AgentAuditState();
        var finding = CreateRemediableFinding("FW-001");
        var audit = new AgentResult
        {
            Intent = AgentIntent.FirewallCheck,
            AgentFindings = new[] { finding }
        };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", finding) });
        var service = CreateService(state, explanationProvider: new ExplanationProvider());

        var result = await service.HandleFollowUpAsync(
            new AgentQuery(AgentIntent.FixFinding, "FW-001"),
            CancellationToken.None);

        Assert.Equal(AgentIntent.FixFinding, result.Intent);
        Assert.Contains("Interactive Remediation: FW-001", result.Summary);
        Assert.NotNull(result.RemediationPlan);
        Assert.Single(result.RemediationPlan.Sections);
        var matched = Assert.Single(result.AgentFindings);
        Assert.Equal("FW-001", matched.RuleId);
    }

    [Fact]
    public async Task FixFinding_ValidationFails_ReturnsSafetyBlockMessage()
    {
        var state = new AgentAuditState();
        var finding = CreateRiskyFindingWithoutRollback("FW-DANGER");
        var audit = new AgentResult
        {
            Intent = AgentIntent.FirewallCheck,
            AgentFindings = new[] { finding }
        };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-DANGER", finding) });
        var service = CreateService(state, explanationProvider: new ExplanationProvider());

        var result = await service.HandleFollowUpAsync(
            new AgentQuery(AgentIntent.FixFinding, "FW-DANGER"),
            CancellationToken.None);

        Assert.Equal(AgentIntent.FixFinding, result.Intent);
        Assert.Contains("Cannot guide remediation", result.Summary);
        Assert.Contains("safety", result.Summary);
        Assert.NotEmpty(result.Warnings);
        Assert.NotNull(result.RemediationPlan);
    }

    [Fact]
    public async Task PrioritizeRemediation_NoLastResult_ReturnsGuidanceMessage()
    {
        var state = new AgentAuditState();
        var service = CreateService(state);

        var result = await service.HandleFollowUpAsync(
            new AgentQuery(AgentIntent.PrioritizeRemediation),
            CancellationToken.None);

        Assert.Equal(AgentIntent.PrioritizeRemediation, result.Intent);
        Assert.Contains("Run an audit first", result.Summary);
        Assert.Empty(result.AgentFindings);
    }

    [Fact]
    public async Task PrioritizeRemediation_NoFindings_ReturnsEmptyMessage()
    {
        var state = new AgentAuditState();
        var audit = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            AgentFindings = Array.Empty<Finding>()
        };
        state.RememberAudit(audit, AgentIntent.FullAudit, Array.Empty<(string, Finding)>());
        var service = CreateService(state);

        var result = await service.HandleFollowUpAsync(
            new AgentQuery(AgentIntent.PrioritizeRemediation),
            CancellationToken.None);

        Assert.Equal(AgentIntent.PrioritizeRemediation, result.Intent);
        Assert.Contains("No active findings", result.Summary);
    }

    [Fact]
    public async Task PrioritizeRemediation_WithFindings_ReturnsSortedPlan()
    {
        var state = new AgentAuditState();
        var highFinding = CreateFinding("SSH-001", "sshd_config", Severity.High);
        var criticalFinding = CreateFinding("FW-001", "0.0.0.0/0", Severity.Critical);
        var audit = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            AgentFindings = new[] { highFinding, criticalFinding }
        };
        state.RememberAudit(audit, AgentIntent.FullAudit, new[] { ("SSH-001", highFinding), ("FW-001", criticalFinding) });
        var service = CreateService(state, explanationProvider: new ExplanationProvider());

        var result = await service.HandleFollowUpAsync(
            new AgentQuery(AgentIntent.PrioritizeRemediation),
            CancellationToken.None);

        Assert.Equal(AgentIntent.PrioritizeRemediation, result.Intent);
        Assert.Contains("Remediation Plan", result.Summary);
        Assert.NotNull(result.RemediationPlan);
        Assert.Equal(2, result.RemediationPlan.Sections.Count);
        Assert.Contains("[Critical]", result.RemediationPlan.Sections[0].FindingSummary);
        Assert.Contains("[High]", result.RemediationPlan.Sections[1].FindingSummary);
    }

    [Fact]
    public async Task ExplainCritical_NoLastResult_ReturnsGuidanceMessage()
    {
        var state = new AgentAuditState();
        var service = CreateService(state);

        var result = await service.HandleFollowUpAsync(
            new AgentQuery(AgentIntent.ExplainCritical),
            CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainCritical, result.Intent);
        Assert.Contains("Run an audit first", result.Summary);
        Assert.Empty(result.AgentFindings);
    }

    [Fact]
    public async Task ExplainCritical_NoHighOrCritical_ReturnsAllClearMessage()
    {
        var state = new AgentAuditState();
        var lowFinding = CreateFinding("LOW-001", "target", Severity.Low);
        var audit = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            AgentFindings = new[] { lowFinding }
        };
        state.RememberAudit(audit, AgentIntent.FullAudit, new[] { ("LOW-001", lowFinding) });
        var service = CreateService(state);

        var result = await service.HandleFollowUpAsync(
            new AgentQuery(AgentIntent.ExplainCritical),
            CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainCritical, result.Intent);
        Assert.Contains("No Critical or High", result.Summary);
        Assert.Empty(result.AgentFindings);
    }

    [Fact]
    public async Task ExplainCritical_WithHighFindings_ReturnsExplanationSummary()
    {
        var state = new AgentAuditState();
        var highFinding = CreateFinding("FW-001", "0.0.0.0/0", Severity.High);
        var audit = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            AgentFindings = new[] { highFinding }
        };
        state.RememberAudit(audit, AgentIntent.FullAudit, new[] { ("FW-001", highFinding) });
        var service = CreateService(state);

        var result = await service.HandleFollowUpAsync(
            new AgentQuery(AgentIntent.ExplainCritical),
            CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainCritical, result.Intent);
        Assert.Contains("Critical / High Findings (1)", result.Summary);
        Assert.Contains("[FW-001]", result.Summary);
        var returned = Assert.Single(result.AgentFindings);
        Assert.Equal("FW-001", returned.RuleId);
    }

    private static AgentFollowUpService CreateService(
        AgentAuditState state,
        IAuditHistoryStore? historyStore = null,
        ISuppressionStore? suppressionStore = null,
        Func<AgentIntent, string?, CancellationToken, Task<AgentResult>>? runAudit = null,
        IExplanationProvider? explanationProvider = null)
    {
        return new AgentFollowUpService(
            state,
            explanationProvider ?? new TestExplanationProvider(),
            historyStore,
            suppressionStore,
            runAudit ?? RunAuditShouldNotBeCalled);
    }

    private static Task<AgentResult> RunAuditShouldNotBeCalled(AgentIntent intent, string? rawLog, CancellationToken ct)
    {
        throw new InvalidOperationException("RunAudit should not be called by this test.");
    }

    private static Finding CreateRemediableFinding(string ruleId)
    {
        var now = DateTime.UtcNow;
        return new Finding
        {
            RuleId = ruleId,
            Category = "Firewall",
            Severity = Severity.High,
            SourceHost = "localhost",
            Target = "INPUT",
            ShortDescription = "Default policy is ACCEPT",
            Details = """
                      **What was found:** Default policy is ACCEPT.
                      **Why this matters:** All traffic is allowed.
                      **Suggested next action:**
                      1. Change policy: `echo safe-command`
                      **Rollback commands:**
                      1. Restore: `echo rollback-command`
                      **How to verify:**
                      1. Check: `echo verify-command`
                      """,
            TimeRangeStart = now,
            TimeRangeEnd = now
        };
    }

    private static Finding CreateRiskyFindingWithoutRollback(string ruleId)
    {
        var now = DateTime.UtcNow;
        return new Finding
        {
            RuleId = ruleId,
            Category = "Firewall",
            Severity = Severity.Critical,
            SourceHost = "localhost",
            Target = "INPUT",
            ShortDescription = "Dangerous firewall config",
            Details = """
                      **What was found:** Dangerous config detected.
                      **Why this matters:** System is exposed.
                      **Suggested next action:**
                      1. Change policy: `sudo iptables -P INPUT DROP`
                      """,
            TimeRangeStart = now,
            TimeRangeEnd = now
        };
    }

    private static AuditHistoryEntry ToHistoryEntry(string id, DateTime timestamp, AgentIntent intent, Finding finding)
    {
        return new AuditHistoryEntry
        {
            SnapshotId = id,
            TimestampUtc = timestamp,
            Intent = intent,
            TotalFindings = 1,
            SnapshotFindings = new[]
            {
                new AuditSnapshotFinding
                {
                    RuleId = finding.RuleId!,
                    Target = finding.Target,
                    Severity = finding.Severity.ToString(),
                    ShortDescription = finding.ShortDescription,
                    Category = finding.Category,
                    Fingerprint = finding.Fingerprint
                }
            }
        };
    }

    private static Finding CreateFinding(string ruleId, string target, Severity severity)
    {
        var now = DateTime.UtcNow;
        return new Finding
        {
            RuleId = ruleId,
            Category = "Test",
            Severity = severity,
            SourceHost = "localhost",
            Target = target,
            ShortDescription = $"{ruleId} finding",
            Details = "Details",
            TimeRangeStart = now,
            TimeRangeEnd = now
        };
    }

    private sealed class TestExplanationProvider : IExplanationProvider
    {
        public string GetExplanation(string key, IReadOnlyDictionary<string, string> variables)
        {
            return $"explanation:{key}";
        }

        public StructuredExplanation GetStructuredExplanation(string key, IReadOnlyDictionary<string, string> variables)
        {
            return new StructuredExplanation { WhatWasFound = GetExplanation(key, variables) };
        }

        public StructuredExplanation ParseStructuredFromText(string text)
        {
            return new StructuredExplanation { WhyItMatters = text, WhatWasFound = text };
        }
    }
}
