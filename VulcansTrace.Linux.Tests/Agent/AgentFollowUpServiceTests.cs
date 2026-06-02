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

    private static AgentFollowUpService CreateService(
        AgentAuditState state,
        IAuditHistoryStore? historyStore = null,
        ISuppressionStore? suppressionStore = null,
        Func<AgentIntent, string?, CancellationToken, Task<AgentResult>>? runAudit = null)
    {
        return new AgentFollowUpService(
            state,
            new TestExplanationProvider(),
            historyStore,
            suppressionStore,
            runAudit ?? RunAuditShouldNotBeCalled);
    }

    private static Task<AgentResult> RunAuditShouldNotBeCalled(AgentIntent intent, string? rawLog, CancellationToken ct)
    {
        throw new InvalidOperationException("RunAudit should not be called by this test.");
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
