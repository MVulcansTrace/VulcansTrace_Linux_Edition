using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class FindingExplanationServiceTests
{
    [Fact]
    public async Task ExplainFindingAsync_BuildsStructuredSummaryFromFindingDetails()
    {
        var service = CreateService(new FailingRule());
        var finding = CreateFinding("FW-001", "0.0.0.0/0", Severity.High);

        var result = await service.ExplainFindingAsync(finding, EmptyHistory(), CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Same(finding, Assert.Single(result.AgentFindings));
        Assert.Contains("[FW-001] FW-001 finding", result.Summary);
        Assert.Contains("What was found", result.Summary);
        Assert.Contains("parsed-found:Details for FW-001", result.Summary);
        Assert.Contains("Why it matters", result.Summary);
        Assert.Contains("parsed-why:Details for FW-001", result.Summary);
        Assert.Contains("How to verify", result.Summary);
        Assert.Contains("Suggested next action", result.Summary);
        Assert.Contains("Confidence:", result.Summary);
        Assert.Empty(result.Warnings);
    }

    [Fact]
    public async Task ExplainFindingAsync_StandardDepth_NoAdaptiveSections()
    {
        var service = CreateService(new FailingRule());
        var finding = CreateFinding("FW-001", "0.0.0.0/0", Severity.High);

        var result = await service.ExplainFindingAsync(finding, EmptyHistory(), CancellationToken.None);

        Assert.DoesNotContain("History", result.Summary);
        Assert.DoesNotContain("Root cause", result.Summary);
        Assert.DoesNotContain("What changed", result.Summary);
    }

    [Fact]
    public async Task ExplainFindingAsync_FamiliarDepth_AddsHistorySection()
    {
        var service = CreateService(new FailingRule());
        var finding = CreateFinding("FW-001", "0.0.0.0/0", Severity.High);
        var history = CreateHistory("FW-001", Severity.High, Severity.High);

        var result = await service.ExplainFindingAsync(finding, history, CancellationToken.None);

        Assert.Contains("History", result.Summary);
        Assert.Contains("[FW-001]", result.Summary);
        Assert.Contains("2 retained audit snapshot(s)", result.Summary);
        Assert.DoesNotContain("Root cause", result.Summary);
        Assert.DoesNotContain("What changed", result.Summary);
    }

    [Fact]
    public async Task ExplainFindingAsync_RecurringDepth_AddsRootCauseSection()
    {
        var service = CreateService(new FailingRule());
        var finding = CreateFinding("FW-001", "0.0.0.0/0", Severity.High);
        var history = CreateHistoryWithCycles("FW-001", Severity.High, closedCycleCount: 2);

        var result = await service.ExplainFindingAsync(finding, history, CancellationToken.None);

        Assert.Contains("History", result.Summary);
        Assert.Contains("Root cause", result.Summary);
        Assert.Contains("firewall keeps reverting", result.Summary);
        Assert.Contains("completed 2 remediation cycle(s)", result.Summary);
        Assert.DoesNotContain("What changed", result.Summary);
    }

    [Fact]
    public async Task ExplainFindingAsync_EscalatingDepth_AddsSeverityTimeline()
    {
        var service = CreateService(new FailingRule());
        var finding = CreateFinding("FW-001", "0.0.0.0/0", Severity.High);
        var history = CreateHistory("FW-001", Severity.Medium, Severity.High);

        var result = await service.ExplainFindingAsync(finding, history, CancellationToken.None);

        Assert.Contains("History", result.Summary);
        Assert.Contains("What changed", result.Summary);
        Assert.Contains("**[FW-001]** severity escalated from Medium to High", result.Summary);
        Assert.DoesNotContain("Root cause", result.Summary);
        Assert.DoesNotContain("completed 0 remediation cycle(s)", result.Summary);
    }

    [Fact]
    public async Task ExplainFindingAsync_EscalatingAndRecurring_AddsRootCauseToo()
    {
        var service = CreateService(new FailingRule());
        var finding = CreateFinding("FW-001", "0.0.0.0/0", Severity.High);
        var history = CreateHistoryWithCycles("FW-001", Severity.Medium, Severity.High, closedCycleCount: 2);

        var result = await service.ExplainFindingAsync(finding, history, CancellationToken.None);

        Assert.Contains("History", result.Summary);
        Assert.Contains("What changed", result.Summary);
        Assert.Contains("Root cause", result.Summary);
        Assert.Contains("firewall keeps reverting", result.Summary);
    }

    [Fact]
    public async Task ExplainFindingAsync_EscalatingDepth_WithStaleSnapshot_ReferencesAgainstNow()
    {
        var service = CreateService(new FailingRule());
        var finding = CreateFinding("FW-001", "0.0.0.0/0", Severity.High);
        var history = CreateHistoryWithStaleCurrent("FW-001", Severity.Medium, Severity.High, currentDaysAgo: 5);

        var result = await service.ExplainFindingAsync(finding, history, CancellationToken.None);

        Assert.Contains("What changed", result.Summary);
        Assert.Contains("**[FW-001]** severity escalated from Medium to High (previous 1 week ago, latest 5 days ago).", result.Summary);
    }

    [Fact]
    public async Task ExplainFindingAsync_EscalatingDepth_VerifiedFixShownWithoutClosedCycles()
    {
        var service = CreateService(new FailingRule());
        var finding = CreateFinding("FW-001", "0.0.0.0/0", Severity.High);
        var history = CreateHistoryWithVerifiedFix("FW-001", Severity.Medium, Severity.High, verifiedFixedDaysAgo: 2);

        var result = await service.ExplainFindingAsync(finding, history, CancellationToken.None);

        // The last-verified-fixed timestamp surfaces even when no remediation
        // cycle has closed yet (verified fixed but not yet returned).
        Assert.Contains("last verified fixed", result.Summary);
        Assert.DoesNotContain("remediation cycle(s)", result.Summary);
    }

    [Fact]
    public async Task ExplainFindingAsync_RecurringDepth_CountsOnlyClosedCycles()
    {
        var service = CreateService(new FailingRule());
        var finding = CreateFinding("FW-001", "0.0.0.0/0", Severity.High);
        var history = CreateHistoryWithCycles("FW-001", Severity.High, closedCycleCount: 2, openCycleCount: 3);

        var result = await service.ExplainFindingAsync(finding, history, CancellationToken.None);

        Assert.Contains("completed 2 remediation cycle(s)", result.Summary);
        Assert.DoesNotContain("completed 5 remediation cycle(s)", result.Summary);
    }

    [Fact]
    public async Task HandleExplainFindingAsync_TargetReferenceMatchesPreviousFindingAndPreservesAuditState()
    {
        var state = new AgentAuditState();
        var previousFinding = CreateFinding("SSH-001", "sshd_config", Severity.High) with
        {
            Category = "SSH",
            ShortDescription = "Weak SSH configuration"
        };
        var previousResult = new AgentResult
        {
            Intent = AgentIntent.SshCheck,
            AgentFindings = new[] { previousFinding }
        };
        state.RememberAudit(previousResult, AgentIntent.SshCheck, new[] { ("SSH-001", previousFinding) });
        var service = CreateService(new FailingRule(), state);

        var result = await service.HandleExplainFindingAsync(new AgentQuery(AgentIntent.ExplainFinding, "weak ssh"), CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Same(previousFinding, Assert.Single(result.AgentFindings));
        Assert.Contains("Weak SSH configuration", result.Summary);
        Assert.Same(previousResult, state.LastResult);
        Assert.Equal(AgentIntent.SshCheck, state.LastAuditIntent);
    }

    [Fact]
    public async Task HandleExplainFindingAsync_TargetReferenceMatchesRuleIdRunsSingleRuleExplanation()
    {
        var state = new AgentAuditState();
        var rule = new FailingRule();
        var service = CreateService(rule, state);

        var result = await service.HandleExplainFindingAsync(new AgentQuery(AgentIntent.ExplainFinding, "TEST-001"), CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Single(result.AgentFindings);
        Assert.Equal("TEST-001", result.AgentFindings[0].RuleId);
        Assert.Equal(1, result.FailedCount);
        Assert.Contains("Explanation for [High] Test failed", result.Summary);
        Assert.Null(state.LastResult);
        Assert.Null(state.FindPreviousFinding("TEST-001"));
    }

    [Fact]
    public async Task HandleExplainFindingAsync_UnknownReferenceReturnsGuidance()
    {
        var service = CreateService(new FailingRule());

        var result = await service.HandleExplainFindingAsync(new AgentQuery(AgentIntent.ExplainFinding, "NOPE-404"), CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Empty(result.AgentFindings);
        Assert.Contains("I don't have a finding matching 'NOPE-404'", result.Summary);
    }

    [Fact]
    public async Task HandleExplainFindingAsync_MissingReferenceReturnsSelectionGuidance()
    {
        var service = CreateService(new FailingRule());

        var result = await service.HandleExplainFindingAsync(new AgentQuery(AgentIntent.ExplainFinding), CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Empty(result.AgentFindings);
        Assert.Contains("Please specify a finding", result.Summary);
        Assert.Contains("select one from the findings list", result.Summary);
    }

    [Fact]
    public async Task HandleExplainFindingAsync_CategoryReference_PrefersFocusedFinding()
    {
        var state = new AgentAuditState();
        var service = CreateService(new FailingRule(), state);
        var first = CreateFinding("SSH-001", "sshd_config", Severity.High) with
        {
            Category = "SSH",
            ShortDescription = "First SSH issue"
        };
        var second = CreateFinding("SSH-002", "sshd_config", Severity.High) with
        {
            Category = "SSH",
            ShortDescription = "Second SSH issue"
        };
        var batch = new AgentResult
        {
            Intent = AgentIntent.SshCheck,
            AgentFindings = new[] { first, second }
        };
        state.RememberAudit(batch, AgentIntent.SshCheck, new[] { ("SSH-001", first), ("SSH-002", second) });
        state.FocusFinding(second, "SSH-002");

        var result = await service.HandleExplainFindingAsync(new AgentQuery(AgentIntent.ExplainFinding, "SSH"), CancellationToken.None);

        Assert.Same(second, Assert.Single(result.AgentFindings));
        Assert.Contains("Second SSH issue", result.Summary);
    }

    private static FindingExplanationService CreateService(IRule rule, AgentAuditState? state = null)
    {
        state ??= new AgentAuditState();
        var explanationProvider = new TestExplanationProvider();
        var scannerCoordinator = new ScannerCoordinator(new[] { new NoopScanner() });
        var ruleEvaluationService = new RuleEvaluationService(new[] { rule }, MachineRole.Server, policyProvider: null);
        var findingAssemblyService = new FindingAssemblyService(explanationProvider, suppressionStore: null);
        var singleRuleExplanationService = new SingleRuleExplanationService(
            scannerCoordinator,
            ruleEvaluationService,
            findingAssemblyService,
            new AgentResultComposer(),
            state,
            MachineRole.Server);

        return new FindingExplanationService(
            state,
            ruleEvaluationService,
            explanationProvider,
            singleRuleExplanationService);
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
            Details = $"Details for {ruleId}",
            TimeRangeStart = now,
            TimeRangeEnd = now
        };
    }

    private static IReadOnlyDictionary<string, RuleMemoryEntry> EmptyHistory() =>
        new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase);

    private static IReadOnlyDictionary<string, RuleMemoryEntry> CreateHistory(
        string ruleId,
        params Severity[] severities)
    {
        var now = DateTime.UtcNow;
        var snapshots = severities
            .Select((severity, index) => new RuleSeveritySnapshot
            {
                UtcTimestamp = now.AddDays(-(severities.Length - 1 - index)),
                Severity = severity
            })
            .ToArray();

        var previous = snapshots[^2].Severity;
        var current = snapshots[^1].Severity;
        var trend = current > previous
            ? RuleStatusTrend.Worsening
            : current < previous
                ? RuleStatusTrend.Improving
                : RuleStatusTrend.Stable;

        return new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            [ruleId] = new RuleMemoryEntry
            {
                RuleId = ruleId,
                Category = "Firewall",
                FirstSeenUtc = snapshots[0].UtcTimestamp,
                LastSeenUtc = snapshots[^1].UtcTimestamp,
                SeverityHistory = snapshots,
                Trend = trend,
                LastSeverity = current
            }
        };
    }

    private static IReadOnlyDictionary<string, RuleMemoryEntry> CreateHistoryWithCycles(
        string ruleId,
        Severity firstSeverity,
        Severity lastSeverity,
        int closedCycleCount,
        int openCycleCount = 0)
    {
        var now = DateTime.UtcNow;
        var cycles = Enumerable.Range(1, closedCycleCount)
            .Select(i => new RemediationCycle
            {
                CycleNumber = i,
                AttemptedUtc = now.AddDays(-30 * (closedCycleCount - i + 1)),
                VerifiedFixedUtc = now.AddDays(-25 * (closedCycleCount - i + 1)),
                ReturnedUtc = now.AddDays(-10 * (closedCycleCount - i + 1))
            })
            .ToList();

        for (var i = 0; i < openCycleCount; i++)
        {
            cycles.Add(new RemediationCycle
            {
                CycleNumber = closedCycleCount + i + 1,
                AttemptedUtc = now.AddDays(-(i + 1))
            });
        }

        var snapshots = new[]
        {
            new RuleSeveritySnapshot { UtcTimestamp = now.AddDays(-10), Severity = firstSeverity },
            new RuleSeveritySnapshot { UtcTimestamp = now, Severity = lastSeverity }
        };

        var previous = snapshots[^2].Severity;
        var current = snapshots[^1].Severity;
        var trend = current > previous
            ? RuleStatusTrend.Worsening
            : current < previous
                ? RuleStatusTrend.Improving
                : RuleStatusTrend.Stable;

        return new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            [ruleId] = new RuleMemoryEntry
            {
                RuleId = ruleId,
                Category = "Firewall",
                FirstSeenUtc = snapshots[0].UtcTimestamp,
                LastSeenUtc = snapshots[^1].UtcTimestamp,
                SeverityHistory = snapshots,
                RemediationCycles = cycles,
                Trend = trend,
                LastSeverity = current
            }
        };
    }

    private static IReadOnlyDictionary<string, RuleMemoryEntry> CreateHistoryWithCycles(
        string ruleId,
        Severity severity,
        int closedCycleCount,
        int openCycleCount = 0) =>
        CreateHistoryWithCycles(ruleId, severity, severity, closedCycleCount, openCycleCount);

    private static IReadOnlyDictionary<string, RuleMemoryEntry> CreateHistoryWithStaleCurrent(
        string ruleId,
        Severity firstSeverity,
        Severity lastSeverity,
        int currentDaysAgo)
    {
        var now = DateTime.UtcNow;
        var snapshots = new[]
        {
            new RuleSeveritySnapshot { UtcTimestamp = now.AddDays(-(currentDaysAgo + 5)), Severity = firstSeverity },
            new RuleSeveritySnapshot { UtcTimestamp = now.AddDays(-currentDaysAgo), Severity = lastSeverity }
        };

        return new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            [ruleId] = new RuleMemoryEntry
            {
                RuleId = ruleId,
                Category = "Firewall",
                FirstSeenUtc = snapshots[0].UtcTimestamp,
                LastSeenUtc = snapshots[^1].UtcTimestamp,
                SeverityHistory = snapshots,
                Trend = RuleStatusTrend.Worsening,
                LastSeverity = lastSeverity
            }
        };
    }

    private static IReadOnlyDictionary<string, RuleMemoryEntry> CreateHistoryWithVerifiedFix(
        string ruleId,
        Severity firstSeverity,
        Severity lastSeverity,
        int verifiedFixedDaysAgo = 2)
    {
        var now = DateTime.UtcNow;
        var snapshots = new[]
        {
            new RuleSeveritySnapshot { UtcTimestamp = now.AddDays(-(verifiedFixedDaysAgo + 5)), Severity = firstSeverity },
            new RuleSeveritySnapshot { UtcTimestamp = now.AddDays(-verifiedFixedDaysAgo), Severity = lastSeverity }
        };

        return new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            [ruleId] = new RuleMemoryEntry
            {
                RuleId = ruleId,
                Category = "Firewall",
                FirstSeenUtc = snapshots[0].UtcTimestamp,
                LastSeenUtc = snapshots[^1].UtcTimestamp,
                SeverityHistory = snapshots,
                LastVerifiedFixedUtc = now.AddDays(-verifiedFixedDaysAgo),
                Trend = RuleStatusTrend.Worsening,
                LastSeverity = lastSeverity
            }
        };
    }

    private sealed class NoopScanner : IScanner
    {
        public string Name => "Noop";

        public Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }

    private sealed class FailingRule : IRule
    {
        public string Id => "TEST-001";
        public string Category => "Test";
        public string Description => "Test failed";
        public string WhatItChecks => "Test";
        public IReadOnlyList<string> SupportedDataSources => Array.Empty<string>();
        public Severity Severity => Severity.High;
        public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();

        public RuleResult Evaluate(ScanData data)
        {
            return RuleResult.Fail(Id, Category, Id, Description, Severity, "test-target");
        }
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
            return new StructuredExplanation
            {
                WhatWasFound = $"parsed-found:{text}",
                WhyItMatters = $"parsed-why:{text}",
                HowToVerify = "parsed-verify",
                SuggestedNextAction = "parsed-action",
                Confidence = "High",
                Caveats = "parsed-caveat"
            };
        }
    }
}
