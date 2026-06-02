using System.Collections.ObjectModel;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class RemediationSessionIntegrationTests
{
    [Fact]
    public async Task FullSessionFlow_Create_UpdateSteps_Verify_Export()
    {
        var state = new AgentAuditState();
        var store = new InMemorySessionStore();
        var finding = CreateRemediableFinding("FW-001");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", finding) });

        var afterResult = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = Array.Empty<Finding>() };
        var service = CreateService(state, store, (intent, _, _) => Task.FromResult(afterResult));

        var messages = new ObservableCollection<AgentMessageViewModel>();
        var categories = new ObservableCollection<string>();
        SeverityFilterOption? severityFilter = null;
        string? categoryFilter = null;
        var presenter = new AgentResultPresenter(
            messages, categories,
            () => severityFilter, () => categoryFilter,
            _ => { }, _ => { });

        var createResult = await service.CreateSessionAsync("FW-001", CancellationToken.None);
        Assert.Equal(AgentIntent.StartRemediation, createResult.Intent);
        Assert.NotNull(createResult.RemediationSession);

        var session = createResult.RemediationSession!;
        Assert.Equal(RemediationSessionStatus.Active, session.Status);
        Assert.NotNull(session.BeforeSnapshot);
        Assert.NotEmpty(session.StepStates);
        Assert.Equal(RemediationStepState.Pending, session.StepStates["FW-001"]);

        presenter.PresentFindings(createResult, showCapabilityReport: false, showPassedCount: false, showWarnings: false);
        var sessionMsg = Assert.Single(messages);
        Assert.Equal(session.SessionId, sessionMsg.SessionId);
        Assert.Equal(RemediationSessionStatus.Active, sessionMsg.SessionStatus);
        Assert.True(sessionMsg.HasActiveSession);
        Assert.True(sessionMsg.HasRemediationSection);
        Assert.NotNull(sessionMsg.RemediationSection);

        var updateResult = service.UpdateStepState(session.SessionId, "FW-001", RemediationStepState.Completed);
        Assert.Equal(RemediationSessionStatus.Completed, updateResult.RemediationSession!.Status);
        Assert.DoesNotContain(RemediationStepState.Pending, updateResult.RemediationSession.StepStates.Values);

        messages.Clear();
        var verifyResult = await service.RunVerificationAsync(session.SessionId, CancellationToken.None);
        Assert.Equal(AgentIntent.VerifyRemediation, verifyResult.Intent);
        Assert.NotNull(verifyResult.RemediationSession);
        Assert.Equal(RemediationSessionStatus.Verified, verifyResult.RemediationSession.Status);
        Assert.NotNull(verifyResult.RemediationSession.VerificationResult);
        Assert.NotEmpty(verifyResult.RemediationSession.VerificationResult.FixedFindings);

        presenter.PresentFindings(verifyResult, showCapabilityReport: false, showPassedCount: false, showWarnings: false);
        var verifyMsg = Assert.Single(messages);
        Assert.Equal(session.SessionId, verifyMsg.SessionId);
        Assert.Equal(RemediationSessionStatus.Verified, verifyMsg.SessionStatus);
        Assert.True(verifyMsg.IsVerificationResult);
        Assert.False(verifyMsg.HasActiveSession);

        var formatter = new RemediationMarkdownFormatter();
        var markdown = formatter.FormatSession(verifyResult.RemediationSession);
        Assert.Contains("# VulcansTrace Remediation Session Report", markdown);
        Assert.Contains(session.SessionId, markdown);
        Assert.Contains("**Status:** Verified", markdown);
        Assert.Contains("## Before Snapshot", markdown);
        Assert.Contains("[FW-001] [High] Default policy is ACCEPT", markdown);
        Assert.Contains("## Verification Result", markdown);
        Assert.Contains("### Fixed", markdown);
        Assert.Contains("✓ [FW-001]", markdown);
        Assert.Contains("## Remediation Plan", markdown);
    }

    [Fact]
    public async Task SessionWithBlockedSteps_ShowsBlockedInPresenterAndExport()
    {
        var state = new AgentAuditState();
        var store = new InMemorySessionStore();
        var finding = CreateRiskyFindingWithoutRollback("FW-DANGER");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-DANGER", finding) });

        var service = CreateService(state, store);

        var messages = new ObservableCollection<AgentMessageViewModel>();
        var categories = new ObservableCollection<string>();
        var presenter = new AgentResultPresenter(
            messages, categories,
            () => null, () => null,
            _ => { }, _ => { });

        var createResult = await service.CreateSessionAsync("FW-DANGER", CancellationToken.None);
        Assert.NotEmpty(createResult.Warnings);

        presenter.PresentFindings(createResult, showCapabilityReport: false, showPassedCount: false, showWarnings: false);
        var msg = Assert.Single(messages);
        Assert.Equal(RemediationSessionStatus.Blocked, msg.SessionStatus);
        Assert.False(msg.HasActiveSession);
        Assert.False(msg.HasRemediationSection);

        var formatter = new RemediationMarkdownFormatter();
        var markdown = formatter.FormatSession(createResult.RemediationSession!);
        Assert.Contains("## Blocked Steps", markdown);
        Assert.Contains("FW-DANGER", markdown);
    }

    [Fact]
    public void JsonFileSessionStore_RoundTripsTimeline()
    {
        var tempPath = Path.GetTempFileName();
        try
        {
            var store = new JsonFileSessionStore(tempPath);
            var session = new RemediationSession
            {
                SessionId = "roundtrip1",
                SourceFindings = Array.Empty<Finding>(),
                RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
                StepStates = new Dictionary<string, RemediationStepState> { ["FW-001"] = RemediationStepState.Completed },
                BlockedReasons = Array.Empty<string>(),
                Timeline = new[]
                {
                    new RemediationSessionEvent
                    {
                        TimestampUtc = new DateTime(2026, 6, 2, 10, 0, 0, DateTimeKind.Utc),
                        Type = RemediationSessionEventType.Created,
                        Title = "Session started"
                    },
                    new RemediationSessionEvent
                    {
                        TimestampUtc = new DateTime(2026, 6, 2, 10, 5, 0, DateTimeKind.Utc),
                        Type = RemediationSessionEventType.StepMarkedCompleted,
                        Title = "FW-001 marked completed",
                        RuleId = "FW-001"
                    }
                }
            };

            store.Save(session);
            var loaded = store.Load("roundtrip1");

            Assert.NotNull(loaded);
            Assert.Equal(2, loaded.Timeline.Count);
            Assert.Equal(RemediationSessionEventType.Created, loaded.Timeline[0].Type);
            Assert.Equal("Session started", loaded.Timeline[0].Title);
            Assert.Equal(new DateTime(2026, 6, 2, 10, 0, 0, DateTimeKind.Utc), loaded.Timeline[0].TimestampUtc);
            Assert.Equal(DateTimeKind.Utc, loaded.Timeline[0].TimestampUtc.Kind);
            Assert.Equal(RemediationSessionEventType.StepMarkedCompleted, loaded.Timeline[1].Type);
            Assert.Equal("FW-001", loaded.Timeline[1].RuleId);
            Assert.Equal(new DateTime(2026, 6, 2, 10, 5, 0, DateTimeKind.Utc), loaded.Timeline[1].TimestampUtc);
            Assert.Equal(DateTimeKind.Utc, loaded.Timeline[1].TimestampUtc.Kind);
        }
        finally
        {
            File.Delete(tempPath);
        }
    }

    private static GuidedRemediationService CreateService(
        AgentAuditState state,
        InMemorySessionStore store,
        Func<AgentIntent, string?, CancellationToken, Task<AgentResult>>? runAudit = null)
    {
        var planBuilder = new RemediationPlanBuilder(new ExplanationProvider());
        return new GuidedRemediationService(state, planBuilder, store, runAudit);
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
}
