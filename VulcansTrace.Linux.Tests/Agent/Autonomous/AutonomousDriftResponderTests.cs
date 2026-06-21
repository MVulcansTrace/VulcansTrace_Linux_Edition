using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Autonomous;
using VulcansTrace.Linux.Agent.Baselines;
using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Notifications;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Scheduling;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Security;

namespace VulcansTrace.Linux.Tests.Agent.Autonomous;

public class AutonomousDriftResponderTests
{
    private static readonly byte[] TestKey = Convert.FromHexString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    [Fact]
    public async Task RespondToDriftAsync_DisabledSchedule_DoesNothing()
    {
        var agent = new FakeAgent();
        var store = new InMemoryBaselineStore();
        var notifier = new FakeNotificationService();
        var responder = CreateResponder(agent, store, notifier, _ => TestKey);

        var schedule = CreateSchedule(autonomousDriftResponse: false);
        var result = await responder.RespondToDriftAsync(schedule);

        Assert.False(result);
        Assert.Null(notifier.LastAlert);
        Assert.False(agent.CheckDriftCalled);
    }

    [Fact]
    public async Task RespondToDriftAsync_NoBaselineStore_DoesNothing()
    {
        var agent = new FakeAgent();
        var notifier = new FakeNotificationService();
        var responder = CreateResponder(agent, baselineStore: null, notifier, _ => TestKey);

        var schedule = CreateSchedule(autonomousDriftResponse: true);
        var result = await responder.RespondToDriftAsync(schedule);

        Assert.False(result);
        Assert.Null(notifier.LastAlert);
    }

    [Fact]
    public async Task RespondToDriftAsync_NoDrift_DoesNothing()
    {
        var agent = new FakeAgent();
        var store = new InMemoryBaselineStore();
        var notifier = new FakeNotificationService();
        var responder = CreateResponder(agent, store, notifier, _ => TestKey);

        agent.DriftResult = new AgentResult
        {
            Intent = AgentIntent.CheckDrift,
            AgentFindings = Array.Empty<Finding>()
        };

        var schedule = CreateSchedule(autonomousDriftResponse: true, threshold: Severity.High);
        var result = await responder.RespondToDriftAsync(schedule);

        Assert.False(result);
        Assert.Null(notifier.LastAlert);
        Assert.True(agent.CheckDriftCalled);
        Assert.False(agent.RunAuditCalled);
    }

    [Fact]
    public async Task RespondToDriftAsync_DriftBelowThreshold_DoesNothing()
    {
        var agent = new FakeAgent();
        var store = new InMemoryBaselineStore();
        var notifier = new FakeNotificationService();
        var responder = CreateResponder(agent, store, notifier, _ => TestKey);

        agent.DriftResult = new AgentResult
        {
            Intent = AgentIntent.CheckDrift,
            AgentFindings = new[] { CreateFinding("FW-001", "22/tcp", Severity.Medium) }
        };

        var schedule = CreateSchedule(autonomousDriftResponse: true, threshold: Severity.High);
        var result = await responder.RespondToDriftAsync(schedule);

        Assert.False(result);
        Assert.Null(notifier.LastAlert);
    }

    [Fact]
    public async Task RespondToDriftAsync_DriftAtThreshold_SendsSignedAlert()
    {
        var agent = new FakeAgent();
        var store = new InMemoryBaselineStore();
        var notifier = new FakeNotificationService();
        var responder = CreateResponder(agent, store, notifier, _ => TestKey);

        agent.DriftResult = new AgentResult
        {
            Intent = AgentIntent.CheckDrift,
            AgentFindings = new[]
            {
                CreateFinding("FW-002", "0.0.0.0/0", Severity.Critical),
                CreateFinding("FW-003", "3389/tcp", Severity.High)
            }
        };

        agent.FullResult = new AgentResult
        {
            Intent = AgentIntent.FirewallCheck,
            AgentFindings = agent.DriftResult.AgentFindings,
            AttackChains = new[]
            {
                new AttackChain
                {
                    Narrative = "FW-002 exposes the host, then FW-003 allows RDP brute force.",
                    CombinedSeverity = Severity.Critical,
                    RuleIds = new[] { "FW-002", "FW-003" }
                }
            },
            ProactiveAlerts = new[]
            {
                new ProactiveAlert
                {
                    RuleId = "FW-002",
                    CurrentSeverity = Severity.Critical,
                    DaysSinceVerifiedFixed = 7,
                    Guidance = "Check firewall startup scripts that may have rebuilt the policy."
                }
            },
            Narrative = new Narrative { Summary = "The firewall posture has degraded." },
            UtcTimestamp = new DateTime(2026, 6, 20, 12, 0, 0, DateTimeKind.Utc)
        };

        var schedule = CreateSchedule(autonomousDriftResponse: true, threshold: Severity.High);
        var result = await responder.RespondToDriftAsync(schedule);

        Assert.True(result);
        Assert.NotNull(notifier.LastAlert);
        Assert.Equal("Test Schedule", notifier.LastAlert.ScheduleName);
        Assert.Equal(Severity.Critical, notifier.LastAlert.MaxSeverity);
        Assert.Equal(2, notifier.LastAlert.DriftFindingCount);
        Assert.Contains("FW-002", notifier.LastAlert.RuleIds);
        Assert.Contains("FW-003", notifier.LastAlert.RuleIds);
        Assert.Single(notifier.LastAlert.AttackChainNarratives);
        Assert.Single(notifier.LastAlert.ProactiveAlertSummaries);
        Assert.False(string.IsNullOrWhiteSpace(notifier.LastAlert.Signature));
        Assert.NotEqual("UNSIGNED", notifier.LastAlert.Signature);
        Assert.True(agent.RunAuditCalled);
    }

    [Fact]
    public async Task RespondToDriftAsync_AlertSignatureIsVerifiableWithConfiguredKey()
    {
        var agent = new FakeAgent();
        var store = new InMemoryBaselineStore();
        var notifier = new FakeNotificationService();
        var responder = CreateResponder(agent, store, notifier, _ => TestKey);

        agent.DriftResult = new AgentResult
        {
            Intent = AgentIntent.CheckDrift,
            AgentFindings = new[] { CreateFinding("SSH-001", "sshd", Severity.High) }
        };
        agent.FullResult = new AgentResult
        {
            Intent = AgentIntent.SshCheck,
            AgentFindings = agent.DriftResult.AgentFindings,
            UtcTimestamp = new DateTime(2026, 6, 20, 12, 0, 0, DateTimeKind.Utc)
        };

        var schedule = CreateSchedule(autonomousDriftResponse: true, threshold: Severity.High);
        await responder.RespondToDriftAsync(schedule);

        Assert.NotNull(notifier.LastAlert);
        Assert.True(new SignedAlertVerifier().Verify(notifier.LastAlert, TestKey));
    }

    [Fact]
    public async Task RespondToDriftAsync_NoSigningKeyConfigured_SendsUnsignedAlert()
    {
        var agent = new FakeAgent();
        var store = new InMemoryBaselineStore();
        var notifier = new FakeNotificationService();
        var responder = CreateResponder(agent, store, notifier, _ => null);

        agent.DriftResult = new AgentResult
        {
            Intent = AgentIntent.CheckDrift,
            AgentFindings = new[] { CreateFinding("FW-001", "22/tcp", Severity.Critical) }
        };
        agent.FullResult = new AgentResult
        {
            Intent = AgentIntent.FirewallCheck,
            AgentFindings = agent.DriftResult.AgentFindings,
            UtcTimestamp = new DateTime(2026, 6, 20, 12, 0, 0, DateTimeKind.Utc)
        };

        var schedule = CreateSchedule(autonomousDriftResponse: true, threshold: Severity.High);
        var result = await responder.RespondToDriftAsync(schedule);

        Assert.True(result);
        Assert.NotNull(notifier.LastAlert);
        Assert.Equal(SignedAlertVerifier.UnsignedSentinel, notifier.LastAlert.Signature);
        Assert.False(new SignedAlertVerifier().Verify(notifier.LastAlert, TestKey));
    }

    [Fact]
    public async Task RespondToDriftAsync_RequireSignedAlertsAndNoKey_SkipsAlert()
    {
        var agent = new FakeAgent();
        var store = new InMemoryBaselineStore();
        var notifier = new FakeNotificationService();
        var responder = CreateResponder(agent, store, notifier, _ => null);

        agent.DriftResult = new AgentResult
        {
            Intent = AgentIntent.CheckDrift,
            AgentFindings = new[] { CreateFinding("FW-001", "22/tcp", Severity.Critical) }
        };
        agent.FullResult = new AgentResult
        {
            Intent = AgentIntent.FirewallCheck,
            AgentFindings = agent.DriftResult.AgentFindings,
            UtcTimestamp = new DateTime(2026, 6, 20, 12, 0, 0, DateTimeKind.Utc)
        };

        var schedule = CreateSchedule(autonomousDriftResponse: true, threshold: Severity.High) with { RequireSignedAlerts = true };
        var result = await responder.RespondToDriftAsync(schedule);

        // Fail closed: with no signing key, a require-signed schedule sends nothing at all.
        Assert.False(result);
        Assert.Null(notifier.LastAlert);
    }

    [Fact]
    public async Task RespondToDriftAsync_RemediationEnabled_IncludesRemediationSummary()
    {
        var agent = new FakeAgent();
        var store = new InMemoryBaselineStore();
        var notifier = new FakeNotificationService();
        var remediationBuilder = new RemediationPlanBuilder(new ExplanationProvider());
        var responder = CreateResponder(agent, store, notifier, _ => TestKey, remediationBuilder);

        agent.DriftResult = new AgentResult
        {
            Intent = AgentIntent.CheckDrift,
            AgentFindings = new[] { CreateFinding("FW-001", "22/tcp", Severity.Critical) }
        };
        agent.FullResult = new AgentResult
        {
            Intent = AgentIntent.FirewallCheck,
            AgentFindings = agent.DriftResult.AgentFindings,
            UtcTimestamp = new DateTime(2026, 6, 20, 12, 0, 0, DateTimeKind.Utc)
        };

        var schedule = CreateSchedule(autonomousDriftResponse: true, threshold: Severity.High) with
        {
            AllowAutoRemediate = true
        };

        var result = await responder.RespondToDriftAsync(schedule);

        Assert.True(result);
        Assert.NotNull(notifier.LastAlert);
        Assert.False(string.IsNullOrWhiteSpace(notifier.LastAlert.RemediationSummary));
        Assert.Contains("Remediation proposal", notifier.LastAlert.RemediationSummary);
    }

    [Fact]
    public async Task RespondToDriftAsync_RemediationPrefixFilter_ExcludesNonMatchingFindings()
    {
        var agent = new FakeAgent();
        var store = new InMemoryBaselineStore();
        var notifier = new FakeNotificationService();
        var remediationBuilder = new RemediationPlanBuilder(new ExplanationProvider());
        var responder = CreateResponder(agent, store, notifier, _ => TestKey, remediationBuilder);

        agent.DriftResult = new AgentResult
        {
            Intent = AgentIntent.CheckDrift,
            AgentFindings = new[]
            {
                CreateFinding("FW-001", "22/tcp", Severity.Critical),
                CreateFinding("SSH-001", "sshd", Severity.Critical)
            }
        };
        agent.FullResult = new AgentResult
        {
            Intent = AgentIntent.FirewallCheck,
            AgentFindings = agent.DriftResult.AgentFindings,
            UtcTimestamp = new DateTime(2026, 6, 20, 12, 0, 0, DateTimeKind.Utc)
        };

        var schedule = CreateSchedule(autonomousDriftResponse: true, threshold: Severity.High) with
        {
            AllowAutoRemediate = true,
            AllowedRemediationRulePrefixes = new[] { "FW" }
        };

        var result = await responder.RespondToDriftAsync(schedule);

        Assert.True(result);
        Assert.NotNull(notifier.LastAlert);
        Assert.False(string.IsNullOrWhiteSpace(notifier.LastAlert.RemediationSummary));
        Assert.Contains("1 of 2 findings in scope", notifier.LastAlert.RemediationSummary);
    }

    private static AutonomousDriftResponder CreateResponder(
        IAgent agent,
        IBaselineStore? baselineStore,
        INotificationService notificationService,
        Func<string, byte[]?> signingKeyResolver,
        RemediationPlanBuilder? remediationPlanBuilder = null)
    {
        return new AutonomousDriftResponder(
            agent,
            baselineStore,
            notificationService,
            signingKeyResolver,
            remediationPlanBuilder ?? new RemediationPlanBuilder(new ExplanationProvider()));
    }

    private static AuditSchedule CreateSchedule(bool autonomousDriftResponse, Severity threshold = Severity.High)
    {
        return new AuditSchedule
        {
            Id = Guid.NewGuid().ToString("N"),
            Name = "Test Schedule",
            Intent = AgentIntent.FirewallCheck,
            CronExpression = "0 6 * * *",
            MachineRole = MachineRole.Workstation,
            NotificationChannel = NotificationChannel.Desktop,
            AutonomousDriftResponse = autonomousDriftResponse,
            AutonomousDriftSeverityThreshold = threshold
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

    private sealed class FakeAgent : IAgent
    {
        public AgentResult DriftResult { get; set; } = new();
        public AgentResult FullResult { get; set; } = new();
        public bool CheckDriftCalled { get; set; }
        public bool RunAuditCalled { get; set; }

        public Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct) => throw new NotSupportedException();

        public Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
        {
            RunAuditCalled = true;
            return Task.FromResult(FullResult);
        }

        public Task<AgentResult> ExplainFindingAsync(Finding finding, CancellationToken ct) => throw new NotSupportedException();

        public Task<AgentResult> SetBaselineAsync(string name, string? description, CancellationToken ct) => throw new NotSupportedException();

        public Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
        {
            CheckDriftCalled = true;
            return Task.FromResult(DriftResult);
        }

        public Task<AgentResult> GetBaselineAsync(AgentIntent intent, CancellationToken ct) => throw new NotSupportedException();

        public Task<AgentResult> StartRemediationAsync(string findingReference, CancellationToken ct) => throw new NotSupportedException();

        public Task<AgentResult> VerifyRemediationAsync(string sessionId, CancellationToken ct) => throw new NotSupportedException();

        public Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct) => throw new NotSupportedException();

        public Task<AgentResult> ListRemediationSessionsAsync(CancellationToken ct) => throw new NotSupportedException();

        public Task<AgentResult> LoadRemediationSessionAsync(string sessionId, CancellationToken ct) => throw new NotSupportedException();

        public Task<AgentResult> DeleteRemediationSessionAsync(string sessionId, CancellationToken ct) => throw new NotSupportedException();

        public Task<AgentResult> AddSessionNoteAsync(string sessionId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct) => throw new NotSupportedException();

        public Task<AgentResult> AddStepNoteAsync(string sessionId, string ruleId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed class FakeNotificationService : INotificationService
    {
        public SignedAlertMessage? LastAlert { get; private set; }

        public Task NotifyAsync(string title, string message, CancellationToken ct = default) => Task.CompletedTask;

        public Task NotifyCriticalFindingsAsync(string scheduleName, int criticalCount, CancellationToken ct = default) => Task.CompletedTask;

        public Task NotifySignedAlertAsync(SignedAlertMessage alert, CancellationToken ct = default)
        {
            LastAlert = alert;
            return Task.CompletedTask;
        }
    }
}
