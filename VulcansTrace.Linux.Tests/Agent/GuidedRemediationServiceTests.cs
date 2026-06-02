using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class GuidedRemediationServiceTests
{
    [Fact]
    public async Task PrioritizeRemediation_NoLastResult_ReturnsGuidanceMessage()
    {
        var state = new AgentAuditState();
        var service = CreateService(state);

        var result = await service.HandlePrioritizeRemediationAsync(CancellationToken.None);

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

        var result = await service.HandlePrioritizeRemediationAsync(CancellationToken.None);

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
        var service = CreateService(state, new ExplanationProvider());

        var result = await service.HandlePrioritizeRemediationAsync(CancellationToken.None);

        Assert.Equal(AgentIntent.PrioritizeRemediation, result.Intent);
        Assert.Contains("Remediation Plan", result.Summary);
        Assert.NotNull(result.RemediationPlan);
        Assert.Equal(2, result.RemediationPlan.Sections.Count);
        Assert.Contains("[Critical]", result.RemediationPlan.Sections[0].FindingSummary);
        Assert.Contains("[High]", result.RemediationPlan.Sections[1].FindingSummary);
    }

    [Fact]
    public async Task FixFinding_NoLastResult_ReturnsGuidanceMessage()
    {
        var state = new AgentAuditState();
        var service = CreateService(state);

        var result = await service.HandleFixFindingAsync(
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

        var result = await service.HandleFixFindingAsync(
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

        var result = await service.HandleFixFindingAsync(
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
        var service = CreateService(state, new ExplanationProvider());

        var result = await service.HandleFixFindingAsync(
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
        var service = CreateService(state, new ExplanationProvider());

        var result = await service.HandleFixFindingAsync(
            new AgentQuery(AgentIntent.FixFinding, "FW-DANGER"),
            CancellationToken.None);

        Assert.Equal(AgentIntent.FixFinding, result.Intent);
        Assert.Contains("Cannot guide remediation", result.Summary);
        Assert.Contains("safety", result.Summary);
        Assert.NotEmpty(result.Warnings);
        Assert.Null(result.RemediationPlan);
    }

    [Fact]
    public async Task FixFinding_PlanContainsExpectedCommandPhases()
    {
        var state = new AgentAuditState();
        var finding = CreateRemediableFinding("FW-001");
        var audit = new AgentResult
        {
            Intent = AgentIntent.FirewallCheck,
            AgentFindings = new[] { finding }
        };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", finding) });
        var service = CreateService(state, new ExplanationProvider());

        var result = await service.HandleFixFindingAsync(
            new AgentQuery(AgentIntent.FixFinding, "FW-001"),
            CancellationToken.None);

        var section = Assert.Single(result.RemediationPlan!.Sections);
        Assert.NotEmpty(section.ApplyCommands);
        Assert.NotEmpty(section.RollbackCommands);
        Assert.NotEmpty(section.VerificationCommands);
    }

    [Fact]
    public async Task CreateSession_NoLastResult_ReturnsGuidanceMessage()
    {
        var state = new AgentAuditState();
        var store = new InMemorySessionStore();
        var service = CreateService(state, sessionStore: store);

        var result = await service.CreateSessionAsync("FW-001", CancellationToken.None);

        Assert.Equal(AgentIntent.StartRemediation, result.Intent);
        Assert.Contains("Run an audit first", result.Summary);
    }

    [Fact]
    public async Task CreateSession_NoReference_ReturnsPromptMessage()
    {
        var state = new AgentAuditState();
        var finding = CreateRemediableFinding("FW-001");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", finding) });
        var store = new InMemorySessionStore();
        var service = CreateService(state, sessionStore: store);

        var result = await service.CreateSessionAsync("", CancellationToken.None);

        Assert.Equal(AgentIntent.StartRemediation, result.Intent);
        Assert.Contains("Please specify", result.Summary);
    }

    [Fact]
    public async Task CreateSession_UnknownReference_ReturnsNotFound()
    {
        var state = new AgentAuditState();
        var finding = CreateRemediableFinding("FW-001");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", finding) });
        var store = new InMemorySessionStore();
        var service = CreateService(state, sessionStore: store);

        var result = await service.CreateSessionAsync("NONEXISTENT", CancellationToken.None);

        Assert.Contains("couldn't find finding", result.Summary);
    }

    [Fact]
    public async Task CreateSession_ValidReference_CapturesBeforeSnapshotAndSavesToStore()
    {
        var state = new AgentAuditState();
        var finding = CreateRemediableFinding("FW-001");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", finding) });
        var store = new InMemorySessionStore();
        var service = CreateService(state, new ExplanationProvider(), sessionStore: store);

        var result = await service.CreateSessionAsync("FW-001", CancellationToken.None);

        Assert.Equal(AgentIntent.StartRemediation, result.Intent);
        Assert.NotNull(result.RemediationPlan);
        Assert.NotEmpty(result.AgentFindings);

        var saved = store.List();
        Assert.Single(saved);
        Assert.NotNull(saved[0].BeforeSnapshot);
        Assert.Equal(AgentIntent.FirewallCheck, saved[0].BeforeSnapshot!.Intent);
        Assert.Single(saved[0].BeforeSnapshot!.Findings);
    }

    [Fact]
    public async Task CreateSession_AddsCreatedEvent()
    {
        var state = new AgentAuditState();
        var finding = CreateRemediableFinding("FW-001");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", finding) });
        var store = new InMemorySessionStore();
        var service = CreateService(state, new ExplanationProvider(), sessionStore: store);

        await service.CreateSessionAsync("FW-001", CancellationToken.None);

        var saved = store.List()[0];
        Assert.Single(saved.Timeline);
        Assert.Equal(RemediationSessionEventType.Created, saved.Timeline[0].Type);
        Assert.Contains("FW-001", saved.Timeline[0].Title);
    }

    [Fact]
    public async Task CreateSession_BlockedStep_AddsStepBlockedEvent()
    {
        var state = new AgentAuditState();
        var finding = CreateRiskyFindingWithoutRollback("FW-DANGER");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-DANGER", finding) });
        var store = new InMemorySessionStore();
        var service = CreateService(state, new ExplanationProvider(), sessionStore: store);

        await service.CreateSessionAsync("FW-DANGER", CancellationToken.None);

        var saved = store.List()[0];
        Assert.Equal(2, saved.Timeline.Count);
        Assert.Equal(RemediationSessionEventType.Created, saved.Timeline[0].Type);
        Assert.Equal(RemediationSessionEventType.StepBlocked, saved.Timeline[1].Type);
        Assert.Equal("FW-DANGER", saved.Timeline[1].RuleId);
    }

    [Fact]
    public async Task CreateSession_BlocksRiskySectionsWithoutRollback()
    {
        var state = new AgentAuditState();
        var finding = CreateRiskyFindingWithoutRollback("FW-DANGER");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-DANGER", finding) });
        var store = new InMemorySessionStore();
        var service = CreateService(state, new ExplanationProvider(), sessionStore: store);

        var result = await service.CreateSessionAsync("FW-DANGER", CancellationToken.None);

        var saved = store.List();
        Assert.Single(saved);
        Assert.Equal(RemediationStepState.Blocked, saved[0].StepStates["FW-DANGER"]);
        Assert.Equal(RemediationSessionStatus.Blocked, saved[0].Status);
        Assert.NotEmpty(saved[0].BlockedReasons);
        Assert.NotEmpty(result.Warnings);
    }

    [Fact]
    public async Task CreateSession_MultipleFindings_AllStepsPending()
    {
        var state = new AgentAuditState();
        var f1 = CreateRemediableFinding("FW-001");
        var f2 = CreateRemediableFinding("FW-002");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { f1, f2 } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", f1), ("FW-002", f2) });
        var store = new InMemorySessionStore();
        var service = CreateService(state, new ExplanationProvider(), sessionStore: store);

        var result = await service.CreateSessionAsync("FW-001", CancellationToken.None);

        var saved = store.List();
        Assert.Single(saved);
        Assert.Equal(RemediationStepState.Pending, saved[0].StepStates["FW-001"]);
    }

    [Fact]
    public async Task UpdateStepState_UpdatesAndPersists()
    {
        var state = new AgentAuditState();
        var finding = CreateRemediableFinding("FW-001");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", finding) });
        var store = new InMemorySessionStore();
        var service = CreateService(state, new ExplanationProvider(), sessionStore: store);

        await service.CreateSessionAsync("FW-001", CancellationToken.None);
        var sessionId = store.List()[0].SessionId;

        var updateResult = service.UpdateStepState(sessionId, "FW-001", RemediationStepState.Completed);

        Assert.Equal(AgentIntent.StartRemediation, updateResult.Intent);
        var updated = store.Load(sessionId);
        Assert.NotNull(updated);
        Assert.Equal(RemediationStepState.Completed, updated.StepStates["FW-001"]);
    }

    [Fact]
    public async Task UpdateStepState_AddsStateChangeEvent()
    {
        var state = new AgentAuditState();
        var finding = CreateRemediableFinding("FW-001");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", finding) });
        var store = new InMemorySessionStore();
        var service = CreateService(state, new ExplanationProvider(), sessionStore: store);

        await service.CreateSessionAsync("FW-001", CancellationToken.None);
        var sessionId = store.List()[0].SessionId;

        service.UpdateStepState(sessionId, "FW-001", RemediationStepState.Completed);

        var updated = store.Load(sessionId)!;
        var stepEvent = Assert.Single(updated.Timeline, e => e.Type == RemediationSessionEventType.StepMarkedCompleted);
        Assert.Equal("FW-001", stepEvent.RuleId);
        Assert.Contains("completed", stepEvent.Title);
    }

    [Theory]
    [InlineData(RemediationStepState.Pending, RemediationSessionEventType.StepMarkedPending, "pending")]
    [InlineData(RemediationStepState.InProgress, RemediationSessionEventType.StepMarkedInProgress, "inprogress")]
    [InlineData(RemediationStepState.Completed, RemediationSessionEventType.StepMarkedCompleted, "completed")]
    [InlineData(RemediationStepState.Skipped, RemediationSessionEventType.StepMarkedSkipped, "skipped")]
    [InlineData(RemediationStepState.Failed, RemediationSessionEventType.StepMarkedFailed, "failed")]
    public async Task UpdateStepState_MapsEachStateToCorrectEventType(
        RemediationStepState newState,
        RemediationSessionEventType expectedEventType,
        string expectedInTitle)
    {
        var state = new AgentAuditState();
        var finding = CreateRemediableFinding("FW-001");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", finding) });
        var store = new InMemorySessionStore();
        var service = CreateService(state, new ExplanationProvider(), sessionStore: store);

        await service.CreateSessionAsync("FW-001", CancellationToken.None);
        var sessionId = store.List()[0].SessionId;

        service.UpdateStepState(sessionId, "FW-001", newState);

        var updated = store.Load(sessionId)!;
        var stepEvent = Assert.Single(updated.Timeline, e => e.Type == expectedEventType);
        Assert.Equal("FW-001", stepEvent.RuleId);
        Assert.Contains(expectedInTitle, stepEvent.Title);
    }

    [Fact]
    public async Task UpdateStepState_BlockedStepCannotBeChanged()
    {
        var state = new AgentAuditState();
        var finding = CreateRiskyFindingWithoutRollback("FW-DANGER");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-DANGER", finding) });
        var store = new InMemorySessionStore();
        var service = CreateService(state, new ExplanationProvider(), sessionStore: store);

        await service.CreateSessionAsync("FW-DANGER", CancellationToken.None);
        var sessionId = store.List()[0].SessionId;

        var result = service.UpdateStepState(sessionId, "FW-DANGER", RemediationStepState.Completed);

        Assert.Contains("blocked", result.Summary.ToLowerInvariant());
        var unchanged = store.Load(sessionId);
        Assert.Equal(RemediationStepState.Blocked, unchanged!.StepStates["FW-DANGER"]);
    }

    [Fact]
    public async Task UpdateStepState_AllCompleted_MarksSessionCompleted()
    {
        var state = new AgentAuditState();
        var finding = CreateRemediableFinding("FW-001");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", finding) });
        var store = new InMemorySessionStore();
        var service = CreateService(state, new ExplanationProvider(), sessionStore: store);

        await service.CreateSessionAsync("FW-001", CancellationToken.None);
        var sessionId = store.List()[0].SessionId;

        service.UpdateStepState(sessionId, "FW-001", RemediationStepState.Completed);

        var updated = store.Load(sessionId);
        Assert.Equal(RemediationSessionStatus.Completed, updated!.Status);
    }

    [Fact]
    public async Task RunVerification_RunsAuditAndProducesDiff()
    {
        var state = new AgentAuditState();
        var finding = CreateRemediableFinding("FW-001");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", finding) });
        var store = new InMemorySessionStore();

        var afterResult = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = Array.Empty<Finding>() };
        var service = CreateService(state, new ExplanationProvider(), sessionStore: store,
            runAudit: (intent, _, _) => Task.FromResult(afterResult));

        await service.CreateSessionAsync("FW-001", CancellationToken.None);
        var sessionId = store.List()[0].SessionId;

        var result = await service.RunVerificationAsync(sessionId, CancellationToken.None);

        Assert.Equal(AgentIntent.VerifyRemediation, result.Intent);
        Assert.Contains("Fixed", result.Summary);

        var verified = store.Load(sessionId);
        Assert.Equal(RemediationSessionStatus.Verified, verified!.Status);
        Assert.NotNull(verified.VerificationResult);
        Assert.NotEmpty(verified.VerificationResult.FixedFindings);
    }

    [Fact]
    public async Task RunVerification_AddsVerificationCompletedEvent()
    {
        var state = new AgentAuditState();
        var finding = CreateRemediableFinding("FW-001");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", finding) });
        var store = new InMemorySessionStore();

        var afterResult = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = Array.Empty<Finding>() };
        var service = CreateService(state, new ExplanationProvider(), sessionStore: store,
            runAudit: (intent, _, _) => Task.FromResult(afterResult));

        await service.CreateSessionAsync("FW-001", CancellationToken.None);
        var sessionId = store.List()[0].SessionId;

        await service.RunVerificationAsync(sessionId, CancellationToken.None);

        var verified = store.Load(sessionId)!;
        Assert.Contains(verified.Timeline, e => e.Type == RemediationSessionEventType.VerificationStarted);
        Assert.Contains(verified.Timeline, e => e.Type == RemediationSessionEventType.VerificationCompleted);
        var completedEvent = verified.Timeline.Single(e => e.Type == RemediationSessionEventType.VerificationCompleted);
        Assert.Contains("fixed", completedEvent.Title);
    }

    [Fact]
    public async Task RunVerification_BlockedSession_AddsVerificationBlockedEvent()
    {
        var state = new AgentAuditState();
        var finding = CreateRiskyFindingWithoutRollback("FW-DANGER");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-DANGER", finding) });
        var store = new InMemorySessionStore();
        var service = CreateService(state, new ExplanationProvider(), sessionStore: store,
            runAudit: (_, _, _) => Task.FromResult(new AgentResult { Intent = AgentIntent.FirewallCheck }));

        await service.CreateSessionAsync("FW-DANGER", CancellationToken.None);
        var sessionId = store.List()[0].SessionId;

        await service.RunVerificationAsync(sessionId, CancellationToken.None);

        var blocked = store.Load(sessionId)!;
        Assert.Contains(blocked.Timeline, e => e.Type == RemediationSessionEventType.VerificationBlocked);
    }

    [Fact]
    public async Task RunVerification_WhenAuditThrows_AddsVerificationFailedEvent()
    {
        var state = new AgentAuditState();
        var finding = CreateRemediableFinding("FW-001");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", finding) });
        var store = new InMemorySessionStore();
        var service = CreateService(state, new ExplanationProvider(), sessionStore: store,
            runAudit: (_, _, _) => throw new InvalidOperationException("audit crashed"));

        await service.CreateSessionAsync("FW-001", CancellationToken.None);
        var sessionId = store.List()[0].SessionId;

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.RunVerificationAsync(sessionId, CancellationToken.None));

        var failed = store.Load(sessionId)!;
        Assert.Contains(failed.Timeline, e => e.Type == RemediationSessionEventType.VerificationStarted);
        var failedEvent = Assert.Single(failed.Timeline, e => e.Type == RemediationSessionEventType.VerificationFailed);
        Assert.Contains("audit crashed", failedEvent.Details);
    }

    [Fact]
    public async Task RunVerification_RestoresAuditState()
    {
        var state = new AgentAuditState();
        var finding = CreateRemediableFinding("FW-001");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", finding) });
        var store = new InMemorySessionStore();
        var originalResult = state.LastResult;

        var afterResult = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = Array.Empty<Finding>() };
        var service = CreateService(state, new ExplanationProvider(), sessionStore: store,
            runAudit: (intent, _, _) => Task.FromResult(afterResult));

        await service.CreateSessionAsync("FW-001", CancellationToken.None);
        var sessionId = store.List()[0].SessionId;

        await service.RunVerificationAsync(sessionId, CancellationToken.None);

        Assert.Same(originalResult, state.LastResult);
    }

    [Fact]
    public async Task RunVerification_UnknownSession_ReturnsNotFound()
    {
        var state = new AgentAuditState();
        var store = new InMemorySessionStore();
        var fallbackResult = new AgentResult { Intent = AgentIntent.FullAudit, AgentFindings = Array.Empty<Finding>() };
        var service = CreateService(state, sessionStore: store,
            runAudit: (intent, _, _) => Task.FromResult(fallbackResult));

        var result = await service.RunVerificationAsync("nonexistent", CancellationToken.None);

        Assert.Contains("not found", result.Summary);
    }

    [Fact]
    public async Task RunVerification_BlockedSession_ReturnsSafetyBlockMessage()
    {
        var state = new AgentAuditState();
        var finding = CreateRiskyFindingWithoutRollback("FW-DANGER");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-DANGER", finding) });
        var store = new InMemorySessionStore();
        var service = CreateService(state, new ExplanationProvider(), sessionStore: store,
            runAudit: (_, _, _) => Task.FromResult(new AgentResult { Intent = AgentIntent.FirewallCheck }));

        await service.CreateSessionAsync("FW-DANGER", CancellationToken.None);
        var sessionId = store.List()[0].SessionId;

        var result = await service.RunVerificationAsync(sessionId, CancellationToken.None);

        Assert.Equal(AgentIntent.VerifyRemediation, result.Intent);
        Assert.Contains("blocked", result.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.NotEmpty(result.Warnings);
    }

    [Fact]
    public void UpdateStepState_UnknownSession_ReturnsNotFound2()
    {
        var state = new AgentAuditState();
        var store = new InMemorySessionStore();
        var service = CreateService(state, sessionStore: store);

        var result = service.UpdateStepState("nonexistent", "FW-001", RemediationStepState.Completed);

        Assert.Contains("not found", result.Summary);
    }

    [Fact]
    public async Task MarkSessionExported_AddsExportedEvent()
    {
        var state = new AgentAuditState();
        var finding = CreateRemediableFinding("FW-001");
        var audit = new AgentResult { Intent = AgentIntent.FirewallCheck, AgentFindings = new[] { finding } };
        state.RememberAudit(audit, AgentIntent.FirewallCheck, new[] { ("FW-001", finding) });
        var store = new InMemorySessionStore();
        var service = CreateService(state, new ExplanationProvider(), sessionStore: store);

        await service.CreateSessionAsync("FW-001", CancellationToken.None);
        var sessionId = store.List()[0].SessionId;

        var result = await service.MarkSessionExportedAsync(sessionId, CancellationToken.None);

        Assert.Equal(AgentIntent.StartRemediation, result.Intent);
        var saved = store.Load(sessionId)!;
        Assert.Contains(saved.Timeline, e => e.Type == RemediationSessionEventType.Exported);
    }

    [Fact]
    public async Task MarkSessionExported_UnknownSession_ReturnsNotFound()
    {
        var state = new AgentAuditState();
        var store = new InMemorySessionStore();
        var service = CreateService(state, sessionStore: store);

        var result = await service.MarkSessionExportedAsync("nonexistent", CancellationToken.None);

        Assert.Contains("not found", result.Summary);
    }

    private static GuidedRemediationService CreateService(
        AgentAuditState state,
        IExplanationProvider? explanationProvider = null,
        ISessionStore? sessionStore = null,
        Func<AgentIntent, string?, CancellationToken, Task<AgentResult>>? runAudit = null)
    {
        var planBuilder = new RemediationPlanBuilder(explanationProvider ?? new TestExplanationProvider());
        return new GuidedRemediationService(state, planBuilder, sessionStore, runAudit);
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

    private sealed class TestExplanationProvider : IExplanationProvider
    {
        public string GetExplanation(string key, IReadOnlyDictionary<string, string> variables)
            => $"explanation:{key}";

        public StructuredExplanation GetStructuredExplanation(string key, IReadOnlyDictionary<string, string> variables)
            => new() { WhatWasFound = GetExplanation(key, variables) };

        public StructuredExplanation ParseStructuredFromText(string text)
            => new() { WhyItMatters = text, WhatWasFound = text };
    }
}
