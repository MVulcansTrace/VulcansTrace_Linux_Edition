using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Dialogue;

public class DiagnosticDialogueServiceTests
{
    private readonly DiagnosticDialogueService _service = new();

    [Fact]
    public async Task BeginInvestigation_RecurringFinding_ReturnsQuestionAndSetsState()
    {
        var context = CreateContextWithMemory("FW-004", "FW", 2, RuleStatusTrend.Stable);

        var result = await _service.BeginInvestigationAsync(context, "FW-004", CancellationToken.None);

        Assert.Equal(AgentIntent.InvestigateRecurrence, result.Intent);
        Assert.NotNull(result.Narrative);
        Assert.Contains("config-management", result.Narrative!.KeyFindingsParagraph);
        Assert.Equal(DialogueState.AwaitingDiagnosticAnswer, context.Entities.DiagnosticState);
        Assert.Equal("FW-004", context.Entities.PendingDiagnosticRuleId);
        Assert.NotNull(context.Entities.PendingDiagnosticQuestion);
    }

    [Fact]
    public async Task BeginInvestigation_WorseningTrend_ReturnsQuestion()
    {
        var context = CreateContextWithMemory("FW-004", "FW", 1, RuleStatusTrend.Worsening);

        var result = await _service.BeginInvestigationAsync(context, "FW-004", CancellationToken.None);

        Assert.Equal(AgentIntent.InvestigateRecurrence, result.Intent);
        Assert.Contains("getting worse", result.Narrative!.KeyFindingsParagraph);
        Assert.Equal(DialogueState.AwaitingDiagnosticAnswer, context.Entities.DiagnosticState);
    }

    [Fact]
    public async Task BeginInvestigation_NoHistory_ReturnsGuidanceAndResetsState()
    {
        var context = new DialogueContext();

        var result = await _service.BeginInvestigationAsync(context, "FW-004", CancellationToken.None);

        Assert.Equal(AgentIntent.InvestigateRecurrence, result.Intent);
        Assert.Contains("don't have any history", result.Summary);
        Assert.Equal(DialogueState.Idle, context.Entities.DiagnosticState);
    }

    [Fact]
    public async Task BeginInvestigation_NotRecurringEnough_ReturnsGuidanceAndResetsState()
    {
        var context = CreateContextWithMemory("FW-004", "FW", 1, RuleStatusTrend.Stable);

        var result = await _service.BeginInvestigationAsync(context, "FW-004", CancellationToken.None);

        Assert.Contains("doesn't show a recurring pattern", result.Summary);
        Assert.Equal(DialogueState.Idle, context.Entities.DiagnosticState);
    }

    [Fact]
    public async Task ContinueInvestigation_ConfigManagementAnswer_ReturnsRootCauseAndSetsState()
    {
        var context = CreateContextWithMemory("FW-004", "FW", 2, RuleStatusTrend.Stable);
        context.Entities.DiagnosticState = DialogueState.AwaitingDiagnosticAnswer;
        context.Entities.PendingDiagnosticRuleId = "FW-004";

        var result = await _service.ContinueInvestigationAsync(context, "FW-004", "We use Ansible", CancellationToken.None);

        Assert.Equal(AgentIntent.AnswerDiagnosticQuestion, result.Intent);
        Assert.Contains("config-management tool", result.Narrative!.KeyFindingsParagraph);
        Assert.Equal(DialogueState.RootCauseProposed, context.Entities.DiagnosticState);
    }

    [Fact]
    public async Task ContinueInvestigation_WithCorrelations_IncludesRelatedFindings()
    {
        var context = CreateContextWithMemory("FW-004", "FW", 2, RuleStatusTrend.Stable);
        context.Entities.DiagnosticState = DialogueState.AwaitingDiagnosticAnswer;
        context.Entities.PendingDiagnosticRuleId = "FW-004";
        context.RememberResult(new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            AgentFindings = Array.Empty<Finding>(),
            PostureCorrelations = new[]
            {
                new PostureCorrelation
                {
                    PatternId = "P1",
                    RuleIdA = "FW-004",
                    RuleIdB = "SSH-002",
                    Narrative = "Exposed SSH plus missing firewall is high risk",
                    CombinedSeverity = Severity.Critical,
                    MatchedFindingRuleIds = new[] { "FW-004", "SSH-002" }
                }
            }
        });

        var result = await _service.ContinueInvestigationAsync(context, "FW-004", "reboot", CancellationToken.None);

        Assert.Contains("SSH-002", result.Narrative!.KeyFindingsParagraph);
        Assert.Contains("connected to SSH-002", result.Narrative.KeyFindingsParagraph);
    }

    [Fact]
    public void ResetDiagnosticState_ClearsState()
    {
        var context = new DialogueContext();
        context.Entities.DiagnosticState = DialogueState.AwaitingDiagnosticAnswer;
        context.Entities.PendingDiagnosticRuleId = "FW-004";
        context.Entities.PendingDiagnosticQuestion = "question?";

        _service.ResetDiagnosticState(context.Entities);

        Assert.Equal(DialogueState.Idle, context.Entities.DiagnosticState);
        Assert.Null(context.Entities.PendingDiagnosticRuleId);
        Assert.Null(context.Entities.PendingDiagnosticQuestion);
    }

    private static DialogueContext CreateContextWithMemory(string ruleId, string category, int closedCycles, RuleStatusTrend trend)
    {
        var context = new DialogueContext();
        var cycles = new List<RemediationCycle>();
        for (int i = 0; i < closedCycles; i++)
        {
            var attempted = DateTime.UtcNow.AddDays(-(closedCycles - i) * 7);
            cycles.Add(new RemediationCycle
            {
                CycleNumber = i + 1,
                AttemptedUtc = attempted,
                VerifiedFixedUtc = attempted.AddHours(1),
                ReturnedUtc = attempted.AddHours(2)
            });
        }

        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            [ruleId] = new RuleMemoryEntry
            {
                RuleId = ruleId,
                Category = category,
                Trend = trend,
                RemediationCycles = cycles
            }
        };

        context.RememberAudit(
            new AgentResult { Intent = AgentIntent.FullAudit, AgentFindings = Array.Empty<Finding>() },
            AgentIntent.FullAudit,
            Array.Empty<(string, Finding)>());

        // Replace the history after RememberAudit (which clears it).
        context.Entities.RuleHistory = history;

        return context;
    }
}
