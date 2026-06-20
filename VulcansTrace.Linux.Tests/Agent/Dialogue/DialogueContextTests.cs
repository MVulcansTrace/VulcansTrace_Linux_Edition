using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Dialogue;

public class DialogueContextTests
{
    [Fact]
    public void RememberAudit_SetsLastResultAndIntent()
    {
        var context = new DialogueContext();
        var finding = CreateFinding("TEST-001", "Test");
        var result = new AgentResult
        {
            Intent = AgentIntent.FirewallCheck,
            AgentFindings = new[] { finding }
        };

        context.RememberAudit(result, AgentIntent.FirewallCheck, new[] { ("TEST-001", finding) });

        Assert.Same(result, context.LastResult);
        Assert.Equal(AgentIntent.FirewallCheck, context.LastAuditIntent);
        Assert.Equal(AgentIntent.FirewallCheck, context.Entities.LastIntent);
        Assert.Equal(ConversationTopic.Audit, context.Entities.LastTopic);
    }

    [Fact]
    public void FindPreviousFinding_MatchesRuleId()
    {
        var context = new DialogueContext();
        var finding = CreateFinding("TEST-001", "Test");
        context.RememberAudit(
            new AgentResult { Intent = AgentIntent.FullAudit, AgentFindings = new[] { finding } },
            AgentIntent.FullAudit,
            new[] { ("TEST-001", finding) });

        var found = context.FindPreviousFinding("TEST-001");

        Assert.Same(finding, found);
    }

    [Fact]
    public void FocusFinding_SetsEntities()
    {
        var context = new DialogueContext();
        var finding = CreateFinding("TEST-001", "Firewall");

        context.FocusFinding(finding);

        Assert.Same(finding, context.Entities.LastFinding);
        Assert.Equal("TEST-001", context.Entities.LastRuleId);
        Assert.Equal("Firewall", context.Entities.LastCategory);
    }

    [Fact]
    public void PushTurn_CapsHistory()
    {
        var context = new DialogueContext();
        for (var i = 0; i < DialogueContext.MaxHistoryTurns + 5; i++)
        {
            context.PushTurn(DialogueTurn.Now($"query {i}", AgentIntent.FullAudit, null));
        }

        Assert.Equal(DialogueContext.MaxHistoryTurns, context.History.Count);
    }

    [Fact]
    public void Reset_ClearsState()
    {
        var context = new DialogueContext();
        var finding = CreateFinding("TEST-001", "Test");
        context.RememberAudit(
            new AgentResult { Intent = AgentIntent.FullAudit, AgentFindings = new[] { finding } },
            AgentIntent.FullAudit,
            new[] { ("TEST-001", finding) });
        context.PushTurn(DialogueTurn.Now("q", AgentIntent.FullAudit, null));

        context.Reset();

        Assert.Null(context.LastResult);
        Assert.Empty(context.History);
        Assert.Null(context.Entities.LastFinding);
    }

    [Fact]
    public void RememberResult_Null_ClearsLastResult()
    {
        var context = new DialogueContext();
        var finding = CreateFinding("TEST-001", "Test");
        context.RememberAudit(
            new AgentResult { Intent = AgentIntent.FullAudit, AgentFindings = new[] { finding } },
            AgentIntent.FullAudit,
            new[] { ("TEST-001", finding) });

        context.RememberResult(null);

        Assert.Null(context.LastResult);
    }

    [Fact]
    public void RestoreState_PreserveCoverage_KeepsLiveCheckedCategories()
    {
        var context = new DialogueContext();
        var liveCoverage = new[]
        {
            new CategoryAuditEntry { Category = "SSH", UtcTimestamp = DateTime.UtcNow }
        };
        context.Entities.CheckedCategories = liveCoverage;

        var savedEntities = new EntityFrame { CheckedCategories = Array.Empty<CategoryAuditEntry>() };

        // preserveCoverage keeps the just-recorded (live) coverage; the stale snapshot is ignored.
        context.RestoreState(null, savedEntities, preserveCoverage: true);

        var kept = Assert.Single(context.Entities.CheckedCategories);
        Assert.Equal("SSH", kept.Category);
    }

    [Fact]
    public void RestoreState_PreserveRuleHistory_KeepsLiveRuleHistory()
    {
        var context = new DialogueContext();
        var liveHistory = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = new RuleMemoryEntry
            {
                RuleId = "FW-001",
                Category = "Firewall",
                LastSeverity = Severity.High
            }
        };
        context.Entities.RuleHistory = liveHistory;

        var savedEntities = new EntityFrame
        {
            RuleHistory = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        };

        context.RestoreState(null, savedEntities, preserveRuleHistory: true);

        Assert.True(context.Entities.RuleHistory.ContainsKey("FW-001"));
        Assert.Equal(Severity.High, context.Entities.RuleHistory["FW-001"].LastSeverity);
    }

    [Fact]
    public void RestoreState_Default_RevertsRuleHistoryFromSnapshot()
    {
        var context = new DialogueContext();
        context.Entities.RuleHistory = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = new RuleMemoryEntry { RuleId = "FW-001", Category = "Firewall" }
        };

        var savedEntities = new EntityFrame
        {
            RuleHistory = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        };

        context.RestoreState(null, savedEntities);

        Assert.Empty(context.Entities.RuleHistory);
    }

    [Fact]
    public void RestoreState_Default_RevertsCheckedCategoriesFromSnapshot()
    {
        var context = new DialogueContext();
        context.Entities.CheckedCategories = new[]
        {
            new CategoryAuditEntry { Category = "SSH", UtcTimestamp = DateTime.UtcNow }
        };

        var savedEntities = new EntityFrame { CheckedCategories = Array.Empty<CategoryAuditEntry>() };

        context.RestoreState(null, savedEntities);

        Assert.Empty(context.Entities.CheckedCategories);
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
