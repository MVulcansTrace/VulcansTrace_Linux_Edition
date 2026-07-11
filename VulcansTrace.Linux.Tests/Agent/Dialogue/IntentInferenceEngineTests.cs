using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Dialogue;

public class IntentInferenceEngineTests
{
    private readonly IntentInferenceEngine _engine = new();
    private readonly QueryParser _parser = new();
    private readonly AnaphoraResolver _resolver = new();

    [Fact]
    public void Infer_AfterExplanation_FixItBecomesFixFinding()
    {
        var context = new DialogueContext();
        var finding = CreateFinding("TEST-001", "Firewall");
        context.RememberResult(new AgentResult
        {
            Intent = AgentIntent.ExplainFinding,
            AgentFindings = new[] { finding }
        });
        context.FocusFinding(finding, finding.RuleId);

        var parsed = _parser.Parse("how do I fix it");
        var resolution = new ReferenceResolution(true, null, null, null, null, finding, null);
        var (inferred, wasInferred) = _engine.Infer(parsed, resolution, context.SnapshotEntities());

        Assert.True(wasInferred);
        Assert.Equal(AgentIntent.FixFinding, inferred.Intent);
        Assert.Equal("TEST-001", inferred.TargetReference);
    }

    [Fact]
    public void Infer_AfterAudit_SSHOnesBecomesFilterCategory()
    {
        var context = new DialogueContext();
        context.RememberAudit(
            new AgentResult { Intent = AgentIntent.FullAudit, AgentFindings = Array.Empty<Finding>() },
            AgentIntent.FullAudit,
            Array.Empty<(string, Finding)>());

        var parsed = _parser.Parse("only the SSH ones");
        var resolution = new ReferenceResolution(true, null, null, "SSH", null, null, null);
        var (inferred, wasInferred) = _engine.Infer(parsed, resolution, context.SnapshotEntities());

        Assert.True(wasInferred);
        Assert.Equal(AgentIntent.FilterCategory, inferred.Intent);
        Assert.Equal("SSH", inferred.TargetReference);
    }

    [Fact]
    public void Infer_AfterRemediation_VerifyItBecomesVerifyRemediation()
    {
        var context = new DialogueContext();
        var session = new RemediationSession
        {
            SessionId = "abc12345",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan(),
            StepStates = new Dictionary<string, RemediationStepState>()
        };
        context.RememberResult(new AgentResult
        {
            Intent = AgentIntent.StartRemediation,
            RemediationSession = session,
            AgentFindings = Array.Empty<Finding>()
        });

        var parsed = _parser.Parse("verify it");
        var resolution = new ReferenceResolution(true, null, "abc12345", null, null, null, null);
        var (inferred, wasInferred) = _engine.Infer(parsed, resolution, context.SnapshotEntities());

        Assert.True(wasInferred);
        Assert.Equal(AgentIntent.VerifyRemediation, inferred.Intent);
        Assert.Equal("abc12345", inferred.TargetReference);
    }

    [Fact]
    public void Infer_ConfidentParserNoContext_ReturnsParsed()
    {
        var context = new DialogueContext();
        var parsed = _parser.Parse("run a full audit");
        var resolution = ReferenceResolution.Empty;
        var (inferred, wasInferred) = _engine.Infer(parsed, resolution, context.SnapshotEntities());

        Assert.False(wasInferred);
        Assert.Equal(AgentIntent.FullAudit, inferred.Intent);
    }

    [Fact]
    public void Infer_AuditReroute_PreservesSlots()
    {
        // A low-confidence brevity query with a resolved category promotes to that category's audit;
        // the reconstructed AgentQuery must carry the parser's slots forward so freshness/verbosity
        // survive the reroute.
        var context = new DialogueContext();
        var parsed = _parser.Parse("give me the short version");
        Assert.Equal(QueryVerbosity.Terse, parsed.Slots.Verbosity);

        var resolution = new ReferenceResolution(false, null, null, "Firewall", null, null, null);
        var (inferred, wasInferred) = _engine.Infer(parsed, resolution, context.SnapshotEntities());

        Assert.True(wasInferred);
        Assert.Equal(AgentIntent.FirewallCheck, inferred.Intent);
        Assert.Equal(QueryVerbosity.Terse, inferred.Slots.Verbosity);
    }

    [Fact]
    public void Infer_PrioritizeRemediationWithOrdinal_DoesNotChangeIntent()
    {
        var context = new DialogueContext();
        context.RememberAudit(
            new AgentResult { Intent = AgentIntent.FullAudit, AgentFindings = Array.Empty<Finding>() },
            AgentIntent.FullAudit,
            Array.Empty<(string, Finding)>());

        var parsed = _parser.Parse("what should I fix first");
        var resolution = new ReferenceResolution(false, null, null, null, 1, null, null);
        var (inferred, wasInferred) = _engine.Infer(parsed, resolution, context.SnapshotEntities());

        Assert.False(wasInferred);
        Assert.Equal(AgentIntent.PrioritizeRemediation, inferred.Intent);
    }

    [Fact]
    public void Infer_OpenIssuesAfterRemediation_DoesNotResume()
    {
        var context = new DialogueContext();
        var session = new RemediationSession
        {
            SessionId = "abc12345",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan(),
            StepStates = new Dictionary<string, RemediationStepState>()
        };
        context.RememberResult(new AgentResult
        {
            Intent = AgentIntent.StartRemediation,
            RemediationSession = session,
            AgentFindings = Array.Empty<Finding>()
        });

        var parsed = _parser.Parse("are there open issues?");
        var resolution = _resolver.Resolve(parsed.RawQuery!, context.SnapshotEntities());
        var (inferred, wasInferred) = _engine.Infer(parsed, resolution, context.SnapshotEntities());

        Assert.NotEqual(AgentIntent.ResumeRemediation, inferred.Intent);
    }

    [Fact]
    public void Infer_AfterRemediation_CheckFirewallRemainsFirewallCheck()
    {
        var context = new DialogueContext();
        var session = new RemediationSession
        {
            SessionId = "abc12345",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan(),
            StepStates = new Dictionary<string, RemediationStepState>()
        };
        context.RememberResult(new AgentResult
        {
            Intent = AgentIntent.StartRemediation,
            RemediationSession = session,
            AgentFindings = Array.Empty<Finding>()
        });

        var parsed = _parser.Parse("check my firewall");
        var resolution = _resolver.Resolve(parsed.RawQuery!, context.SnapshotEntities());
        var (inferred, wasInferred) = _engine.Infer(parsed, resolution, context.SnapshotEntities());

        Assert.False(wasInferred);
        Assert.Equal(AgentIntent.FirewallCheck, inferred.Intent);
    }

    [Fact]
    public void Infer_AfterRemediation_CheckItBecomesVerifyRemediation()
    {
        var context = new DialogueContext();
        var session = new RemediationSession
        {
            SessionId = "abc12345",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan(),
            StepStates = new Dictionary<string, RemediationStepState>()
        };
        context.RememberResult(new AgentResult
        {
            Intent = AgentIntent.StartRemediation,
            RemediationSession = session,
            AgentFindings = Array.Empty<Finding>()
        });

        var parsed = _parser.Parse("check it");
        var resolution = new ReferenceResolution(true, null, "abc12345", null, null, null, null);
        var (inferred, wasInferred) = _engine.Infer(parsed, resolution, context.SnapshotEntities());

        Assert.True(wasInferred);
        Assert.Equal(AgentIntent.VerifyRemediation, inferred.Intent);
        Assert.Equal("abc12345", inferred.TargetReference);
    }

    [Fact]
    public void Infer_AfterRemediation_DidTheFixWorkBecomesVerifyRemediation()
    {
        var context = new DialogueContext();
        var session = new RemediationSession
        {
            SessionId = "abc12345",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan(),
            StepStates = new Dictionary<string, RemediationStepState>()
        };
        context.RememberResult(new AgentResult
        {
            Intent = AgentIntent.StartRemediation,
            RemediationSession = session,
            AgentFindings = Array.Empty<Finding>()
        });

        var parsed = _parser.Parse("did it work?");
        var resolution = new ReferenceResolution(true, null, "abc12345", null, null, null, null);
        var (inferred, wasInferred) = _engine.Infer(parsed, resolution, context.SnapshotEntities());

        Assert.True(wasInferred);
        Assert.Equal(AgentIntent.VerifyRemediation, inferred.Intent);
        Assert.Equal("abc12345", inferred.TargetReference);
    }

    [Theory]
    [InlineData("notebook", AgentIntent.AddSessionNote)]
    [InlineData("prefix", AgentIntent.FixFinding)]
    [InlineData("listen", AgentIntent.ListRemediationSessions)]
    [InlineData("check italy", AgentIntent.VerifyRemediation)]
    [InlineData("my_note", AgentIntent.AddSessionNote)]
    public void Infer_AfterRemediation_SubstringFalsePositivesAreRejected(string query, AgentIntent avoidedIntent)
    {
        var context = new DialogueContext();
        var session = new RemediationSession
        {
            SessionId = "abc12345",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan(),
            StepStates = new Dictionary<string, RemediationStepState>()
        };
        context.RememberResult(new AgentResult
        {
            Intent = AgentIntent.StartRemediation,
            RemediationSession = session,
            AgentFindings = Array.Empty<Finding>()
        });

        var parsed = _parser.Parse(query);
        var resolution = _resolver.Resolve(parsed.RawQuery!, context.SnapshotEntities());
        var (inferred, _) = _engine.Infer(parsed, resolution, context.SnapshotEntities());

        Assert.NotEqual(avoidedIntent, inferred.Intent);
    }

    [Fact]
    public void Infer_AfterRemediation_LaterWholeWordMatchStillApplies()
    {
        var context = new DialogueContext();
        var session = new RemediationSession
        {
            SessionId = "abc12345",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan(),
            StepStates = new Dictionary<string, RemediationStepState>()
        };
        context.RememberResult(new AgentResult
        {
            Intent = AgentIntent.StartRemediation,
            RemediationSession = session,
            AgentFindings = Array.Empty<Finding>()
        });

        var parsed = _parser.Parse("notebook note");
        var resolution = _resolver.Resolve(parsed.RawQuery!, context.SnapshotEntities());
        var (inferred, wasInferred) = _engine.Infer(parsed, resolution, context.SnapshotEntities());

        Assert.True(wasInferred);
        Assert.Equal(AgentIntent.AddSessionNote, inferred.Intent);
    }

    [Fact]
    public void Infer_CheckWithRuleIdDoesNotBecomeVerifyRemediation()
    {
        var context = new DialogueContext();
        context.RememberResult(new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            AgentFindings = Array.Empty<Finding>()
        });

        var parsed = _parser.Parse("check FW-001");
        var resolution = _resolver.Resolve(parsed.RawQuery!, context.SnapshotEntities());
        var (inferred, _) = _engine.Infer(parsed, resolution, context.SnapshotEntities());

        Assert.NotEqual(AgentIntent.VerifyRemediation, inferred.Intent);
    }

    [Fact]
    public void Infer_AwaitingDiagnosticAnswer_AnyQueryBecomesAnswerDiagnosticQuestion()
    {
        var context = new DialogueContext();
        context.Entities.LastTopic = ConversationTopic.Explanation;
        context.Entities.DiagnosticState = DialogueState.AwaitingDiagnosticAnswer;
        context.Entities.PendingDiagnosticRuleId = "FW-004";

        var parsed = _parser.Parse("I'm using Ansible");
        var resolution = _resolver.Resolve(parsed.RawQuery!, context.SnapshotEntities());
        var (inferred, wasInferred) = _engine.Infer(parsed, resolution, context.SnapshotEntities());

        Assert.True(wasInferred);
        Assert.Equal(AgentIntent.AnswerDiagnosticQuestion, inferred.Intent);
        Assert.Equal("FW-004", inferred.TargetReference);
    }

    [Fact]
    public void Infer_AfterExplanation_RecurrenceKeywordsBecomeInvestigateRecurrence()
    {
        var context = new DialogueContext();
        var finding = CreateFinding("FW-004", "Firewall");
        context.RememberResult(new AgentResult
        {
            Intent = AgentIntent.ExplainFinding,
            AgentFindings = new[] { finding }
        });
        context.FocusFinding(finding, finding.RuleId);

        var parsed = _parser.Parse("it came back again");
        var resolution = _resolver.Resolve(parsed.RawQuery!, context.SnapshotEntities());
        var (inferred, _) = _engine.Infer(parsed, resolution, context.SnapshotEntities());

        Assert.Equal(AgentIntent.InvestigateRecurrence, inferred.Intent);
        Assert.Equal("FW-004", inferred.TargetReference);
    }

    [Fact]
    public void Infer_AfterRemediation_RecurrenceKeywordsBecomeInvestigateRecurrence()
    {
        var context = new DialogueContext();
        var session = new RemediationSession
        {
            SessionId = "abc12345",
            SourceFindings = new[] { CreateFinding("FW-004", "Firewall") },
            RemediationPlan = new RemediationPlan(),
            StepStates = new Dictionary<string, RemediationStepState>()
        };
        context.RememberResult(new AgentResult
        {
            Intent = AgentIntent.StartRemediation,
            RemediationSession = session,
            AgentFindings = Array.Empty<Finding>()
        });

        var parsed = _parser.Parse("FW-004 keeps returning");
        var resolution = _resolver.Resolve(parsed.RawQuery!, context.SnapshotEntities());
        var (inferred, _) = _engine.Infer(parsed, resolution, context.SnapshotEntities());

        Assert.Equal(AgentIntent.InvestigateRecurrence, inferred.Intent);
        Assert.Equal("FW-004", inferred.TargetReference);
    }

    [Fact]
    public void Infer_AfterExplanation_AmbiguousRecurrenceQuery_InfersInvestigateRecurrence()
    {
        var context = new DialogueContext();
        var finding = CreateFinding("FW-004", "Firewall");
        context.RememberResult(new AgentResult
        {
            Intent = AgentIntent.ExplainFinding,
            AgentFindings = new[] { finding }
        });
        context.FocusFinding(finding, finding.RuleId);

        // "it returned" is not a standalone keyword, so the parser is low-confidence.
        var parsed = _parser.Parse("it returned");
        var resolution = _resolver.Resolve(parsed.RawQuery!, context.SnapshotEntities());
        var (inferred, wasInferred) = _engine.Infer(parsed, resolution, context.SnapshotEntities());

        Assert.True(wasInferred);
        Assert.Equal(AgentIntent.InvestigateRecurrence, inferred.Intent);
        Assert.Equal("FW-004", inferred.TargetReference);
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
