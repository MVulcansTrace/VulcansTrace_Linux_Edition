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
