using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class RemediationMarkdownFormatterTests
{
    [Fact]
    public void FormatSession_IncludesSessionHeaderAndStepStates()
    {
        var session = new RemediationSession
        {
            SessionId = "abc12345",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState>
            {
                ["FW-001"] = RemediationStepState.Pending,
                ["SSH-001"] = RemediationStepState.Completed
            },
            BlockedReasons = Array.Empty<string>()
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.FormatSession(session);

        Assert.Contains("# VulcansTrace Remediation Session Report", result);
        Assert.Contains("**Session ID:** abc12345", result);
        Assert.Contains("**Status:** Active", result);
        Assert.Contains("**FW-001:** Pending", result);
        Assert.Contains("**SSH-001:** Completed", result);
    }

    [Fact]
    public void FormatSession_IncludesBlockedReasons()
    {
        var session = new RemediationSession
        {
            SessionId = "blocked1",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState>
            {
                ["FW-001"] = RemediationStepState.Blocked
            },
            BlockedReasons = new[] { "[FW-001] No rollback guidance", "[FW-001] Unclassified command" }
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.FormatSession(session);

        Assert.Contains("## Blocked Steps", result);
        Assert.Contains("[FW-001] No rollback guidance", result);
        Assert.Contains("[FW-001] Unclassified command", result);
    }

    [Fact]
    public void FormatSession_IncludesBeforeSnapshotFindings()
    {
        var session = new RemediationSession
        {
            SessionId = "snap1",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState>(),
            BeforeSnapshot = new AuditSnapshot
            {
                Findings = new[]
                {
                    new AuditSnapshotFinding
                    {
                        RuleId = "FW-001", Target = "firewall", Severity = "High",
                        ShortDescription = "SSH exposed"
                    }
                },
                TimestampUtc = DateTime.UtcNow,
                Intent = AgentIntent.FirewallCheck
            },
            BlockedReasons = Array.Empty<string>()
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.FormatSession(session);

        Assert.Contains("## Before Snapshot", result);
        Assert.Contains("[FW-001] [High] SSH exposed", result);
    }

    [Fact]
    public void FormatSession_IncludesVerificationResult()
    {
        var session = new RemediationSession
        {
            SessionId = "verify1",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState>(),
            VerificationResult = new SessionVerificationResult
            {
                FixedFindings = new[]
                {
                    new AuditSnapshotFinding
                    {
                        RuleId = "FW-001", Target = "firewall", Severity = "High",
                        ShortDescription = "SSH exposed"
                    }
                },
                UnchangedFindings = Array.Empty<AuditSnapshotFinding>(),
                NewFindings = new[]
                {
                    new AuditSnapshotFinding
                    {
                        RuleId = "NET-002", Target = "network", Severity = "Medium",
                        ShortDescription = "New issue"
                    }
                },
                WorsenedFindings = Array.Empty<SeverityChangeFinding>(),
                DiffNarrative = "1 resolved, 1 new."
            },
            BlockedReasons = Array.Empty<string>()
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.FormatSession(session);

        Assert.Contains("## Verification Result", result);
        Assert.Contains("1 resolved, 1 new.", result);
        Assert.Contains("### Fixed", result);
        Assert.Contains("✓ [FW-001] SSH exposed", result);
        Assert.Contains("### New Findings", result);
        Assert.Contains("⚠ [NET-002] New issue", result);
    }

    [Fact]
    public void FormatSession_IncludesWorsenedFindings()
    {
        var session = new RemediationSession
        {
            SessionId = "worse1",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState>(),
            VerificationResult = new SessionVerificationResult
            {
                FixedFindings = Array.Empty<AuditSnapshotFinding>(),
                UnchangedFindings = Array.Empty<AuditSnapshotFinding>(),
                NewFindings = Array.Empty<AuditSnapshotFinding>(),
                WorsenedFindings = new[]
                {
                    new SeverityChangeFinding
                    {
                        RuleId = "FW-002", Target = "firewall", OldSeverity = "Medium",
                        NewSeverity = "Critical", ShortDescription = "Firewall disabled", Fingerprint = "fp"
                    }
                },
                DiffNarrative = "1 worsened."
            },
            BlockedReasons = Array.Empty<string>()
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.FormatSession(session);

        Assert.Contains("### Worsened", result);
        Assert.Contains("✗ [FW-002] Medium → Critical: Firewall disabled", result);
    }

    [Fact]
    public void FormatSession_IncludesRemediationPlan()
    {
        var section = new RemediationSection
        {
            RuleId = "FW-001",
            FindingSummary = "[High] SSH exposed",
            RiskNote = "Risk here",
            ApplyCommands = new[]
            {
                new RemediationCommand { Command = "sudo ufw allow 22", Safety = CommandSafety.ConfigChange }
            },
            RollbackCommands = Array.Empty<RemediationCommand>(),
            VerificationCommands = Array.Empty<RemediationCommand>()
        };
        var session = new RemediationSession
        {
            SessionId = "plan1",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = new[] { section } },
            StepStates = new Dictionary<string, RemediationStepState> { ["FW-001"] = RemediationStepState.Pending },
            BlockedReasons = Array.Empty<string>()
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.FormatSession(session);

        Assert.Contains("## Remediation Plan", result);
        Assert.Contains("FW-001: [High] SSH exposed", result);
        Assert.Contains("sudo ufw allow 22", result);
    }
}
