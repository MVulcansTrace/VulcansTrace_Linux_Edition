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

    [Fact]
    public void Format_IncludesImpactPreview()
    {
        var plan = new RemediationPlan
        {
            Sections = new[]
            {
                new RemediationSection
                {
                    RuleId = "FW-001",
                    FindingSummary = "[High] Default policy ACCEPT",
                    RiskNote = "High risk",
                    ImpactPreview = new RemediationImpactPreview
                    {
                        ExpectedImpact = "Default INPUT policy will change to DROP.",
                        ExpectedImpactSource = RemediationImpactSource.SuggestedAction,
                        RollbackPath = "sudo iptables -P INPUT ACCEPT",
                        RollbackPathKind = RemediationPreviewTextKind.Command,
                        VerificationCommand = "sudo iptables -L INPUT | head -n 1",
                        IsVerificationCommand = true,
                        VerificationKind = RemediationPreviewTextKind.Command
                    },
                    ApplyCommands = new[]
                    {
                        new RemediationCommand { Command = "sudo iptables -P INPUT DROP", Safety = CommandSafety.ConfigChange }
                    },
                    RollbackCommands = new[]
                    {
                        new RemediationCommand { Command = "sudo iptables -P INPUT ACCEPT", Safety = CommandSafety.ConfigChange }
                    }
                }
            }
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.Format(plan);

        Assert.Contains("**Impact Preview**", result);
        Assert.Contains("**Impact:** Default INPUT policy will change to DROP.", result);
        Assert.Contains("**Rollback:** `sudo iptables -P INPUT ACCEPT`", result);
        Assert.Contains("**Verify:** `sudo iptables -L INPUT | head -n 1`", result);
    }

    [Fact]
    public void Format_IncludesImpactPreviewSimulationFields()
    {
        var plan = new RemediationPlan
        {
            Sections = new[]
            {
                new RemediationSection
                {
                    RuleId = "FW-001",
                    FindingSummary = "[High] Default policy ACCEPT",
                    RiskNote = "High risk",
                    ImpactPreview = new RemediationImpactPreview
                    {
                        ExpectedImpact = "Default INPUT policy will change to DROP.",
                        ExpectedImpactSource = RemediationImpactSource.SuggestedAction,
                        RiskBefore = "[High] High risk",
                        ExpectedRiskAfter = "Finding should be resolved after applying configuration changes.",
                        CommandCount = 2,
                        RollbackAvailable = true,
                        HasRestartImpact = true,
                        HasLockoutRisk = true,
                        RestartImpactDescription = "Service restart required.",
                        LockoutRiskDescription = "SSH access will be blocked.",
                        RollbackPath = "sudo iptables -P INPUT ACCEPT",
                        RollbackPathKind = RemediationPreviewTextKind.Command,
                        VerificationCommand = "sudo iptables -L INPUT | head -n 1",
                        IsVerificationCommand = true,
                        VerificationKind = RemediationPreviewTextKind.Command
                    },
                    ApplyCommands = new[]
                    {
                        new RemediationCommand { Command = "sudo iptables -P INPUT DROP", Safety = CommandSafety.ConfigChange }
                    },
                    RollbackCommands = new[]
                    {
                        new RemediationCommand { Command = "sudo iptables -P INPUT ACCEPT", Safety = CommandSafety.ConfigChange }
                    }
                }
            }
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.Format(plan);

        Assert.Contains("**Risk before:** [High] High risk", result);
        Assert.Contains("**Expected risk after:** Finding should be resolved after applying configuration changes.", result);
        Assert.Contains("**Commands involved:** 2", result);
        Assert.Contains("**Rollback available:** Yes", result);
        Assert.Contains("**Restart impact:** Service restart required.", result);
        Assert.Contains("**Lockout risk:** SSH access will be blocked.", result);
    }

    [Fact]
    public void Format_RollbackHint_NotWrappedInBackticks()
    {
        var plan = new RemediationPlan
        {
            Sections = new[]
            {
                new RemediationSection
                {
                    RuleId = "FW-001",
                    FindingSummary = "[High] Default policy ACCEPT",
                    RiskNote = "High risk",
                    ImpactPreview = new RemediationImpactPreview
                    {
                        ExpectedImpact = "Default INPUT policy will change to DROP.",
                        ExpectedImpactSource = RemediationImpactSource.SuggestedAction,
                        RollbackPath = "Revert iptables rules with -D instead of -A.",
                        RollbackPathKind = RemediationPreviewTextKind.GenericGuidance,
                        VerificationCommand = "sudo iptables -L INPUT | head -n 1",
                        IsVerificationCommand = true,
                        VerificationKind = RemediationPreviewTextKind.Command
                    },
                    ApplyCommands = new[]
                    {
                        new RemediationCommand { Command = "sudo iptables -P INPUT DROP", Safety = CommandSafety.ConfigChange }
                    },
                    RollbackCommands = Array.Empty<RemediationCommand>()
                }
            }
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.Format(plan);

        Assert.Contains("**Rollback:** Revert iptables rules with -D instead of -A.", result);
        Assert.DoesNotContain("**Rollback:** `Revert iptables rules", result);
    }

    [Fact]
    public void Format_VerificationFallback_NotWrappedInBackticks()
    {
        var plan = new RemediationPlan
        {
            Sections = new[]
            {
                new RemediationSection
                {
                    RuleId = "FW-001",
                    FindingSummary = "[High] Default policy ACCEPT",
                    RiskNote = "High risk",
                    ImpactPreview = new RemediationImpactPreview
                    {
                        ExpectedImpact = "Drop default.",
                        ExpectedImpactSource = RemediationImpactSource.SuggestedAction,
                        RollbackPath = "Revert iptables rules with -D instead of -A.",
                        RollbackPathKind = RemediationPreviewTextKind.GenericGuidance,
                        VerificationCommand = "Run verification manually after applying.",
                        IsVerificationCommand = false,
                        VerificationKind = RemediationPreviewTextKind.ManualFallback
                    },
                    ApplyCommands = new[]
                    {
                        new RemediationCommand { Command = "sudo iptables -P INPUT DROP", Safety = CommandSafety.ConfigChange }
                    }
                }
            }
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.Format(plan);

        Assert.Contains("**Verify:** Run verification manually after applying.", result);
        Assert.DoesNotContain("**Verify:** `Run verification manually after applying.`", result);
    }

    [Fact]
    public void Format_IncludesMitreTechniques_WhenPresent()
    {
        var plan = new RemediationPlan
        {
            Sections = new[]
            {
                new RemediationSection
                {
                    RuleId = "FW-001",
                    FindingSummary = "[High] Default policy ACCEPT",
                    RiskNote = "High risk",
                    MitreTechniques = new[]
                    {
                        new MitreTechnique { TechniqueId = "T1562.004", TechniqueName = "Disable or Modify System Firewall", Tactic = "Defense Evasion", WhyItMatters = "Firewall." }
                    },
                    ApplyCommands = new[]
                    {
                        new RemediationCommand { Command = "sudo iptables -P INPUT DROP", Safety = CommandSafety.ConfigChange }
                    }
                }
            }
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.Format(plan);

        Assert.Contains("T1562.004", result);
        Assert.Contains("Disable or Modify System Firewall", result);
        Assert.Contains("MITRE ATT&CK", result);
    }

    [Fact]
    public void Format_OmitsImpactPreview_WhenNull()
    {
        var plan = new RemediationPlan
        {
            Sections = new[]
            {
                new RemediationSection
                {
                    RuleId = "FW-001",
                    FindingSummary = "[High] Default policy ACCEPT",
                    RiskNote = "High risk",
                    ApplyCommands = new[]
                    {
                        new RemediationCommand { Command = "sudo iptables -P INPUT DROP", Safety = CommandSafety.ConfigChange }
                    }
                }
            }
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.Format(plan);

        Assert.DoesNotContain("**Impact Preview**", result);
        Assert.DoesNotContain("**Impact:**", result);
    }

    [Fact]
    public void FormatSession_IncludesTimeline()
    {
        var session = new RemediationSession
        {
            SessionId = "timeline1",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState>(),
            BlockedReasons = Array.Empty<string>(),
            Timeline = new[]
            {
                new RemediationSessionEvent
                {
                    TimestampUtc = new DateTime(2026, 6, 2, 14, 22, 10, DateTimeKind.Utc),
                    Type = RemediationSessionEventType.Created,
                    Title = "Session started for FW-001"
                },
                new RemediationSessionEvent
                {
                    TimestampUtc = new DateTime(2026, 6, 2, 14, 24, 1, DateTimeKind.Utc),
                    Type = RemediationSessionEventType.StepMarkedCompleted,
                    Title = "FW-001 marked completed",
                    RuleId = "FW-001"
                }
            }
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.FormatSession(session);

        Assert.Contains("## Timeline", result);
        Assert.Contains("2026-06-02 14:22:10 UTC — Created: Session started for FW-001", result);
        Assert.Contains("2026-06-02 14:24:01 UTC — StepMarkedCompleted: FW-001 marked completed", result);
    }

    [Fact]
    public void FormatSession_IncludesBlockedTimelineEvents()
    {
        var session = new RemediationSession
        {
            SessionId = "blocked1",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState> { ["FW-DANGER"] = RemediationStepState.Blocked },
            BlockedReasons = new[] { "[FW-DANGER] No rollback guidance" },
            Timeline = new[]
            {
                new RemediationSessionEvent
                {
                    TimestampUtc = DateTime.UtcNow,
                    Type = RemediationSessionEventType.StepBlocked,
                    Title = "FW-DANGER requires rollback guidance",
                    RuleId = "FW-DANGER",
                    Details = "[FW-DANGER] No rollback guidance"
                }
            }
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.FormatSession(session);

        Assert.Contains("## Timeline", result);
        Assert.Contains("StepBlocked: FW-DANGER requires rollback guidance", result);
        Assert.Contains("[FW-DANGER] No rollback guidance", result);
    }

    [Fact]
    public void FormatSession_IncludesVerificationTimelineEvents()
    {
        var session = new RemediationSession
        {
            SessionId = "verify1",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState>(),
            BlockedReasons = Array.Empty<string>(),
            VerificationResult = new SessionVerificationResult
            {
                FixedFindings = Array.Empty<AuditSnapshotFinding>(),
                UnchangedFindings = Array.Empty<AuditSnapshotFinding>(),
                NewFindings = Array.Empty<AuditSnapshotFinding>(),
                WorsenedFindings = Array.Empty<SeverityChangeFinding>(),
                DiffNarrative = "All clear."
            },
            Timeline = new[]
            {
                new RemediationSessionEvent
                {
                    TimestampUtc = new DateTime(2026, 6, 2, 14, 25, 33, DateTimeKind.Utc),
                    Type = RemediationSessionEventType.VerificationCompleted,
                    Title = "1 fixed, 0 unchanged, 0 new, 0 worsened",
                    Details = "All clear."
                }
            }
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.FormatSession(session);

        Assert.Contains("## Timeline", result);
        Assert.Contains("2026-06-02 14:25:33 UTC — VerificationCompleted: 1 fixed, 0 unchanged, 0 new, 0 worsened", result);
        Assert.Contains("All clear.", result);
    }

    [Fact]
    public void FormatSession_IncludesSessionNotes()
    {
        var session = new RemediationSession
        {
            SessionId = "notes1",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState>(),
            BlockedReasons = Array.Empty<string>(),
            Notes = new[]
            {
                new SessionNote
                {
                    CreatedAtUtc = new DateTime(2026, 6, 2, 14, 30, 0, DateTimeKind.Utc),
                    Text = "Changed firewall policy after confirming console access."
                }
            }
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.FormatSession(session);

        Assert.Contains("## Notes", result);
        Assert.Contains("### Session Notes", result);
        Assert.Contains("2026-06-02 14:30:00 UTC — Changed firewall policy after confirming console access.", result);
    }

    [Fact]
    public void FormatSession_IncludesStepNotes()
    {
        var session = new RemediationSession
        {
            SessionId = "notes2",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState>(),
            BlockedReasons = Array.Empty<string>(),
            Notes = new[]
            {
                new SessionNote
                {
                    CreatedAtUtc = new DateTime(2026, 6, 2, 14, 32, 0, DateTimeKind.Utc),
                    Text = "Backup saved to /tmp/fw-2026-06-02.rules.",
                    RuleId = "FW-001"
                }
            }
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.FormatSession(session);

        Assert.Contains("## Notes", result);
        Assert.Contains("### Step Notes", result);
        Assert.Contains("#### FW-001", result);
        Assert.Contains("2026-06-02 14:32:00 UTC — Backup saved to /tmp/fw-2026-06-02.rules.", result);
    }

    [Fact]
    public void FormatSession_IncludesEvidenceLinks()
    {
        var session = new RemediationSession
        {
            SessionId = "notes3",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState>(),
            BlockedReasons = Array.Empty<string>(),
            Notes = new[]
            {
                new SessionNote
                {
                    CreatedAtUtc = DateTime.UtcNow,
                    Text = "Verified with command output.",
                    RuleId = "FW-001",
                    EvidenceLinks = new[] { "/tmp/fw-2026-06-02.rules", "iptables -L -n" }
                }
            }
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.FormatSession(session);

        Assert.Contains("Evidence: `/tmp/fw-2026-06-02.rules`", result);
        Assert.Contains("Evidence: `iptables -L -n`", result);
    }

    [Fact]
    public void FormatSession_NoNotes_OmitsNotesSection()
    {
        var session = new RemediationSession
        {
            SessionId = "nonotes",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState>(),
            BlockedReasons = Array.Empty<string>()
        };

        var formatter = new RemediationMarkdownFormatter();
        var result = formatter.FormatSession(session);

        Assert.DoesNotContain("## Notes", result);
    }
}
