using System;
using System.Collections.ObjectModel;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Messages;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Agent.Suggestions;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class AgentResultPresenterTests
{
    [AvaloniaFact]
    public void PresentFindings_AddsCapabilitySummaryGroupsWarningsAndCategoryFilters()
    {
        var harness = new PresenterHarness();
        var result = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            Summary = "Full audit complete. 3 issue(s) found, 2 High/Critical. 2 check(s) passed.",
            CapabilityReport = "Data sources: ss available.",
            PassedCount = 2,
            AgentFindings = new[]
            {
                CreateFinding("FW-001", "Firewall", Severity.High, "SSH exposed"),
                CreateFinding("SSH-001", "SSH", Severity.Medium, "Root login enabled"),
                CreateFinding("FW-002", "Firewall", Severity.Critical, "Firewall disabled")
            },
            Warnings = new[] { "permission denied reading process details" }
        };

        harness.Presenter.PresentFindings(result);

        Assert.Contains(harness.Messages, m => m.Text == "Data sources: ss available." && m.IsInfo);
        Assert.Contains(harness.Messages, m => m.Text == "Full audit complete. 3 issue(s) found, 2 High/Critical. 2 check(s) passed." && !m.IsInfo);
        // The passed-count is already in the composer summary (the lead), so it isn't restated as a
        // standalone "✓ N checks passed" line.
        Assert.DoesNotContain(harness.Messages, m => m.Text.StartsWith("✓"));
        Assert.Contains(harness.Messages, m => m.Text == "Findings: 1 Critical, 1 High, 1 Medium (3 total)" && m.IsInfo);

        var firewallGroup = Assert.Single(harness.Messages, m => m.Category == "Firewall");
        Assert.Equal("[Firewall] 2 findings — 2 High/Critical", firewallGroup.Text);
        Assert.Equal(Severity.Critical, firewallGroup.Severity);
        Assert.Contains("[FW-002] [Critical] Firewall disabled", firewallGroup.Details);
        Assert.Contains("[FW-001] [High] SSH exposed", firewallGroup.Details);

        var sshGroup = Assert.Single(harness.Messages, m => m.Category == "SSH");
        Assert.Equal("[SSH] 1 finding", sshGroup.Text);
        Assert.Equal(Severity.Medium, sshGroup.Severity);

        Assert.Equal(new[] { ChatFilterConstants.AllCategoriesFilter, "Firewall", "SSH" }, harness.CategoryFilters.ToArray());
        Assert.Contains(harness.Messages, m => m.Text.Contains("blocked by permissions", StringComparison.OrdinalIgnoreCase) && m.IsInfo);
        Assert.True(harness.HasPrivilegeWarning);
        Assert.Contains("elevated privileges", harness.PrivilegeWarningText);
    }

    [AvaloniaFact]
    public void ApplyChatFilters_HidesOnlyFindingGroupsThatDoNotMatch()
    {
        var harness = new PresenterHarness();
        var result = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            Summary = "Audit complete",
            AgentFindings = new[]
            {
                CreateFinding("FW-001", "Firewall", Severity.High, "SSH exposed"),
                CreateFinding("SSH-001", "SSH", Severity.Medium, "Root login enabled"),
                CreateFinding("NET-001", "Network", Severity.Critical, "Promiscuous interface")
            }
        };
        harness.Presenter.PresentFindings(result);

        harness.SeverityFilter = new SeverityFilterOption("High & Critical only", Severity.High);
        harness.CategoryFilter = "Firewall";
        harness.Presenter.ApplyChatFilters();

        Assert.True(harness.Messages.Single(m => m.Category == "Firewall").IsVisible);
        Assert.False(harness.Messages.Single(m => m.Category == "SSH").IsVisible);
        Assert.False(harness.Messages.Single(m => m.Category == "Network").IsVisible);
        Assert.True(harness.Messages.Single(m => m.Text == "Audit complete").IsVisible);
        Assert.True(harness.Messages.Single(m => m.Text.StartsWith("Findings:")).IsVisible);

        harness.SeverityFilter = new SeverityFilterOption("Critical only", Severity.Critical);
        harness.CategoryFilter = ChatFilterConstants.AllCategoriesFilter;
        harness.Presenter.ApplyChatFilters();

        Assert.False(harness.Messages.Single(m => m.Category == "Firewall").IsVisible);
        Assert.False(harness.Messages.Single(m => m.Category == "SSH").IsVisible);
        Assert.True(harness.Messages.Single(m => m.Category == "Network").IsVisible);
    }

    [AvaloniaFact]
    public void AddAgentFinding_ExtractsVerificationCommandsFromDetails()
    {
        var harness = new PresenterHarness();
        var finding = CreateFinding("FW-001", "Firewall", Severity.High, "SSH exposed") with
        {
            Confidence = DetectionConfidence.High,
            EvidenceSignals =
            [
                new EvidenceSignal { Name = "Rule FW-001 triggered", Source = "SecurityRule", Explanation = "Detected exposed SSH" }
            ],
            Details = "**How to verify:**\n1. Check listening ports: `ss -tlnp`"
        };

        harness.Presenter.AddAgentFinding(finding);

        var message = Assert.Single(harness.Messages);
        Assert.Equal("[FW-001] [High] SSH exposed", message.Text);
        Assert.Equal(finding.Details, message.Details);
        Assert.Equal("High", message.Confidence);
        Assert.Equal("Rule FW-001 triggered", message.EvidenceSignalsDisplay);
        Assert.True(message.HasConfidence);
        Assert.True(message.HasEvidenceSignals);
        var command = Assert.Single(message.VerificationCommands);
        Assert.Equal("ss -tlnp", command.FullCommand);
        Assert.Equal(CommandSafety.ReadOnly, command.Safety);
        Assert.True(message.HasVerificationCommands);
    }

    [AvaloniaFact]
    public void AddAgentFinding_GroupedFinding_IncludesNoiseBudgetDetails()
    {
        var harness = new PresenterHarness();
        var finding = CreateFinding("FS-001", "FilesystemAudit", Severity.High, "World writable file") with
        {
            GroupedCount = 3,
            RepresentativeTargets = ["/tmp/a", "/tmp/b", "/var/log/c"],
            RiskDrivers = ["/tmp", "/var/log"]
        };

        harness.Presenter.AddAgentFinding(finding);

        var message = Assert.Single(harness.Messages);
        Assert.Equal("[FS-001] [High] World writable file x3", message.Text);
        Assert.Contains("Grouped findings: 3", message.Details);
        Assert.Contains("Representative targets: /tmp/a; /tmp/b; /var/log/c", message.Details);
        Assert.Contains("Risk drivers: /tmp; /var/log", message.Details);
    }

    [AvaloniaFact]
    public void PresentFindings_FixFindingWithSingleRemediationSection_AddsInteractiveMessage()
    {
        var harness = new PresenterHarness();
        var section = new RemediationSection
        {
            RuleId = "FW-001",
            FindingSummary = "[High] SSH exposed",
            RiskNote = "Remote access is exposed.",
            Preconditions = new[] { "Confirm maintenance window." },
            ApplyCommands = new[]
            {
                new RemediationCommand { Command = "sudo ufw allow from 10.0.0.5 to any port 22", Safety = CommandSafety.ConfigChange }
            },
            RollbackCommands = new[]
            {
                new RemediationCommand { Command = "sudo ufw delete allow from 10.0.0.5 to any port 22", Safety = CommandSafety.ConfigChange }
            },
            VerificationCommands = new[]
            {
                new RemediationCommand { Command = "sudo ufw status", Safety = CommandSafety.ReadOnly }
            },
            HasExplicitRollbackGuidance = true
        };
        var result = new AgentResult
        {
            Intent = AgentIntent.FixFinding,
            Summary = "Interactive remediation ready",
            RemediationPlan = new RemediationPlan { Sections = new[] { section } },
            AgentFindings = new[] { CreateFinding("FW-001", "Firewall", Severity.High, "SSH exposed") }
        };

        harness.Presenter.PresentFindings(result);

        var message = Assert.Single(harness.Messages);
        Assert.Equal("Interactive remediation ready", message.Text);
        Assert.Equal("Risk: Remote access is exposed.", message.Details);
        Assert.Equal(Severity.High, message.Severity);
        Assert.Same(section, message.RemediationSection);
        Assert.True(message.HasRemediationSection);
        Assert.True(message.HasPreconditions);
        Assert.True(message.HasApplyCommands);
        Assert.True(message.HasRollbackCommands);
        Assert.True(message.HasRemediationVerificationCommands);
        Assert.Equal("sudo ufw allow from 10.0.0.5 to any port 22", Assert.Single(message.RemediationApplyCommands).FullCommand);
    }

    [AvaloniaFact]
    public void PresentFindings_RespectsSuppressedReportSections()
    {
        var harness = new PresenterHarness();
        var result = new AgentResult
        {
            Intent = AgentIntent.ShowBaseline,
            Summary = "Baseline shown",
            CapabilityReport = "Data sources: hidden",
            PassedCount = 4,
            Warnings = new[] { "permission denied" }
        };

        harness.Presenter.PresentFindings(result, showCapabilityReport: false, showPassedCount: false, showWarnings: false);

        var message = Assert.Single(harness.Messages);
        Assert.Equal("Baseline shown", message.Text);
        Assert.False(harness.HasPrivilegeWarning);
    }

    private static Finding CreateFinding(string ruleId, string category, Severity severity, string description)
    {
        var now = DateTime.UtcNow;
        return new Finding
        {
            RuleId = ruleId,
            Category = category,
            Severity = severity,
            SourceHost = "localhost",
            Target = $"{category}-target",
            ShortDescription = description,
            Details = "Details",
            TimeRangeStart = now,
            TimeRangeEnd = now
        };
    }

    [AvaloniaFact]
    public void PresentFindings_StartRemediationWithSession_AddsSessionMessageWithActiveStatus()
    {
        var harness = new PresenterHarness();
        var section = new RemediationSection
        {
            RuleId = "FW-001",
            FindingSummary = "[High] SSH exposed",
            RiskNote = "Remote access is exposed.",
            Preconditions = new[] { "Confirm maintenance window." },
            ApplyCommands = new[]
            {
                new RemediationCommand { Command = "sudo ufw allow from 10.0.0.5 to any port 22", Safety = CommandSafety.ConfigChange }
            },
            RollbackCommands = Array.Empty<RemediationCommand>(),
            VerificationCommands = Array.Empty<RemediationCommand>()
        };
        var session = new RemediationSession
        {
            SessionId = "abc12345",
            SourceFindings = new[] { CreateFinding("FW-001", "Firewall", Severity.High, "SSH exposed") },
            RemediationPlan = new RemediationPlan { Sections = new[] { section } },
            StepStates = new Dictionary<string, RemediationStepState> { ["FW-001"] = RemediationStepState.Pending },
            BlockedReasons = Array.Empty<string>()
        };
        var result = new AgentResult
        {
            Intent = AgentIntent.StartRemediation,
            Summary = "Session created",
            RemediationPlan = session.RemediationPlan,
            RemediationSession = session,
            AgentFindings = session.SourceFindings
        };

        harness.Presenter.PresentFindings(result);

        var message = Assert.Single(harness.Messages);
        Assert.Equal("Session created", message.Text);
        Assert.Equal("abc12345", message.SessionId);
        Assert.Equal(RemediationSessionStatus.Active, message.SessionStatus);
        Assert.True(message.HasActiveSession);
        Assert.True(message.HasRemediationSection);
        Assert.Same(section, message.RemediationSection);
    }

    [AvaloniaFact]
    public void PresentFindings_VerifyRemediationWithSession_AddsVerificationResultMessage()
    {
        var harness = new PresenterHarness();
        var verificationResult = new SessionVerificationResult
        {
            FixedFindings = new[]
            {
                new AuditSnapshotFinding { RuleId = "FW-001", Target = "Firewall-target", Severity = "High", ShortDescription = "SSH exposed" }
            },
            UnchangedFindings = Array.Empty<AuditSnapshotFinding>(),
            NewFindings = Array.Empty<AuditSnapshotFinding>(),
            WorsenedFindings = Array.Empty<SeverityChangeFinding>(),
            DiffNarrative = "1 finding resolved."
        };
        var session = new RemediationSession
        {
            SessionId = "abc12345",
            Status = RemediationSessionStatus.Verified,
            SourceFindings = new[] { CreateFinding("FW-001", "Firewall", Severity.High, "SSH exposed") },
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState> { ["FW-001"] = RemediationStepState.Completed },
            VerificationResult = verificationResult,
            BlockedReasons = Array.Empty<string>()
        };
        var result = new AgentResult
        {
            Intent = AgentIntent.VerifyRemediation,
            Summary = "Verification result",
            RemediationSession = session,
            AgentFindings = session.SourceFindings
        };

        harness.Presenter.PresentFindings(result);

        var message = Assert.Single(harness.Messages);
        Assert.Equal("Verification result", message.Text);
        Assert.Equal("abc12345", message.SessionId);
        Assert.Equal(RemediationSessionStatus.Verified, message.SessionStatus);
        Assert.True(message.IsVerificationResult);
        Assert.False(message.HasActiveSession);
    }

    [AvaloniaFact]
    public void PresentFindings_StartRemediation_IncludesTimeline()
    {
        var harness = new PresenterHarness();
        var section = new RemediationSection
        {
            RuleId = "FW-001",
            FindingSummary = "[High] SSH exposed",
            RiskNote = "Remote access is exposed.",
            Preconditions = Array.Empty<string>(),
            ApplyCommands = Array.Empty<RemediationCommand>(),
            RollbackCommands = Array.Empty<RemediationCommand>(),
            VerificationCommands = Array.Empty<RemediationCommand>()
        };
        var session = new RemediationSession
        {
            SessionId = "abc12345",
            SourceFindings = new[] { CreateFinding("FW-001", "Firewall", Severity.High, "SSH exposed") },
            RemediationPlan = new RemediationPlan { Sections = new[] { section } },
            StepStates = new Dictionary<string, RemediationStepState> { ["FW-001"] = RemediationStepState.Pending },
            BlockedReasons = Array.Empty<string>(),
            Timeline = new[]
            {
                new RemediationSessionEvent
                {
                    TimestampUtc = DateTime.UtcNow,
                    Type = RemediationSessionEventType.Created,
                    Title = "Session started for FW-001"
                }
            }
        };
        var result = new AgentResult
        {
            Intent = AgentIntent.StartRemediation,
            Summary = "Session created",
            RemediationPlan = session.RemediationPlan,
            RemediationSession = session,
            AgentFindings = session.SourceFindings
        };

        harness.Presenter.PresentFindings(result);

        var message = Assert.Single(harness.Messages);
        Assert.True(message.HasSessionTimeline);
        Assert.Single(message.SessionTimeline);
        Assert.Equal(RemediationSessionEventType.Created, message.SessionTimeline[0].Type);
    }

    [AvaloniaFact]
    public void PresentFindings_VerifyRemediation_IncludesUpdatedTimeline()
    {
        var harness = new PresenterHarness();
        var session = new RemediationSession
        {
            SessionId = "abc12345",
            Status = RemediationSessionStatus.Verified,
            SourceFindings = new[] { CreateFinding("FW-001", "Firewall", Severity.High, "SSH exposed") },
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState> { ["FW-001"] = RemediationStepState.Completed },
            VerificationResult = new SessionVerificationResult
            {
                FixedFindings = Array.Empty<AuditSnapshotFinding>(),
                UnchangedFindings = Array.Empty<AuditSnapshotFinding>(),
                NewFindings = Array.Empty<AuditSnapshotFinding>(),
                WorsenedFindings = Array.Empty<SeverityChangeFinding>(),
                DiffNarrative = "All clear."
            },
            BlockedReasons = Array.Empty<string>(),
            Timeline = new[]
            {
                new RemediationSessionEvent
                {
                    TimestampUtc = DateTime.UtcNow,
                    Type = RemediationSessionEventType.Created,
                    Title = "Session started for FW-001"
                },
                new RemediationSessionEvent
                {
                    TimestampUtc = DateTime.UtcNow,
                    Type = RemediationSessionEventType.VerificationCompleted,
                    Title = "1 fixed, 0 unchanged, 0 new, 0 worsened"
                }
            }
        };
        var result = new AgentResult
        {
            Intent = AgentIntent.VerifyRemediation,
            Summary = "Verification result",
            RemediationSession = session,
            AgentFindings = session.SourceFindings
        };

        harness.Presenter.PresentFindings(result);

        var message = Assert.Single(harness.Messages);
        Assert.True(message.HasSessionTimeline);
        Assert.Equal(2, message.SessionTimeline.Count);
        Assert.Equal(RemediationSessionEventType.VerificationCompleted, message.SessionTimeline[1].Type);
    }

    [AvaloniaFact]
    public void PresentFindings_AddSessionNote_RendersConciseConfirmation()
    {
        var harness = new PresenterHarness();
        var session = new RemediationSession
        {
            SessionId = "abc12345",
            Status = RemediationSessionStatus.Active,
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState>(),
            BlockedReasons = Array.Empty<string>(),
            Notes = new[]
            {
                new SessionNote
                {
                    Text = "Changed firewall policy after confirming console access.",
                    EvidenceLinks = new[] { "/tmp/fw-2026-06-02.rules" }
                }
            },
            Timeline = new[]
            {
                new RemediationSessionEvent
                {
                    TimestampUtc = DateTime.UtcNow,
                    Type = RemediationSessionEventType.Created,
                    Title = "Session started"
                }
            }
        };
        var result = new AgentResult
        {
            Intent = AgentIntent.AddSessionNote,
            Summary = "Full session summary that should not be rendered",
            RemediationSession = session,
            AgentFindings = Array.Empty<Finding>()
        };

        harness.Presenter.PresentFindings(result);

        var message = Assert.Single(harness.Messages);
        Assert.True(message.IsInfo);
        Assert.Equal("Note added to session abc12345 (1 evidence link(s)): Changed firewall policy after confirming console access.", message.Text);
        Assert.Equal("abc12345", message.SessionId);
        Assert.True(message.HasSessionTimeline);
    }

    [AvaloniaFact]
    public void PresentFindings_AddStepNote_RendersConciseConfirmation()
    {
        var harness = new PresenterHarness();
        var session = new RemediationSession
        {
            SessionId = "abc12345",
            Status = RemediationSessionStatus.Active,
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState>(),
            BlockedReasons = Array.Empty<string>(),
            Notes = new[]
            {
                new SessionNote
                {
                    Text = "Backup saved to /tmp/backup.rules.",
                    RuleId = "FW-001"
                }
            }
        };
        var result = new AgentResult
        {
            Intent = AgentIntent.AddStepNote,
            Summary = "Full session summary that should not be rendered",
            RemediationSession = session,
            AgentFindings = Array.Empty<Finding>()
        };

        harness.Presenter.PresentFindings(result);

        var message = Assert.Single(harness.Messages);
        Assert.True(message.IsInfo);
        Assert.Equal("Note added to step FW-001 in session abc12345: Backup saved to /tmp/backup.rules.", message.Text);
        Assert.Equal("abc12345", message.SessionId);
    }

    [AvaloniaFact]
    public void PresentFindings_AddSessionNote_NoNotes_FallsBackToSummary()
    {
        var harness = new PresenterHarness();
        var session = new RemediationSession
        {
            SessionId = "abc12345",
            Status = RemediationSessionStatus.Active,
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState>(),
            BlockedReasons = Array.Empty<string>()
        };
        var result = new AgentResult
        {
            Intent = AgentIntent.AddSessionNote,
            Summary = "Session not found.",
            RemediationSession = session,
            AgentFindings = Array.Empty<Finding>()
        };

        harness.Presenter.PresentFindings(result);

        var message = Assert.Single(harness.Messages);
        Assert.Equal("Session not found.", message.Text);
    }

    [AvaloniaFact]
    public void AgentMessageViewModel_HasActiveSession_TrueOnlyWhenActive()
    {
        var msg = new AgentMessageViewModel { SessionId = "abc", SessionStatus = RemediationSessionStatus.Active };
        Assert.True(msg.HasActiveSession);

        msg.SessionStatus = RemediationSessionStatus.Verified;
        Assert.False(msg.HasActiveSession);

        msg.SessionStatus = RemediationSessionStatus.Completed;
        Assert.False(msg.HasActiveSession);

        msg.SessionStatus = RemediationSessionStatus.Blocked;
        Assert.False(msg.HasActiveSession);

        msg.SessionId = "";
        msg.SessionStatus = RemediationSessionStatus.Active;
        Assert.False(msg.HasActiveSession);
    }

    [AvaloniaFact]
    public void PresentFindings_AttachesSuggestionsToSummaryMessage()
    {
        var harness = new PresenterHarness();
        var result = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            Summary = "Audit complete",
            AgentFindings = new[] { CreateFinding("FW-001", "Firewall", Severity.High, "SSH exposed") },
            Suggestions = new[]
            {
                new SuggestedFollowUp { Label = "Fix it", Query = "fix FW-001", Intent = AgentIntent.FixFinding }
            }
        };

        harness.Presenter.PresentFindings(result);

        var summary = Assert.Single(harness.Messages, m => m.Text == "Audit complete");
        Assert.True(summary.HasSuggestions);
        Assert.Single(summary.Suggestions);
        Assert.NotNull(summary.SuggestionCommand);
    }

    [AvaloniaFact]
    public void PresentFindings_AuditWithMissingTool_LeadsWithFriendlyMissingToolLine()
    {
        var harness = new PresenterHarness();
        var result = new AgentResult
        {
            Intent = AgentIntent.FirewallCheck,
            Summary = "Firewall check complete. 0 issue(s).",
            PassedCount = 2,
            AgentFindings = new[] { CreateFinding("FW-001", "Firewall", Severity.High, "SSH exposed") },
            Warnings = new[] { "iptables command not found" }
        };

        harness.Presenter.PresentFindings(result);

        // The missing-tool lead (BuildMissingToolLead) opens with "I ran a firewall check. <message>",
        // replacing the denser composer summary (result.Summary) for this case only.
        var lead = Assert.Single(harness.Messages, m => m.Text.StartsWith("I ran a firewall check.", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("iptables", lead.Text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(harness.Messages, m => m.Text == "Firewall check complete. 0 issue(s).");
        // The missing-tool lead already conveys the passed-checks count, so the standalone "✓ N checks passed" line is suppressed.
        Assert.DoesNotContain(harness.Messages, m => m.Text.StartsWith("✓"));
        // The missing-tool message body lives only in the lead — not duplicated as a standalone warning.
        Assert.Single(harness.Messages, m => m.Text.Contains("couldn't inspect active firewall rules", StringComparison.OrdinalIgnoreCase));
    }

    [AvaloniaFact]
    public void AddUserMessage_WhileSearchActive_RespectsSearchWithoutFlash()
    {
        var harness = new PresenterHarness();
        harness.Messages.Add(new AgentMessageViewModel { Text = "firewall rule found", IsVisible = true });
        harness.Presenter.SetSearchQuery("firewall");

        harness.Presenter.AddUserMessage("network port open");

        Assert.False(harness.Messages[1].IsVisible);
    }

    [AvaloniaFact]
    public void AddAgentMessage_WhileSearchActive_RespectsSearchWithoutFlash()
    {
        var harness = new PresenterHarness();
        harness.Messages.Add(new AgentMessageViewModel { Text = "firewall rule found", IsVisible = true });
        harness.Presenter.SetSearchQuery("firewall");

        harness.Presenter.AddAgentMessage("network port open", isInfo: true);

        Assert.False(harness.Messages[1].IsVisible);
    }

    [AvaloniaFact]
    public void DirectMessagesAdd_WhileSearchActive_IsFilteredByPresenter()
    {
        var harness = new PresenterHarness();
        harness.Messages.Add(new AgentMessageViewModel { Text = "firewall rule found", IsVisible = true });
        harness.Presenter.SetSearchQuery("firewall");

        harness.Messages.Add(new AgentMessageViewModel
        {
            Text = "Critical chain detected — ssh exposed",
            Details = "Risk note",
            IsUser = false,
            IsInfo = false,
            Severity = Severity.Critical,
            Timestamp = DateTime.Now
        });

        Assert.False(harness.Messages[1].IsVisible);
    }

    [AvaloniaFact]
    public void PresentFindings_BulkAdd_AppliesFiltersOnceAtEnd()
    {
        var spy = new PresenterHarness.CountingChatFilter();
        var harness = new PresenterHarness(spy);
        harness.Messages.Add(new AgentMessageViewModel { Text = "firewall rule found", IsVisible = true });
        harness.Presenter.SetSearchQuery("firewall");

        var result = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            Summary = "Audit complete",
            AgentFindings = new[]
            {
                CreateFinding("SSH-001", "SSH", Severity.High, "Root login enabled"),
                CreateFinding("NET-001", "Network", Severity.Critical, "Promiscuous interface")
            }
        };

        var filterCountBefore = spy.ApplyCount;

        harness.Presenter.PresentFindings(result);

        // The bulk presentation must apply filters exactly once (at the end), not on every add.
        Assert.Equal(filterCountBefore + 1, spy.ApplyCount);

        // The bulk-added audit messages (summary, group summary, SSH/Network group headers) contain
        // no "firewall" token, so the active search must hide every one of them after the terminal pass.
        Assert.All(harness.Messages.Where(m => !m.Text.Contains("firewall", StringComparison.OrdinalIgnoreCase)), m => Assert.False(m.IsVisible));
        // The original matching message should remain visible.
        Assert.True(harness.Messages[0].IsVisible);
    }

    [AvaloniaFact]
    public void AddAgentFinding_WhileSearchActive_IsFilteredByPresenter()
    {
        var harness = new PresenterHarness();
        harness.Messages.Add(new AgentMessageViewModel { Text = "firewall rule found", IsVisible = true });
        harness.Presenter.SetSearchQuery("firewall");

        harness.Presenter.AddAgentFinding(CreateFinding("SSH-001", "SSH", Severity.High, "Root login enabled"));

        Assert.False(harness.Messages[1].IsVisible);
    }

    private sealed class PresenterHarness
    {
        public ObservableCollection<AgentMessageViewModel> Messages { get; } = new();
        public ObservableCollection<string> CategoryFilters { get; } = new();
        public SeverityFilterOption? SeverityFilter { get; set; }
        public string? CategoryFilter { get; set; }
        public bool HasPrivilegeWarning { get; private set; }
        public string PrivilegeWarningText { get; private set; } = string.Empty;
        public AgentResultPresenter Presenter { get; }

        public PresenterHarness(IChatFilter? chatFilter = null, IPinnedMessageStore? pinnedMessageStore = null)
        {
            Presenter = new AgentResultPresenter(
                Messages,
                CategoryFilters,
                () => SeverityFilter,
                () => CategoryFilter,
                value => HasPrivilegeWarning = value,
                text => PrivilegeWarningText = text,
                _ => Task.CompletedTask,
                chatFilter: chatFilter,
                pinnedMessageStore: pinnedMessageStore);
        }

        // A counting decorator over the real DefaultChatFilter: it records how many times Apply ran
        // AND applies the real filter, so a test can assert both the call count and the resulting
        // visibility in one harness. (A pure counter that force-sets IsVisible=true would make any
        // correctness assertion vacuous.)
        public sealed class CountingChatFilter : IChatFilter
        {
            private readonly DefaultChatFilter _inner = new();

            public int ApplyCount { get; private set; }

            public void Apply(
                IReadOnlyList<AgentMessageViewModel> messages,
                SeverityFilterOption? severityFilter,
                string? categoryFilter,
                string? searchQuery)
            {
                ApplyCount++;
                _inner.Apply(messages, severityFilter, categoryFilter, searchQuery);
            }
        }
    }

    [AvaloniaFact]
    public void AddAgentMessage_SetsMessageId()
    {
        var harness = new PresenterHarness();

        harness.Presenter.AddAgentMessage("hello", true);

        var message = Assert.Single(harness.Messages);
        Assert.False(string.IsNullOrWhiteSpace(message.MessageId));
    }

    [AvaloniaFact]
    public void AddAgentMessage_NewInstanceSameContent_DoesNotInheritPin()
    {
        var store = new InMemoryPinnedMessageStore();
        var harness = new PresenterHarness(pinnedMessageStore: store);
        var message = harness.Presenter.AddAgentMessage("hello", true);
        store.Pin(message.ToPinnedMessage());

        // Each AddAgentMessage gets a fresh MessageId, so a second message with identical content
        // is a distinct instance and must NOT inherit the original's pin.
        var harness2 = new PresenterHarness(pinnedMessageStore: store);
        var replay = harness2.Presenter.AddAgentMessage("hello", true);

        Assert.False(replay.IsPinned);
        Assert.NotEqual(message.MessageId, replay.MessageId);
    }

    [AvaloniaFact]
    public void AddAgentMessage_WhenMessageIdExplicitlyRestored_MarksPinned()
    {
        var store = new InMemoryPinnedMessageStore();
        var harness = new PresenterHarness(pinnedMessageStore: store);
        var message = harness.Presenter.AddAgentMessage("hello", true);
        var savedId = message.MessageId;
        store.Pin(message.ToPinnedMessage());

        // Restoring the same GUID (e.g. from persisted state) must restore the pin.
        var harness2 = new PresenterHarness(pinnedMessageStore: store);
        var replay = harness2.Presenter.AddAgentMessage("hello", true);
        replay.MessageId = savedId;
        harness2.Presenter.RefreshPinnedState(replay);

        Assert.True(replay.IsPinned);
        Assert.Equal(savedId, replay.MessageId);
    }

    [AvaloniaFact]
    public void AddUserMessage_SetsMessageId()
    {
        var harness = new PresenterHarness();

        harness.Presenter.AddUserMessage("user question");

        var message = Assert.Single(harness.Messages);
        Assert.False(string.IsNullOrWhiteSpace(message.MessageId));
    }
}
