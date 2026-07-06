using System;
using System.Collections.Immutable;
using System.Text.RegularExpressions;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

internal sealed class GuidedRemediationService
{
    private readonly AgentAuditState _auditState;
    private readonly RemediationPlanBuilder _planBuilder;
    private readonly ISessionStore? _sessionStore;
    private readonly Func<AgentIntent, string?, IProgress<AgentAuditProgress>?, CancellationToken, Task<AgentResult>>? _runAudit;
    private readonly StepOutcomeParser _outcomeParser;
    private readonly FailureResponseTable _failureResponseTable;

    public GuidedRemediationService(
        AgentAuditState auditState,
        RemediationPlanBuilder planBuilder,
        ISessionStore? sessionStore = null,
        Func<AgentIntent, string?, IProgress<AgentAuditProgress>?, CancellationToken, Task<AgentResult>>? runAudit = null,
        StepOutcomeParser? outcomeParser = null,
        FailureResponseTable? failureResponseTable = null)
    {
        _auditState = auditState ?? throw new ArgumentNullException(nameof(auditState));
        _planBuilder = planBuilder ?? throw new ArgumentNullException(nameof(planBuilder));
        _sessionStore = sessionStore;
        _runAudit = runAudit;
        _outcomeParser = outcomeParser ?? new StepOutcomeParser();
        _failureResponseTable = failureResponseTable ?? new FailureResponseTable();
    }

    public Task<AgentResult> HandlePrioritizeRemediationAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_auditState.LastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.PrioritizeRemediation,
                Summary = "Run an audit first, then ask me what to fix first.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        if (_auditState.LastResult.AgentFindings.Count == 0)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.PrioritizeRemediation,
                Summary = "No active findings to remediate. Great job!",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var plan = _planBuilder.Build(_auditState.LastResult.AgentFindings);
        var sorted = plan.Sections.OrderByDescending(s => ParseSeverityFromSummary(s.FindingSummary)).ToList();
        var sortedPlan = plan with { Sections = sorted };

        var parts = new List<string> { "**Remediation Plan — Fix in this order**", "" };
        for (int i = 0; i < sorted.Count; i++)
        {
            var section = sorted[i];
            parts.Add($"{i + 1}. {section.FindingSummary}");
            if (!string.IsNullOrWhiteSpace(section.RiskNote))
            {
                parts.Add($"   Risk: {section.RiskNote}");
            }
            if (section.ApplyCommands.Count > 0)
            {
                parts.Add($"   Action: `{section.ApplyCommands[0].Command}`");
            }
            parts.Add("");
        }

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.PrioritizeRemediation,
            Summary = string.Join("\n", parts),
            AgentFindings = _auditState.LastResult.AgentFindings.OrderByDescending(f => f.Severity).ToList(),
            RemediationPlan = sortedPlan,
            Warnings = Array.Empty<string>()
        });
    }

    public Task<AgentResult> HandleFixFindingAsync(AgentQuery agentQuery, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_auditState.LastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.FixFinding,
                Summary = "Run an audit first, then ask me to fix a specific finding (e.g., \"fix FW-001\").",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var reference = agentQuery.TargetReference;
        if (string.IsNullOrWhiteSpace(reference))
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.FixFinding,
                Summary = "Please specify which finding to fix (e.g., **fix FW-001**).",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var matched = _auditState.FindPreviousFinding(reference);
        if (matched == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.FixFinding,
                Summary = $"I couldn't find finding **{reference}** in the last audit. Run an audit first or check the finding ID.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var plan = _planBuilder.Build(new[] { matched });
        var section = plan.Sections.FirstOrDefault();

        if (section == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.FixFinding,
                Summary = $"I found **{reference}** but couldn't build a remediation plan for it.",
                AgentFindings = new[] { matched },
                Warnings = Array.Empty<string>()
            });
        }

        var validation = RemediationPlanValidator.Validate(plan);
        if (!validation.IsValid)
        {
            var parts = new List<string>
            {
                $"**Cannot guide remediation for {reference}**",
                "",
                "This finding has risky or unclassified commands that lack explicit rollback guidance. The plan was blocked for safety.",
                ""
            };
            foreach (var err in validation.Errors)
            {
                parts.Add($"  • {err}");
            }
            parts.Add("");
            parts.Add("Please review the explanation template and ensure rollback commands are provided.");

            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.FixFinding,
                Summary = string.Join("\n", parts),
                AgentFindings = new[] { matched },
                Warnings = validation.Errors.ToList()
            });
        }

        var summaryParts = new List<string>
        {
            $"**Interactive Remediation: {section.RuleId}**",
            "",
            $"{section.FindingSummary}",
            ""
        };

        if (section.Preconditions.Count > 0)
        {
            summaryParts.Add("**Preconditions:**");
            foreach (var pre in section.Preconditions)
            {
                summaryParts.Add($"  • {pre}");
            }
            summaryParts.Add("");
        }

        if (section.BackupCommands.Count > 0)
        {
            summaryParts.Add($"**Backup ({section.BackupCommands.Count} command(s)):** Run these first to preserve state.");
            summaryParts.Add("");
        }

        summaryParts.Add($"**Apply ({section.ApplyCommands.Count} command(s)):** Step-by-step fix commands.");
        summaryParts.Add("");

        if (section.RollbackCommands.Count > 0 || section.RollbackHints.Count > 0)
        {
            summaryParts.Add($"**Rollback:** Available if something goes wrong.");
            summaryParts.Add("");
        }

        if (section.VerificationCommands.Count > 0)
        {
            summaryParts.Add($"**Verify ({section.VerificationCommands.Count} command(s)):** Confirm the fix worked.");
            summaryParts.Add("");
        }

        summaryParts.Add("Review each command before running it. Use the **Copy** button to grab commands.");

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.FixFinding,
            Summary = string.Join("\n", summaryParts),
            AgentFindings = new[] { matched },
            RemediationPlan = plan,
            Warnings = Array.Empty<string>()
        });
    }

    public Task<AgentResult> CreateSessionAsync(string findingReference, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_auditState.LastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = "Run an audit first, then start a remediation session (e.g., \"remediate FW-001\").",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        if (string.IsNullOrWhiteSpace(findingReference))
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = "Please specify which finding to remediate (e.g., **remediate FW-001**).",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var matched = _auditState.FindPreviousFinding(findingReference);
        if (matched == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = $"I couldn't find finding **{findingReference}** in the last audit. Run an audit first or check the finding ID.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var findings = new[] { matched };
        var plan = _planBuilder.Build(findings);
        var validation = RemediationPlanValidator.Validate(plan);

        var stepStates = new Dictionary<string, RemediationStepState>();
        var blockedReasons = new List<string>();

        foreach (var section in plan.Sections)
        {
            var sectionErrors = validation.Errors.Where(e => e.StartsWith($"[{section.RuleId}]", StringComparison.Ordinal)).ToList();
            if (!validation.IsValid && sectionErrors.Count > 0)
            {
                stepStates[section.RuleId] = RemediationStepState.Blocked;
                blockedReasons.AddRange(sectionErrors);
            }
            else
            {
                stepStates[section.RuleId] = RemediationStepState.Pending;
            }
        }

        var beforeSnapshot = CaptureSnapshot(_auditState.LastResult);
        var isBlocked = stepStates.Count > 0 && stepStates.Values.All(s => s == RemediationStepState.Blocked);

        var session = new RemediationSession
        {
            SessionId = Guid.NewGuid().ToString("N")[..8],
            SourceFindings = findings,
            RemediationPlan = plan,
            StepStates = stepStates,
            BeforeSnapshot = beforeSnapshot,
            Status = isBlocked ? RemediationSessionStatus.Blocked : RemediationSessionStatus.Active,
            BlockedReasons = blockedReasons,
            Timeline = Array.Empty<RemediationSessionEvent>()
        };

        session = AppendEvent(session, RemediationSessionEventType.Created, $"Session started for {findingReference}");

        foreach (var reason in blockedReasons)
        {
            var ruleId = ExtractRuleIdFromBlockedReason(reason);
            var title = ruleId != null
                ? $"{ruleId} requires rollback guidance"
                : "Blocked step requires rollback guidance";
            session = AppendEvent(session, RemediationSessionEventType.StepBlocked, title, ruleId, reason);
        }

        _sessionStore?.Save(session);

        return Task.FromResult(BuildSessionResult(session));
    }

    public AgentResult UpdateStepState(string sessionId, string ruleId, RemediationStepState state, string? failureReason = null)
    {
        if (_sessionStore == null)
        {
            return new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = "Session persistence is not available.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        var session = _sessionStore.Load(sessionId);
        if (session == null)
        {
            return new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = $"Session **{sessionId}** not found.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        if (!session.RemediationPlan.Sections.Any(s => s.RuleId == ruleId))
        {
            return new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = $"Step **{ruleId}** does not exist in this session's remediation plan.",
                AgentFindings = session.SourceFindings,
                Warnings = Array.Empty<string>()
            };
        }

        var current = session.StepStates.GetValueOrDefault(ruleId);
        if (current == RemediationStepState.Blocked && state != RemediationStepState.Blocked)
        {
            return new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = $"Cannot change step **{ruleId}** — it is blocked due to safety concerns.",
                AgentFindings = session.SourceFindings,
                Warnings = Array.Empty<string>()
            };
        }

        var updatedSteps = new Dictionary<string, RemediationStepState>(session.StepStates)
        {
            [ruleId] = state
        };

        var updatedFailureReasons = new Dictionary<string, string>(session.StepFailureReasons, StringComparer.OrdinalIgnoreCase);
        if (state == RemediationStepState.Failed && !string.IsNullOrWhiteSpace(failureReason))
        {
            updatedFailureReasons[ruleId] = failureReason.Trim();
        }
        else if (state != RemediationStepState.Failed && updatedFailureReasons.ContainsKey(ruleId))
        {
            updatedFailureReasons.Remove(ruleId);
        }

        var eventType = state switch
        {
            RemediationStepState.Pending => RemediationSessionEventType.StepMarkedPending,
            RemediationStepState.InProgress => RemediationSessionEventType.StepMarkedInProgress,
            RemediationStepState.Completed => RemediationSessionEventType.StepMarkedCompleted,
            RemediationStepState.Skipped => RemediationSessionEventType.StepMarkedSkipped,
            RemediationStepState.Blocked => RemediationSessionEventType.StepBlocked,
            RemediationStepState.Failed => RemediationSessionEventType.StepMarkedFailed,
            _ => RemediationSessionEventType.StepMarkedPending
        };

        var eventTitle = state == RemediationStepState.Failed && !string.IsNullOrWhiteSpace(failureReason)
            ? $"{ruleId} marked failed: {failureReason.Trim()}"
            : $"{ruleId} marked {state.ToString().ToLowerInvariant()}";

        var updatedSession = AppendEvent(session, eventType, eventTitle, ruleId, failureReason);

        var allCompleted = updatedSteps.Values.All(s => s is RemediationStepState.Completed or RemediationStepState.Skipped);
        var newStatus = updatedSession.Status switch
        {
            // A failed or otherwise non-terminal step reopens a finished session.
            RemediationSessionStatus.Completed or RemediationSessionStatus.Verified when !allCompleted
                => RemediationSessionStatus.Active,
            // A verified session stays verified when steps are re-marked completed/skipped;
            // it must not regress to merely "completed" from a no-op update.
            RemediationSessionStatus.Verified
                => RemediationSessionStatus.Verified,
            _ => allCompleted ? RemediationSessionStatus.Completed : updatedSession.Status
        };

        updatedSession = updatedSession with
        {
            StepStates = updatedSteps,
            StepFailureReasons = updatedFailureReasons,
            Status = newStatus
        };

        _sessionStore.Save(updatedSession);

        return BuildSessionResult(updatedSession);
    }

    public Task<AgentResult> HandleReportStepResultAsync(AgentQuery query, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_sessionStore == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ReportStepResult,
                Summary = "Session persistence is not available.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var sessionId = ResolveSessionId(query);
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ReportStepResult,
                Summary = "Please specify which remediation session you're updating (e.g., **FW-001 failed in session abc12345** or **step 1 failed**).",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var session = _sessionStore.Load(sessionId);
        if (session == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ReportStepResult,
                Summary = $"Session **{sessionId}** not found. Use **list sessions** to see available sessions.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var report = _outcomeParser.Parse(query.RawQuery);
        var ruleId = ResolveTargetRuleId(session, report);

        if (string.IsNullOrWhiteSpace(ruleId))
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ReportStepResult,
                Summary = "I couldn't tell which step you're reporting on. Try **FW-001 failed**, **FW-001 done**, or **step 1 failed** (use the rule ID or the step number shown in your plan).",
                AgentFindings = session.SourceFindings,
                RemediationSession = session,
                Warnings = Array.Empty<string>()
            });
        }

        if (report.Kind == StepOutcomeKind.Success)
        {
            var updateResult = UpdateStepState(sessionId, ruleId, RemediationStepState.Completed);
            var updatedSession = updateResult.RemediationSession ?? session;
            return Task.FromResult(BuildStepOutcomeResult(updatedSession, ruleId, success: true, report: report));
        }

        var failureReason = report.FailureReason ?? "Unknown failure";
        var failureResult = UpdateStepState(sessionId, ruleId, RemediationStepState.Failed, failureReason);
        var failedSession = failureResult.RemediationSession ?? session;
        return Task.FromResult(BuildStepOutcomeResult(failedSession, ruleId, success: false, failureReason, query.RawQuery, report));
    }

    public Task<AgentResult> RunVerificationAsync(string sessionId, CancellationToken ct) =>
        RunVerificationAsync(sessionId, null, ct);

    public async Task<AgentResult> RunVerificationAsync(string sessionId, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_sessionStore == null)
        {
            return new AgentResult
            {
                Intent = AgentIntent.VerifyRemediation,
                Summary = "Session persistence is not available.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        if (_runAudit == null)
        {
            return new AgentResult
            {
                Intent = AgentIntent.VerifyRemediation,
                Summary = "Verification requires an audit runner.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        var session = _sessionStore.Load(sessionId);
        if (session == null)
        {
            return new AgentResult
            {
                Intent = AgentIntent.VerifyRemediation,
                Summary = $"Session **{sessionId}** not found.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        if (session.BeforeSnapshot == null)
        {
            var blockedSnapshotSession = AppendEvent(session, RemediationSessionEventType.VerificationBlocked,
                $"Session **{sessionId}** has no before snapshot to compare against.");
            _sessionStore.Save(blockedSnapshotSession);
            return new AgentResult
            {
                Intent = AgentIntent.VerifyRemediation,
                Summary = $"Session **{sessionId}** has no before snapshot to compare against.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        if (session.Status == RemediationSessionStatus.Blocked)
        {
            var blockedSession = AppendEvent(session, RemediationSessionEventType.VerificationBlocked,
                $"Session **{sessionId}** is blocked due to safety concerns and cannot be verified as a completed remediation.");
            _sessionStore.Save(blockedSession);
            return new AgentResult
            {
                Intent = AgentIntent.VerifyRemediation,
                Summary = $"Session **{sessionId}** is blocked due to safety concerns and cannot be verified as a completed remediation.",
                AgentFindings = session.SourceFindings,
                Warnings = session.BlockedReasons
            };
        }

        var savedState = _auditState.SnapshotState();
        try
        {
            session = AppendEvent(session, RemediationSessionEventType.VerificationStarted,
                $"Verification started for session {sessionId}");
            _sessionStore.Save(session);

            var auditResult = await _runAudit(session.BeforeSnapshot!.Intent, null, progress, ct);
            var afterSnapshot = CaptureSnapshot(auditResult);

            var beforeEntry = ToHistoryEntry(session.BeforeSnapshot);
            var afterEntry = ToHistoryEntry(afterSnapshot);
            var diff = AuditDiffCalculator.Calculate(beforeEntry, afterEntry);

            var verificationResult = new SessionVerificationResult
            {
                FixedFindings = diff.ResolvedFindings.Select(f => ToSnapshotFinding(f)).ToList(),
                UnchangedFindings = diff.UnchangedFindings.Select(f => ToSnapshotFinding(f)).ToList(),
                NewFindings = diff.NewFindings.Select(f => ToSnapshotFinding(f)).ToList(),
                WorsenedFindings = diff.WorsenedFindings.ToList(),
                DiffNarrative = diff.Narrative,
                VerifiedAtUtc = DateTime.UtcNow
            };

            var updatedSession = AppendEvent(session, RemediationSessionEventType.VerificationCompleted,
                $"{verificationResult.FixedFindings.Count} fixed, {verificationResult.UnchangedFindings.Count} unchanged, {verificationResult.NewFindings.Count} new, {verificationResult.WorsenedFindings.Count} worsened",
                details: diff.Narrative);

            updatedSession = updatedSession with
            {
                AfterSnapshot = afterSnapshot,
                VerificationResult = verificationResult,
                Status = RemediationSessionStatus.Verified
            };

            _sessionStore.Save(updatedSession);

            return BuildVerificationResult(updatedSession);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var failedSession = AppendEvent(session, RemediationSessionEventType.VerificationFailed,
                $"Verification failed for session {sessionId}",
                details: ex.Message);
            _sessionStore.Save(failedSession);
            throw;
        }
        finally
        {
            // Preserve the cumulative memory recorded by the verification re-audit; only the transient
            // last-result/ranked-findings state should be reverted.
            _auditState.RestoreState(savedState.LastResult, savedState.Entities, preserveCoverage: true, preserveRuleHistory: true);
        }
    }

    public Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_sessionStore == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = "Session persistence is not available.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var session = _sessionStore.Load(sessionId);
        if (session == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = $"Session **{sessionId}** not found.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var updatedSession = AppendEvent(session, RemediationSessionEventType.Exported,
            $"Session {sessionId} exported");
        _sessionStore.Save(updatedSession);

        return Task.FromResult(BuildSessionResult(updatedSession));
    }

    public Task<AgentResult> ListSessionsAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_sessionStore == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ListRemediationSessions,
                Summary = "Session persistence is not available.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var sessions = _sessionStore.List();
        if (sessions.Count == 0)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ListRemediationSessions,
                Summary = "No remediation sessions found. Start one with \"remediate FW-001\".",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>(),
                RemediationSessions = sessions
            });
        }

        var parts = new List<string>
        {
            "**Remediation Sessions**",
            ""
        };

        foreach (var session in sessions)
        {
            var findingSummary = session.RemediationPlan.Sections.FirstOrDefault()?.FindingSummary ?? "No summary";
            parts.Add($"• **{session.SessionId}** — {session.Status} — {session.CreatedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
            parts.Add($"  Finding: {findingSummary}");
        }

        parts.Add("");
        parts.Add("To resume a session, say \"resume session <id>\".");

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.ListRemediationSessions,
            Summary = string.Join("\n", parts),
            AgentFindings = Array.Empty<Finding>(),
            Warnings = Array.Empty<string>(),
            RemediationSessions = sessions
        });
    }

    public Task<AgentResult> LoadSessionAsync(string sessionId, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(sessionId))
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ResumeRemediation,
                Summary = "Please specify which session to resume (e.g., **resume session abc12345**).",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        if (_sessionStore == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ResumeRemediation,
                Summary = "Session persistence is not available.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var session = _sessionStore.Load(sessionId);
        if (session == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ResumeRemediation,
                Summary = $"Session **{sessionId}** not found. Use \"list sessions\" to see available sessions.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var updatedSession = AppendEvent(session, RemediationSessionEventType.SessionResumed,
            $"Session {sessionId} resumed");
        _sessionStore.Save(updatedSession);

        return Task.FromResult(BuildSessionResult(updatedSession, AgentIntent.ResumeRemediation));
    }

    public Task<AgentResult> DeleteSessionAsync(string sessionId, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_sessionStore == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ListRemediationSessions,
                Summary = "Session persistence is not available.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        if (string.IsNullOrWhiteSpace(sessionId))
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ListRemediationSessions,
                Summary = "Please specify which session to delete.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var session = _sessionStore.Load(sessionId);
        if (session == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ListRemediationSessions,
                Summary = $"Session **{sessionId}** not found.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        _sessionStore.Delete(sessionId);

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.ListRemediationSessions,
            Summary = $"Session **{sessionId}** deleted.",
            AgentFindings = Array.Empty<Finding>(),
            Warnings = Array.Empty<string>()
        });
    }

    public AgentResult AddSessionNote(string sessionId, string text, IReadOnlyList<string>? evidenceLinks = null)
    {
        if (_sessionStore == null)
        {
            return new AgentResult
            {
                Intent = AgentIntent.AddSessionNote,
                Summary = "Session persistence is not available.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        if (string.IsNullOrWhiteSpace(sessionId))
        {
            return new AgentResult
            {
                Intent = AgentIntent.AddSessionNote,
                Summary = "Please specify which session to add the note to.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        var session = _sessionStore.Load(sessionId);
        if (session == null)
        {
            return new AgentResult
            {
                Intent = AgentIntent.AddSessionNote,
                Summary = $"Session **{sessionId}** not found.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        if (string.IsNullOrWhiteSpace(text))
        {
            return new AgentResult
            {
                Intent = AgentIntent.AddSessionNote,
                Summary = "Note text cannot be empty.",
                AgentFindings = session.SourceFindings,
                Warnings = Array.Empty<string>()
            };
        }

        var updatedSession = AppendNote(session, text, ruleId: null, evidenceLinks);
        _sessionStore.Save(updatedSession);

        return BuildSessionResult(updatedSession, AgentIntent.AddSessionNote);
    }

    public AgentResult AddStepNote(string sessionId, string ruleId, string text, IReadOnlyList<string>? evidenceLinks = null)
    {
        if (_sessionStore == null)
        {
            return new AgentResult
            {
                Intent = AgentIntent.AddStepNote,
                Summary = "Session persistence is not available.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        if (string.IsNullOrWhiteSpace(sessionId))
        {
            return new AgentResult
            {
                Intent = AgentIntent.AddStepNote,
                Summary = "Please specify which session to add the note to.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        if (string.IsNullOrWhiteSpace(ruleId))
        {
            return new AgentResult
            {
                Intent = AgentIntent.AddStepNote,
                Summary = "Please specify which step to add the note to.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        var session = _sessionStore.Load(sessionId);
        if (session == null)
        {
            return new AgentResult
            {
                Intent = AgentIntent.AddStepNote,
                Summary = $"Session **{sessionId}** not found.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        if (!session.RemediationPlan.Sections.Any(s => s.RuleId == ruleId))
        {
            return new AgentResult
            {
                Intent = AgentIntent.AddStepNote,
                Summary = $"Step **{ruleId}** does not exist in this session's remediation plan.",
                AgentFindings = session.SourceFindings,
                Warnings = Array.Empty<string>()
            };
        }

        if (string.IsNullOrWhiteSpace(text))
        {
            return new AgentResult
            {
                Intent = AgentIntent.AddStepNote,
                Summary = "Note text cannot be empty.",
                AgentFindings = session.SourceFindings,
                Warnings = Array.Empty<string>()
            };
        }

        var updatedSession = AppendNote(session, text, ruleId, evidenceLinks);
        _sessionStore.Save(updatedSession);

        return BuildSessionResult(updatedSession, AgentIntent.AddStepNote);
    }

    private static AuditSnapshot CaptureSnapshot(AgentResult result) => new()
    {
        Findings = result.AgentFindings.Select(ToSnapshotFinding).ToList(),
        TimestampUtc = result.UtcTimestamp,
        Intent = result.Intent
    };

    private static AuditSnapshotFinding ToSnapshotFinding(Finding f) => new()
    {
        RuleId = f.RuleId ?? $"__null-{f.Fingerprint ?? f.Id.ToString("N")}",
        Target = f.Target,
        Severity = f.Severity.ToString(),
        Confidence = f.Confidence.ToString(),
        EvidenceSignals = f.EvidenceSignals,
        ShortDescription = f.ShortDescription,
        Category = f.Category,
        GroupedCount = f.GroupedCount,
        RepresentativeTargets = f.RepresentativeTargets,
        RiskDrivers = f.RiskDrivers,
        Fingerprint = f.Fingerprint
    };

    private static AuditSnapshotFinding ToSnapshotFinding(DiffFinding f) => new()
    {
        RuleId = f.RuleId,
        Target = f.Target,
        Severity = f.Severity,
        Confidence = f.Confidence,
        EvidenceSignals = f.EvidenceSignals,
        ShortDescription = f.ShortDescription,
        GroupedCount = f.GroupedCount,
        RepresentativeTargets = f.RepresentativeTargets,
        RiskDrivers = f.RiskDrivers,
        Fingerprint = f.Fingerprint
    };

    private static AuditHistoryEntry ToHistoryEntry(AuditSnapshot snapshot) => new()
    {
        SnapshotId = snapshot.TimestampUtc.Ticks.ToString("x"),
        TimestampUtc = snapshot.TimestampUtc,
        Intent = snapshot.Intent,
        TotalFindings = snapshot.Findings.Count,
        SnapshotFindings = snapshot.Findings.ToList()
    };

    private string? ResolveSessionId(AgentQuery query)
    {
        var target = query.TargetReference;
        if (!string.IsNullOrWhiteSpace(target) && IsSessionId(target))
            return target;

        target = query.Entities?.SessionId;
        if (!string.IsNullOrWhiteSpace(target) && IsSessionId(target))
            return target;

        if (!string.IsNullOrWhiteSpace(_auditState.Entities.ActiveSessionId) && IsSessionId(_auditState.Entities.ActiveSessionId))
            return _auditState.Entities.ActiveSessionId;

        if (!string.IsNullOrWhiteSpace(_auditState.Entities.LastRemediationSessionId) && IsSessionId(_auditState.Entities.LastRemediationSessionId))
            return _auditState.Entities.LastRemediationSessionId;

        return null;
    }

    private static bool IsSessionId(string value) =>
        !string.IsNullOrWhiteSpace(value) && Regex.IsMatch(value.Trim(), @"^[0-9a-fA-F]{8}$");

    private static string? ResolveTargetRuleId(RemediationSession session, StepOutcomeReport report)
    {
        if (!string.IsNullOrWhiteSpace(report.RuleId))
            return report.RuleId;

        if (report.StepOrdinal.HasValue)
        {
            return ResolveRuleIdByStepOrdinal(session, report.StepOrdinal.Value);
        }

        // Implicit current step: first non-terminal step in plan order.
        return session.RemediationPlan.Sections
            .Select(s => s.RuleId)
            .FirstOrDefault(ruleId =>
            {
                var state = session.StepStates.GetValueOrDefault(ruleId);
                return state is RemediationStepState.Pending or RemediationStepState.InProgress;
            });
    }

    private static string? ResolveRuleIdByStepOrdinal(RemediationSession session, int ordinal)
    {
        if (ordinal <= 0)
            return null;

        // Multi-section plans number steps by section (one finding per section).
        if (ordinal <= session.RemediationPlan.Sections.Count)
            return session.RemediationPlan.Sections[ordinal - 1].RuleId;

        // A remediation session is built from a single finding, so it has one section.
        // The user is guided through that section's apply commands ("Apply (N command(s)):
        // Step-by-step fix commands"), which means "step N" refers to the Nth apply command.
        if (session.RemediationPlan.Sections.Count == 1)
        {
            var section = session.RemediationPlan.Sections[0];
            if (ordinal <= section.ApplyCommands.Count)
                return section.RuleId;
        }

        return null;
    }

    private static string? ResolveAttemptedCommand(RemediationSession session, string? ruleId, StepOutcomeReport report)
    {
        var section = session.RemediationPlan.Sections.FirstOrDefault(s => s.RuleId == ruleId);
        if (section == null || section.ApplyCommands.Count == 0)
            return null;

        // For a single-section session, "step N" points at the Nth apply command.
        if (report.StepOrdinal.HasValue && session.RemediationPlan.Sections.Count == 1)
        {
            var index = report.StepOrdinal.Value - 1;
            if (index >= 0 && index < section.ApplyCommands.Count)
                return section.ApplyCommands[index].Command;
        }

        return section.ApplyCommands[0].Command;
    }

    private AgentResult BuildStepOutcomeResult(RemediationSession session, string ruleId, bool success, string? failureReason = null, string? originalErrorText = null, StepOutcomeReport? report = null)
    {
        var section = session.RemediationPlan.Sections.FirstOrDefault(s => s.RuleId == ruleId);
        var parts = new List<string>
        {
            $"**Step Outcome — Session {session.SessionId}**",
            ""
        };

        if (success)
        {
            parts.Add($"✓ **{ruleId}** marked completed.");

            var nextStep = session.RemediationPlan.Sections
                .Where(s =>
                {
                    var state = session.StepStates.GetValueOrDefault(s.RuleId);
                    return state is RemediationStepState.Pending or RemediationStepState.InProgress;
                })
                .FirstOrDefault();

            if (nextStep != null)
            {
                parts.Add("");
                parts.Add($"**Next step: {nextStep.RuleId}**");
                parts.Add($"{nextStep.FindingSummary}");
                if (nextStep.ApplyCommands.Count > 0)
                {
                    parts.Add($"Command: `{nextStep.ApplyCommands[0].Command}`");
                }
            }
            else
            {
                parts.Add("");
                parts.Add("All steps are complete. Run **verify remediation** to confirm the finding is fixed.");
            }
        }
        else
        {
            var attemptedCommand = report != null
                ? ResolveAttemptedCommand(session, ruleId, report)
                : section?.ApplyCommands.FirstOrDefault()?.Command;
            var guidance = _failureResponseTable.BuildResponse(ruleId, failureReason, attemptedCommand, originalErrorText);
            parts.Add(guidance);

            if (section != null)
            {
                parts.Add("");
                parts.Add($"Original step: **{section.RuleId}** — {section.FindingSummary}");
                // Show the command the user actually reported on (ordinal-aware) when available.
                var displayCommand = !string.IsNullOrWhiteSpace(attemptedCommand)
                    ? attemptedCommand
                    : section.ApplyCommands.FirstOrDefault()?.Command;
                if (!string.IsNullOrWhiteSpace(displayCommand))
                {
                    parts.Add($"Command: `{displayCommand}`");
                }
            }
        }

        return new AgentResult
        {
            Intent = AgentIntent.ReportStepResult,
            Summary = string.Join("\n", parts),
            AgentFindings = session.SourceFindings,
            RemediationPlan = session.RemediationPlan,
            RemediationSession = session,
            Warnings = Array.Empty<string>()
        };
    }

    private static AgentResult BuildSessionResult(RemediationSession session, AgentIntent intent = AgentIntent.StartRemediation)
    {
        var plan = session.RemediationPlan;
        var section = plan.Sections.FirstOrDefault();

        var summaryParts = new List<string>
        {
            $"**Remediation Session: {session.SessionId}**",
            ""
        };

        if (session.BlockedReasons.Count > 0)
        {
            summaryParts.Add("**Session contains blocked steps:**");
            foreach (var reason in session.BlockedReasons)
            {
                summaryParts.Add($"  • {reason}");
            }
            summaryParts.Add("");
        }

        if (section != null)
        {
            summaryParts.Add($"Finding: {section.FindingSummary}");
            summaryParts.Add("");

            if (section.Preconditions.Count > 0)
            {
                summaryParts.Add("**Preconditions:**");
                foreach (var pre in section.Preconditions)
                {
                    summaryParts.Add($"  • {pre}");
                }
                summaryParts.Add("");
            }

            if (section.BackupCommands.Count > 0)
            {
                summaryParts.Add($"**Backup ({section.BackupCommands.Count} command(s)):** Run these first to preserve state.");
                summaryParts.Add("");
            }

            summaryParts.Add($"**Apply ({section.ApplyCommands.Count} command(s)):** Step-by-step fix commands.");
            summaryParts.Add("");

            if (section.RollbackCommands.Count > 0 || section.RollbackHints.Count > 0)
            {
                summaryParts.Add("**Rollback:** Available if something goes wrong.");
                summaryParts.Add("");
            }

            if (section.VerificationCommands.Count > 0)
            {
                summaryParts.Add($"**Verify ({section.VerificationCommands.Count} command(s)):** Confirm the fix worked.");
                summaryParts.Add("");
            }
        }

        summaryParts.Add("Review each command before running it. Use the **Copy** button to grab commands.");

        return new AgentResult
        {
            Intent = intent,
            Summary = string.Join("\n", summaryParts),
            AgentFindings = session.SourceFindings,
            RemediationPlan = plan,
            RemediationSession = session,
            Warnings = session.BlockedReasons
        };
    }

    private static AgentResult BuildVerificationResult(RemediationSession session)
    {
        var v = session.VerificationResult!;
        var parts = new List<string>
        {
            $"**Verification Result: Session {session.SessionId}**",
            "",
            v.DiffNarrative,
            "",
            $"Fixed: {v.FixedFindings.Count} | Unchanged: {v.UnchangedFindings.Count} | New: {v.NewFindings.Count} | Worsened: {v.WorsenedFindings.Count}",
            ""
        };

        if (v.FixedFindings.Count > 0)
        {
            parts.Add("**Fixed:**");
            foreach (var f in v.FixedFindings)
            {
                parts.Add($"  ✓ [{f.RuleId}] {f.ShortDescription}");
            }
            parts.Add("");
        }

        if (v.NewFindings.Count > 0)
        {
            parts.Add("**New findings:**");
            foreach (var f in v.NewFindings)
            {
                parts.Add($"  ⚠ [{f.RuleId}] {f.ShortDescription}");
            }
            parts.Add("");
        }

        if (v.WorsenedFindings.Count > 0)
        {
            parts.Add("**Worsened:**");
            foreach (var f in v.WorsenedFindings)
            {
                parts.Add($"  ✗ [{f.RuleId}] {f.OldSeverity} → {f.NewSeverity}: {f.ShortDescription}");
            }
            parts.Add("");
        }

        return new AgentResult
        {
            Intent = AgentIntent.VerifyRemediation,
            Summary = string.Join("\n", parts),
            AgentFindings = session.SourceFindings,
            RemediationSession = session,
            Warnings = Array.Empty<string>()
        };
    }

    private static RemediationSession AppendEvent(
        RemediationSession session,
        RemediationSessionEventType type,
        string title,
        string? ruleId = null,
        string? details = null)
    {
        var evt = new RemediationSessionEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Type = type,
            Title = title,
            RuleId = ruleId,
            Details = details ?? ""
        };
        var updated = ((ImmutableList<RemediationSessionEvent>)session.Timeline).Add(evt);
        return session with { Timeline = updated };
    }

    private static RemediationSession AppendNote(
        RemediationSession session,
        string text,
        string? ruleId,
        IReadOnlyList<string>? evidenceLinks)
    {
        var links = evidenceLinks ?? Array.Empty<string>();
        var note = new SessionNote
        {
            Text = text.Trim(),
            RuleId = ruleId,
            EvidenceLinks = links
        };
        var updatedNotes = ((ImmutableList<SessionNote>)session.Notes).Add(note);

        var isSessionNote = string.IsNullOrWhiteSpace(ruleId);
        var eventType = isSessionNote ? RemediationSessionEventType.SessionNoteAdded : RemediationSessionEventType.StepNoteAdded;
        var title = isSessionNote ? $"Session note added: {text.Trim()}" : $"Step note added for {ruleId}: {text.Trim()}";
        var details = links.Count > 0 ? string.Join("; ", links) : null;
        var eventRuleId = isSessionNote ? null : ruleId;

        var updatedSession = AppendEvent(session, eventType, title, eventRuleId, details);
        return updatedSession with { Notes = updatedNotes };
    }

    private static string? ExtractRuleIdFromBlockedReason(string reason)
    {
        if (reason.StartsWith('['))
        {
            var end = reason.IndexOf(']', 1);
            if (end > 1)
            {
                return reason[1..end];
            }
        }
        return null;
    }

    private static Severity ParseSeverityFromSummary(string summary)
    {
        if (summary.Contains("Critical", StringComparison.OrdinalIgnoreCase)) return Severity.Critical;
        if (summary.Contains("High", StringComparison.OrdinalIgnoreCase)) return Severity.High;
        if (summary.Contains("Medium", StringComparison.OrdinalIgnoreCase)) return Severity.Medium;
        if (summary.Contains("Low", StringComparison.OrdinalIgnoreCase)) return Severity.Low;
        return Severity.Info;
    }
}
