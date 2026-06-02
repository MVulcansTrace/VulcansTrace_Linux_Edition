using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

internal sealed class GuidedRemediationService
{
    private readonly AgentAuditState _auditState;
    private readonly RemediationPlanBuilder _planBuilder;
    private readonly ISessionStore? _sessionStore;
    private readonly Func<AgentIntent, string?, CancellationToken, Task<AgentResult>>? _runAudit;

    public GuidedRemediationService(
        AgentAuditState auditState,
        RemediationPlanBuilder planBuilder,
        ISessionStore? sessionStore = null,
        Func<AgentIntent, string?, CancellationToken, Task<AgentResult>>? runAudit = null)
    {
        _auditState = auditState ?? throw new ArgumentNullException(nameof(auditState));
        _planBuilder = planBuilder ?? throw new ArgumentNullException(nameof(planBuilder));
        _sessionStore = sessionStore;
        _runAudit = runAudit;
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
            BlockedReasons = blockedReasons
        };

        _sessionStore?.Save(session);

        return Task.FromResult(BuildSessionResult(session));
    }

    public AgentResult UpdateStepState(string sessionId, string ruleId, RemediationStepState state)
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

        var allCompleted = updatedSteps.Values.All(s => s is RemediationStepState.Completed or RemediationStepState.Skipped);
        var updatedSession = session with
        {
            StepStates = updatedSteps,
            Status = allCompleted ? RemediationSessionStatus.Completed : session.Status
        };

        _sessionStore.Save(updatedSession);

        return BuildSessionResult(updatedSession);
    }

    public async Task<AgentResult> RunVerificationAsync(string sessionId, CancellationToken ct)
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
            return new AgentResult
            {
                Intent = AgentIntent.VerifyRemediation,
                Summary = $"Session **{sessionId}** is blocked due to safety concerns and cannot be verified as a completed remediation.",
                AgentFindings = session.SourceFindings,
                Warnings = session.BlockedReasons
            };
        }

        var savedLastResult = _auditState.LastResult;
        try
        {
            var auditResult = await _runAudit(session.BeforeSnapshot.Intent, null, ct);
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

            var updatedSession = session with
            {
                AfterSnapshot = afterSnapshot,
                VerificationResult = verificationResult,
                Status = RemediationSessionStatus.Verified
            };

            _sessionStore.Save(updatedSession);

            return BuildVerificationResult(updatedSession);
        }
        finally
        {
            _auditState.RememberResult(savedLastResult);
        }
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
        ShortDescription = f.ShortDescription,
        Category = f.Category,
        Fingerprint = f.Fingerprint
    };

    private static AuditSnapshotFinding ToSnapshotFinding(DiffFinding f) => new()
    {
        RuleId = f.RuleId,
        Target = f.Target,
        Severity = f.Severity,
        ShortDescription = f.ShortDescription,
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

    private static AgentResult BuildSessionResult(RemediationSession session)
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
            Intent = AgentIntent.StartRemediation,
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

    private static Severity ParseSeverityFromSummary(string summary)
    {
        if (summary.Contains("Critical", StringComparison.OrdinalIgnoreCase)) return Severity.Critical;
        if (summary.Contains("High", StringComparison.OrdinalIgnoreCase)) return Severity.High;
        if (summary.Contains("Medium", StringComparison.OrdinalIgnoreCase)) return Severity.Medium;
        if (summary.Contains("Low", StringComparison.OrdinalIgnoreCase)) return Severity.Low;
        return Severity.Info;
    }
}
