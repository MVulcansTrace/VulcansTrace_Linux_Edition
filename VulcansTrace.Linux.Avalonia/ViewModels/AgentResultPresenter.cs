using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Agent.Suggestions;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

internal sealed class AgentResultPresenter
{
    private const string AllCategoriesFilter = "All categories";

    private readonly ObservableCollection<AgentMessageViewModel> _messages;
    private readonly ObservableCollection<string> _categoryFilters;
    private readonly Func<SeverityFilterOption?> _getSeverityFilter;
    private readonly Func<string?> _getCategoryFilter;
    private readonly Action<bool> _setPrivilegeWarning;
    private readonly Action<string> _setPrivilegeWarningText;
    private readonly Func<SuggestedFollowUp, Task> _executeSuggestion;
    private readonly WarningInterpreter _warningInterpreter;
    private readonly IntentSummaryBuilder _intentSummaryBuilder;

    public AgentResultPresenter(
        ObservableCollection<AgentMessageViewModel> messages,
        ObservableCollection<string> categoryFilters,
        Func<SeverityFilterOption?> getSeverityFilter,
        Func<string?> getCategoryFilter,
        Action<bool> setPrivilegeWarning,
        Action<string> setPrivilegeWarningText,
        Func<SuggestedFollowUp, Task> executeSuggestion,
        WarningInterpreter? warningInterpreter = null,
        IntentSummaryBuilder? intentSummaryBuilder = null)
    {
        _messages = messages ?? throw new ArgumentNullException(nameof(messages));
        _categoryFilters = categoryFilters ?? throw new ArgumentNullException(nameof(categoryFilters));
        _getSeverityFilter = getSeverityFilter ?? throw new ArgumentNullException(nameof(getSeverityFilter));
        _getCategoryFilter = getCategoryFilter ?? throw new ArgumentNullException(nameof(getCategoryFilter));
        _setPrivilegeWarning = setPrivilegeWarning ?? throw new ArgumentNullException(nameof(setPrivilegeWarning));
        _setPrivilegeWarningText = setPrivilegeWarningText ?? throw new ArgumentNullException(nameof(setPrivilegeWarningText));
        _executeSuggestion = executeSuggestion ?? throw new ArgumentNullException(nameof(executeSuggestion));
        _warningInterpreter = warningInterpreter ?? new WarningInterpreter();
        _intentSummaryBuilder = intentSummaryBuilder ?? new IntentSummaryBuilder();
    }

    public void PresentFindings(AgentResult result, bool showCapabilityReport = true, bool showPassedCount = true, bool showWarnings = true)
    {
        AgentMessageViewModel? suggestionAnchor = null;

        if (showCapabilityReport && !string.IsNullOrWhiteSpace(result.CapabilityReport))
            TrackSuggestionAnchor(ref suggestionAnchor, AddAgentMessage(result.CapabilityReport, true));

        // Interpret warnings once, up front. IntentSummaryBuilder.BuildMissingToolLead uses the
        // MissingTool classification to lead with a friendly "I ran a … <tool> is missing" sentence,
        // and the warning-display loop below reuses this same interpreted set (no double interpretation).
        var interpreted = result.Warnings.Count > 0
            ? _warningInterpreter.Interpret(result.Intent, result.Warnings, result.DataSourceCapabilities)
            : Array.Empty<UserFriendlyWarning>();

        // For an audit whose primary tool is missing, IntentSummaryBuilder produces a friendlier lead
        // than the denser AgentResultComposer summary (result.Summary), which has no concept of
        // interpreted warnings. In every other case result.Summary is richer (it carries suppressed /
        // crashed / not-applicable counts), so it is kept. Scoped to audit intents so non-audit
        // intents (ExplainFinding, SetBaseline, …) keep their own summary.
        var missingToolWarning = interpreted.FirstOrDefault(w => w.Category == WarningCategory.MissingTool);
        var useBuilderLead = missingToolWarning != null && AgentResultStateCoordinator.IsAuditIntent(result.Intent);

        if (result.Intent == AgentIntent.FixFinding
            && result.Warnings.Count == 0
            && result.RemediationPlan?.Sections.Count == 1)
        {
            TrackSuggestionAnchor(ref suggestionAnchor, AddInteractiveRemediationMessage(result));
        }
        else if (result.Intent == AgentIntent.StartRemediation && result.RemediationSession != null)
        {
            TrackSuggestionAnchor(ref suggestionAnchor, AddSessionMessage(result));
        }
        else if (result.Intent == AgentIntent.ResumeRemediation && result.RemediationSession != null)
        {
            TrackSuggestionAnchor(ref suggestionAnchor, AddSessionMessage(result));
        }
        else if (result.Intent == AgentIntent.VerifyRemediation && result.RemediationSession != null)
        {
            TrackSuggestionAnchor(ref suggestionAnchor, AddVerificationResultMessage(result));
        }
        else if (result.Intent == AgentIntent.ListRemediationSessions)
        {
            TrackSuggestionAnchor(ref suggestionAnchor, AddAgentMessage(result.Summary, result.RemediationSessions.Count == 0));
        }
        else if ((result.Intent == AgentIntent.AddSessionNote || result.Intent == AgentIntent.AddStepNote)
            && result.RemediationSession != null)
        {
            TrackSuggestionAnchor(ref suggestionAnchor, AddNoteConfirmationMessage(result));
        }
        else
        {
            var lead = useBuilderLead
                ? _intentSummaryBuilder.BuildMissingToolLead(result.Intent, result.AgentFindings, result.PassedCount, missingToolWarning!)
                : result.Summary;
            TrackSuggestionAnchor(ref suggestionAnchor, AddAgentMessage(lead, result.AgentFindings.Count == 0));

            if (result.Narrative != null && !string.IsNullOrWhiteSpace(result.Narrative.FullText))
            {
                TrackSuggestionAnchor(ref suggestionAnchor, AddAgentMessage(result.Narrative.FullText, false));
            }

            // Every audit result's lead already states the passed-checks count — either the
            // missing-tool lead above or the composer summary (result.Summary) — so only emit the
            // standalone line for non-audit results, otherwise the count appears twice.
            if (showPassedCount && result.PassedCount > 0 && !AgentResultStateCoordinator.IsAuditIntent(result.Intent))
            {
                var checkWord = result.PassedCount == 1 ? "check" : "checks";
                TrackSuggestionAnchor(ref suggestionAnchor, AddAgentMessage($"✓ {result.PassedCount} {checkWord} passed", true));
            }

            if (result.AgentFindings.Count > 0)
            {
                AddAgentFindingGroupSummary(result.AgentFindings);

                _categoryFilters.Clear();
                _categoryFilters.Add(AllCategoriesFilter);
                foreach (var cat in result.AgentFindings.Select(f => f.Category).Distinct().OrderBy(c => c))
                {
                    _categoryFilters.Add(cat);
                }

                var grouped = result.AgentFindings
                    .GroupBy(f => f.Category)
                    .Select(g => new { Category = g.Key, Findings = g.OrderByDescending(f => f.Severity).ToList() })
                    .OrderByDescending(g => g.Findings.Max(f => f.Severity))
                    .ToList();

                foreach (var group in grouped)
                {
                    AddAgentFindingGroup(group.Category, group.Findings);
                }
            }
        }

        if (showWarnings && result.Warnings.Count > 0)
        {
            foreach (var warning in interpreted)
            {
                string text;
                if (useBuilderLead && warning.Category == WarningCategory.MissingTool)
                {
                    // The message is already embedded in the missing-tool lead; keep only its actionable
                    // suggestion (e.g. install guidance) so nothing is duplicated or dropped.
                    if (string.IsNullOrEmpty(warning.Suggestion))
                        continue;
                    text = warning.Suggestion;
                }
                else
                {
                    text = warning.Suggestion != null
                        ? $"{warning.Message} {warning.Suggestion}"
                        : warning.Message;
                }
                TrackSuggestionAnchor(ref suggestionAnchor, AddAgentMessage(text, true));
            }

            DetectPrivilegeWarning(result.Warnings);
        }

        AttachSuggestions(result, suggestionAnchor);
        ApplyChatFilters();
    }

    private static void TrackSuggestionAnchor(ref AgentMessageViewModel? anchor, AgentMessageViewModel? candidate)
    {
        // Anchor chips to the first substantive agent message, skipping info-only
        // messages such as the capability report so the chips stay near the summary/findings.
        if (anchor == null && candidate is { IsUser: false, IsInfo: false })
            anchor = candidate;
    }

    private void AttachSuggestions(AgentResult result, AgentMessageViewModel? anchor)
    {
        if (anchor == null || result.Suggestions.Count == 0)
            return;

        anchor.Suggestions = result.Suggestions;
        anchor.SuggestionCommand = new RelayCommand<SuggestedFollowUp>(async suggestion =>
        {
            if (suggestion != null && !string.IsNullOrWhiteSpace(suggestion.Query))
                await _executeSuggestion(suggestion);
        });
    }

    public void AddUserMessage(string text)
    {
        _messages.Add(new AgentMessageViewModel
        {
            Text = text,
            IsUser = true,
            Timestamp = DateTime.Now
        });
    }

    public AgentMessageViewModel AddAgentMessage(string text, bool isInfo)
    {
        var message = new AgentMessageViewModel
        {
            Text = text,
            IsUser = false,
            IsInfo = isInfo,
            Timestamp = DateTime.Now
        };
        _messages.Add(message);
        return message;
    }

    public void AddAgentFinding(Finding finding)
    {
        var ruleIdPrefix = string.IsNullOrEmpty(finding.RuleId) ? "" : $"[{finding.RuleId}] ";
        var verificationCommands = VerificationCommandExtractor.ExtractHowToVerify(finding.Details);
        var groupBadge = FormatGroupBadge(finding);
        var details = FormatFindingDetails(finding);

        _messages.Add(new AgentMessageViewModel
        {
            Text = $"{ruleIdPrefix}[{finding.Severity}] {finding.ShortDescription}{groupBadge}",
            Details = details,
            IsUser = false,
            IsInfo = false,
            Severity = finding.Severity,
            Confidence = finding.Confidence.ToString(),
            EvidenceSignalsDisplay = FormatEvidenceSignals(finding.EvidenceSignals),
            Timestamp = DateTime.Now,
            VerificationCommands = verificationCommands
        });
    }

    private void AddAgentFindingGroupSummary(IReadOnlyList<Finding> findings)
    {
        var critical = findings.Where(f => f.Severity == Severity.Critical).Sum(GetRawFindingCount);
        var high = findings.Where(f => f.Severity == Severity.High).Sum(GetRawFindingCount);
        var medium = findings.Where(f => f.Severity == Severity.Medium).Sum(GetRawFindingCount);
        var low = findings.Where(f => f.Severity == Severity.Low).Sum(GetRawFindingCount);
        var info = findings.Where(f => f.Severity == Severity.Info).Sum(GetRawFindingCount);

        var parts = new List<string>();
        if (critical > 0) parts.Add($"{critical} Critical");
        if (high > 0) parts.Add($"{high} High");
        if (medium > 0) parts.Add($"{medium} Medium");
        if (low > 0) parts.Add($"{low} Low");
        if (info > 0) parts.Add($"{info} Info");

        var rawTotal = findings.Sum(GetRawFindingCount);
        var groupWord = findings.Count == 1 ? "representative group" : "representative groups";
        var rawFindingWord = rawTotal == 1 ? "raw finding" : "raw findings";
        var totalLabel = rawTotal == findings.Count
            ? $"{findings.Count} total"
            : $"{findings.Count} {groupWord}, {rawTotal} {rawFindingWord}";
        var summary = $"Findings: {string.Join(", ", parts)} ({totalLabel})";
        _messages.Add(new AgentMessageViewModel
        {
            Text = summary,
            IsUser = false,
            IsInfo = true,
            Timestamp = DateTime.Now
        });
    }

    private void AddAgentFindingGroup(string category, IReadOnlyList<Finding> findings)
    {
        var rawTotal = findings.Sum(GetRawFindingCount);
        var highCritical = findings.Where(f => f.Severity >= Severity.High).Sum(GetRawFindingCount);
        var findingWord = findings.Count == 1 ? "finding" : "findings";
        var groupWord = findings.Count == 1 ? "representative group" : "representative groups";
        var rawFindingWord = rawTotal == 1 ? "raw finding" : "raw findings";
        var countLabel = rawTotal == findings.Count
            ? $"{findings.Count} {findingWord}"
            : $"{findings.Count} {groupWord}, {rawTotal} {rawFindingWord}";
        var header = highCritical > 0
            ? $"[{category}] {countLabel} — {highCritical} High/Critical"
            : $"[{category}] {countLabel}";

        var details = new StringBuilder();
        foreach (var finding in findings)
        {
            var ruleIdPrefix = string.IsNullOrEmpty(finding.RuleId) ? "" : $"[{finding.RuleId}] ";
            var confidence = finding.Confidence == DetectionConfidence.Unknown
                ? string.Empty
                : $" confidence {finding.Confidence}";
            var signals = FormatEvidenceSignals(finding.EvidenceSignals);
            var signalText = string.IsNullOrEmpty(signals) ? string.Empty : $" ({signals})";
            details.AppendLine($"• {ruleIdPrefix}[{finding.Severity}{confidence}] {finding.ShortDescription}{FormatGroupBadge(finding)}{signalText}");
        }

        _messages.Add(new AgentMessageViewModel
        {
            Text = header,
            Details = details.ToString().TrimEnd(),
            IsUser = false,
            IsInfo = false,
            Severity = findings.Max(f => f.Severity),
            Confidence = findings.Select(f => f.Confidence).OrderByDescending(c => c).FirstOrDefault().ToString(),
            EvidenceSignalsDisplay = FormatEvidenceSignals(findings.SelectMany(f => f.EvidenceSignals).DistinctBy(s => s.Name).ToList()),
            Timestamp = DateTime.Now,
            Category = category
        });
    }

    private static string FormatGroupBadge(Finding finding) =>
        finding.GroupedCount > 1 ? $" x{finding.GroupedCount}" : string.Empty;

    private static int GetRawFindingCount(Finding finding) => Math.Max(1, finding.GroupedCount);

    private static string FormatFindingDetails(Finding finding)
    {
        if (finding.GroupedCount <= 1 &&
            finding.RepresentativeTargets.Count == 0 &&
            finding.RiskDrivers.Count == 0)
        {
            return finding.Details;
        }

        var details = new StringBuilder(finding.Details.TrimEnd());
        if (details.Length > 0)
        {
            details.AppendLine();
            details.AppendLine();
        }

        if (finding.GroupedCount > 1)
        {
            details.AppendLine($"Grouped findings: {finding.GroupedCount}");
        }

        if (finding.RepresentativeTargets.Count > 0)
        {
            details.AppendLine($"Representative targets: {string.Join("; ", finding.RepresentativeTargets)}");
        }

        if (finding.RiskDrivers.Count > 0)
        {
            details.AppendLine($"Risk drivers: {string.Join("; ", finding.RiskDrivers)}");
        }

        return details.ToString().TrimEnd();
    }

    private AgentMessageViewModel AddInteractiveRemediationMessage(AgentResult result)
    {
        var section = result.RemediationPlan!.Sections[0];
        var severity = ParseSeverityFromSummary(section.FindingSummary);

        var message = new AgentMessageViewModel
        {
            Text = result.Summary,
            Details = $"Risk: {section.RiskNote}",
            IsUser = false,
            IsInfo = false,
            Severity = severity,
            Timestamp = DateTime.Now,
            RemediationSection = section
        };
        _messages.Add(message);
        return message;
    }

    private AgentMessageViewModel AddSessionMessage(AgentResult result)
    {
        var session = result.RemediationSession!;
        var section = session.RemediationPlan.Sections.FirstOrDefault();
        var severity = section != null ? ParseSeverityFromSummary(section.FindingSummary) : Severity.Info;
        var sectionIsBlocked = section != null
            && session.StepStates.TryGetValue(section.RuleId, out var stepState)
            && stepState == RemediationStepState.Blocked;

        var message = new AgentMessageViewModel
        {
            Text = result.Summary,
            Details = section != null && !sectionIsBlocked ? $"Risk: {section.RiskNote}" : "",
            IsUser = false,
            IsInfo = false,
            Severity = severity,
            Timestamp = DateTime.Now,
            RemediationSection = sectionIsBlocked ? null : section,
            SessionId = session.SessionId,
            SessionStatus = session.Status,
            SessionTimeline = session.Timeline
        };
        _messages.Add(message);
        return message;
    }

    private AgentMessageViewModel AddVerificationResultMessage(AgentResult result)
    {
        var session = result.RemediationSession!;
        var v = session.VerificationResult;

        var message = new AgentMessageViewModel
        {
            Text = result.Summary,
            IsUser = false,
            IsInfo = false,
            Timestamp = DateTime.Now,
            SessionId = session.SessionId,
            SessionStatus = session.Status,
            IsVerificationResult = true,
            SessionTimeline = session.Timeline
        };
        _messages.Add(message);
        return message;
    }

    private AgentMessageViewModel AddNoteConfirmationMessage(AgentResult result)
    {
        var session = result.RemediationSession!;
        var note = session.Notes.LastOrDefault();
        if (note == null)
        {
            return AddAgentMessage(result.Summary, true);
        }

        var location = string.IsNullOrEmpty(note.RuleId)
            ? $"session {session.SessionId}"
            : $"step {note.RuleId} in session {session.SessionId}";
        var evidenceHint = note.EvidenceLinks.Count > 0
            ? $" ({note.EvidenceLinks.Count} evidence link(s))"
            : "";

        var message = new AgentMessageViewModel
        {
            Text = $"Note added to {location}{evidenceHint}: {note.Text}",
            IsUser = false,
            IsInfo = true,
            Timestamp = DateTime.Now,
            SessionId = session.SessionId,
            SessionStatus = session.Status,
            SessionTimeline = session.Timeline
        };
        _messages.Add(message);
        return message;
    }

    public void ApplyChatFilters()
    {
        var severityFilter = _getSeverityFilter();
        var categoryFilter = _getCategoryFilter();

        // Snapshot the collection so a concurrent/re-entrant modification (e.g. another
        // dispatcher job adding messages while a filter change is being applied) cannot
        // invalidate the enumerator.
        foreach (var msg in _messages.ToList())
        {
            if (msg == null)
                continue;

            if (msg.IsUser || msg.IsInfo || string.IsNullOrEmpty(msg.Category))
            {
                msg.IsVisible = true;
                continue;
            }

            var severityOk = true;
            var categoryOk = true;

            if (severityFilter != null)
            {
                if (severityFilter.MinSeverity == Severity.High && msg.Severity < Severity.High)
                    severityOk = false;
                if (severityFilter.MinSeverity == Severity.Critical && msg.Severity < Severity.Critical)
                    severityOk = false;
            }

            if (!IsAllCategoryFilter(categoryFilter) && !msg.Category.Equals(categoryFilter, StringComparison.OrdinalIgnoreCase))
                categoryOk = false;

            msg.IsVisible = severityOk && categoryOk;
        }
    }

    private void DetectPrivilegeWarning(IReadOnlyList<string> warnings)
    {
        // Scan the RAW warnings, not the interpreted/collapsed messages. The interpreter
        // collapses many raw warnings into keyword-free summaries, so scanning interpreted
        // text would miss privilege signals (e.g. "insufficient privileges") that don't match
        // the exact "permission denied"/"operation not permitted" literals the interpreter
        // keys on. Raw warnings always carry the original phrasing.
        var privilegeWarning = warnings.FirstOrDefault(w =>
            w.Contains("permission", StringComparison.OrdinalIgnoreCase) ||
            w.Contains("privilege", StringComparison.OrdinalIgnoreCase) ||
            w.Contains("denied", StringComparison.OrdinalIgnoreCase) ||
            w.Contains("elevated", StringComparison.OrdinalIgnoreCase));

        if (privilegeWarning != null)
        {
            _setPrivilegeWarning(true);
            _setPrivilegeWarningText("Some inspections are limited without elevated privileges. Process names, connection details, and service states may be hidden. Run with sudo for full visibility.");
        }
    }

    private static Severity ParseSeverityFromSummary(string summary)
    {
        if (summary.Contains("Critical", StringComparison.OrdinalIgnoreCase)) return Severity.Critical;
        if (summary.Contains("High", StringComparison.OrdinalIgnoreCase)) return Severity.High;
        if (summary.Contains("Medium", StringComparison.OrdinalIgnoreCase)) return Severity.Medium;
        if (summary.Contains("Low", StringComparison.OrdinalIgnoreCase)) return Severity.Low;
        return Severity.Info;
    }

    private static string FormatEvidenceSignals(IReadOnlyList<EvidenceSignal> signals)
    {
        if (signals.Count == 0)
            return string.Empty;

        return string.Join(", ", signals.Select(s => s.Name));
    }

    private static bool IsAllCategoryFilter(string? categoryFilter) =>
        string.IsNullOrWhiteSpace(categoryFilter)
            || categoryFilter.Equals(AllCategoriesFilter, StringComparison.OrdinalIgnoreCase);
}
