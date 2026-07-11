using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Messages;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Agent.Suggestions;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

internal sealed class AgentResultPresenter
{
    private readonly ObservableCollection<AgentMessageViewModel> _messages;
    private readonly ObservableCollection<string> _categoryFilters;
    private readonly Func<SeverityFilterOption?> _getSeverityFilter;
    private readonly Func<string?> _getCategoryFilter;
    private readonly Action<bool> _setPrivilegeWarning;
    private readonly Action<string> _setPrivilegeWarningText;
    private readonly Func<SuggestedFollowUp, Task> _executeSuggestion;
    private readonly WarningInterpreter _warningInterpreter;
    private readonly IntentSummaryBuilder _intentSummaryBuilder;
    private readonly IChatFilter _chatFilter;
    private readonly IPinnedMessageStore? _pinnedMessageStore;

    private readonly Action _onFiltersApplied;
    private string? _searchQuery;

    // ObservableCollection events fire synchronously on the mutating thread, and all
    // presenter mutation in this Avalonia view-model stack runs on the UI thread. A
    // plain int counter is sufficient; nested PresentFindings scopes are the only
    // source of re-entrancy here.
    private int _suppressChatFilters;

    public AgentResultPresenter(
        ObservableCollection<AgentMessageViewModel> messages,
        ObservableCollection<string> categoryFilters,
        Func<SeverityFilterOption?> getSeverityFilter,
        Func<string?> getCategoryFilter,
        Action<bool> setPrivilegeWarning,
        Action<string> setPrivilegeWarningText,
        Func<SuggestedFollowUp, Task> executeSuggestion,
        Action? onFiltersApplied = null,
        WarningInterpreter? warningInterpreter = null,
        IntentSummaryBuilder? intentSummaryBuilder = null,
        IChatFilter? chatFilter = null,
        IPinnedMessageStore? pinnedMessageStore = null)
    {
        _messages = messages ?? throw new ArgumentNullException(nameof(messages));
        _categoryFilters = categoryFilters ?? throw new ArgumentNullException(nameof(categoryFilters));
        _getSeverityFilter = getSeverityFilter ?? throw new ArgumentNullException(nameof(getSeverityFilter));
        _getCategoryFilter = getCategoryFilter ?? throw new ArgumentNullException(nameof(getCategoryFilter));
        _setPrivilegeWarning = setPrivilegeWarning ?? throw new ArgumentNullException(nameof(setPrivilegeWarning));
        _setPrivilegeWarningText = setPrivilegeWarningText ?? throw new ArgumentNullException(nameof(setPrivilegeWarningText));
        _executeSuggestion = executeSuggestion ?? throw new ArgumentNullException(nameof(executeSuggestion));
        _onFiltersApplied = onFiltersApplied ?? (() => { });
        _warningInterpreter = warningInterpreter ?? new WarningInterpreter();
        _intentSummaryBuilder = intentSummaryBuilder ?? new IntentSummaryBuilder();
        _chatFilter = chatFilter ?? new DefaultChatFilter();
        _pinnedMessageStore = pinnedMessageStore;
        _messages.CollectionChanged += OnMessagesCollectionChanged;
    }

    /// <summary>
    /// Suppresses automatic chat-filter re-evaluation while messages are being added in bulk.
    /// Dispose the returned object to re-enable filtering. Scopes may be nested.
    /// </summary>
    private IDisposable SuppressChatFilters()
    {
        _suppressChatFilters++;
        return new SuppressScope(this);
    }

    private void OnMessagesCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (_suppressChatFilters != 0)
            return;

        if (e.Action is NotifyCollectionChangedAction.Add or NotifyCollectionChangedAction.Remove or NotifyCollectionChangedAction.Reset)
            ApplyCurrentFilter();
    }

    private sealed class SuppressScope : IDisposable
    {
        private readonly AgentResultPresenter _presenter;
        public SuppressScope(AgentResultPresenter presenter) => _presenter = presenter;
        public void Dispose() => _presenter._suppressChatFilters--;
    }

    public IReadOnlyList<AgentMessageViewModel> PresentFindings(AgentResult result, bool showCapabilityReport = true, bool showPassedCount = true, bool showWarnings = true)
    {
        var created = new List<AgentMessageViewModel>();

        using (SuppressChatFilters())
        {
            AgentMessageViewModel? suggestionAnchor = null;

            if (showCapabilityReport && !string.IsNullOrWhiteSpace(result.CapabilityReport))
                created.Add(TrackSuggestionAnchor(ref suggestionAnchor, AddAgentMessage(result.CapabilityReport, true)));

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
                created.Add(TrackSuggestionAnchor(ref suggestionAnchor, AddInteractiveRemediationMessage(result)));
            }
            else if (result.Intent == AgentIntent.StartRemediation && result.RemediationSession != null)
            {
                created.Add(TrackSuggestionAnchor(ref suggestionAnchor, AddSessionMessage(result)));
            }
            else if (result.Intent == AgentIntent.ResumeRemediation && result.RemediationSession != null)
            {
                created.Add(TrackSuggestionAnchor(ref suggestionAnchor, AddSessionMessage(result)));
            }
            else if (result.Intent == AgentIntent.VerifyRemediation && result.RemediationSession != null)
            {
                created.Add(TrackSuggestionAnchor(ref suggestionAnchor, AddVerificationResultMessage(result)));
            }
            else if (result.Intent == AgentIntent.ListRemediationSessions)
            {
                created.Add(TrackSuggestionAnchor(ref suggestionAnchor, AddAgentMessage(result.Summary, result.RemediationSessions.Count == 0)));
            }
            else if ((result.Intent == AgentIntent.AddSessionNote || result.Intent == AgentIntent.AddStepNote)
                && result.RemediationSession != null)
            {
                created.Add(TrackSuggestionAnchor(ref suggestionAnchor, AddNoteConfirmationMessage(result)));
            }
            else
            {
                var lead = useBuilderLead
                    ? _intentSummaryBuilder.BuildMissingToolLead(result.Intent, result.AgentFindings, result.PassedCount, missingToolWarning!)
                    : result.Summary;
                created.Add(TrackSuggestionAnchor(ref suggestionAnchor, AddAgentMessage(lead, result.AgentFindings.Count == 0, isProse: true)));

                if (result.Narrative != null && !string.IsNullOrWhiteSpace(result.Narrative.FullText))
                {
                    created.Add(TrackSuggestionAnchor(ref suggestionAnchor, AddAgentMessage(result.Narrative.FullText, false, isProse: true)));
                }

                // Every audit result's lead already states the passed-checks count — either the
                // missing-tool lead above or the composer summary (result.Summary) — so only emit the
                // standalone line for non-audit results, otherwise the count appears twice.
                if (showPassedCount && result.PassedCount > 0 && !AgentResultStateCoordinator.IsAuditIntent(result.Intent))
                {
                    var checkWord = result.PassedCount == 1 ? "check" : "checks";
                    created.Add(TrackSuggestionAnchor(ref suggestionAnchor, AddAgentMessage($"✓ {result.PassedCount} {checkWord} passed", true)));
                }

                if (result.AgentFindings.Count > 0)
                {
                    created.Add(AddAgentFindingGroupSummary(result.AgentFindings));

                    _categoryFilters.Clear();
                    _categoryFilters.Add(ChatFilterConstants.AllCategoriesFilter);
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
                        created.Add(AddAgentFindingGroup(group.Category, group.Findings));
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
                    created.Add(TrackSuggestionAnchor(ref suggestionAnchor, AddAgentMessage(text, true)));
                }

                DetectPrivilegeWarning(result.Warnings);
            }

            AttachSuggestions(result, suggestionAnchor);
        }

        ApplyCurrentFilter();
        _onFiltersApplied();
        return created;
    }

    private static AgentMessageViewModel TrackSuggestionAnchor(ref AgentMessageViewModel? anchor, AgentMessageViewModel candidate)
    {
        // Anchor chips to the first substantive agent message, skipping info-only
        // messages such as the capability report so the chips stay near the summary/findings.
        if (anchor == null && candidate is { IsUser: false, IsInfo: false })
            anchor = candidate;
        return candidate;
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

    private void ConfigureMessage(AgentMessageViewModel message)
    {
        if (string.IsNullOrWhiteSpace(message.MessageId))
        {
            message.MessageId = AgentMessageFingerprint.NewId();
        }

        if (_pinnedMessageStore != null)
        {
            try
            {
                message.IsPinned = _pinnedMessageStore.IsPinned(message.MessageId);
            }
            catch
            {
                message.IsPinned = false;
            }
        }
    }

    /// <summary>
    /// Re-evaluates the pinned state of a message against the store. Used when a message's
    /// identifier is restored from persisted state (e.g. reloading a pinned message into the transcript).
    /// </summary>
    public void RefreshPinnedState(AgentMessageViewModel message)
    {
        if (_pinnedMessageStore != null && !string.IsNullOrWhiteSpace(message.MessageId))
        {
            try
            {
                message.IsPinned = _pinnedMessageStore.IsPinned(message.MessageId);
            }
            catch
            {
                message.IsPinned = false;
            }
        }
    }

    public void AddUserMessage(string text)
    {
        var message = new AgentMessageViewModel
        {
            Text = text,
            IsUser = true,
            Timestamp = DateTime.Now
        };
        ConfigureMessage(message);
        _messages.Add(message);
    }

    public AgentMessageViewModel AddAgentMessage(string text, bool isInfo, bool isError = false, bool isProse = false)
    {
        var isErrorMessage = isError || (!isInfo && IsErrorText(text));
        // Sanitize every agent message, not just error-flagged ones: the process-start rewrite
        // drops embedded working-directory paths and home-prefix scrubbing ensures no absolute
        // local path reaches the chat, regardless of which call site produced the text. Both
        // transforms are idempotent, so already-sanitized runner/warning text is unaffected.
        text = ErrorSanitizer.Sanitize(text);

        var message = new AgentMessageViewModel
        {
            Text = text,
            IsUser = false,
            IsInfo = isInfo,
            IsError = isErrorMessage,
            IsProse = isProse,
            Timestamp = DateTime.Now
        };
        ConfigureMessage(message);
        _messages.Add(message);
        return message;
    }

    private static bool IsErrorText(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return false;

        var trimmed = text.Trim();
        return trimmed.StartsWith("Error:", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("Agent error:", StringComparison.OrdinalIgnoreCase);
    }

    public void AddAgentFinding(Finding finding)
    {
        var ruleIdPrefix = string.IsNullOrEmpty(finding.RuleId) ? "" : $"[{finding.RuleId}] ";
        var verificationCommands = VerificationCommandExtractor.ExtractHowToVerify(finding.Details);
        var groupBadge = FormatGroupBadge(finding);
        var details = FormatFindingDetails(finding);

        var message = new AgentMessageViewModel
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
        };
        ConfigureMessage(message);
        _messages.Add(message);
    }

    private AgentMessageViewModel AddAgentFindingGroupSummary(IReadOnlyList<Finding> findings)
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
        var message = new AgentMessageViewModel
        {
            Text = summary,
            IsUser = false,
            IsInfo = true,
            Timestamp = DateTime.Now
        };
        ConfigureMessage(message);
        _messages.Add(message);
        return message;
    }

    private AgentMessageViewModel AddAgentFindingGroup(string category, IReadOnlyList<Finding> findings)
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

        var message = new AgentMessageViewModel
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
        };
        ConfigureMessage(message);
        _messages.Add(message);
        return message;
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
        ConfigureMessage(message);
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
        ConfigureMessage(message);
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
        ConfigureMessage(message);
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
        ConfigureMessage(message);
        _messages.Add(message);
        return message;
    }

    public void SetSearchQuery(string? query)
    {
        _searchQuery = query;
        ApplyCurrentFilter();
    }

    public void ApplyChatFilters()
    {
        ApplyCurrentFilter();
    }

    private void ApplyCurrentFilter()
    {
        _chatFilter.Apply(_messages.ToList(), _getSeverityFilter(), _getCategoryFilter(), _searchQuery);
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
}
