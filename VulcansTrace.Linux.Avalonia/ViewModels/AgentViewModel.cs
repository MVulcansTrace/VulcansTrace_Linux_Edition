using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Threading;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Actions;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Messages;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Agent.Suggestions;
using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Avalonia.Threading;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for the agent chat panel.
/// </summary>
public sealed class AgentViewModel : ViewModelBase, IDisposable
{
    private const string WelcomeMessage =
        "Ready when you are. I can audit this system, analyze Linux logs, investigate targets, and help remediate what I find.";

    private CancellationTokenSource? _streamingCts;
    private List<AgentMessageViewModel>? _currentStreamingBatch;
    private ITypewriterScheduler _typewriterScheduler;

    /// <summary>Gets or sets the scheduler used for typewriter/streaming animation. Exposed for tests.</summary>
    internal ITypewriterScheduler TypewriterScheduler
    {
        get => _typewriterScheduler;
        set => _typewriterScheduler = value;
    }

    private IAgent _agent;
    private readonly AgentResultPresenter _presenter;
    private readonly AgentHistoryCoordinator _historyCoordinator;
    private readonly AgentOperationRunner _operationRunner;
    private readonly AgentQueryExecutor _queryExecutor;
    private readonly AgentResultStateCoordinator _resultState;
    private readonly RemediationPlanBuilder _remediationPlanBuilder;
    private readonly RemediationExecutor _remediationExecutor;
    private readonly IThreatIntelStore? _threatIntelStore;
    private readonly IDialogService? _dialogService;
    private readonly IAgentMemoryStore? _memoryStore;
    private readonly IPinnedMessageStore? _pinnedMessageStore;
    private readonly AnalystActionLogger? _analystActionLogger;
    private ISessionStore? _sessionStore;
    private string? _lastShownMemoryWarning;

    private string _userQuery = "";
    private string _logText = "";
    private bool _isBusy;
    private string _agentStatus = "Online";
    private bool _isSlashPaletteOpen;
    private bool _hasPrivilegeWarning;
    private string _privilegeWarningText = "";
    private SeverityFilterOption? _selectedChatSeverityFilter;
    private string? _selectedChatCategoryFilter;
    private RemediationSession? _selectedSession;
    private bool _hasOnlyWelcomeMessage = true;
    private bool _hasNoVisibleMessages;
    private bool _isAgentToolsPanelOpen;
    private string _slashHelpQuery = "";
    private bool _isSlashHelpOpen;
    private SlashCommandItem? _selectedSlashHelpCommand;
    private readonly List<SlashCommandItem> _allSlashCommands = new();

    private readonly List<string> _queryHistory = new();
    private int _queryHistoryIndex = -1;
    private string _chatSearchQuery = "";
    private bool _hasNoSearchMatches;
    private double _auditProgressPercent;
    private string _auditProgressMessage = string.Empty;
    private bool _auditProgressIsIndeterminate;
    private int _pinnedMessageCount;
    private string _pinMessageStatusMessage = string.Empty;
    private readonly Dictionary<string, AgentMessageViewModel> _messagesById = new(StringComparer.OrdinalIgnoreCase);

    // ── Page state machine fields ──────────────────────────────────────
    private DispatcherTimer? _elapsedTimer;
    private DateTime _operationStartTime;
    private string _elapsedDisplay = string.Empty;
    private FindingItemViewModel? _selectedResultFinding;
    private bool _isTranscriptOpen = true;
    private bool _lastOperationFailed;
    private string _currentOperationTitle = "Agent operation";
    private string _scanProfileName = "Low - Critical Threat Triage";
    private string _scanProfileDescription = "Shows High and Critical findings for rapid triage.";
    private string _baselineStatusText = "Baseline: Not configured";

    /// <summary>Gets the collection of chat messages.</summary>
    public ObservableCollection<AgentMessageViewModel> Messages { get; } = new();

    /// <summary>Gets the collection of pinned messages shown under Evidence.</summary>
    public ObservableCollection<AgentMessageViewModel> PinnedMessages { get; } = new();

    /// <summary>
    /// Gets the newest completed Agent message that can be pinned. This provides a
    /// stable semantic target outside Avalonia's templated chat rows, whose nested
    /// buttons are not consistently exported by AT-SPI on Linux.
    /// </summary>
    public AgentMessageViewModel? LatestPinnableMessage => Messages
        .LastOrDefault(message => !message.IsUser && message.CanBePinned);

    /// <summary>Gets whether the semantic latest-message pin action is available.</summary>
    public bool HasLatestPinnableMessage => LatestPinnableMessage != null;

    /// <summary>
    /// Gets the newest source-provided follow-up. This provides a stable semantic
    /// route outside Avalonia's nested message template, whose suggestion buttons
    /// are not consistently exported by AT-SPI on Linux.
    /// </summary>
    public SuggestedFollowUp? LatestSuggestedFollowUp => Messages
        .LastOrDefault(message => message.HasSuggestions)
        ?.Suggestions.FirstOrDefault();

    /// <summary>Gets whether a stable latest-suggestion action is available.</summary>
    public bool HasLatestSuggestedFollowUp => LatestSuggestedFollowUp != null;

    /// <summary>Gets the contextual label shown beside the stable suggestion action.</summary>
    public string LatestSuggestedFollowUpLabel => LatestSuggestedFollowUp?.Label ?? string.Empty;

    /// <summary>Gets quick-check actions for the "Run checks" group.</summary>
    public ObservableCollection<AgentQuickAction> QuickActionsChecks { get; } = new();

    /// <summary>Gets quick-check actions for the "Baseline" group.</summary>
    public ObservableCollection<AgentQuickAction> QuickActionsBaseline { get; } = new();

    /// <summary>Gets quick-check actions for the "Export" group.</summary>
    public ObservableCollection<AgentQuickAction> QuickActionsExport { get; } = new();

    /// <summary>Gets the programmatic action catalog for analysis actions.</summary>
    public ObservableCollection<AgentQuickAction> ToolPanelAnalysisActions { get; } = new();

    /// <summary>Gets the programmatic action catalog for focused checks.</summary>
    public ObservableCollection<AgentQuickAction> ToolPanelRunCheckActions { get; } = new();

    /// <summary>Gets the programmatic action catalog for baseline operations.</summary>
    public ObservableCollection<AgentQuickAction> ToolPanelBaselineActions { get; } = new();

    /// <summary>Gets the programmatic action catalog for export operations.</summary>
    public ObservableCollection<AgentQuickAction> ToolPanelExportActions { get; } = new();

    /// <summary>Gets the filtered slash-command palette items.</summary>
    public ObservableCollection<SlashCommandItem> FilteredSlashCommands { get; } = new();

    /// <summary>Gets the filtered items shown in the searchable slash-command help popup.</summary>
    public ObservableCollection<SlashCommandItem> FilteredSlashHelpCommands { get; } = new();

    /// <summary>Gets the active chat filter chips shown above the transcript.</summary>
    public ObservableCollection<ChatFilterChipViewModel> ActiveChatFilterChips { get; } = new();

    /// <summary>Gets the collection of recent audit history entries.</summary>
    public ObservableCollection<AuditHistoryEntry> History { get; } = new();

    /// <summary>Gets the collection of persisted remediation sessions.</summary>
    public ObservableCollection<RemediationSession> Sessions { get; } = new();

    /// <summary>Gets or sets the selected remediation session.</summary>
    public RemediationSession? SelectedSession
    {
        get => _selectedSession;
        set
        {
            if (SetField(ref _selectedSession, value))
            {
                ResumeSessionCommand.RaiseCanExecuteChanged();
                DeleteSessionCommand.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>Gets available severity filters for the chat.</summary>
    public ObservableCollection<SeverityFilterOption> ChatSeverityFilters { get; } = new()
    {
        new SeverityFilterOption("All severities", Severity.Info),
        new SeverityFilterOption("High & Critical only", Severity.High),
        new SeverityFilterOption("Critical only", Severity.Critical)
    };

    /// <summary>Gets or sets the selected severity filter for chat findings.</summary>
    public SeverityFilterOption? SelectedChatSeverityFilter
    {
        get => _selectedChatSeverityFilter;
        set
        {
            if (SetField(ref _selectedChatSeverityFilter, value))
            {
                _presenter.ApplyChatFilters();
                RefreshActiveFilterChips();
                UpdateHasNoSearchMatches();
            }
        }
    }

    /// <summary>Gets available category filters from the current audit.</summary>
    public ObservableCollection<string> ChatCategoryFilters { get; } = new();

    /// <summary>Gets or sets the selected category filter for chat findings.</summary>
    public string? SelectedChatCategoryFilter
    {
        get => _selectedChatCategoryFilter;
        set
        {
            if (SetField(ref _selectedChatCategoryFilter, value))
            {
                _presenter.ApplyChatFilters();
                RefreshActiveFilterChips();
                UpdateHasNoSearchMatches();
            }
        }
    }

    private AuditHistoryEntry? _selectedBeforeEntry;
    private AuditHistoryEntry? _selectedAfterEntry;

    /// <summary>Gets or sets the selected "before" history entry for diff.</summary>
    public AuditHistoryEntry? SelectedBeforeEntry
    {
        get => _selectedBeforeEntry;
        set
        {
            if (SetField(ref _selectedBeforeEntry, value))
            {
                CompareSelectedAuditsCommand.RaiseCanExecuteChanged();
                OnPropertyChanged(nameof(CanCompareSelectedAudits));
            }
        }
    }

    /// <summary>Gets or sets the selected "after" history entry for diff.</summary>
    public AuditHistoryEntry? SelectedAfterEntry
    {
        get => _selectedAfterEntry;
        set
        {
            if (SetField(ref _selectedAfterEntry, value))
            {
                CompareSelectedAuditsCommand.RaiseCanExecuteChanged();
                OnPropertyChanged(nameof(CanCompareSelectedAudits));
            }
        }
    }

    /// <summary>Gets whether two specific history entries are selected for comparison.</summary>
    public bool CanCompareSelectedAudits => SelectedBeforeEntry != null && SelectedAfterEntry != null;

    /// <summary>Gets or sets the user's current query text.</summary>
    public string UserQuery
    {
        get => _userQuery;
        set
        {
            if (SetField(ref _userQuery, value))
            {
                SendQueryCommand.RaiseCanExecuteChanged();
                UpdateSlashPalette();
            }
        }
    }

    /// <summary>Gets or sets the current firewall log text to include in agent analysis.</summary>
    public string LogText
    {
        get => _logText;
        set => SetField(ref _logText, value);
    }

    /// <summary>Gets whether an agent operation is in progress.</summary>
    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (SetField(ref _isBusy, value))
            {
                AgentStatus = value ? "Busy" : "Online";
                if (value)
                {
                    // Collapse the tools panel when an operation starts so it does not
                    // cover the transcript/results while the check runs.
                    IsAgentToolsPanelOpen = false;
                }
                // Reset on every transition: clears stale values when an operation ends (hide the
                // bar) and when the next one starts (no leftover label/percent from the prior op,
                // which a late Progress<T> callback may have written after the previous reset).
                AuditProgressPercent = 0;
                AuditProgressMessage = string.Empty;
                AuditProgressIsIndeterminate = false;
                OnPropertyChanged(nameof(ShowAuditProgress));
                SendQueryCommand.RaiseCanExecuteChanged();
                ExecuteSlashCommandCommand.RaiseCanExecuteChanged();
                CancelQueryCommand.RaiseCanExecuteChanged();
                FullAuditCommand.RaiseCanExecuteChanged();
                PrepareLogAnalysisCommand.RaiseCanExecuteChanged();
                PrepareInvestigationCommand.RaiseCanExecuteChanged();
                FirewallCommand.RaiseCanExecuteChanged();
                PortsCommand.RaiseCanExecuteChanged();
                ServicesCommand.RaiseCanExecuteChanged();
                NetworkCommand.RaiseCanExecuteChanged();
                ContainerCommand.RaiseCanExecuteChanged();
                KubernetesCommand.RaiseCanExecuteChanged();
                YaraCommand.RaiseCanExecuteChanged();
                ProcessRuntimeCommand.RaiseCanExecuteChanged();
                ExplainSelectedCommand.RaiseCanExecuteChanged();
                VerifySelectedCommand.RaiseCanExecuteChanged();
                ExportAuditCommand.RaiseCanExecuteChanged();
                ExportRemediationCommand.RaiseCanExecuteChanged();
                VerifySessionCommand.RaiseCanExecuteChanged();
                ExportSessionCommand.RaiseCanExecuteChanged();
                ExportThreatIntelCommand.RaiseCanExecuteChanged();
                CompareAuditsCommand.RaiseCanExecuteChanged();
                BatchAutoFixCommand.RaiseCanExecuteChanged();
                RunLatestSuggestedFollowUpCommand.RaiseCanExecuteChanged();
                OnPropertyChanged(nameof(CanExplainSelected));
                OnPropertyChanged(nameof(CanVerifySelected));
                OnPropertyChanged(nameof(CanExportAudit));
                OnPropertyChanged(nameof(CanExportSession));
                OnPropertyChanged(nameof(CanExportThreatIntel));
                OnPropertyChanged(nameof(CanBatchAutoFix));
                OnPropertyChanged(nameof(CanCompareAudits));
                if (value)
                {
                    _lastOperationFailed = false;
                    CurrentOperationTitle = "Agent operation";
                    StartElapsedTimer();
                }
                else
                {
                    StopElapsedTimer();
                    _lastOperationFailed = _operationRunner.LastFailed;
                }
                NotifyPageStateChanged();
            }
        }
    }

    // ── Page state machine ─────────────────────────────────────────────

    /// <summary>Gets the high-level visual state of the workspace.</summary>
    public AgentPageState CurrentPageState
    {
        get
        {
            if (_isBusy) return AgentPageState.Running;
            if (_lastOperationFailed) return AgentPageState.Error;
            if (_resultState.HasCompletedAudit)
                return AgentPageState.Results;
            return AgentPageState.Idle;
        }
    }

    /// <summary>True when the workspace should show the idle hero + mission cards.</summary>
    public bool IsIdleState => CurrentPageState == AgentPageState.Idle;

    /// <summary>True when the workspace should show the running progress view.</summary>
    public bool IsRunningState => CurrentPageState == AgentPageState.Running;

    /// <summary>True when the workspace should show the results master-detail.</summary>
    public bool IsResultsState => CurrentPageState == AgentPageState.Results;

    /// <summary>True when the workspace should show an error state.</summary>
    public bool IsErrorState => CurrentPageState == AgentPageState.Error;

    /// <summary>Gets whether the compact idle suggestions are visible above the transcript.</summary>
    public bool ShowIdleWorkspace => IsIdleState;

    /// <summary>Gets whether running progress is visible above the transcript.</summary>
    public bool ShowRunningWorkspace => IsRunningState;

    /// <summary>Gets whether the latest result artifact is visible above the transcript.</summary>
    public bool ShowResultsWorkspace => IsResultsState;

    /// <summary>Gets whether the latest error artifact is visible above the transcript.</summary>
    public bool ShowErrorWorkspace => IsErrorState;

    /// <summary>Gets the semantic Trace Pulse progress shown around the Agent avatar.</summary>
    public double TracePulseProgress => CurrentPageState switch
    {
        AgentPageState.Running => AuditProgressPercent,
        AgentPageState.Results or AgentPageState.Error => 100,
        _ => 0
    };

    /// <summary>Gets whether the Trace Pulse should rotate while progress is unknown.</summary>
    public bool TracePulseIsIndeterminate => IsRunningState && AuditProgressIsIndeterminate;

    /// <summary>Gets the concise, truthful Agent state used in the header.</summary>
    public string TracePulseStatusText => CurrentPageState switch
    {
        AgentPageState.Running => "Investigating",
        AgentPageState.Results => "Completed",
        AgentPageState.Error => "Blocked",
        _ => "Ready"
    };

    /// <summary>Gets the live detail carried by the Trace Pulse state.</summary>
    public string TracePulseDetailText => CurrentPageState switch
    {
        AgentPageState.Running when !string.IsNullOrWhiteSpace(AuditProgressMessage) => AuditProgressMessage,
        AgentPageState.Running => CurrentOperationTitle,
        AgentPageState.Results => ActiveFindingCount == 1
            ? "1 active finding in the latest run"
            : $"{ActiveFindingCount} active findings in the latest run",
        AgentPageState.Error => "Review the recovery context in the conversation",
        _ => "Conversation and investigation workspace"
    };

    /// <summary>Gets a screen-reader description of the Trace Pulse state.</summary>
    public string TracePulseAccessibleName => $"Agent {TracePulseStatusText}: {TracePulseDetailText}";

    /// <summary>
    /// Whether the transcript is available. Agent-first layout keeps it open;
    /// the property remains for command/test compatibility.
    /// </summary>
    public bool IsTranscriptOpen
    {
        get => _isTranscriptOpen;
        set
        {
            if (SetField(ref _isTranscriptOpen, value))
            {
                OnPropertyChanged(nameof(ShowIdleWorkspace));
                OnPropertyChanged(nameof(ShowRunningWorkspace));
                OnPropertyChanged(nameof(ShowResultsWorkspace));
                OnPropertyChanged(nameof(ShowErrorWorkspace));
            }
        }
    }

    /// <summary>Elapsed time display string (e.g. "1:23") updated during operations.</summary>
    public string ElapsedDisplay
    {
        get => _elapsedDisplay;
        private set => SetField(ref _elapsedDisplay, value);
    }

    /// <summary>Gets the truthful label for the operation currently reporting progress.</summary>
    public string CurrentOperationTitle
    {
        get => _currentOperationTitle;
        private set
        {
            if (SetField(ref _currentOperationTitle, value))
            {
                OnPropertyChanged(nameof(TracePulseDetailText));
                OnPropertyChanged(nameof(TracePulseAccessibleName));
            }
        }
    }

    /// <summary>Phase step items for the running-state checklist.</summary>
    public ObservableCollection<PhaseStepViewModel> PhaseSteps { get; } = new();

    /// <summary>Findings adapted for the results-state DataGrid.</summary>
    public ObservableCollection<FindingItemViewModel> ResultFindings { get; } = new();

    /// <summary>The finding selected in the results DataGrid, driving the detail pane.</summary>
    public FindingItemViewModel? SelectedResultFinding
    {
        get => _selectedResultFinding;
        set
        {
            if (SetField(ref _selectedResultFinding, value))
            {
                OnPropertyChanged(nameof(HasSelectedResultFinding));
                OnPropertyChanged(nameof(SelectedResultFindingPinLabel));
                ExplainSelectedCommand?.RaiseCanExecuteChanged();
                VerifySelectedCommand?.RaiseCanExecuteChanged();
                ToggleResultFindingPinCommand?.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>Whether a finding is selected in the results pane.</summary>
    public bool HasSelectedResultFinding => _selectedResultFinding != null;

    /// <summary>Gets whether the completed audit contains findings.</summary>
    public bool HasResultFindings => ResultFindings.Count > 0;

    /// <summary>Gets whether the completed audit finished cleanly with no findings.</summary>
    public bool HasNoResultFindings => _resultState.HasCompletedAudit && ResultFindings.Count == 0;

    /// <summary>Gets the pin action label for the selected result finding.</summary>
    public string SelectedResultFindingPinLabel => SelectedResultFinding?.IsPinned == true ? "Unpin" : "Pin";

    /// <summary>Pinned findings for the inspector panel.</summary>
    public ObservableCollection<VulcansTrace.Linux.Agent.Findings.PinnedFinding> InspectorPinnedFindings { get; } = new();

    /// <summary>Whether there are pinned findings to show.</summary>
    public bool HasInspectorPinnedFindings => InspectorPinnedFindings.Count > 0;

    /// <summary>Whether session data (results) exists.</summary>
    public bool HasSessionData => _resultState.LastResult != null;

    /// <summary>Gets a human-readable session data status.</summary>
    public string SessionDataStatusText => HasSessionData ? "Loaded" : "None";

    /// <summary>Gets the active finding count for the current session.</summary>
    public int ActiveFindingCount => _resultState.LastResult?.AgentFindings.Count ?? 0;

    /// <summary>Gets a truthful status label for the current session.</summary>
    public string CurrentSessionStatus => CurrentPageState switch
    {
        AgentPageState.Running => "Running",
        AgentPageState.Results => "Completed",
        AgentPageState.Error => "Error",
        _ => "Idle"
    };

    /// <summary>Formatted session creation time.</summary>
    public string SessionCreatedDisplay => _resultState.LastResult != null
        ? _resultState.LastResult.UtcTimestamp.ToLocalTime().ToString("g")
        : "Not started";

    /// <summary>Scan profile display name derived from the current intensity.</summary>
    public string ScanProfileName
    {
        get => _scanProfileName;
        private set => SetField(ref _scanProfileName, value);
    }

    /// <summary>Scan profile description text.</summary>
    public string ScanProfileDescription
    {
        get => _scanProfileDescription;
        private set => SetField(ref _scanProfileDescription, value);
    }

    /// <summary>Gets the active baseline status shown in the application chrome.</summary>
    public string BaselineStatusText
    {
        get => _baselineStatusText;
        private set => SetField(ref _baselineStatusText, value);
    }

    /// <summary>Updates the Agent inspector to match the actual analysis intensity.</summary>
    public void UpdateScanProfile(string name, string description)
    {
        ScanProfileName = name;
        ScanProfileDescription = description;
    }

    private void NotifyPageStateChanged()
    {
        OnPropertyChanged(nameof(CurrentPageState));
        OnPropertyChanged(nameof(IsIdleState));
        OnPropertyChanged(nameof(IsRunningState));
        OnPropertyChanged(nameof(IsResultsState));
        OnPropertyChanged(nameof(IsErrorState));
        OnPropertyChanged(nameof(ShowIdleWorkspace));
        OnPropertyChanged(nameof(ShowRunningWorkspace));
        OnPropertyChanged(nameof(ShowResultsWorkspace));
        OnPropertyChanged(nameof(ShowErrorWorkspace));
        OnPropertyChanged(nameof(HasSessionData));
        OnPropertyChanged(nameof(SessionDataStatusText));
        OnPropertyChanged(nameof(ActiveFindingCount));
        OnPropertyChanged(nameof(CurrentSessionStatus));
        OnPropertyChanged(nameof(SessionCreatedDisplay));
        OnPropertyChanged(nameof(TracePulseProgress));
        OnPropertyChanged(nameof(TracePulseIsIndeterminate));
        OnPropertyChanged(nameof(TracePulseStatusText));
        OnPropertyChanged(nameof(TracePulseDetailText));
        OnPropertyChanged(nameof(TracePulseAccessibleName));
    }

    private void StartElapsedTimer()
    {
        _operationStartTime = DateTime.UtcNow;
        ElapsedDisplay = "0:00";
        _elapsedTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _elapsedTimer.Tick += (_, _) =>
        {
            var elapsed = DateTime.UtcNow - _operationStartTime;
            ElapsedDisplay = elapsed.TotalHours >= 1
                ? $"{(int)elapsed.TotalHours}:{elapsed.Minutes:D2}:{elapsed.Seconds:D2}"
                : $"{(int)elapsed.TotalMinutes}:{elapsed.Seconds:D2}";
        };
        _elapsedTimer.Start();
    }

    private void StopElapsedTimer()
    {
        _elapsedTimer?.Stop();
        _elapsedTimer = null;
    }

    private void PopulateResultFindings()
    {
        ResultFindings.Clear();
        SelectedResultFinding = null;
        var findings = _resultState.LastResult?.AgentFindings;
        if (findings != null)
        {
            foreach (var f in findings)
            {
                ResultFindings.Add(new FindingItemViewModel(f));
            }
        }
        OnPropertyChanged(nameof(HasResultFindings));
        OnPropertyChanged(nameof(HasNoResultFindings));
    }

    /// <summary>Clears the results-grid selection when another finding surface takes focus.</summary>
    public void ClearResultSelection() => SelectedResultFinding = null;

    /// <summary>Reloads the inspector's pinned findings from the shared application store.</summary>
    public void RefreshInspectorPinnedFindings()
    {
        InspectorPinnedFindings.Clear();
        var pinned = PinnedFindingsProvider?.Invoke() ?? Array.Empty<VulcansTrace.Linux.Agent.Findings.PinnedFinding>();
        foreach (var finding in pinned)
            InspectorPinnedFindings.Add(finding);
        OnPropertyChanged(nameof(HasInspectorPinnedFindings));
    }

    private void ToggleSelectedResultFindingPin()
    {
        var selected = SelectedResultFinding;
        if (selected == null || RequestToggleResultFindingPin == null)
            return;

        RequestToggleResultFindingPin(selected);
        OnPropertyChanged(nameof(SelectedResultFindingPinLabel));
        RefreshInspectorPinnedFindings();
        ToggleResultFindingPinCommand.RaiseCanExecuteChanged();
    }

    /// <summary>Gets the current agent status for the header badge.</summary>
    public string AgentStatus
    {
        get => _agentStatus;
        private set => SetField(ref _agentStatus, value);
    }

    /// <summary>Gets the current audit progress percent (0–100).</summary>
    public double AuditProgressPercent
    {
        get => _auditProgressPercent;
        private set
        {
            if (SetField(ref _auditProgressPercent, value))
            {
                OnPropertyChanged(nameof(TracePulseProgress));
                OnPropertyChanged(nameof(TracePulseAccessibleName));
            }
        }
    }

    /// <summary>Gets the current audit progress message.</summary>
    public string AuditProgressMessage
    {
        get => _auditProgressMessage;
        private set
        {
            if (SetField(ref _auditProgressMessage, value))
            {
                OnPropertyChanged(nameof(TracePulseDetailText));
                OnPropertyChanged(nameof(TracePulseAccessibleName));
            }
        }
    }

    /// <summary>Gets whether the progress bar should be indeterminate.</summary>
    public bool AuditProgressIsIndeterminate
    {
        get => _auditProgressIsIndeterminate;
        private set
        {
            if (SetField(ref _auditProgressIsIndeterminate, value))
            {
                OnPropertyChanged(nameof(TracePulseIsIndeterminate));
            }
        }
    }

    /// <summary>Gets whether to show the determinate audit progress UI.</summary>
    public bool ShowAuditProgress => IsBusy && !string.IsNullOrEmpty(AuditProgressMessage);

    /// <summary>Gets the number of pinned messages currently saved.</summary>
    public int PinnedMessageCount
    {
        get => _pinnedMessageCount;
        private set
        {
            if (SetField(ref _pinnedMessageCount, value))
            {
                OnPropertyChanged(nameof(HasPinnedMessages));
                OnPropertyChanged(nameof(PinnedMessageCountLabel));
            }
        }
    }

    /// <summary>Gets whether there are any pinned messages.</summary>
    public bool HasPinnedMessages => PinnedMessageCount > 0;

    /// <summary>Gets the formatted pinned message count label for the Evidence tab.</summary>
    public string PinnedMessageCountLabel => PinnedMessageCount > 0 ? $"({PinnedMessageCount})" : string.Empty;

    /// <summary>Gets the latest pinned-message persistence warning, if any.</summary>
    public string PinMessageStatusMessage
    {
        get => _pinMessageStatusMessage;
        private set
        {
            if (SetField(ref _pinMessageStatusMessage, value))
            {
                OnPropertyChanged(nameof(HasPinMessageStatusMessage));
            }
        }
    }

    /// <summary>Gets whether the pinned-message status message should be shown.</summary>
    public bool HasPinMessageStatusMessage => !string.IsNullOrWhiteSpace(PinMessageStatusMessage);

    /// <summary>Gets whether only the initial welcome message is shown.</summary>
    public bool HasOnlyWelcomeMessage
    {
        get => _hasOnlyWelcomeMessage;
        private set
        {
            if (SetField(ref _hasOnlyWelcomeMessage, value))
            {
                OnPropertyChanged(nameof(IsThreadActive));
            }
        }
    }

    /// <summary>
    /// Gets whether the thread has content beyond the welcome state. Drives the
    /// results-state compaction of the agent header (UI v2 Phase 2).
    /// </summary>
    public bool IsThreadActive => !HasOnlyWelcomeMessage;

    /// <summary>Gets whether the agent tools panel is expanded.</summary>
    public bool IsAgentToolsPanelOpen
    {
        get => _isAgentToolsPanelOpen;
        set => SetField(ref _isAgentToolsPanelOpen, value);
    }

    /// <summary>Gets whether messages exist but none are visible under the current filters.</summary>
    public bool HasNoVisibleMessages
    {
        get => _hasNoVisibleMessages;
        private set => SetField(ref _hasNoVisibleMessages, value);
    }

    /// <summary>Re-evaluates <see cref="HasNoVisibleMessages"/> and raises change notification if it changed.</summary>
    public void RefreshHasNoVisibleMessages()
    {
        if (SetField(ref _hasNoVisibleMessages, Messages.Count > 0 && Messages.All(m => !m.IsVisible), nameof(HasNoVisibleMessages)))
        {
            OnPropertyChanged(nameof(HasNoVisibleFilterMessages));
        }
    }

    /// <summary>Gets or sets the chat transcript search text.</summary>
    public string ChatSearchQuery
    {
        get => _chatSearchQuery;
        set
        {
            if (SetField(ref _chatSearchQuery, value))
            {
                _presenter.SetSearchQuery(value);
                ClearChatSearchCommand.RaiseCanExecuteChanged();
                UpdateHasNoSearchMatches();
            }
        }
    }

    /// <summary>Gets whether messages exist but none match the current search query.</summary>
    public bool HasNoSearchMatches
    {
        get => _hasNoSearchMatches;
        private set => SetField(ref _hasNoSearchMatches, value);
    }

    /// <summary>
    /// Gets whether active non-search filters have no matching finding messages.
    /// Context messages (the welcome text, user prompts, and informational summaries) stay
    /// visible by design, so using <see cref="HasNoVisibleMessages"/> here would make the
    /// filter empty state unreachable in the real transcript.
    /// </summary>
    public bool HasNoVisibleFilterMessages =>
        string.IsNullOrWhiteSpace(_chatSearchQuery)
        && HasActiveChatFilters
        && !Messages.Any(IsFilterableFindingMessageAndVisible);

    private static bool IsFilterableFindingMessageAndVisible(AgentMessageViewModel message) =>
        message.IsRowVisible
        && !message.IsUser
        && !message.IsInfo
        && !string.IsNullOrWhiteSpace(message.Category);

    /// <summary>Gets the empty-state text for a chat search with no visible matches.</summary>
    public string ChatSearchEmptyStateText => HasActiveChatFilters
        ? "No visible messages match your search and active filters."
        : "No messages match your search.";

    private void UpdateHasNoSearchMatches()
    {
        HasNoSearchMatches = !string.IsNullOrWhiteSpace(_chatSearchQuery)
            && Messages.Count > 0
            && Messages.All(m => !m.IsVisible);
        OnPropertyChanged(nameof(HasNoVisibleFilterMessages));
        OnPropertyChanged(nameof(ChatSearchEmptyStateText));
    }

    private bool HasActiveChatFilters
    {
        get
        {
            var hasSeverityFilter = _selectedChatSeverityFilter != null
                && ChatSeverityFilters.Count > 0
                && _selectedChatSeverityFilter != ChatSeverityFilters[0];
            var hasCategoryFilter = !string.IsNullOrWhiteSpace(_selectedChatCategoryFilter)
                && !_selectedChatCategoryFilter.Equals(ChatFilterConstants.AllCategoriesFilter, StringComparison.OrdinalIgnoreCase);

            return hasSeverityFilter || hasCategoryFilter;
        }
    }

    /// <summary>Moves to the previous query in history (Up arrow behavior).</summary>
    public void RecallPreviousQuery()
    {
        if (_queryHistory.Count == 0)
            return;

        if (_queryHistoryIndex < 0)
            _queryHistoryIndex = _queryHistory.Count - 1;
        else if (_queryHistoryIndex > 0)
            _queryHistoryIndex--;

        UserQuery = _queryHistory[_queryHistoryIndex];
    }

    /// <summary>Moves to the next query in history (Down arrow behavior).</summary>
    public void RecallNextQuery()
    {
        if (_queryHistory.Count == 0 || _queryHistoryIndex < 0)
            return;

        _queryHistoryIndex++;
        if (_queryHistoryIndex >= _queryHistory.Count)
        {
            _queryHistoryIndex = -1;
            UserQuery = string.Empty;
        }
        else
        {
            UserQuery = _queryHistory[_queryHistoryIndex];
        }
    }

    private SlashCommandItem? _selectedSlashCommand;

    /// <summary>Gets or sets the currently selected slash-command palette item.</summary>
    public SlashCommandItem? SelectedSlashCommand
    {
        get => _selectedSlashCommand;
        set => SetField(ref _selectedSlashCommand, value);
    }

    /// <summary>
    /// Moves the slash-command selection to the next item, wrapping to the top.
    /// </summary>
    public void SelectNextSlashCommand()
    {
        if (FilteredSlashCommands.Count == 0)
            return;

        var index = SelectedSlashCommand is null ? -1 : FilteredSlashCommands.IndexOf(SelectedSlashCommand);
        index = (index + 1) % FilteredSlashCommands.Count;
        SelectedSlashCommand = FilteredSlashCommands[index];
    }

    /// <summary>
    /// Moves the slash-command selection to the previous item, wrapping to the bottom.
    /// </summary>
    public void SelectPreviousSlashCommand()
    {
        if (FilteredSlashCommands.Count == 0)
            return;

        var index = SelectedSlashCommand is null ? 0 : FilteredSlashCommands.IndexOf(SelectedSlashCommand);
        index = (index - 1 + FilteredSlashCommands.Count) % FilteredSlashCommands.Count;
        SelectedSlashCommand = FilteredSlashCommands[index];
    }
    /// <summary>Gets whether the slash-command palette is open.</summary>
    public bool IsSlashPaletteOpen
    {
        get => _isSlashPaletteOpen;
        private set => SetField(ref _isSlashPaletteOpen, value);
    }

    /// <summary>
    /// Dismisses the slash-command palette without clearing the typed query, so an Esc or click-away
    /// doesn't discard what the user entered; editing the query reopens the palette through
    /// <see cref="UpdateSlashPalette"/>. Wired to the Esc key and TextBox blur in the view.
    /// </summary>
    public void CloseSlashPalette()
    {
        IsSlashPaletteOpen = false;
        FilteredSlashCommands.Clear();
        SelectedSlashCommand = null;
    }

    /// <summary>Gets whether the searchable slash-command help popup is open.</summary>
    public bool IsSlashHelpOpen
    {
        get => _isSlashHelpOpen;
        private set
        {
            if (SetField(ref _isSlashHelpOpen, value))
            {
                OpenSlashHelpCommand.RaiseCanExecuteChanged();
                CloseSlashHelpCommand.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>Gets or sets the search text in the slash-command help popup.</summary>
    public string SlashHelpQuery
    {
        get => _slashHelpQuery;
        set
        {
            if (SetField(ref _slashHelpQuery, value))
            {
                UpdateSlashHelpFilter();
            }
        }
    }

    /// <summary>Gets or sets the currently selected item in the slash-command help popup.</summary>
    public SlashCommandItem? SelectedSlashHelpCommand
    {
        get => _selectedSlashHelpCommand;
        set => SetField(ref _selectedSlashHelpCommand, value);
    }

    /// <summary>Opens the searchable slash-command help popup.</summary>
    public void OpenSlashHelp()
    {
        // Dismiss the inline palette so only one command surface is visible at a time.
        IsSlashPaletteOpen = false;
        FilteredSlashCommands.Clear();
        SelectedSlashCommand = null;

        SlashHelpQuery = string.Empty;
        IsSlashHelpOpen = true;
        UpdateSlashHelpFilter();
    }

    /// <summary>Closes the searchable slash-command help popup.</summary>
    public void CloseSlashHelp()
    {
        IsSlashHelpOpen = false;
        SlashHelpQuery = string.Empty;
        FilteredSlashHelpCommands.Clear();
        SelectedSlashHelpCommand = null;
    }

    /// <summary>Moves the help-popup selection to the next item, wrapping to the top.</summary>
    public void SelectNextSlashHelpCommand()
    {
        if (FilteredSlashHelpCommands.Count == 0)
            return;

        var index = SelectedSlashHelpCommand is null ? -1 : FilteredSlashHelpCommands.IndexOf(SelectedSlashHelpCommand);
        index = (index + 1) % FilteredSlashHelpCommands.Count;
        SelectedSlashHelpCommand = FilteredSlashHelpCommands[index];
    }

    /// <summary>Moves the help-popup selection to the previous item, wrapping to the bottom.</summary>
    public void SelectPreviousSlashHelpCommand()
    {
        if (FilteredSlashHelpCommands.Count == 0)
            return;

        var index = SelectedSlashHelpCommand is null ? 0 : FilteredSlashHelpCommands.IndexOf(SelectedSlashHelpCommand);
        index = (index - 1 + FilteredSlashHelpCommands.Count) % FilteredSlashHelpCommands.Count;
        SelectedSlashHelpCommand = FilteredSlashHelpCommands[index];
    }

    /// <summary>Gets the last agent result.</summary>
    public AgentResult? LastResult => _resultState.LastResult;

    /// <summary>Gets whether the last agent operation completed without erroring or being cancelled.</summary>
    public bool LastOperationSucceeded => _operationRunner.LastSucceeded;

    /// <summary>Gets whether the selected UI finding can be explained now.</summary>
    public bool CanExplainSelected => !_isBusy && GetSelectedFinding() != null;

    /// <summary>Gets whether the selected UI finding can be verified now.</summary>
    public bool CanVerifySelected => !_isBusy && GetSelectedFinding() is Finding f && !string.IsNullOrWhiteSpace(f.RuleId);

    /// <summary>Gets whether the latest agent result is an audit that can be exported.</summary>
    public bool CanExportAudit => !_isBusy && _resultState.IsExportableAudit;

    /// <summary>Gets whether the latest agent result has a remediation session report to export.</summary>
    public bool CanExportSession => !_isBusy && _resultState.LastResult?.RemediationSession != null;

    /// <summary>Gets whether the latest agent result can be exported as STIX/MISP threat intelligence.</summary>
    public bool CanExportThreatIntel => !_isBusy && _resultState.IsExportableAudit;

    /// <summary>Gets whether a batch auto-fix can run over the latest audit findings.</summary>
    public bool CanBatchAutoFix => !_isBusy && _resultState.LastResult?.AgentFindings.Count > 0;

    /// <summary>Gets whether two audit snapshots are available for comparison.</summary>
    public bool CanCompareAudits => History.Count >= 2;

    /// <summary>Gets whether a privilege warning is active.</summary>
    public bool HasPrivilegeWarning
    {
        get => _hasPrivilegeWarning;
        private set => SetField(ref _hasPrivilegeWarning, value);
    }

    /// <summary>Gets the privilege warning text.</summary>
    public string PrivilegeWarningText
    {
        get => _privilegeWarningText;
        private set => SetField(ref _privilegeWarningText, value);
    }

    /// <summary>
    /// Optional provider that returns the currently selected finding from the UI.
    /// When set, ExplainFinding queries will target this finding if no explicit reference is given.
    /// </summary>
    public Func<Finding?>? SelectedFindingProvider { get; set; }

    /// <summary>Raised when an agent audit completes successfully.</summary>
    public event EventHandler<AgentResult>? AuditCompleted;

    /// <summary>Raised when a mission card requests focus for the shared composer.</summary>
    public event EventHandler? ComposerFocusRequested;

    /// <summary>Gets the command to send a query to the agent.</summary>
    public AsyncRelayCommand SendQueryCommand { get; }

    /// <summary>Gets the command to cancel the current agent operation.</summary>
    public RelayCommand CancelQueryCommand { get; }

    /// <summary>Gets the command to execute a slash-command palette item.</summary>
    public AsyncRelayCommand ExecuteSlashCommandCommand { get; }

    /// <summary>Gets the command to run a full audit.</summary>
    public AsyncRelayCommand FullAuditCommand { get; }

    /// <summary>Gets the command that prepares the composer for pasted-log analysis.</summary>
    public RelayCommand PrepareLogAnalysisCommand { get; }

    /// <summary>Gets the command that prepares the composer for a targeted investigation.</summary>
    public RelayCommand PrepareInvestigationCommand { get; }

    /// <summary>Gets the command to run a firewall check.</summary>
    public AsyncRelayCommand FirewallCommand { get; }

    /// <summary>Gets the command to run a port check.</summary>
    public AsyncRelayCommand PortsCommand { get; }

    /// <summary>Gets the command to run a service check.</summary>
    public AsyncRelayCommand ServicesCommand { get; }

    /// <summary>Gets the command to run a network check.</summary>
    public AsyncRelayCommand NetworkCommand { get; }

    /// <summary>Gets the command to run a container security check.</summary>
    public AsyncRelayCommand ContainerCommand { get; }

    /// <summary>Gets the command to run a Kubernetes security check.</summary>
    public AsyncRelayCommand KubernetesCommand { get; }

    /// <summary>Gets the command to run a YARA malware signature scan.</summary>
    public AsyncRelayCommand YaraCommand { get; }

    /// <summary>Gets the command to run a process runtime check.</summary>
    public AsyncRelayCommand ProcessRuntimeCommand { get; }

    /// <summary>Gets the command to explain the selected finding.</summary>
    public AsyncRelayCommand ExplainSelectedCommand { get; }

    /// <summary>Gets the command to verify the selected finding has been remediated.</summary>
    public AsyncRelayCommand VerifySelectedCommand { get; }

    /// <summary>Gets the command to export the last agent audit.</summary>
    public RelayCommand ExportAuditCommand { get; }

    /// <summary>Gets the command to save the last audit as a baseline.</summary>
    public AsyncRelayCommand SetBaselineCommand { get; }

    /// <summary>Gets the command to check drift against the saved baseline.</summary>
    public AsyncRelayCommand CheckDriftCommand { get; }

    /// <summary>Gets the command to show the current baseline.</summary>
    public AsyncRelayCommand ShowBaselineCommand { get; }

    /// <summary>Gets the command to open the searchable slash-command help popup.</summary>
    public RelayCommand OpenSlashHelpCommand { get; }

    /// <summary>Gets the command to close the searchable slash-command help popup.</summary>
    public RelayCommand CloseSlashHelpCommand { get; }

    /// <summary>Gets the command to compare the last two audits.</summary>
    public RelayCommand CompareAuditsCommand { get; }

    /// <summary>Gets the command to compare two selected audits.</summary>
    public RelayCommand CompareSelectedAuditsCommand { get; }

    /// <summary>Gets the command to clear chat filters.</summary>
    public RelayCommand ClearChatFiltersCommand { get; }

    /// <summary>Gets the command to clear the chat transcript search.</summary>
    public RelayCommand ClearChatSearchCommand { get; }

    /// <summary>Gets the command to export a remediation plan for the last audit.</summary>
    public RelayCommand ExportRemediationCommand { get; }

    /// <summary>Gets the command to run verification on an active remediation session.</summary>
    public AsyncRelayCommand VerifySessionCommand { get; }

    /// <summary>Gets the command to export the current remediation session report.</summary>
    public AsyncRelayCommand ExportSessionCommand { get; }

    /// <summary>Gets the command to export findings as STIX or MISP threat intelligence.</summary>
    public AsyncRelayCommand ExportThreatIntelCommand { get; }

    /// <summary>Gets the command to list persisted remediation sessions.</summary>
    public AsyncRelayCommand ListSessionsCommand { get; }

    /// <summary>Gets the command to resume the selected remediation session.</summary>
    public AsyncRelayCommand ResumeSessionCommand { get; }

    /// <summary>Gets the command to delete the selected remediation session.</summary>
    public AsyncRelayCommand DeleteSessionCommand { get; }

    /// <summary>Gets the command to import threat intelligence IOCs.</summary>
    public AsyncRelayCommand ImportThreatIntelCommand { get; }

    /// <summary>Gets the command to toggle the agent tools panel.</summary>
    public RelayCommand ToggleAgentToolsPanelCommand { get; }

    /// <summary>Gets the command to toggle the chat transcript panel.</summary>
    public RelayCommand ToggleTranscriptCommand { get; }

    /// <summary>Gets the command to pin or unpin the selected result finding.</summary>
    public RelayCommand ToggleResultFindingPinCommand { get; }

    /// <summary>Gets the command to pin or unpin a chat message.</summary>
    public AsyncRelayCommand<AgentMessageViewModel> TogglePinMessageCommand { get; }

    /// <summary>Gets the command to execute the newest suggested follow-up.</summary>
    public AsyncRelayCommand RunLatestSuggestedFollowUpCommand { get; }

    /// <summary>Gets the command to deploy active countermeasures for a critical chain.</summary>
    public AsyncRelayCommand DeployCountermeasuresCommand { get; }

    /// <summary>Gets the command to run a batch auto-fix over the latest audit findings.</summary>
    public AsyncRelayCommand BatchAutoFixCommand { get; }

    /// <summary>
    /// Callback invoked when the user requests an audit export from the agent panel.
    /// Set by the parent ViewModel to bridge to the shared evidence export logic.
    /// </summary>
    public Action? RequestExportAudit { get; set; }

    /// <summary>
    /// Callback invoked when the user requests a remediation plan export.
    /// Set by the parent ViewModel to handle the save dialog.
    /// </summary>
    public Action<string>? RequestExportRemediation { get; set; }

    /// <summary>
    /// Callback invoked when the user requests a session report export.
    /// Set by the parent ViewModel to handle the save dialog and report whether the file was written.
    /// </summary>
    public Func<string, Task<bool>>? RequestExportSession { get; set; }

    /// <summary>
    /// Callback invoked when the user requests to export findings as STIX/MISP threat intelligence.
    /// Set by the parent ViewModel to handle the format selection and save dialog.
    /// </summary>
    public Func<Task<bool>>? RequestExportThreatIntel { get; set; }

    /// <summary>Callback that toggles a result finding in the shared pinned-finding store.</summary>
    public Action<FindingItemViewModel>? RequestToggleResultFindingPin { get; set; }

    /// <summary>Provider for the shared pinned-finding collection displayed by the inspector.</summary>
    public Func<IReadOnlyList<VulcansTrace.Linux.Agent.Findings.PinnedFinding>>? PinnedFindingsProvider { get; set; }

    /// <summary>
    /// Callback invoked when the user requests to show an audit diff.
    /// Set by the parent ViewModel to open the diff window.
    /// </summary>
    public Action<AuditDiff>? ShowAuditDiffAction { get; set; }

    /// <summary>
    /// Callback invoked when the user requests the log-diff demo.
    /// Set by the parent ViewModel to open a pre-loaded Log Diff window.
    /// </summary>
    public Func<Task>? ShowLogDiffDemoAction { get; set; }

    /// <summary>
    /// Callback invoked to navigate to the Threat Intel management view.
    /// Set by the parent window to switch the selected sidebar item.
    /// </summary>
    public Action? NavigateToThreatIntelAction { get; set; }

    /// <summary>
    /// Swaps the underlying agent implementation (used when machine role changes)
    /// and resets the cached result state.
    /// </summary>
    /// <param name="agent">The new agent instance to use for queries.</param>
    /// <param name="sessionStore">The session store associated with the new agent.</param>
    public void SetAgent(IAgent agent, ISessionStore? sessionStore = null)
    {
        _agent = agent ?? throw new ArgumentNullException(nameof(agent));
        _sessionStore = sessionStore ?? _sessionStore;
        SelectedSession = null;
        RefreshSessions();
        _resultState.Reset();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AgentViewModel"/> class.
    /// </summary>
    /// <param name="agent">The agent instance to use for queries.</param>
    /// <param name="historyStore">The store for persisting audit history.</param>
    /// <param name="remediationPlanBuilder">The plan builder for remediation exports.</param>
    /// <param name="sessionStore">Optional store for browsing and managing remediation sessions.</param>
    /// <param name="memoryStore">Optional store for cross-session conversation memory.</param>
    /// <param name="pinnedMessageStore">Optional store for pinned chat messages.</param>
    public AgentViewModel(IAgent agent, IAuditHistoryStore historyStore, RemediationPlanBuilder remediationPlanBuilder, RemediationExecutor remediationExecutor, ISessionStore? sessionStore = null, IThreatIntelStore? threatIntelStore = null, IDialogService? dialogService = null, IAgentMemoryStore? memoryStore = null, IPinnedMessageStore? pinnedMessageStore = null, AnalystActionLogger? analystActionLogger = null)
    {
        _agent = agent ?? throw new ArgumentNullException(nameof(agent));
        ArgumentNullException.ThrowIfNull(historyStore);
        _remediationPlanBuilder = remediationPlanBuilder ?? throw new ArgumentNullException(nameof(remediationPlanBuilder));
        _remediationExecutor = remediationExecutor ?? throw new ArgumentNullException(nameof(remediationExecutor));
        _sessionStore = sessionStore;
        _threatIntelStore = threatIntelStore;
        _dialogService = dialogService;
        _memoryStore = memoryStore;
        _pinnedMessageStore = pinnedMessageStore;
        _analystActionLogger = analystActionLogger;
        _typewriterScheduler = new DispatcherTypewriterScheduler();
        _presenter = new AgentResultPresenter(
            Messages,
            ChatCategoryFilters,
            () => _selectedChatSeverityFilter,
            () => _selectedChatCategoryFilter,
            v => HasPrivilegeWarning = v,
            t => PrivilegeWarningText = t,
            ExecuteSuggestionAsync,
            RefreshHasNoVisibleMessages,
            pinnedMessageStore: _pinnedMessageStore);
        _operationRunner = new AgentOperationRunner(
            value => IsBusy = value,
            ClearPrivilegeWarning,
            AddAgentMessage,
            OnAuditProgress);
        _queryExecutor = new AgentQueryExecutor(() => _agent);
        _historyCoordinator = new AgentHistoryCoordinator(
            historyStore,
            History,
            (text, isInfo) => _presenter.AddAgentMessage(text, isInfo),
            () => Messages,
            () =>
            {
                OnPropertyChanged(nameof(CanCompareAudits));
                CompareAuditsCommand!.RaiseCanExecuteChanged();
                CompareSelectedAuditsCommand!.RaiseCanExecuteChanged();
            });
        // SetLastResult and PublishAuditCompleted below marshal the complete
        // result-finalization operation. These callbacks therefore run directly and
        // remain in the same UI-dispatcher job as the state and history mutations.
        _resultState = new AgentResultStateCoordinator(
            _historyCoordinator,
            OnPropertyChanged,
            RefreshResultCommands,
            result => AuditCompleted?.Invoke(this, result));

        WireMessagesCollectionChanged();

        SendQueryCommand = new AsyncRelayCommand(
            async _ => await SendQueryAsync(),
            _ => CanSendQuery(),
            ex =>
            {
                IsBusy = false;
                AddAgentMessage($"Error: {ex.Message}", true, isError: true);
            });

        CancelQueryCommand = new RelayCommand(
            _ => CancelQuery(),
            _ => CanCancel());

        ExecuteSlashCommandCommand = new AsyncRelayCommand(
            async param =>
            {
                if (param is SlashCommandItem cmd && !_isBusy)
                {
                    IsSlashPaletteOpen = false;
                    IsSlashHelpOpen = false;
                    UserQuery = string.Empty;
                    if (cmd.Handler is not null)
                    {
                        await cmd.Handler();
                    }
                }
            },
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        FullAuditCommand = new AsyncRelayCommand(
            async _ => await RunQuickAuditAsync(AgentIntent.FullAudit, "Run a full audit"),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        PrepareLogAnalysisCommand = new RelayCommand(
            _ =>
            {
                IsTranscriptOpen = true;
                UserQuery = string.Empty;
                ComposerFocusRequested?.Invoke(this, EventArgs.Empty);
            },
            _ => !_isBusy);

        PrepareInvestigationCommand = new RelayCommand(
            _ =>
            {
                IsTranscriptOpen = true;
                if (string.IsNullOrWhiteSpace(UserQuery))
                    UserQuery = "Investigate ";
                ComposerFocusRequested?.Invoke(this, EventArgs.Empty);
            },
            _ => !_isBusy);

        FirewallCommand = new AsyncRelayCommand(
            async _ => await RunQuickAuditAsync(AgentIntent.FirewallCheck, "Check my firewall"),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        PortsCommand = new AsyncRelayCommand(
            async _ => await RunQuickAuditAsync(AgentIntent.PortCheck, "What ports are open?"),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        ServicesCommand = new AsyncRelayCommand(
            async _ => await RunQuickAuditAsync(AgentIntent.ServiceCheck, "What services are running?"),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        NetworkCommand = new AsyncRelayCommand(
            async _ => await RunQuickAuditAsync(AgentIntent.NetworkCheck, "Check my network"),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        ContainerCommand = new AsyncRelayCommand(
            async _ => await RunQuickAuditAsync(AgentIntent.ContainerCheck, "Check my containers"),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        KubernetesCommand = new AsyncRelayCommand(
            async _ => await RunQuickAuditAsync(AgentIntent.KubernetesCheck, "Check my kubernetes"),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        YaraCommand = new AsyncRelayCommand(
            async _ => await RunQuickAuditAsync(AgentIntent.YaraCheck, "Run a YARA scan"),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        ProcessRuntimeCommand = new AsyncRelayCommand(
            async _ => await RunQuickAuditAsync(AgentIntent.ProcessRuntimeCheck, "Check running processes"),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        ExplainSelectedCommand = new AsyncRelayCommand(
            async _ => await ExplainSelectedAsync(),
            _ => CanExplainSelected,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        VerifySelectedCommand = new AsyncRelayCommand(
            async _ => await VerifySelectedAsync(),
            _ => CanVerifySelected,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        ExportAuditCommand = new RelayCommand(
            _ => RequestExportAudit?.Invoke(),
            _ => CanExportAudit);

        ExportRemediationCommand = new RelayCommand(
            _ => ExportRemediationPlan(),
            _ => CanExportAudit);

        CompareAuditsCommand = new RelayCommand(
            _ => CompareLastTwoAudits(),
            _ => CanCompareAudits);

        CompareSelectedAuditsCommand = new RelayCommand(
            _ => CompareSelectedAudits(),
            _ => CanCompareSelectedAudits);

        ClearChatFiltersCommand = new RelayCommand(
            _ =>
            {
                SelectedChatSeverityFilter = ChatSeverityFilters[0];
                SelectedChatCategoryFilter = null;
            },
            _ => ActiveChatFilterChips.Count > 0);

        ClearChatSearchCommand = new RelayCommand(
            _ => ClearChatSearch(),
            _ => !string.IsNullOrWhiteSpace(_chatSearchQuery));

        SetBaselineCommand = new AsyncRelayCommand(
            async _ => await SetBaselineAsync(),
            _ => !_isBusy && _resultState.HasCompletedAudit,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        CheckDriftCommand = new AsyncRelayCommand(
            async _ => await CheckDriftAsync(),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        ShowBaselineCommand = new AsyncRelayCommand(
            async _ => await ShowBaselineAsync(),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        OpenSlashHelpCommand = new RelayCommand(
            _ => OpenSlashHelp(),
            _ => !_isSlashHelpOpen);

        CloseSlashHelpCommand = new RelayCommand(
            _ => CloseSlashHelp(),
            _ => _isSlashHelpOpen);

        VerifySessionCommand = new AsyncRelayCommand(
            async param => await VerifySessionAsync((param as string) ?? ""),
            param => !_isBusy && !string.IsNullOrWhiteSpace(param as string),
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        ExportSessionCommand = new AsyncRelayCommand(
            async _ => await ExportSessionAsync(),
            _ => !_isBusy && _resultState.LastResult?.RemediationSession != null,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        ExportThreatIntelCommand = new AsyncRelayCommand(
            async _ => await ExportThreatIntelAsync(),
            _ => CanExportThreatIntel,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        ListSessionsCommand = new AsyncRelayCommand(
            async _ => await ListSessionsAsync(),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        ResumeSessionCommand = new AsyncRelayCommand(
            async _ => await ResumeSessionAsync(),
            _ => !_isBusy && _selectedSession != null,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        DeleteSessionCommand = new AsyncRelayCommand(
            async _ => await DeleteSessionAsync(),
            _ => !_isBusy && _selectedSession != null,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        ImportThreatIntelCommand = new AsyncRelayCommand(
            async _ => await ImportThreatIntelAsync(),
            _ => !_isBusy && _threatIntelStore != null && _dialogService != null,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        ToggleAgentToolsPanelCommand = new RelayCommand(
            _ => IsAgentToolsPanelOpen = !IsAgentToolsPanelOpen,
            _ => true);

        ToggleTranscriptCommand = new RelayCommand(
            _ => IsTranscriptOpen = !IsTranscriptOpen,
            _ => true);

        ToggleResultFindingPinCommand = new RelayCommand(
            _ => ToggleSelectedResultFindingPin(),
            _ => !_isBusy && SelectedResultFinding != null && RequestToggleResultFindingPin != null);

        TogglePinMessageCommand = new AsyncRelayCommand<AgentMessageViewModel>(
            async msg => await TogglePinMessageAsync(msg),
            msg => msg != null,
            ex => AddAgentMessage($"Error toggling pin: {ex.Message}", true, isError: true));

        RunLatestSuggestedFollowUpCommand = new AsyncRelayCommand(
            async _ => await RunLatestSuggestedFollowUpAsync(),
            _ => !_isBusy && HasLatestSuggestedFollowUp,
            ex => AddAgentMessage($"Error running suggestion: {ex.Message}", true, isError: true));

        DeployCountermeasuresCommand = new AsyncRelayCommand(
            async param => await DeployCountermeasuresAsync(param as RemediationSection),
            param => !_isBusy && param is RemediationSection section && section.CountermeasureCommands.Count > 0,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        BatchAutoFixCommand = new AsyncRelayCommand(
            async _ => await BatchAutoFixAsync(),
            _ => CanBatchAutoFix,
            ex => AddAgentMessage($"Error: {ex.Message}", true, isError: true));

        _selectedChatSeverityFilter = ChatSeverityFilters[0];

        RefreshSessions();

        _historyCoordinator.LoadExisting();

        InitializeQuickActions();
        InitializeSlashCommands();

        // The permanent header owns identity; the first reply leads with
        // readiness and concrete capabilities instead of repeating its name.
        AddAgentMessage(WelcomeMessage, false);
        RefreshPinnedMessages();
        _historyCoordinator.ShowPersistenceWarningIfAny();
        ShowMemoryPersistenceWarningIfAny();
    }

    private void MarkChatInteracted()
    {
        HasOnlyWelcomeMessage = false;
    }

    private bool CanSendQuery() => !string.IsNullOrWhiteSpace(_userQuery) && !_isBusy;
    private bool CanCancel() => _isBusy && _operationRunner.CanCancel;

    private void InitializeQuickActions()
    {
        void AddRunCheck(AgentQuickAction action)
        {
            QuickActionsChecks.Add(action);
            ToolPanelRunCheckActions.Add(action);
        }

        void AddBaseline(AgentQuickAction action)
        {
            QuickActionsBaseline.Add(action);
            ToolPanelBaselineActions.Add(action);
        }

        void AddExport(AgentQuickAction action)
        {
            QuickActionsExport.Add(action);
            ToolPanelExportActions.Add(action);
        }

        void AddAnalysis(AgentQuickAction action)
        {
            ToolPanelAnalysisActions.Add(action);
        }

        AddAnalysis(new AgentQuickAction
        {
            Label = "Explain Selected",
            Icon = "mdi-comment-question-outline",
            Group = "Analysis",
            Command = ExplainSelectedCommand,
            AutomationIdOverride = "AgentExplainSelectedButton"
        });
        AddAnalysis(new AgentQuickAction
        {
            Label = "Import Threat Intel",
            Icon = "mdi-shield-link-variant",
            Group = "Analysis",
            Command = ImportThreatIntelCommand,
            AutomationIdOverride = "AgentThreatIntelButton"
        });
        AddAnalysis(new AgentQuickAction
        {
            Label = "Compare Last Two",
            Icon = "mdi-compare-horizontal",
            Group = "Analysis",
            Command = CompareAuditsCommand,
            AutomationIdOverride = "AgentCompareAuditsButton"
        });
        AddAnalysis(new AgentQuickAction
        {
            Label = "Compare Selected",
            Icon = "mdi-compare",
            Group = "Analysis",
            Command = CompareSelectedAuditsCommand,
            AutomationIdOverride = "AgentCompareSelectedButton"
        });
        AddAnalysis(new AgentQuickAction
        {
            Label = "Batch Auto-Fix",
            Icon = "mdi-wrench",
            Group = "Analysis",
            Command = BatchAutoFixCommand,
            AutomationIdOverride = "AgentBatchAutoFixButton"
        });

        AddRunCheck(new AgentQuickAction { Label = "Full audit", Icon = "mdi-magnify", Group = "Run checks", Command = FullAuditCommand });
        AddRunCheck(new AgentQuickAction { Label = "Firewall", Icon = "mdi-shield", Group = "Run checks", Command = FirewallCommand });
        AddRunCheck(new AgentQuickAction { Label = "Ports", Icon = "mdi-ethernet", Group = "Run checks", Command = PortsCommand });
        AddRunCheck(new AgentQuickAction { Label = "Services", Icon = "mdi-cog", Group = "Run checks", Command = ServicesCommand });
        AddRunCheck(new AgentQuickAction { Label = "Network", Icon = "mdi-web", Group = "Run checks", Command = NetworkCommand });
        AddRunCheck(new AgentQuickAction { Label = "Containers", Icon = "mdi-cube", Group = "Run checks", Command = ContainerCommand });
        AddRunCheck(new AgentQuickAction { Label = "Kubernetes", Icon = "mdi-kubernetes", Group = "Run checks", Command = KubernetesCommand });
        AddRunCheck(new AgentQuickAction { Label = "YARA", Icon = "mdi-virus", Group = "Run checks", Command = YaraCommand });
        AddRunCheck(new AgentQuickAction { Label = "Processes", Icon = "mdi-monitor", Group = "Run checks", Command = ProcessRuntimeCommand });

        AddBaseline(new AgentQuickAction { Label = "Set baseline", Icon = "mdi-pin", Group = "Baseline", Command = SetBaselineCommand });
        AddBaseline(new AgentQuickAction { Label = "Check drift", Icon = "mdi-compare", Group = "Baseline", Command = CheckDriftCommand });
        AddBaseline(new AgentQuickAction { Label = "Show baseline", Icon = "mdi-eye", Group = "Baseline", Command = ShowBaselineCommand });

        AddExport(new AgentQuickAction { Label = "Export audit", Icon = "mdi-content-save", Group = "Export", Command = ExportAuditCommand });
        AddExport(new AgentQuickAction
        {
            Label = "Export Remediation",
            Icon = "mdi-file-document-arrow-right-outline",
            Group = "Export",
            Command = ExportRemediationCommand,
            AutomationIdOverride = "AgentExportRemediationButton"
        });
        AddExport(new AgentQuickAction
        {
            Label = "Export Session",
            Icon = "mdi-file-document-check-outline",
            Group = "Export",
            Command = ExportSessionCommand,
            AutomationIdOverride = "AgentExportSessionButton"
        });
        AddExport(new AgentQuickAction
        {
            Label = "Export STIX/MISP",
            Icon = "mdi-share-variant",
            Group = "Export",
            Command = ExportThreatIntelCommand,
            AutomationIdOverride = "AgentExportThreatIntelButton"
        });
    }

    private void InitializeSlashCommands()
    {
        AddAuditSlashCommand("/firewall", "Firewall", "Check firewall configuration", AgentIntent.FirewallCheck, "Check my firewall");
        AddAuditSlashCommand("/ports", "Ports", "List open ports", AgentIntent.PortCheck, "What ports are open?");
        AddAuditSlashCommand("/services", "Services", "List running services", AgentIntent.ServiceCheck, "What services are running?");
        AddAuditSlashCommand("/network", "Network", "Check network configuration", AgentIntent.NetworkCheck, "Check my network");
        AddAuditSlashCommand("/ssh", "SSH", "Check SSH daemon hardening", AgentIntent.SshCheck, "Check ssh config");
        AddAuditSlashCommand("/filesystem", "Filesystem", "Check filesystem audit findings", AgentIntent.FilesystemAuditCheck, "Check filesystem security");
        AddAuditSlashCommand("/kernel", "Kernel", "Check kernel hardening", AgentIntent.KernelCheck, "Check kernel hardening");
        AddAuditSlashCommand("/users", "Users", "Check local users and account policy", AgentIntent.UserAccountCheck, "Check user accounts");
        AddAuditSlashCommand("/logging", "Logging", "Check logging and audit coverage", AgentIntent.LoggingAuditCheck, "Check logging audit");
        AddAuditSlashCommand("/cron", "Cron", "Check cron jobs and script permissions", AgentIntent.CronJobCheck, "Check cron jobs");
        AddAuditSlashCommand("/packages", "Packages", "Check package vulnerabilities", AgentIntent.PackageVulnerabilityCheck, "Check package vulnerabilities");
        AddAuditSlashCommand("/threatintel", "Threat intel", "Correlate host state with imported IOCs", AgentIntent.ThreatIntelCheck, "Check threat intel");
        AddAuditSlashCommand("/fullaudit", "Full audit", "Run a comprehensive audit", AgentIntent.FullAudit, "Run a full audit");
        AddAuditSlashCommand("/full", "Full audit", "Run a comprehensive audit", AgentIntent.FullAudit, "Run a full audit");
        AddAuditSlashCommand("/containers", "Containers", "Check container security", AgentIntent.ContainerCheck, "Check my containers");
        AddAuditSlashCommand("/kubernetes", "Kubernetes", "Check Kubernetes posture", AgentIntent.KubernetesCheck, "Check my kubernetes");
        AddAuditSlashCommand("/yara", "YARA", "Run YARA malware scan", AgentIntent.YaraCheck, "Run a YARA scan");
        AddAuditSlashCommand("/processes", "Processes", "Check running processes", AgentIntent.ProcessRuntimeCheck, "Check running processes");
        AddSlashCommand("/baseline", "Set baseline", "Save last audit as baseline", () => SetBaselineAsync());
        AddSlashCommand("/drift", "Check drift", "Compare against baseline", () => CheckDriftAsync());
        AddSlashCommand("/baseline show", "Show baseline", "Display saved baseline", () => ShowBaselineAsync());
        AddSlashCommand("/show baseline", "Show baseline", "Display saved baseline", () => ShowBaselineAsync());
        AddSlashCommand("/logdiffdemo", "Log diff demo", "Open the log diff window with sample data", () => ShowLogDiffDemoAsync());
        AddSlashCommand("/threatinteldemo", "Threat intel demo", "Import sample threat intelligence IOCs", () => ImportThreatIntelDemoAsync());
        AddSlashCommand("/sessions", "Sessions", "List remediation sessions", () => ListSessionsAsync());
        AddSlashCommand("/risk", "Risk score", "Show the current risk score", () => RunQueryShortcutAsync("risk score"));
        AddSlashCommand("/clear", "Clear chat", "Clear the visible agent conversation", ClearChatAsync);
        AddSlashCommand("/help", "Help", "Show available commands", ShowSlashHelpAsync);
    }

    private void AddAuditSlashCommand(string commandText, string title, string description, AgentIntent intent, string query)
        => AddSlashCommand(commandText, title, description, () => RunQuickAuditAsync(intent, query));

    private void AddSlashCommand(string commandText, string title, string description, Func<Task> handler)
    {
        _allSlashCommands.Add(new SlashCommandItem
        {
            CommandText = commandText,
            Title = title,
            Description = description,
            Command = ExecuteSlashCommandCommand,
            Handler = handler
        });
    }

    private Task RunQueryShortcutAsync(string query)
    {
        UserQuery = query;
        return SendQueryAsync();
    }

    private Task ClearChatAsync()
    {
        CancelActiveStreamers();
        Messages.Clear();
        SelectedChatSeverityFilter = ChatSeverityFilters[0];
        SelectedChatCategoryFilter = null;
        ClearChatSearch();
        AddAgentMessage(WelcomeMessage, false);
        HasOnlyWelcomeMessage = true;
        RefreshActiveFilterChips();
        return Task.CompletedTask;
    }

    private void ClearChatSearch()
    {
        ChatSearchQuery = string.Empty;
    }

    private void AddToQueryHistory(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
            return;

        _queryHistory.Add(query);
        _queryHistoryIndex = -1;
    }

    private Task ShowSlashHelpAsync()
    {
        OpenSlashHelp();
        return Task.CompletedTask;
    }

    private void UpdateSlashPalette()
    {
        // While the searchable help popup is open, keep the inline palette suppressed so only one
        // command surface is visible at a time.
        if (_isSlashHelpOpen)
        {
            IsSlashPaletteOpen = false;
            FilteredSlashCommands.Clear();
            SelectedSlashCommand = null;
            return;
        }

        var query = _userQuery.Trim();
        if (query.StartsWith("/"))
        {
            // Filter by command-text prefix so the palette shows exactly the commands Enter will
            // dispatch (SendQueryAsync matches by the same prefix, exact-first). Title/Description
            // substring matching was intentionally removed: it surfaced commands that typing+Enter
            // could never invoke, so the palette offered items and Enter then silently ran a
            // different command — or none.
            var filtered = _allSlashCommands.Where(c =>
                c.CommandText.StartsWith(query, StringComparison.OrdinalIgnoreCase));

            FilteredSlashCommands.Clear();
            foreach (var item in filtered)
            {
                FilteredSlashCommands.Add(item);
            }

            SelectedSlashCommand = FilteredSlashCommands.Count > 0 ? FilteredSlashCommands[0] : null;
            IsSlashPaletteOpen = FilteredSlashCommands.Count > 0;
        }
        else
        {
            IsSlashPaletteOpen = false;
            FilteredSlashCommands.Clear();
        }
    }

    private void UpdateSlashHelpFilter()
    {
        var query = _slashHelpQuery.Trim();
        var filtered = string.IsNullOrWhiteSpace(query)
            ? _allSlashCommands.OrderBy(c => c.CommandText, StringComparer.OrdinalIgnoreCase)
            : _allSlashCommands.Where(c =>
                  c.CommandText.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                  c.Title.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                  c.Description.Contains(query, StringComparison.OrdinalIgnoreCase))
              .OrderBy(c => c.CommandText, StringComparer.OrdinalIgnoreCase);

        FilteredSlashHelpCommands.Clear();
        foreach (var item in filtered)
        {
            FilteredSlashHelpCommands.Add(item);
        }

        SelectedSlashHelpCommand = FilteredSlashHelpCommands.Count > 0 ? FilteredSlashHelpCommands[0] : null;
    }

    private async Task ExecuteSuggestionAsync(SuggestedFollowUp suggestion)
    {
        if (_isBusy)
            return;

        if (IsAuditIntent(suggestion.Intent))
        {
            await RunQuickAuditAsync(suggestion.Intent, suggestion.Query);
        }
        else
        {
            UserQuery = suggestion.Query;
            await SendQueryAsync();
        }
    }

    private async Task RunLatestSuggestedFollowUpAsync()
    {
        var suggestion = LatestSuggestedFollowUp;
        if (suggestion != null)
        {
            await ExecuteSuggestionAsync(suggestion);
        }
    }

    private static bool IsAuditIntent(AgentIntent intent) => intent switch
    {
        AgentIntent.FullAudit
            or AgentIntent.FirewallCheck
            or AgentIntent.NetworkCheck
            or AgentIntent.ServiceCheck
            or AgentIntent.PortCheck
            or AgentIntent.SshCheck
            or AgentIntent.FilePermissionCheck
            or AgentIntent.FilesystemAuditCheck
            or AgentIntent.KernelCheck
            or AgentIntent.UserAccountCheck
            or AgentIntent.LoggingAuditCheck
            or AgentIntent.CronJobCheck
            or AgentIntent.PackageVulnerabilityCheck
            or AgentIntent.ContainerCheck
            or AgentIntent.KubernetesCheck
            or AgentIntent.ThreatIntelCheck
            or AgentIntent.YaraCheck
            or AgentIntent.ProcessRuntimeCheck => true,
        _ => false
    };

    /// <summary>
    /// Notifies the agent panel that the host findings selection changed.
    /// </summary>
    public void NotifySelectedFindingChanged()
    {
        ExplainSelectedCommand.RaiseCanExecuteChanged();
        OnPropertyChanged(nameof(CanExplainSelected));
        VerifySelectedCommand.RaiseCanExecuteChanged();
        OnPropertyChanged(nameof(CanVerifySelected));
    }

    private void CancelQuery()
    {
        CancelActiveStreamers();
        _operationRunner.Cancel();
    }

    private void CancelActiveStreamers()
    {
        // Cancelling the streaming token synchronously disposes each active streamer via its
        // registration, which flushes its message without advancing the queue (see
        // AgentMessageStreamer.Complete vs Dispose).
        if (_streamingCts is not null)
        {
            _streamingCts.Cancel();
            _streamingCts.Dispose();
            _streamingCts = null;
        }

        // Reveal any messages still queued for their streaming turn so a completed result
        // stays readable after cancel/new-query/dispose.
        var batch = _currentStreamingBatch;
        _currentStreamingBatch = null;
        if (batch is not null)
        {
            foreach (var message in batch)
            {
                message.IsStreamingPending = false;
            }
        }
    }

    private void BeginChatAction()
    {
        CancelActiveStreamers();
        MarkChatInteracted();
    }

    private void AddUserActionMessage(string text)
    {
        BeginChatAction();
        AddUserMessage(text);
    }

    private async Task SendQueryAsync()
    {
        var query = _userQuery.Trim();
        if (string.IsNullOrWhiteSpace(query))
            return;

        AddToQueryHistory(query);

        // Slash-command dispatch: prefer an exact command-text match, then a prefix match — the
        // same predicate the palette filters by — so Enter always runs a command the palette
        // actually showed, never a hidden or different one.
        if (query.StartsWith("/", StringComparison.Ordinal))
        {
            var match = _allSlashCommands.FirstOrDefault(c =>
                c.CommandText.Equals(query, StringComparison.OrdinalIgnoreCase))
                ?? _allSlashCommands.FirstOrDefault(c =>
                c.CommandText.StartsWith(query, StringComparison.OrdinalIgnoreCase));
            if (match is not null)
            {
                IsSlashPaletteOpen = false;
                UserQuery = string.Empty;
                await match.Handler!();
                return;
            }
        }

        AddUserActionMessage(query);
        UserQuery = string.Empty;

        await _operationRunner.RunAsync(async (progress, token) =>
        {
            CurrentOperationTitle = query;
            var result = await _queryExecutor.ExecuteAsync(query, LogText, SelectedFindingProvider, progress, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() =>
            {
                PresentFindings(result);
                RefreshSessionsIfNeeded(result);
            });

            // Raise audit completion for audit intents so MainViewModel can sync evidence
            if (AgentResultStateCoordinator.IsAuditIntent(result.Intent))
            {
                PublishAuditCompleted(result);
            }
        });
    }

    private async Task RunQuickAuditAsync(AgentIntent intent, string displayQuery)
    {
        AddUserActionMessage(displayQuery);

        await _operationRunner.RunAsync(async (progress, token) =>
        {
            CurrentOperationTitle = displayQuery;
            var result = await _agent.RunAuditAsync(intent, LogText, progress, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() => PresentFindings(result));

            PublishAuditCompleted(result);
        });
    }

    private async Task ExplainSelectedAsync()
    {
        BeginChatAction();
        var selected = GetSelectedFinding();
        if (selected == null)
        {
            AddAgentMessage("No finding is selected. Select a finding from the list first.", true);
            return;
        }

        AddUserMessage("Explain selected");

        await _operationRunner.RunAsync(async token =>
        {
            CurrentOperationTitle = "Explain selected finding";
            var result = await _agent.ExplainFindingAsync(selected, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() =>
            {
                PresentFindings(result, showCapabilityReport: false, showPassedCount: false, showWarnings: false);
            });
        });
    }

    private async Task VerifySelectedAsync()
    {
        BeginChatAction();
        var selected = GetSelectedFinding();
        if (selected == null || string.IsNullOrWhiteSpace(selected.RuleId))
        {
            AddAgentMessage("Select a finding with a rule ID to verify remediation.", true);
            return;
        }

        AddUserMessage($"Verify {selected.RuleId}");

        await _operationRunner.RunAsync(async token =>
        {
            CurrentOperationTitle = $"Verify {selected.RuleId}";
            var result = await _agent.VerifyFindingAsync(selected.RuleId, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() =>
            {
                PresentFindings(result, showCapabilityReport: false, showPassedCount: false, showWarnings: false);
            });
        });
    }

    private Finding? GetSelectedFinding() =>
        SelectedResultFinding?.Finding ?? SelectedFindingProvider?.Invoke();

    private const int TypewriterCharsPerTick = 3;
    private const int DefaultTypewriterTickMilliseconds = 30;
    private const int MaxUiTestTypewriterTickMilliseconds = 60_000;

    internal static TimeSpan ResolveTypewriterTickInterval(string? value)
    {
        return int.TryParse(value, out var milliseconds)
            && milliseconds > 0
            && milliseconds <= MaxUiTestTypewriterTickMilliseconds
                ? TimeSpan.FromMilliseconds(milliseconds)
                : TimeSpan.FromMilliseconds(DefaultTypewriterTickMilliseconds);
    }

    private void PresentFindings(AgentResult result, bool showCapabilityReport = true, bool showPassedCount = true, bool showWarnings = true)
    {
        // Reset chat filters when a new audit result (or a findings recap of the last audit)
        // arrives so findings from the current intent aren't hidden by a stale category or
        // severity selection.
        if (AgentResultStateCoordinator.IsAuditIntent(result.Intent)
            || result.Intent == AgentIntent.ShowFindings)
        {
            SelectedChatSeverityFilter = ChatSeverityFilters[0];
            SelectedChatCategoryFilter = null;
        }

        var created = _presenter.PresentFindings(result, showCapabilityReport, showPassedCount, showWarnings);
        var proseMessages = created.Where(m => m.IsProse && !m.IsUser).ToList();
        StreamMessagesSequentially(proseMessages);
    }

    private void StreamMessagesSequentially(IReadOnlyList<AgentMessageViewModel> proseMessages)
    {
        // Only prose with actual text participates in the typewriter sequence. Empty bubbles
        // are not hidden; hiding them would either strand them invisible or flash a blank row.
        var streamableMessages = proseMessages.Where(m => !string.IsNullOrEmpty(m.Text)).ToList();
        if (streamableMessages.Count == 0)
            return;

        // Cancel any in-flight sequence first (e.g. a quick-audit or explain flow that did not
        // pre-cancel) so two sequences never stream at once, and reveal its queued messages.
        CancelActiveStreamers();

        // Hide every streamable prose bubble until its turn; only the active one is shown streaming.
        foreach (var message in streamableMessages)
        {
            message.StreamingText = string.Empty;
            message.IsStreaming = false;
            message.IsStreamingPending = true;
        }

        // Streaming owns its own lifetime: the operation token is already dead by the time the
        // result is presented, so this dedicated source is what cancel/new-query/dispose cancel.
        _streamingCts = new CancellationTokenSource();
        var token = _streamingCts.Token;
        _currentStreamingBatch = streamableMessages;

        var queue = new Queue<AgentMessageViewModel>(streamableMessages);

        void StartNext()
        {
            while (queue.Count > 0)
            {
                if (token.IsCancellationRequested)
                    return;

                var message = queue.Dequeue();

                AgentMessageStreamer? streamer = null;
                streamer = new AgentMessageStreamer(
                    message,
                    message.Text,
                    TypewriterCharsPerTick,
                    ResolveTypewriterTickInterval(
                        Environment.GetEnvironmentVariable("VT_UI_TEST_TYPEWRITER_TICK_MS")),
                    _typewriterScheduler,
                    onCompleted: () => StartNext(),
                    cancellationToken: token);
                streamer.Start();
                return;
            }

            // Everything streamed naturally; nothing left to cancel.
            _currentStreamingBatch = null;
            if (_streamingCts is not null)
            {
                _streamingCts.Dispose();
                _streamingCts = null;
            }
        }

        StartNext();
    }

    private void AddUserMessage(string text) => _presenter.AddUserMessage(text);
    private void AddAgentMessage(string text, bool isInfo, bool isError = false) => _presenter.AddAgentMessage(text, isInfo, isError);
    private void AddAgentFinding(Finding finding) => _presenter.AddAgentFinding(finding);

    /// <summary>
    /// Posts the structured analysis summary card to the thread (UI v2 Phase 2). Called by
    /// MainViewModel when an analysis completes, on either path (log paste or agent audit).
    /// </summary>
    public AnalysisSummaryCardMessageViewModel AddAnalysisSummaryCard(
        string headerLine,
        string summaryLine,
        IReadOnlyList<SummaryChipViewModel> chips,
        ICommand? navigateCommand)
    {
        // The welcome hint is stale once real analysis content arrives; dropping it
        // keeps the thread compact and the scroll position deterministic.
        if (HasOnlyWelcomeMessage && Messages.Count == 1)
        {
            Messages.RemoveAt(0);
        }

        // Card content ends the welcome state even though it arrives outside the
        // agent conversation flow (log-paste analysis posts from MainViewModel).
        MarkChatInteracted();
        return _presenter.AddAnalysisSummaryCard(headerLine, summaryLine, chips, navigateCommand);
    }

    /// <summary>
    /// Posts a per-finding card to the thread (UI v2 Phase 2). Called by MainViewModel
    /// after the summary card, for the top findings of the completed analysis.
    /// </summary>
    public FindingCardMessageViewModel AddFindingCard(
        FindingItemViewModel item,
        ICommand? openCommand,
        ICommand? suppressCommand)
    {
        MarkChatInteracted();
        return _presenter.AddFindingCard(item, openCommand, suppressCommand);
    }

    /// <summary>
    /// Posts the "N more findings" deep link to the thread (UI v2 Phase 2). Called by
    /// MainViewModel after the per-finding cards when more findings remain.
    /// </summary>
    public MoreFindingsLinkMessageViewModel AddMoreFindingsLink(
        int remainingCount,
        ICommand? openCommand,
        object? commandParameter)
    {
        MarkChatInteracted();
        return _presenter.AddMoreFindingsLink(remainingCount, openCommand, commandParameter);
    }

    /// <summary>
    /// Posts a single informational message to the Agent transcript from outside the
    /// agent conversation flow (e.g. the main analysis view surfacing remediation detail).
    /// </summary>
    public void PostInfo(string text) => _presenter.AddAgentMessage(text, isInfo: true);

    private void ClearPrivilegeWarning()
    {
        HasPrivilegeWarning = false;
        PrivilegeWarningText = string.Empty;
    }

    private void SetLastResult(AgentResult result)
    {
        UiThread.Run(() =>
        {
            if (result.Baseline is not null)
                BaselineStatusText = $"Baseline: {result.Baseline.Name}";
            _resultState.SetLastResult(result, _agent.LastResult);
            ShowMemoryPersistenceWarningIfAny();
        });
    }

    private void ShowMemoryPersistenceWarningIfAny()
    {
        if (_memoryStore == null)
            return;

        var warning = _memoryStore.PersistenceWarning;
        if (string.IsNullOrWhiteSpace(warning) || warning == _lastShownMemoryWarning)
            return;

        _lastShownMemoryWarning = warning;
        AddAgentMessage($"Note: {warning}", true);
    }

    private async Task TogglePinMessageAsync(AgentMessageViewModel? message)
    {
        if (message == null)
            return;

        if (message.IsPinned)
        {
            await UnpinMessageAsync(message);
        }
        else
        {
            await PinMessageAsync(message);
        }
    }

    private async Task PinMessageAsync(AgentMessageViewModel message)
    {
        if (_pinnedMessageStore == null || !message.CanBePinned)
            return;

        // Move the durable store work off the UI thread so file I/O and validation do not
        // freeze the chat interface. The store is the source of truth; after the write we
        // re-read IsPinned and mirror that state into the UI.
        bool accepted;
        try
        {
            await Task.Run(() => _pinnedMessageStore.Pin(message.ToPinnedMessage()));
            accepted = SafeIsPinned(message.MessageId);
            RefreshPinnedMessageStatus();
        }
        catch (Exception ex)
        {
            // If the store throws, we cannot assume the pin succeeded. Re-read if possible,
            // otherwise treat it as rejected and surface the failure.
            accepted = SafeIsPinned(message.MessageId);
            PinMessageStatusMessage = $"Could not pin message: {ErrorSanitizer.SanitizeException(ex)}";
        }

        ApplyPinnedState(message, accepted);
        if (accepted)
        {
            AddOrRefreshPinnedMessage(message);
        }
    }

    private async Task UnpinMessageAsync(AgentMessageViewModel message)
    {
        if (_pinnedMessageStore == null)
            return;

        bool stillPinned;
        try
        {
            await Task.Run(() => _pinnedMessageStore.Unpin(message.MessageId));
            stillPinned = SafeIsPinned(message.MessageId);
            RefreshPinnedMessageStatus();
        }
        catch (Exception ex)
        {
            stillPinned = SafeIsPinned(message.MessageId);
            PinMessageStatusMessage = $"Could not unpin message: {ErrorSanitizer.SanitizeException(ex)}";
        }

        ApplyPinnedState(message, stillPinned);
        if (!stillPinned)
        {
            RemovePinnedMessageById(message.MessageId);
        }
    }

    private bool SafeIsPinned(string messageId)
    {
        try
        {
            return _pinnedMessageStore?.IsPinned(messageId) ?? false;
        }
        catch
        {
            return false;
        }
    }

    private void ApplyPinnedState(AgentMessageViewModel source, bool isPinned)
    {
        source.IsPinned = isPinned;
        if (_messagesById.TryGetValue(source.MessageId, out var twin) && twin != source)
        {
            twin.IsPinned = isPinned;
        }
    }

    private void AddOrRefreshPinnedMessage(AgentMessageViewModel message)
    {
        var existing = PinnedMessages.FirstOrDefault(m => m.MessageId == message.MessageId);
        if (existing != null)
        {
            existing.IsPinned = true;
            return;
        }

        var clone = CreatePinnedMessageViewModel(message.ToPinnedMessage());
        clone.TogglePinCommand = TogglePinMessageCommand;
        PinnedMessages.Add(clone);
        PinnedMessageCount = PinnedMessages.Count;
    }

    private void RemovePinnedMessageById(string messageId)
    {
        var existing = PinnedMessages.FirstOrDefault(m => m.MessageId == messageId);
        if (existing != null)
        {
            PinnedMessages.Remove(existing);
        }
        PinnedMessageCount = PinnedMessages.Count;
    }

    private void RefreshPinnedMessages()
    {
        PinnedMessages.Clear();
        if (_pinnedMessageStore == null)
        {
            PinnedMessageCount = 0;
            RefreshPinnedMessageStatus();
            return;
        }

        try
        {
            foreach (var pinned in _pinnedMessageStore.GetAll())
            {
                var vm = CreatePinnedMessageViewModel(pinned);
                vm.TogglePinCommand = TogglePinMessageCommand;
                PinnedMessages.Add(vm);
            }

            PinnedMessageCount = PinnedMessages.Count;
            RefreshPinnedMessageStatus();
        }
        catch (Exception ex)
        {
            PinnedMessages.Clear();
            PinnedMessageCount = 0;
            PinMessageStatusMessage = $"Could not load pinned messages: {ErrorSanitizer.SanitizeException(ex)}";
        }
    }

    private static AgentMessageViewModel CreatePinnedMessageViewModel(PinnedMessage pinned)
    {
        return new AgentMessageViewModel
        {
            MessageId = pinned.MessageId,
            Text = pinned.Text,
            Details = pinned.Details,
            IsUser = pinned.IsUser,
            IsInfo = pinned.IsInfo,
            IsError = pinned.IsError,
            IsProse = pinned.IsProse,
            Category = pinned.Category,
            Severity = Enum.TryParse<Severity>(pinned.Severity, out var severity) ? severity : Severity.Info,
            Timestamp = pinned.TimestampUtc == DateTime.MinValue ? DateTime.MinValue : pinned.TimestampUtc.ToLocalTime(),
            IsPinned = true
        };
    }

    private void RefreshPinnedMessageStatus()
    {
        PinMessageStatusMessage = _pinnedMessageStore?.PersistenceWarning ?? string.Empty;
    }

    private void RefreshResultCommands()
    {
        ExportAuditCommand.RaiseCanExecuteChanged();
        ExportRemediationCommand.RaiseCanExecuteChanged();
        ExportSessionCommand.RaiseCanExecuteChanged();
        ExportThreatIntelCommand.RaiseCanExecuteChanged();
        SetBaselineCommand.RaiseCanExecuteChanged();
        BatchAutoFixCommand.RaiseCanExecuteChanged();
        OnPropertyChanged(nameof(CanExportSession));
        OnPropertyChanged(nameof(CanExportThreatIntel));
        OnPropertyChanged(nameof(CanBatchAutoFix));
        NotifyPageStateChanged();
        PopulateResultFindings();
    }

    private void PublishAuditCompleted(AgentResult result)
    {
        UiThread.Run(() => _resultState.PublishAuditCompleted(result));
    }

    /// <summary>Marks the most recent audit history entry as exported.</summary>
    public void MarkLatestAuditExported()
    {
        _historyCoordinator.MarkLatestExported();
    }

    private async Task SetBaselineAsync()
    {
        if (_resultState.LastResult == null)
        {
            BeginChatAction();
            AddAgentMessage("Run an audit first, then save it as a baseline.", true);
            return;
        }

        AddUserActionMessage("Set baseline");

        await _operationRunner.RunAsync(async (progress, token) =>
        {
            CurrentOperationTitle = "Set baseline";
            // Pass empty name so the agent generates it from the last audit intent,
            // avoiding wrong intent (e.g. CheckDrift) in the name.
            var result = await _agent.SetBaselineAsync("", null, progress, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() =>
            {
                PresentFindings(result, showCapabilityReport: false, showPassedCount: false);
            });
        });

        await (_analystActionLogger?.LogBaselineSetAsync("avalonia", _resultState.LastAuditIntent.ToString()) ?? Task.CompletedTask);
    }

    private async Task CheckDriftAsync()
    {
        var intent = _resultState.LastAuditIntent;
        AddUserActionMessage($"Check drift ({intent})");

        await _operationRunner.RunAsync(async (progress, token) =>
        {
            CurrentOperationTitle = $"Check drift ({intent})";
            var result = await _agent.CheckDriftAsync(intent, null, progress, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() => PresentFindings(result, showCapabilityReport: false, showPassedCount: false));
        });

        await (_analystActionLogger?.LogDriftCheckedAsync("avalonia", intent.ToString()) ?? Task.CompletedTask);
    }

    private async Task ShowBaselineAsync()
    {
        var intent = _resultState.LastAuditIntent;
        AddUserActionMessage("Show baseline");

        await _operationRunner.RunAsync(async token =>
        {
            CurrentOperationTitle = "Show baseline";
            var result = await _agent.GetBaselineAsync(intent, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() => PresentFindings(result, showCapabilityReport: false, showPassedCount: false, showWarnings: false));
        });
    }

    private async Task ShowLogDiffDemoAsync()
    {
        AddUserActionMessage("Log diff demo");

        if (ShowLogDiffDemoAction == null)
        {
            AddAgentMessage("Log diff demo is not available in this configuration.", isInfo: true);
            return;
        }

        await _operationRunner.RunAsync(async token =>
        {
            CurrentOperationTitle = "Run log comparison demo";
            await ShowLogDiffDemoAction();
        });
    }

    private async Task ImportThreatIntelDemoAsync()
    {
        AddUserActionMessage("Threat intel demo");

        if (_threatIntelStore == null)
        {
            AddAgentMessage("Threat intel store is not available in this configuration.", isInfo: true);
            return;
        }

        var json = @"{
            ""type"": ""bundle"",
            ""objects"": [
                { ""type"": ""ipv4-addr"", ""value"": ""10.99.99.100"" },
                { ""type"": ""ipv4-addr"", ""value"": ""10.99.99.101"" },
                { ""type"": ""indicator"", ""pattern"": ""[network-traffic:dst_port = 4444]"" },
                { ""type"": ""indicator"", ""pattern"": ""[domain-name:value = 'evil.example.com']"" }
            ]
        }";

        await _operationRunner.RunAsync(token =>
        {
            CurrentOperationTitle = "Import threat intelligence demo";
            var result = StixParser.Parse(json);
            _threatIntelStore.Import(result.Entries);
            var msg = $"Imported {result.ImportedCount} demo IOC(s). Open the Threat Intel view to review.";
            Dispatcher.UIThread.Post(() =>
            {
                AddAgentMessage(msg, isInfo: false);
                NavigateToThreatIntelAction?.Invoke();
            });
            return Task.CompletedTask;
        });
    }

    private async Task VerifySessionAsync(string sessionId)
    {
        AddUserActionMessage($"Verify remediation session {sessionId}");

        await _operationRunner.RunAsync(async (progress, token) =>
        {
            CurrentOperationTitle = $"Verify remediation session {sessionId}";
            var result = await _agent.VerifyRemediationAsync(sessionId, progress, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() =>
            {
                PresentFindings(result, showCapabilityReport: false, showPassedCount: false, showWarnings: false);
                RefreshSessionsIfNeeded(result);
            });
        });
    }

    private void ExportRemediationPlan()
    {
        var lastResult = _resultState.LastResult;
        if (lastResult == null || lastResult.AgentFindings.Count == 0)
        {
            AddAgentMessage("No findings available to generate a remediation plan. Run an audit first.", true);
            return;
        }

        try
        {
            var plan = _remediationPlanBuilder.Build(lastResult.AgentFindings);
            var validation = RemediationPlanValidator.Validate(plan);
            if (!validation.IsValid)
            {
                AddAgentMessage("Remediation plan export blocked: missing rollback guidance for risky or unclassified commands.", true);
                foreach (var err in validation.Errors)
                {
                    AddAgentMessage($"  • {err}", true);
                }
                return;
            }

            var formatter = new RemediationMarkdownFormatter();
            var markdown = formatter.Format(plan);
            RequestExportRemediation?.Invoke(markdown);
        }
        catch (Exception ex)
        {
            AddAgentMessage($"Failed to generate remediation plan: {ex.Message}", true);
        }
    }

    private async Task ExportSessionAsync()
    {
        var session = _resultState.LastResult?.RemediationSession;
        if (session == null)
        {
            AddAgentMessage("No active remediation session to export.", true);
            return;
        }

        await _operationRunner.RunAsync(async token =>
        {
            CurrentOperationTitle = "Export remediation session";
            var formatter = new RemediationMarkdownFormatter();
            var markdown = formatter.FormatSession(session);

            var exportCallback = RequestExportSession;
            if (exportCallback == null)
            {
                AddAgentMessage("Session export is not available in this view.", true);
                return;
            }

            var exported = await exportCallback(markdown);
            if (!exported)
            {
                return;
            }

            var result = await _agent.MarkSessionExportedAsync(session.SessionId, token);
            SetLastResult(result);

            if (result.RemediationSession != null)
            {
                Dispatcher.UIThread.Post(() =>
                {
                    UpdateSessionTimeline(result.RemediationSession);
                    RefreshSessions();
                });
            }
        });
    }

    private async Task ExportThreatIntelAsync()
    {
        var exportCallback = RequestExportThreatIntel;
        if (exportCallback == null)
        {
            AddAgentMessage("STIX/MISP export is not available in this view.", true);
            return;
        }

        await _operationRunner.RunAsync(async _ =>
        {
            CurrentOperationTitle = "Export threat intelligence";
            var exported = await exportCallback();
            if (exported)
            {
                Dispatcher.UIThread.Post(() => AddAgentMessage("Threat intelligence exported.", false));
            }
        });
    }

    private void UpdateSessionTimeline(RemediationSession session)
    {
        foreach (var message in Messages.Where(m => m.SessionId == session.SessionId))
        {
            message.SessionStatus = session.Status;
            message.SessionTimeline = session.Timeline;
        }
    }

    private void CompareLastTwoAudits()
    {
        if (History.Count < 2)
        {
            AddAgentMessage("Need at least 2 audits in history to compare. Run more audits first.", true);
            return;
        }

        var newer = History[0];
        var older = History[1];
        var diff = AuditDiffCalculator.Calculate(older, newer);
        ShowAuditDiffAction?.Invoke(diff);
    }

    private void CompareSelectedAudits()
    {
        if (SelectedBeforeEntry == null || SelectedAfterEntry == null)
        {
            AddAgentMessage("Select both a 'Before' and an 'After' audit from history.", true);
            return;
        }

        var diff = AuditDiffCalculator.Calculate(SelectedBeforeEntry, SelectedAfterEntry);
        ShowAuditDiffAction?.Invoke(diff);
    }

    private void RefreshSessions()
    {
        if (_sessionStore == null) return;

        Sessions.Clear();
        foreach (var session in _sessionStore.List())
        {
            Sessions.Add(session);
        }
    }

    private void RefreshSessionsIfNeeded(AgentResult result)
    {
        if (result.RemediationSession != null || result.RemediationSessions.Count > 0)
        {
            RefreshSessions();
        }
    }

    private async Task ListSessionsAsync()
    {
        AddUserActionMessage("List sessions");

        await _operationRunner.RunAsync(async token =>
        {
            CurrentOperationTitle = "List remediation sessions";
            var result = await _agent.ListRemediationSessionsAsync(token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() =>
            {
                PresentFindings(result, showCapabilityReport: false, showPassedCount: false, showWarnings: false);
                RefreshSessions();
            });
        });
    }

    private async Task ResumeSessionAsync()
    {
        var session = _selectedSession;
        if (session == null)
        {
            AddAgentMessage("Select a session from the Remediation Sessions list first.", true);
            return;
        }

        AddUserActionMessage($"Resume session {session.SessionId}");

        await _operationRunner.RunAsync(async token =>
        {
            CurrentOperationTitle = $"Resume session {session.SessionId}";
            var result = await _agent.LoadRemediationSessionAsync(session.SessionId, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() =>
            {
                PresentFindings(result, showCapabilityReport: false, showPassedCount: false, showWarnings: false);
                RefreshSessionsIfNeeded(result);
            });
        });
    }

    private async Task DeleteSessionAsync()
    {
        var session = _selectedSession;
        if (session == null)
        {
            AddAgentMessage("Select a session from the Remediation Sessions list first.", true);
            return;
        }

        BeginChatAction();

        await _operationRunner.RunAsync(async token =>
        {
            CurrentOperationTitle = $"Delete session {session.SessionId}";
            var result = await _agent.DeleteRemediationSessionAsync(session.SessionId, token);

            Dispatcher.UIThread.Post(() =>
            {
                SelectedSession = null;
                RefreshSessions();
                PresentFindings(result, showCapabilityReport: false, showPassedCount: false, showWarnings: false);
            });
        });
    }

    private async Task ImportThreatIntelAsync()
    {
        if (_dialogService == null || _threatIntelStore == null)
            return;

        var filePath = await _dialogService.ShowOpenFileDialogAsync(
            "Import Threat Intelligence",
            "JSON files (*.json)|*.json|All files (*.*)|*.*");

        if (string.IsNullOrWhiteSpace(filePath))
            return;

        if (!File.Exists(filePath))
        {
            AddAgentMessage($"File not found: {filePath}", true);
            return;
        }

        var formatOptions = new[] { "Auto-detect", "STIX 2.1", "MISP JSON" };
        var formatIndex = await _dialogService.ShowSelectionDialogAsync(
            "Import Threat Intelligence",
            $"Importing: {Path.GetFileName(filePath)}\n\nSelect format:",
            formatOptions,
            defaultIndex: 0);

        if (formatIndex == null)
            return;

        var format = formatIndex.Value switch
        {
            1 => "stix",
            2 => "misp",
            _ => "auto"
        };

        var json = await File.ReadAllTextAsync(filePath);

        if (format == "auto")
        {
            if (ThreatIntelFormatDetector.TryDetect(json, out var detectedFormat))
            {
                format = detectedFormat == ThreatIntelBundleFormat.Stix ? "stix" : "misp";
            }
            else
            {
                AddAgentMessage("Could not auto-detect format. Please select STIX 2.1 or MISP JSON.", true);
                return;
            }
        }
        ThreatIntelImportResult result;

        try
        {
            result = format switch
            {
                "stix" => StixParser.Parse(json),
                "misp" => MispParser.Parse(json),
                _ => throw new InvalidOperationException($"Unknown format: {format}")
            };
        }
        catch (Exception ex)
        {
            AddAgentMessage($"Parse error: {ex.Message}", true);
            return;
        }

        _threatIntelStore.Import(result.Entries);

        var msg = $"Imported {result.ImportedCount} IOC(s) from {format.ToUpperInvariant()} bundle.";
        if (result.SkippedCount > 0)
            msg += $" Skipped: {result.SkippedCount}.";
        AddAgentMessage(msg, false);

        if (!string.IsNullOrWhiteSpace(_threatIntelStore.PersistenceWarning))
            AddAgentMessage($"Warning: {_threatIntelStore.PersistenceWarning}", true);

        await (_analystActionLogger?.LogThreatIntelImportedAsync("avalonia", format, result.ImportedCount) ?? Task.CompletedTask);

        foreach (var warning in result.Warnings)
            AddAgentMessage($"Warning: {warning}", true);
    }

    public void AddCountermeasureMessage(RemediationSection section)
    {
        if (Messages.Any(message => IsSameCountermeasureSection(message.RemediationSection, section)))
            return;

        Messages.Add(new AgentMessageViewModel
        {
            Text = $"**Critical chain detected — {section.FindingSummary}**",
            Details = section.RiskNote,
            IsUser = false,
            IsInfo = false,
            Severity = Severity.Critical,
            Timestamp = DateTime.Now,
            RemediationSection = section
        });
    }

    private static bool IsSameCountermeasureSection(RemediationSection? existing, RemediationSection candidate)
    {
        if (existing == null)
            return false;

        if (!string.Equals(existing.RuleId, candidate.RuleId, StringComparison.Ordinal))
            return false;

        var existingCommands = existing.CountermeasureCommands.Select(command => command.Command);
        var candidateCommands = candidate.CountermeasureCommands.Select(command => command.Command);
        return existingCommands.SequenceEqual(candidateCommands, StringComparer.Ordinal);
    }

    private async Task BatchAutoFixAsync()
    {
        var lastResult = _resultState.LastResult;
        if (lastResult == null || lastResult.AgentFindings.Count == 0)
        {
            AddAgentMessage("No audit findings are available to auto-fix. Run an audit first.", true);
            return;
        }

        var plan = _remediationPlanBuilder.Build(lastResult.AgentFindings);
        if (plan.Sections.Count == 0)
        {
            AddAgentMessage("No auto-fixable findings were found in the latest audit.", true);
            return;
        }

        var policy = AutoFixPolicy.Standard();

        try
        {
            IsBusy = true;

            AddAgentMessage($"Running batch auto-fix dry-run for {plan.Sections.Count} finding(s)...", true);
            var dryRunResult = await _remediationExecutor.ExecuteAsync(plan, policy, dryRun: true);
            AddAgentMessage($"[DRY-RUN] {dryRunResult.Summary}", true);

            if (dryRunResult.Sections.Any(s => s.Skipped))
            {
                AddAgentMessage("Batch auto-fix blocked by safety policy. Review the dry-run output above.", true);
                return;
            }

            if (_dialogService == null)
            {
                AddAgentMessage("Dialog service unavailable — cannot confirm live deployment.", true);
                return;
            }

            var confirm = await _dialogService.ShowSelectionDialogAsync(
                "Batch Auto-Fix",
                $"Dry-run completed. Proceed with live deployment of {plan.Sections.Count} remediation section(s)?",
                new[] { "Deploy Live", "Cancel" },
                defaultIndex: 1);

            if (confirm != 0)
            {
                AddAgentMessage("Batch auto-fix cancelled.", true);
                return;
            }

            AddAgentMessage("Deploying batch auto-fix live...", true);
            var liveResult = await _remediationExecutor.ExecuteAsync(plan, policy, dryRun: false);
            AddAgentMessage($"[LIVE] {liveResult.Summary}", liveResult.Sections.All(s => s.ApplyResults.All(r => r.Skipped || r.Success)));

            if (liveResult.Sections.Any(s => s.RollbackResults.Count > 0))
            {
                AddAgentMessage("Rollback was executed automatically because one or more commands failed.", true);
            }

            await (_analystActionLogger?.LogBatchAutoFixAsync("avalonia", plan.Sections.Count) ?? Task.CompletedTask);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task DeployCountermeasuresAsync(RemediationSection? section)
    {
        if (section == null || section.CountermeasureCommands.Count == 0)
        {
            AddAgentMessage("No countermeasures to deploy.", true);
            return;
        }

        var plan = new RemediationPlan { Sections = new[] { section } };
        var policy = new AutoFixPolicy
        {
            AllowConfigChange = true,
            RequireRollbackGuidance = true
        };

        // Dry-run
        AddAgentMessage("Running countermeasure dry-run...", true);
        var dryRunResult = await _remediationExecutor.ExecuteAsync(plan, policy, dryRun: true);
        AddAgentMessage($"[DRY-RUN] {dryRunResult.Summary}", true);

        if (dryRunResult.Sections.Any(s => s.Skipped))
        {
            AddAgentMessage("Countermeasure deployment blocked by safety policy. Review the output above.", true);
            return;
        }

        if (_dialogService == null)
        {
            AddAgentMessage("Dialog service unavailable — cannot confirm live deployment.", true);
            return;
        }

        var confirm = await _dialogService.ShowSelectionDialogAsync(
            "Deploy Countermeasures",
            "Dry-run completed successfully. Proceed with live deployment?",
            new[] { "Deploy Live", "Cancel" },
            defaultIndex: 1);

        if (confirm != 0)
        {
            AddAgentMessage("Live deployment cancelled.", true);
            return;
        }

        AddAgentMessage("Deploying countermeasures live...", true);
        var liveResult = await _remediationExecutor.ExecuteAsync(plan, policy, dryRun: false);
        AddAgentMessage($"[LIVE] {liveResult.Summary}", liveResult.Sections.All(s => s.ApplyResults.All(r => r.Skipped || r.Success)));

        if (liveResult.Sections.Any(s => s.RollbackResults.Count > 0))
        {
            AddAgentMessage("Rollback was executed automatically because one or more commands failed.", true);
        }

        await (_analystActionLogger?.LogCountermeasureDeployedAsync("avalonia", section.FindingSummary) ?? Task.CompletedTask);
    }

    private void RefreshActiveFilterChips()
    {
        ActiveChatFilterChips.Clear();

        var severity = _selectedChatSeverityFilter;
        if (severity != null && severity != ChatSeverityFilters[0])
        {
            ActiveChatFilterChips.Add(new ChatFilterChipViewModel
            {
                Label = $"Severity: {severity.Display}",
                RemoveCommand = new RelayCommand(_ => SelectedChatSeverityFilter = ChatSeverityFilters[0])
            });
        }

        var category = _selectedChatCategoryFilter;
        if (!string.IsNullOrWhiteSpace(category) && !category.Equals(ChatFilterConstants.AllCategoriesFilter, StringComparison.OrdinalIgnoreCase))
        {
            ActiveChatFilterChips.Add(new ChatFilterChipViewModel
            {
                Label = $"Category: {category}",
                RemoveCommand = new RelayCommand(_ => SelectedChatCategoryFilter = null)
            });
        }

        ClearChatFiltersCommand.RaiseCanExecuteChanged();
        RefreshHasNoVisibleMessages();
        UpdateHasNoSearchMatches();
    }

    private void WireMessagesCollectionChanged()
    {
        Messages.CollectionChanged += (s, e) =>
        {
            if (e.OldItems != null)
            {
                foreach (AgentMessageViewModel message in e.OldItems)
                {
                    message.PropertyChanged -= OnMessagePropertyChanged;
                    _messagesById.Remove(message.MessageId);
                }
            }

            if (e.NewItems != null)
            {
                foreach (AgentMessageViewModel message in e.NewItems)
                {
                    message.PropertyChanged += OnMessagePropertyChanged;
                    message.TogglePinCommand = TogglePinMessageCommand;
                    _messagesById[message.MessageId] = message;
                }
            }

            RefreshHasNoVisibleMessages();
            UpdateHasNoSearchMatches();
            OnPropertyChanged(nameof(LatestPinnableMessage));
            OnPropertyChanged(nameof(HasLatestPinnableMessage));
            RefreshLatestSuggestedFollowUp();
        };
    }

    private void OnAuditProgress(AgentAuditProgress progress)
    {
        // Progress<T> may deliver a report asynchronously after the operation has already ended and
        // IsBusy reset; ignore those so the bar's backing state stays empty while not busy.
        if (!_isBusy)
        {
            return;
        }

        AuditProgressPercent = progress.PercentComplete;
        AuditProgressMessage = progress.FormatMessage();
        AuditProgressIsIndeterminate = progress.IsIndeterminate;
        CurrentOperationTitle = string.IsNullOrWhiteSpace(progress.Phase)
            ? "Agent operation"
            : progress.Phase;
        OnPropertyChanged(nameof(ShowAuditProgress));
        UpdatePhaseSteps(progress);
    }

    private static readonly string[] KnownPhases =
    {
        "Scanning system", "Evaluating rules", "Assembling findings",
        "Validating findings", "Analyzing logs", "Building summary",
        "Correlating posture", "Building attack chains", "Finalizing result",
        "Detecting recurring issues", "Updating memory", "Updating coverage",
        "Computing trajectory", "Surfacing remediation wisdom", "Composing narrative"
    };

    private void UpdatePhaseSteps(AgentAuditProgress progress)
    {
        PhaseSteps.Clear();
        var total = progress.TotalSteps > 0 ? progress.TotalSteps : KnownPhases.Length;
        for (int i = 0; i < total; i++)
        {
            var name = i < KnownPhases.Length ? KnownPhases[i] : $"Phase {i + 1}";
            PhaseStepState state;
            if (i < progress.StepIndex) state = PhaseStepState.Completed;
            else if (i == progress.StepIndex) state = PhaseStepState.Active;
            else state = PhaseStepState.Pending;
            PhaseSteps.Add(new PhaseStepViewModel { Name = name, State = state });
        }
    }

    private void OnMessagePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(AgentMessageViewModel.IsVisible))
        {
            RefreshHasNoVisibleMessages();
            UpdateHasNoSearchMatches();
        }

        if (e.PropertyName is nameof(AgentMessageViewModel.CanBePinned)
            or nameof(AgentMessageViewModel.IsUser))
        {
            OnPropertyChanged(nameof(LatestPinnableMessage));
            OnPropertyChanged(nameof(HasLatestPinnableMessage));
        }

        if (e.PropertyName is nameof(AgentMessageViewModel.Suggestions)
            or nameof(AgentMessageViewModel.HasSuggestions))
        {
            RefreshLatestSuggestedFollowUp();
        }
    }

    private void RefreshLatestSuggestedFollowUp()
    {
        OnPropertyChanged(nameof(LatestSuggestedFollowUp));
        OnPropertyChanged(nameof(HasLatestSuggestedFollowUp));
        OnPropertyChanged(nameof(LatestSuggestedFollowUpLabel));
        RunLatestSuggestedFollowUpCommand.RaiseCanExecuteChanged();
    }

    /// <inheritdoc />
    public void Dispose()
    {
        CancelActiveStreamers();
        StopElapsedTimer();
        _operationRunner.Dispose();
    }
}

/// <summary>
/// A small view model for an active chat filter chip shown above the transcript.
/// </summary>
public sealed class ChatFilterChipViewModel : ViewModelBase
{
    private string _label = "";

    /// <summary>Gets or sets the chip label (e.g. "Severity: High").</summary>
    public string Label
    {
        get => _label;
        set => SetField(ref _label, value);
    }

    /// <summary>Gets or sets the command invoked when the chip is removed.</summary>
    public ICommand RemoveCommand { get; set; } = new RelayCommand(_ => { });
}

/// <summary>State of a single phase step in the running-state checklist.</summary>
public enum PhaseStepState
{
    Completed,
    Active,
    Pending
}

/// <summary>View model for a single phase step in the scan progress checklist.</summary>
public sealed class PhaseStepViewModel : ViewModelBase
{
    /// <summary>Gets or sets the phase name.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Gets or sets the step state.</summary>
    public PhaseStepState State { get; set; }

    /// <summary>True when this step is completed.</summary>
    public bool IsCompleted => State == PhaseStepState.Completed;

    /// <summary>True when this step is currently active.</summary>
    public bool IsActive => State == PhaseStepState.Active;

    /// <summary>True when this step is pending.</summary>
    public bool IsPending => State == PhaseStepState.Pending;
}
