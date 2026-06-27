using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Agent.Suggestions;
using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for the agent chat panel.
/// </summary>
public sealed class AgentViewModel : ViewModelBase, IDisposable
{
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
    private readonly List<SlashCommandItem> _allSlashCommands = new();

    /// <summary>Gets the collection of chat messages.</summary>
    public ObservableCollection<AgentMessageViewModel> Messages { get; } = new();

    /// <summary>Gets the collection of quick-check action chips.</summary>
    public ObservableCollection<AgentQuickAction> QuickActions { get; } = new();

    /// <summary>Gets the filtered slash-command palette items.</summary>
    public ObservableCollection<SlashCommandItem> FilteredSlashCommands { get; } = new();

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
                SendQueryCommand.RaiseCanExecuteChanged();
                ExecuteSlashCommandCommand.RaiseCanExecuteChanged();
                CancelQueryCommand.RaiseCanExecuteChanged();
                FullAuditCommand.RaiseCanExecuteChanged();
                FirewallCommand.RaiseCanExecuteChanged();
                PortsCommand.RaiseCanExecuteChanged();
                ServicesCommand.RaiseCanExecuteChanged();
                NetworkCommand.RaiseCanExecuteChanged();
                ContainerCommand.RaiseCanExecuteChanged();
                KubernetesCommand.RaiseCanExecuteChanged();
                YaraCommand.RaiseCanExecuteChanged();
                ProcessRuntimeCommand.RaiseCanExecuteChanged();
                ExplainSelectedCommand.RaiseCanExecuteChanged();
                ExportAuditCommand.RaiseCanExecuteChanged();
                ExportRemediationCommand.RaiseCanExecuteChanged();
                VerifySessionCommand.RaiseCanExecuteChanged();
                ExportSessionCommand.RaiseCanExecuteChanged();
                CompareAuditsCommand.RaiseCanExecuteChanged();
                OnPropertyChanged(nameof(CanExplainSelected));
                OnPropertyChanged(nameof(CanExportAudit));
                OnPropertyChanged(nameof(CanExportSession));
                OnPropertyChanged(nameof(CanCompareAudits));
            }
        }
    }

    /// <summary>Gets the current agent status for the header badge.</summary>
    public string AgentStatus
    {
        get => _agentStatus;
        private set => SetField(ref _agentStatus, value);
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
    }

    /// <summary>Gets the last agent result.</summary>
    public AgentResult? LastResult => _resultState.LastResult;

    /// <summary>Gets whether the selected UI finding can be explained now.</summary>
    public bool CanExplainSelected => !_isBusy && SelectedFindingProvider?.Invoke() != null;

    /// <summary>Gets whether the latest agent result is an audit that can be exported.</summary>
    public bool CanExportAudit => !_isBusy && _resultState.IsExportableAudit;

    /// <summary>Gets whether the latest agent result has a remediation session report to export.</summary>
    public bool CanExportSession => !_isBusy && _resultState.LastResult?.RemediationSession != null;

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

    /// <summary>Gets the command to send a query to the agent.</summary>
    public AsyncRelayCommand SendQueryCommand { get; }

    /// <summary>Gets the command to cancel the current agent operation.</summary>
    public RelayCommand CancelQueryCommand { get; }

    /// <summary>Gets the command to execute a slash-command palette item.</summary>
    public AsyncRelayCommand ExecuteSlashCommandCommand { get; }

    /// <summary>Gets the command to run a full audit.</summary>
    public AsyncRelayCommand FullAuditCommand { get; }

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

    /// <summary>Gets the command to export the last agent audit.</summary>
    public RelayCommand ExportAuditCommand { get; }

    /// <summary>Gets the command to save the last audit as a baseline.</summary>
    public AsyncRelayCommand SetBaselineCommand { get; }

    /// <summary>Gets the command to check drift against the saved baseline.</summary>
    public AsyncRelayCommand CheckDriftCommand { get; }

    /// <summary>Gets the command to show the current baseline.</summary>
    public AsyncRelayCommand ShowBaselineCommand { get; }

    /// <summary>Gets the command to compare the last two audits.</summary>
    public RelayCommand CompareAuditsCommand { get; }

    /// <summary>Gets the command to compare two selected audits.</summary>
    public RelayCommand CompareSelectedAuditsCommand { get; }

    /// <summary>Gets the command to clear chat filters.</summary>
    public RelayCommand ClearChatFiltersCommand { get; }

    /// <summary>Gets the command to export a remediation plan for the last audit.</summary>
    public RelayCommand ExportRemediationCommand { get; }

    /// <summary>Gets the command to run verification on an active remediation session.</summary>
    public AsyncRelayCommand VerifySessionCommand { get; }

    /// <summary>Gets the command to export the current remediation session report.</summary>
    public AsyncRelayCommand ExportSessionCommand { get; }

    /// <summary>Gets the command to list persisted remediation sessions.</summary>
    public AsyncRelayCommand ListSessionsCommand { get; }

    /// <summary>Gets the command to resume the selected remediation session.</summary>
    public AsyncRelayCommand ResumeSessionCommand { get; }

    /// <summary>Gets the command to delete the selected remediation session.</summary>
    public AsyncRelayCommand DeleteSessionCommand { get; }

    /// <summary>Gets the command to import threat intelligence IOCs.</summary>
    public AsyncRelayCommand ImportThreatIntelCommand { get; }

    /// <summary>Gets the command to add a note to the active remediation session.</summary>
    public AsyncRelayCommand AddSessionNoteCommand { get; }

    /// <summary>Gets the command to add a note to a specific remediation step.</summary>
    public AsyncRelayCommand AddStepNoteCommand { get; }

    /// <summary>Gets the command to deploy active countermeasures for a critical chain.</summary>
    public AsyncRelayCommand DeployCountermeasuresCommand { get; }

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
    /// Callback invoked when the user requests to show an audit diff.
    /// Set by the parent ViewModel to open the diff window.
    /// </summary>
    public Action<AuditDiff>? ShowAuditDiffAction { get; set; }

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
    public AgentViewModel(IAgent agent, IAuditHistoryStore historyStore, RemediationPlanBuilder remediationPlanBuilder, RemediationExecutor remediationExecutor, ISessionStore? sessionStore = null, IThreatIntelStore? threatIntelStore = null, IDialogService? dialogService = null, IAgentMemoryStore? memoryStore = null)
    {
        _agent = agent ?? throw new ArgumentNullException(nameof(agent));
        ArgumentNullException.ThrowIfNull(historyStore);
        _remediationPlanBuilder = remediationPlanBuilder ?? throw new ArgumentNullException(nameof(remediationPlanBuilder));
        _remediationExecutor = remediationExecutor ?? throw new ArgumentNullException(nameof(remediationExecutor));
        _sessionStore = sessionStore;
        _threatIntelStore = threatIntelStore;
        _dialogService = dialogService;
        _memoryStore = memoryStore;
        _presenter = new AgentResultPresenter(
            Messages,
            ChatCategoryFilters,
            () => _selectedChatSeverityFilter,
            () => _selectedChatCategoryFilter,
            v => HasPrivilegeWarning = v,
            t => PrivilegeWarningText = t,
            ExecuteSuggestionAsync);
        _operationRunner = new AgentOperationRunner(
            value => IsBusy = value,
            ClearPrivilegeWarning,
            AddAgentMessage);
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
        _resultState = new AgentResultStateCoordinator(
            _historyCoordinator,
            OnPropertyChanged,
            RefreshResultCommands,
            result => AuditCompleted?.Invoke(this, result));

        SendQueryCommand = new AsyncRelayCommand(
            async _ => await SendQueryAsync(),
            _ => CanSendQuery(),
            ex =>
            {
                IsBusy = false;
                AddAgentMessage($"Error: {ex.Message}", true);
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
                    UserQuery = string.Empty;
                    if (cmd.Handler is not null)
                    {
                        await cmd.Handler();
                    }
                }
            },
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        FullAuditCommand = new AsyncRelayCommand(
            async _ => await RunQuickAuditAsync(AgentIntent.FullAudit, "Run a full audit"),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        FirewallCommand = new AsyncRelayCommand(
            async _ => await RunQuickAuditAsync(AgentIntent.FirewallCheck, "Check my firewall"),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        PortsCommand = new AsyncRelayCommand(
            async _ => await RunQuickAuditAsync(AgentIntent.PortCheck, "What ports are open?"),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        ServicesCommand = new AsyncRelayCommand(
            async _ => await RunQuickAuditAsync(AgentIntent.ServiceCheck, "What services are running?"),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        NetworkCommand = new AsyncRelayCommand(
            async _ => await RunQuickAuditAsync(AgentIntent.NetworkCheck, "Check my network"),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        ContainerCommand = new AsyncRelayCommand(
            async _ => await RunQuickAuditAsync(AgentIntent.ContainerCheck, "Check my containers"),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        KubernetesCommand = new AsyncRelayCommand(
            async _ => await RunQuickAuditAsync(AgentIntent.KubernetesCheck, "Check my kubernetes"),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        YaraCommand = new AsyncRelayCommand(
            async _ => await RunQuickAuditAsync(AgentIntent.YaraCheck, "Run a YARA scan"),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        ProcessRuntimeCommand = new AsyncRelayCommand(
            async _ => await RunQuickAuditAsync(AgentIntent.ProcessRuntimeCheck, "Check running processes"),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        ExplainSelectedCommand = new AsyncRelayCommand(
            async _ => await ExplainSelectedAsync(),
            _ => CanExplainSelected,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

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
            _ => { SelectedChatSeverityFilter = ChatSeverityFilters[0]; SelectedChatCategoryFilter = null; },
            _ => true);

        SetBaselineCommand = new AsyncRelayCommand(
            async _ => await SetBaselineAsync(),
            _ => !_isBusy && _resultState.HasCompletedAudit,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        CheckDriftCommand = new AsyncRelayCommand(
            async _ => await CheckDriftAsync(),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        ShowBaselineCommand = new AsyncRelayCommand(
            async _ => await ShowBaselineAsync(),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        VerifySessionCommand = new AsyncRelayCommand(
            async param => await VerifySessionAsync((param as string) ?? ""),
            param => !_isBusy && !string.IsNullOrWhiteSpace(param as string),
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        ExportSessionCommand = new AsyncRelayCommand(
            async _ => await ExportSessionAsync(),
            _ => !_isBusy && _resultState.LastResult?.RemediationSession != null,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        ListSessionsCommand = new AsyncRelayCommand(
            async _ => await ListSessionsAsync(),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        ResumeSessionCommand = new AsyncRelayCommand(
            async _ => await ResumeSessionAsync(),
            _ => !_isBusy && _selectedSession != null,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        DeleteSessionCommand = new AsyncRelayCommand(
            async _ => await DeleteSessionAsync(),
            _ => !_isBusy && _selectedSession != null,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        ImportThreatIntelCommand = new AsyncRelayCommand(
            async _ => await ImportThreatIntelAsync(),
            _ => !_isBusy && _threatIntelStore != null && _dialogService != null,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        AddSessionNoteCommand = new AsyncRelayCommand(
            async param => await AddSessionNoteAsync((param as string) ?? ""),
            param => !_isBusy && _resultState.LastResult?.RemediationSession != null && !string.IsNullOrWhiteSpace(param as string),
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        AddStepNoteCommand = new AsyncRelayCommand(
            async param => await AddStepNoteAsync((param as string) ?? ""),
            param => !_isBusy && _resultState.LastResult?.RemediationSession != null && !string.IsNullOrWhiteSpace(param as string),
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        DeployCountermeasuresCommand = new AsyncRelayCommand(
            async param => await DeployCountermeasuresAsync(param as RemediationSection),
            param => !_isBusy && param is RemediationSection section && section.CountermeasureCommands.Count > 0,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        _selectedChatSeverityFilter = ChatSeverityFilters[0];

        RefreshSessions();

        _historyCoordinator.LoadExisting();

        InitializeQuickActions();
        InitializeSlashCommands();

        // Welcome message
        AddAgentMessage("Ask me about your system security. Try: \"Is my system secure?\" or \"Check my firewall\"", false);
        _historyCoordinator.ShowPersistenceWarningIfAny();
        ShowMemoryPersistenceWarningIfAny();
    }

    private bool CanSendQuery() => !string.IsNullOrWhiteSpace(_userQuery) && !_isBusy;
    private bool CanCancel() => _isBusy && _operationRunner.CanCancel;

    private void InitializeQuickActions()
    {
        QuickActions.Add(new AgentQuickAction { Label = "Full audit", Icon = "🔍", Command = FullAuditCommand });
        QuickActions.Add(new AgentQuickAction { Label = "Firewall", Icon = "🧱", Command = FirewallCommand });
        QuickActions.Add(new AgentQuickAction { Label = "Ports", Icon = "🔌", Command = PortsCommand });
        QuickActions.Add(new AgentQuickAction { Label = "Services", Icon = "⚙️", Command = ServicesCommand });
        QuickActions.Add(new AgentQuickAction { Label = "Network", Icon = "🌐", Command = NetworkCommand });
        QuickActions.Add(new AgentQuickAction { Label = "Containers", Icon = "📦", Command = ContainerCommand });
        QuickActions.Add(new AgentQuickAction { Label = "Kubernetes", Icon = "☸️", Command = KubernetesCommand });
        QuickActions.Add(new AgentQuickAction { Label = "YARA", Icon = "🦠", Command = YaraCommand });
        QuickActions.Add(new AgentQuickAction { Label = "Processes", Icon = "PROC", Command = ProcessRuntimeCommand });
        QuickActions.Add(new AgentQuickAction { Label = "Set baseline", Icon = "BASE", Command = SetBaselineCommand });
        QuickActions.Add(new AgentQuickAction { Label = "Check drift", Icon = "DIFF", Command = CheckDriftCommand });
        QuickActions.Add(new AgentQuickAction { Label = "Show baseline", Icon = "SHOW", Command = ShowBaselineCommand });
        QuickActions.Add(new AgentQuickAction { Label = "Export audit", Icon = "SAVE", Command = ExportAuditCommand });
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
        Messages.Clear();
        SelectedChatSeverityFilter = ChatSeverityFilters[0];
        SelectedChatCategoryFilter = null;
        AddAgentMessage("Chat cleared.", true);
        return Task.CompletedTask;
    }

    private Task ShowSlashHelpAsync()
    {
        AddAgentMessage(
            "Available commands: /firewall, /ports, /services, /network, /ssh, /filesystem, /kernel, /users, /logging, /cron, /packages, /threatintel, /full, /fullaudit, /containers, /kubernetes, /yara, /processes, /baseline, /drift, /baseline show, /show baseline, /sessions, /risk, /clear, /help",
            false);
        return Task.CompletedTask;
    }

    private void UpdateSlashPalette()
    {
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

            IsSlashPaletteOpen = FilteredSlashCommands.Count > 0;
        }
        else
        {
            IsSlashPaletteOpen = false;
            FilteredSlashCommands.Clear();
        }
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
    }

    private void CancelQuery()
    {
        _operationRunner.Cancel();
    }

    private async Task SendQueryAsync()
    {
        var query = _userQuery.Trim();
        if (string.IsNullOrWhiteSpace(query))
            return;

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

        AddUserMessage(query);
        UserQuery = string.Empty;

        await _operationRunner.RunAsync(async token =>
        {
            var result = await _queryExecutor.ExecuteAsync(query, LogText, SelectedFindingProvider, token);
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
        AddUserMessage(displayQuery);

        await _operationRunner.RunAsync(async token =>
        {
            var result = await _agent.RunAuditAsync(intent, LogText, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() => PresentFindings(result));

            PublishAuditCompleted(result);
        });
    }

    private async Task ExplainSelectedAsync()
    {
        var selected = SelectedFindingProvider?.Invoke();
        if (selected == null)
        {
            AddAgentMessage("No finding is selected. Select a finding from the list first.", true);
            return;
        }

        AddUserMessage("Explain selected");

        await _operationRunner.RunAsync(async token =>
        {
            var result = await _agent.ExplainFindingAsync(selected, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() =>
            {
                PresentFindings(result, showCapabilityReport: false, showPassedCount: false, showWarnings: false);
            });
        });
    }

    private void PresentFindings(AgentResult result, bool showCapabilityReport = true, bool showPassedCount = true, bool showWarnings = true)
    {
        // Reset chat filters when a new audit result arrives so findings from the current
        // intent aren't hidden by a stale category or severity selection.
        if (AgentResultStateCoordinator.IsAuditIntent(result.Intent))
        {
            SelectedChatSeverityFilter = ChatSeverityFilters[0];
            SelectedChatCategoryFilter = null;
        }

        _presenter.PresentFindings(result, showCapabilityReport, showPassedCount, showWarnings);
    }

    private void AddUserMessage(string text) => _presenter.AddUserMessage(text);
    private void AddAgentMessage(string text, bool isInfo) => _presenter.AddAgentMessage(text, isInfo);
    private void AddAgentFinding(Finding finding) => _presenter.AddAgentFinding(finding);

    private void ClearPrivilegeWarning()
    {
        HasPrivilegeWarning = false;
        PrivilegeWarningText = string.Empty;
    }

    private void SetLastResult(AgentResult result)
    {
        _resultState.SetLastResult(result);
        ShowMemoryPersistenceWarningIfAny();
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

    private void RefreshResultCommands()
    {
        ExportAuditCommand.RaiseCanExecuteChanged();
        ExportRemediationCommand.RaiseCanExecuteChanged();
        ExportSessionCommand.RaiseCanExecuteChanged();
        SetBaselineCommand.RaiseCanExecuteChanged();
        OnPropertyChanged(nameof(CanExportSession));
    }

    private void PublishAuditCompleted(AgentResult result)
    {
        _resultState.PublishAuditCompleted(result);
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
            AddAgentMessage("Run an audit first, then save it as a baseline.", true);
            return;
        }

        AddUserMessage("Set baseline");

        await _operationRunner.RunAsync(async token =>
        {
            // Pass empty name so the agent generates it from the last audit intent,
            // avoiding wrong intent (e.g. CheckDrift) in the name.
            var result = await _agent.SetBaselineAsync("", null, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() =>
            {
                PresentFindings(result, showCapabilityReport: false, showPassedCount: false);
            });
        });
    }

    private async Task CheckDriftAsync()
    {
        var intent = _resultState.LastAuditIntent;
        AddUserMessage($"Check drift ({intent})");

        await _operationRunner.RunAsync(async token =>
        {
            var result = await _agent.CheckDriftAsync(intent, null, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() => PresentFindings(result, showCapabilityReport: false, showPassedCount: false));
        });
    }

    private async Task ShowBaselineAsync()
    {
        var intent = _resultState.LastAuditIntent;
        AddUserMessage("Show baseline");

        await _operationRunner.RunAsync(async token =>
        {
            var result = await _agent.GetBaselineAsync(intent, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() => PresentFindings(result, showCapabilityReport: false, showPassedCount: false, showWarnings: false));
        });
    }

    private async Task VerifySessionAsync(string sessionId)
    {
        AddUserMessage($"Verify remediation session {sessionId}");

        await _operationRunner.RunAsync(async token =>
        {
            var result = await _agent.VerifyRemediationAsync(sessionId, token);
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
        AddUserMessage("List sessions");

        await _operationRunner.RunAsync(async token =>
        {
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

        AddUserMessage($"Resume session {session.SessionId}");

        await _operationRunner.RunAsync(async token =>
        {
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

        await _operationRunner.RunAsync(async token =>
        {
            var result = await _agent.DeleteRemediationSessionAsync(session.SessionId, token);

            Dispatcher.UIThread.Post(() =>
            {
                SelectedSession = null;
                RefreshSessions();
                PresentFindings(result, showCapabilityReport: false, showPassedCount: false, showWarnings: false);
            });
        });
    }

    private async Task AddSessionNoteAsync(string text)
    {
        var session = _resultState.LastResult?.RemediationSession;
        if (session == null)
        {
            AddAgentMessage("No active remediation session to add a note to.", true);
            return;
        }

        await _operationRunner.RunAsync(async token =>
        {
            var result = await _agent.AddSessionNoteAsync(session.SessionId, text, null, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() =>
            {
                if (result.RemediationSession != null)
                {
                    UpdateSessionTimeline(result.RemediationSession);
                    RefreshSessions();
                }
                PresentFindings(result, showCapabilityReport: false, showPassedCount: false, showWarnings: false);
            });
        });
    }

    private async Task AddStepNoteAsync(string param)
    {
        var session = _resultState.LastResult?.RemediationSession;
        if (session == null)
        {
            AddAgentMessage("No active remediation session to add a note to.", true);
            return;
        }

        // param format: "ruleId|note text"
        var parts = param.Split('|', 2);
        if (parts.Length < 2 || string.IsNullOrWhiteSpace(parts[0]) || string.IsNullOrWhiteSpace(parts[1]))
        {
            AddAgentMessage("Provide the note as 'ruleId|note text'.", true);
            return;
        }

        var ruleId = parts[0].Trim();
        var text = parts[1].Trim();

        await _operationRunner.RunAsync(async token =>
        {
            var result = await _agent.AddStepNoteAsync(session.SessionId, ruleId, text, null, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() =>
            {
                if (result.RemediationSession != null)
                {
                    UpdateSessionTimeline(result.RemediationSession);
                    RefreshSessions();
                }
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
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _operationRunner.Dispose();
    }
}
