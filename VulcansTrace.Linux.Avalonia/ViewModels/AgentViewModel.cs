using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input;
using Avalonia.Threading;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for the agent chat panel.
/// </summary>
public sealed class AgentViewModel : ViewModelBase, IDisposable
{
    private IAgent _agent;
    private readonly AgentResultPresenter _presenter;
    private readonly AgentHistoryCoordinator _historyCoordinator;
    private CancellationTokenSource? _cts;

    private string _userQuery = "";
    private string _logText = "";
    private bool _isBusy;
    private bool _hasPrivilegeWarning;
    private string _privilegeWarningText = "";
    private AgentResult? _lastResult;
    private bool _lastResultIsExportableAudit;
    private bool _hasCompletedAudit;
    private AgentIntent _lastAuditIntent = AgentIntent.FullAudit;
    private SeverityFilterOption? _selectedChatSeverityFilter;
    private string? _selectedChatCategoryFilter;

    /// <summary>Gets the collection of chat messages.</summary>
    public ObservableCollection<AgentMessageViewModel> Messages { get; } = new();

    /// <summary>Gets the collection of recent audit history entries.</summary>
    public ObservableCollection<AuditHistoryEntry> History { get; } = new();

    /// <summary>Gets available severity filters for the chat.</summary>
    public ObservableCollection<SeverityFilterOption> ChatSeverityFilters { get; } = new()
    {
        new SeverityFilterOption("All", Severity.Info),
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
                SendQueryCommand.RaiseCanExecuteChanged();
                CancelQueryCommand.RaiseCanExecuteChanged();
                FullAuditCommand.RaiseCanExecuteChanged();
                FirewallCommand.RaiseCanExecuteChanged();
                PortsCommand.RaiseCanExecuteChanged();
                ServicesCommand.RaiseCanExecuteChanged();
                NetworkCommand.RaiseCanExecuteChanged();
                ExplainSelectedCommand.RaiseCanExecuteChanged();
                ExportAuditCommand.RaiseCanExecuteChanged();
                ExportRemediationCommand.RaiseCanExecuteChanged();
                CompareAuditsCommand.RaiseCanExecuteChanged();
                OnPropertyChanged(nameof(CanExplainSelected));
                OnPropertyChanged(nameof(CanExportAudit));
                OnPropertyChanged(nameof(CanCompareAudits));
            }
        }
    }

    /// <summary>Gets the last agent result.</summary>
    public AgentResult? LastResult => _lastResult;

    /// <summary>Gets whether the selected UI finding can be explained now.</summary>
    public bool CanExplainSelected => !_isBusy && SelectedFindingProvider?.Invoke() != null;

    /// <summary>Gets whether the latest agent result is an audit that can be exported.</summary>
    public bool CanExportAudit => !_isBusy && _lastResultIsExportableAudit;

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
    /// Callback invoked when the user requests to show an audit diff.
    /// Set by the parent ViewModel to open the diff window.
    /// </summary>
    public Action<AuditDiff>? ShowAuditDiffAction { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AgentViewModel"/> class.
    /// </summary>
    /// <param name="agent">The agent instance to use for queries.</param>
    /// <param name="historyStore">The store for persisting audit history.</param>
    /// <summary>
    /// Swaps the underlying agent implementation (used when machine role changes).
    /// </summary>
    public void SetAgent(IAgent agent)
    {
        _agent = agent ?? throw new ArgumentNullException(nameof(agent));
        _lastResult = null;
        _lastResultIsExportableAudit = false;
        _hasCompletedAudit = false;
        _lastAuditIntent = AgentIntent.FullAudit;

        OnPropertyChanged(nameof(LastResult));
        OnPropertyChanged(nameof(CanExportAudit));
        ExportAuditCommand.RaiseCanExecuteChanged();
        ExportRemediationCommand.RaiseCanExecuteChanged();
        SetBaselineCommand.RaiseCanExecuteChanged();
    }

    public AgentViewModel(IAgent agent, IAuditHistoryStore historyStore)
    {
        _agent = agent ?? throw new ArgumentNullException(nameof(agent));
        ArgumentNullException.ThrowIfNull(historyStore);
        _presenter = new AgentResultPresenter(
            Messages,
            ChatCategoryFilters,
            () => _selectedChatSeverityFilter,
            () => _selectedChatCategoryFilter,
            v => HasPrivilegeWarning = v,
            t => PrivilegeWarningText = t);

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
            _ => !_isBusy && _hasCompletedAudit,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        CheckDriftCommand = new AsyncRelayCommand(
            async _ => await CheckDriftAsync(),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        ShowBaselineCommand = new AsyncRelayCommand(
            async _ => await ShowBaselineAsync(),
            _ => !_isBusy,
            ex => AddAgentMessage($"Error: {ex.Message}", true));

        _selectedChatSeverityFilter = ChatSeverityFilters[0];

        _historyCoordinator = new AgentHistoryCoordinator(
            historyStore,
            History,
            (text, isInfo) => _presenter.AddAgentMessage(text, isInfo),
            () => Messages,
            () =>
            {
                OnPropertyChanged(nameof(CanCompareAudits));
                CompareAuditsCommand.RaiseCanExecuteChanged();
                CompareSelectedAuditsCommand.RaiseCanExecuteChanged();
            });

        _historyCoordinator.LoadExisting();

        // Welcome message
        AddAgentMessage("Ask me about your system security. Try: \"Is my system secure?\" or \"Check my firewall\"", false);
        _historyCoordinator.ShowPersistenceWarningIfAny();
    }

    /// <summary>Gets the command to compare the last two audits.</summary>
    public RelayCommand CompareAuditsCommand { get; }

    /// <summary>Gets the command to compare two selected audits.</summary>
    public RelayCommand CompareSelectedAuditsCommand { get; }

    /// <summary>Gets the command to clear chat filters.</summary>
    public RelayCommand ClearChatFiltersCommand { get; }

    /// <summary>Gets the command to export a remediation plan for the last audit.</summary>
    public RelayCommand ExportRemediationCommand { get; }

    private bool CanSendQuery() => !string.IsNullOrWhiteSpace(_userQuery) && !_isBusy;
    private bool CanCancel() => _isBusy && _cts != null && !_cts.IsCancellationRequested;

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
        _cts?.Cancel();
    }

    private async Task SendQueryAsync()
    {
        var query = _userQuery.Trim();
        if (string.IsNullOrWhiteSpace(query))
            return;

        AddUserMessage(query);
        UserQuery = string.Empty;
        IsBusy = true;
        ClearPrivilegeWarning();

        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        try
        {
            AgentResult result;

            // Quick-parse to see if this is an ExplainFinding intent with a UI-selected finding
            var parsed = new QueryParser().Parse(query);
            if (parsed.Intent == AgentIntent.ExplainFinding && string.IsNullOrWhiteSpace(parsed.TargetReference))
            {
                var selected = SelectedFindingProvider?.Invoke();
                if (selected != null)
                {
                    result = await _agent.ExplainFindingAsync(selected, token);
                }
                else
                {
                    result = await _agent.AskAsync(query, LogText, token);
                }
            }
            else
            {
                result = await _agent.AskAsync(query, LogText, token);
            }

            SetLastResult(result);

            Dispatcher.UIThread.Post(() => PresentFindings(result));

            // Raise audit completion for audit intents so MainViewModel can sync evidence
            if (IsAuditIntent(result.Intent))
            {
                PublishAuditCompleted(result);
            }
        }
        catch (OperationCanceledException)
        {
            Dispatcher.UIThread.Post(() => AddAgentMessage("Query cancelled.", true));
        }
        catch (Exception ex)
        {
            Dispatcher.UIThread.Post(() => AddAgentMessage($"Agent error: {ex.Message}", true));
        }
        finally
        {
            Dispatcher.UIThread.Post(() => IsBusy = false);
            _cts?.Dispose();
            _cts = null;
        }
    }

    private async Task RunQuickAuditAsync(AgentIntent intent, string displayQuery)
    {
        AddUserMessage(displayQuery);
        IsBusy = true;
        ClearPrivilegeWarning();

        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        try
        {
            var result = await _agent.RunAuditAsync(intent, LogText, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() => PresentFindings(result));

            PublishAuditCompleted(result);
        }
        catch (OperationCanceledException)
        {
            Dispatcher.UIThread.Post(() => AddAgentMessage("Query cancelled.", true));
        }
        catch (Exception ex)
        {
            Dispatcher.UIThread.Post(() => AddAgentMessage($"Agent error: {ex.Message}", true));
        }
        finally
        {
            Dispatcher.UIThread.Post(() => IsBusy = false);
            _cts?.Dispose();
            _cts = null;
        }
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
        IsBusy = true;
        ClearPrivilegeWarning();

        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        try
        {
            var result = await _agent.ExplainFindingAsync(selected, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() =>
            {
                AddAgentMessage(result.Summary, result.AgentFindings.Count == 0);
                foreach (var finding in result.AgentFindings)
                {
                    AddAgentFinding(finding);
                }
            });
        }
        catch (OperationCanceledException)
        {
            Dispatcher.UIThread.Post(() => AddAgentMessage("Query cancelled.", true));
        }
        catch (Exception ex)
        {
            Dispatcher.UIThread.Post(() => AddAgentMessage($"Agent error: {ex.Message}", true));
        }
        finally
        {
            Dispatcher.UIThread.Post(() => IsBusy = false);
            _cts?.Dispose();
            _cts = null;
        }
    }

    private void PresentFindings(AgentResult result, bool showCapabilityReport = true, bool showPassedCount = true, bool showWarnings = true)
        => _presenter.PresentFindings(result, showCapabilityReport, showPassedCount, showWarnings);

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
        _lastResult = result;
        _lastResultIsExportableAudit = IsAuditIntent(result.Intent);
        OnPropertyChanged(nameof(LastResult));
        OnPropertyChanged(nameof(CanExportAudit));
        ExportAuditCommand.RaiseCanExecuteChanged();
        ExportRemediationCommand.RaiseCanExecuteChanged();
        SetBaselineCommand.RaiseCanExecuteChanged();
    }

    private void PublishAuditCompleted(AgentResult result)
    {
        AuditCompleted?.Invoke(this, result);
        _hasCompletedAudit = true;
        _lastAuditIntent = result.Intent;
        _lastResultIsExportableAudit = true;
        OnPropertyChanged(nameof(CanExportAudit));
        ExportAuditCommand.RaiseCanExecuteChanged();
        ExportRemediationCommand.RaiseCanExecuteChanged();
        SetBaselineCommand.RaiseCanExecuteChanged();
        _historyCoordinator.AppendHistoryEntry(result);
    }

    public void MarkLatestAuditExported()
    {
        _historyCoordinator.MarkLatestExported();
    }

    private static bool IsAuditIntent(AgentIntent intent) =>
        intent is AgentIntent.FullAudit
            or AgentIntent.FirewallCheck
            or AgentIntent.PortCheck
            or AgentIntent.ServiceCheck
            or AgentIntent.NetworkCheck
            or AgentIntent.SshCheck
            or AgentIntent.FilePermissionCheck
            or AgentIntent.KernelCheck;

    private async Task SetBaselineAsync()
    {
        if (_lastResult == null)
        {
            AddAgentMessage("Run an audit first, then save it as a baseline.", true);
            return;
        }

        AddUserMessage("Set baseline");
        IsBusy = true;
        ClearPrivilegeWarning();

        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        try
        {
            // Pass empty name so the agent generates it from _lastAuditIntent,
            // avoiding wrong intent (e.g. CheckDrift) in the name.
            var result = await _agent.SetBaselineAsync("", null, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() =>
            {
                AddAgentMessage(result.Summary, true);
            });
        }
        catch (OperationCanceledException)
        {
            Dispatcher.UIThread.Post(() => AddAgentMessage("Query cancelled.", true));
        }
        catch (Exception ex)
        {
            Dispatcher.UIThread.Post(() => AddAgentMessage($"Agent error: {ex.Message}", true));
        }
        finally
        {
            Dispatcher.UIThread.Post(() => IsBusy = false);
            _cts?.Dispose();
            _cts = null;
        }
    }

    private async Task CheckDriftAsync()
    {
        var intent = _lastAuditIntent;
        AddUserMessage($"Check drift ({intent})");
        IsBusy = true;
        ClearPrivilegeWarning();

        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        try
        {
            var result = await _agent.CheckDriftAsync(intent, null, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() => PresentFindings(result, showCapabilityReport: false, showPassedCount: false));
        }
        catch (OperationCanceledException)
        {
            Dispatcher.UIThread.Post(() => AddAgentMessage("Query cancelled.", true));
        }
        catch (Exception ex)
        {
            Dispatcher.UIThread.Post(() => AddAgentMessage($"Agent error: {ex.Message}", true));
        }
        finally
        {
            Dispatcher.UIThread.Post(() => IsBusy = false);
            _cts?.Dispose();
            _cts = null;
        }
    }

    private async Task ShowBaselineAsync()
    {
        var intent = _lastAuditIntent;
        AddUserMessage("Show baseline");
        IsBusy = true;
        ClearPrivilegeWarning();

        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        try
        {
            var result = await _agent.GetBaselineAsync(intent, token);
            SetLastResult(result);

            Dispatcher.UIThread.Post(() => PresentFindings(result, showCapabilityReport: false, showPassedCount: false, showWarnings: false));
        }
        catch (OperationCanceledException)
        {
            Dispatcher.UIThread.Post(() => AddAgentMessage("Query cancelled.", true));
        }
        catch (Exception ex)
        {
            Dispatcher.UIThread.Post(() => AddAgentMessage($"Agent error: {ex.Message}", true));
        }
        finally
        {
            Dispatcher.UIThread.Post(() => IsBusy = false);
            _cts?.Dispose();
            _cts = null;
        }
    }

    private void ExportRemediationPlan()
    {
        if (_lastResult == null || _lastResult.AgentFindings.Count == 0)
        {
            AddAgentMessage("No findings available to generate a remediation plan. Run an audit first.", true);
            return;
        }

        try
        {
            var builder = new RemediationPlanBuilder(new ExplanationProvider());
            var plan = builder.Build(_lastResult.AgentFindings);
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

    /// <inheritdoc />
    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
    }
}

/// <summary>
/// Represents a single message in the agent chat panel.
/// </summary>
public sealed class AgentMessageViewModel : ViewModelBase
{
    private string _text = "";
    private string _details = "";
    private bool _isUser;
    private bool _isInfo;
    private bool _isVisible = true;
    private Severity _severity;
    private DateTime _timestamp;
    private string _category = "";
    private IReadOnlyList<CopyableCommand> _verificationCommands = Array.Empty<CopyableCommand>();
    private RemediationSection? _remediationSection;

    public string Text
    {
        get => _text;
        set => SetField(ref _text, value);
    }

    public string Details
    {
        get => _details;
        set => SetField(ref _details, value);
    }

    public bool IsUser
    {
        get => _isUser;
        set => SetField(ref _isUser, value);
    }

    public bool IsInfo
    {
        get => _isInfo;
        set => SetField(ref _isInfo, value);
    }

    public bool IsVisible
    {
        get => _isVisible;
        set => SetField(ref _isVisible, value);
    }

    public string Category
    {
        get => _category;
        set => SetField(ref _category, value);
    }

    public Severity Severity
    {
        get => _severity;
        set => SetField(ref _severity, value);
    }

    public DateTime Timestamp
    {
        get => _timestamp;
        set => SetField(ref _timestamp, value);
    }

    /// <summary>Gets or sets the verification commands that can be copied from this message.</summary>
    public IReadOnlyList<CopyableCommand> VerificationCommands
    {
        get => _verificationCommands;
        set => SetField(ref _verificationCommands, value);
    }

    /// <summary>Gets whether this message has verification commands to display.</summary>
    public bool HasVerificationCommands => _verificationCommands.Count > 0;

    /// <summary>Gets or sets the interactive remediation section for this message.</summary>
    public RemediationSection? RemediationSection
    {
        get => _remediationSection;
        set
        {
            if (SetField(ref _remediationSection, value))
            {
                OnPropertyChanged(nameof(HasRemediationSection));
                OnPropertyChanged(nameof(HasPreconditions));
                OnPropertyChanged(nameof(HasBackupCommands));
                OnPropertyChanged(nameof(HasApplyCommands));
                OnPropertyChanged(nameof(HasRollbackCommands));
                OnPropertyChanged(nameof(HasRemediationVerificationCommands));
                OnPropertyChanged(nameof(RemediationPreconditions));
                OnPropertyChanged(nameof(RemediationBackupCommands));
                OnPropertyChanged(nameof(RemediationApplyCommands));
                OnPropertyChanged(nameof(RemediationRollbackCommands));
                OnPropertyChanged(nameof(RemediationVerificationCommands));
            }
        }
    }

    /// <summary>Gets whether this message has an interactive remediation section.</summary>
    public bool HasRemediationSection => _remediationSection != null;

    /// <summary>Gets whether the remediation section has preconditions.</summary>
    public bool HasPreconditions => _remediationSection?.Preconditions.Count > 0;

    /// <summary>Gets whether the remediation section has backup commands.</summary>
    public bool HasBackupCommands => _remediationSection?.BackupCommands.Count > 0;

    /// <summary>Gets whether the remediation section has apply commands.</summary>
    public bool HasApplyCommands => _remediationSection?.ApplyCommands.Count > 0;

    /// <summary>Gets whether the remediation section has rollback commands.</summary>
    public bool HasRollbackCommands => _remediationSection?.RollbackCommands.Count > 0;

    /// <summary>Gets whether the remediation section has verification commands.</summary>
    public bool HasRemediationVerificationCommands => _remediationSection?.VerificationCommands.Count > 0;

    /// <summary>Gets the preconditions for the remediation.</summary>
    public IReadOnlyList<string> RemediationPreconditions =>
        _remediationSection?.Preconditions ?? Array.Empty<string>();

    /// <summary>Gets the backup commands as copyable commands.</summary>
    public IReadOnlyList<CopyableCommand> RemediationBackupCommands =>
        ToCopyableCommands(_remediationSection?.BackupCommands);

    /// <summary>Gets the apply commands as copyable commands.</summary>
    public IReadOnlyList<CopyableCommand> RemediationApplyCommands =>
        ToCopyableCommands(_remediationSection?.ApplyCommands);

    /// <summary>Gets the rollback commands as copyable commands.</summary>
    public IReadOnlyList<CopyableCommand> RemediationRollbackCommands =>
        ToCopyableCommands(_remediationSection?.RollbackCommands);

    /// <summary>Gets the verification commands as copyable commands.</summary>
    public IReadOnlyList<CopyableCommand> RemediationVerificationCommands =>
        ToCopyableCommands(_remediationSection?.VerificationCommands);

    private static IReadOnlyList<CopyableCommand> ToCopyableCommands(IReadOnlyList<RemediationCommand>? commands)
    {
        if (commands == null || commands.Count == 0)
            return Array.Empty<CopyableCommand>();

        return commands.Select(c => new CopyableCommand
        {
            DisplayText = c.Command,
            FullCommand = c.Command,
            Safety = c.Safety,
            Analysis = c.Analysis
        }).ToList();
    }

    /// <summary>
    /// Copies the specified command text to the system clipboard.
    /// </summary>
    public void CopyCommandToClipboard(string commandText)
    {
        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow?.Clipboard?.SetTextAsync(commandText);
        }
    }
}
