using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for the agent chat panel.
/// </summary>
public sealed class AgentViewModel : ViewModelBase, IDisposable
{
    private readonly IAgent _agent;
    private CancellationTokenSource? _cts;

    private string _userQuery = "";
    private string _logText = "";
    private bool _isBusy;
    private bool _hasPrivilegeWarning;
    private string _privilegeWarningText = "";
    private AgentResult? _lastResult;
    private bool _lastResultIsExportableAudit;

    /// <summary>Gets the collection of chat messages.</summary>
    public ObservableCollection<AgentMessageViewModel> Messages { get; } = new();

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
                OnPropertyChanged(nameof(CanExplainSelected));
                OnPropertyChanged(nameof(CanExportAudit));
            }
        }
    }

    /// <summary>Gets the last agent result.</summary>
    public AgentResult? LastResult => _lastResult;

    /// <summary>Gets whether the selected UI finding can be explained now.</summary>
    public bool CanExplainSelected => !_isBusy && SelectedFindingProvider?.Invoke() != null;

    /// <summary>Gets whether the latest agent result is an audit that can be exported.</summary>
    public bool CanExportAudit => !_isBusy && _lastResultIsExportableAudit;

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

    /// <summary>
    /// Callback invoked when the user requests an audit export from the agent panel.
    /// Set by the parent ViewModel to bridge to the shared evidence export logic.
    /// </summary>
    public Action? RequestExportAudit { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AgentViewModel"/> class.
    /// </summary>
    /// <param name="agent">The agent instance to use for queries.</param>
    public AgentViewModel(IAgent agent)
    {
        _agent = agent ?? throw new ArgumentNullException(nameof(agent));

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

        // Welcome message
        AddAgentMessage("Ask me about your system security. Try: \"Is my system secure?\" or \"Check my firewall\"", false);
    }

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

            Dispatcher.UIThread.Post(() =>
            {
                AddAgentMessage(result.Summary, result.AgentFindings.Count == 0);

                if (result.AgentFindings.Count > 0)
                {
                    AddAgentFindingGroupSummary(result.AgentFindings);

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

                if (result.Warnings.Count > 0)
                {
                    AddAgentMessage($"Warnings: {string.Join("; ", result.Warnings)}", true);
                    DetectPrivilegeWarning(result.Warnings);
                }
            });

            // Raise audit completion for audit intents so MainViewModel can sync evidence
            if (result.Intent is AgentIntent.FullAudit or AgentIntent.FirewallCheck
                or AgentIntent.PortCheck or AgentIntent.ServiceCheck or AgentIntent.NetworkCheck)
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

    private void AddUserMessage(string text)
    {
        Messages.Add(new AgentMessageViewModel
        {
            Text = text,
            IsUser = true,
            Timestamp = DateTime.Now
        });
    }

    private void AddAgentMessage(string text, bool isInfo)
    {
        Messages.Add(new AgentMessageViewModel
        {
            Text = text,
            IsUser = false,
            IsInfo = isInfo,
            Timestamp = DateTime.Now
        });
    }

    private void AddAgentFinding(Finding finding)
    {
        var ruleIdPrefix = string.IsNullOrEmpty(finding.RuleId) ? "" : $"[{finding.RuleId}] ";
        Messages.Add(new AgentMessageViewModel
        {
            Text = $"{ruleIdPrefix}[{finding.Severity}] {finding.ShortDescription}",
            Details = finding.Details,
            IsUser = false,
            IsInfo = false,
            Severity = finding.Severity,
            Timestamp = DateTime.Now
        });
    }

    private void AddAgentFindingGroupSummary(IReadOnlyList<Finding> findings)
    {
        var critical = findings.Count(f => f.Severity == Severity.Critical);
        var high = findings.Count(f => f.Severity == Severity.High);
        var medium = findings.Count(f => f.Severity == Severity.Medium);
        var low = findings.Count(f => f.Severity == Severity.Low);
        var info = findings.Count(f => f.Severity == Severity.Info);

        var parts = new List<string>();
        if (critical > 0) parts.Add($"{critical} Critical");
        if (high > 0) parts.Add($"{high} High");
        if (medium > 0) parts.Add($"{medium} Medium");
        if (low > 0) parts.Add($"{low} Low");
        if (info > 0) parts.Add($"{info} Info");

        var summary = $"Findings: {string.Join(", ", parts)} ({findings.Count} total)";
        Messages.Add(new AgentMessageViewModel
        {
            Text = summary,
            IsUser = false,
            IsInfo = true,
            Timestamp = DateTime.Now
        });
    }

    private void AddAgentFindingGroup(string category, IReadOnlyList<Finding> findings)
    {
        var highCritical = findings.Count(f => f.Severity >= Severity.High);
        var header = highCritical > 0
            ? $"[{category}] {findings.Count} finding(s) — {highCritical} High/Critical"
            : $"[{category}] {findings.Count} finding(s)";

        var details = new System.Text.StringBuilder();
        foreach (var finding in findings)
        {
            var ruleIdPrefix = string.IsNullOrEmpty(finding.RuleId) ? "" : $"[{finding.RuleId}] ";
            details.AppendLine($"• {ruleIdPrefix}[{finding.Severity}] {finding.ShortDescription}");
        }

        Messages.Add(new AgentMessageViewModel
        {
            Text = header,
            Details = details.ToString().TrimEnd(),
            IsUser = false,
            IsInfo = false,
            Severity = findings.Max(f => f.Severity),
            Timestamp = DateTime.Now
        });
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

            Dispatcher.UIThread.Post(() =>
            {
                AddAgentMessage(result.Summary, result.AgentFindings.Count == 0);

                if (result.AgentFindings.Count > 0)
                {
                    AddAgentFindingGroupSummary(result.AgentFindings);

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

                if (result.Warnings.Count > 0)
                {
                    AddAgentMessage($"Warnings: {string.Join("; ", result.Warnings)}", true);
                    DetectPrivilegeWarning(result.Warnings);
                }
            });

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

    private void DetectPrivilegeWarning(IReadOnlyList<string> warnings)
    {
        var privilegeWarning = warnings.FirstOrDefault(w =>
            w.Contains("permission", StringComparison.OrdinalIgnoreCase) ||
            w.Contains("privilege", StringComparison.OrdinalIgnoreCase) ||
            w.Contains("denied", StringComparison.OrdinalIgnoreCase) ||
            w.Contains("elevated", StringComparison.OrdinalIgnoreCase));

        if (privilegeWarning != null)
        {
            HasPrivilegeWarning = true;
            PrivilegeWarningText = "Some inspections are limited without elevated privileges. Process names, connection details, and service states may be hidden. Run with sudo for full visibility.";
        }
    }

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
    }

    private void PublishAuditCompleted(AgentResult result)
    {
        AuditCompleted?.Invoke(this, result);
        _lastResultIsExportableAudit = true;
        OnPropertyChanged(nameof(CanExportAudit));
        ExportAuditCommand.RaiseCanExecuteChanged();
    }

    private static bool IsAuditIntent(AgentIntent intent) =>
        intent is AgentIntent.FullAudit
            or AgentIntent.FirewallCheck
            or AgentIntent.PortCheck
            or AgentIntent.ServiceCheck
            or AgentIntent.NetworkCheck;

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
    private Severity _severity;
    private DateTime _timestamp;

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
}
