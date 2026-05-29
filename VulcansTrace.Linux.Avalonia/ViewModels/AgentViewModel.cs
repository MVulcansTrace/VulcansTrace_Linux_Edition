using System;
using System.Collections.ObjectModel;
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
    private AgentResult? _lastResult;

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
            }
        }
    }

    /// <summary>Gets the last agent result.</summary>
    public AgentResult? LastResult => _lastResult;

    /// <summary>
    /// Optional provider that returns the currently selected finding from the UI.
    /// When set, ExplainFinding queries will target this finding if no explicit reference is given.
    /// </summary>
    public Func<Finding?>? SelectedFindingProvider { get; set; }

    /// <summary>Gets the command to send a query to the agent.</summary>
    public AsyncRelayCommand SendQueryCommand { get; }

    /// <summary>Gets the command to cancel the current agent operation.</summary>
    public RelayCommand CancelQueryCommand { get; }

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

        // Welcome message
        AddAgentMessage("Ask me about your system security. Try: \"Is my system secure?\" or \"Check my firewall\"", false);
    }

    private bool CanSendQuery() => !string.IsNullOrWhiteSpace(_userQuery) && !_isBusy;
    private bool CanCancel() => _isBusy && _cts != null && !_cts.IsCancellationRequested;

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

            _lastResult = result;

            Dispatcher.UIThread.Post(() =>
            {
                AddAgentMessage(result.Summary, result.AgentFindings.Count == 0);

                foreach (var finding in result.AgentFindings)
                {
                    AddAgentFinding(finding);
                }

                if (result.Warnings.Count > 0)
                {
                    AddAgentMessage($"Warnings: {string.Join("; ", result.Warnings)}", true);
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
        Messages.Add(new AgentMessageViewModel
        {
            Text = $"[{finding.Severity}] {finding.ShortDescription}",
            Details = finding.Details,
            IsUser = false,
            IsInfo = false,
            Severity = finding.Severity,
            Timestamp = DateTime.Now
        });
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
