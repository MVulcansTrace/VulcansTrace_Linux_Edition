using System;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

internal sealed class AgentOperationRunner : IDisposable
{
    private readonly Action<bool> _setBusy;
    private readonly Action _clearPrivilegeWarning;
    private readonly Action<string, bool, bool> _addAgentMessage;
    private CancellationTokenSource? _cts;
    private bool _lastSucceeded = true;

    public AgentOperationRunner(
        Action<bool> setBusy,
        Action clearPrivilegeWarning,
        Action<string, bool, bool> addAgentMessage)
    {
        _setBusy = setBusy ?? throw new ArgumentNullException(nameof(setBusy));
        _clearPrivilegeWarning = clearPrivilegeWarning ?? throw new ArgumentNullException(nameof(clearPrivilegeWarning));
        _addAgentMessage = addAgentMessage ?? throw new ArgumentNullException(nameof(addAgentMessage));
    }

    public bool CanCancel => _cts != null && !_cts.IsCancellationRequested;

    /// <summary>
    /// Gets whether the most recent operation completed without throwing or being cancelled.
    /// </summary>
    public bool LastSucceeded => _lastSucceeded;

    public void Cancel()
    {
        _cts?.Cancel();
    }

    public async Task RunAsync(Func<CancellationToken, Task> operation)
    {
        ArgumentNullException.ThrowIfNull(operation);

        if (_cts != null)
        {
            throw new InvalidOperationException("An agent operation is already in progress.");
        }

        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        _setBusy(true);
        _clearPrivilegeWarning();
        _lastSucceeded = false;

        try
        {
            await operation(token);
            _lastSucceeded = true;
        }
        catch (OperationCanceledException)
        {
            // Cancellation is a user action, not an error — keep it as a neutral info bubble.
            RunOnUiThread(() => _addAgentMessage("Query cancelled.", true, false));
        }
        catch (Exception ex)
        {
            RunOnUiThread(() => _addAgentMessage($"Agent error: {ex.Message}", true, true));
        }
        finally
        {
            RunOnUiThread(() => _setBusy(false));
            _cts?.Dispose();
            _cts = null;
        }
    }

    private static void RunOnUiThread(Action action)
    {
        if (Dispatcher.UIThread.CheckAccess())
        {
            action();
        }
        else
        {
            Dispatcher.UIThread.Post(action);
        }
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
    }
}
