using System;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using VulcansTrace.Linux.Agent.Reports;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

internal sealed class AgentOperationRunner : IDisposable
{
    private readonly Action<bool> _setBusy;
    private readonly Action _clearPrivilegeWarning;
    private readonly Action<string, bool, bool> _addAgentMessage;
    private readonly Action<AgentAuditProgress> _onProgress;
    private CancellationTokenSource? _cts;
    private bool _lastSucceeded = true;

    public AgentOperationRunner(
        Action<bool> setBusy,
        Action clearPrivilegeWarning,
        Action<string, bool, bool> addAgentMessage,
        Action<AgentAuditProgress>? onProgress = null)
    {
        _setBusy = setBusy ?? throw new ArgumentNullException(nameof(setBusy));
        _clearPrivilegeWarning = clearPrivilegeWarning ?? throw new ArgumentNullException(nameof(clearPrivilegeWarning));
        _addAgentMessage = addAgentMessage ?? throw new ArgumentNullException(nameof(addAgentMessage));
        _onProgress = onProgress ?? (_ => { });
    }

    public bool CanCancel => _cts != null && !_cts.IsCancellationRequested;

    /// <summary>Gets the cancellation token for the current operation, or <see cref="CancellationToken.None"/> if no operation is running.</summary>
    public CancellationToken Token => _cts?.Token ?? CancellationToken.None;

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
        await RunAsync((_, token) => operation(token));
    }

    public async Task RunAsync(Func<IProgress<AgentAuditProgress>, CancellationToken, Task> operation)
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

        // Use a lightweight IProgress<T> implementation that explicitly marshals to the UI thread.
        // This keeps the dispatcher hop in one obvious place and avoids relying on a captured
        // SynchronizationContext, which may be missing if RunAsync is invoked off the UI thread.
        var progress = new UiThreadProgress<AgentAuditProgress>(p => RunOnUiThread(() => _onProgress(p)));

        try
        {
            await operation(progress, token);
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

/// <summary>
/// A minimal <see cref="IProgress<T>"/> implementation that invokes the supplied handler directly.
/// Combine with an explicit <see cref="Dispatcher.UIThread"/> post (as in <see cref="AgentOperationRunner"/>)
/// when the handler must run on the UI thread.
/// </summary>
internal sealed class UiThreadProgress<T> : IProgress<T>
{
    private readonly Action<T> _handler;

    public UiThreadProgress(Action<T> handler)
    {
        _handler = handler ?? throw new ArgumentNullException(nameof(handler));
    }

    public void Report(T value) => _handler(value);
}
