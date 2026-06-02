using System;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

internal sealed class AgentOperationRunner : IDisposable
{
    private readonly Action<bool> _setBusy;
    private readonly Action _clearPrivilegeWarning;
    private readonly Action<string, bool> _addAgentMessage;
    private CancellationTokenSource? _cts;

    public AgentOperationRunner(
        Action<bool> setBusy,
        Action clearPrivilegeWarning,
        Action<string, bool> addAgentMessage)
    {
        _setBusy = setBusy ?? throw new ArgumentNullException(nameof(setBusy));
        _clearPrivilegeWarning = clearPrivilegeWarning ?? throw new ArgumentNullException(nameof(clearPrivilegeWarning));
        _addAgentMessage = addAgentMessage ?? throw new ArgumentNullException(nameof(addAgentMessage));
    }

    public bool CanCancel => _cts != null && !_cts.IsCancellationRequested;

    public void Cancel()
    {
        _cts?.Cancel();
    }

    public async Task RunAsync(Func<CancellationToken, Task> operation)
    {
        ArgumentNullException.ThrowIfNull(operation);

        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        _setBusy(true);
        _clearPrivilegeWarning();

        try
        {
            await operation(token);
        }
        catch (OperationCanceledException)
        {
            Dispatcher.UIThread.Post(() => _addAgentMessage("Query cancelled.", true));
        }
        catch (Exception ex)
        {
            Dispatcher.UIThread.Post(() => _addAgentMessage($"Agent error: {ex.Message}", true));
        }
        finally
        {
            Dispatcher.UIThread.Post(() => _setBusy(false));
            _cts?.Dispose();
            _cts = null;
        }
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
    }
}
