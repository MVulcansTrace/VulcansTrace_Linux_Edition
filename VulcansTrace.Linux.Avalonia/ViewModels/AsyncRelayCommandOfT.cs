using System;
using System.Threading.Tasks;
using System.Windows.Input;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// A generic relay command that supports async execution, catching and surfacing
/// exceptions through an error handler instead of letting them escape on the UI thread.
/// Re-entrant calls are ignored while an execution is in flight.
/// </summary>
public sealed class AsyncRelayCommand<T> : ICommand
{
    private readonly Func<T?, Task> _execute;
    private readonly Func<T?, bool>? _canExecute;
    private readonly Action<Exception>? _onException;
    private bool _isExecuting;
    private TaskCompletionSource? _executionTcs;

    public AsyncRelayCommand(
        Func<T?, Task> execute,
        Func<T?, bool>? canExecute = null,
        Action<Exception>? onException = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
        _onException = onException;
    }

    /// <summary>
    /// Gets a task that completes when the current execution finishes.
    /// Returns an already-completed task if nothing is running.
    /// </summary>
    public Task ExecutionTask => _executionTcs?.Task ?? Task.CompletedTask;

    public bool CanExecute(object? parameter)
    {
        if (_isExecuting)
            return false;

        return _canExecute?.Invoke(parameter is T t ? t : default) ?? true;
    }

    public void Execute(object? parameter)
    {
        if (_isExecuting)
            return;

        _isExecuting = true;
        _executionTcs = new TaskCompletionSource();
        RaiseCanExecuteChanged();

        Task task;
        try
        {
            task = _execute(parameter is T t ? t : default);
        }
        catch (Exception ex)
        {
            Complete(ex);
            return;
        }

        if (task.IsCompleted)
        {
            Complete(task);
        }
        else
        {
            task.GetAwaiter().OnCompleted(() => Complete(task));
        }
    }

    private void Complete(Task task)
    {
        if (task.IsFaulted)
        {
            var ex = task.Exception?.InnerException ?? task.Exception;
            if (ex != null)
            {
                _onException?.Invoke(ex);
            }
        }

        _isExecuting = false;
        _executionTcs?.TrySetResult();
        RaiseCanExecuteChanged();
    }

    private void Complete(Exception exception)
    {
        _onException?.Invoke(exception);
        _isExecuting = false;
        _executionTcs?.TrySetResult();
        RaiseCanExecuteChanged();
    }

    public event EventHandler? CanExecuteChanged;

    public void RaiseCanExecuteChanged()
    {
        CanExecuteChanged?.Invoke(this, EventArgs.Empty);
    }
}
