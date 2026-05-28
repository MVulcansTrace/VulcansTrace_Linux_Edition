using System;
using System.Threading.Tasks;
using System.Windows.Input;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// A relay command that properly supports async execution, catching and surfacing
/// exceptions through an error handler instead of letting them escape as unhandled
/// exceptions on the UI thread.
/// </summary>
public sealed class AsyncRelayCommand : ICommand
{
    private readonly Func<object?, Task> _execute;
    private readonly Func<object?, bool>? _canExecute;
    private readonly Action<Exception>? _onException;
    private bool _isExecuting;
    private TaskCompletionSource? _executionTcs;

    public AsyncRelayCommand(
        Func<object?, Task> execute,
        Func<object?, bool>? canExecute = null,
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

        return _canExecute?.Invoke(parameter) ?? true;
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
            task = _execute(parameter);
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
