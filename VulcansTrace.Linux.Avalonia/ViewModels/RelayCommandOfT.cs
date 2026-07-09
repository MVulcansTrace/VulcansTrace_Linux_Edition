using System;
using System.Windows.Input;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// A generic relay command implementation that delegates execution to provided delegates.
/// </summary>
public sealed class RelayCommand<T> : ICommand
{
    private readonly Action<T?> _execute;
    private readonly Func<T?, bool>? _canExecute;

    public RelayCommand(Action<T?> execute, Func<T?, bool>? canExecute = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter is T t ? t : default) ?? true;

    public void Execute(object? parameter) => _execute(parameter is T t ? t : default);

    private EventHandler? _canExecuteChanged;

    public event EventHandler? CanExecuteChanged
    {
        add
        {
            _canExecuteChanged += value;
            value?.Invoke(this, EventArgs.Empty);
        }
        remove => _canExecuteChanged -= value;
    }

    public void RaiseCanExecuteChanged()
    {
        _canExecuteChanged?.Invoke(this, EventArgs.Empty);
    }
}
