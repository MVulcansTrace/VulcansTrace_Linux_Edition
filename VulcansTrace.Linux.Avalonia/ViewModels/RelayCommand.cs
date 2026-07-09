using System;
using System.Windows.Input;
using Avalonia.Input;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// A simple relay command implementation that delegates execution to provided delegates.
/// </summary>
public sealed class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    private readonly Func<object?, bool>? _canExecute;

    public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;

    public void Execute(object? parameter) => _execute(parameter);

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