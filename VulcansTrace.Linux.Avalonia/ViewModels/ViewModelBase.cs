using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Base class for all view models in the MVVM pattern.
/// </summary>
/// <remarks>
/// Provides common functionality for implementing INotifyPropertyChanged with thread-safe event notification.
/// </remarks>
public abstract class ViewModelBase : INotifyPropertyChanged
{
    /// <summary>
    /// Event raised when a property value changes.
    /// </summary>
    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>
    /// Sets a field value and raises PropertyChanged event if the value has changed.
    /// </summary>
    /// <typeparam name="T">The type of the field.</typeparam>
    /// <param name="field">Reference to the field to update.</param>
    /// <param name="value">The new value.</param>
    /// <param name="propertyName">Name of the property (automatically provided by CallerMemberName).</param>
    /// <returns>True if the value changed; otherwise, false.</returns>
    protected bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
            return false;

        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    /// <summary>
    /// Raises the PropertyChanged event for a specific property.
    /// </summary>
    /// <param name="propertyName">Name of the property (automatically provided by CallerMemberName).</param>
    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}