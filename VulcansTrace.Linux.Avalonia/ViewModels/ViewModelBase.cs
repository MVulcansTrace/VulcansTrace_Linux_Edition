using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Avalonia;
using Avalonia.Threading;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Base class for all view models in the MVVM pattern.
/// </summary>
/// <remarks>
/// Provides common functionality for implementing INotifyPropertyChanged with thread-safe event notification.
/// </remarks>
public abstract class ViewModelBase : INotifyPropertyChanged
{
#if DEBUG
    // Application.Current is process-global, so it is not enough on its own to
    // identify a UI-owned view model (parallel unit tests can have an Avalonia app
    // active while constructing unrelated view models on worker threads). Capture
    // ownership per instance at construction instead.
    private readonly bool _enforceUiThreadAffinity =
        Application.Current is not null && Dispatcher.UIThread.CheckAccess();
#endif

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
#if DEBUG
        // UI-bound view-model state must be mutated on the UI thread: an off-thread
        // PropertyChanged raise silently desyncs bindings (the Live Stream end/stop
        // bug). Fail loud in Debug/test so the bug is caught at write-time; Release
        // builds skip the check (structural marshaling keeps them correct).
        // Instances created outside an active UI dispatcher (CLI/headless unit-test
        // hosts) are deliberately exempt; UI-owned instances keep the tripwire for
        // their entire lifetime.
        if (_enforceUiThreadAffinity && !Dispatcher.UIThread.CheckAccess())
        {
            throw new InvalidOperationException(
                $"PropertyChanged for '{propertyName}' was raised off the UI thread. " +
                "Marshal the mutation via Dispatcher.UIThread.Post/InvokeAsync or UiThread.Run.");
        }
#endif
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
