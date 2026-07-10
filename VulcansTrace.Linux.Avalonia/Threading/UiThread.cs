using System;
using System.Threading.Tasks;
using Avalonia.Threading;

namespace VulcansTrace.Linux.Avalonia.Threading;

/// <summary>
/// Helpers for running work on the Avalonia UI thread. When the caller is already
/// on the UI thread the work runs inline (synchronously, zero behavior change);
/// otherwise it is marshaled via <see cref="Dispatcher.UIThread"/>. Use these
/// instead of hand-rolling the <c>CheckAccess</c> fast-path so UI-bound view-model
/// mutations are always raised on the UI thread.
/// </summary>
public static class UiThread
{
    /// <summary>
    /// Runs <paramref name="action"/> on the UI thread. Inline when already there,
    /// otherwise posted (fire-and-forget) to the UI dispatcher.
    /// </summary>
    public static void Run(Action action)
    {
        if (Dispatcher.UIThread.CheckAccess())
            action();
        else
            Dispatcher.UIThread.Post(action);
    }

    /// <summary>
    /// Runs <paramref name="action"/> on the UI thread and awaits its result.
    /// Inline when already there, otherwise invoked (awaited) on the UI dispatcher.
    /// </summary>
    public static Task<T> InvokeAsync<T>(Func<Task<T>> action)
    {
        if (Dispatcher.UIThread.CheckAccess())
            return action();
        return Dispatcher.UIThread.InvokeAsync(action);
    }

    /// <summary>
    /// Runs <paramref name="action"/> on the UI thread and awaits its completion.
    /// Inline when already there, otherwise invoked (awaited) on the UI dispatcher
    /// at Normal priority. Use this (not <see cref="Run"/>, which is fire-and-forget)
    /// when the caller must wait for the UI work to finish before proceeding.
    /// </summary>
    public static async Task InvokeAsync(Action action)
    {
        if (Dispatcher.UIThread.CheckAccess())
        {
            action();
            return;
        }

        await Dispatcher.UIThread.InvokeAsync(action);
    }
}
