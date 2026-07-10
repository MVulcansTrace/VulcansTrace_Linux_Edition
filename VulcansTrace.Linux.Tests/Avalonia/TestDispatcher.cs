using Avalonia.Threading;

namespace VulcansTrace.Linux.Tests.Avalonia;

/// <summary>
/// Shared UI-dispatcher test helpers, replacing the per-class <c>FlushDispatcher()</c>
/// copies that previously lived in each Avalonia test file. Import the members with
/// <c>using static VulcansTrace.Linux.Tests.Avalonia.TestDispatcher;</c> so call sites
/// read as plain <c>FlushDispatcher()</c>.
/// </summary>
internal static class TestDispatcher
{
    /// <summary>Pumps the UI dispatcher until its queued jobs are drained.</summary>
    public static void FlushDispatcher() => Dispatcher.UIThread.RunJobs();
}
