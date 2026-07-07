using System;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Generates a unique identifier for an agent chat message.
/// Each message instance gets its own GUID so pinning is per-instance, not content-based.
/// </summary>
internal static class AgentMessageFingerprint
{
    /// <summary>
    /// Creates a new GUID-based message identifier.
    /// </summary>
    public static string NewId() => Guid.NewGuid().ToString("N");
}
