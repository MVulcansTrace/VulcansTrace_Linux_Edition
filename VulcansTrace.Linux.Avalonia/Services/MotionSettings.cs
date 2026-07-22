using System;

namespace VulcansTrace.Linux.Avalonia.Services;

/// <summary>
/// Centralizes whether optional interface motion should run.
/// </summary>
/// <remarks>
/// Machine mode disables motion so automation observes settled UI. Users can
/// opt out of non-essential motion with <c>VT_REDUCED_MOTION=1</c>.
/// </remarks>
public static class MotionSettings
{
    /// <summary>Gets whether optional motion is enabled for this process.</summary>
    public static bool IsEnabled => !MachineMode.IsEnabled && !IsTruthy(
        Environment.GetEnvironmentVariable("VT_REDUCED_MOTION"));

    private static bool IsTruthy(string? value) => value?.Trim().ToLowerInvariant() is
        "1" or "true" or "yes" or "on";
}
