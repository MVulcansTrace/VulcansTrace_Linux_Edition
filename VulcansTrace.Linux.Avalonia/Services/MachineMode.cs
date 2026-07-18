using System;

namespace VulcansTrace.Linux.Avalonia.Services;

/// <summary>
/// Central gate for <c>VT_MACHINE_MODE</c>: when enabled, the app renders its
/// deterministic variant so vision-driven harnesses observe a stable UI —
/// no informational modal dialogs and no content-transition animation.
/// Views, automation ids, commands, and state transitions are unchanged;
/// only presentation is affected.
/// </summary>
/// <remarks>
/// Same philosophy as the <c>VT_SCENARIO_ID</c> export hook. This is the
/// first centralized env helper in the app: the scattered <c>VT_*</c> reads
/// (EvidenceViewModel, AgentViewModel, SecurityAgent, …) should migrate here
/// over time. The value is cached at first read; tests reset the cache via
/// <see cref="ResetForTests"/> after mutating the environment.
/// </remarks>
public static class MachineMode
{
    private static bool? _enabled;

    /// <summary>True when VT_MACHINE_MODE holds a truthy value (1/true/yes).</summary>
    public static bool IsEnabled
    {
        get
        {
            _enabled ??= IsTruthy(Environment.GetEnvironmentVariable("VT_MACHINE_MODE"));
            return _enabled.Value;
        }
    }

    internal static void ResetForTests() => _enabled = null;

    private static bool IsTruthy(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;
        var trimmed = value.Trim();
        return trimmed.Equals("1", StringComparison.OrdinalIgnoreCase)
            || trimmed.Equals("true", StringComparison.OrdinalIgnoreCase)
            || trimmed.Equals("yes", StringComparison.OrdinalIgnoreCase);
    }
}
