using System;

namespace VulcansTrace.Linux.Avalonia.Services;

/// <summary>
/// Deterministic export-path override for isolated desktop scenarios.
/// </summary>
/// <remarks>
/// The override requires a scenario identity so a stale export variable from
/// a normal launch cannot silently redirect user exports. When no override
/// is active the interactive save dialog is used.
/// </remarks>
public static class ScenarioExport
{
    /// <summary>
    /// Returns the scenario-driven export path, or <c>null</c> to use the
    /// interactive save dialog.
    /// </summary>
    public static string? ResolvePath()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("VT_SCENARIO_ID")))
            return null;

        return Environment.GetEnvironmentVariable("VT_UI_TEST_EXPORT_PATH");
    }
}
