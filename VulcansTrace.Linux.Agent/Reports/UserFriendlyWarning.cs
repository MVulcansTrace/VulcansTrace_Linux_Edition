using System;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Categories of user-friendly warnings derived from raw scanner output.
/// </summary>
public enum WarningCategory
{
    /// <summary>A required command or config file was not found.</summary>
    MissingTool,

    /// <summary>An operation was blocked by filesystem or system permissions.</summary>
    PermissionDenied,

    /// <summary>An expected configuration file or setting is missing.</summary>
    ConfigurationMissing,

    /// <summary>A generic scanner error that doesn't fit the other categories.</summary>
    ScannerError
}

/// <summary>
/// A cleaned, collapsed warning suitable for display in the agent chat.
/// </summary>
/// <param name="Category">The warning category.</param>
/// <param name="Message">The human-readable message.</param>
/// <param name="Count">How many raw warnings were collapsed into this message.</param>
/// <param name="Suggestion">Optional guidance for the user.</param>
public sealed record UserFriendlyWarning(
    WarningCategory Category,
    string Message,
    int Count,
    string? Suggestion = null);
