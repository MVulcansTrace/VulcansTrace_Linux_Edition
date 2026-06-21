using System;
using System.IO;

namespace VulcansTrace.Linux.Agent;

/// <summary>
/// Resolves the VulcansTrace configuration directory. Centralizing this gives the file-backed stores
/// a single source of truth and lets callers — notably tests — inject an isolated directory instead
/// of mutating the process-wide <c>XDG_CONFIG_HOME</c> environment variable.
/// </summary>
public static class VulcansTraceConfig
{
    private static string? _overrideDirectory;

    /// <summary>
    /// Process-wide override for the config base directory, intended to be set once at process
    /// startup (e.g. from the CLI <c>--config-dir</c> flag). When set, it takes precedence over
    /// <c>XDG_CONFIG_HOME</c> for resolutions that do not pass an explicit directory. Tests bypass
    /// it by always passing an explicit directory, so this static never affects the parallel suite.
    /// </summary>
    /// <remarks>
    /// This is mutable global state. It is appropriate for a single-shot CLI process, but do not
    /// rely on it in long-running server processes or when multiple commands with different config
    /// directories may run in-process. In those cases, always pass an explicit
    /// <paramref name="configDirectory"/> to <see cref="GetDirectory(string?)"/>.
    /// </remarks>
    public static string? OverrideDirectory
    {
        set => _overrideDirectory = value;
    }

    /// <summary>
    /// Returns the VulcansTrace config directory (the base config dir plus a <c>VulcansTrace</c>
    /// segment). Resolution precedence: an explicit <paramref name="configDirectory"/>, then
    /// <see cref="OverrideDirectory"/>, then <c>XDG_CONFIG_HOME</c>, then <c>~/.config</c>.
    /// </summary>
    /// <param name="configDirectory">Optional explicit base config directory (e.g. a per-test temp dir).</param>
    /// <returns>The resolved VulcansTrace config directory path (not yet created on disk).</returns>
    public static string GetDirectory(string? configDirectory = null)
    {
        string baseDir;
        if (!string.IsNullOrWhiteSpace(configDirectory))
        {
            baseDir = configDirectory!;
        }
        else if (!string.IsNullOrWhiteSpace(_overrideDirectory))
        {
            baseDir = _overrideDirectory!;
        }
        else
        {
            baseDir = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME")
                      ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        }

        return Path.Combine(baseDir, "VulcansTrace");
    }
}

