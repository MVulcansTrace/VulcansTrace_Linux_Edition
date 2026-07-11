using System.ComponentModel;
using System.Text.RegularExpressions;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Produces user-safe text for display by rephrasing raw framework exceptions and scrubbing
/// the current user's home-directory prefix.
/// </summary>
/// <remarks>
/// <para>Two transforms are applied:</para>
/// <list type="bullet">
/// <item>The .NET process-start failure — the <see cref="Win32Exception"/> raised by
/// <see cref="System.Diagnostics.Process.Start"/>, whose message embeds the process's absolute
/// working directory — is rewritten to a concise, path-free "tool could not be started" message.</item>
/// <item>The current user's home directory (<see cref="Environment.SpecialFolder.UserProfile"/>) is
/// replaced with <c>~</c> wherever it appears, so same-user absolute paths never reach the UI.</item>
/// </list>
/// <para><b>Guarantee scope:</b> this does NOT scrub other absolute paths (e.g. <c>/etc</c>,
/// <c>/var</c>, another user's home, or <c>/root</c> when not running as root). Those are either
/// harmless system paths or are collapsed upstream (the <c>WarningInterpreter</c> turns
/// <c>find: '...': Permission denied</c> floods into a single summary). Any call site displaying
/// arbitrary exception text should route it through <see cref="SanitizeException"/> so these
/// transforms apply.</para>
/// </remarks>
public static partial class ErrorSanitizer
{
    // Matches the .NET process-start failure, e.g.
    // "An error occurred trying to start process 'iptables' with working directory
    // '/home/user/...'. No such file or directory" — and drops the working-directory
    // clause so no absolute local path reaches the user.
    [GeneratedRegex(
        @"An error occurred trying to start process '(?<tool>[^']+)'",
        RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex ProcessStartRegex();

    /// <summary>
    /// Sanitizes an arbitrary message for display. Null/whitespace input returns
    /// <see cref="string.Empty"/>.
    /// </summary>
    public static string Sanitize(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
            return string.Empty;

        var text = message;

        var match = ProcessStartRegex().Match(text);
        if (match.Success)
        {
            var tool = match.Groups["tool"].Value;
            return $"The tool '{tool}' could not be started (it may not be installed or is not on PATH).";
        }

        return ScrubHome(text).Trim();
    }

    /// <summary>
    /// Sanitizes an exception's message for display, collapsing framework process-start
    /// failures into a friendly, path-free message.
    /// </summary>
    public static string SanitizeException(Exception? ex)
    {
        if (ex is null)
            return string.Empty;

        return Sanitize(ex.Message);
    }

    /// <summary>
    /// Sanitizes an optional warning (e.g. a store <c>PersistenceWarning</c>) for display while
    /// preserving a <c>null</c>/whitespace input as <c>null</c>. This keeps the
    /// <c>warning ?? fallback</c> idiom intact at call sites: a healthy store still yields
    /// <c>null</c> (so the fallback message is shown), while a real warning is scrubbed of the
    /// process-start working directory and the current user's home prefix.
    /// </summary>
    public static string? SanitizeOptional(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
            return null;

        return Sanitize(message);
    }

    private static string ScrubHome(string text)
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrEmpty(home))
            return text;

        return text.Replace(home, "~", StringComparison.Ordinal);
    }
}
