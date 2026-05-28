namespace VulcansTrace.Linux.Core.Logging;

/// <summary>
/// Defines the severity levels for logging operations.
/// </summary>
public enum LogLevel
{
    /// <summary>Detailed diagnostic information for debugging purposes.</summary>
    Debug,

    /// <summary>General informational messages about normal operation.</summary>
    Info,

    /// <summary>Warning messages about potentially problematic situations.</summary>
    Warning,

    /// <summary>Error messages indicating serious problems.</summary>
    Error
}

/// <summary>
/// Defines the contract for logging implementations.
/// </summary>
/// <remarks>
/// Implementations write log messages at various severity levels to different outputs (e.g., console, file, diagnostics).
/// </remarks>
public interface ILogSink
{
    /// <summary>
    /// Writes a log entry at the specified severity level.
    /// </summary>
    /// <param name="level">The severity level of the log entry.</param>
    /// <param name="message">The message to log.</param>
    /// <param name="exception">Optional exception associated with this log entry.</param>
    void Write(LogLevel level, string message, Exception? exception = null);
}

/// <summary>
/// A null logging implementation that silently discards all log messages.
/// </summary>
/// <remarks>
/// Used as the default logging sink when no logging is configured or when logging should be suppressed.
public sealed class NullLogSink : ILogSink
{
    /// <summary>
    /// Gets the singleton instance of NullLogSink.
    /// </summary>
    public static readonly NullLogSink Instance = new();

    private NullLogSink()
    {
    }

    /// <summary>
    /// Performs no operation - all log messages are discarded.
    /// </summary>
    /// <param name="level">The severity level (ignored).</param>
    /// <param name="message">The message (ignored).</param>
    /// <param name="exception">The exception (ignored).</param>
    public void Write(LogLevel level, string message, Exception? exception = null)
    {
    }
}
