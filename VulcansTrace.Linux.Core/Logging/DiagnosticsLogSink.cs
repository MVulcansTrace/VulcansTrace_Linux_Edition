using System.Diagnostics;

namespace VulcansTrace.Linux.Core.Logging;

/// <summary>
/// A logging implementation that writes to System.Diagnostics.Trace.
/// </summary>
/// <remarks>
/// Logs are written using Trace.WriteLine with a format of "[LEVEL] message" and optionally include exception details.
public sealed class DiagnosticsLogSink : ILogSink
{
    /// <summary>
    /// Writes a log entry to System.Diagnostics.Trace.
    /// </summary>
    /// <param name="level">The severity level of the log entry.</param>
    /// <param name="message">The message to log.</param>
    /// <param name="exception">Optional exception to include with the message.</param>
    public void Write(LogLevel level, string message, Exception? exception = null)
    {
        var detail = exception == null
            ? message
            : $"{message}{Environment.NewLine}{exception}";
        Trace.WriteLine($"[{level}] {detail}");
    }
}
