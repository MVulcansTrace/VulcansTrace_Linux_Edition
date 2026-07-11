using System.Diagnostics;
using System.Text;
using VulcansTrace.Linux.Agent.Reports;

namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Runs short-lived scanner commands with consistent timeout, cancellation, and output limits.
/// </summary>
internal static class ScannerCommandRunner
{
    private const int DefaultMaxOutputChars = 1_048_576;
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    public static async Task<(string? Stdout, string? Stderr, bool Success)> RunAsync(
        string fileName,
        IReadOnlyList<string> args,
        CancellationToken ct,
        TimeSpan? timeout = null,
        int maxOutputChars = DefaultMaxOutputChars)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);

        var commandTimeout = timeout ?? DefaultTimeout;
        if (commandTimeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(timeout), "Command timeout must be positive.");
        if (maxOutputChars <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxOutputChars), "Maximum output size must be positive.");

        ct.ThrowIfCancellationRequested();

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            foreach (var arg in args)
                psi.ArgumentList.Add(arg);

            using var process = Process.Start(psi);
            if (process == null)
                return (null, $"Failed to start '{fileName}'.", false);

            var stdout = new StringBuilder();
            var stderr = new StringBuilder();
            var stdoutChars = 0;
            var stderrChars = 0;
            var stdoutTruncated = false;
            var stderrTruncated = false;
            var outputLock = new object();

            process.OutputDataReceived += (_, e) =>
            {
                if (e.Data != null)
                    AppendBounded(stdout, e.Data, ref stdoutChars, ref stdoutTruncated, maxOutputChars, outputLock);
            };
            process.ErrorDataReceived += (_, e) =>
            {
                if (e.Data != null)
                    AppendBounded(stderr, e.Data, ref stderrChars, ref stderrTruncated, maxOutputChars, outputLock);
            };

            await using (ct.Register(() => KillProcess(process)))
            {
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(commandTimeout);

                try
                {
                    await process.WaitForExitAsync(timeoutCts.Token);
                    await Task.Delay(100, CancellationToken.None);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    KillProcess(process);
                    AppendLine(stderr, $"Command timed out after {commandTimeout.TotalSeconds:0.#} seconds.", outputLock);
                    return (stdout.ToString().Trim(), stderr.ToString().Trim(), false);
                }

                ct.ThrowIfCancellationRequested();

                if (stdoutTruncated)
                    AppendLine(stderr, $"Standard output was truncated after {maxOutputChars} characters.", outputLock);
                if (stderrTruncated)
                    AppendLine(stderr, $"Standard error was truncated after {maxOutputChars} characters.", outputLock);

                return (stdout.ToString().Trim(), stderr.ToString().Trim(), process.ExitCode == 0);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return (null, ErrorSanitizer.Sanitize(ex.Message), false);
        }
    }

    private static void KillProcess(Process process)
    {
        try { process.Kill(entireProcessTree: true); } catch { /* ignore */ }
    }

    private static void AppendBounded(
        StringBuilder builder,
        string line,
        ref int currentLength,
        ref bool truncated,
        int maxChars,
        object syncRoot)
    {
        lock (syncRoot)
        {
            if (currentLength >= maxChars)
            {
                truncated = true;
                return;
            }

            var text = line + Environment.NewLine;
            var remaining = maxChars - currentLength;
            if (text.Length > remaining)
            {
                builder.Append(text.AsSpan(0, remaining));
                currentLength = maxChars;
                truncated = true;
                return;
            }

            builder.Append(text);
            currentLength += text.Length;
        }
    }

    private static void AppendLine(StringBuilder builder, string line, object syncRoot)
    {
        lock (syncRoot)
        {
            if (builder.Length > 0)
                builder.AppendLine();
            builder.Append(line);
        }
    }
}
