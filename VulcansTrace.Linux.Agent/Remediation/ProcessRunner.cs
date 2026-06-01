using System.Diagnostics;

namespace VulcansTrace.Linux.Agent.Remediation;

/// <summary>
/// Executes shell commands and captures their output.
/// </summary>
public interface IProcessRunner
{
    /// <summary>
    /// Executes a shell command and returns the result.
    /// </summary>
    /// <remarks>
    /// Implementations must never throw for runtime errors (e.g., process start failure, timeout).
    /// Errors are communicated via <see cref="ProcessResult.Success"/> and <see cref="ProcessResult.StdErr"/>.
    /// The only permitted exception is <see cref="OperationCanceledException"/> when <paramref name="ct"/> is triggered.
    /// </remarks>
    /// <param name="command">The command to execute.</param>
    /// <param name="timeout">Maximum time to wait for completion.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The execution result.</returns>
    Task<ProcessResult> RunAsync(string command, TimeSpan timeout, CancellationToken ct = default);
}

/// <summary>
/// Default implementation of <see cref="IProcessRunner"/> using <see cref="Process"/>.
/// </summary>
public sealed class ProcessRunner : IProcessRunner
{
    /// <inheritdoc />
    public async Task<ProcessResult> RunAsync(string command, TimeSpan timeout, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return new ProcessResult
            {
                Success = false,
                ExitCode = -1,
                StdOut = "",
                StdErr = "Command was empty."
            };
        }

        if (timeout <= TimeSpan.Zero)
        {
            return new ProcessResult
            {
                Success = false,
                ExitCode = -1,
                StdOut = "",
                StdErr = "Command timeout must be positive."
            };
        }

        using var process = new Process();
        process.StartInfo.FileName = "/bin/bash";
        process.StartInfo.RedirectStandardInput = true;
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.RedirectStandardError = true;
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.CreateNoWindow = true;

        var stdoutBuilder = new System.Text.StringBuilder();
        var stderrBuilder = new System.Text.StringBuilder();

        process.OutputDataReceived += (_, e) => { if (e.Data != null) stdoutBuilder.AppendLine(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (e.Data != null) stderrBuilder.AppendLine(e.Data); };

        try
        {
            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            // Write the command via stdin instead of -c "..." to avoid
            // shell escaping vulnerabilities (newlines, quotes, backticks, $()).
            await process.StandardInput.WriteLineAsync(command);
            process.StandardInput.Close();

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);

            try
            {
                await process.WaitForExitAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(); } catch { /* ignored */ }
                return new ProcessResult
                {
                    Success = false,
                    ExitCode = -1,
                    StdOut = stdoutBuilder.ToString(),
                    StdErr = (stderrBuilder.ToString() + "\nCommand timed out.").Trim()
                };
            }

            // Give a small grace period for async streams to finish flushing
            await Task.Delay(100, CancellationToken.None);

            var exitCode = process.ExitCode;
            return new ProcessResult
            {
                Success = exitCode == 0,
                ExitCode = exitCode,
                StdOut = stdoutBuilder.ToString().Trim(),
                StdErr = stderrBuilder.ToString().Trim()
            };
        }
        catch (Exception ex)
        {
            return new ProcessResult
            {
                Success = false,
                ExitCode = -1,
                StdOut = stdoutBuilder.ToString(),
                StdErr = $"Failed to start process: {ex.Message}"
            };
        }
    }
}

/// <summary>
/// The result of executing a shell command.
/// </summary>
public sealed record ProcessResult
{
    /// <summary>Whether the command exited with code 0.</summary>
    public required bool Success { get; init; }

    /// <summary>The process exit code.</summary>
    public required int ExitCode { get; init; }

    /// <summary>Standard output.</summary>
    public required string StdOut { get; init; }

    /// <summary>Standard error.</summary>
    public required string StdErr { get; init; }
}
