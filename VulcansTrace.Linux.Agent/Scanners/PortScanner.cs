using System.Diagnostics;
using System.Globalization;

namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans for open/listening ports using the <c>ss</c> command (preferred) or <c>netstat</c> fallback.
/// </summary>
public sealed class PortScanner : IScanner
{
    /// <inheritdoc />
    public string Name => "Port";

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var (output, error, ok) = await RunCommandAsync("ss", new[] { "-tulnp" }, cancellationToken);
        var ssStatus = DataSourceCapability.FromCommandResult(ok, output, error);
        var permissionLimited = ssStatus == CapabilityStatus.PermissionLimited;
        builder.AddCapability(new DataSourceCapability { SourceName = "ss", Status = ssStatus, Detail = error });

        if (ssStatus != CapabilityStatus.Available || string.IsNullOrWhiteSpace(output))
        {
            (output, error, ok) = await RunCommandAsync("netstat", new[] { "-tulnp" }, cancellationToken);
            var netstatStatus = DataSourceCapability.FromCommandResult(ok, output, error);
            permissionLimited |= netstatStatus == CapabilityStatus.PermissionLimited;
            builder.AddCapability(new DataSourceCapability { SourceName = "netstat", Status = netstatStatus, Detail = error });
        }
        else
        {
            builder.AddCapability(new DataSourceCapability { SourceName = "netstat", Status = CapabilityStatus.Unknown });
        }

        if (permissionLimited && (!ok || string.IsNullOrWhiteSpace(output) || DataSourceCapability.ContainsPermissionDenied(output)))
        {
            builder.AddWarning("Port scan skipped: permission denied. Run with elevated privileges to see process names.");
            return;
        }

        if (!ok || string.IsNullOrWhiteSpace(output))
        {
            builder.AddWarning($"Port scan skipped: neither 'ss' nor 'netstat' is available. {error}");
            return;
        }

        if (DataSourceCapability.ContainsPermissionDenied(output))
        {
            builder.AddWarning("Port scan skipped: permission denied. Run with elevated privileges to see process names.");
            return;
        }

        ParseOutput(output, builder);
    }

    internal static void ParseOutput(string output, ScanDataBuilder builder)
    {
        var lines = output.Split('\n');
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line))
                continue;

            // Skip header lines
            if (line.StartsWith("Netid") || line.StartsWith("Proto") || line.StartsWith("Active"))
                continue;

            var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 5)
                continue;

            // ss format: Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
            // netstat format: Proto  Recv-Q  Send-Q  Local Address  Foreign Address  State  PID/Program
            // Heuristic: in ss format parts[1] is a state string; in netstat it's a number (Recv-Q).
            var isSsFormat = parts[0] is "tcp" or "udp" or "tcp6" or "udp6"
                && !int.TryParse(parts[1], out _);
            var proto = parts[0];
            var stateIndex = isSsFormat ? 1 : 5;
            var localAddrIndex = isSsFormat ? 4 : 3;
            var processIndex = 6;

            if (parts.Length <= localAddrIndex)
                continue;

            var localAddrPart = parts[localAddrIndex];
            var (localAddress, localPort) = ParseAddressPort(localAddrPart);

            string? processName = null;
            int? processId = null;
            if (parts.Length > processIndex)
            {
                (processName, processId) = ParseProcess(parts[processIndex]);
            }

            var state = parts.Length > stateIndex ? parts[stateIndex] : "UNKNOWN";

            builder.AddOpenPort(new OpenPort
            {
                Protocol = proto,
                LocalAddress = localAddress,
                LocalPort = localPort,
                State = state,
                ProcessName = processName,
                ProcessId = processId
            });
        }
    }

    internal static (string Address, int Port) ParseAddressPort(string input)
    {
        // Handle IPv6 [::]:22 and IPv4 0.0.0.0:22
        var lastColon = input.LastIndexOf(':');
        if (lastColon < 0)
            return (input, 0);

        var address = input.Substring(0, lastColon).TrimStart('[').TrimEnd(']');
        var portStr = input.Substring(lastColon + 1);
        if (int.TryParse(portStr, NumberStyles.None, CultureInfo.InvariantCulture, out var port))
            return (address, port);

        return (input, 0);
    }

    internal static (string? Name, int? Pid) ParseProcess(string input)
    {
        // Format: "users:(("sshd",pid=1234,fd=3))" or "1234/sshd"
        if (input.Contains("pid="))
        {
            var pidStart = input.IndexOf("pid=") + 4;
            var pidEnd = input.IndexOf(',', pidStart);
            var pidStr = pidEnd > 0 ? input.Substring(pidStart, pidEnd - pidStart) : input.Substring(pidStart).TrimEnd(')');
            if (int.TryParse(pidStr, out var pid))
                return (null, pid);
        }

        var slashIndex = input.IndexOf('/');
        if (slashIndex > 0)
        {
            var pidStr = input.Substring(0, slashIndex);
            var name = input.Substring(slashIndex + 1);
            if (int.TryParse(pidStr, out var pid))
                return (name, pid);
        }

        return (null, null);
    }

    private static async Task<(string? Stdout, string? Stderr, bool Success)> RunCommandAsync(
        string fileName, string[] args, CancellationToken ct)
    {
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

            await using (ct.Register(() =>
            {
                try { process.Kill(); } catch { /* ignore */ }
            }))
            {
                var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
                var stderrTask = process.StandardError.ReadToEndAsync(ct);
                var exitTask = process.WaitForExitAsync(ct);
                await Task.WhenAll(stdoutTask, stderrTask, exitTask);
                var success = process.ExitCode == 0;
                return (stdoutTask.Result, stderrTask.Result, success);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return (null, ex.Message, false);
        }
    }
}
