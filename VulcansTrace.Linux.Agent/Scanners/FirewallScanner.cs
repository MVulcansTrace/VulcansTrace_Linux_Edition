using System.Diagnostics;

namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans the system's firewall configuration using iptables or nftables.
/// </summary>
public sealed class FirewallScanner : IScanner
{
    /// <inheritdoc />
    public string Name => "Firewall";

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        // Try iptables first, then nftables
        var (iptablesOutput, iptablesError, iptablesOk) =
            await RunCommandAsync("iptables", new[] { "-L", "-n", "-v" }, cancellationToken);

        var iptablesStatus = DataSourceCapability.FromCommandResult(iptablesOk, iptablesOutput, iptablesError);
        builder.AddCapability(new DataSourceCapability { SourceName = "iptables", Status = iptablesStatus, Detail = iptablesError });
        if (iptablesStatus == CapabilityStatus.Available && !string.IsNullOrWhiteSpace(iptablesOutput))
        {
            builder.AddCapability(new DataSourceCapability { SourceName = "nftables", Status = CapabilityStatus.Unknown, Detail = "Not checked because iptables returned usable data." });
            builder.FirewallRaw = iptablesOutput;
            builder.FirewallActive = true;
            ParseIptables(iptablesOutput, builder);
            return;
        }

        var (nftOutput, nftError, nftOk) =
            await RunCommandAsync("nft", new[] { "list", "ruleset" }, cancellationToken);

        var nftStatus = DataSourceCapability.FromCommandResult(nftOk, nftOutput, nftError);
        builder.AddCapability(new DataSourceCapability { SourceName = "nftables", Status = nftStatus, Detail = nftError });
        if (nftStatus == CapabilityStatus.Available && !string.IsNullOrWhiteSpace(nftOutput))
        {
            builder.FirewallRaw = nftOutput;
            builder.FirewallActive = true;
            ParseNftables(nftOutput, builder);
            return;
        }

        // No firewall detected
        builder.FirewallActive = false;

        if (!iptablesOk && !string.IsNullOrWhiteSpace(iptablesError))
        {
            builder.AddWarning($"Firewall scan: iptables failed ({iptablesError}).");
        }
        else if (!nftOk && !string.IsNullOrWhiteSpace(nftError))
        {
            builder.AddWarning($"Firewall scan: nftables failed ({nftError}).");
        }
    }

    internal static void ParseIptables(string output, ScanDataBuilder builder)
    {
        var lines = output.Split('\n');
        string? currentChain = null;

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line))
                continue;

            // Chain header: "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)"
            if (line.StartsWith("Chain "))
            {
                var chainEnd = line.IndexOf(' ', 6);
                currentChain = chainEnd > 0 ? line.Substring(6, chainEnd - 6) : line.Substring(6);
                continue;
            }

            // Skip header line: "pkts bytes target ..."
            if (line.StartsWith("pkts") || line.StartsWith("target"))
                continue;

            if (currentChain == null)
                continue;

            var rule = ParseIptablesRuleLine(line, currentChain);
            if (rule != null)
                builder.AddFirewallRule(rule);
        }
    }

    internal static FirewallRule? ParseIptablesRuleLine(string line, string chain)
    {
        var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3)
            return null;

        // Format: pkts bytes target prot opt in out source destination [options...]
        var target = parts[2];
        var protocol = parts.Length > 3 ? parts[3] : "all";
        var inInterface = parts.Length > 5 ? parts[5].Replace("*", "") : null;
        var outInterface = parts.Length > 6 ? parts[6].Replace("*", "") : null;
        var source = parts.Length > 7 ? parts[7] : "0.0.0.0/0";
        var destination = parts.Length > 8 ? parts[8] : "0.0.0.0/0";

        string? destPort = null;
        string? stateMatch = null;

        for (var i = 9; i < parts.Length; i++)
        {
            if (parts[i] == "dpt:" && i + 1 < parts.Length)
            {
                destPort = parts[i + 1];
            }
            else if (parts[i] == "dpts:" && i + 1 < parts.Length)
            {
                destPort = parts[i + 1];
            }
            else if ((parts[i] == "--dport" || parts[i] == "dpt") && i + 1 < parts.Length)
            {
                destPort = parts[i + 1];
            }
            else if (parts[i].StartsWith("dpt:", StringComparison.OrdinalIgnoreCase))
            {
                destPort = parts[i].Substring(4);
            }
            else if (parts[i].StartsWith("dpts:", StringComparison.OrdinalIgnoreCase))
            {
                destPort = parts[i].Substring(5);
            }
            else if ((parts[i] == "--state" || parts[i] == "state") && i + 1 < parts.Length)
            {
                stateMatch = parts[i + 1];
            }
        }

        return new FirewallRule
        {
            Chain = chain,
            Target = target,
            Protocol = protocol,
            Source = source,
            Destination = destination,
            DestinationPort = destPort,
            InInterface = inInterface,
            OutInterface = outInterface,
            StateMatch = stateMatch,
            RawLine = line
        };
    }

    internal static void ParseNftables(string output, ScanDataBuilder builder)
    {
        // Basic nftables parsing — extract rule lines with chain context
        var lines = output.Split('\n');
        string? currentChain = null;

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line))
                continue;

            // chain ingress { ... }
            if (line.StartsWith("chain "))
            {
                var parts = line.Split(new[] { ' ', '{' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 1)
                    currentChain = parts[1];
                continue;
            }

            if (currentChain == null)
                continue;

            // Simple heuristic: lines starting with common actions
            var actions = new[] { "accept", "drop", "reject", "log", "counter", "jump", "goto" };
            var firstWord = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (firstWord != null && actions.Any(a => line.Contains(a, StringComparison.OrdinalIgnoreCase)))
            {
                builder.AddFirewallRule(new FirewallRule
                {
                    Chain = currentChain,
                    RawLine = line,
                    Target = firstWord,
                    Protocol = "all",
                    Source = "0.0.0.0/0",
                    Destination = "0.0.0.0/0"
                });
            }
        }
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
