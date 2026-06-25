namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans the system's firewall configuration using iptables or nftables.
/// </summary>
public sealed class FirewallScanner : IScanner
{
    /// <inheritdoc />
    public string Name => "Firewall";

    private static readonly TimeSpan FirewallProbeTimeout = TimeSpan.FromSeconds(10);

    // How iptables/nftables are probed. Defaults to the real ScannerCommandRunner; an internal ctor
    // lets tests inject canned results so the iptables→nftables control flow can be exercised without
    // spawning processes or mutating the process-global PATH.
    private readonly FirewallCommandFunc _runCommand;

    /// <summary>Creates a scanner that probes the real iptables/nftables backends.</summary>
    public FirewallScanner() : this(RunViaRunner) { }

    /// <summary>
    /// Creates a scanner that probes backends via <paramref name="runCommand"/>. Intended for tests
    /// that need to drive the iptables/nftables selection logic deterministically.
    /// </summary>
    internal FirewallScanner(FirewallCommandFunc runCommand)
    {
        _runCommand = runCommand ?? throw new ArgumentNullException(nameof(runCommand));
    }

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        // Probe iptables first and only fall back to nftables when iptables is missing or returns
        // no usable data. This avoids spawning a privileged nft probe on the common iptables-based
        // host; each probe is bounded by FirewallProbeTimeout so a hanging backend can't stall the
        // scan (worst case: the iptables timeout, then nft).
        var (iptablesOutput, iptablesError, iptablesOk) =
            await _runCommand("iptables", new[] { "-L", "-n", "-v" }, cancellationToken, FirewallProbeTimeout);

        var iptablesStatus = DataSourceCapability.FromCommandResult(iptablesOk, iptablesOutput, iptablesError);
        builder.AddCapability(new DataSourceCapability { SourceName = "iptables", Status = iptablesStatus, Detail = iptablesError, Command = "iptables -L -n -v" });

        if (iptablesStatus == CapabilityStatus.Available && !string.IsNullOrWhiteSpace(iptablesOutput))
        {
            builder.AddCapability(new DataSourceCapability { SourceName = "nftables", Status = CapabilityStatus.Unknown, Detail = "Not checked because iptables returned usable data.", Command = "nft list ruleset" });
            builder.FirewallRaw = iptablesOutput;
            builder.FirewallActive = true;
            ParseIptables(iptablesOutput, builder);
            return;
        }

        var (nftOutput, nftError, nftOk) =
            await _runCommand("nft", new[] { "list", "ruleset" }, cancellationToken, FirewallProbeTimeout);

        var nftStatus = DataSourceCapability.FromCommandResult(nftOk, nftOutput, nftError);
        builder.AddCapability(new DataSourceCapability { SourceName = "nftables", Status = nftStatus, Detail = nftError, Command = "nft list ruleset" });
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

            var rule = ParseNftablesRuleLine(line, currentChain);
            if (rule != null)
            {
                builder.AddFirewallRule(rule);
            }
        }
    }

    internal static FirewallRule? ParseNftablesRuleLine(string line, string chain)
    {
        if (line.StartsWith("type ", StringComparison.OrdinalIgnoreCase) ||
            line.StartsWith("policy ", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var tokens = line.Split(new[] { ' ', '\t', ',', ';', '{', '}', '(', ')' }, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0)
            return null;

        var actionTokens = new[] { "accept", "drop", "reject", "log", "jump", "goto" };
        string? target = null;
        for (var i = tokens.Length - 1; i >= 0; i--)
        {
            if (actionTokens.Any(a => tokens[i].Equals(a, StringComparison.OrdinalIgnoreCase)))
            {
                target = tokens[i];
                break;
            }
        }

        if (target == null)
            return null;

        var protocol = tokens.Any(t => t.Equals("tcp", StringComparison.OrdinalIgnoreCase))
            ? "tcp"
            : tokens.Any(t => t.Equals("udp", StringComparison.OrdinalIgnoreCase))
                ? "udp"
                : "all";

        return new FirewallRule
        {
            Chain = chain,
            RawLine = line,
            Target = target,
            Protocol = protocol,
            Source = ReadNftablesAddress(tokens, "saddr") ?? "0.0.0.0/0",
            Destination = ReadNftablesAddress(tokens, "daddr") ?? "0.0.0.0/0",
            DestinationPort = ReadNftablesPort(tokens)
        };
    }

    private static string? ReadNftablesAddress(string[] tokens, string key)
    {
        for (var i = 0; i + 1 < tokens.Length; i++)
        {
            if (tokens[i].Equals(key, StringComparison.OrdinalIgnoreCase))
                return tokens[i + 1].Trim('"');
        }

        return null;
    }

    private static string? ReadNftablesPort(string[] tokens)
    {
        for (var i = 0; i + 1 < tokens.Length; i++)
        {
            if (!tokens[i].Equals("dport", StringComparison.OrdinalIgnoreCase))
                continue;

            var candidate = tokens[i + 1].Trim('"');
            return int.TryParse(candidate, out _) ? candidate : null;
        }

        return null;
    }

    private static Task<(string? Stdout, string? Stderr, bool Success)> RunViaRunner(
        string fileName, IReadOnlyList<string> args, CancellationToken ct, TimeSpan? timeout)
        => ScannerCommandRunner.RunAsync(fileName, args, ct, timeout);
}

/// <summary>
/// Runs a firewall-backend probe command, returning its captured (stdout, stderr, exit-success).
/// Mirrors <see cref="ScannerCommandRunner.RunAsync"/>; defaulted there in production and injected
/// from tests.
/// </summary>
internal delegate Task<(string? Stdout, string? Stderr, bool Success)> FirewallCommandFunc(
    string fileName, IReadOnlyList<string> args, CancellationToken cancellationToken, TimeSpan? timeout);
