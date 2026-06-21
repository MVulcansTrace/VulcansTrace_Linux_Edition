using System.Globalization;

namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans network interfaces, routes, and active connections using <c>ip</c>.
/// </summary>
public sealed class NetworkScanner : IScanner
{
    /// <inheritdoc />
    public string Name => "Network";

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var (addrOutput, addrError, addrOk) = await RunCommandAsync("ip", new[] { "addr" }, cancellationToken);
        var (routeOutput, routeError, routeOk) = await RunCommandAsync("ip", new[] { "route" }, cancellationToken);
        var (connOutput, connError, connOk) = await RunCommandAsync("ss", new[] { "-tunap" }, cancellationToken);

        var addrStatus = DataSourceCapability.FromCommandResult(addrOk, addrOutput, addrError);
        builder.AddCapability(new DataSourceCapability { SourceName = "ip addr", Status = addrStatus, Detail = addrError, Command = "ip addr" });

        if (addrOk && !string.IsNullOrWhiteSpace(addrOutput))
            ParseAddresses(addrOutput, builder);
        else
            builder.AddWarning($"Network interface scan skipped: 'ip addr' failed. {addrError}");

        var routeStatus = DataSourceCapability.FromCommandResult(routeOk, routeOutput, routeError);
        builder.AddCapability(new DataSourceCapability { SourceName = "ip route", Status = routeStatus, Detail = routeError, Command = "ip route" });

        if (routeOk && !string.IsNullOrWhiteSpace(routeOutput))
            ParseRoutes(routeOutput, builder);
        else
            builder.AddWarning($"Route scan skipped: 'ip route' failed. {routeError}");

        var connStatus = DataSourceCapability.FromCommandResult(connOk, connOutput, connError);
        builder.AddCapability(new DataSourceCapability { SourceName = "ss connections", Status = connStatus, Detail = connError, Command = "ss -tunap" });

        if (connOk && !string.IsNullOrWhiteSpace(connOutput) && !DataSourceCapability.ContainsPermissionDenied(connOutput))
            ParseConnections(connOutput, builder);
        else if (DataSourceCapability.ContainsPermissionDenied(connOutput) || DataSourceCapability.ContainsPermissionDenied(connError))
            builder.AddWarning("Connection scan skipped: permission denied.");
        else
            builder.AddWarning($"Connection scan skipped: 'ss' failed. {connError}");
    }

    internal static void ParseAddresses(string output, ScanDataBuilder builder)
    {
        var lines = output.Split('\n');
        NetworkInterface? current = null;
        var addresses = new List<string>();

        foreach (var rawLine in lines)
        {
            if (string.IsNullOrWhiteSpace(rawLine))
                continue;

            // Interface header lines are NOT indented (column 0).
            // Detail lines (inet, inet6, link/ether) ARE indented with leading spaces.
            // We must check the RAW line before trimming, otherwise MAC/IP lines
            // that contain ':' can be mistaken for headers.
            var isHeader = rawLine.Length > 0 && rawLine[0] != ' ' && rawLine[0] != '\t';
            var hasColon = rawLine.Contains(':');

            if (isHeader && hasColon)
            {
                if (current != null)
                {
                    builder.AddNetworkInterface(current with { Addresses = addresses.ToArray() });
                }

                var colonIndex = rawLine.IndexOf(':');
                var name = colonIndex > 0
                    ? rawLine.Substring(colonIndex + 1).Trim().Split(' ')[0].TrimEnd(':')
                    : "unknown";
                var isUp = rawLine.Contains("UP");

                current = new NetworkInterface
                {
                    Name = name,
                    IsUp = isUp,
                    MacAddress = null
                };
                addresses.Clear();
                continue;
            }

            if (current == null)
                continue;

            var trimmed = rawLine.Trim();

            // MAC address: "    link/ether 00:11:22:33:44:55 ..."
            if (trimmed.Contains("link/ether"))
            {
                var parts = trimmed.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 1)
                {
                    current = current with { MacAddress = parts[1] };
                }
                continue;
            }

            // IP address: "    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0"
            if (trimmed.Contains("inet ") || trimmed.Contains("inet6 "))
            {
                var parts = trimmed.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                for (var i = 0; i < parts.Length - 1; i++)
                {
                    if ((parts[i] == "inet" || parts[i] == "inet6") && i + 1 < parts.Length)
                    {
                        addresses.Add(parts[i + 1]);
                    }
                }
            }
        }

        if (current != null)
        {
            builder.AddNetworkInterface(current with { Addresses = addresses.ToArray() });
        }
    }

    internal static void ParseRoutes(string output, ScanDataBuilder builder)
    {
        var lines = output.Split('\n');
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line))
                continue;

            var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
                continue;

            // default via 192.168.1.1 dev eth0 proto dhcp metric 100
            // 192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.10 metric 100
            var destination = parts[0];
            string? gateway = null;
            var iface = "";
            var flags = "";

            for (var i = 0; i < parts.Length - 1; i++)
            {
                if (parts[i] == "via" && i + 1 < parts.Length)
                    gateway = parts[i + 1];
                else if (parts[i] == "dev" && i + 1 < parts.Length)
                    iface = parts[i + 1];
                else if (parts[i] == "proto" && i + 1 < parts.Length)
                    flags = parts[i + 1];
            }

            builder.AddRoute(new RouteEntry
            {
                Destination = destination,
                Gateway = gateway,
                Interface = iface,
                Flags = flags
            });
        }
    }

    internal static void ParseConnections(string output, ScanDataBuilder builder)
    {
        var lines = output.Split('\n');
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line))
                continue;

            if (line.StartsWith("Netid") || line.StartsWith("State"))
                continue;

            var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 6)
                continue;

            // ss -tunap format
            var proto = parts[0];
            var state = parts[1];
            var (localAddr, localPort) = ParseAddressPort(parts[4]);
            var (remoteAddr, remotePort) = ParseAddressPort(parts[5]);

            string? processName = null;
            if (parts.Length > 6)
            {
                var procPart = parts[6];
                if (procPart.Contains('/'))
                {
                    processName = procPart.Substring(procPart.IndexOf('/') + 1).TrimEnd(')');
                }
                else if (procPart.Contains("pid="))
                {
                    // ss users:(("name",pid=N,fd=M)) format — look for quoted name
                    var quoteStart = procPart.IndexOf('"');
                    var quoteEnd = procPart.IndexOf('"', quoteStart + 1);
                    if (quoteStart >= 0 && quoteEnd > quoteStart)
                    {
                        processName = procPart.Substring(quoteStart + 1, quoteEnd - quoteStart - 1);
                    }
                }
            }

            builder.AddActiveConnection(new ActiveConnection
            {
                Protocol = proto,
                LocalAddress = localAddr,
                LocalPort = localPort,
                RemoteAddress = remoteAddr,
                RemotePort = remotePort,
                State = state,
                ProcessName = processName
            });
        }
    }

    internal static (string Address, int Port) ParseAddressPort(string input)
    {
        var lastColon = input.LastIndexOf(':');
        if (lastColon < 0)
            return (input, 0);

        var address = input.Substring(0, lastColon).TrimStart('[').TrimEnd(']');
        var portStr = input.Substring(lastColon + 1);
        if (int.TryParse(portStr, NumberStyles.None, CultureInfo.InvariantCulture, out var port))
            return (address, port);

        return (input, 0);
    }

    private static async Task<(string? Stdout, string? Stderr, bool Success)> RunCommandAsync(
        string fileName, string[] args, CancellationToken ct)
    {
        return await ScannerCommandRunner.RunAsync(fileName, args, ct);
    }
}
