namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Aggregated data collected from all system scanners.
/// Immutable record used as input for security rule evaluation.
/// </summary>
public sealed record ScanData
{
    /// <summary>Raw firewall rule text (iptables -L -n -v or nft list ruleset).</summary>
    public string FirewallRaw { get; init; } = string.Empty;

    /// <summary>Parsed firewall rules.</summary>
    public IReadOnlyList<FirewallRule> FirewallRules { get; init; } = Array.Empty<FirewallRule>();

    /// <summary>Indicates whether a firewall (iptables or nftables) appears active.</summary>
    public bool FirewallActive { get; init; }

    /// <summary>Open/listening ports with process info.</summary>
    public IReadOnlyList<OpenPort> OpenPorts { get; init; } = Array.Empty<OpenPort>();

    /// <summary>Running system services.</summary>
    public IReadOnlyList<RunningService> RunningServices { get; init; } = Array.Empty<RunningService>();

    /// <summary>Network interfaces and their addresses.</summary>
    public IReadOnlyList<NetworkInterface> NetworkInterfaces { get; init; } = Array.Empty<NetworkInterface>();

    /// <summary>Routing table entries.</summary>
    public IReadOnlyList<RouteEntry> Routes { get; init; } = Array.Empty<RouteEntry>();

    /// <summary>Active network connections.</summary>
    public IReadOnlyList<ActiveConnection> ActiveConnections { get; init; } = Array.Empty<ActiveConnection>();

    /// <summary>Warnings collected during scanning (permission errors, missing tools, etc.).</summary>
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();

    /// <summary>Capabilities of each data source checked during scanning.</summary>
    public IReadOnlyList<DataSourceCapability> Capabilities { get; init; } = Array.Empty<DataSourceCapability>();
}

/// <summary>A parsed firewall rule entry.</summary>
public sealed record FirewallRule
{
    public string Chain { get; init; } = string.Empty;
    public string Target { get; init; } = string.Empty;
    public string Protocol { get; init; } = string.Empty;
    public string Source { get; init; } = string.Empty;
    public string Destination { get; init; } = string.Empty;
    public string? DestinationPort { get; init; }
    public string? InInterface { get; init; }
    public string? OutInterface { get; init; }
    public string? StateMatch { get; init; }
    public string RawLine { get; init; } = string.Empty;
}

/// <summary>An open/listening port with owning process info.</summary>
public sealed record OpenPort
{
    public string Protocol { get; init; } = string.Empty;
    public string LocalAddress { get; init; } = string.Empty;
    public int LocalPort { get; init; }
    public string? ProcessName { get; init; }
    public int? ProcessId { get; init; }
    public string State { get; init; } = string.Empty;
}

/// <summary>A running system service.</summary>
public sealed record RunningService
{
    public string Name { get; init; } = string.Empty;
    public string State { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
}

/// <summary>A network interface and its assigned addresses.</summary>
public sealed record NetworkInterface
{
    public string Name { get; init; } = string.Empty;
    public IReadOnlyList<string> Addresses { get; init; } = Array.Empty<string>();
    public bool IsUp { get; init; }
    public string? MacAddress { get; init; }
}

/// <summary>A routing table entry.</summary>
public sealed record RouteEntry
{
    public string Destination { get; init; } = string.Empty;
    public string? Gateway { get; init; }
    public string Interface { get; init; } = string.Empty;
    public string Flags { get; init; } = string.Empty;
}

/// <summary>An active network connection.</summary>
public sealed record ActiveConnection
{
    public string Protocol { get; init; } = string.Empty;
    public string LocalAddress { get; init; } = string.Empty;
    public int LocalPort { get; init; }
    public string RemoteAddress { get; init; } = string.Empty;
    public int RemotePort { get; init; }
    public string State { get; init; } = string.Empty;
    public string? ProcessName { get; init; }
}
