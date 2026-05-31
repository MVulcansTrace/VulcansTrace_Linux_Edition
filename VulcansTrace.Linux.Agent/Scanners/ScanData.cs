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

    /// <summary>SSH daemon configuration settings.</summary>
    public SshConfig? SshConfig { get; init; }

    /// <summary>Sensitive file and directory permission entries.</summary>
    public IReadOnlyList<FilePermissionEntry> FilePermissions { get; init; } = Array.Empty<FilePermissionEntry>();

    /// <summary>Kernel and system hardening parameters.</summary>
    public KernelParameters? KernelParameters { get; init; }
}

/// <summary> Parsed SSH daemon configuration entry. </summary>
public sealed record SshConfig
{
    /// <summary>Whether the configuration could be read.</summary>
    public bool ConfigReadable { get; init; }

    /// <summary>Value of PermitRootLogin directive.</summary>
    public string? PermitRootLogin { get; init; }

    /// <summary>Value of PasswordAuthentication directive.</summary>
    public string? PasswordAuthentication { get; init; }

    /// <summary>Value of MaxAuthTries directive.</summary>
    public int? MaxAuthTries { get; init; }

    /// <summary>Value of Protocol directive (legacy).</summary>
    public string? Protocol { get; init; }

    /// <summary>Value of PermitEmptyPasswords directive.</summary>
    public string? PermitEmptyPasswords { get; init; }

    /// <summary>Value of PubkeyAuthentication directive.</summary>
    public string? PubkeyAuthentication { get; init; }

    /// <summary>Value of ChallengeResponseAuthentication directive.</summary>
    public string? ChallengeResponseAuthentication { get; init; }

    /// <summary>Value of UsePAM directive.</summary>
    public string? UsePAM { get; init; }

    /// <summary>Value of X11Forwarding directive.</summary>
    public string? X11Forwarding { get; init; }

    /// <summary>Value of ClientAliveInterval directive.</summary>
    public int? ClientAliveInterval { get; init; }

    /// <summary>Value of LoginGraceTime directive.</summary>
    public int? LoginGraceTime { get; init; }

    /// <summary>Value of AllowUsers directive.</summary>
    public string? AllowUsers { get; init; }

    /// <summary>Value of AllowGroups directive.</summary>
    public string? AllowGroups { get; init; }

    /// <summary>Value of DenyUsers directive.</summary>
    public string? DenyUsers { get; init; }

    /// <summary>Value of DenyGroups directive.</summary>
    public string? DenyGroups { get; init; }

    /// <summary>Raw configuration lines that were parsed.</summary>
    public IReadOnlyList<string> RawLines { get; init; } = Array.Empty<string>();
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

/// <summary>Permission metadata for a single file or directory.</summary>
public sealed record FilePermissionEntry
{
    /// <summary>Absolute path to the file or directory.</summary>
    public string Path { get; init; } = string.Empty;

    /// <summary>Octal permission mode (e.g. "640").</summary>
    public string Mode { get; init; } = string.Empty;

    /// <summary>File owner username.</summary>
    public string Owner { get; init; } = string.Empty;

    /// <summary>File group name.</summary>
    public string Group { get; init; } = string.Empty;

    /// <summary>Whether the path exists.</summary>
    public bool Exists { get; init; }
}

/// <summary>Kernel and system hardening parameters read from /proc/sys and EFI variables.</summary>
public sealed record KernelParameters
{
    /// <summary>Value of kernel.randomize_va_space (ASLR). 2 = full, 1 = partial, 0 = off.</summary>
    public int? RandomizeVaSpace { get; init; }

    /// <summary>Value of net.ipv4.ip_forward. 0 = disabled, 1 = enabled.</summary>
    public int? IpForwardIpv4 { get; init; }

    /// <summary>Value of net.ipv6.conf.all.forwarding. 0 = disabled, 1 = enabled.</summary>
    public int? IpForwardIpv6 { get; init; }

    /// <summary>Value of net.ipv4.conf.all.accept_redirects. 0 = disabled, 1 = enabled.</summary>
    public int? AcceptRedirectsIpv4 { get; init; }

    /// <summary>Value of net.ipv6.conf.all.accept_redirects. 0 = disabled, 1 = enabled.</summary>
    public int? AcceptRedirectsIpv6 { get; init; }

    /// <summary>Value of net.ipv4.conf.all.accept_source_route. 0 = disabled, 1 = enabled.</summary>
    public int? AcceptSourceRouteIpv4 { get; init; }

    /// <summary>Value of kernel.modules_disabled. 0 = enabled, 1 = disabled.</summary>
    public int? ModulesDisabled { get; init; }

    /// <summary>Whether Secure Boot is enabled.</summary>
    public bool? SecureBootEnabled { get; init; }

    /// <summary>Value of kernel.kptr_restrict. 0 = no restriction, 1 = restricted, 2 = fully restricted.</summary>
    public int? KptrRestrict { get; init; }

    /// <summary>Value of kernel.dmesg_restrict. 0 = unrestricted, 1 = restricted to CAP_SYSLOG.</summary>
    public int? DmesgRestrict { get; init; }

    /// <summary>Whether the parameters were readable.</summary>
    public bool ParametersReadable { get; init; }

    /// <summary>Raw warning or detail message if reading failed.</summary>
    public string? ReadWarning { get; init; }
}
