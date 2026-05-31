namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Gathers live system data for security rule evaluation.
/// </summary>
public interface IScanner
{
    /// <summary>Human-readable scanner name.</summary>
    string Name { get; }

    /// <summary>
    /// Scans the live system and populates the provided <see cref="ScanDataBuilder"/>.
    /// </summary>
    /// <param name="builder">Builder to populate with scanned data.</param>
    /// <param name="cancellationToken">Token to cancel the scan.</param>
    Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken);
}

/// <summary>
/// Mutable builder used to aggregate data from multiple scanners into a single <see cref="ScanData"/>.
/// All mutation methods are thread-safe.
/// </summary>
public sealed class ScanDataBuilder
{
    private readonly List<FirewallRule> _firewallRules = new();
    private readonly List<OpenPort> _openPorts = new();
    private readonly List<RunningService> _runningServices = new();
    private readonly List<NetworkInterface> _networkInterfaces = new();
    private readonly List<RouteEntry> _routes = new();
    private readonly List<ActiveConnection> _activeConnections = new();
    private readonly List<FilePermissionEntry> _filePermissions = new();
    private readonly List<string> _warnings = new();
    private readonly List<DataSourceCapability> _capabilities = new();
    private readonly object _lock = new();
    private string _firewallRaw = string.Empty;
    private bool _firewallActive;
    private SshConfig? _sshConfig;
    private KernelParameters? _kernelParameters;

    public string FirewallRaw
    {
        get { lock (_lock) { return _firewallRaw; } }
        set { lock (_lock) { _firewallRaw = value; } }
    }

    public bool FirewallActive
    {
        get { lock (_lock) { return _firewallActive; } }
        set { lock (_lock) { _firewallActive = value; } }
    }

    public void AddFirewallRule(FirewallRule rule)
    {
        lock (_lock) { _firewallRules.Add(rule); }
    }

    public void AddOpenPort(OpenPort port)
    {
        lock (_lock) { _openPorts.Add(port); }
    }

    public void AddRunningService(RunningService service)
    {
        lock (_lock) { _runningServices.Add(service); }
    }

    public void AddNetworkInterface(NetworkInterface iface)
    {
        lock (_lock) { _networkInterfaces.Add(iface); }
    }

    public void AddRoute(RouteEntry route)
    {
        lock (_lock) { _routes.Add(route); }
    }

    public void AddActiveConnection(ActiveConnection connection)
    {
        lock (_lock) { _activeConnections.Add(connection); }
    }

    public void AddFilePermission(FilePermissionEntry entry)
    {
        lock (_lock) { _filePermissions.Add(entry); }
    }

    public void AddWarning(string warning)
    {
        lock (_lock) { _warnings.Add(warning); }
    }

    public void AddCapability(DataSourceCapability capability)
    {
        lock (_lock) { _capabilities.Add(capability); }
    }

    public void SetSshConfig(SshConfig config)
    {
        lock (_lock) { _sshConfig = config; }
    }

    public void SetKernelParameters(KernelParameters parameters)
    {
        lock (_lock) { _kernelParameters = parameters; }
    }

    public ScanData Build()
    {
        lock (_lock)
        {
            return new ScanData
            {
                FirewallRaw = _firewallRaw,
                FirewallRules = _firewallRules.ToArray(),
                FirewallActive = _firewallActive,
                OpenPorts = _openPorts.ToArray(),
                RunningServices = _runningServices.ToArray(),
                NetworkInterfaces = _networkInterfaces.ToArray(),
                Routes = _routes.ToArray(),
                ActiveConnections = _activeConnections.ToArray(),
                FilePermissions = _filePermissions.ToArray(),
                Warnings = _warnings.ToArray(),
                Capabilities = _capabilities.ToArray(),
                SshConfig = _sshConfig,
                KernelParameters = _kernelParameters
            };
        }
    }
}
