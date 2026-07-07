using VulcansTrace.Linux.Core.Security;

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
    private readonly List<FilesystemAuditEntry> _filesystemAudits = new();
    private readonly List<FileHashEntry> _fileHashes = new();
    private readonly List<string> _warnings = new();
    private readonly List<DataSourceCapability> _capabilities = new();
    private readonly List<UserAccount> _userAccounts = new();
    private readonly List<ShadowEntry> _shadowEntries = new();
    private readonly List<CronJobEntry> _cronJobs = new();
    private readonly List<ContainerInfo> _containers = new();
    private readonly List<KubernetesPodInfo> _kubernetesPods = new();
    private readonly List<YaraMatchEntry> _yaraMatches = new();
    private readonly List<ProcessRuntimeEntry> _processRuntimes = new();
    private readonly object _lock = new();
    private string _firewallRaw = string.Empty;
    private bool _firewallActive;
    private SshConfig? _sshConfig;
    private KernelParameters? _kernelParameters;
    private string _tmpMountOptions = string.Empty;
    private string _tmpMountTarget = string.Empty;
    private LoginDefs? _loginDefs;
    private PamConfig? _pamConfig;
    private LoggingAuditConfig? _loggingAuditConfig;
    private SudoersConfig? _sudoersConfig;
    private SystemdTimerSocketConfig? _systemdTimerSocketConfig;
    private MacConfig? _macConfig;
    private BootloaderConfig? _bootloaderConfig;
    private PackageVulnerabilityStatus? _packageVulnerabilityStatus;
    private ContainerRuntimeInfo? _containerRuntime;

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

    public void AddFilesystemAudit(FilesystemAuditEntry entry)
    {
        lock (_lock) { _filesystemAudits.Add(entry); }
    }

    public void AddFileHash(FileHashEntry entry)
    {
        lock (_lock) { _fileHashes.Add(entry); }
    }

    public void SetTmpMountOptions(string options)
    {
        lock (_lock) { _tmpMountOptions = options; }
    }

    public void SetTmpMountTarget(string target)
    {
        lock (_lock) { _tmpMountTarget = target; }
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

    public void AddUserAccount(UserAccount account)
    {
        lock (_lock) { _userAccounts.Add(account); }
    }

    public void AddShadowEntry(ShadowEntry entry)
    {
        lock (_lock) { _shadowEntries.Add(entry); }
    }

    public void SetLoginDefs(LoginDefs defs)
    {
        lock (_lock) { _loginDefs = defs; }
    }

    public void SetPamConfig(PamConfig config)
    {
        lock (_lock) { _pamConfig = config; }
    }

    public void SetLoggingAuditConfig(LoggingAuditConfig config)
    {
        lock (_lock) { _loggingAuditConfig = config; }
    }

    public void SetSudoersConfig(SudoersConfig config)
    {
        lock (_lock) { _sudoersConfig = config; }
    }

    public void SetSystemdTimerSocketConfig(SystemdTimerSocketConfig config)
    {
        lock (_lock) { _systemdTimerSocketConfig = config; }
    }

    public void SetMacConfig(MacConfig config)
    {
        lock (_lock) { _macConfig = config; }
    }

    public void SetBootloaderConfig(BootloaderConfig config)
    {
        lock (_lock) { _bootloaderConfig = config; }
    }

    public void AddCronJob(CronJobEntry entry)
    {
        lock (_lock) { _cronJobs.Add(entry); }
    }

    public void SetPackageVulnerabilityStatus(PackageVulnerabilityStatus status)
    {
        lock (_lock) { _packageVulnerabilityStatus = status; }
    }

    public void SetContainerRuntime(ContainerRuntimeInfo runtime)
    {
        lock (_lock) { _containerRuntime = runtime; }
    }

    public void AddContainer(ContainerInfo container)
    {
        lock (_lock) { _containers.Add(container); }
    }

    public void AddKubernetesPod(KubernetesPodInfo pod)
    {
        lock (_lock) { _kubernetesPods.Add(pod); }
    }

    public void AddYaraMatch(YaraMatchEntry entry)
    {
        lock (_lock) { _yaraMatches.Add(entry); }
    }

    public void AddProcessRuntime(ProcessRuntimeEntry entry)
    {
        lock (_lock) { _processRuntimes.Add(entry); }
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
                FilesystemAudits = _filesystemAudits.ToArray(),
                FileHashes = _fileHashes.ToArray(),
                TmpMountOptions = _tmpMountOptions,
                TmpMountTarget = _tmpMountTarget,
                Warnings = _warnings.ToArray(),
                Capabilities = _capabilities.ToArray(),
                SshConfig = _sshConfig,
                KernelParameters = _kernelParameters,
                UserAccounts = _userAccounts.ToArray(),
                ShadowEntries = _shadowEntries.ToArray(),
                LoginDefs = _loginDefs,
                PamConfig = _pamConfig,
                LoggingAudit = _loggingAuditConfig,
                SudoersConfig = _sudoersConfig,
                SystemdTimerSocketConfig = _systemdTimerSocketConfig,
                MacConfig = _macConfig,
                BootloaderConfig = _bootloaderConfig,
                CronJobs = _cronJobs.ToArray(),
                PackageVulnerabilities = _packageVulnerabilityStatus,
                ContainerRuntime = _containerRuntime,
                Containers = _containers.ToArray(),
                KubernetesPods = _kubernetesPods.ToArray(),
                YaraMatches = _yaraMatches.ToArray(),
                ProcessRuntimes = _processRuntimes.ToArray()
            };
        }
    }
}
