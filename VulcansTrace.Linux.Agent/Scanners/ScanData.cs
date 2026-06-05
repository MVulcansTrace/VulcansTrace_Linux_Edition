using VulcansTrace.Linux.Core.Security;

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

    /// <summary>Filesystem audit findings (world-writable files, SUID/SGID binaries, unowned files, etc.).</summary>
    public IReadOnlyList<FilesystemAuditEntry> FilesystemAudits { get; init; } = Array.Empty<FilesystemAuditEntry>();

    /// <summary>SHA-256 hashes of interesting files discovered during scanning.</summary>
    public IReadOnlyList<FileHashEntry> FileHashes { get; init; } = Array.Empty<FileHashEntry>();

    /// <summary>Mount options for /tmp (comma-separated).</summary>
    public string TmpMountOptions { get; init; } = string.Empty;

    /// <summary>Mount target for /tmp (e.g. "/tmp" if separate mount, "/" if on root filesystem).</summary>
    public string TmpMountTarget { get; init; } = string.Empty;

    /// <summary>Local user accounts from /etc/passwd.</summary>
    public IReadOnlyList<UserAccount> UserAccounts { get; init; } = Array.Empty<UserAccount>();

    /// <summary>Shadow password entries from /etc/shadow.</summary>
    public IReadOnlyList<ShadowEntry> ShadowEntries { get; init; } = Array.Empty<ShadowEntry>();

    /// <summary>Password aging definitions from /etc/login.defs.</summary>
    public LoginDefs? LoginDefs { get; init; }

    /// <summary>PAM password configuration lines.</summary>
    public PamConfig? PamConfig { get; init; }

    /// <summary>Logging and auditing configuration (rsyslog, journald, auditd, logrotate, forwarding).</summary>
    public LoggingAuditConfig? LoggingAudit { get; init; }

    /// <summary>Parsed cron job entries from system and user crontabs.</summary>
    public IReadOnlyList<CronJobEntry> CronJobs { get; init; } = Array.Empty<CronJobEntry>();

    /// <summary>Package vulnerability status including installed packages and pending security updates.</summary>
    public PackageVulnerabilityStatus? PackageVulnerabilities { get; init; }

    /// <summary>Container runtime availability and socket exposure status.</summary>
    public ContainerRuntimeInfo? ContainerRuntime { get; init; }

    /// <summary>Running containers detected via docker or crictl.</summary>
    public IReadOnlyList<ContainerInfo> Containers { get; init; } = Array.Empty<ContainerInfo>();

    /// <summary>Kubernetes pods and their security contexts detected via kubectl.</summary>
    public IReadOnlyList<KubernetesPodInfo> KubernetesPods { get; init; } = Array.Empty<KubernetesPodInfo>();

    /// <summary>YARA rule matches discovered on SUID/SGID binaries, running process executables, and cron scripts.</summary>
    public IReadOnlyList<YaraMatchEntry> YaraMatches { get; init; } = Array.Empty<YaraMatchEntry>();
}

/// <summary>An installed package parsed from dpkg-query.</summary>
public sealed record InstalledPackage
{
    /// <summary>Package name.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Installed version string.</summary>
    public string Version { get; init; } = string.Empty;

    /// <summary>Package architecture (e.g., amd64, arm64).</summary>
    public string Architecture { get; init; } = string.Empty;
}

/// <summary>A package with a known pending update, optionally classified as a security update.</summary>
public sealed record VulnerablePackage
{
    /// <summary>Package name.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Currently installed version.</summary>
    public string InstalledVersion { get; init; } = string.Empty;

    /// <summary>Available updated version.</summary>
    public string AvailableVersion { get; init; } = string.Empty;

    /// <summary>Whether the available update comes from a security repository.</summary>
    public bool IsSecurityUpdate { get; init; }

    /// <summary>Associated CVE identifiers (if debsecan or similar enrichment is available).</summary>
    public IReadOnlyList<string> CveIds { get; init; } = Array.Empty<string>();

    /// <summary>Source repository or origin (e.g., "ubuntu-security", "debian-security").</summary>
    public string Source { get; init; } = string.Empty;
}

/// <summary>Aggregated package vulnerability scanning results.</summary>
public sealed record PackageVulnerabilityStatus
{
    /// <summary>Whether package data could be read.</summary>
    public bool PackagesReadable { get; init; }

    /// <summary>Warning or detail message if reading failed.</summary>
    public string? ReadWarning { get; init; }

    /// <summary>All installed packages.</summary>
    public IReadOnlyList<InstalledPackage> InstalledPackages { get; init; } = Array.Empty<InstalledPackage>();

    /// <summary>Packages with known pending updates affecting this system.</summary>
    public IReadOnlyList<VulnerablePackage> VulnerablePackages { get; init; } = Array.Empty<VulnerablePackage>();

    /// <summary>Whether unattended-upgrades configuration file exists.</summary>
    public bool UnattendedUpgradesConfigured { get; init; }

    /// <summary>Whether unattended-upgrades appears actively enabled.</summary>
    public bool UnattendedUpgradesEnabled { get; init; }

    /// <summary>Whether CVE enrichment data (e.g., from debsecan) was available during the scan.</summary>
    public bool CveDataAvailable { get; init; }
}

/// <summary>A parsed cron job entry from system or user crontabs.</summary>
public sealed record CronJobEntry
{
    /// <summary>Absolute path to the source crontab file or script.</summary>
    public string SourceFile { get; init; } = string.Empty;

    /// <summary>Cron schedule expression or directory-derived frequency (e.g. "0 5 * * *", "@daily").</summary>
    public string Schedule { get; init; } = string.Empty;

    /// <summary>The command or script path to execute.</summary>
    public string Command { get; init; } = string.Empty;

    /// <summary>User the job runs as (system crontabs only).</summary>
    public string? RunAsUser { get; init; }

    /// <summary>True for executable scripts in cron.daily/hourly/weekly/monthly directories.</summary>
    public bool IsScript { get; init; }

    /// <summary>Octal permission mode for script files.</summary>
    public string? ScriptPermissions { get; init; }

    /// <summary>File owner for script files.</summary>
    public string? ScriptOwner { get; init; }

    /// <summary>File group for script files.</summary>
    public string? ScriptGroup { get; init; }
}

/// <summary>Logging and auditing subsystem configuration.</summary>
public sealed record LoggingAuditConfig
{
    /// <summary>Whether rsyslog service is active.</summary>
    public bool RsyslogActive { get; init; }

    /// <summary>Whether systemd-journald service is active.</summary>
    public bool JournaldActive { get; init; }

    /// <summary>Whether auditd service is active.</summary>
    public bool AuditdActive { get; init; }

    /// <summary>Whether auditd has active rules configured.</summary>
    public bool AuditdRulesConfigured { get; init; }

    /// <summary>Whether log rotation is configured.</summary>
    public bool LogRotationConfigured { get; init; }

    /// <summary>Whether central log forwarding is configured.</summary>
    public bool CentralForwardingConfigured { get; init; }

    /// <summary>Raw auditd rules found on the system.</summary>
    public IReadOnlyList<string> AuditdRules { get; init; } = Array.Empty<string>();

    /// <summary>Forwarding targets detected (e.g. "@@192.168.1.10:514").</summary>
    public IReadOnlyList<string> ForwardingTargets { get; init; } = Array.Empty<string>();

    /// <summary>Warning or detail message if reading failed.</summary>
    public string? ReadWarning { get; init; }
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

/// <summary>Filesystem audit entry for world-writable files, SUID/SGID binaries, unowned files, etc.</summary>
public sealed record FilesystemAuditEntry
{
    /// <summary>Absolute path to the file or directory.</summary>
    public string Path { get; init; } = string.Empty;

    /// <summary>Octal permission mode (e.g. "4755").</summary>
    public string Mode { get; init; } = string.Empty;

    /// <summary>File owner username or UID.</summary>
    public string Owner { get; init; } = string.Empty;

    /// <summary>File group name or GID.</summary>
    public string Group { get; init; } = string.Empty;

    /// <summary>Audit category (e.g. "WorldWritableFile", "SuidBinary", "SgidBinary", "UnownedFile", "WorldWritableDirNoSticky").</summary>
    public string AuditCategory { get; init; } = string.Empty;
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

/// <summary>A local user account parsed from /etc/passwd.</summary>
public sealed record UserAccount
{
    public string Username { get; init; } = string.Empty;
    public int Uid { get; init; }
    public int Gid { get; init; }
    public string Gecos { get; init; } = string.Empty;
    public string HomeDirectory { get; init; } = string.Empty;
    public string Shell { get; init; } = string.Empty;
    public bool HomeDirectoryExists { get; init; }
}

/// <summary>A shadow password entry parsed from /etc/shadow.</summary>
public sealed record ShadowEntry
{
    public string Username { get; init; } = string.Empty;
    public string PasswordHash { get; init; } = string.Empty;
    public int? LastChange { get; init; }
    public int? MinDays { get; init; }
    public int? MaxDays { get; init; }
    public int? WarnDays { get; init; }
    public int? InactiveDays { get; init; }
    public int? ExpireDate { get; init; }
}

/// <summary>Password aging policy parsed from /etc/login.defs.</summary>
public sealed record LoginDefs
{
    public bool Readable { get; init; }
    public int? PassMaxDays { get; init; }
    public int? PassMinDays { get; init; }
    public int? PassMinLen { get; init; }
    public int? PassWarnAge { get; init; }
    public string? EncryptMethod { get; init; }
}

/// <summary>PAM password configuration aggregated from relevant PAM files.</summary>
public sealed record PamConfig
{
    public bool Readable { get; init; }
    public IReadOnlyList<string> RawLines { get; init; } = Array.Empty<string>();

    /// <summary>Raw lines keyed by source file path (e.g. "/etc/pam.d/common-auth").</summary>
    public IReadOnlyDictionary<string, string[]> RawLinesByFile { get; init; }
        = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
}

/// <summary>Container runtime detection status.</summary>
public sealed record ContainerRuntimeInfo
{
    /// <summary>Whether Docker CLI was available.</summary>
    public bool DockerAvailable { get; init; }

    /// <summary>Whether containerd CLI (ctr/crictl) was available.</summary>
    public bool ContainerdAvailable { get; init; }

    /// <summary>Whether /var/run/docker.sock exists on the host.</summary>
    public bool DockerSocketExposed { get; init; }
}

/// <summary>A running container detected via docker or crictl.</summary>
public sealed record ContainerInfo
{
    /// <summary>Container name.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Container image repository.</summary>
    public string Image { get; init; } = string.Empty;

    /// <summary>Container image tag.</summary>
    public string Tag { get; init; } = string.Empty;

    /// <summary>Whether the container runs in privileged mode.</summary>
    public bool IsPrivileged { get; init; }

    /// <summary>Whether the container shares the host PID namespace.</summary>
    public bool HasHostPid { get; init; }

    /// <summary>Whether the container shares the host network namespace.</summary>
    public bool HasHostNetwork { get; init; }

    /// <summary>Whether the container mounts the Docker socket.</summary>
    public bool HasDockerSocketMount { get; init; }

    /// <summary>Known risky base image or layer hints detected from local image metadata.</summary>
    public IReadOnlyList<string> KnownBadBaseLayers { get; init; } = Array.Empty<string>();

    /// <summary>Runtime that reported this container (docker or containerd).</summary>
    public string Runtime { get; init; } = string.Empty;
}

/// <summary>A Kubernetes pod and its security posture.</summary>
public sealed record KubernetesPodInfo
{
    /// <summary>Pod namespace.</summary>
    public string Namespace { get; init; } = string.Empty;

    /// <summary>Pod name.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Containers within the pod.</summary>
    public IReadOnlyList<K8sContainerInfo> Containers { get; init; } = Array.Empty<K8sContainerInfo>();

    /// <summary>Whether the pod shares the host network namespace.</summary>
    public bool HostNetwork { get; init; }

    /// <summary>Whether the pod shares the host PID namespace.</summary>
    public bool HostPid { get; init; }

    /// <summary>Whether the pod shares the host IPC namespace.</summary>
    public bool HostIpc { get; init; }

    /// <summary>Detected Pod Security Standard violation descriptions.</summary>
    public IReadOnlyList<string> Violations { get; init; } = Array.Empty<string>();
}

/// <summary>A container within a Kubernetes pod.</summary>
public sealed record K8sContainerInfo
{
    /// <summary>Container name.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Container image.</summary>
    public string Image { get; init; } = string.Empty;

    /// <summary>Whether the container explicitly runs as root.</summary>
    public bool RunAsRoot { get; init; }

    /// <summary>Whether the container is privileged.</summary>
    public bool Privileged { get; init; }

    /// <summary>Whether privilege escalation is allowed (true if missing or not false).</summary>
    public bool AllowPrivilegeEscalation { get; init; }

    /// <summary>Whether the root filesystem is read-only.</summary>
    public bool ReadOnlyRootFilesystem { get; init; }

    /// <summary>Whether all capabilities are dropped.</summary>
    public bool DropAllCapabilities { get; init; }

    /// <summary>Seccomp profile type (e.g. RuntimeDefault, Unconfined, or custom).</summary>
    public string SeccompProfile { get; init; } = string.Empty;
}
