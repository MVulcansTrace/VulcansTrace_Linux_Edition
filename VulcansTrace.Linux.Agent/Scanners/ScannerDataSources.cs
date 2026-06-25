namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// The authoritative mapping from <see cref="ScanData"/> fields to the scanner that produces
/// each, and from each rule category to its primary scanner. This is the single source of truth
/// used to derive which scanners a targeted audit must run (see
/// <see cref="Rules.RuleEvaluationService.GetRequiredScannerNames"/>), so rule data dependencies
/// drive scanner selection instead of a hand-maintained intent map.
/// </summary>
internal static class ScannerDataSources
{
    /// <summary>
    /// Each ScanData field mapped to the single scanner (<see cref="IScanner.Name"/>) that
    /// populates it. Fields produced by every scanner (Capabilities, Warnings) are omitted:
    /// they impose no constraint on scanner selection.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> FieldToScanner =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["FirewallRules"] = "Firewall",
            ["FirewallRaw"] = "Firewall",
            ["FirewallActive"] = "Firewall",
            ["OpenPorts"] = "Port",
            ["RunningServices"] = "Service",
            ["NetworkInterfaces"] = "Network",
            ["Routes"] = "Network",
            ["ActiveConnections"] = "Network",
            ["FilePermissions"] = "FilePermission",
            ["FilesystemAudits"] = "FilesystemAudit",
            ["TmpMountOptions"] = "FilesystemAudit",
            ["TmpMountTarget"] = "FilesystemAudit",
            ["FileHashes"] = "FileHash",
            ["SshConfig"] = "SshConfig",
            ["KernelParameters"] = "KernelHardening",
            ["UserAccounts"] = "UserAccount",
            ["ShadowEntries"] = "UserAccount",
            ["LoginDefs"] = "UserAccount",
            ["PamConfig"] = "UserAccount",
            ["LoggingAudit"] = "LoggingAudit",
            ["CronJobs"] = "CronJob",
            ["PackageVulnerabilities"] = "PackageVulnerability",
            ["ContainerRuntime"] = "Container",
            ["Containers"] = "Container",
            ["KubernetesPods"] = "Kubernetes",
            ["YaraMatches"] = "Yara",
            ["ProcessRuntimes"] = "ProcessRuntime",
        };

    /// <summary>
    /// Each rule category (see <see cref="Query.IntentCategoryMap"/>) mapped to the scanner
    /// that owns that category's primary data — the scanner every rule in the category needs
    /// by default (before considering any <see cref="Rules.IRule.RequiredDataFields"/>).
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> CategoryToPrimaryScanner =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Firewall"] = "Firewall",
            ["Network"] = "Network",
            ["Service"] = "Service",
            ["Port"] = "Port",
            ["SSH"] = "SshConfig",
            ["FilePermission"] = "FilePermission",
            ["FilesystemAudit"] = "FilesystemAudit",
            ["Kernel"] = "KernelHardening",
            ["UserAccount"] = "UserAccount",
            ["Logging"] = "LoggingAudit",
            ["CronJob"] = "CronJob",
            ["PackageVulnerability"] = "PackageVulnerability",
            ["Container"] = "Container",
            ["Kubernetes"] = "Kubernetes",
            ["ThreatIntel"] = "FileHash",
            ["Yara"] = "Yara",
            ["ProcessRuntime"] = "ProcessRuntime",
        };

    /// <summary>Returns the scanner name that produces <paramref name="field"/>, or null.</summary>
    public static string? ScannerForField(string field) =>
        FieldToScanner.TryGetValue(field, out var scanner) ? scanner : null;
}
