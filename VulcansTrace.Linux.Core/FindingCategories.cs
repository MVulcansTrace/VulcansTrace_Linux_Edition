namespace VulcansTrace.Linux.Core;

public static class FindingCategories
{
    public const string PortScan = "PortScan";
    public const string Flood = "Flood";
    public const string LateralMovement = "LateralMovement";
    public const string Beaconing = "Beaconing";
    public const string PolicyViolation = "PolicyViolation";
    public const string Novelty = "Novelty";
    public const string FlagAnomaly = "FlagAnomaly";
    public const string MacSpoofing = "MacSpoofing";
    public const string KernelModule = "KernelModule";
    public const string InterfaceHopping = "InterfaceHopping";
    public const string UnusualPacketSize = "UnusualPacketSize";
    public const string C2Channel = "C2Channel";
    public const string PrivilegeEscalation = "PrivilegeEscalation";
    public const string UserAccount = "UserAccount";
    public const string FilesystemAudit = "FilesystemAudit";
    public const string CronJob = "CronJob";
    public const string PackageVulnerability = "PackageVulnerability";
    public const string Container = "Container";
    public const string Kubernetes = "Kubernetes";
    public const string ThreatIntel = "ThreatIntel";
    public const string Yara = "Yara";
}
