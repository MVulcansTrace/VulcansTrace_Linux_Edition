namespace VulcansTrace.Linux.Core.ThreatIntel;

/// <summary>
/// Types of indicators of compromise (IOCs) that can be imported and correlated.
/// </summary>
public enum IocType
{
    /// <summary>IPv4 address.</summary>
    IPv4,

    /// <summary>IPv6 address.</summary>
    IPv6,

    /// <summary>Domain name.</summary>
    Domain,

    /// <summary>TCP/UDP port number.</summary>
    Port,

    /// <summary>File hash (typically SHA-256).</summary>
    FileHash,

    /// <summary>URL.</summary>
    URL
}
