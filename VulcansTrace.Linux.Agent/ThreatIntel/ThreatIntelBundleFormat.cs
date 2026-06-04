namespace VulcansTrace.Linux.Agent.ThreatIntel;

/// <summary>
/// Supported offline threat intelligence bundle formats.
/// </summary>
public enum ThreatIntelBundleFormat
{
    /// <summary>STIX 2.x bundle JSON.</summary>
    Stix,

    /// <summary>MISP event JSON.</summary>
    Misp
}
