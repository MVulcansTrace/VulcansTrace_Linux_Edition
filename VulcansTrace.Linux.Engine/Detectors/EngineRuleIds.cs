namespace VulcansTrace.Linux.Engine.Detectors;

/// <summary>
/// Stable rule identifiers for log-analysis detector findings.
/// </summary>
/// <remarks>
/// The <c>ENG-</c> prefix keeps engine rule ids disjoint from Security Agent rule ids
/// (FW-001, SSH-002, …) and from posture-correlation wildcard patterns — e.g. a
/// <c>PORT-*</c> pattern cannot match <c>ENG-PORTSCAN-001</c>.
/// </remarks>
public static class EngineRuleIds
{
    /// <summary>Rule id for <see cref="PortScanDetector"/> findings.</summary>
    public const string PortScan = "ENG-PORTSCAN-001";

    /// <summary>Rule id for <see cref="BeaconingDetector"/> findings.</summary>
    public const string Beaconing = "ENG-BEACON-001";

    /// <summary>Rule id for <see cref="C2ChannelDetector"/> findings.</summary>
    public const string C2Channel = "ENG-C2-001";

    /// <summary>Rule id for <see cref="FlagAnomalyDetector"/> findings.</summary>
    public const string FlagAnomaly = "ENG-FLAG-001";

    /// <summary>Rule id for <see cref="FloodDetector"/> findings.</summary>
    public const string Flood = "ENG-FLOOD-001";

    /// <summary>Rule id for <see cref="InterfaceHoppingDetector"/> findings.</summary>
    public const string InterfaceHopping = "ENG-IFHOP-001";

    /// <summary>Rule id for <see cref="KernelModuleDetector"/> findings.</summary>
    public const string KernelModule = "ENG-KMOD-001";

    /// <summary>Rule id for <see cref="LateralMovementDetector"/> findings.</summary>
    public const string LateralMovement = "ENG-LATMOVE-001";

    /// <summary>Rule id for <see cref="MacSpoofingDetector"/> findings.</summary>
    public const string MacSpoofing = "ENG-MACSPOOF-001";

    /// <summary>Rule id for <see cref="NoveltyDetector"/> findings.</summary>
    public const string Novelty = "ENG-NOVELTY-001";

    /// <summary>Rule id for <see cref="PolicyViolationDetector"/> findings.</summary>
    public const string PolicyViolation = "ENG-POLICY-001";

    /// <summary>Rule id for <see cref="PrivilegeEscalationDetector"/> findings.</summary>
    public const string PrivilegeEscalation = "ENG-PRIVESC-001";

    /// <summary>Rule id for <see cref="ThreatIntelDetector"/> findings.</summary>
    public const string ThreatIntel = "ENG-TI-001";

    /// <summary>Rule id for <see cref="UnusualPacketSizeDetector"/> findings.</summary>
    public const string UnusualPacketSize = "ENG-PKTSIZE-001";
}
