using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine;

/// <summary>
/// Configuration profile controlling detector behavior and thresholds.
/// </summary>
/// <remarks>
/// Profiles are typically provided by <see cref="Configuration.AnalysisProfileProvider"/> based on intensity level,
/// but can be customized for specific analysis needs. Use the <c>with</c> expression to create modified copies.
/// </remarks>
public sealed record AnalysisProfile
{
    // Detector enable flags

    /// <summary>Gets or initializes whether port scan detection is enabled.</summary>
    public bool EnablePortScan { get; init; }

    /// <summary>Gets or initializes whether flood/DoS detection is enabled.</summary>
    public bool EnableFlood { get; init; }

    /// <summary>Gets or initializes whether lateral movement detection is enabled.</summary>
    public bool EnableLateralMovement { get; init; }

    /// <summary>Gets or initializes whether beaconing detection is enabled.</summary>
    public bool EnableBeaconing { get; init; }

    /// <summary>Gets or initializes whether policy violation detection is enabled.</summary>
    public bool EnablePolicy { get; init; }

    /// <summary>Gets or initializes whether novelty/anomaly detection is enabled.</summary>
    public bool EnableNovelty { get; init; }

    // Linux Deep Inspection detectors

    /// <summary>Gets or initializes whether TCP flag anomaly detection is enabled.</summary>
    public bool EnableFlagAnomaly { get; init; }

    /// <summary>Gets or initializes whether MAC address spoofing detection is enabled.</summary>
    public bool EnableMacSpoofing { get; init; }

    /// <summary>Gets or initializes whether kernel module detection is enabled.</summary>
    public bool EnableKernelModule { get; init; }

    /// <summary>Gets or initializes whether interface hopping detection is enabled.</summary>
    public bool EnableInterfaceHopping { get; init; }

    /// <summary>Gets or initializes whether unusual packet size detection is enabled.</summary>
    public bool EnableUnusualPacketSize { get; init; }

    /// <summary>Gets or initializes whether C2 channel detection is enabled.</summary>
    public bool EnableC2Detection { get; init; }

    /// <summary>Gets or initializes whether admin access spike detection is enabled.</summary>
    public bool EnablePrivilegeEscalationDetection { get; init; }

    // Port scan thresholds

    /// <summary>Gets or initializes the minimum distinct ports to qualify as a port scan.</summary>
    public int PortScanMinPorts { get; init; }

    /// <summary>Gets or initializes the time window in minutes for port scan detection.</summary>
    public int PortScanWindowMinutes { get; init; }

    /// <summary>Gets or initializes the maximum entries to analyze per source IP (null for unlimited).</summary>
    public int? PortScanMaxEntriesPerSource { get; init; }

    // Flood thresholds

    /// <summary>Gets or initializes the minimum events to qualify as a flood.</summary>
    public int FloodMinEvents { get; init; }

    /// <summary>Gets or initializes the time window in seconds for flood detection.</summary>
    public int FloodWindowSeconds { get; init; }

    // Lateral movement thresholds

    /// <summary>Gets or initializes the minimum internal hosts contacted to qualify as lateral movement.</summary>
    public int LateralMinHosts { get; init; }

    /// <summary>Gets or initializes the time window in minutes for lateral movement detection.</summary>
    public int LateralWindowMinutes { get; init; }

    // Beaconing thresholds

    /// <summary>Gets or initializes the minimum events to analyze for beaconing.</summary>
    public int BeaconMinEvents { get; init; }

    /// <summary>Gets or initializes the maximum standard deviation for regular interval detection.</summary>
    public double BeaconStdDevThreshold { get; init; }

    /// <summary>Gets or initializes the minimum interval in seconds between beacons.</summary>
    public int BeaconMinIntervalSeconds { get; init; }

    /// <summary>Gets or initializes the maximum interval in seconds between beacons.</summary>
    public int BeaconMaxIntervalSeconds { get; init; }

    /// <summary>Gets or initializes the maximum samples to analyze per source/destination tuple.</summary>
    public int BeaconMaxSamplesPerTuple { get; init; }

    /// <summary>Gets or initializes the minimum duration in seconds for beaconing analysis.</summary>
    public int BeaconMinDurationSeconds { get; init; }

    /// <summary>Gets or initializes the percentage of outliers to trim from interval analysis.</summary>
    public double BeaconTrimPercent { get; init; }

    // C2 Channel thresholds

    /// <summary>Gets or initializes the tolerance in seconds for identifying periodic communication patterns.</summary>
    public double C2ToleranceSeconds { get; init; }

    /// <summary>Gets or initializes the minimum interval in seconds for C2 channel detection.</summary>
    public int C2MinIntervalSeconds { get; init; }

    /// <summary>Gets or initializes the maximum interval in seconds for C2 channel detection.</summary>
    public int C2MaxIntervalSeconds { get; init; }

    /// <summary>Gets or initializes the minimum occurrences of similar intervals to qualify as a pattern.</summary>
    public int C2MinOccurrences { get; init; }

    /// <summary>Gets or initializes the minimum number of events required to form a C2 pattern.</summary>
    public int C2MinPatternEvents { get; init; }

    /// <summary>Gets or initializes the minimum group size for C2 connection tuple pre-filtering.</summary>
    public int C2MinGroupSize { get; init; }

    // Privilege escalation thresholds

    /// <summary>Gets or initializes the time window in minutes for detecting admin access spikes.</summary>
    public int PrivilegeSpikeWindowMinutes { get; init; }

    // Policy settings

    /// <summary>Gets or initializes the list of administrative ports to monitor for unauthorized access.</summary>
    public IReadOnlyList<int> AdminPorts { get; init; } = Array.Empty<int>();

    /// <summary>Gets or initializes the list of ports that should not allow outbound traffic.</summary>
    public IReadOnlyList<int> DisallowedOutboundPorts { get; init; } = Array.Empty<int>();

    // Output filtering

    /// <summary>Gets or initializes the minimum severity level for findings to be included in results.</summary>
    public Severity MinSeverityToShow { get; init; } = Severity.Medium;

    /// <summary>Gets or initializes the minimum admin port access attempts within the spike window to trigger a finding.</summary>
    public int PrivilegeSpikeMinAttempts { get; init; }

    /// <summary>Gets or initializes the minimum distinct admin ports accessed within the sweep window to trigger a finding.</summary>
    public int PrivilegeSweepMinDistinctPorts { get; init; }

    // Interface hopping thresholds

    /// <summary>Gets or initializes the time window in minutes for detecting rapid interface switching.</summary>
    public int InterfaceHoppingWindowMinutes { get; init; }

    /// <summary>Gets or initializes the time window in minutes for detecting rapid MAC-to-IP changes.</summary>
    public int MacSpoofingWindowMinutes { get; init; }

    // Packet size thresholds

    /// <summary>Gets or initializes the packet size threshold above which packets are considered suspiciously large.</summary>
    public int PacketSizeLargeThreshold { get; init; }

    /// <summary>Gets or initializes the packet size threshold below which packets are considered suspiciously small.</summary>
    public int PacketSizeSmallThreshold { get; init; }

    /// <summary>Gets or initializes the minimum number of packets required for statistical size analysis.</summary>
    public int PacketSizeMinForAnalysis { get; init; }

    /// <summary>Gets or initializes the consistency percentage threshold for covert channel detection.</summary>
    public double PacketSizeConsistencyPercent { get; init; }

    /// <summary>Gets or initializes the minimum count of same-size packets for covert channel detection.</summary>
    public int PacketSizeMinConsistentCount { get; init; }

    /// <summary>Gets or initializes the variance ratio threshold for high-variance packet size detection.</summary>
    public double PacketSizeVarianceRatio { get; init; }

    /// <summary>Gets or initializes the minimum average packet size for high-variance detection.</summary>
    public int PacketSizeMinAvgForVariance { get; init; }

    public int MaxFindingsPerDetector { get; init; }

    /// <summary>Gets or initializes the minimum events to qualify as a flag anomaly.</summary>
    public int FlagAnomalyMinEvents { get; init; } = 1;

    /// <summary>Gets or initializes the minimum events to qualify as a kernel module finding.</summary>
    public int KernelModuleMinEvents { get; init; } = 1;

    /// <summary>Gets or initializes the minimum events to qualify as a policy violation.</summary>
    public int PolicyViolationMinEvents { get; init; } = 1;

    /// <summary>Gets or initializes the maximum global occurrences for a destination to be considered novel (default 1).</summary>
    public int NoveltyMaxGlobalOccurrences { get; init; } = 1;
}
