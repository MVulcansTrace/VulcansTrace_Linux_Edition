using System.Collections.Immutable;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine.Configuration;

/// <summary>
/// Provides pre-configured analysis profiles based on intensity level.
/// </summary>
/// <remarks>
/// Each intensity level has carefully tuned thresholds:
/// <list type="bullet">
/// <item><see cref="IntensityLevel.Low"/>: Conservative, high thresholds, fewer findings</item>
/// <item><see cref="IntensityLevel.Medium"/>: Balanced thresholds for general use</item>
/// <item><see cref="IntensityLevel.High"/>: Aggressive, low thresholds, more findings</item>
/// </list>
/// </remarks>
public sealed class AnalysisProfileProvider
{
    /// <summary>
    /// Gets the analysis profile for the specified intensity level.
    /// </summary>
    /// <param name="level">The desired intensity level.</param>
    /// <returns>A configured <see cref="AnalysisProfile"/> with appropriate thresholds.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when an invalid intensity level is provided.</exception>
    public AnalysisProfile GetProfile(IntensityLevel level)
    {
        var adminPorts = ImmutableArray.Create(445, 3389, 22);
        var disallowedOutbound = ImmutableArray.Create(21, 23, 445);

        return level switch
        {
            IntensityLevel.Low => new AnalysisProfile
            {
                // Baseline detectors
                EnablePortScan = true,
                EnableFlood = true,
                EnableLateralMovement = true,
                EnableBeaconing = true,
                EnablePolicy = true,
                EnableNovelty = false,

                // Linux Deep Inspection detectors
                EnableFlagAnomaly = true,
                EnableMacSpoofing = true,
                EnableKernelModule = false,
                EnableInterfaceHopping = false,
                EnableUnusualPacketSize = false,
                EnableC2Detection = false,

                // Thresholds
                PortScanMinPorts = 30,
                PortScanWindowMinutes = 5,
                PortScanMaxEntriesPerSource = null,

                FloodMinEvents = 400,
                FloodWindowSeconds = 60,

                LateralMinHosts = 6,
                LateralWindowMinutes = 10,

                BeaconMinEvents = 8,
                BeaconStdDevThreshold = 3.0,
                BeaconMinIntervalSeconds = 60,
                BeaconMaxIntervalSeconds = 900,
                BeaconMaxSamplesPerTuple = 200,
                BeaconMinDurationSeconds = 120,
                BeaconTrimPercent = 0.1,

                // C2 thresholds
                C2ToleranceSeconds = 10.0,
                C2MinIntervalSeconds = 120,
                C2MaxIntervalSeconds = 3600,
                C2MinOccurrences = 5,
                C2MinPatternEvents = 10,
                C2MinGroupSize = 4,

                // Privilege escalation thresholds
                EnablePrivilegeEscalationDetection = false,
                PrivilegeSpikeWindowMinutes = 10,
                PrivilegeSpikeMinAttempts = 8,
                PrivilegeSweepMinDistinctPorts = 4,

                InterfaceHoppingWindowMinutes = 10,
                MacSpoofingWindowMinutes = 10,

                PacketSizeLargeThreshold = 4000,
                PacketSizeSmallThreshold = 20,
                PacketSizeMinForAnalysis = 15,
                PacketSizeConsistencyPercent = 80,
                PacketSizeMinConsistentCount = 15,
                PacketSizeVarianceRatio = 0.6,
                PacketSizeMinAvgForVariance = 150,

                AdminPorts = adminPorts,
                DisallowedOutboundPorts = disallowedOutbound,

                MaxFindingsPerDetector = 100,
                MinSeverityToShow = Severity.High
            },
            IntensityLevel.Medium => new AnalysisProfile
            {
                // Baseline detectors
                EnablePortScan = true,
                EnableFlood = true,
                EnableLateralMovement = true,
                EnableBeaconing = true,
                EnablePolicy = true,
                EnableNovelty = true,

                // Linux Deep Inspection detectors
                EnableFlagAnomaly = true,
                EnableMacSpoofing = true,
                EnableKernelModule = true,
                EnableInterfaceHopping = true,
                EnableUnusualPacketSize = true,
                EnableC2Detection = true,

                // Thresholds
                PortScanMinPorts = 15,
                PortScanWindowMinutes = 5,
                PortScanMaxEntriesPerSource = null,

                FloodMinEvents = 200,
                FloodWindowSeconds = 60,

                LateralMinHosts = 4,
                LateralWindowMinutes = 10,

                BeaconMinEvents = 6,
                BeaconStdDevThreshold = 5.0,
                BeaconMinIntervalSeconds = 30,
                BeaconMaxIntervalSeconds = 900,
                BeaconMaxSamplesPerTuple = 200,
                BeaconMinDurationSeconds = 120,
                BeaconTrimPercent = 0.1,

                // C2 thresholds
                C2ToleranceSeconds = 5.0,
                C2MinIntervalSeconds = 60,
                C2MaxIntervalSeconds = 1800,
                C2MinOccurrences = 3,
                C2MinPatternEvents = 6,
                C2MinGroupSize = 3,

                // Privilege escalation thresholds
                EnablePrivilegeEscalationDetection = true,
                PrivilegeSpikeWindowMinutes = 5,
                PrivilegeSpikeMinAttempts = 5,
                PrivilegeSweepMinDistinctPorts = 3,

                InterfaceHoppingWindowMinutes = 5,
                MacSpoofingWindowMinutes = 5,

                PacketSizeLargeThreshold = 3000,
                PacketSizeSmallThreshold = 40,
                PacketSizeMinForAnalysis = 10,
                PacketSizeConsistencyPercent = 70,
                PacketSizeMinConsistentCount = 10,
                PacketSizeVarianceRatio = 0.5,
                PacketSizeMinAvgForVariance = 100,

                AdminPorts = adminPorts,
                DisallowedOutboundPorts = disallowedOutbound,

                MaxFindingsPerDetector = 100,
                MinSeverityToShow = Severity.Medium
            },
            IntensityLevel.High => new AnalysisProfile
            {
                // Baseline detectors
                EnablePortScan = true,
                EnableFlood = true,
                EnableLateralMovement = true,
                EnableBeaconing = true,
                EnablePolicy = true,
                EnableNovelty = true,

                // Linux Deep Inspection detectors
                EnableFlagAnomaly = true,
                EnableMacSpoofing = true,
                EnableKernelModule = true,
                EnableInterfaceHopping = true,
                EnableUnusualPacketSize = true,
                EnableC2Detection = true,

                // Thresholds
                PortScanMinPorts = 8,
                PortScanWindowMinutes = 5,
                PortScanMaxEntriesPerSource = null,

                FloodMinEvents = 100,
                FloodWindowSeconds = 60,

                LateralMinHosts = 3,
                LateralWindowMinutes = 10,

                BeaconMinEvents = 4,
                BeaconStdDevThreshold = 8.0,
                BeaconMinIntervalSeconds = 10,
                BeaconMaxIntervalSeconds = 900,
                BeaconMaxSamplesPerTuple = 200,
                BeaconMinDurationSeconds = 120,
                BeaconTrimPercent = 0.1,

                // C2 thresholds
                C2ToleranceSeconds = 8.0,
                C2MinIntervalSeconds = 30,
                C2MaxIntervalSeconds = 1800,
                C2MinOccurrences = 2,
                C2MinPatternEvents = 4,
                C2MinGroupSize = 3,

                // Privilege escalation thresholds
                EnablePrivilegeEscalationDetection = true,
                PrivilegeSpikeWindowMinutes = 10,
                PrivilegeSpikeMinAttempts = 4,
                PrivilegeSweepMinDistinctPorts = 2,

                InterfaceHoppingWindowMinutes = 10,
                MacSpoofingWindowMinutes = 10,

                PacketSizeLargeThreshold = 2000,
                PacketSizeSmallThreshold = 60,
                PacketSizeMinForAnalysis = 5,
                PacketSizeConsistencyPercent = 60,
                PacketSizeMinConsistentCount = 5,
                PacketSizeVarianceRatio = 0.4,
                PacketSizeMinAvgForVariance = 80,

                AdminPorts = adminPorts,
                DisallowedOutboundPorts = disallowedOutbound,

                MaxFindingsPerDetector = 100,
                MinSeverityToShow = Severity.Info
            },
            _ => throw new ArgumentOutOfRangeException(nameof(level), level, null)
        };
    }
}
