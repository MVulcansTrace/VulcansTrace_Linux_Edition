namespace VulcansTrace.Linux.Engine;

/// <summary>
/// Defines the sensitivity level for threat detection analysis.
/// </summary>
/// <remarks>
/// Higher intensity levels detect more subtle threats but may produce more findings.
/// </remarks>
public enum IntensityLevel
{
    /// <summary>Conservative detection with high thresholds. Fewer findings, higher confidence.</summary>
    Low,

    /// <summary>Balanced detection with moderate thresholds. Good for general use.</summary>
    Medium,

    /// <summary>Aggressive detection with low thresholds. More findings, may include noise.</summary>
    High
}