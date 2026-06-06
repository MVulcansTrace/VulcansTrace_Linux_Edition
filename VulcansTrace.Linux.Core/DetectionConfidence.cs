namespace VulcansTrace.Linux.Core;

/// <summary>
/// Confidence level assigned to a detection finding, independent of severity.
/// </summary>
public enum DetectionConfidence
{
    Unknown,
    Low,
    Medium,
    High,
    Confirmed
}
