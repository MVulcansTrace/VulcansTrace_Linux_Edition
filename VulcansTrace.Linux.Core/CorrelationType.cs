namespace VulcansTrace.Linux.Core;

/// <summary>
/// Describes the nature of a correlation between two findings.
/// </summary>
public enum CorrelationType
{
    /// <summary>Findings indicate an escalation pattern (e.g., beaconing followed by lateral movement).</summary>
    EscalatesTo,

    /// <summary>Findings share the same source host but are not necessarily part of a known kill-chain pair.</summary>
    SameHost,

    /// <summary>Findings follow each other in temporal sequence across the same host.</summary>
    TemporalSequence
}
