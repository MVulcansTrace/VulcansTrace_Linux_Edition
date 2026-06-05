using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine.LogDiff;

/// <summary>
/// Represents a connection pattern grouped for responder diffing and how it changed
/// between a baseline and an incident analysis.
/// </summary>
public sealed record DiffEvent
{
    /// <summary>The traffic pattern key that groups this diff record. Source port is wildcarded because it is commonly ephemeral.</summary>
    public required string ConnectionKey { get; init; }

    /// <summary>The diff state for this connection pattern.</summary>
    public required LogDiffState State { get; init; }

    /// <summary>Number of events in the baseline for this key.</summary>
    public int BaselineCount { get; init; }

    /// <summary>Number of events in the incident for this key.</summary>
    public int IncidentCount { get; init; }

    /// <summary>Source IP address extracted from a representative event.</summary>
    public string SourceIP { get; init; } = string.Empty;

    /// <summary>Destination IP address extracted from a representative event.</summary>
    public string DestinationIP { get; init; } = string.Empty;

    /// <summary>Source port extracted from a representative event.</summary>
    public int SourcePort { get; init; }

    /// <summary>Destination port extracted from a representative event.</summary>
    public int DestinationPort { get; init; }

    /// <summary>Protocol extracted from a representative event.</summary>
    public string Protocol { get; init; } = string.Empty;

    /// <summary>First timestamp for this key in the baseline (or <see cref="DateTime.MinValue"/> if absent).</summary>
    public DateTime BaselineFirstSeen { get; init; }

    /// <summary>Last timestamp for this key in the baseline (or <see cref="DateTime.MinValue"/> if absent).</summary>
    public DateTime BaselineLastSeen { get; init; }

    /// <summary>First timestamp for this key in the incident (or <see cref="DateTime.MinValue"/> if absent).</summary>
    public DateTime IncidentFirstSeen { get; init; }

    /// <summary>Last timestamp for this key in the incident (or <see cref="DateTime.MinValue"/> if absent).</summary>
    public DateTime IncidentLastSeen { get; init; }

    /// <summary>Action distribution in the baseline.</summary>
    public IReadOnlyDictionary<string, int> BaselineActions { get; init; } = new Dictionary<string, int>();

    /// <summary>Action distribution in the incident.</summary>
    public IReadOnlyDictionary<string, int> IncidentActions { get; init; } = new Dictionary<string, int>();

    /// <summary>Human-readable count delta description.</summary>
    public string CountDelta => $"{BaselineCount} → {IncidentCount}";

    /// <summary>The dominant action in the baseline.</summary>
    public string BaselineDominantAction
    {
        get
        {
            if (BaselineActions.Count == 0) return "—";
            return BaselineActions.OrderByDescending(kvp => kvp.Value).First().Key;
        }
    }

    /// <summary>The dominant action in the incident.</summary>
    public string IncidentDominantAction
    {
        get
        {
            if (IncidentActions.Count == 0) return "—";
            return IncidentActions.OrderByDescending(kvp => kvp.Value).First().Key;
        }
    }

    /// <summary>The dominant action in the incident (or baseline for Removed). Prefer <see cref="BaselineDominantAction"/> and <see cref="IncidentDominantAction"/> for side-specific display.</summary>
    public string DominantAction
    {
        get
        {
            var actions = State == LogDiffState.Removed ? BaselineActions : IncidentActions;
            if (actions.Count == 0) return "UNKNOWN";
            return actions.OrderByDescending(kvp => kvp.Value).First().Key;
        }
    }
}
