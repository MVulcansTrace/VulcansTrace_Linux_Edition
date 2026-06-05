namespace VulcansTrace.Linux.Engine.LogDiff;

/// <summary>
/// Represents the state of a diffed item when comparing two analysis results.
/// </summary>
public enum LogDiffState
{
    /// <summary>The item is present in the incident result but not in the baseline.</summary>
    Added,

    /// <summary>The item is present in the baseline result but not in the incident.</summary>
    Removed,

    /// <summary>The item exists in both results but has materially changed (e.g., count delta or action shift).</summary>
    Changed,

    /// <summary>The item exists in both results with no material change.</summary>
    Unchanged
}
