namespace VulcansTrace.Linux.Agent.Findings;

/// <summary>
/// Defines storage and retrieval of pinned findings.
/// </summary>
public interface IPinnedFindingStore
{
    /// <summary>
    /// Pins a finding. If a finding with the same fingerprint already exists, it is replaced.
    /// </summary>
    /// <param name="finding">The finding to pin.</param>
    void Pin(PinnedFinding finding);

    /// <summary>
    /// Removes the pinned finding with the specified fingerprint, if it exists.
    /// </summary>
    /// <param name="fingerprint">The stable fingerprint of the finding to unpin.</param>
    void Unpin(string fingerprint);

    /// <summary>
    /// Checks whether a finding with the specified fingerprint is pinned.
    /// </summary>
    /// <param name="fingerprint">The stable fingerprint to check.</param>
    /// <returns>True if pinned; otherwise, false.</returns>
    bool IsPinned(string fingerprint);

    /// <summary>
    /// Gets all pinned findings, ordered by most recently pinned first.
    /// </summary>
    IReadOnlyList<PinnedFinding> GetAll();

    /// <summary>
    /// Gets the latest persistence warning, if pins could not be stored durably.
    /// </summary>
    string? PersistenceWarning { get; }
}
