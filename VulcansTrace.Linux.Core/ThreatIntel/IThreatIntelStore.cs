namespace VulcansTrace.Linux.Core.ThreatIntel;

/// <summary>
/// Defines storage and retrieval of imported threat intelligence IOCs.
/// </summary>
public interface IThreatIntelStore
{
    /// <summary>Imports a batch of IOCs, replacing any existing entries with the same key.</summary>
    /// <param name="entries">The IOCs to import.</param>
    void Import(IEnumerable<IocEntry> entries);

    /// <summary>Removes all stored IOCs.</summary>
    void Clear();

    /// <summary>Total number of stored IOCs.</summary>
    int Count { get; }

    /// <summary>Number of stored IOCs of a specific type.</summary>
    /// <param name="type">The IOC type to count.</param>
    int CountByType(IocType type);

    /// <summary>Gets all IOCs of a specific type.</summary>
    /// <param name="type">The IOC type to retrieve.</param>
    IReadOnlyList<IocEntry> GetByType(IocType type);

    /// <summary>Gets all stored IOCs.</summary>
    IReadOnlyList<IocEntry> GetAll();

    /// <summary>Warning message if persistence is unavailable.</summary>
    string? PersistenceWarning { get; }
}
