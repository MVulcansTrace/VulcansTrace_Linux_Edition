namespace VulcansTrace.Linux.Agent.Scheduling;

/// <summary>
/// Persistence for recurring audit schedules.
/// </summary>
public interface IScheduleStore
{
    /// <summary>Optional warning if persistence failed to load.</summary>
    string? PersistenceWarning { get; }

    /// <summary>Returns all schedules.</summary>
    IReadOnlyList<AuditSchedule> GetAll();

    /// <summary>Returns a single schedule by ID, or null if not found.</summary>
    AuditSchedule? GetById(string id);

    /// <summary>Saves or updates a schedule.</summary>
    void Save(AuditSchedule schedule);

    /// <summary>Removes a schedule by ID.</summary>
    void Delete(string id);
}
