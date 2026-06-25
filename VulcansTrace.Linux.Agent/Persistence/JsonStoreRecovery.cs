using FluentValidation;
using VulcansTrace.Linux.Agent.Validation;

namespace VulcansTrace.Linux.Agent.Persistence;

/// <summary>
/// Encapsulates the common load-and-repair pattern used by JSON-backed stores:
/// load, partition into valid/rejected entries, quarantine the original file,
/// rewrite the live file with only valid entries, and produce a human-readable warning.
/// </summary>
internal static class JsonStoreRecovery
{
    /// <summary>
    /// Loads a list of entries from persistence, drops invalid ones, quarantines the original
    /// file, rewrites the live file with valid entries, and returns a result containing the
    /// survivors and an optional warning message.
    /// </summary>
    /// <typeparam name="T">The entry type.</typeparam>
    /// <param name="persistence">The file persistence helper.</param>
    /// <param name="validator">The validator for individual entries.</param>
    /// <param name="entryNoun">Singular noun used in warning messages (e.g., "baseline").</param>
    /// <param name="summarizeRejected">Optional function to summarize a rejected entry for the warning.</param>
    /// <returns>A result containing the valid entries and an optional warning.</returns>
    public static LoadAndRepairResult<T> LoadAndRepair<T>(
        JsonFilePersistence<List<T>> persistence,
        IValidator<T> validator,
        string entryNoun,
        Func<T, string>? summarizeRejected = null)
    {
        var entries = persistence.Load();
        if (entries == null)
        {
            return new LoadAndRepairResult<T>(new List<T>(), 0, null);
        }

        var valid = validator.PartitionValid(entries, out var rejected);
        if (rejected.Count == 0)
        {
            return new LoadAndRepairResult<T>(valid, 0, null);
        }

        var summary = BuildRejectedSummary(rejected, summarizeRejected);
        var quarantined = persistence.Quarantine();

        try
        {
            persistence.Save(valid);
            var preservationPhrase = quarantined is null
                ? "original could not be preserved"
                : "original preserved as a .corrupt file";
            var warning = $"Loaded {valid.Count} {Pluralize(entryNoun, valid.Count)}; {rejected.Count} invalid {Pluralize(entryNoun, rejected.Count)} were skipped: {summary} ({preservationPhrase}).";
            return new LoadAndRepairResult<T>(valid, rejected.Count, warning);
        }
        catch (Exception ex)
        {
            var warning = $"Loaded {valid.Count} {Pluralize(entryNoun, valid.Count)}; {rejected.Count} invalid {Pluralize(entryNoun, rejected.Count)} were skipped: {summary}; could not rewrite the live file: {ex.Message}";
            return new LoadAndRepairResult<T>(valid, rejected.Count, warning);
        }
    }

    private static string BuildRejectedSummary<T>(List<T> rejected, Func<T, string>? summarizeRejected)
    {
        if (summarizeRejected == null)
        {
            return $"{rejected.Count} rejected";
        }

        var summary = string.Join(", ", rejected.Take(3).Select(summarizeRejected));
        if (rejected.Count > 3)
        {
            summary += $", ... ({rejected.Count - 3} more)";
        }

        return summary;
    }

    private static string Pluralize(string noun, int count)
    {
        return count == 1 ? noun : $"{noun}s";
    }
}

/// <summary>
/// Result of a load-and-repair operation.
/// </summary>
/// <typeparam name="T">The entry type.</typeparam>
/// <param name="Valid">The valid entries that should populate the store.</param>
/// <param name="RejectedCount">The number of entries that failed validation.</param>
/// <param name="Warning">A warning message describing what happened, or null if nothing was rejected.</param>
internal sealed record LoadAndRepairResult<T>(List<T> Valid, int RejectedCount, string? Warning);
