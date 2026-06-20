using System.Collections.Immutable;
using VulcansTrace.Linux.Agent.Query;

namespace VulcansTrace.Linux.Agent.Memory;

/// <summary>
/// Records which audit categories have been checked and computes blind spots
/// relative to the full category catalog.
/// </summary>
public sealed class CategoryCoverageRecorder
{
    /// <summary>
    /// Updates the coverage history with the category (or all categories for a full audit)
    /// represented by <paramref name="intent"/>.
    /// </summary>
    public IReadOnlyList<CategoryAuditEntry> Record(
        AgentIntent intent,
        DateTime timestampUtc,
        IReadOnlyList<CategoryAuditEntry> existing)
    {
        if (!IntentCategoryMap.IsAuditIntent(intent))
            return existing;

        var builder = existing.ToList();

        if (IntentCategoryMap.IsFullAudit(intent))
        {
            foreach (var category in IntentCategoryMap.AllCategories)
            {
                Upsert(builder, category, timestampUtc);
            }
        }
        else if (IntentCategoryMap.GetCategory(intent) is { } category)
        {
            Upsert(builder, category, timestampUtc);
        }

        return builder.ToImmutableList();
    }

    /// <summary>
    /// Returns the set of categories that have never been recorded as audited.
    /// </summary>
    public static IReadOnlyList<string> GetUncheckedCategories(IEnumerable<CategoryAuditEntry> checkedCategories)
    {
        var checkedSet = checkedCategories.Select(c => c.Category).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return IntentCategoryMap.AllCategories
            .Where(c => !checkedSet.Contains(c))
            .ToList();
    }

    /// <summary>
    /// Returns the distinct categories that have been recorded as audited, ordered alphabetically.
    /// </summary>
    public static IReadOnlyList<string> GetCheckedCategories(IEnumerable<CategoryAuditEntry> checkedCategories)
    {
        return checkedCategories
            .Select(c => c.Category)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(c => c, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static void Upsert(List<CategoryAuditEntry> builder, string category, DateTime timestampUtc)
    {
        var index = builder.FindIndex(e => e.Category.Equals(category, StringComparison.OrdinalIgnoreCase));
        var entry = new CategoryAuditEntry { Category = category, UtcTimestamp = timestampUtc };

        if (index >= 0)
        {
            builder[index] = entry;
        }
        else
        {
            builder.Add(entry);
        }
    }
}
