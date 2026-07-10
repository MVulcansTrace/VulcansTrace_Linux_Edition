using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// Provides a browsable catalog of all registered security rules.
/// </summary>
public sealed class RuleCatalog
{
    private readonly IReadOnlyList<RuleCatalogItem> _items;

    /// <summary>
    /// Initializes a new instance of the <see cref="RuleCatalog"/> class.
    /// </summary>
    /// <param name="rules">The rules to expose in the catalog.</param>
    public RuleCatalog(IEnumerable<IRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        _items = rules.Select(r => new RuleCatalogItem
        {
            Id = r.Id,
            Category = r.Category,
            Description = r.Description,
            WhatItChecks = r.WhatItChecks,
            Severity = r.Severity,
            SupportedDataSources = r.SupportedDataSources,
            ExplanationKey = r.Id,
            CisMappings = r.CisMappings,
            MitreTechniques = r.MitreTechniques
        }).ToList();
    }

    /// <summary>
    /// Gets all catalog items.
    /// </summary>
    public IReadOnlyList<RuleCatalogItem> Items => _items;

    /// <summary>
    /// Gets items filtered by a search term (matches Id, Category or its display label, Description, WhatItChecks, or DataSources).
    /// </summary>
    /// <param name="search">The search term (case-insensitive).</param>
    /// <returns>Matching catalog items.</returns>
    public IEnumerable<RuleCatalogItem> Search(string search)
    {
        if (string.IsNullOrWhiteSpace(search))
            return _items;

        var term = search.Trim();
        return _items.Where(i =>
            i.Id.Contains(term, StringComparison.OrdinalIgnoreCase) ||
            i.Category.Contains(term, StringComparison.OrdinalIgnoreCase) ||
            CategoryDisplay.ToDisplayName(i.Category).Contains(term, StringComparison.OrdinalIgnoreCase) ||
            i.Description.Contains(term, StringComparison.OrdinalIgnoreCase) ||
            i.WhatItChecks.Contains(term, StringComparison.OrdinalIgnoreCase) ||
            i.SupportedDataSources.Any(ds => ds.Contains(term, StringComparison.OrdinalIgnoreCase)) ||
            i.MitreTechniques.Any(m => m.TechniqueId.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                                       m.TechniqueName.Contains(term, StringComparison.OrdinalIgnoreCase)));
    }
}
