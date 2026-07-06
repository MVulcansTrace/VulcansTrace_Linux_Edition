using System.Collections.Generic;
using VulcansTrace.Linux.Agent.Query;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Decides which chat messages are visible based on severity/category filters and a search query.
/// </summary>
internal interface IChatFilter
{
    /// <summary>
    /// Applies the current filters to all messages and sets each message's <see cref="AgentMessageViewModel.IsVisible"/> property.
    /// </summary>
    /// <param name="messages">The messages to evaluate. The collection may be enumerated more than once; callers should snapshot it if necessary.</param>
    /// <param name="severityFilter">Optional minimum severity filter.</param>
    /// <param name="categoryFilter">Optional category filter.</param>
    /// <param name="searchQuery">Optional substring search query.</param>
    void Apply(
        IReadOnlyList<AgentMessageViewModel> messages,
        SeverityFilterOption? severityFilter,
        string? categoryFilter,
        string? searchQuery);
}
