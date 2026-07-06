using System;
using System.Collections.Generic;
using System.Linq;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Default chat-filter implementation. User and info messages are always visible; finding messages
/// are filtered by severity, category, and an optional substring search over text and details.
/// </summary>
internal sealed class DefaultChatFilter : IChatFilter
{
    public void Apply(
        IReadOnlyList<AgentMessageViewModel> messages,
        SeverityFilterOption? severityFilter,
        string? categoryFilter,
        string? searchQuery)
    {
        var searchEmpty = string.IsNullOrWhiteSpace(searchQuery);

        foreach (var msg in messages)
        {
            if (msg == null)
                continue;

            bool visible;
            if (msg.IsUser || msg.IsInfo || string.IsNullOrEmpty(msg.Category))
            {
                visible = true;
            }
            else
            {
                var severityOk = true;
                var categoryOk = true;

                if (severityFilter != null)
                {
                    if (severityFilter.MinSeverity == Severity.High && msg.Severity < Severity.High)
                        severityOk = false;
                    if (severityFilter.MinSeverity == Severity.Critical && msg.Severity < Severity.Critical)
                        severityOk = false;
                }

                if (!IsAllCategoryFilter(categoryFilter) && !msg.Category.Equals(categoryFilter, StringComparison.OrdinalIgnoreCase))
                    categoryOk = false;

                visible = severityOk && categoryOk;
            }

            if (visible && !searchEmpty && !MatchesSearch(msg, searchQuery!))
                visible = false;

            msg.IsVisible = visible;
        }
    }

    private static bool MatchesSearch(AgentMessageViewModel msg, string searchQuery)
    {
        if (string.IsNullOrWhiteSpace(searchQuery))
            return true;

        return msg.Text.Contains(searchQuery, StringComparison.OrdinalIgnoreCase)
            || msg.Details.Contains(searchQuery, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAllCategoryFilter(string? categoryFilter) =>
        string.IsNullOrWhiteSpace(categoryFilter)
            || categoryFilter.Equals(ChatFilterConstants.AllCategoriesFilter, StringComparison.OrdinalIgnoreCase);
}
