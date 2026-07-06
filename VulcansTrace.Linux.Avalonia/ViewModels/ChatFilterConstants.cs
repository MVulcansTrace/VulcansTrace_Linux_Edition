namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Shared constants for chat filtering so the "no filter" sentinel stays consistent
/// across the presenter, the filter implementation, and the view model.
/// </summary>
public static class ChatFilterConstants
{
    /// <summary>
    /// The category filter value that means "do not filter by category".
    /// </summary>
    public const string AllCategoriesFilter = "All categories";
}
