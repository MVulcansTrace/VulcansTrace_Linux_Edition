using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Avalonia.Services;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Filters available for the suppression review queue.
/// </summary>
public enum ReviewFilter
{
    AllNeedingReview,
    ExpiringSoon,
    ExpiredRecently,
    Permanent,
    StalePermanent
}

/// <summary>
/// Represents a single suppression entry in the review queue with its computed category.
/// </summary>
public sealed class ReviewItem
{
    /// <summary>The underlying suppression entry.</summary>
    public SuppressionEntry Entry { get; }

    /// <summary>The review category assigned to this entry.</summary>
    public ReviewFilter Category { get; }

    /// <summary>A human-readable status label.</summary>
    public string StatusLabel { get; }

    /// <summary>Background color for the status badge.</summary>
    public string StatusBackground { get; }

    /// <summary>Foreground color for the status badge.</summary>
    public string StatusForeground { get; }

    /// <summary>Whether this entry can be renewed (has an expiry).</summary>
    public bool CanRenew => Entry.ExpiresAt.HasValue;

    /// <summary>
    /// Initializes a new instance of the <see cref="ReviewItem"/> class.
    /// </summary>
    public ReviewItem(SuppressionEntry entry, ReviewFilter category, string statusLabel, string statusBackground, string statusForeground)
    {
        Entry = entry;
        Category = category;
        StatusLabel = statusLabel;
        StatusBackground = statusBackground;
        StatusForeground = statusForeground;
    }
}

/// <summary>
/// ViewModel for managing and displaying active rule suppressions and the review queue.
/// </summary>
public sealed class SuppressionViewModel : ViewModelBase
{
    private readonly ISuppressionStore _store;
    private readonly IDialogService _dialogService;
    private string _statusMessage = "";
    private ReviewFilter _selectedReviewFilter = ReviewFilter.AllNeedingReview;

    /// <summary>Gets the collection of active suppression entries.</summary>
    public ObservableCollection<SuppressionEntry> Entries { get; } = new();

    /// <summary>Gets the collection of review queue items.</summary>
    public ObservableCollection<ReviewItem> ReviewQueueItems { get; } = new();

    /// <summary>Gets the available review filters.</summary>
    public ObservableCollection<ReviewFilter> ReviewFilters { get; } = new();

    /// <summary>Gets or sets the selected review filter.</summary>
    public ReviewFilter SelectedReviewFilter
    {
        get => _selectedReviewFilter;
        set
        {
            if (SetField(ref _selectedReviewFilter, value))
            {
                RefreshReviewQueue();
            }
        }
    }

    /// <summary>Gets the count of items currently shown in the review queue.</summary>
    public int ReviewQueueCount => ReviewQueueItems.Count;

    /// <summary>Gets or sets a status message about the last suppression action.</summary>
    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetField(ref _statusMessage, value);
    }

    /// <summary>Gets the command to remove a suppression entry.</summary>
    public RelayCommand RemoveSuppressionCommand { get; }

    /// <summary>Gets the command to renew a suppression entry.</summary>
    public AsyncRelayCommand RenewSuppressionCommand { get; }

    /// <summary>Gets the command to convert a suppression entry's duration.</summary>
    public AsyncRelayCommand ConvertDurationCommand { get; }

    /// <summary>Gets the command to edit a suppression entry's reason.</summary>
    public AsyncRelayCommand EditReasonCommand { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SuppressionViewModel"/> class.
    /// </summary>
    /// <param name="store">The suppression store to read from and write to.</param>
    /// <param name="dialogService">The dialog service for user interactions.</param>
    public SuppressionViewModel(ISuppressionStore store, IDialogService dialogService)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));

        RemoveSuppressionCommand = new RelayCommand(
            param =>
            {
                var entry = param as SuppressionEntry ?? (param as ReviewItem)?.Entry;
                if (entry != null)
                {
                    _store.Remove(entry.RuleId, entry.Target);
                    Refresh();
                    StatusMessage = _store.PersistenceWarning ?? $"Removed suppression for {entry.RuleId} ({entry.Target}).";
                }
            },
            _ => true);

        RenewSuppressionCommand = new AsyncRelayCommand(
            async param =>
            {
                if (param is ReviewItem item)
                {
                    await RenewOrConvertAsync(item.Entry, isRenewal: true);
                }
            },
            _ => true,
            ex => StatusMessage = $"Renew failed: {ex.Message}");

        ConvertDurationCommand = new AsyncRelayCommand(
            async param =>
            {
                if (param is ReviewItem item)
                {
                    await RenewOrConvertAsync(item.Entry, isRenewal: false);
                }
            },
            _ => true,
            ex => StatusMessage = $"Convert failed: {ex.Message}");

        EditReasonCommand = new AsyncRelayCommand(
            async param =>
            {
                if (param is not ReviewItem item)
                    return;

                var newReason = await _dialogService.ShowInputDialogAsync(
                    "Edit Reason",
                    $"Edit reason for {item.Entry.RuleId} on {item.Entry.Target}:",
                    item.Entry.Reason);

                if (newReason == null)
                    return;

                _store.Remove(item.Entry.RuleId, item.Entry.Target);
                _store.Add(item.Entry with { Reason = string.IsNullOrWhiteSpace(newReason) ? "Accepted by user" : newReason });
                Refresh();
                StatusMessage = _store.PersistenceWarning ?? $"Updated reason for {item.Entry.RuleId} ({item.Entry.Target}).";
            },
            _ => true,
            ex => StatusMessage = $"Edit reason failed: {ex.Message}");

        foreach (ReviewFilter filter in Enum.GetValues(typeof(ReviewFilter)))
        {
            ReviewFilters.Add(filter);
        }
    }

    /// <summary>
    /// Adds a suppression for the specified rule and target with an optional expiry duration.
    /// </summary>
    public void AddSuppression(
        string ruleId,
        string target,
        string reason,
        SuppressionDuration duration = SuppressionDuration.Permanent,
        string? fingerprint = null)
    {
        var now = DateTime.UtcNow;
        var expiresAt = duration switch
        {
            SuppressionDuration.Days7 => now.AddDays(7),
            SuppressionDuration.Days30 => now.AddDays(30),
            SuppressionDuration.Days90 => now.AddDays(90),
            _ => (DateTime?)null
        };

        var reviewDate = duration switch
        {
            SuppressionDuration.Days7 => now.AddDays(7),
            SuppressionDuration.Days30 => now.AddDays(30),
            SuppressionDuration.Days90 => now.AddDays(90),
            _ => (DateTime?)null
        };

        _store.Add(new SuppressionEntry
        {
            RuleId = ruleId,
            Target = target,
            Reason = string.IsNullOrWhiteSpace(reason) ? "Accepted by user" : reason,
            CreatedAt = now,
            ExpiresAt = expiresAt,
            ReviewDate = reviewDate,
            Fingerprint = fingerprint
        });
        Refresh();

        var expiryText = expiresAt.HasValue ? $" (expires {expiresAt.Value:yyyy-MM-dd})" : " (permanent)";
        StatusMessage = _store.PersistenceWarning ?? $"Accepted risk: {ruleId} ({target}){expiryText}.";
    }

    /// <summary>
    /// Refreshes the entries list and review queue from the store.
    /// </summary>
    public void Refresh()
    {
        Entries.Clear();
        foreach (var entry in _store.GetAll())
        {
            Entries.Add(entry);
        }

        RefreshReviewQueue();

        if (!string.IsNullOrWhiteSpace(_store.PersistenceWarning))
        {
            StatusMessage = _store.PersistenceWarning;
        }
    }

    /// <summary>
    /// Refreshes the review queue based on the current filter.
    /// </summary>
    public void RefreshReviewQueue()
    {
        ReviewQueueItems.Clear();
        var now = DateTime.UtcNow;

        var raw = _store.GetAllRaw();
        var items = new List<ReviewItem>();

        foreach (var entry in raw)
        {
            if (TryCategorize(entry, now, out var item))
            {
                items.Add(item);
            }
        }

        // Sort by urgency
        items.Sort((a, b) =>
        {
            var orderA = GetUrgencyOrder(a.Category);
            var orderB = GetUrgencyOrder(b.Category);
            if (orderA != orderB)
                return orderA.CompareTo(orderB);

            // Within same category, sort by ExpiresAt (soonest first) or CreatedAt (oldest first)
            if (a.Category == ReviewFilter.ExpiringSoon || a.Category == ReviewFilter.ExpiredRecently)
            {
                var expA = a.Entry.ExpiresAt ?? DateTime.MaxValue;
                var expB = b.Entry.ExpiresAt ?? DateTime.MaxValue;
                return expA.CompareTo(expB);
            }
            return a.Entry.CreatedAt.CompareTo(b.Entry.CreatedAt);
        });

        foreach (var item in items)
        {
            if (_selectedReviewFilter == ReviewFilter.AllNeedingReview || item.Category == _selectedReviewFilter)
            {
                ReviewQueueItems.Add(item);
            }
        }

        OnPropertyChanged(nameof(ReviewQueueCount));
    }

    private static bool TryCategorize(SuppressionEntry entry, DateTime now, out ReviewItem item)
    {
        item = null!;

        if (entry.ExpiresAt.HasValue)
        {
            var expires = entry.ExpiresAt.Value;
            var daysUntilExpiry = (expires - now).TotalDays;

            if (expires <= now && daysUntilExpiry > -SuppressionRetentionPolicy.ExpiredRetentionDays)
            {
                item = new ReviewItem(entry, ReviewFilter.ExpiredRecently, "Expired recently", "#7f1d1d", "#fecaca");
                return true;
            }

            if (expires > now && daysUntilExpiry <= 7)
            {
                item = new ReviewItem(entry, ReviewFilter.ExpiringSoon, "Expiring soon", "#854d0e", "#fde047");
                return true;
            }

            // Active but not expiring soon — not shown in review queue
            return false;
        }

        // Permanent
        var ageDays = (now - entry.CreatedAt).TotalDays;
        if (ageDays > 90)
        {
            item = new ReviewItem(entry, ReviewFilter.StalePermanent, "Stale permanent", "#3f1515", "#fca5a5");
            return true;
        }

        item = new ReviewItem(entry, ReviewFilter.Permanent, "Permanent", "#1e293b", "#94a3b8");
        return true;
    }

    private static int GetUrgencyOrder(ReviewFilter category) => category switch
    {
        ReviewFilter.ExpiredRecently => 0,
        ReviewFilter.ExpiringSoon => 1,
        ReviewFilter.StalePermanent => 2,
        ReviewFilter.Permanent => 3,
        _ => 4
    };

    private async Task RenewOrConvertAsync(SuppressionEntry entry, bool isRenewal)
    {
        var durationOptions = new[] { "7 days", "30 days", "90 days", "Permanent" };
        var title = isRenewal ? "Renew Suppression" : "Convert Duration";
        var message = isRenewal
            ? $"Renew {entry.RuleId} on {entry.Target}. Select duration:"
            : $"Convert duration for {entry.RuleId} on {entry.Target}. Select new duration:";

        var defaultIndex = entry.ExpiresAt.HasValue
            ? (entry.ExpiresAt.Value - entry.CreatedAt) switch
            {
                TimeSpan ts when ts.TotalDays <= 8 => 0,
                TimeSpan ts when ts.TotalDays <= 32 => 1,
                TimeSpan ts when ts.TotalDays <= 92 => 2,
                _ => 1
            }
            : 3;

        var durationIndex = await _dialogService.ShowSelectionDialogAsync(title, message, durationOptions, defaultIndex);
        if (durationIndex == null)
            return;

        var duration = durationIndex.Value switch
        {
            0 => SuppressionDuration.Days7,
            1 => SuppressionDuration.Days30,
            2 => SuppressionDuration.Days90,
            _ => SuppressionDuration.Permanent
        };

        var now = DateTime.UtcNow;
        var expiresAt = duration switch
        {
            SuppressionDuration.Days7 => now.AddDays(7),
            SuppressionDuration.Days30 => now.AddDays(30),
            SuppressionDuration.Days90 => now.AddDays(90),
            _ => (DateTime?)null
        };

        var reviewDate = duration switch
        {
            SuppressionDuration.Days7 => now.AddDays(7),
            SuppressionDuration.Days30 => now.AddDays(30),
            SuppressionDuration.Days90 => now.AddDays(90),
            _ => (DateTime?)null
        };

        _store.Remove(entry.RuleId, entry.Target);
        _store.Add(new SuppressionEntry
        {
            RuleId = entry.RuleId,
            Target = entry.Target,
            Reason = entry.Reason,
            CreatedAt = now,
            ExpiresAt = expiresAt,
            ReviewDate = reviewDate,
            Fingerprint = entry.Fingerprint
        });
        Refresh();

        var action = isRenewal ? "Renewed" : "Converted";
        var expiryText = expiresAt.HasValue ? $" (expires {expiresAt.Value:yyyy-MM-dd})" : " (permanent)";
        StatusMessage = _store.PersistenceWarning ?? $"{action}: {entry.RuleId} ({entry.Target}){expiryText}.";
    }
}
