using System;
using System.Collections.ObjectModel;
using VulcansTrace.Linux.Agent.Rules;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for managing and displaying active rule suppressions.
/// </summary>
public sealed class SuppressionViewModel : ViewModelBase
{
    private readonly ISuppressionStore _store;
    private string _statusMessage = "";

    /// <summary>Gets the collection of active suppression entries.</summary>
    public ObservableCollection<SuppressionEntry> Entries { get; } = new();

    /// <summary>Gets or sets a status message about the last suppression action.</summary>
    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetField(ref _statusMessage, value);
    }

    /// <summary>Gets the command to remove a suppression entry.</summary>
    public RelayCommand RemoveSuppressionCommand { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SuppressionViewModel"/> class.
    /// </summary>
    /// <param name="store">The suppression store to read from and write to.</param>
    public SuppressionViewModel(ISuppressionStore store)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        RemoveSuppressionCommand = new RelayCommand(
            param =>
            {
                if (param is SuppressionEntry entry)
                {
                    _store.Remove(entry.RuleId, entry.Target);
                    Refresh();
                    StatusMessage = _store.PersistenceWarning ?? $"Removed suppression for {entry.RuleId} ({entry.Target}).";
                }
            },
            _ => true);
    }

    /// <summary>
    /// Adds a suppression for the specified rule and target.
    /// </summary>
    public void AddSuppression(string ruleId, string target, string reason)
    {
        _store.Add(new SuppressionEntry
        {
            RuleId = ruleId,
            Target = target,
            Reason = string.IsNullOrWhiteSpace(reason) ? "Accepted by user" : reason,
            CreatedAt = DateTime.UtcNow
        });
        Refresh();
        StatusMessage = _store.PersistenceWarning ?? $"Accepted risk: {ruleId} ({target}).";
    }

    /// <summary>
    /// Refreshes the entries list from the store.
    /// </summary>
    public void Refresh()
    {
        Entries.Clear();
        foreach (var entry in _store.GetAll())
        {
            Entries.Add(entry);
        }

        if (!string.IsNullOrWhiteSpace(_store.PersistenceWarning))
        {
            StatusMessage = _store.PersistenceWarning;
        }
    }
}
