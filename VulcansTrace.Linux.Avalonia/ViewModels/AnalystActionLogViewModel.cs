using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Avalonia.Threading;
using VulcansTrace.Linux.Agent.Actions;
using VulcansTrace.Linux.Avalonia.Services;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// A read-only view model wrapper for a single analyst action log entry.
/// </summary>
public sealed class AnalystActionEntryViewModel : ViewModelBase
{
    /// <summary>Initializes a new instance from the underlying entry.</summary>
    public AnalystActionEntryViewModel(AnalystActionEntry entry)
    {
        Entry = entry;
    }

    /// <summary>Gets the underlying entry.</summary>
    public AnalystActionEntry Entry { get; }

    /// <summary>Gets the local timestamp.</summary>
    public DateTime Timestamp => Entry.TimestampUtc.ToLocalTime();

    /// <summary>Gets the actor.</summary>
    public string Actor => Entry.Actor;

    /// <summary>Gets the action type.</summary>
    public string ActionType => Entry.ActionType;

    /// <summary>Gets the optional target.</summary>
    public string? Target => Entry.Target;

    /// <summary>Gets the optional details.</summary>
    public string? Details => Entry.Details;

    /// <summary>Gets the optional severity.</summary>
    public string? Severity => Entry.Severity;
}

/// <summary>
/// ViewModel for reviewing, exporting, and clearing the analyst action audit log. Subscribes to the
/// store's <see cref="IAnalystActionStore.Changed"/> event so the grid stays current as actions are
/// logged from anywhere in the app, refreshing on the UI thread.
/// </summary>
public sealed class AnalystActionLogViewModel : ViewModelBase
{
    private readonly IAnalystActionStore _store;
    private readonly IDialogService _dialogService;
    private int _count;
    private string _statusMessage = "";

    /// <summary>Gets the displayed analyst action entries.</summary>
    public ObservableCollection<AnalystActionEntryViewModel> Entries { get; } = new();

    /// <summary>Gets or sets a status message about persistence or the last action.</summary>
    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetField(ref _statusMessage, value);
    }

    /// <summary>Gets the total number of entries currently in the store, cached from the last refresh.</summary>
    public int TotalCount => _count;

    /// <summary>Gets a value indicating whether any entries are shown.</summary>
    public bool HasEntries => _count > 0;

    /// <summary>Gets the command to refresh the entries from the store.</summary>
    public RelayCommand RefreshCommand { get; }

    /// <summary>Gets the command to clear all entries.</summary>
    public AsyncRelayCommand ClearCommand { get; }

    /// <summary>Gets the command to export the log to JSON.</summary>
    public AsyncRelayCommand ExportCommand { get; }

    /// <summary>Initializes a new instance of the <see cref="AnalystActionLogViewModel"/> class.</summary>
    public AnalystActionLogViewModel(IAnalystActionStore store, IDialogService dialogService)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));

        RefreshCommand = new RelayCommand(
            _ => Refresh(),
            _ => true);

        ClearCommand = new AsyncRelayCommand(
            async _ => await ClearAsync(),
            _ => TotalCount > 0,
            ex => StatusMessage = $"Clear failed: {ex.Message}");

        ExportCommand = new AsyncRelayCommand(
            async _ => await ExportAsync(),
            _ => TotalCount > 0,
            ex => StatusMessage = $"Export failed: {ex.Message}");

        _store.Changed += OnStoreChanged;
        Refresh();
    }

    /// <summary>
    /// Marshals a store change notification to the UI thread and refreshes. The store raises this on
    /// whichever thread the append ran (often a thread-pool thread via the logger), so the grid must
    /// only be rebuilt on the UI thread.
    /// </summary>
    private void OnStoreChanged(object? sender, EventArgs e)
    {
        if (Dispatcher.UIThread.CheckAccess())
            Refresh();
        else
            Dispatcher.UIThread.Post(Refresh);
    }

    /// <summary>
    /// Refreshes the displayed entries from the store.
    /// </summary>
    public void Refresh()
    {
        var entries = _store.GetAll();
        _count = entries.Count;

        Entries.Clear();
        foreach (var entry in entries.OrderByDescending(e => e.TimestampUtc))
        {
            Entries.Add(new AnalystActionEntryViewModel(entry));
        }

        OnPropertyChanged(nameof(TotalCount));
        OnPropertyChanged(nameof(HasEntries));
        ClearCommand.RaiseCanExecuteChanged();
        ExportCommand.RaiseCanExecuteChanged();
        StatusMessage = _store.PersistenceWarning ?? $"{TotalCount} analyst action(s) recorded.";
    }

    private async Task ClearAsync()
    {
        var confirm = await _dialogService.ShowSelectionDialogAsync(
            "Clear Analyst Action Log",
            $"Delete all {TotalCount} recorded analyst actions? This cannot be undone.",
            new[] { "Clear", "Cancel" },
            defaultIndex: 1);

        if (confirm != 0)
        {
            StatusMessage = "Clear cancelled.";
            return;
        }

        _store.Clear();
        StatusMessage = _store.PersistenceWarning ?? "Analyst action log cleared.";
    }

    private async Task ExportAsync()
    {
        var path = await _dialogService.ShowSaveFileDialogAsync(
            "Export Analyst Action Log",
            "JSON files (*.json)|*.json|All files (*.*)|*.*",
            $"analyst-actions-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json");

        if (path == null)
        {
            StatusMessage = "Export cancelled.";
            return;
        }

        var actions = _store.GetAll();
        // Match the store's serialization (PascalCase, WriteIndented) so an exported file can be
        // copied back into the config directory and reloaded without being quarantined.
        var json = JsonSerializer.Serialize(actions, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        await File.WriteAllTextAsync(path, json);
        StatusMessage = _store.PersistenceWarning ?? $"Exported {actions.Count} analyst action(s) to {path}.";
    }
}
