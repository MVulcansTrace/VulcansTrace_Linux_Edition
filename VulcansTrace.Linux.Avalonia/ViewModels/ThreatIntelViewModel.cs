using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using VulcansTrace.Linux.Agent.Actions;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// A selectable filter option for IOC type.
/// </summary>
public sealed class IocTypeFilterOption
{
    /// <summary>Display label shown in the filter combo box.</summary>
    public string Label { get; }

    /// <summary>The IOC type to filter by, or <c>null</c> for all types.</summary>
    public IocType? Type { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="IocTypeFilterOption"/> class.
    /// </summary>
    public IocTypeFilterOption(string label, IocType? type)
    {
        Label = label;
        Type = type;
    }
}

/// <summary>
/// ViewModel for importing, reviewing, and managing imported threat-intelligence IOCs.
/// </summary>
public sealed class ThreatIntelViewModel : ViewModelBase
{
    private readonly IThreatIntelStore _store;
    private readonly IDialogService _dialogService;
    private readonly AnalystActionLogger? _analystActionLogger;
    private string _searchText = "";
    private IocTypeFilterOption _selectedTypeFilter = null!;
    private IocEntry? _selectedIoc;
    private string _statusMessage = "";
    private bool _isBusy;

    /// <summary>Gets the IOC entries currently shown after applying filters.</summary>
    public ObservableCollection<IocEntry> FilteredEntries { get; } = new();

    /// <summary>Gets all available IOC type filter options.</summary>
    public ObservableCollection<IocTypeFilterOption> TypeFilterOptions { get; } = new();

    /// <summary>Gets or sets the selected type filter.</summary>
    public IocTypeFilterOption SelectedTypeFilter
    {
        get => _selectedTypeFilter;
        set
        {
            if (SetField(ref _selectedTypeFilter, value))
            {
                ApplyFilter();
            }
        }
    }

    /// <summary>Gets or sets the search text used to filter IOCs.</summary>
    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetField(ref _searchText, value))
            {
                ApplyFilter();
            }
        }
    }

    /// <summary>Gets or sets the currently selected IOC.</summary>
    public IocEntry? SelectedIoc
    {
        get => _selectedIoc;
        set
        {
            if (SetField(ref _selectedIoc, value))
            {
                RemoveSelectedCommand.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>Gets or sets a status message describing the last action.</summary>
    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetField(ref _statusMessage, value);
    }

    /// <summary>Gets whether an import is in progress.</summary>
    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (SetField(ref _isBusy, value))
            {
                ImportCommand.RaiseCanExecuteChanged();
                ClearCommand.RaiseCanExecuteChanged();
                RemoveSelectedCommand.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>Gets the total number of IOCs currently stored.</summary>
    public int TotalCount => _store.Count;

    /// <summary>Gets the number of IOCs shown after filtering.</summary>
    public int FilteredCount => FilteredEntries.Count;

    /// <summary>Gets a value indicating whether any IOCs are shown after filtering.</summary>
    public bool HasFilteredEntries => FilteredEntries.Count > 0;

    /// <summary>Gets a value indicating whether there are no stored IOCs.</summary>
    public bool IsEmpty => TotalCount == 0;

    /// <summary>Gets the command to import IOCs from a JSON file.</summary>
    public AsyncRelayCommand ImportCommand { get; }

    /// <summary>Gets the command to remove the selected IOC.</summary>
    public AsyncRelayCommand RemoveSelectedCommand { get; }

    /// <summary>Gets the command to clear all stored IOCs.</summary>
    public AsyncRelayCommand ClearCommand { get; }

    /// <summary>Gets the command to refresh the view from the store.</summary>
    public RelayCommand RefreshCommand { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="ThreatIntelViewModel"/> class.
    /// </summary>
    public ThreatIntelViewModel(IThreatIntelStore store, IDialogService dialogService, AnalystActionLogger? analystActionLogger = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
        _analystActionLogger = analystActionLogger;

        TypeFilterOptions.Add(new IocTypeFilterOption("All types", null));
        foreach (IocType type in Enum.GetValues(typeof(IocType)))
        {
            TypeFilterOptions.Add(new IocTypeFilterOption(type.ToString(), type));
        }
        _selectedTypeFilter = TypeFilterOptions[0];

        ImportCommand = new AsyncRelayCommand(
            async _ => await ImportAsync(),
            _ => !IsBusy,
            ex => StatusMessage = $"Import failed: {ErrorSanitizer.SanitizeException(ex)}");

        RemoveSelectedCommand = new AsyncRelayCommand(
            async _ => await RemoveSelectedAsync(),
            _ => !IsBusy && SelectedIoc != null,
            ex => StatusMessage = $"Remove failed: {ErrorSanitizer.SanitizeException(ex)}");

        ClearCommand = new AsyncRelayCommand(
            async _ => await ClearAllAsync(),
            _ => !IsBusy && _store.Count > 0,
            ex => StatusMessage = $"Clear failed: {ErrorSanitizer.SanitizeException(ex)}");

        RefreshCommand = new RelayCommand(
            _ => Refresh(),
            _ => !IsBusy);

        Refresh();
    }

    /// <summary>
    /// Refreshes the filtered entries from the store and updates status/count properties.
    /// </summary>
    public void Refresh()
    {
        ApplyFilter();
        OnPropertyChanged(nameof(TotalCount));
        OnPropertyChanged(nameof(IsEmpty));
        ClearCommand.RaiseCanExecuteChanged();
        StatusMessage = _store.PersistenceWarning ?? (IsEmpty ? "No IOCs imported yet." : $"{TotalCount} {(TotalCount == 1 ? "IOC" : "IOCs")} loaded.");
    }

    /// <summary>
    /// Applies the current type and search filters to the store contents.
    /// </summary>
    public void ApplyFilter()
    {
        FilteredEntries.Clear();

        var query = _store.GetAll().AsEnumerable();

        if (SelectedTypeFilter?.Type.HasValue == true)
        {
            var type = SelectedTypeFilter.Type.Value;
            query = query.Where(e => e.Type == type);
        }

        var search = SearchText?.Trim();
        if (!string.IsNullOrWhiteSpace(search))
        {
            var comparison = StringComparison.OrdinalIgnoreCase;
            query = query.Where(e =>
                e.Value.Contains(search, comparison) ||
                e.Source.Contains(search, comparison) ||
                (e.Description?.Contains(search, comparison) ?? false) ||
                e.StorageKey.Contains(search, comparison));
        }

        foreach (var entry in query.OrderByDescending(e => e.ThreatScore).ThenBy(e => e.Value))
        {
            FilteredEntries.Add(entry);
        }

        OnPropertyChanged(nameof(FilteredCount));
        OnPropertyChanged(nameof(HasFilteredEntries));
    }

    private async Task RemoveSelectedAsync()
    {
        var selected = SelectedIoc;
        if (selected == null)
            return;

        var removed = _store.Remove(selected.StorageKey);
        SelectedIoc = null;
        Refresh();
        StatusMessage = _store.PersistenceWarning
            ?? (removed ? $"Removed {selected.Type} {selected.Value}." : "The selected IOC was already removed.");
        if (removed)
        {
            await (_analystActionLogger?.LogThreatIntelRemovedAsync("avalonia", selected.Type.ToString(), selected.Value) ?? Task.CompletedTask);
        }
    }

    private async Task ClearAllAsync()
    {
        var previousCount = _store.Count;
        _store.Clear();
        SelectedIoc = null;
        Refresh();
        StatusMessage = _store.PersistenceWarning ?? "Cleared all IOCs.";
        await (_analystActionLogger?.LogThreatIntelClearedAsync("avalonia", previousCount) ?? Task.CompletedTask);
    }

    private async Task ImportAsync()
    {
        var filePath = await _dialogService.ShowOpenFileDialogAsync(
            "Import Threat Intelligence",
            "JSON files (*.json)|*.json|All files (*.*)|*.*");

        if (string.IsNullOrWhiteSpace(filePath))
            return;

        if (!File.Exists(filePath))
        {
            StatusMessage = $"File not found: {filePath}";
            return;
        }

        var formatOptions = new[] { "Auto-detect", "STIX 2.1", "MISP JSON" };
        var formatIndex = await _dialogService.ShowSelectionDialogAsync(
            "Import Threat Intelligence",
            $"Importing: {Path.GetFileName(filePath)}\n\nSelect format:",
            formatOptions,
            defaultIndex: 0);

        if (formatIndex == null)
            return;

        var format = formatIndex.Value switch
        {
            1 => "stix",
            2 => "misp",
            _ => "auto"
        };

        var json = await File.ReadAllTextAsync(filePath);

        if (format == "auto")
        {
            if (ThreatIntelFormatDetector.TryDetect(json, out var detectedFormat))
            {
                format = detectedFormat == ThreatIntelBundleFormat.Stix ? "stix" : "misp";
            }
            else
            {
                StatusMessage = "Could not auto-detect format. Please select STIX 2.1 or MISP JSON.";
                return;
            }
        }

        ThreatIntelImportResult result;
        try
        {
            result = format switch
            {
                "stix" => StixParser.Parse(json),
                "misp" => MispParser.Parse(json),
                _ => throw new InvalidOperationException($"Unknown format: {format}")
            };
        }
        catch (Exception ex)
        {
            StatusMessage = $"Parse error: {ErrorSanitizer.SanitizeException(ex)}";
            return;
        }

        IsBusy = true;
        try
        {
            _store.Import(result.Entries);
            Refresh();

            StatusMessage = BuildImportStatusMessage(result, format, _store.PersistenceWarning);
            await (_analystActionLogger?.LogThreatIntelImportedAsync("avalonia", format, result.ImportedCount) ?? Task.CompletedTask);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private static string BuildImportStatusMessage(ThreatIntelImportResult result, string format, string? persistenceWarning)
    {
        var parts = new List<string>
        {
            $"Imported {result.ImportedCount} {(result.ImportedCount == 1 ? "IOC" : "IOCs")} from {format.ToUpperInvariant()} bundle."
        };

        if (result.SkippedCount > 0)
            parts[0] += $" Skipped: {result.SkippedCount}.";

        parts.AddRange(result.Warnings.Select(w => $"Warning: {w}"));

        if (!string.IsNullOrWhiteSpace(persistenceWarning))
            parts.Add($"Note: {persistenceWarning}");

        return string.Join(" ", parts);
    }
}
