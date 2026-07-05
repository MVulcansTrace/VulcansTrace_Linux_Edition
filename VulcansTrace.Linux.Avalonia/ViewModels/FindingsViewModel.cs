using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows.Input;
using VulcansTrace.Linux.Agent.Findings;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for displaying, filtering, and managing security findings.
/// </summary>
public sealed class FindingsViewModel : ViewModelBase
{
    private const int MaxParseErrorsToDisplay = 200;

    private readonly IPinnedFindingStore _pinnedFindingStore;
    private string _searchText = "";
    private SeverityFilterOption? _selectedSeverityFilter;
    private int _findingsCount;
    private int _highCriticalCount;
    private int _warningCount;
    private int _parseErrorCount;
    private int _skippedLineCount;
    private int _pinnedCount;
    private bool _showPinnedOnly;
    private bool _hasWarnings;
    private bool _hasParseErrors;
    private bool _hasLoadedResults;
    private FindingItemViewModel? _selectedItem;
    private ICommand? _investigateCommand;
    private ICommand? _suppressCommand;
    private ICommand? _resolveCommand;

    /// <summary>Gets the collection of findings to display.</summary>
    public ObservableCollection<FindingItemViewModel> Items { get; } = new();

    /// <summary>Gets the filtered view of findings (manual filtering)./// </summary>
    public ObservableCollection<FindingItemViewModel> FilteredItems { get; } = new();

    /// <summary>Gets the collection of parse errors.</summary>
    public ObservableCollection<string> ParseErrors { get; } = new();

    /// <summary>Gets the collection of warnings.</summary>
    public ObservableCollection<string> Warnings { get; } = new();

    /// <summary>Gets the available severity filter options.</summary>
    public ObservableCollection<SeverityFilterOption> SeverityFilters { get; } = new();

    /// <summary>Gets or sets the command used to investigate a finding via the Security Agent.</summary>
    public ICommand? InvestigateCommand
    {
        get => _investigateCommand;
        set => SetField(ref _investigateCommand, value);
    }

    /// <summary>Gets or sets the command used to suppress (accept risk for) a finding.</summary>
    public ICommand? SuppressCommand
    {
        get => _suppressCommand;
        set => SetField(ref _suppressCommand, value);
    }

    /// <summary>Gets or sets the command used to generate a remediation plan for a finding.</summary>
    public ICommand? ResolveCommand
    {
        get => _resolveCommand;
        set => SetField(ref _resolveCommand, value);
    }

    /// <summary>Gets the command used to pin a finding.</summary>
    public RelayCommand PinCommand { get; }

    /// <summary>Gets the command used to unpin a finding.</summary>
    public RelayCommand UnpinCommand { get; }

    /// <summary>Gets the command used to toggle the pinned-only filter.</summary>
    public RelayCommand TogglePinnedOnlyCommand { get; }

    /// <summary>Gets the command used to toggle pin/unpin on the selected finding.</summary>
    public RelayCommand TogglePinSelectedCommand { get; }

    /// <summary>Gets or sets whether only pinned findings are shown.</summary>
    public bool ShowPinnedOnly
    {
        get => _showPinnedOnly;
        set
        {
            if (SetField(ref _showPinnedOnly, value))
            {
                ApplyFilters();
                TogglePinnedOnlyCommand?.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>Gets the number of pinned findings currently in the store.</summary>
    public int PinnedCount
    {
        get => _pinnedCount;
        private set
        {
            if (SetField(ref _pinnedCount, value))
            {
                OnPropertyChanged(nameof(HasPinnedFindings));
                OnPropertyChanged(nameof(PinnedCountLabel));
                TogglePinnedOnlyCommand?.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>Gets whether there are any pinned findings.</summary>
    public bool HasPinnedFindings => PinnedCount > 0;

    /// <summary>Gets the formatted pinned count label for the toolbar button.</summary>
    public string PinnedCountLabel => PinnedCount > 0 ? $"({PinnedCount})" : string.Empty;

    /// <summary>Gets or sets the command invoked by the empty-state action button.</summary>
    public ICommand? EmptyStateActionCommand { get; set; }

    /// <summary>Gets or sets the text of the empty-state action button.</summary>
    public string EmptyStateActionText { get; set; } = "Analyze";

    /// <summary>Gets whether there are filtered findings to display.</summary>
    public bool HasData => FilteredItems.Count > 0;

    /// <summary>Gets whether any findings have been loaded, regardless of the active filter.</summary>
    public bool HasItems => Items.Count > 0;

    /// <summary>Gets whether findings exist but none match the current filter.</summary>
    public bool HasNoFilterMatches => Items.Count > 0 && FilteredItems.Count == 0;

    /// <summary>Gets whether an analysis or audit result has been loaded.</summary>
    public bool HasLoadedResults
    {
        get => _hasLoadedResults;
        private set
        {
            if (SetField(ref _hasLoadedResults, value))
            {
                RaiseEmptyStateText();
            }
        }
    }

    /// <summary>Gets the headline shown when no findings are available.</summary>
    public string EmptyStateHeadline => HasLoadedResults ? "No findings at this intensity" : "No findings yet";

    /// <summary>Gets the description shown when no findings are available.</summary>
    public string EmptyStateDescription => HasLoadedResults
        ? "The last run completed without displayable findings. Review warnings or parse errors, adjust filters, or try a higher intensity if you expected activity."
        : "Paste a firewall log and click Analyze to detect port scans, floods, and other suspicious activity.";

    /// <summary>Gets or sets the search text for filtering findings.</summary>
    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetField(ref _searchText, value))
            {
                ApplyFilters();
            }
        }
    }

    /// <summary>Gets or sets the selected severity filter.</summary>
    public SeverityFilterOption? SelectedSeverityFilter
    {
        get => _selectedSeverityFilter;
        set
        {
            if (SetField(ref _selectedSeverityFilter, value))
            {
                ApplyFilters();
            }
        }
    }

    /// <summary>Gets the total number of findings.</summary>
    public int FindingsCount
    {
        get => _findingsCount;
        private set => SetField(ref _findingsCount, value);
    }

    /// <summary>Gets the count of High and Critical severity findings.</summary>
    public int HighCriticalCount
    {
        get => _highCriticalCount;
        private set => SetField(ref _highCriticalCount, value);
    }

    /// <summary>Gets the number of warnings.</summary>
    public int WarningCount
    {
        get => _warningCount;
        private set
        {
            if (SetField(ref _warningCount, value))
            {
                HasWarnings = value > 0;
            }
        }
    }

    /// <summary>Gets the number of parse errors.</summary>
    public int ParseErrorCount
    {
        get => _parseErrorCount;
        private set
        {
            if (SetField(ref _parseErrorCount, value))
            {
                HasParseErrors = value > 0;
            }
        }
    }

    /// <summary>Gets the number of lines silently skipped during parsing.</summary>
    public int SkippedLineCount
    {
        get => _skippedLineCount;
        private set => SetField(ref _skippedLineCount, value);
    }

    /// <summary>Gets whether there are any warnings.</summary>
    public bool HasWarnings
    {
        get => _hasWarnings;
        private set => SetField(ref _hasWarnings, value);
    }

    /// <summary>Gets whether there are any parse errors.</summary>
    public bool HasParseErrors
    {
        get => _hasParseErrors;
        private set => SetField(ref _hasParseErrors, value);
    }

    /// <summary>Gets or sets the selected finding item.</summary>
    public FindingItemViewModel? SelectedItem
    {
        get => _selectedItem;
        set
        {
            if (SetField(ref _selectedItem, value))
            {
                OnPropertyChanged(nameof(HasSelectedItem));
                OnPropertyChanged(nameof(SelectedFindingActionContext));
                TogglePinSelectedCommand?.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>Gets whether a finding is selected for toolbar actions.</summary>
    public bool HasSelectedItem => SelectedItem != null;

    /// <summary>Gets the toolbar text that explains which finding actions apply to.</summary>
    public string SelectedFindingActionContext => SelectedItem == null
        ? "Select a finding to investigate, suppress, or resolve"
        : $"Selected: {FormatSelectedFinding(SelectedItem)}";

    /// <summary>
    /// Initializes a new instance of the <see cref="FindingsViewModel"/> class.
    /// Uses an in-memory store for design-time and fallback scenarios.
    /// </summary>
    public FindingsViewModel()
        : this(new InMemoryPinnedFindingStore())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="FindingsViewModel"/> class.
    /// </summary>
    /// <param name="pinnedFindingStore">The store for pinned findings.</param>
    public FindingsViewModel(IPinnedFindingStore pinnedFindingStore)
    {
        _pinnedFindingStore = pinnedFindingStore ?? throw new ArgumentNullException(nameof(pinnedFindingStore));

        // Initialize severity filters
        SeverityFilters.Add(new SeverityFilterOption("All severities", null));
        SeverityFilters.Add(new SeverityFilterOption("High & Critical only", Severity.High));
        SeverityFilters.Add(new SeverityFilterOption("Critical only", Severity.Critical));
        SelectedSeverityFilter = SeverityFilters[0];

        PinCommand = new RelayCommand(
            param => PinItem(param as FindingItemViewModel),
            param => param is FindingItemViewModel item && !item.IsPinned);

        UnpinCommand = new RelayCommand(
            param => UnpinItem(param as FindingItemViewModel),
            param => param is FindingItemViewModel item && item.IsPinned);

        TogglePinnedOnlyCommand = new RelayCommand(
            _ => ShowPinnedOnly = !ShowPinnedOnly,
            _ => PinnedCount > 0 || ShowPinnedOnly);

        TogglePinSelectedCommand = new RelayCommand(
            _ => TogglePinSelected(),
            _ => SelectedItem != null);

        RefreshPinnedCount();
    }

    /// <summary>
    /// Toggles the pinned state of the currently selected finding.
    /// </summary>
    public void TogglePinSelected()
    {
        var item = SelectedItem;
        if (item == null)
            return;

        if (item.IsPinned)
        {
            UnpinItem(item);
        }
        else
        {
            PinItem(item);
        }
    }

    /// <summary>
    /// Loads findings and statistics from an analysis result.
    /// </summary>
    /// <param name="result">The analysis result to load.</param>
    public void LoadResults(AnalysisResult result)
    {
        // Clear previous data
        SelectedItem = null;
        Items.Clear();
        FilteredItems.Clear();
        ParseErrors.Clear();
        Warnings.Clear();

        // Load findings
        foreach (var f in result.Findings)
        {
            var item = new FindingItemViewModel(f);
            item.IsPinned = _pinnedFindingStore.IsPinned(f.Fingerprint);
            Items.Add(item);
        }

        // Load parse errors (with limit)
        var totalParseErrors = result.ParseErrorCount;
        var errorsToDisplay = result.ParseErrors;
        var displayLimit = Math.Min(MaxParseErrorsToDisplay, errorsToDisplay.Count);

        for (var i = 0; i < displayLimit; i++)
        {
            ParseErrors.Add(errorsToDisplay[i]);
        }

        if (totalParseErrors > displayLimit)
        {
            var remaining = totalParseErrors - displayLimit;
            ParseErrors.Add($"...and {remaining} more parse errors not shown.");
        }

        // Load warnings
        foreach (var warning in result.Warnings)
        {
            Warnings.Add(warning);
        }

        // Update statistics
        HasLoadedResults = true;
        FindingsCount = result.Findings.Count;
        HighCriticalCount = result.Findings.Count(f => f.Severity >= Severity.High);
        WarningCount = result.Warnings.Count;
        ParseErrorCount = result.ParseErrorCount;
        SkippedLineCount = result.SkippedLineCount;
        RefreshPinnedCount();

        // Apply initial filters
        ApplyFilters();
        RaiseDataState();
    }

    /// <summary>
    /// Adds a single finding to the display without clearing existing items.
    /// Used by the live stream to merge real-time findings into the main grid.
    /// </summary>
    public void AddFinding(Finding finding)
    {
        var item = new FindingItemViewModel(finding);
        item.IsPinned = _pinnedFindingStore.IsPinned(finding.Fingerprint);
        HasLoadedResults = true;
        Items.Add(item);
        FindingsCount++;
        if (finding.Severity >= Severity.High)
        {
            HighCriticalCount++;
        }
        if (item.IsPinned)
        {
            RefreshPinnedCount();
        }
        ApplyFilters();
    }

    /// <summary>
    /// Clears all findings and resets statistics.
    /// </summary>
    public void Clear()
    {
        SelectedItem = null;
        Items.Clear();
        FilteredItems.Clear();
        ParseErrors.Clear();
        Warnings.Clear();
        FindingsCount = 0;
        HighCriticalCount = 0;
        WarningCount = 0;
        ParseErrorCount = 0;
        SkippedLineCount = 0;
        HasLoadedResults = false;
        RefreshPinnedCount();
        RaiseDataState();
    }

    private void RaiseDataState()
    {
        OnPropertyChanged(nameof(HasData));
        OnPropertyChanged(nameof(HasItems));
        OnPropertyChanged(nameof(HasNoFilterMatches));
    }

    private void RaiseEmptyStateText()
    {
        OnPropertyChanged(nameof(EmptyStateHeadline));
        OnPropertyChanged(nameof(EmptyStateDescription));
    }

    private static string FormatSelectedFinding(FindingItemViewModel item)
    {
        var label = string.IsNullOrWhiteSpace(item.Finding.RuleId)
            ? item.Category
            : item.Finding.RuleId;

        var route = string.IsNullOrWhiteSpace(item.SourceHost)
            ? item.Target
            : $"{item.SourceHost} -> {item.Target}";

        return $"{label} - {item.Severity} - {route}";
    }

    private void ApplyFilters()
    {
        FilteredItems.Clear();

        foreach (var item in Items)
        {
            if (FilterItem(item))
            {
                FilteredItems.Add(item);
            }
        }

        RaiseDataState();
    }

    private bool FilterItem(FindingItemViewModel item)
    {
        // Apply pinned-only filter
        if (_showPinnedOnly && !item.IsPinned)
        {
            return false;
        }

        // Apply severity filter
        if (_selectedSeverityFilter?.MinSeverity != null &&
            Enum.TryParse<Severity>(item.Severity, out var sev) &&
            sev < _selectedSeverityFilter.MinSeverity.Value)
        {
            return false;
        }

        // Apply text search
        if (string.IsNullOrWhiteSpace(_searchText))
            return true;

        return item.Category.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ||
               item.SourceHost.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ||
               item.Target.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ||
               item.TimeRangeDisplay.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ||
               item.ShortDescription.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ||
               item.Confidence.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ||
               item.EvidenceSignalsDisplay.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ||
               item.MitreTechniquesDisplay.Contains(_searchText, StringComparison.OrdinalIgnoreCase);
    }

    private void PinItem(FindingItemViewModel? item)
    {
        if (item == null)
            return;

        _pinnedFindingStore.Pin(CreatePinnedFinding(item));
        item.IsPinned = true;
        PinCommand.RaiseCanExecuteChanged();
        UnpinCommand.RaiseCanExecuteChanged();
        RefreshPinnedCount();
        if (_showPinnedOnly)
        {
            ApplyFilters();
        }
    }

    private void UnpinItem(FindingItemViewModel? item)
    {
        if (item == null)
            return;

        _pinnedFindingStore.Unpin(item.Finding.Fingerprint);
        item.IsPinned = false;
        PinCommand.RaiseCanExecuteChanged();
        UnpinCommand.RaiseCanExecuteChanged();
        RefreshPinnedCount();
        if (_showPinnedOnly)
        {
            ApplyFilters();
        }
    }

    private void RefreshPinnedCount()
    {
        // Count pinned findings that are actually present in the current view.
        // The store may contain pins from prior sessions whose fingerprints do
        // not appear in the current scan; showing that total on the badge would
        // over-promise how many rows "Pinned only" will display.
        PinnedCount = Items.Count(i => i.IsPinned);
        TogglePinnedOnlyCommand?.RaiseCanExecuteChanged();
    }

    internal static PinnedFinding CreatePinnedFinding(FindingItemViewModel item)
    {
        return new PinnedFinding
        {
            Fingerprint = item.Finding.Fingerprint,
            RuleId = item.Finding.RuleId,
            Category = item.Category,
            Severity = item.Severity,
            SourceHost = item.SourceHost,
            Target = item.Target,
            ShortDescription = item.ShortDescription
        };
    }
}
