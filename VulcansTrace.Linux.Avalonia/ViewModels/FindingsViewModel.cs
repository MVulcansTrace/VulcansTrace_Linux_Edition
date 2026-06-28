using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows.Input;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for displaying, filtering, and managing security findings.
/// </summary>
public sealed class FindingsViewModel : ViewModelBase
{
    private const int MaxParseErrorsToDisplay = 200;

    private string _searchText = "";
    private SeverityFilterOption? _selectedSeverityFilter;
    private int _findingsCount;
    private int _highCriticalCount;
    private int _warningCount;
    private int _parseErrorCount;
    private int _skippedLineCount;
    private bool _hasWarnings;
    private bool _hasParseErrors;
    private bool _hasLoadedResults;
    private FindingItemViewModel? _selectedItem;
    private ICommand? _acceptRiskCommand;

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

    /// <summary>Gets or sets the command used to accept risk for the selected finding.</summary>
    public ICommand? AcceptRiskCommand
    {
        get => _acceptRiskCommand;
        set => SetField(ref _acceptRiskCommand, value);
    }

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
        set => SetField(ref _selectedItem, value);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="FindingsViewModel"/> class.
    /// </summary>
    public FindingsViewModel()
    {
        // Initialize severity filters
        SeverityFilters.Add(new SeverityFilterOption("All severities", null));
        SeverityFilters.Add(new SeverityFilterOption("High & Critical only", Severity.High));
        SeverityFilters.Add(new SeverityFilterOption("Critical only", Severity.Critical));
        SelectedSeverityFilter = SeverityFilters[0];
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
            Items.Add(new FindingItemViewModel(f));
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
        HasLoadedResults = true;
        Items.Add(item);
        FindingsCount++;
        if (finding.Severity >= Severity.High)
        {
            HighCriticalCount++;
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
               item.ShortDescription.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ||
               item.Confidence.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ||
               item.EvidenceSignalsDisplay.Contains(_searchText, StringComparison.OrdinalIgnoreCase);
    }
}
