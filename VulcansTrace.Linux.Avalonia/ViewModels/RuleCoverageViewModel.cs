using System.Collections.ObjectModel;
using System.Linq;
using System.Windows.Input;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for the Rule Coverage tab.
/// Groups rule results by category and exposes passed, failed, suppressed, and crashed counts.
/// </summary>
public sealed class RuleCoverageViewModel : ViewModelBase
{
    private int _totalPassed;
    private int _totalFailed;
    private int _totalSuppressed;
    private int _totalCrashed;
    private int _totalNotApplicable;
    private int _totalRules;
    private bool _hasData;

    /// <summary>Gets the collection of coverage rows grouped by category.</summary>
    public ObservableCollection<RuleCoverageCategoryViewModel> Categories { get; } = new();

    /// <summary>Gets the total number of rules that passed.</summary>
    public int TotalPassed
    {
        get => _totalPassed;
        private set => SetField(ref _totalPassed, value);
    }

    /// <summary>Gets the total number of rules that failed.</summary>
    public int TotalFailed
    {
        get => _totalFailed;
        private set => SetField(ref _totalFailed, value);
    }

    /// <summary>Gets the total number of rules suppressed.</summary>
    public int TotalSuppressed
    {
        get => _totalSuppressed;
        private set => SetField(ref _totalSuppressed, value);
    }

    /// <summary>Gets the total number of rules that crashed.</summary>
    public int TotalCrashed
    {
        get => _totalCrashed;
        private set => SetField(ref _totalCrashed, value);
    }

    /// <summary>Gets the total number of rules not applicable.</summary>
    public int TotalNotApplicable
    {
        get => _totalNotApplicable;
        private set => SetField(ref _totalNotApplicable, value);
    }

    /// <summary>Gets the total number of rules evaluated.</summary>
    public int TotalRules
    {
        get => _totalRules;
        private set => SetField(ref _totalRules, value);
    }

    /// <summary>Gets whether any coverage data has been loaded.</summary>
    public bool HasData
    {
        get => _hasData;
        private set => SetField(ref _hasData, value);
    }

    /// <summary>Gets or sets the command invoked by the empty-state action button.</summary>
    public ICommand? EmptyStateActionCommand { get; set; }

    /// <summary>Gets or sets the label of the empty-state action button.</summary>
    public string EmptyStateActionText { get; set; } = "Analyze";

    /// <summary>
    /// Loads coverage data from an agent audit result.
    /// </summary>
    public void LoadResults(AgentResult? result)
    {
        Categories.Clear();

        if (result?.RuleResults is not { Count: > 0 } ruleResults)
        {
            TotalPassed = 0;
            TotalFailed = 0;
            TotalSuppressed = 0;
            TotalCrashed = 0;
            TotalNotApplicable = 0;
            TotalRules = 0;
            HasData = false;
            return;
        }

        var grouped = ruleResults
            .GroupBy(r => r.Category)
            .Select(g => new RuleCoverageCategoryViewModel
            {
                Category = g.Key,
                Passed = g.Count(r => r.Status == RuleStatus.Passed),
                Failed = g.Count(r => r.Status == RuleStatus.Failed),
                Suppressed = g.Count(r => r.Status == RuleStatus.Suppressed),
                Crashed = g.Count(r => r.Status == RuleStatus.Crashed),
                NotApplicable = g.Count(r => r.Status == RuleStatus.NotApplicable)
            })
            .OrderByDescending(r => r.Failed + r.Crashed)
            .ThenBy(r => r.Category)
            .ToList();

        foreach (var row in grouped)
        {
            Categories.Add(row);
        }

        TotalPassed = ruleResults.Count(r => r.Status == RuleStatus.Passed);
        TotalFailed = ruleResults.Count(r => r.Status == RuleStatus.Failed);
        TotalSuppressed = ruleResults.Count(r => r.Status == RuleStatus.Suppressed);
        TotalCrashed = ruleResults.Count(r => r.Status == RuleStatus.Crashed);
        TotalNotApplicable = ruleResults.Count(r => r.Status == RuleStatus.NotApplicable);
        TotalRules = ruleResults.Count;
        HasData = true;
    }
}
