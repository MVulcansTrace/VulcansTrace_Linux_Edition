using System.Collections.ObjectModel;
using System.Windows.Input;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for the Risk Scorecard tab.
/// Displays overall risk grade, numeric score, and per-category breakdown.
/// </summary>
public sealed class RiskScorecardViewModel : ViewModelBase
{
    private double _numericScore;
    private string _letterGrade = "—";
    private string _summaryStatus = "—";
    private string _gradeColor = "#64748b";
    private string _gradeBackground = "#1e293b";
    private bool _hasData;

    /// <summary>Gets the collection of category risk breakdowns.</summary>
    public ObservableCollection<CategoryRisk> ByCategory { get; } = new();

    /// <summary>Gets the overall numeric risk score (0–100).</summary>
    public double NumericScore
    {
        get => _numericScore;
        private set => SetField(ref _numericScore, value);
    }

    /// <summary>Gets the letter grade (A–F).</summary>
    public string LetterGrade
    {
        get => _letterGrade;
        private set => SetField(ref _letterGrade, value);
    }

    /// <summary>Gets the human-readable summary status (Low, Moderate, High, Elevated, Severe).</summary>
    public string SummaryStatus
    {
        get => _summaryStatus;
        private set => SetField(ref _summaryStatus, value);
    }

    /// <summary>Gets the foreground color for the grade badge.</summary>
    public string GradeColor
    {
        get => _gradeColor;
        private set => SetField(ref _gradeColor, value);
    }

    /// <summary>Gets the background color for the grade badge.</summary>
    public string GradeBackground
    {
        get => _gradeBackground;
        private set => SetField(ref _gradeBackground, value);
    }

    /// <summary>Gets whether scorecard data has been loaded.</summary>
    public bool HasData
    {
        get => _hasData;
        private set => SetField(ref _hasData, value);
    }

    /// <summary>Gets or sets the command invoked by the empty-state action button.</summary>
    public ICommand? EmptyStateActionCommand { get; set; }

    /// <summary>Gets or sets the text of the empty-state action button.</summary>
    public string EmptyStateActionText { get; set; } = "Analyze";

    /// <summary>
    /// Loads a risk scorecard into the view model.
    /// </summary>
    public void LoadScorecard(RiskScorecard? scorecard)
    {
        ByCategory.Clear();

        if (scorecard == null)
        {
            NumericScore = 0;
            LetterGrade = "—";
            SummaryStatus = "—";
            GradeColor = "#64748b";
            GradeBackground = "#1e293b";
            HasData = false;
            return;
        }

        NumericScore = scorecard.NumericScore;
        LetterGrade = scorecard.LetterGrade;
        SummaryStatus = scorecard.SummaryStatus;
        HasData = true;

        var (color, background) = scorecard.LetterGrade switch
        {
            "A" => ("#34d399", "#064e3b"),
            "B" => ("#60a5fa", "#1e3a8a"),
            "C" => ("#fbbf24", "#451a03"),
            "D" => ("#fb923c", "#431407"),
            _ => ("#f87171", "#450a0a")
        };

        GradeColor = color;
        GradeBackground = background;

        foreach (var category in scorecard.ByCategory)
        {
            ByCategory.Add(category);
        }
    }
}
