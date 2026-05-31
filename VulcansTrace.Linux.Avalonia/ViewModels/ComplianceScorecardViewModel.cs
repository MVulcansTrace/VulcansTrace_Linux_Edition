using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using VulcansTrace.Linux.Core.Compliance;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for the Compliance Scorecard tab.
/// Displays overall CIS compliance score, per-family breakdown, and trend over time.
/// </summary>
public sealed class ComplianceScorecardViewModel : ViewModelBase
{
    private double _overallScore;
    private string _summaryStatus = "—";
    private string _statusColor = "#64748b";
    private string _statusBackground = "#1e293b";
    private bool _hasData;
    private string _trendDirection = "—";
    private string _trendArrow = "";

    /// <summary>Gets the collection of control family scores.</summary>
    public ObservableCollection<ControlFamilyScore> FamilyScores { get; } = new();

    /// <summary>Gets the collection of trend points.</summary>
    public ObservableCollection<ComplianceTrendPointViewModel> TrendPoints { get; } = new();

    /// <summary>Gets the overall compliance score (0–100).</summary>
    public double OverallScore
    {
        get => _overallScore;
        private set => SetField(ref _overallScore, value);
    }

    /// <summary>Gets the overall summary status (Pass, Warn, Fail).</summary>
    public string SummaryStatus
    {
        get => _summaryStatus;
        private set => SetField(ref _summaryStatus, value);
    }

    /// <summary>Gets the foreground color for the overall status badge.</summary>
    public string StatusColor
    {
        get => _statusColor;
        private set => SetField(ref _statusColor, value);
    }

    /// <summary>Gets the background color for the overall status badge.</summary>
    public string StatusBackground
    {
        get => _statusBackground;
        private set => SetField(ref _statusBackground, value);
    }

    /// <summary>Gets whether scorecard data has been loaded.</summary>
    public bool HasData
    {
        get => _hasData;
        private set => SetField(ref _hasData, value);
    }

    /// <summary>Gets a text description of the trend direction.</summary>
    public string TrendDirection
    {
        get => _trendDirection;
        private set => SetField(ref _trendDirection, value);
    }

    /// <summary>Gets an arrow emoji representing the trend direction.</summary>
    public string TrendArrow
    {
        get => _trendArrow;
        private set => SetField(ref _trendArrow, value);
    }

    /// <summary>
    /// Loads a compliance scorecard into the view model.
    /// </summary>
    public void LoadScorecard(ComplianceScorecard? scorecard)
    {
        FamilyScores.Clear();
        TrendPoints.Clear();

        if (scorecard == null)
        {
            OverallScore = 0;
            SummaryStatus = "—";
            StatusColor = "#64748b";
            StatusBackground = "#1e293b";
            HasData = false;
            TrendDirection = "—";
            TrendArrow = "";
            return;
        }

        OverallScore = scorecard.OverallScore;
        SummaryStatus = scorecard.SummaryStatus;
        HasData = true;

        switch (scorecard.SummaryStatus)
        {
            case "Pass":
                StatusColor = "#34d399";
                StatusBackground = "#064e3b";
                break;
            case "Warn":
                StatusColor = "#fbbf24";
                StatusBackground = "#451a03";
                break;
            default:
                StatusColor = "#f87171";
                StatusBackground = "#450a0a";
                break;
        }

        foreach (var family in scorecard.FamilyScores)
        {
            FamilyScores.Add(family);
        }

        if (scorecard.Trend.Count > 0)
        {
            var maxScore = scorecard.Trend.Max(p => p.OverallScore);
            if (maxScore < 1) maxScore = 1;

            foreach (var point in scorecard.Trend)
            {
                TrendPoints.Add(new ComplianceTrendPointViewModel
                {
                    Timestamp = point.Timestamp,
                    OverallScore = point.OverallScore,
                    BarHeight = Math.Max(4, point.OverallScore / maxScore * 60)
                });
            }
        }

        var (direction, arrow) = ComplianceTrendAnalyzer.ComputeDirection(scorecard.Trend, scorecard.OverallScore);
        TrendDirection = direction;
        TrendArrow = arrow;
    }
}

/// <summary>
/// Lightweight view model for a single compliance trend point.
/// </summary>
public sealed class ComplianceTrendPointViewModel : ViewModelBase
{
    private DateTime _timestamp;
    private double _overallScore;

    public DateTime Timestamp
    {
        get => _timestamp;
        set => SetField(ref _timestamp, value);
    }

    public double OverallScore
    {
        get => _overallScore;
        set => SetField(ref _overallScore, value);
    }

    private double _barHeight;

    /// <summary>Height of the trend bar in pixels (0–60).</summary>
    public double BarHeight
    {
        get => _barHeight;
        set => SetField(ref _barHeight, value);
    }
}
