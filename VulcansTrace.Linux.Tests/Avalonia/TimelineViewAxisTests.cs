using System.Text.RegularExpressions;
using VulcansTrace.Linux.Avalonia.Views;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class TimelineViewAxisTests
{
    [Fact]
    public void ComputeTickLabels_SubMinuteSpan_UsesMillisecondPrecision()
    {
        // Regression: a ~10 ms agent audit produced identical "20:07:04" labels on
        // every tick. Sub-minute spans must render milliseconds.
        var min = new DateTime(2026, 7, 11, 20, 7, 4, DateTimeKind.Utc);

        var labels = TimelineView.ComputeTickLabels(min, min.AddMilliseconds(10), tickCount: 5);

        Assert.Equal(5, labels.Count);
        Assert.All(labels, l => Assert.Matches(new Regex(@"^\d{2}:\d{2}:\d{2}\.\d{3}$"), l.label));
        Assert.Equal(labels.Count, labels.Select(l => l.label).Distinct().Count());
    }

    [Fact]
    public void ComputeTickLabels_MinuteToDaySpan_UsesSecondPrecision()
    {
        var min = new DateTime(2026, 7, 11, 20, 7, 4, DateTimeKind.Utc);

        var labels = TimelineView.ComputeTickLabels(min, min.AddMinutes(5), tickCount: 3);

        Assert.All(labels, l => Assert.Matches(new Regex(@"^\d{2}:\d{2}:\d{2}$"), l.label));
    }

    [Fact]
    public void ComputeTickLabels_MultiDaySpan_UsesDateAndMinutePrecision()
    {
        var min = new DateTime(2026, 7, 11, 20, 7, 4, DateTimeKind.Utc);

        var labels = TimelineView.ComputeTickLabels(min, min.AddDays(2), tickCount: 3);

        Assert.All(labels, l => Assert.Matches(new Regex(@"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$"), l.label));
    }

    [Fact]
    public void ComputeTickLabels_ZeroSpan_FallsBackToOneSecondWindow()
    {
        var min = new DateTime(2026, 7, 11, 20, 7, 4, DateTimeKind.Utc);

        var labels = TimelineView.ComputeTickLabels(min, min, tickCount: 3);

        Assert.Equal(3, labels.Count);
        Assert.Equal(labels.Count, labels.Select(l => l.label).Distinct().Count());
    }
}
