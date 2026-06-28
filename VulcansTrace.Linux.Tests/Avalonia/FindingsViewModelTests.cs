using System;
using System.Linq;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class FindingsViewModelTests
{
    [Fact]
    public void LoadResults_PopulatesCountsAndFilters()
    {
        var vm = new FindingsViewModel();
        var result = new AnalysisResult
        {
            Findings =
            [
                new Finding
                {
                    Category = FindingCategories.PortScan,
                    Severity = Severity.High,
                    SourceHost = "192.168.1.10",
                    Target = "multi",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Port scan",
                    Details = "detail"
                },
                new Finding
                {
                    Category = FindingCategories.Beaconing,
                    Severity = Severity.Low,
                    SourceHost = "192.168.1.11",
                    Target = "10.0.0.2",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(2),
                    ShortDescription = "Beaconing",
                    Details = "detail"
                }
            ],
            Warnings = ["warn-1"],
            ParseErrorCount = 1,
            ParseErrors = ["parse-error-1"],
            SkippedLineCount = 2
        };

        vm.LoadResults(result);

        Assert.Equal(2, vm.FindingsCount);
        Assert.Equal(1, vm.HighCriticalCount);
        Assert.Equal(1, vm.WarningCount);
        Assert.Equal(1, vm.ParseErrorCount);
        Assert.Equal(2, vm.SkippedLineCount);
        Assert.Equal(vm.Items.Count, vm.FilteredItems.Count);
        Assert.Single(vm.ParseErrors);
        Assert.Single(vm.Warnings);
    }

    [Fact]
    public void SearchText_FiltersFindings()
    {
        var vm = new FindingsViewModel();
        var result = new AnalysisResult
        {
            Findings =
            [
                new Finding
                {
                    Category = FindingCategories.PortScan,
                    Severity = Severity.Medium,
                    SourceHost = "192.168.1.12",
                    Target = "multi",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Port scan detected",
                    Details = "detail"
                },
                new Finding
                {
                    Category = FindingCategories.Beaconing,
                    Severity = Severity.Medium,
                    SourceHost = "192.168.1.13",
                    Target = "10.0.0.9",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Periodic beacons",
                    Details = "detail"
                }
            ]
        };

        vm.LoadResults(result);
        vm.SearchText = "beacon";

        Assert.Single(vm.FilteredItems);
        Assert.Contains(vm.FilteredItems, item => item.Category == FindingCategories.Beaconing);
    }

    [Fact]
    public void LoadResults_ClampsParseErrors()
    {
        var vm = new FindingsViewModel();
        var errors = Enumerable.Range(0, 205).Select(i => $"err-{i}").ToArray();
        var result = new AnalysisResult
        {
            ParseErrorCount = errors.Length,
            ParseErrors = errors
        };

        vm.LoadResults(result);

        Assert.Equal(201, vm.ParseErrors.Count);
        Assert.EndsWith("more parse errors not shown.", vm.ParseErrors[^1]);
    }

    [Fact]
    public void LoadResults_PopulatesConfidenceAndEvidenceSignals()
    {
        var vm = new FindingsViewModel();
        var result = new AnalysisResult
        {
            Findings =
            [
                new Finding
                {
                    Category = FindingCategories.Beaconing,
                    Severity = Severity.High,
                    Confidence = DetectionConfidence.Confirmed,
                    SourceHost = "192.168.1.10",
                    Target = "10.0.0.5",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Beaconing detected",
                    Details = "detail",
                    EvidenceSignals =
                    [
                        new EvidenceSignal { Name = "Known malicious IP", Source = EvidenceSignal.ThreatIntelSource },
                        new EvidenceSignal { Name = "Beaconing pattern", Source = EvidenceSignal.BehaviorSource }
                    ]
                }
            ]
        };

        vm.LoadResults(result);

        var item = vm.Items.Single();
        Assert.Equal("Confirmed", item.Confidence);
        Assert.Contains("Known malicious IP", item.EvidenceSignalsDisplay);
        Assert.Contains("Beaconing pattern", item.EvidenceSignalsDisplay);
    }

    [Fact]
    public void SearchText_FiltersByConfidence()
    {
        var vm = new FindingsViewModel();
        var result = new AnalysisResult
        {
            Findings =
            [
                new Finding
                {
                    Category = FindingCategories.PortScan,
                    Severity = Severity.Medium,
                    Confidence = DetectionConfidence.Low,
                    SourceHost = "192.168.1.12",
                    Target = "multi",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Port scan detected",
                    Details = "detail"
                },
                new Finding
                {
                    Category = FindingCategories.Beaconing,
                    Severity = Severity.Medium,
                    Confidence = DetectionConfidence.High,
                    SourceHost = "192.168.1.13",
                    Target = "10.0.0.9",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Periodic beacons",
                    Details = "detail"
                }
            ]
        };

        vm.LoadResults(result);
        vm.SearchText = "High";

        Assert.Single(vm.FilteredItems);
        Assert.Equal("Beaconing", vm.FilteredItems[0].Category);
    }

    [Fact]
    public void SearchText_FiltersByEvidenceSignal()
    {
        var vm = new FindingsViewModel();
        var result = new AnalysisResult
        {
            Findings =
            [
                new Finding
                {
                    Category = FindingCategories.PortScan,
                    Severity = Severity.Medium,
                    Confidence = DetectionConfidence.Medium,
                    SourceHost = "192.168.1.12",
                    Target = "multi",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Port scan detected",
                    Details = "detail",
                    EvidenceSignals =
                    [
                        new EvidenceSignal { Name = "Many distinct ports", Source = "Behavior" }
                    ]
                },
                new Finding
                {
                    Category = FindingCategories.Beaconing,
                    Severity = Severity.Medium,
                    Confidence = DetectionConfidence.Medium,
                    SourceHost = "192.168.1.13",
                    Target = "10.0.0.9",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Periodic beacons",
                    Details = "detail",
                    EvidenceSignals =
                    [
                        new EvidenceSignal { Name = "Repeated destination", Source = "Behavior" }
                    ]
                }
            ]
        };

        vm.LoadResults(result);
        vm.SearchText = "Repeated destination";

        Assert.Single(vm.FilteredItems);
        Assert.Equal("Beaconing", vm.FilteredItems[0].Category);
    }

    [Fact]
    public void EmptyStateText_DistinguishesInitialAndCompletedEmptyResults()
    {
        var vm = new FindingsViewModel();

        Assert.False(vm.HasLoadedResults);
        Assert.Equal("No findings yet", vm.EmptyStateHeadline);

        vm.LoadResults(new AnalysisResult());

        Assert.True(vm.HasLoadedResults);
        Assert.False(vm.HasItems);
        Assert.Equal("No findings at this intensity", vm.EmptyStateHeadline);
        Assert.Contains("last run completed", vm.EmptyStateDescription);

        vm.Clear();

        Assert.False(vm.HasLoadedResults);
        Assert.Equal("No findings yet", vm.EmptyStateHeadline);
    }

    [Theory]
    [InlineData(1, "")]
    [InlineData(5, "×5")]
    [InlineData(438, "×438")]
    public void FindingItemViewModel_GroupBadge_OnlyShowsGroupedFindings(int groupedCount, string expectedBadge)
    {
        var finding = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multi",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan",
            Details = "detail",
            GroupedCount = groupedCount
        };

        var item = new FindingItemViewModel(finding);

        Assert.Equal(expectedBadge, item.GroupBadge);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(438)]
    public void FindingItemViewModel_GroupedCount_AlwaysShowsRawCount(int groupedCount)
    {
        var finding = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multi",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan",
            Details = "detail",
            GroupedCount = groupedCount
        };

        var item = new FindingItemViewModel(finding);

        Assert.Equal(groupedCount, item.GroupedCount);
    }
}
