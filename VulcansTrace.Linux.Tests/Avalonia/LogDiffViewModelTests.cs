using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine.LogDiff;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class LogDiffViewModelTests
{
    [Fact]
    public void LoadDiff_CopiesEventsFindingsAndCountsIntoViewModel()
    {
        var result = new LogDiffResult
        {
            Events =
            [
                new DiffEvent
                {
                    ConnectionKey = "10.0.0.1:*-192.168.1.1:443-TCP",
                    State = LogDiffState.Added,
                    BaselineCount = 0,
                    IncidentCount = 3,
                    SourceIP = "10.0.0.1",
                    DestinationIP = "192.168.1.1",
                    DestinationPort = 443,
                    Protocol = "TCP"
                },
                new DiffEvent
                {
                    ConnectionKey = "10.0.0.2:*-192.168.1.1:22-TCP",
                    State = LogDiffState.Unchanged,
                    BaselineCount = 2,
                    IncidentCount = 2,
                    SourceIP = "10.0.0.2",
                    DestinationIP = "192.168.1.1",
                    DestinationPort = 22,
                    Protocol = "TCP"
                }
            ],
            Findings =
            [
                new DiffFinding
                {
                    State = LogDiffState.Added,
                    Finding = new Finding
                    {
                        Category = FindingCategories.PortScan,
                        Severity = Severity.High,
                        SourceHost = "10.0.0.1",
                        Target = "192.168.1.1:443",
                        TimeRangeStart = DateTime.UtcNow,
                        TimeRangeEnd = DateTime.UtcNow.AddMinutes(1),
                        ShortDescription = "Port scan detected",
                        Details = "Details"
                    }
                }
            ]
        };
        var vm = new LogDiffViewModel();

        vm.LoadDiff(result);

        Assert.Equal(2, vm.Events.Count);
        Assert.Single(vm.Findings);
        Assert.Equal(1, vm.AddedCount);
        Assert.Equal(1, vm.UnchangedCount);
        Assert.Equal(1, vm.AddedFindingsCount);
        Assert.Contains("1 new traffic pattern", vm.Narrative);
    }
}
