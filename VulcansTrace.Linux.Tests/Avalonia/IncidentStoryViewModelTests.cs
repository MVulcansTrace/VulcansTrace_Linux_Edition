using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class IncidentStoryViewModelTests
{
    [AvaloniaFact]
    public void EmptyStateText_DistinguishesInitialAndCompletedEmptyTraceMap()
    {
        var vm = new IncidentStoryViewModel();

        Assert.False(vm.HasLoadedTraceMap);
        Assert.Equal("No incident story yet", vm.EmptyStateHeadline);

        vm.LoadTraceMap(new TraceMapResult
        {
            Findings = Array.Empty<Finding>(),
            Edges = Array.Empty<CorrelationEdge>()
        });

        Assert.True(vm.HasLoadedTraceMap);
        Assert.False(vm.HasStory);
        Assert.Equal("No incident story in this result", vm.EmptyStateHeadline);
        Assert.Contains("last run completed", vm.EmptyStateDescription);

        vm.LoadTraceMap(null);

        Assert.False(vm.HasLoadedTraceMap);
        Assert.Equal("No incident story yet", vm.EmptyStateHeadline);
    }
}
