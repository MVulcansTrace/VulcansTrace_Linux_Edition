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

    [AvaloniaFact]
    public async Task CopyStatusIsError_True_OnFailure_False_AfterReset()
    {
        var vm = new IncidentStoryViewModel();

        // Load a real story so HasStory is true and CopyMarkdownCommand can run.
        vm.LoadTraceMap(new TraceMapResult
        {
            Findings = new[]
            {
                new Finding
                {
                    RuleId = "FW-001",
                    Severity = Severity.High,
                    ShortDescription = "SSH exposed",
                    SourceHost = "10.0.0.1"
                }
            },
            Edges = Array.Empty<CorrelationEdge>()
        });

        Assert.True(vm.HasStory);
        // LoadTraceMap resets the copy status to empty + non-error.
        Assert.Equal(string.Empty, vm.CopyStatus);
        Assert.False(vm.CopyStatusIsError);

        // Invoke the copy command. With no real MainWindow/clipboard in the test
        // runner, the method falls through to "Clipboard not available." which is
        // an error state — so CopyStatusIsError must be true (not green).
        vm.CopyMarkdownCommand.Execute(null);
        await ((AsyncRelayCommand)vm.CopyMarkdownCommand).ExecutionTask;

        Assert.Contains("Clipboard not available", vm.CopyStatus);
        Assert.True(vm.CopyStatusIsError);

        // Reloading the trace map must clear both the text and the error flag,
        // so a stale failure color can't survive a fresh story load.
        vm.LoadTraceMap(null);

        Assert.Equal(string.Empty, vm.CopyStatus);
        Assert.False(vm.CopyStatusIsError);
    }
}
