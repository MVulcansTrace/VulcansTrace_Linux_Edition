using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Avalonia.ViewModels;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class AuditDiffViewModelTests
{
    [Fact]
    public void LoadDiff_CopiesNarrativeIntoViewModel()
    {
        var diff = new AuditDiff
        {
            NewFindings = new[]
            {
                new DiffFinding
                {
                    RuleId = "PORT-003",
                    Target = "0.0.0.0:5432",
                    Severity = "Critical",
                    ShortDescription = "Database ports should not be exposed to all interfaces"
                }
            }
        };
        var vm = new AuditDiffViewModel();

        vm.LoadDiff(diff);

        Assert.Equal("1 new Critical finding.", vm.Narrative);
        Assert.Equal("1 new, 0 resolved, 0 worsened, 0 improved, 0 confidence changed.", vm.Summary);
        Assert.Equal(1, vm.NewCount);
        Assert.Equal(0, vm.ConfidenceChangedCount);
    }
}
