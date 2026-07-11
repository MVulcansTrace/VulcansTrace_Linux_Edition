using VulcansTrace.Linux.Agent.Diagnostics;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Avalonia.ViewModels;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class DoctorViewModelTests
{
    [AvaloniaFact]
    public void LoadResults_ZeroCapabilities_SetsHasProbedAndSummary()
    {
        var vm = new DoctorViewModel(new DoctorService(System.Array.Empty<IScanner>()));
        Assert.False(vm.HasProbed);
        Assert.False(vm.HasData);

        vm.LoadResults(new DoctorResult
        {
            Capabilities = System.Array.Empty<DataSourceCapability>(),
            IsHealthy = false,
            PermissionLimitedCount = 0,
            UnavailableCount = 0
        });

        Assert.True(vm.HasProbed);
        Assert.False(vm.HasData);
        Assert.Equal("No capabilities reported.", vm.SummaryText);
    }

    [AvaloniaFact]
    public void LoadResults_WithCapabilities_SetsHasDataAndHasProbed()
    {
        var vm = new DoctorViewModel(new DoctorService(System.Array.Empty<IScanner>()));

        vm.LoadResults(new DoctorResult
        {
            Capabilities = new[]
            {
                new DataSourceCapability { SourceName = "iptables", Status = CapabilityStatus.Available }
            },
            IsHealthy = true,
            PermissionLimitedCount = 0,
            UnavailableCount = 0
        });

        Assert.True(vm.HasProbed);
        Assert.True(vm.HasData);
        Assert.Single(vm.Capabilities);
        Assert.Equal("All 1 data sources are available.", vm.SummaryText);
    }

    [AvaloniaFact]
    public void LoadResults_WithWarnings_CollapsesIntoFriendlyMessage()
    {
        var vm = new DoctorViewModel(new DoctorService(System.Array.Empty<IScanner>()));

        vm.LoadResults(new DoctorResult
        {
            Capabilities = new[]
            {
                new DataSourceCapability { SourceName = "iptables", Status = CapabilityStatus.Available }
            },
            IsHealthy = true,
            Warnings = new[] { "Scanner 'X' failed: boom" }
        });

        var friendly = Assert.Single(vm.Warnings);
        Assert.Contains("scanner returned", friendly, System.StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("boom", friendly, System.StringComparison.OrdinalIgnoreCase);
    }

    [AvaloniaFact]
    public void LoadResults_WithPermissionLimited_SetsCorrectSummary()
    {
        var vm = new DoctorViewModel(new DoctorService(System.Array.Empty<IScanner>()));

        vm.LoadResults(new DoctorResult
        {
            Capabilities = new[]
            {
                new DataSourceCapability { SourceName = "ss", Status = CapabilityStatus.PermissionLimited }
            },
            IsHealthy = false,
            PermissionLimitedCount = 1,
            UnavailableCount = 0
        });

        Assert.True(vm.HasProbed);
        Assert.True(vm.HasData);
        Assert.Contains("1 permission-limited", vm.SummaryText);
    }

    [AvaloniaFact]
    public void LoadResults_WithUnknown_SetsIncompleteVisibilitySummary()
    {
        var vm = new DoctorViewModel(new DoctorService(System.Array.Empty<IScanner>()));

        vm.LoadResults(new DoctorResult
        {
            Capabilities = new[]
            {
                new DataSourceCapability { SourceName = "file-hash", Status = CapabilityStatus.Unknown }
            },
            IsHealthy = false,
            UnknownCount = 1
        });

        Assert.True(vm.HasProbed);
        Assert.True(vm.HasData);
        Assert.Contains("1 not checked", vm.SummaryText);
        Assert.DoesNotContain("All", vm.SummaryText);
    }

    [AvaloniaFact]
    public void LoadResults_ClearsPreviousData()
    {
        var vm = new DoctorViewModel(new DoctorService(System.Array.Empty<IScanner>()));

        vm.LoadResults(new DoctorResult
        {
            Capabilities = new[]
            {
                new DataSourceCapability { SourceName = "iptables", Status = CapabilityStatus.Available }
            },
            IsHealthy = true,
            Warnings = new[] { "old warning" }
        });

        vm.LoadResults(new DoctorResult
        {
            Capabilities = new[]
            {
                new DataSourceCapability { SourceName = "ss", Status = CapabilityStatus.Available }
            },
            IsHealthy = true,
            Warnings = System.Array.Empty<string>()
        });

        Assert.Single(vm.Capabilities);
        Assert.Equal("ss", vm.Capabilities[0].SourceName);
        Assert.Empty(vm.Warnings);
    }

    [AvaloniaFact]
    public void LoadResults_PermissionDeniedFlood_CollapsesToSingleFriendlyWarning()
    {
        var vm = new DoctorViewModel(new DoctorService(System.Array.Empty<IScanner>()));

        var warnings = System.Linq.Enumerable
            .Range(0, 40)
            .Select(i => $"find: '/var/{i}': Permission denied")
            .ToArray();

        vm.LoadResults(new DoctorResult
        {
            Capabilities = new[]
            {
                new DataSourceCapability { SourceName = "find-world-writable-files", Status = CapabilityStatus.PermissionLimited }
            },
            IsHealthy = false,
            PermissionLimitedCount = 1,
            Warnings = warnings
        });

        var friendly = Assert.Single(vm.Warnings);
        Assert.Contains("40 checks were blocked", friendly, System.StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("find:", friendly, System.StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("/var/", friendly, System.StringComparison.OrdinalIgnoreCase);
    }

    [AvaloniaFact]
    public void LoadResults_CapabilityDetail_SanitizesProcessStartError()
    {
        var vm = new DoctorViewModel(new DoctorService(System.Array.Empty<IScanner>()));
        var home = System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile);

        vm.LoadResults(new DoctorResult
        {
            Capabilities = new[]
            {
                new DataSourceCapability
                {
                    SourceName = "iptables",
                    Status = CapabilityStatus.Unavailable,
                    Detail = $"An error occurred trying to start process 'iptables' with working directory '{home}/Projects/X'. No such file or directory"
                }
            },
            IsHealthy = false,
            UnavailableCount = 1
        });

        var detail = Assert.Single(vm.Capabilities).Detail;
        Assert.Contains("could not be started", detail, System.StringComparison.OrdinalIgnoreCase);
        Assert.Contains("iptables", detail, System.StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("working directory", detail, System.StringComparison.OrdinalIgnoreCase);
    }
}
