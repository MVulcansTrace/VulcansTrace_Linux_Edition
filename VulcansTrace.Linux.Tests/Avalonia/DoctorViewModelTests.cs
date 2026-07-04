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
    public void LoadResults_WithWarnings_PopulatesWarningsCollection()
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

        Assert.Single(vm.Warnings);
        Assert.Contains("Scanner 'X' failed: boom", vm.Warnings);
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
}
