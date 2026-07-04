using System;
using System.Collections.Generic;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class RuleCoverageViewModelTests
{
    [AvaloniaFact]
    public void LoadResults_NullResult_ClearsData()
    {
        var vm = new RuleCoverageViewModel();
        vm.LoadResults(null);

        Assert.Empty(vm.Categories);
        Assert.Equal(0, vm.TotalRules);
        Assert.False(vm.HasData);
    }

    [AvaloniaFact]
    public void LoadResults_EmptyRuleResults_ClearsData()
    {
        var vm = new RuleCoverageViewModel();
        vm.LoadResults(new AgentResult { RuleResults = Array.Empty<RuleResult>() });

        Assert.Empty(vm.Categories);
        Assert.Equal(0, vm.TotalRules);
        Assert.False(vm.HasData);
    }

    [AvaloniaFact]
    public void LoadResults_GroupsByCategoryAndComputesTotals()
    {
        var vm = new RuleCoverageViewModel();
        var result = new AgentResult
        {
            RuleResults = new List<RuleResult>
            {
                RuleResult.Pass("FW-001", "Firewall", "FW-001", "Firewall active"),
                RuleResult.Pass("FW-002", "Firewall", "FW-002", "Default drop"),
                RuleResult.Fail("NW-001", "Network", "NW-001", "Default route", Severity.High, "eth0"),
                RuleResult.Crash("SV-001", "Service", "Service check"),
                new RuleResult
                {
                    RuleId = "PT-001",
                    Category = "Port",
                    Passed = false,
                    Status = RuleStatus.Suppressed,
                    ExplanationKey = "PT-001",
                    Description = "Open port"
                }
            }
        };

        vm.LoadResults(result);

        Assert.True(vm.HasData);
        Assert.Equal(5, vm.TotalRules);
        Assert.Equal(2, vm.TotalPassed);
        Assert.Equal(1, vm.TotalFailed);
        Assert.Equal(1, vm.TotalSuppressed);
        Assert.Equal(1, vm.TotalCrashed);

        Assert.Equal(4, vm.Categories.Count);

        // Ordered by Failed+Crashed descending, then by Category ascending
        var network = vm.Categories[0];
        Assert.Equal("Network", network.Category);
        Assert.Equal(0, network.Passed);
        Assert.Equal(1, network.Failed);
        Assert.Equal(0, network.Suppressed);
        Assert.Equal(0, network.Crashed);
        Assert.Equal(1, network.Total);

        var service = vm.Categories[1];
        Assert.Equal("Service", service.Category);
        Assert.Equal(0, service.Passed);
        Assert.Equal(0, service.Failed);
        Assert.Equal(0, service.Suppressed);
        Assert.Equal(1, service.Crashed);
        Assert.Equal(1, service.Total);

        var firewall = vm.Categories[2];
        Assert.Equal("Firewall", firewall.Category);
        Assert.Equal(2, firewall.Passed);
        Assert.Equal(0, firewall.Failed);
        Assert.Equal(0, firewall.Suppressed);
        Assert.Equal(0, firewall.Crashed);
        Assert.Equal(2, firewall.Total);

        var port = vm.Categories[3];
        Assert.Equal("Port", port.Category);
        Assert.Equal(0, port.Passed);
        Assert.Equal(0, port.Failed);
        Assert.Equal(1, port.Suppressed);
        Assert.Equal(0, port.Crashed);
        Assert.Equal(1, port.Total);
    }

    [AvaloniaFact]
    public void LoadResults_OrdersByFailedPlusCrashedDescending()
    {
        var vm = new RuleCoverageViewModel();
        var result = new AgentResult
        {
            RuleResults = new List<RuleResult>
            {
                RuleResult.Pass("A-001", "Alpha", "A-001", "Alpha pass"),
                RuleResult.Fail("B-001", "Beta", "B-001", "Beta fail", Severity.Medium, "x"),
                RuleResult.Fail("B-002", "Beta", "B-002", "Beta fail 2", Severity.Medium, "y"),
                RuleResult.Crash("G-001", "Gamma", "Gamma crash")
            }
        };

        vm.LoadResults(result);

        Assert.Equal("Beta", vm.Categories[0].Category);   // 2 failed
        Assert.Equal("Gamma", vm.Categories[1].Category);  // 1 crashed
        Assert.Equal("Alpha", vm.Categories[2].Category);  // 0 failed/crashed
    }
}
