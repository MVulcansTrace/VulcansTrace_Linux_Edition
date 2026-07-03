using VulcansTrace.Linux.Avalonia.ViewModels;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class AgentQuickActionTests
{
    [Theory]
    [InlineData("Run checks", "Full audit", "AgentQuickAction_Runchecks_Fullaudit")]
    [InlineData("Export", "Export audit", "AgentQuickAction_Export_Exportaudit")]
    [InlineData("Baseline", "Check drift", "AgentQuickAction_Baseline_Checkdrift")]
    [InlineData("Welcome", "Full audit", "AgentQuickAction_Welcome_Fullaudit")]
    public void AutomationId_DerivesFromGroupAndLabel(string group, string label, string expected)
    {
        var action = new AgentQuickAction { Group = group, Label = label };

        Assert.Equal(expected, action.AutomationId);
    }

    [Fact]
    public void AutomationId_UsesExplicitOverrideWhenSet()
    {
        var action = new AgentQuickAction { Group = "Analysis", Label = "Explain Selected", AutomationIdOverride = "AgentExplainSelectedButton" };

        Assert.Equal("AgentExplainSelectedButton", action.AutomationId);
    }

    [Fact]
    public void AutomationId_StripsSpacesAndSpecialCharacters()
    {
        var action = new AgentQuickAction { Group = "Run checks", Label = "Show baseline" };

        Assert.Equal("AgentQuickAction_Runchecks_Showbaseline", action.AutomationId);
    }
}
