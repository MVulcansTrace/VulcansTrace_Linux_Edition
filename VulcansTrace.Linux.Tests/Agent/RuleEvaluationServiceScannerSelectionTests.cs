using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Rules.SecurityRules;
using VulcansTrace.Linux.Agent.Rules.SecurityRules.ThreatIntel;
using VulcansTrace.Linux.Agent.ThreatIntel;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

/// <summary>
/// Verifies scanner selection is DERIVED from rule data dependencies, not a hand-maintained
/// intent map. These are the cases that previously regressed as silent false-negatives
/// (TI-001/TI-002 under /threatintel, NET-004 under /network) because the rules read data
/// produced by scanners the intent didn't run.
/// </summary>
public class RuleEvaluationServiceScannerSelectionTests
{
    private static RuleEvaluationService With(params IRule[] rules) =>
        new(rules, MachineRole.Server, policyProvider: null);

    [Fact]
    public void FullAudit_ReturnsNull_SoAllScannersRun()
    {
        var svc = With(new DefaultRouteRule());

        Assert.Null(svc.GetRequiredScannerNames(AgentIntent.FullAudit));
    }

    [Fact]
    public void ThreatIntelCheck_IncludesFileHash_Port_And_Network()
    {
        var store = new InMemoryThreatIntelStore();
        var svc = With(new ThreatIntelHashRule(store), new ThreatIntelIpRule(store), new ThreatIntelPortRule(store));

        var names = svc.GetRequiredScannerNames(AgentIntent.ThreatIntelCheck);

        Assert.NotNull(names);
        Assert.Contains("FileHash", names!, StringComparer.OrdinalIgnoreCase);  // TI-003
        Assert.Contains("Port", names!, StringComparer.OrdinalIgnoreCase);      // TI-002 reads OpenPorts
        Assert.Contains("Network", names!, StringComparer.OrdinalIgnoreCase);   // TI-001 reads ActiveConnections
    }

    [Fact]
    public void NetworkCheck_IncludesPort_ForLoopbackExposureRule()
    {
        var svc = With(new DefaultRouteRule(), new LoopbackExposureRule());

        var names = svc.GetRequiredScannerNames(AgentIntent.NetworkCheck);

        Assert.NotNull(names);
        Assert.Contains("Network", names!, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("Port", names!, StringComparer.OrdinalIgnoreCase);      // NET-004 reads OpenPorts
    }

    [Fact]
    public void PortCheck_DerivesOnlyPort_WhenRulesReadNoCrossCategoryData()
    {
        var svc = With(new DatabasePortExposureRule());

        var names = svc.GetRequiredScannerNames(AgentIntent.PortCheck);

        Assert.NotNull(names);
        Assert.Equal("Port", Assert.Single(names!));
    }

    [Fact]
    public void FirewallCheck_DerivesOnlyFirewall()
    {
        var svc = With(new FirewallActiveRule());

        var names = svc.GetRequiredScannerNames(AgentIntent.FirewallCheck);

        Assert.NotNull(names);
        Assert.Equal("Firewall", Assert.Single(names!));
    }
}
