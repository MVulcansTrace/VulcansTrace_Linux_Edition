using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Rules.SecurityRules;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class RuleCatalogTests
{
    private static IRule[] GetAllRules() => new IRule[]
    {
        new FirewallActiveRule(),
        new FirewallDefaultDropRule(),
        new FirewallSshExposureRule(),
        new FirewallStateTrackingRule(),
        new FirewallIcmpRule(),
        new DefaultRouteRule(),
        new SuspiciousConnectionsRule(),
        new NetworkInterfaceUpRule(),
        new LoopbackExposureRule(),
        new TelnetServiceRule(),
        new FtpServiceRule(),
        new SshServiceRule(),
        new LegacyRservicesRule(),
        new UnnecessaryServicesRule(),
        new SshNonDefaultPortRule(),
        new WideOpenServicesRule(),
        new DatabasePortExposureRule(),
        new HighPortListeningRule()
    };

    [Fact]
    public void Catalog_Contains_All_Rules()
    {
        var catalog = new RuleCatalog(GetAllRules());

        Assert.Equal(18, catalog.Items.Count);
    }

    [Fact]
    public void Catalog_Items_Have_Required_Metadata()
    {
        var catalog = new RuleCatalog(GetAllRules());

        foreach (var item in catalog.Items)
        {
            Assert.False(string.IsNullOrWhiteSpace(item.Id), $"Rule {item.Id} missing Id");
            Assert.False(string.IsNullOrWhiteSpace(item.Category), $"Rule {item.Id} missing Category");
            Assert.False(string.IsNullOrWhiteSpace(item.Description), $"Rule {item.Id} missing Description");
            Assert.False(string.IsNullOrWhiteSpace(item.WhatItChecks), $"Rule {item.Id} missing WhatItChecks");
            Assert.NotNull(item.SupportedDataSources);
            Assert.True(item.SupportedDataSources.Count > 0, $"Rule {item.Id} has no data sources");
            Assert.False(string.IsNullOrWhiteSpace(item.ExplanationKey), $"Rule {item.Id} missing ExplanationKey");
        }
    }

    [Theory]
    [InlineData("FW-0", 5)]
    [InlineData("NET-0", 4)]
    [InlineData("PORT-0", 4)]
    [InlineData("SRV-0", 5)]
    public void Search_By_Prefix_Returns_Expected_Count(string prefix, int expectedCount)
    {
        var catalog = new RuleCatalog(GetAllRules());
        var results = catalog.Search(prefix).ToList();

        Assert.Equal(expectedCount, results.Count);
    }

    [Fact]
    public void Search_By_DataSource_Returns_Rules_Using_That_Source()
    {
        var catalog = new RuleCatalog(GetAllRules());
        var results = catalog.Search("iptables").ToList();

        Assert.True(results.Count > 0);
        Assert.All(results, r => Assert.Contains("iptables", r.SupportedDataSources.First()));
    }

    [Fact]
    public void Search_Empty_Returns_All()
    {
        var catalog = new RuleCatalog(GetAllRules());
        var results = catalog.Search("").ToList();

        Assert.Equal(18, results.Count);
    }

    [Fact]
    public void Search_No_Match_Returns_Empty()
    {
        var catalog = new RuleCatalog(GetAllRules());
        var results = catalog.Search("XYZ-NONEXISTENT").ToList();

        Assert.Empty(results);
    }
}
