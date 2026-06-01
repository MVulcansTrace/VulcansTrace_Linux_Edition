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
        new HighPortListeningRule(),
        new SshPermitRootLoginRule(),
        new SshPasswordAuthenticationRule(),
        new SshMaxAuthTriesRule(),
        new SshProtocolRule(),
        new SshEmptyPasswordsRule(),
        new SshPubkeyAuthenticationRule(),
        new SshX11ForwardingRule(),
        new ShadowPermissionRule(),
        new PasswdPermissionRule(),
        new SshHostKeyPermissionRule(),
        new RootSshDirectoryPermissionRule(),
        new CronDirectoryWorldWritableRule(),
        new CrontabPermissionRule(),
        new UserSshDirectoryPermissionRule(),
        new AslrEnabledRule(),
        new IpForwardingDisabledRule(),
        new IcmpRedirectsDisabledRule(),
        new SourceRoutingDisabledRule(),
        new KernelModuleLoadingRestrictedRule(),
        new SecureBootEnabledRule(),
        new KernelPointerExposureRestrictedRule(),
        new UidZeroBeyondRootRule(),
        new EmptyPasswordRule(),
        new PasswordAgingRule(),
        new PamPasswordComplexityRule(),
        new InactiveAccountsRule(),
        new DuplicateUidsRule(),
        new MissingHomeDirectoryRule(),
        new WorldWritableFileRule(),
        new UnexpectedSuidSgidRule(),
        new UnownedFileRule(),
        new WorldWritableDirNoStickyRule(),
        new TmpHardeningRule(),
        new LoggingServiceActiveRule(),
        new AuditdActiveRule(),
        new AuditdRulesConfiguredRule(),
        new LogRotationConfiguredRule(),
        new CentralForwardingConfiguredRule(),
        new AuditdPrivilegeEscalationMonitoringRule(),
        new ForwardingUsesTcpRule()
    };

    [Fact]
    public void Catalog_Contains_All_Rules()
    {
        var catalog = new RuleCatalog(GetAllRules());

        Assert.Equal(58, catalog.Items.Count);
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
    [InlineData("SSH-0", 7)]
    [InlineData("FILE-0", 7)]
    [InlineData("FSYS-0", 5)]
    [InlineData("KERN-0", 7)]
    [InlineData("USER-0", 7)]
    [InlineData("LOG-0", 7)]
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

        Assert.Equal(58, results.Count);
    }

    [Fact]
    public void Search_No_Match_Returns_Empty()
    {
        var catalog = new RuleCatalog(GetAllRules());
        var results = catalog.Search("XYZ-NONEXISTENT").ToList();

        Assert.Empty(results);
    }

    [Theory]
    [InlineData("FW-001", "CIS 4.5")]
    [InlineData("FW-002", "CIS 4.5")]
    [InlineData("FW-003", "CIS 4.5")]
    [InlineData("FW-004", "CIS 4.5")]
    [InlineData("FW-005", "CIS 4.5")]
    [InlineData("NET-001", "CIS 4.1")]
    [InlineData("NET-002", "CIS 13.3")]
    [InlineData("NET-003", "CIS 4.1")]
    [InlineData("NET-004", "CIS 4.1")]
    [InlineData("PORT-001", "CIS 4.8")]
    [InlineData("PORT-002", "CIS 4.1")]
    [InlineData("PORT-003", "CIS 4.1")]
    [InlineData("PORT-004", "CIS 13.3")]
    [InlineData("SRV-001", "CIS 4.8")]
    [InlineData("SRV-002", "CIS 4.8")]
    [InlineData("SRV-003", "CIS 4.1")]
    [InlineData("SRV-004", "CIS 4.8")]
    [InlineData("SRV-005", "CIS 4.8")]
    [InlineData("SSH-001", "CIS 5.4")]
    [InlineData("SSH-002", "CIS 6.3")]
    [InlineData("SSH-003", "CIS 6.3")]
    [InlineData("SSH-004", "CIS 4.8")]
    [InlineData("SSH-005", "CIS 5.2")]
    [InlineData("SSH-006", "CIS 6.3")]
    [InlineData("SSH-007", "CIS 4.8")]
    [InlineData("FILE-001", "CIS 6.1")]
    [InlineData("FILE-002", "CIS 6.1")]
    [InlineData("FILE-003", "CIS 5.2")]
    [InlineData("FILE-004", "CIS 5.2")]
    [InlineData("FILE-005", "CIS 6.1")]
    [InlineData("FILE-006", "CIS 6.1")]
    [InlineData("FILE-007", "CIS 5.2")]
    [InlineData("FSYS-001", "CIS 6.1.9")]
    [InlineData("FSYS-002", "CIS 6.1.12")]
    [InlineData("FSYS-003", "CIS 6.1.11")]
    [InlineData("FSYS-004", "CIS 6.1.10")]
    [InlineData("FSYS-005", "CIS 1.1.2")]
    [InlineData("KERN-001", "CIS 1.5")]
    [InlineData("KERN-002", "CIS 3.1")]
    [InlineData("KERN-003", "CIS 3.1")]
    [InlineData("KERN-004", "CIS 3.1")]
    [InlineData("KERN-005", "CIS 1.4")]
    [InlineData("KERN-006", "CIS 1.4")]
    [InlineData("KERN-007", "CIS 1.5")]
    [InlineData("USER-001", "CIS 6.2")]
    [InlineData("USER-002", "CIS 5.4")]
    [InlineData("USER-003", "CIS 5.4")]
    [InlineData("USER-004", "CIS 5.4")]
    [InlineData("USER-005", "CIS 6.2")]
    [InlineData("USER-006", "CIS 6.2")]
    [InlineData("USER-007", "CIS 6.2")]
    [InlineData("LOG-001", "CIS 8.1")]
    [InlineData("LOG-002", "CIS 8.2")]
    [InlineData("LOG-003", "CIS 8.2")]
    [InlineData("LOG-004", "CIS 8.3")]
    [InlineData("LOG-005", "CIS 8.4")]
    [InlineData("LOG-006", "CIS 8.2")]
    [InlineData("LOG-007", "CIS 8.4")]
    public void Catalog_Items_KeyRules_HaveCisMappings(string ruleId, string expectedControlId)
    {
        var catalog = new RuleCatalog(GetAllRules());
        var item = catalog.Items.FirstOrDefault(i => i.Id == ruleId);

        Assert.NotNull(item);
        Assert.NotEmpty(item.CisMappings);
        Assert.Contains(item.CisMappings, m => m.ControlId == expectedControlId);
        Assert.All(item.CisMappings, m =>
        {
            Assert.False(string.IsNullOrWhiteSpace(m.ControlName), $"{ruleId} missing ControlName");
            Assert.False(string.IsNullOrWhiteSpace(m.WhyItMatters), $"{ruleId} missing WhyItMatters");
        });
    }
}
