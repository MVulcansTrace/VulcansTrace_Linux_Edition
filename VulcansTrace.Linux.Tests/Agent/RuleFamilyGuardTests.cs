using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Rules.SecurityRules;
using VulcansTrace.Linux.Core.Compliance;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

/// <summary>
/// Regression guard for the CIS benchmark-section-vs-v8-family data bug.
/// <see cref="CisFamilyResolver.ExtractFamilyId"/> reads the CIS Controls v8 family from the
/// leading integer of a rule's numeric <c>ControlId</c>. Several
/// rules historically copied that integer from a CIS <em>Benchmark</em> section number
/// (Ubuntu / Docker / Kubernetes / Containerd), so the rule landed in the wrong v8 family on the
/// Compliance view (e.g. kernel hardening under "Inventory and Control of Enterprise Assets").
/// These tests lock the corrected families so a benchmark number cannot silently regroup a rule
/// into the wrong v8 family again.
/// </summary>
public class RuleFamilyGuardTests
{
    /// <summary>
    /// Rules whose ControlId was corrected from a benchmark section or family wildcard to a
    /// specific CIS Controls v8 safeguard. Benchmark-specific identifiers remain in
    /// <see cref="VulcansTrace.Linux.Core.CisBenchmarkMapping.BenchmarkReference"/>.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, string> ExpectedControlByRuleId =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["KERN-001"] = "CIS 4.1",
            ["KERN-002"] = "CIS 4.1",
            ["KERN-003"] = "CIS 4.1",
            ["KERN-004"] = "CIS 4.1",
            ["KERN-005"] = "CIS 4.1",
            ["KERN-006"] = "CIS 4.1",
            ["KERN-007"] = "CIS 4.1",
            ["FSYS-005"] = "CIS 4.1",
            ["BOOT-001"] = "CIS 4.1",
            ["BOOT-002"] = "CIS 4.1",
            ["BOOT-003"] = "CIS 4.1",
            ["BOOT-004"] = "CIS 4.1",
            ["SYS-001"] = "CIS 4.1",
            ["PKG-VULN-001"] = "CIS 7.3",
            ["PKG-VULN-002"] = "CIS 7.3",
            ["MAC-001"] = "CIS 4.1",
            ["MAC-002"] = "CIS 4.1",
            ["MAC-003"] = "CIS 4.1",
            ["CTR-001"] = "CIS 4.1",
            ["CTR-003"] = "CIS 4.1",
            ["CTR-004"] = "CIS 4.1",
            ["K8S-001"] = "CIS 4.1",
            ["K8S-002"] = "CIS 4.1",
            ["K8S-003"] = "CIS 4.1",
            ["K8S-004"] = "CIS 4.1",
            ["SUDO-001"] = "CIS 6.8",
            ["SUDO-002"] = "CIS 6.8",
            ["SUDO-003"] = "CIS 6.8",
            ["SUDO-004"] = "CIS 6.8",
            ["SUDO-005"] = "CIS 6.8",
            ["SSH-004"] = "CIS 4.1",
            ["SSH-007"] = "CIS 4.1",
            ["SSH-008"] = "CIS 4.1",
            ["NET-004"] = "CIS 4.4",
            ["PORT-002"] = "CIS 4.4",
            ["PORT-003"] = "CIS 4.4",
        };

    private static readonly IReadOnlyDictionary<string, string> ExpectedNameByControlId =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["CIS 4.1"] = "Establish and Maintain a Secure Configuration Process",
            ["CIS 4.4"] = "Implement and Manage a Firewall on Servers",
            ["CIS 6.8"] = "Define and Maintain Role-Based Access Control",
            ["CIS 7.3"] = "Perform Automated Operating System Patch Management",
        };

    private static IReadOnlyList<IRule> DiscoverParameterlessRules()
    {
        var ruleType = typeof(IRule);
        return typeof(AslrEnabledRule).Assembly.GetTypes()
            .Where(t => t is { IsClass: true, IsAbstract: false }
                        && t != ruleType
                        && ruleType.IsAssignableFrom(t)
                        && t.GetConstructor(Type.EmptyTypes) != null)
            .Select(t => (IRule)Activator.CreateInstance(t)!)
            .ToList();
    }

    [Fact]
    public void AllRules_CisMappings_ResolveToKnownV8Family()
    {
        var rules = DiscoverParameterlessRules();
        Assert.NotEmpty(rules);

        foreach (var rule in rules)
        {
            foreach (var mapping in rule.CisMappings)
            {
                var familyId = CisFamilyResolver.ExtractFamilyId(mapping.ControlId);
                Assert.False(familyId is null,
                    $"{rule.Id} ControlId '{mapping.ControlId}' does not parse as a CIS control id");

                var familyName = CisFamilyResolver.GetFamilyName(familyId!);
                Assert.False(string.Equals(familyName, "Other", StringComparison.Ordinal),
                    $"{rule.Id} ControlId '{mapping.ControlId}' resolves to unknown v8 family '{familyId}'");
            }
        }
    }

    [Fact]
    public void RenumberedRules_MapToSpecificV8Safeguard()
    {
        var rules = DiscoverParameterlessRules().ToDictionary(r => r.Id, StringComparer.Ordinal);

        foreach (var (ruleId, expectedControl) in ExpectedControlByRuleId)
        {
            Assert.True(rules.TryGetValue(ruleId, out var rule),
                $"Rule {ruleId} not found among parameterless IRule implementations");
            Assert.NotEmpty(rule!.CisMappings);

            foreach (var mapping in rule.CisMappings)
            {
                Assert.Equal(expectedControl, mapping.ControlId);
                Assert.Equal(ExpectedNameByControlId[expectedControl], mapping.ControlName);
            }
        }
    }
}
