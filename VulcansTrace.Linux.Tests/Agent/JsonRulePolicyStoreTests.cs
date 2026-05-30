using System.Collections.Immutable;
using System.IO;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class JsonRulePolicyStoreTests
{
    [Fact]
    public void RoundTrip_SaveAndLoad_ReturnsSamePolicy()
    {
        var path = Path.GetTempFileName();
        try
        {
            var store = new JsonRulePolicyStore(path);
            var policy = new RulePolicy
            {
                Enabled = false,
                SeverityOverride = Severity.High,
                AutoPass = true,
                Parameters = new Dictionary<string, string> { ["expectedPublicPorts"] = "22,80,8080" }.ToImmutableDictionary()
            };
            store.SetPolicy(MachineRole.DevMachine, "PORT-002", policy);

            // Reload
            var loadedStore = new JsonRulePolicyStore(path);
            var loaded = loadedStore.GetPolicy("PORT-002", MachineRole.DevMachine);

            Assert.NotNull(loaded);
            Assert.False(loaded.Enabled);
            Assert.Equal(Severity.High, loaded.SeverityOverride);
            Assert.True(loaded.AutoPass);
            Assert.Equal("22,80,8080", loaded.Parameters["expectedPublicPorts"]);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void GetPolicy_MissingRule_ReturnsNull()
    {
        var path = Path.GetTempFileName();
        try
        {
            var store = new JsonRulePolicyStore(path);
            var policy = store.GetPolicy("MISSING", MachineRole.Server);
            Assert.Null(policy);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Load_HandEditedJson_UsesCaseInsensitiveRoleAndRuleLookup()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, """
                {
                  "devmachine": {
                    "port-002": {
                      "parameters": {
                        "expectedPublicPorts": "22,80,443,3000"
                      }
                    }
                  }
                }
                """);

            var store = new JsonRulePolicyStore(path);
            var policy = store.GetPolicy("PORT-002", MachineRole.DevMachine);

            Assert.NotNull(policy);
            Assert.Equal("22,80,443,3000", policy.Parameters["expectedPublicPorts"]);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
