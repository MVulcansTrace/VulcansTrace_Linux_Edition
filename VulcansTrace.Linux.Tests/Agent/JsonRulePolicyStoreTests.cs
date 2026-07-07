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

    [Fact]
    public void SaveFailure_SurfacesPersistenceWarning_AndKeepsValueInMemory()
    {
        var blockingFile = Path.GetTempFileName();
        try
        {
            // A path whose parent "directory" is itself a file → Save throws on directory creation.
            var impossiblePath = Path.Combine(blockingFile, "policy.json");
            var store = new JsonRulePolicyStore(impossiblePath);

            var save = store.SetPolicy(MachineRole.Server, "FW-001", new RulePolicy { Enabled = false });

            Assert.Equal(RulePolicySaveOutcome.SessionOnly, save.Outcome);
            Assert.NotNull(store.PersistenceWarning);
            Assert.Contains("Could not save policy", store.PersistenceWarning);
            // The edit is still visible in-memory for the session even though it was not persisted.
            var policy = store.GetPolicy("FW-001", MachineRole.Server);
            Assert.NotNull(policy);
            Assert.False(policy.Enabled);
        }
        finally
        {
            File.Delete(blockingFile);
        }
    }

    [Fact]
    public void TransientLoadFailure_DoesNotClobberValidFile()
    {
        var dir = Path.Combine(Path.GetTempPath(), "policy-transient-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "policy.json");
        try
        {
            // Seed a valid policy file.
            var seedStore = new JsonRulePolicyStore(path);
            seedStore.SetPolicy(MachineRole.Server, "FW-001",
                new RulePolicy { Enabled = false, SeverityOverride = Severity.Critical });
            var originalJson = File.ReadAllText(path);

            // Hold an exclusive write lock so the next store's load hits a sharing violation
            // (the transient branch — file presumed valid but unreadable).
            using (var lockStream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
            {
                var store = new JsonRulePolicyStore(path);
                Assert.NotNull(store.PersistenceWarning);
                Assert.Contains("Could not load saved policy", store.PersistenceWarning);

                // Editing while load-incomplete must apply in-memory but NOT overwrite the file.
                var save = store.SetPolicy(MachineRole.Server, "FW-001", new RulePolicy { Enabled = true });
                Assert.Equal(RulePolicySaveOutcome.SessionOnly, save.Outcome);
                Assert.Contains("session", store.PersistenceWarning, StringComparison.OrdinalIgnoreCase);
            }

            // Lock released: the on-disk file must be byte-identical (never written).
            Assert.Equal(originalJson, File.ReadAllText(path));

            // A fresh store reloads the original valid data intact — no data loss.
            var reloaded = new JsonRulePolicyStore(path);
            Assert.Null(reloaded.PersistenceWarning);
            var policy = reloaded.GetPolicy("FW-001", MachineRole.Server);
            Assert.NotNull(policy);
            Assert.False(policy.Enabled);
            Assert.Equal(Severity.Critical, policy.SeverityOverride);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void Load_UndefinedIntegerSeverity_QuarantinesAndWarns()
    {
        var dir = Path.Combine(Path.GetTempPath(), "policy-badsev-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "policy.json");
        try
        {
            // JsonStringEnumConverter()'s parameterless ctor allows integer values, so 999
            // deserializes to (Severity)999. The validator must reject it and quarantine the file.
            File.WriteAllText(path, """
                {
                  "server": {
                    "TEST-001": { "severityOverride": 999 }
                  }
                }
                """);

            var store = new JsonRulePolicyStore(path);

            Assert.NotNull(store.PersistenceWarning);
            Assert.Contains("quarantined", store.PersistenceWarning, StringComparison.OrdinalIgnoreCase);
            Assert.Null(store.GetPolicy("TEST-001", MachineRole.Server));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }
}
