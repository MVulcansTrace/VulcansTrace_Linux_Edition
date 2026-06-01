using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class FindingAssemblyServiceTests
{
    [Fact]
    public void Assemble_FailedRule_CreatesFindingAndHistoryEntry()
    {
        var service = new FindingAssemblyService(new TestExplanationProvider(), suppressionStore: null);
        var ruleResult = RuleResult.Fail(
            "TEST-001",
            "Test",
            "TEST-001",
            "Test failed",
            Severity.High,
            "test-target",
            new Dictionary<string, string> { ["name"] = "value" });

        var result = service.Assemble(new[] { ruleResult });

        Assert.Single(result.AgentFindings);
        Assert.Single(result.HistoryEntries);
        Assert.Equal(ruleResult, result.RuleResults[0]);
        Assert.Equal(0, result.SuppressedCount);
        Assert.Empty(result.Warnings);

        var finding = result.AgentFindings[0];
        Assert.Equal("TEST-001", finding.RuleId);
        Assert.Equal("Test", finding.Category);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("localhost", finding.SourceHost);
        Assert.Equal("test-target", finding.Target);
        Assert.Equal("Test failed", finding.ShortDescription);
        Assert.Equal("explanation:TEST-001:name=value", finding.Details);
        Assert.Equal("TEST-001", result.HistoryEntries[0].RuleId);
        Assert.Same(finding, result.HistoryEntries[0].Finding);
    }

    [Fact]
    public void Assemble_PassedNotApplicableAndCrashedResults_DoNotCreateFindings()
    {
        var service = new FindingAssemblyService(new TestExplanationProvider(), suppressionStore: null);
        var ruleResults = new[]
        {
            RuleResult.Pass("PASS-001", "Test", "PASS-001", "Passed"),
            RuleResult.NotApplicable("NA-001", "Test", "NA-001", "Not applicable"),
            RuleResult.Crash("CRASH-001", "Test", "Crashed")
        };

        var result = service.Assemble(ruleResults);

        Assert.Empty(result.AgentFindings);
        Assert.Empty(result.HistoryEntries);
        Assert.Equal(ruleResults, result.RuleResults);
        Assert.Equal(0, result.SuppressedCount);
    }

    [Fact]
    public void Assemble_SuppressedFinding_MarksRuleResultAndAddsWarning()
    {
        var suppressionStore = new InMemorySuppressionStore();
        suppressionStore.Add(new SuppressionEntry { RuleId = "TEST-001", Target = "test-target" });
        var service = new FindingAssemblyService(new TestExplanationProvider(), suppressionStore);

        var result = service.Assemble(new[]
        {
            RuleResult.Fail("TEST-001", "Test", "TEST-001", "Test failed", Severity.High, "test-target")
        });

        Assert.Empty(result.AgentFindings);
        Assert.Empty(result.HistoryEntries);
        Assert.Equal(1, result.SuppressedCount);
        Assert.Equal(RuleStatus.Suppressed, result.RuleResults[0].Status);
        Assert.Contains("1 finding(s) suppressed by user configuration.", result.Warnings);
    }

    [Fact]
    public void Assemble_SuppressionStore_PrunesExpiredEntriesBeforeChecking()
    {
        var suppressionStore = new TrackingSuppressionStore();
        var service = new FindingAssemblyService(new TestExplanationProvider(), suppressionStore);

        service.Assemble(new[]
        {
            RuleResult.Fail("TEST-001", "Test", "TEST-001", "Test failed", Severity.High, "test-target")
        });

        Assert.True(suppressionStore.PruneExpiredCalled);
        Assert.True(suppressionStore.IsSuppressedWithFingerprintCalled);
    }

    private sealed class TestExplanationProvider : IExplanationProvider
    {
        public string GetExplanation(string key, IReadOnlyDictionary<string, string> variables)
        {
            var suffix = variables.Count == 0
                ? string.Empty
                : ":" + string.Join(",", variables.Select(kvp => $"{kvp.Key}={kvp.Value}"));

            return $"explanation:{key}{suffix}";
        }

        public StructuredExplanation GetStructuredExplanation(string key, IReadOnlyDictionary<string, string> variables)
        {
            return new StructuredExplanation { WhatWasFound = GetExplanation(key, variables) };
        }

        public StructuredExplanation ParseStructuredFromText(string text)
        {
            return new StructuredExplanation { WhatWasFound = text };
        }
    }

    private sealed class TrackingSuppressionStore : ISuppressionStore
    {
        public bool PruneExpiredCalled { get; private set; }
        public bool IsSuppressedWithFingerprintCalled { get; private set; }
        public string? PersistenceWarning => null;

        public void Add(SuppressionEntry entry)
        {
        }

        public void Remove(string ruleId, string target)
        {
        }

        public bool IsSuppressed(string ruleId, string target)
        {
            return false;
        }

        public bool IsSuppressed(string ruleId, string target, string fingerprint)
        {
            IsSuppressedWithFingerprintCalled = true;
            return false;
        }

        public IReadOnlyList<SuppressionEntry> GetAll()
        {
            return Array.Empty<SuppressionEntry>();
        }

        public IReadOnlyList<SuppressionEntry> GetAllRaw()
        {
            return Array.Empty<SuppressionEntry>();
        }

        public int PruneExpired()
        {
            PruneExpiredCalled = true;
            return 0;
        }
    }
}
