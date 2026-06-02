using VulcansTrace.Linux.Agent.Baselines;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class BaselineDriftServiceTests
{
    [Fact]
    public async Task SetBaselineAsync_UsesLastAuditIntentAndPreservesOriginalFindings()
    {
        var state = new AgentAuditState();
        var store = new InMemoryBaselineStore("baseline warning");
        var finding = CreateFinding("SSH-001", "sshd_config", Severity.High);
        var audit = new AgentResult
        {
            Intent = AgentIntent.CheckDrift,
            UtcTimestamp = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc),
            AgentFindings = new[] { finding }
        };
        state.RememberAudit(audit, AgentIntent.SshCheck, new[] { ("SSH-001", finding) });
        var service = new BaselineDriftService(state, store, RunAuditShouldNotBeCalled);

        var result = await service.SetBaselineAsync(new AgentQuery(AgentIntent.SetBaseline, "Known SSH"), CancellationToken.None);

        var baseline = Assert.Single(store.GetAll());
        Assert.Equal(AgentIntent.SetBaseline, result.Intent);
        Assert.Equal(AgentIntent.SshCheck, baseline.Intent);
        Assert.Equal("Known SSH", baseline.Name);
        Assert.True(baseline.IsActive);
        Assert.Equal(1, baseline.TotalFindings);
        Assert.Equal(1, baseline.HighCount);
        Assert.Same(finding, baseline.OriginalFindings[0]);
        Assert.Equal("baseline warning", Assert.Single(result.Warnings));
        Assert.NotNull(result.Baseline);
        Assert.Equal(baseline.BaselineId, result.Baseline.BaselineId);
    }

    [Fact]
    public async Task RunDriftCheckAsync_ReturnsNewAndWorsenedFindingsAndRestoresPreviousState()
    {
        var state = new AgentAuditState();
        var previousFinding = CreateFinding("PREV-001", "previous", Severity.Low);
        var previousResult = new AgentResult
        {
            Intent = AgentIntent.FirewallCheck,
            AgentFindings = new[] { previousFinding }
        };
        state.RememberAudit(previousResult, AgentIntent.FirewallCheck, new[] { ("PREV-001", previousFinding) });

        var baselineFinding = CreateFinding("FW-001", "22/tcp", Severity.Low);
        var baseline = CreateBaseline(
            AgentIntent.FirewallCheck,
            baselineFinding,
            new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var store = new InMemoryBaselineStore();
        store.Save(baseline);
        store.SetActive(baseline.BaselineId);

        var liveWorsened = CreateFinding("FW-001", "22/tcp", Severity.High);
        var liveNew = CreateFinding("FW-002", "0.0.0.0/0", Severity.Critical);
        var liveResult = new AgentResult
        {
            Intent = AgentIntent.FirewallCheck,
            UtcTimestamp = new DateTime(2026, 1, 2, 0, 0, 0, DateTimeKind.Utc),
            AgentFindings = new[] { liveWorsened, liveNew },
            Warnings = new[] { "live warning" },
            PassedCount = 3,
            FailedCount = 2,
            CapabilityReport = "capabilities"
        };
        var service = new BaselineDriftService(state, store, (_, _, _) => Task.FromResult(liveResult));

        var result = await service.RunDriftCheckAsync(AgentIntent.FirewallCheck, null, CancellationToken.None);

        Assert.Equal(AgentIntent.CheckDrift, result.Intent);
        Assert.NotNull(result.BaselineDiff);
        Assert.Single(result.BaselineDiff.Diff.NewFindings);
        Assert.Single(result.BaselineDiff.Diff.WorsenedFindings);
        Assert.Equal(2, result.AgentFindings.Count);
        Assert.Contains(result.AgentFindings, f => f.RuleId == "FW-001" && f.Category == "Drift");
        Assert.Contains(result.AgentFindings, f => f.RuleId == "FW-002" && f.Category == "Drift");
        Assert.Equal("live warning", Assert.Single(result.Warnings));
        Assert.Equal(3, result.PassedCount);
        Assert.Equal(2, result.FailedCount);
        Assert.Equal("capabilities", result.CapabilityReport);
        Assert.Same(previousResult, state.LastResult);
    }

    [Fact]
    public async Task ShowBaselineForIntentAsync_UsesOriginalFindingsWhenAvailable()
    {
        var state = new AgentAuditState();
        var finding = CreateFinding("PKG-001", "openssl", Severity.Medium);
        var baseline = CreateBaseline(AgentIntent.PackageVulnerabilityCheck, finding, DateTime.UtcNow);
        var store = new InMemoryBaselineStore();
        store.Save(baseline);
        store.SetActive(baseline.BaselineId);
        var service = new BaselineDriftService(state, store, RunAuditShouldNotBeCalled);

        var result = await service.ShowBaselineForIntentAsync(AgentIntent.PackageVulnerabilityCheck, CancellationToken.None);

        Assert.Equal(AgentIntent.ShowBaseline, result.Intent);
        Assert.NotNull(result.Baseline);
        Assert.Equal(baseline.BaselineId, result.Baseline.BaselineId);
        var shown = Assert.Single(result.AgentFindings);
        Assert.Equal(finding.RuleId, shown.RuleId);
        Assert.Contains("Part of baseline", shown.Details);
    }

    private static Task<AgentResult> RunAuditShouldNotBeCalled(AgentIntent intent, string? rawLog, CancellationToken ct)
    {
        throw new InvalidOperationException("RunAudit should not be called by this test.");
    }

    private static BaselineEntry CreateBaseline(AgentIntent intent, Finding finding, DateTime createdUtc)
    {
        return new BaselineEntry
        {
            BaselineId = Guid.NewGuid().ToString("N"),
            Name = $"{intent} baseline",
            CreatedUtc = createdUtc,
            Intent = intent,
            TotalFindings = 1,
            CriticalCount = finding.Severity == Severity.Critical ? 1 : 0,
            HighCount = finding.Severity == Severity.High ? 1 : 0,
            MediumCount = finding.Severity == Severity.Medium ? 1 : 0,
            LowCount = finding.Severity == Severity.Low ? 1 : 0,
            InfoCount = finding.Severity == Severity.Info ? 1 : 0,
            SnapshotFindings = new[]
            {
                new AuditSnapshotFinding
                {
                    RuleId = finding.RuleId!,
                    Target = finding.Target,
                    Severity = finding.Severity.ToString(),
                    ShortDescription = finding.ShortDescription,
                    Category = finding.Category,
                    Fingerprint = finding.Fingerprint
                }
            },
            OriginalFindings = new[] { finding }
        };
    }

    private static Finding CreateFinding(string ruleId, string target, Severity severity)
    {
        var now = DateTime.UtcNow;
        return new Finding
        {
            RuleId = ruleId,
            Category = "Test",
            Severity = severity,
            SourceHost = "localhost",
            Target = target,
            ShortDescription = $"{ruleId} finding",
            Details = "Details",
            TimeRangeStart = now,
            TimeRangeEnd = now
        };
    }
}
