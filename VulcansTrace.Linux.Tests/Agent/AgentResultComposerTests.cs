using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class AgentResultComposerTests
{
    private readonly AgentResultComposer _composer = new();

    [Fact]
    public void BuildSummary_AllPassed_ReturnsPassedSummary()
    {
        var summary = _composer.BuildSummary(
            AgentIntent.FirewallCheck,
            Array.Empty<Finding>(),
            logResult: null,
            new[] { RuleResult.Pass("FW-001", "Firewall", "FW-001", "Firewall is active") });

        Assert.Equal("Firewall check complete. All 1 checks passed.", summary);
    }

    [Fact]
    public void BuildSummary_FindingsSuppressedCrashedAndNotApplicable_IncludesCounts()
    {
        var summary = _composer.BuildSummary(
            AgentIntent.FullAudit,
            new[] { CreateFinding(Severity.Critical), CreateFinding(Severity.Medium) },
            logResult: null,
            new[]
            {
                RuleResult.Pass("PASS-001", "Test", "PASS-001", "Passed"),
                RuleResult.NotApplicable("NA-001", "Test", "NA-001", "Not applicable"),
                RuleResult.Crash("CRASH-001", "Test", "Crashed")
            },
            suppressedCount: 1,
            crashedCount: 1);

        Assert.Equal("Full audit complete. 2 issue(s) found, 1 High/Critical. 1 check(s) passed. 1 suppressed. 1 rule(s) crashed. 1 check(s) not applicable.", summary);
    }

    [Fact]
    public void BuildSummary_LogFindings_IncludesAdditionalLogFindingCount()
    {
        var summary = _composer.BuildSummary(
            AgentIntent.NetworkCheck,
            Array.Empty<Finding>(),
            new AnalysisResult { Findings = new[] { CreateFinding(Severity.High) } },
            new[] { RuleResult.Pass("NET-001", "Network", "NET-001", "Network passed") });

        Assert.Contains("Log analysis found 1 additional finding(s).", summary);
    }

    [Fact]
    public void BuildCapabilityReport_NoCapabilities_ReturnsEmpty()
    {
        var report = _composer.BuildCapabilityReport(Array.Empty<DataSourceCapability>());

        Assert.Equal(string.Empty, report);
    }

    [Fact]
    public void BuildCapabilityReport_IsDeterministicAndDeduplicated()
    {
        var report = _composer.BuildCapabilityReport(new[]
        {
            new DataSourceCapability { SourceName = "systemctl", Status = CapabilityStatus.Unavailable },
            new DataSourceCapability { SourceName = "iptables", Status = CapabilityStatus.Available },
            new DataSourceCapability { SourceName = "systemctl", Status = CapabilityStatus.PermissionLimited },
            new DataSourceCapability { SourceName = "ss", Status = CapabilityStatus.Unknown }
        });

        Assert.Equal("Data sources: iptables available; ss unknown; systemctl permission-limited.", report);
    }

    [Fact]
    public void BuildCapabilityReport_SanitizesAndTruncatesUnavailableDetail()
    {
        var report = _composer.BuildCapabilityReport(new[]
        {
            new DataSourceCapability
            {
                SourceName = "custom",
                Status = CapabilityStatus.Unavailable,
                Detail = "first line\n" + new string('x', 100)
            }
        });

        Assert.StartsWith("Data sources: custom unavailable (first line ", report);
        Assert.Contains("...", report);
        Assert.DoesNotContain('\n', report);
    }

    private static Finding CreateFinding(Severity severity)
    {
        var now = DateTime.UtcNow;
        return new Finding
        {
            Category = "Test",
            Severity = severity,
            SourceHost = "localhost",
            Target = "target",
            ShortDescription = "Test finding",
            Details = "Details",
            TimeRangeStart = now,
            TimeRangeEnd = now
        };
    }
}
