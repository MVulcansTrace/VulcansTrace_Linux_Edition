using VulcansTrace.Linux.Agent.Analysis;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class ProactiveAlertDetectorTests
{
    private readonly ProactiveAlertDetector _detector = new();

    [Fact]
    public void Detect_NoHistory_ReturnsEmpty()
    {
        var finding = CreateFinding("FW-001", Severity.High);
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase);

        var alerts = _detector.Detect(new[] { finding }, history, DateTime.UtcNow);

        Assert.Empty(alerts);
    }

    [Fact]
    public void Detect_FixedThenReturned_ReturnsAlert()
    {
        var now = DateTime.UtcNow;
        var finding = CreateFinding("FW-001", Severity.High);
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = new RuleMemoryEntry
            {
                RuleId = "FW-001",
                LastVerifiedFixedUtc = now.AddDays(-3),
                SeverityHistory = new[]
                {
                    new RuleSeveritySnapshot { UtcTimestamp = now.AddDays(-7), Severity = Severity.High },
                    new RuleSeveritySnapshot { UtcTimestamp = now, Severity = Severity.High }
                }
            }
        };

        var alerts = _detector.Detect(new[] { finding }, history, now);

        Assert.Single(alerts);
        var alert = alerts[0];
        Assert.Equal("FW-001", alert.RuleId);
        Assert.Equal(3, alert.DaysSinceVerifiedFixed);
        Assert.Equal(Severity.High, alert.CurrentSeverity);
        Assert.Contains("firewall", alert.Guidance, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Detect_NeverFixed_ReturnsEmpty()
    {
        var now = DateTime.UtcNow;
        var finding = CreateFinding("FW-001", Severity.High);
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = new RuleMemoryEntry
            {
                RuleId = "FW-001",
                LastVerifiedFixedUtc = null,
                SeverityHistory = new[]
                {
                    new RuleSeveritySnapshot { UtcTimestamp = now.AddDays(-7), Severity = Severity.High },
                    new RuleSeveritySnapshot { UtcTimestamp = now, Severity = Severity.High }
                }
            }
        };

        var alerts = _detector.Detect(new[] { finding }, history, now);

        Assert.Empty(alerts);
    }

    [Fact]
    public void Detect_NotCurrentlyFailing_ReturnsEmpty()
    {
        var now = DateTime.UtcNow;
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = new RuleMemoryEntry
            {
                RuleId = "FW-001",
                LastVerifiedFixedUtc = now.AddDays(-3),
                SeverityHistory = new[]
                {
                    new RuleSeveritySnapshot { UtcTimestamp = now.AddDays(-7), Severity = Severity.High },
                    new RuleSeveritySnapshot { UtcTimestamp = now, Severity = Severity.High }
                }
            }
        };

        var alerts = _detector.Detect(Array.Empty<Finding>(), history, now);

        Assert.Empty(alerts);
    }

    [Fact]
    public void Detect_MultipleAlerts_ReturnsAll()
    {
        var now = DateTime.UtcNow;
        var findings = new[]
        {
            CreateFinding("FW-001", Severity.High),
            CreateFinding("SSH-002", Severity.Critical)
        };
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = new RuleMemoryEntry
            {
                RuleId = "FW-001",
                LastVerifiedFixedUtc = now.AddDays(-1),
                SeverityHistory = Array.Empty<RuleSeveritySnapshot>()
            },
            ["SSH-002"] = new RuleMemoryEntry
            {
                RuleId = "SSH-002",
                LastVerifiedFixedUtc = now.AddDays(-5),
                SeverityHistory = Array.Empty<RuleSeveritySnapshot>()
            }
        };

        var alerts = _detector.Detect(findings, history, now);

        Assert.Equal(2, alerts.Count);
        Assert.Contains(alerts, a => a.RuleId == "FW-001" && a.DaysSinceVerifiedFixed == 1);
        Assert.Contains(alerts, a => a.RuleId == "SSH-002" && a.DaysSinceVerifiedFixed == 5);
        Assert.Contains(alerts, a => a.RuleId == "SSH-002" && a.Guidance.Contains("SSH", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Detect_MultipleFindingsSameRule_DedupesToSingleAlert()
    {
        var now = DateTime.UtcNow;
        var findings = new[]
        {
            CreateFinding("PORT-002", Severity.High),
            CreateFinding("PORT-002", Severity.High),
            CreateFinding("PORT-002", Severity.Critical)
        };
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["PORT-002"] = new RuleMemoryEntry
            {
                RuleId = "PORT-002",
                LastVerifiedFixedUtc = now.AddDays(-3),
                SeverityHistory = Array.Empty<RuleSeveritySnapshot>()
            }
        };

        var alerts = _detector.Detect(findings, history, now);

        Assert.Single(alerts);
        Assert.Equal("PORT-002", alerts[0].RuleId);
        Assert.Equal(Severity.Critical, alerts[0].CurrentSeverity);
    }

    [Fact]
    public void Detect_SameAuditAsVerifiedFixed_DoesNotAlert()
    {
        var now = DateTime.UtcNow;
        var finding = CreateFinding("FW-001", Severity.High);
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = new RuleMemoryEntry
            {
                RuleId = "FW-001",
                LastVerifiedFixedUtc = now,
                SeverityHistory = Array.Empty<RuleSeveritySnapshot>()
            }
        };

        var alerts = _detector.Detect(new[] { finding }, history, now);

        Assert.Empty(alerts);
    }

    [Fact]
    public void Detect_ReferenceUtcBeforeVerifiedFixed_DoesNotAlert()
    {
        var now = DateTime.UtcNow;
        var finding = CreateFinding("FW-001", Severity.High);
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = new RuleMemoryEntry
            {
                RuleId = "FW-001",
                LastVerifiedFixedUtc = now,
                SeverityHistory = Array.Empty<RuleSeveritySnapshot>()
            }
        };

        var alerts = _detector.Detect(new[] { finding }, history, now.AddSeconds(-1));

        Assert.Empty(alerts);
    }

    private static Finding CreateFinding(string ruleId, Severity severity)
    {
        return new Finding
        {
            RuleId = ruleId,
            Category = "Test",
            Severity = severity,
            SourceHost = "localhost",
            Target = "target",
            ShortDescription = $"Finding {ruleId}",
            Details = "Details",
            TimeRangeStart = DateTime.UtcNow,
            TimeRangeEnd = DateTime.UtcNow
        };
    }
}
