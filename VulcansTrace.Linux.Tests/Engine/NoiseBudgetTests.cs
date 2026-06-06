using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using Xunit;

namespace VulcansTrace.Linux.Tests.Engine;

public class NoiseBudgetTests
{
    [Fact]
    public void ApplyNoiseBudget_GroupsByFingerprint_MergesTimeRange()
    {
        var baseTime = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);

        var findings = new List<Finding>
        {
            new()
            {
                Category = "PortScan",
                Severity = Severity.Medium,
                SourceHost = "10.0.0.1",
                Target = "multiple ports",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime.AddMinutes(5),
                ShortDescription = "Scan",
                Details = "Details"
            },
            new()
            {
                Category = "PortScan",
                Severity = Severity.Medium,
                SourceHost = "10.0.0.1",
                Target = "multiple ports",
                TimeRangeStart = baseTime.AddMinutes(30),
                TimeRangeEnd = baseTime.AddMinutes(35),
                ShortDescription = "Scan",
                Details = "Details"
            },
            new()
            {
                Category = "PortScan",
                Severity = Severity.Medium,
                SourceHost = "10.0.0.1",
                Target = "multiple ports",
                TimeRangeStart = baseTime.AddMinutes(60),
                TimeRangeEnd = baseTime.AddMinutes(65),
                ShortDescription = "Scan",
                Details = "Details"
            }
        };

        var profile = new AnalysisProfile { MaxFindingsPerDetector = 10 };
        var warnings = new List<string>();

        var result = SentryAnalyzer.ApplyNoiseBudget(findings, profile, warnings);

        Assert.Single(result);
        Assert.Equal(3, result[0].GroupedCount);
        Assert.Equal(baseTime, result[0].TimeRangeStart);
        Assert.Equal(baseTime.AddMinutes(65), result[0].TimeRangeEnd);
    }

    [Fact]
    public void ApplyNoiseBudget_GroupsSimilarFindingsAcrossDifferentTargets()
    {
        var baseTime = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
        var findings = new[]
        {
            new Finding
            {
                Category = "FilesystemAudit",
                Severity = Severity.High,
                SourceHost = "localhost",
                Target = "/tmp/a",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime,
                ShortDescription = "World writable file",
                Details = "File can be modified by any local user."
            },
            new Finding
            {
                Category = "FilesystemAudit",
                Severity = Severity.High,
                SourceHost = "localhost",
                Target = "/tmp/b",
                TimeRangeStart = baseTime.AddMinutes(1),
                TimeRangeEnd = baseTime.AddMinutes(1),
                ShortDescription = "World writable file",
                Details = "File can be modified by any local user."
            },
            new Finding
            {
                Category = "FilesystemAudit",
                Severity = Severity.High,
                SourceHost = "localhost",
                Target = "/var/log/c",
                TimeRangeStart = baseTime.AddMinutes(2),
                TimeRangeEnd = baseTime.AddMinutes(2),
                ShortDescription = "World writable file",
                Details = "File can be modified by any local user."
            }
        };
        var profile = new AnalysisProfile { MaxFindingsPerDetector = 10 };
        var warnings = new List<string>();

        var result = SentryAnalyzer.ApplyNoiseBudget(findings, profile, warnings);

        var finding = Assert.Single(result);
        Assert.Equal(3, finding.GroupedCount);
        Assert.Equal(new[] { "/tmp/a", "/tmp/b", "/var/log/c" }, finding.RepresentativeTargets);
        Assert.Contains("/tmp", finding.RiskDrivers);
        Assert.Contains("/var/log", finding.RiskDrivers);
        Assert.Empty(warnings);
    }

    [Fact]
    public void ApplyNoiseBudget_RuleBackedFindingsIgnoreTargetSpecificDetails()
    {
        var baseTime = DateTime.UtcNow;
        var findings = new[]
        {
            new Finding
            {
                RuleId = "FS-001",
                Category = "FilesystemAudit",
                Severity = Severity.High,
                SourceHost = "localhost",
                Target = "/tmp/a",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime,
                ShortDescription = "World writable file",
                Details = "Path /tmp/a is world writable."
            },
            new Finding
            {
                RuleId = "FS-001",
                Category = "FilesystemAudit",
                Severity = Severity.High,
                SourceHost = "localhost",
                Target = "/tmp/b",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime,
                ShortDescription = "World writable file",
                Details = "Path /tmp/b is world writable."
            }
        };
        var profile = new AnalysisProfile { MaxFindingsPerDetector = 10 };
        var warnings = new List<string>();

        var result = SentryAnalyzer.ApplyNoiseBudget(findings, profile, warnings);

        var finding = Assert.Single(result);
        Assert.Equal(2, finding.GroupedCount);
        Assert.Equal(new[] { "/tmp/a", "/tmp/b" }, finding.RepresentativeTargets);
    }

    [Fact]
    public void ApplyNoiseBudget_PicksHighestSeverityRepresentative()
    {
        var baseTime = DateTime.UtcNow;

        var findings = new List<Finding>
        {
            new()
            {
                Category = "Beaconing",
                Severity = Severity.Medium,
                SourceHost = "10.0.0.1",
                Target = "192.168.1.1:443",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime.AddMinutes(1),
                ShortDescription = "Beacon",
                Details = "Details"
            },
            new()
            {
                Category = "Beaconing",
                Severity = Severity.Critical,
                SourceHost = "10.0.0.1",
                Target = "192.168.1.1:443",
                TimeRangeStart = baseTime.AddMinutes(2),
                TimeRangeEnd = baseTime.AddMinutes(3),
                ShortDescription = "Beacon",
                Details = "Details"
            },
            new()
            {
                Category = "Beaconing",
                Severity = Severity.High,
                SourceHost = "10.0.0.1",
                Target = "192.168.1.1:443",
                TimeRangeStart = baseTime.AddMinutes(4),
                TimeRangeEnd = baseTime.AddMinutes(5),
                ShortDescription = "Beacon",
                Details = "Details"
            }
        };

        var profile = new AnalysisProfile { MaxFindingsPerDetector = 10 };
        var warnings = new List<string>();

        var result = SentryAnalyzer.ApplyNoiseBudget(findings, profile, warnings);

        Assert.Single(result);
        Assert.Equal(Severity.Critical, result[0].Severity);
        Assert.Equal(3, result[0].GroupedCount);
    }

    [Fact]
    public void ApplyNoiseBudget_DerivesPathRiskDrivers()
    {
        var findings = new List<Finding>
        {
            new()
            {
                Category = "FilesystemAudit",
                Severity = Severity.Medium,
                SourceHost = "localhost",
                Target = "/var/www/html/index.php",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "World-writable",
                Details = "Details"
            },
            new()
            {
                Category = "FilesystemAudit",
                Severity = Severity.Medium,
                SourceHost = "localhost",
                Target = "/var/www/css/style.css",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "World-writable",
                Details = "Details"
            },
            new()
            {
                Category = "FilesystemAudit",
                Severity = Severity.Medium,
                SourceHost = "localhost",
                Target = "/opt/app/config.yml",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "World-writable",
                Details = "Details"
            }
        };

        var drivers = SentryAnalyzer.DeriveRiskDrivers(findings);

        // Path.GetDirectoryName returns immediate parent directories
        Assert.Contains("/var/www/html", drivers);
        Assert.Contains("/var/www/css", drivers);
        Assert.Contains("/opt/app", drivers);
    }

    [Fact]
    public void ApplyNoiseBudget_DerivesIpRiskDrivers()
    {
        var findings = new List<Finding>
        {
            new()
            {
                Category = "Beaconing",
                Severity = Severity.Medium,
                SourceHost = "10.0.0.1",
                Target = "192.168.1.10:443",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Beacon",
                Details = "Details"
            },
            new()
            {
                Category = "Beaconing",
                Severity = Severity.Medium,
                SourceHost = "10.0.0.1",
                Target = "192.168.1.10:8080",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Beacon",
                Details = "Details"
            },
            new()
            {
                Category = "Beaconing",
                Severity = Severity.Medium,
                SourceHost = "10.0.0.1",
                Target = "10.0.0.5:22",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Beacon",
                Details = "Details"
            }
        };

        var drivers = SentryAnalyzer.DeriveRiskDrivers(findings);

        Assert.Contains("192.168.1.10", drivers);
        Assert.Contains("10.0.0.5", drivers);
    }

    [Fact]
    public void ApplyNoiseBudget_DerivesIpRiskDrivers_IgnoresMalformed()
    {
        var findings = new List<Finding>
        {
            new()
            {
                Category = "Beaconing",
                Severity = Severity.Medium,
                SourceHost = "10.0.0.1",
                Target = "::1",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Beacon",
                Details = "Details"
            },
            new()
            {
                Category = "Beaconing",
                Severity = Severity.Medium,
                SourceHost = "10.0.0.1",
                Target = "[bad",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Beacon",
                Details = "Details"
            },
            new()
            {
                Category = "Beaconing",
                Severity = Severity.Medium,
                SourceHost = "10.0.0.1",
                Target = "[malformed",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Beacon",
                Details = "Details"
            }
        };

        var drivers = SentryAnalyzer.DeriveRiskDrivers(findings);

        // None of the malformed targets should produce garbage IP drivers;
        // should fall through to source-host derivation.
        Assert.DoesNotContain(":", drivers);
        Assert.DoesNotContain("[bad", drivers);
        Assert.DoesNotContain("[malformed", drivers);
    }

    [Fact]
    public void ApplyNoiseBudget_RespectsMaxFindingsPerDetector()
    {
        var baseTime = DateTime.UtcNow;
        var findings = new List<Finding>();

        for (int i = 0; i < 12; i++)
        {
            findings.Add(new Finding
            {
                Category = "Novelty",
                Severity = Severity.Info,
                SourceHost = $"10.0.0.{i + 1}",
                Target = $"192.168.1.{i + 1}",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime,
                ShortDescription = "Novel",
                Details = "Details"
            });
        }

        var profile = new AnalysisProfile { MaxFindingsPerDetector = 5 };
        var warnings = new List<string>();

        var result = SentryAnalyzer.ApplyNoiseBudget(findings, profile, warnings);

        Assert.Equal(5, result.Count);
        Assert.Contains(warnings, w => w.Contains("Novelty") && w.Contains("showing top 5"));
    }

    [Fact]
    public void ApplyNoiseBudget_DisabledWhenMaxIsZero()
    {
        var findings = new List<Finding>
        {
            new()
            {
                Category = "PortScan",
                Severity = Severity.Medium,
                SourceHost = "10.0.0.1",
                Target = "multiple ports",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Scan",
                Details = "Details"
            },
            new()
            {
                Category = "PortScan",
                Severity = Severity.Medium,
                SourceHost = "10.0.0.1",
                Target = "multiple ports",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Scan",
                Details = "Details"
            }
        };

        var profile = new AnalysisProfile { MaxFindingsPerDetector = 0 };
        var warnings = new List<string>();

        var result = SentryAnalyzer.ApplyNoiseBudget(findings, profile, warnings);

        Assert.Equal(2, result.Count);
        Assert.Empty(warnings);
    }

    [Fact]
    public void ApplyNoiseBudget_RepresentativeTargets_DedupesSameTarget()
    {
        var baseTime = DateTime.UtcNow;
        var findings = new List<Finding>();

        // All share the same fingerprint (same category, source, target)
        for (int i = 0; i < 10; i++)
        {
            findings.Add(new Finding
            {
                Category = "PortScan",
                Severity = Severity.Medium,
                SourceHost = "10.0.0.1",
                Target = "multiple ports",
                TimeRangeStart = baseTime.AddMinutes(i),
                TimeRangeEnd = baseTime.AddMinutes(i + 1),
                ShortDescription = "Scan",
                Details = "Details"
            });
        }

        var profile = new AnalysisProfile { MaxFindingsPerDetector = 10 };
        var warnings = new List<string>();

        var result = SentryAnalyzer.ApplyNoiseBudget(findings, profile, warnings);

        Assert.Single(result);
        Assert.Equal(10, result[0].GroupedCount);
        // Same target across all findings, so RepresentativeTargets has one item
        Assert.Single(result[0].RepresentativeTargets);
        Assert.Equal("multiple ports", result[0].RepresentativeTargets[0]);
    }

    [Fact]
    public void ApplyNoiseBudget_EmptyFindings_ReturnsEmpty()
    {
        var profile = new AnalysisProfile { MaxFindingsPerDetector = 10 };
        var warnings = new List<string>();

        var result = SentryAnalyzer.ApplyNoiseBudget(Array.Empty<Finding>(), profile, warnings);

        Assert.Empty(result);
        Assert.Empty(warnings);
    }

    [Fact]
    public void ApplyNoiseBudget_OrdersBySeverityThenGroupedCount()
    {
        var baseTime = DateTime.UtcNow;
        var findings = new List<Finding>();

        // Group A: 1 Critical finding
        findings.Add(new Finding
        {
            Category = "PortScan",
            Severity = Severity.Critical,
            SourceHost = "10.0.0.1",
            Target = "multiple ports",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime,
            ShortDescription = "Scan",
            Details = "Details"
        });

        // Group B: 3 High findings (same fingerprint)
        for (int i = 0; i < 3; i++)
        {
            findings.Add(new Finding
            {
                Category = "PortScan",
                Severity = Severity.High,
                SourceHost = "10.0.0.2",
                Target = "multiple ports",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime,
                ShortDescription = "Scan",
                Details = "Details"
            });
        }

        // Group C: 2 Medium findings (same fingerprint)
        for (int i = 0; i < 2; i++)
        {
            findings.Add(new Finding
            {
                Category = "PortScan",
                Severity = Severity.Medium,
                SourceHost = "10.0.0.3",
                Target = "multiple ports",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime,
                ShortDescription = "Scan",
                Details = "Details"
            });
        }

        var profile = new AnalysisProfile { MaxFindingsPerDetector = 2 };
        var warnings = new List<string>();

        var result = SentryAnalyzer.ApplyNoiseBudget(findings, profile, warnings);

        Assert.Equal(2, result.Count);
        Assert.Equal(Severity.Critical, result[0].Severity);
        Assert.Equal(Severity.High, result[1].Severity);
        Assert.Equal(3, result[1].GroupedCount);
    }
}
