using VulcansTrace.Linux.Agent.Rules.SecurityRules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Tests.Agent.Rules;

public class YaraRulesTests
{
    [Fact]
    public void YaraMatchRule_NoMatches_Passes()
    {
        var rule = new YaraMatchRule();
        var data = new ScanData();

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(FindingCategories.Yara, result.Category);
    }

    [Fact]
    public void YaraMatchRule_WithMatches_Fails()
    {
        var rule = new YaraMatchRule();
        var data = new ScanData
        {
            YaraMatches = new[]
            {
                new YaraMatchEntry
                {
                    TargetPath = "/usr/bin/suspicious",
                    ResolvedTargetPath = "/usr/bin/suspicious",
                    TargetKind = "SuidBinary",
                    RuleIdentifier = "Linux_SUID_Shell_Backdoor",
                    ProcessId = null,
                    MatchDescription = "SUID backdoor signature"
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
        Assert.Equal("/usr/bin/suspicious", result.Target);
        Assert.Equal("Linux_SUID_Shell_Backdoor", result.Variables["ruleIdentifier"]);
        Assert.Equal("SuidBinary", result.Variables["targetKind"]);
        Assert.Equal("/usr/bin/suspicious", result.Variables["scanPath"]);
        Assert.Contains("/usr/bin/suspicious", result.Variables["matchList"]);
    }

    [Fact]
    public void YaraMatchRule_MultipleMatches_IncludesCountAndFirstPath()
    {
        var rule = new YaraMatchRule();
        var data = new ScanData
        {
            YaraMatches = new[]
            {
                new YaraMatchEntry
                {
                    TargetPath = "/tmp/bad",
                    ResolvedTargetPath = "/tmp/bad",
                    TargetKind = "CronScript",
                    RuleIdentifier = "Linux_Mirai_Generic"
                },
                new YaraMatchEntry
                {
                    TargetPath = "/usr/bin/evil",
                    ResolvedTargetPath = "/usr/bin/evil",
                    TargetKind = "SuidBinary",
                    RuleIdentifier = "Linux_SUID_Shell_Backdoor"
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal("2", result.Variables["count"]);
        Assert.Equal("/tmp/bad", result.Target);
        Assert.Contains("/tmp/bad", result.Variables["matchList"]);
        Assert.Contains("/usr/bin/evil", result.Variables["matchList"]);
    }

    [Fact]
    public void YaraMatchRule_ProcessMatch_UsesResolvedPathAsTargetAndKeepsProcScanPath()
    {
        var rule = new YaraMatchRule();
        var data = new ScanData
        {
            YaraMatches = new[]
            {
                new YaraMatchEntry
                {
                    TargetPath = "/proc/123/exe",
                    ResolvedTargetPath = "/tmp/deleted-malware",
                    TargetKind = "RunningProcess",
                    RuleIdentifier = "Linux_Mirai_Generic",
                    ProcessId = 123
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal("/tmp/deleted-malware", result.Target);
        Assert.Equal("/proc/123/exe", result.Variables["scanPath"]);
        Assert.Equal("/tmp/deleted-malware", result.Variables["resolvedPath"]);
    }
}
