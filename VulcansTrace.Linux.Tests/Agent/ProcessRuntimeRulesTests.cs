using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Rules.SecurityRules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class ProcessRuntimeRulesTests
{
    [Fact]
    public void RwxMemoryRegionRule_ProcessWithRwx_Fails()
    {
        var rule = new RwxMemoryRegionRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry
                {
                    Pid = 1234,
                    Name = "malware",
                    MemoryMaps = new[] { new ProcessMemoryMap { AddressRange = "7f00-7f01", Permissions = "rwxp", Path = "" } }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
        Assert.Contains("1234", result.Target);
    }

    [Fact]
    public void RwxMemoryRegionRule_NoRwx_Passes()
    {
        var rule = new RwxMemoryRegionRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry
                {
                    Pid = 1234,
                    Name = "bash",
                    MemoryMaps = new[] { new ProcessMemoryMap { AddressRange = "0040-0050", Permissions = "r-xp", Path = "/bin/bash" } }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void RwxMemoryRegionRule_NoProcessData_NotApplicable()
    {
        var rule = new RwxMemoryRegionRule();
        var data = new ScanData { ProcessRuntimes = Array.Empty<ProcessRuntimeEntry>() };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void RwxMemoryRegionRule_AllMapsUnreadable_NotApplicable()
    {
        var rule = new RwxMemoryRegionRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry { Pid = 1234, Name = "bash", MemoryMapsReadable = false }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void RwxMemoryRegionRule_PartialMapsUnreadable_PassesWithMetadata()
    {
        var rule = new RwxMemoryRegionRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry
                {
                    Pid = 1234,
                    Name = "bash",
                    MemoryMapsReadable = true,
                    MemoryMaps = new[] { new ProcessMemoryMap { AddressRange = "0040-0050", Permissions = "r-xp", Path = "/bin/bash" } }
                },
                new ProcessRuntimeEntry { Pid = 5678, Name = "root-owned", MemoryMapsReadable = false }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.Passed, result.Status);
        Assert.Equal("1", result.Variables["mapsUnreadableCount"]);
    }

    [Fact]
    public void LdPreloadInjectionRule_ProcessWithLdPreload_Fails()
    {
        var rule = new LdPreloadInjectionRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry
                {
                    Pid = 5678,
                    Name = "sshd",
                    Environment = new[] { "LD_PRELOAD=/tmp/evil.so", "PATH=/usr/bin" }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void LdPreloadInjectionRule_ProcessWithLdAudit_Fails()
    {
        var rule = new LdPreloadInjectionRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry
                {
                    Pid = 5678,
                    Name = "nginx",
                    Environment = new[] { "LD_AUDIT=/var/tmp/monitor.so" }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void LdPreloadInjectionRule_NoPreload_Passes()
    {
        var rule = new LdPreloadInjectionRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry
                {
                    Pid = 5678,
                    Name = "bash",
                    Environment = new[] { "PATH=/usr/bin", "HOME=/root" }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void LdPreloadInjectionRule_EmptyPreloadValue_Passes()
    {
        var rule = new LdPreloadInjectionRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry
                {
                    Pid = 5678,
                    Name = "bash",
                    Environment = new[] { "LD_PRELOAD=", "PATH=/usr/bin" }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void DeletedBinaryExecutionRule_DeletedExe_Fails()
    {
        var rule = new DeletedBinaryExecutionRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry
                {
                    Pid = 9999,
                    Name = "payload",
                    ExePath = "/tmp/payload (deleted)"
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void DeletedBinaryExecutionRule_TempPath_Fails()
    {
        var rule = new DeletedBinaryExecutionRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry
                {
                    Pid = 8888,
                    Name = "miner",
                    ExePath = "/dev/shm/xmrig"
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void DeletedBinaryExecutionRule_TempPathExactMatch_Fails()
    {
        var rule = new DeletedBinaryExecutionRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry
                {
                    Pid = 7777,
                    Name = "evil",
                    ExePath = "/tmp"
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void DeletedBinaryExecutionRule_NormalExe_Passes()
    {
        var rule = new DeletedBinaryExecutionRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry
                {
                    Pid = 1,
                    Name = "systemd",
                    ExePath = "/usr/lib/systemd/systemd"
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void LdPreloadInjectionRule_AllEnvironmentUnreadable_NotApplicable()
    {
        var rule = new LdPreloadInjectionRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry { Pid = 5678, Name = "sshd", EnvironmentReadable = false }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void DeletedBinaryExecutionRule_AllExeUnreadable_NotApplicable()
    {
        var rule = new DeletedBinaryExecutionRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry { Pid = 9999, Name = "payload", ExePathReadable = false }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void OrphanedAnomalousProcessRule_AnomalousInitChild_Fails()
    {
        var rule = new OrphanedAnomalousProcessRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry
                {
                    Pid = 12345,
                    Name = "xk9j2m4p7q",
                    Ppid = 1
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void OrphanedAnomalousProcessRule_NormalInitChild_Passes()
    {
        var rule = new OrphanedAnomalousProcessRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry
                {
                    Pid = 12345,
                    Name = "systemd-networkd",
                    Ppid = 1
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void OrphanedAnomalousProcessRule_NonInitChild_Passes()
    {
        var rule = new OrphanedAnomalousProcessRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry
                {
                    Pid = 12345,
                    Name = "xk9j2m4p7q",
                    Ppid = 1234
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SuspiciousParentChildRule_ApacheSpawnsBash_Fails()
    {
        var rule = new SuspiciousParentChildRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry { Pid = 100, Name = "apache2", Ppid = 1 },
                new ProcessRuntimeEntry { Pid = 200, Name = "bash", Ppid = 100 }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void SuspiciousParentChildRule_SshdSpawnsPython_Fails()
    {
        var rule = new SuspiciousParentChildRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry { Pid = 100, Name = "sshd", Ppid = 1 },
                new ProcessRuntimeEntry { Pid = 200, Name = "python3", Ppid = 100 }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void SuspiciousParentChildRule_SshdSpawnsBash_Passes()
    {
        var rule = new SuspiciousParentChildRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry { Pid = 100, Name = "sshd", Ppid = 1 },
                new ProcessRuntimeEntry { Pid = 200, Name = "bash", Ppid = 100 }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SuspiciousParentChildRule_NormalHierarchy_Passes()
    {
        var rule = new SuspiciousParentChildRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry { Pid = 100, Name = "nginx", Ppid = 1 },
                new ProcessRuntimeEntry { Pid = 200, Name = "nginx", Ppid = 100 }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SuspiciousParentChildRule_MissingParent_Passes()
    {
        var rule = new SuspiciousParentChildRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry { Pid = 200, Name = "bash", Ppid = 9999 }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.NotNull(result.Variables);
        Assert.True(result.Variables.TryGetValue("missingParentCount", out var missing));
        Assert.Equal("1", missing);
        Assert.True(result.Variables.TryGetValue("totalChecked", out var total));
        Assert.Equal("1", total);
    }

    [Fact]
    public void SuspiciousParentChildRule_MissingParentMetadata_OnFail()
    {
        var rule = new SuspiciousParentChildRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry { Pid = 1, Name = "systemd", Ppid = 0 },
                new ProcessRuntimeEntry { Pid = 100, Name = "apache2", Ppid = 1 },
                new ProcessRuntimeEntry { Pid = 200, Name = "bash", Ppid = 100 },
                new ProcessRuntimeEntry { Pid = 300, Name = "python3", Ppid = 9999 }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.NotNull(result.Variables);
        Assert.True(result.Variables.TryGetValue("missingParentCount", out var missing));
        Assert.Equal("1", missing);
        Assert.True(result.Variables.TryGetValue("totalChecked", out var total));
        Assert.Equal("3", total);
    }

    [Fact]
    public void InterpreterRwxMemoryRule_PythonWithRwx_Fails()
    {
        var rule = new InterpreterRwxMemoryRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry
                {
                    Pid = 4242,
                    Name = "python3.11",
                    Cmdline = "python3.11 -c import socket",
                    MemoryMapsReadable = true,
                    MemoryMaps = new[] { new ProcessMemoryMap { AddressRange = "7f00-7f01", Permissions = "rwxp", Path = "[heap]" } }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
        Assert.Equal("4242", result.Variables["firstPid"]);
    }

    [Fact]
    public void InterpreterRwxMemoryRule_NonInterpreterWithRwx_Passes()
    {
        var rule = new InterpreterRwxMemoryRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry
                {
                    Pid = 4242,
                    Name = "customd",
                    MemoryMapsReadable = true,
                    MemoryMaps = new[] { new ProcessMemoryMap { AddressRange = "7f00-7f01", Permissions = "rwxp", Path = "[heap]" } }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void InterpreterRwxMemoryRule_AllMapsUnreadable_NotApplicable()
    {
        var rule = new InterpreterRwxMemoryRule();
        var data = new ScanData
        {
            ProcessRuntimes = new[]
            {
                new ProcessRuntimeEntry { Pid = 4242, Name = "python3", MemoryMapsReadable = false }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void LdPreloadInjectionRule_NoProcessData_NotApplicable()
    {
        var rule = new LdPreloadInjectionRule();
        var data = new ScanData { ProcessRuntimes = Array.Empty<ProcessRuntimeEntry>() };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void DeletedBinaryExecutionRule_NoProcessData_NotApplicable()
    {
        var rule = new DeletedBinaryExecutionRule();
        var data = new ScanData { ProcessRuntimes = Array.Empty<ProcessRuntimeEntry>() };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void OrphanedAnomalousProcessRule_NoProcessData_NotApplicable()
    {
        var rule = new OrphanedAnomalousProcessRule();
        var data = new ScanData { ProcessRuntimes = Array.Empty<ProcessRuntimeEntry>() };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void SuspiciousParentChildRule_NoProcessData_NotApplicable()
    {
        var rule = new SuspiciousParentChildRule();
        var data = new ScanData { ProcessRuntimes = Array.Empty<ProcessRuntimeEntry>() };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }
}
