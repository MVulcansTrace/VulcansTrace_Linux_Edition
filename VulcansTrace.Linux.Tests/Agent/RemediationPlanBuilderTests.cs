using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class RemediationPlanBuilderTests
{
    [Fact]
    public void Build_Empty_Findings_Returns_Empty_Plan()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var plan = builder.Build(Array.Empty<Finding>());

        Assert.Empty(plan.Sections);
    }

    [Fact]
    public void Build_Extracts_Commands_From_SuggestedNextAction()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-001",
            Category = "Firewall",
            Severity = Severity.High,
            ShortDescription = "Default policy is ACCEPT",
            Target = "INPUT",
            Details = @"**Suggested next action:**
1. Change policy: `sudo iptables -P INPUT DROP`
2. Save rules: `sudo iptables-save > /etc/iptables/rules.v4`"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        Assert.Equal(2, plan.Sections[0].ApplyCommands.Count);
        Assert.Contains("sudo iptables -P INPUT DROP", plan.Sections[0].ApplyCommands.Select(c => c.Command));
    }

    [Fact]
    public void Build_Extracts_Verification_Commands()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-002",
            Category = "Firewall",
            Severity = Severity.Medium,
            ShortDescription = "SSH exposed",
            Target = "SSH/22",
            Details = @"**How to verify:**
1. Check: `sudo ss -tulnp | grep :22`"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        Assert.Single(plan.Sections[0].VerificationCommands);
        Assert.Contains("sudo ss -tulnp | grep :22", plan.Sections[0].VerificationCommands.Select(c => c.Command));
    }

    [Fact]
    public void Build_Generates_Generic_Rollback_When_None_In_Template()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-004",
            Category = "Firewall",
            Severity = Severity.Critical,
            ShortDescription = "No firewall",
            Target = "firewall",
            Details = "No rollback hints in template."
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        Assert.True(plan.Sections[0].RollbackHints.Count > 0);
        Assert.False(plan.Sections[0].HasExplicitRollbackGuidance);
    }

    [Fact]
    public void Build_Extracts_Rollback_Hints_From_Template()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "TEST-001",
            Category = "Port",
            Severity = Severity.Medium,
            ShortDescription = "Test",
            Target = "test",
            Details = @"**Suggested next action:**
`do something`

**Rollback hints:**
- Undo the thing
- Restore backup"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Equal(2, plan.Sections[0].RollbackHints.Count);
        Assert.Contains("Undo the thing", plan.Sections[0].RollbackHints);
        Assert.True(plan.Sections[0].HasExplicitRollbackGuidance);
    }

    [Fact]
    public void Build_Skips_Findings_Without_RuleId()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = null,
            Category = "Firewall",
            Severity = Severity.High,
            ShortDescription = "No rule id"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Empty(plan.Sections);
    }

    [Fact]
    public void Build_VerificationCommands_Carry_CommandAnalysis_ForPipe()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-002",
            Category = "Firewall",
            Severity = Severity.Medium,
            ShortDescription = "SSH exposed",
            Target = "SSH/22",
            Details = @"**How to verify:**
1. Check: `sudo ss -tulnp | grep :22`"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        var cmd = plan.Sections[0].VerificationCommands[0];
        Assert.True(cmd.Analysis.HasPipe);
        Assert.True(cmd.Analysis.RequiresSudo);
        Assert.Equal(CommandSafety.ReadOnly, cmd.Analysis.Safety);
    }

    [Fact]
    public void Build_ApplyCommands_Carry_CommandAnalysis_ForRedirect()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-005",
            Category = "Firewall",
            Severity = Severity.High,
            ShortDescription = "Save rules",
            Target = "INPUT",
            Details = @"**Suggested next action:**
1. Save: `sudo iptables-save > /etc/iptables/rules.v4`"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        var cmd = plan.Sections[0].ApplyCommands[0];
        Assert.True(cmd.Analysis.HasRedirect);
        Assert.True(cmd.Analysis.RequiresSudo);
    }

    [Fact]
    public void Build_Extracts_Preconditions()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-PRE",
            Category = "Firewall",
            Severity = Severity.High,
            ShortDescription = "Preconditions test",
            Target = "INPUT",
            Details = @"**Preconditions:**
- Root or sudo access
- Alternative access method available

**Suggested next action:**
1. Do something: `echo test`"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        Assert.Equal(2, plan.Sections[0].Preconditions.Count);
        Assert.Contains("Root or sudo access", plan.Sections[0].Preconditions);
    }

    [Fact]
    public void Build_Extracts_BackupCommands()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-BAK",
            Category = "Firewall",
            Severity = Severity.High,
            ShortDescription = "Backup test",
            Target = "INPUT",
            Details = @"**Backup commands:**
1. Save rules: `sudo sh -c 'iptables-save > /root/iptables-backup.rules'`

**Suggested next action:**
1. Do something: `echo test`"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        Assert.Single(plan.Sections[0].BackupCommands);
        Assert.Contains("sudo sh -c 'iptables-save > /root/iptables-backup.rules'", plan.Sections[0].BackupCommands.Select(c => c.Command));
    }

    [Fact]
    public void Build_Extracts_RollbackCommands()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-ROLL",
            Category = "Firewall",
            Severity = Severity.High,
            ShortDescription = "Rollback test",
            Target = "INPUT",
            Details = @"**Rollback commands:**
1. Restore rules: `sudo sh -c 'iptables-restore < /root/iptables-backup.rules'`

**Suggested next action:**
1. Do something: `echo test`"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        Assert.Single(plan.Sections[0].RollbackCommands);
        Assert.Contains("sudo sh -c 'iptables-restore < /root/iptables-backup.rules'", plan.Sections[0].RollbackCommands.Select(c => c.Command));
        Assert.True(plan.Sections[0].HasExplicitRollbackGuidance);
    }

    [Fact]
    public void Build_HasExplicitRollbackGuidance_True_When_RollbackHints_In_Template()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-EXP",
            Category = "Firewall",
            Severity = Severity.High,
            ShortDescription = "Explicit rollback",
            Target = "INPUT",
            Details = @"**Suggested next action:**
1. Change policy: `sudo iptables -P INPUT DROP`

**Rollback hints:**
- Restore ACCEPT policy manually"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        Assert.True(plan.Sections[0].HasExplicitRollbackGuidance);
        Assert.Equal(RemediationPreviewTextKind.ExplicitGuidance, plan.Sections[0].ImpactPreview?.RollbackPathKind);
        Assert.Equal("Restore ACCEPT policy manually", plan.Sections[0].ImpactPreview?.RollbackPath);
    }

    [Fact]
    public void Build_HasExplicitRollbackGuidance_False_When_Using_Generic_Fallback()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-GEN",
            Category = "Firewall",
            Severity = Severity.High,
            ShortDescription = "Generic rollback",
            Target = "INPUT",
            Details = @"**Suggested next action:**
1. Change policy: `sudo iptables -P INPUT DROP`"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        Assert.False(plan.Sections[0].HasExplicitRollbackGuidance);
        Assert.NotEmpty(plan.Sections[0].RollbackHints);
    }

    [Fact]
    public void Build_Populates_ImpactPreview_From_StructuredExplanation()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-IMP",
            Category = "Firewall",
            Severity = Severity.High,
            ShortDescription = "Impact preview test",
            Target = "INPUT",
            Details = @"**What was found:**
Default INPUT policy is ACCEPT.

**Why this matters:**
All incoming traffic is allowed until explicit rules are added.

**How to verify:**
1. Check policy: `sudo iptables -L INPUT | head -n 1`

**Rollback commands:**
1. Revert: `sudo iptables -P INPUT ACCEPT`

**Suggested next action:**
1. Drop default: `sudo iptables -P INPUT DROP`"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        var preview = plan.Sections[0].ImpactPreview;
        Assert.NotNull(preview);
        Assert.Contains("Applying this step will: Drop default.", preview.ExpectedImpact);
        Assert.DoesNotContain("All incoming traffic is allowed", preview.ExpectedImpact);
        Assert.Equal(RemediationImpactSource.SuggestedAction, preview.ExpectedImpactSource);
        Assert.Equal("sudo iptables -P INPUT ACCEPT", preview.RollbackPath);
        Assert.Equal(RemediationPreviewTextKind.Command, preview.RollbackPathKind);
        Assert.Equal("sudo iptables -L INPUT | head -n 1", preview.VerificationCommand);
        Assert.True(preview.IsVerificationCommand);
        Assert.Equal(RemediationPreviewTextKind.Command, preview.VerificationKind);
    }

    [Fact]
    public void Build_ImpactPreview_Falls_Back_To_Generic_Rollback_When_None_Provided()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-FBK",
            Category = "Firewall",
            Severity = Severity.High,
            ShortDescription = "Fallback rollback test",
            Target = "INPUT",
            Details = @"**Suggested next action:**
1. Change policy: `sudo iptables -P INPUT DROP`"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        var preview = plan.Sections[0].ImpactPreview;
        Assert.NotNull(preview);
        Assert.Contains("Revert iptables rules", preview.RollbackPath);
        Assert.Equal(RemediationPreviewTextKind.GenericGuidance, preview.RollbackPathKind);
    }

    [Fact]
    public void Build_ImpactPreview_Uses_VerificationCommand_From_HowToVerify()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-VER",
            Category = "Firewall",
            Severity = Severity.Medium,
            ShortDescription = "Verification fallback test",
            Target = "SSH/22",
            Details = @"**How to verify:**
1. Check: `sudo ss -tulnp | grep :22`

**Suggested next action:**
1. Do something: `echo test`"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        var preview = plan.Sections[0].ImpactPreview;
        Assert.NotNull(preview);
        Assert.Equal("sudo ss -tulnp | grep :22", preview.VerificationCommand);
        Assert.True(preview.IsVerificationCommand);
        Assert.Equal(RemediationPreviewTextKind.Command, preview.VerificationKind);
    }

    [Fact]
    public void Build_ImpactPreview_Keeps_ClassifierUnknown_VerificationCommand()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "PKG-VER",
            Category = "Package",
            Severity = Severity.High,
            ShortDescription = "Unknown classifier verification test",
            Target = "apt",
            Details = @"**How to verify:**
1. List upgradable packages: `apt list --upgradeable`

**Suggested next action:**
1. Update package lists: `sudo apt update`"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        var preview = plan.Sections[0].ImpactPreview;
        Assert.NotNull(preview);
        Assert.Equal("apt list --upgradeable", preview.VerificationCommand);
        Assert.True(preview.IsVerificationCommand);
        Assert.Equal(RemediationPreviewTextKind.Command, preview.VerificationKind);
    }

    [Fact]
    public void Build_Preserves_MitreTechniques_From_Finding()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-MITRE",
            Category = "Firewall",
            Severity = Severity.High,
            ShortDescription = "Mitre mapping test",
            Target = "INPUT",
            Details = "Test.",
            MitreTechniques = new[]
            {
                new MitreTechnique { TechniqueId = "T1562.004", TechniqueName = "Disable or Modify System Firewall", Tactic = "Defense Evasion", WhyItMatters = "Firewall misconfigurations can be exploited." }
            }
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        Assert.Single(plan.Sections[0].MitreTechniques);
        Assert.Equal("T1562.004", plan.Sections[0].MitreTechniques[0].TechniqueId);
    }

    [Fact]
    public void Build_ImpactPreview_Rejects_Prose_Backticks_As_VerificationCommand()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-PROSE",
            Category = "Firewall",
            Severity = Severity.Medium,
            ShortDescription = "Prose backtick test",
            Target = "INPUT",
            Details = @"**How to verify:**
The policy should show `DROP` and nothing else.

**Suggested next action:**
1. Do something: `echo test`"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        var preview = plan.Sections[0].ImpactPreview;
        Assert.NotNull(preview);
        // `DROP` is prose, not a shell command — fallback should be used
        Assert.Equal("Run verification manually after applying.", preview.VerificationCommand);
        Assert.False(preview.IsVerificationCommand);
        Assert.Equal(RemediationPreviewTextKind.ManualFallback, preview.VerificationKind);
    }

    [Fact]
    public void BuildCountermeasures_EmptyCriticalChains_ReturnsEmptyPlan()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var traceMap = new TraceMapResult
        {
            Findings = Array.Empty<Finding>(),
            Edges = Array.Empty<CorrelationEdge>(),
            CriticalChains = Array.Empty<CriticalChain>()
        };

        var plan = builder.BuildCountermeasures(traceMap);

        Assert.Empty(plan.Sections);
    }

    [Fact]
    public void BuildCountermeasures_CriticalChain_GeneratesCountermeasureCommands()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var baseTime = DateTime.UtcNow;
        var beaconing = new Finding
        {
            Category = FindingCategories.Beaconing,
            Severity = Severity.Medium,
            SourceHost = "192.168.1.100",
            Target = "10.0.0.5:443",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Beaconing",
            Details = "Regular intervals"
        };
        var lateral = new Finding
        {
            Category = FindingCategories.LateralMovement,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "multiple internal hosts",
            TimeRangeStart = baseTime.AddMinutes(10),
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Lateral movement",
            Details = "Contacted 5 internal hosts"
        };
        var privEsc = new Finding
        {
            Category = FindingCategories.PrivilegeEscalation,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "admin ports in 5min window",
            TimeRangeStart = baseTime.AddMinutes(20),
            TimeRangeEnd = baseTime.AddMinutes(25),
            ShortDescription = "Privilege escalation",
            Details = "6 admin port attempts"
        };
        var traceMap = new TraceMapResult
        {
            Findings = new[] { beaconing, lateral, privEsc },
            Edges = Array.Empty<CorrelationEdge>(),
            CriticalChains = new[]
            {
                new CriticalChain
                {
                    Host = "192.168.1.100",
                    Narrative = "Critical chain detected",
                    FindingIds = new[] { beaconing.Id, lateral.Id, privEsc.Id }
                }
            }
        };

        var plan = builder.BuildCountermeasures(traceMap);

        Assert.Single(plan.Sections);
        var section = plan.Sections[0];
        Assert.Equal("COUNTERMEASURE", section.RuleId);
        Assert.Contains("Beaconing → LateralMovement → PrivilegeEscalation", section.FindingSummary);

        // C-1: ApplyCommands populated so executor actually runs countermeasures
        Assert.Equal(2, section.ApplyCommands.Count);
        Assert.Contains(section.ApplyCommands, c => c.Command.Contains("iptables -A INPUT -s 10.0.0.5"));
        Assert.Contains(section.ApplyCommands, c => c.Command.Contains("auditctl -a"));

        Assert.Equal(2, section.CountermeasureCommands.Count);
        var iptables = section.CountermeasureCommands.First(c => c.Type == CountermeasureType.IptablesDrop);
        var auditd = section.CountermeasureCommands.First(c => c.Type == CountermeasureType.AuditdMonitor);

        Assert.Contains("iptables -A INPUT -s 10.0.0.5", iptables.Command);
        Assert.Contains("iptables -D INPUT -s 10.0.0.5", iptables.RollbackCommand);
        Assert.Equal(CommandSafety.ConfigChange, iptables.Safety);
        Assert.True(iptables.Analysis.RequiresSudo);

        // Auditd cannot filter connect syscalls by remote IP; it tags telemetry for correlation.
        Assert.Contains("auditctl -a", auditd.Command);
        Assert.DoesNotContain("-F addr=", auditd.Command);
        Assert.Contains("vulcanstrace_countermeasure_10_0_0_5", auditd.Command);
        Assert.Contains("auditctl -d", auditd.RollbackCommand);
        Assert.DoesNotContain("-F addr=", auditd.RollbackCommand);
        Assert.Equal(CommandSafety.ConfigChange, auditd.Safety);
        Assert.True(auditd.Analysis.RequiresSudo);

        Assert.Equal(2, section.RollbackCommands.Count);
        Assert.True(section.HasExplicitRollbackGuidance);
        Assert.NotNull(section.ImpactPreview);
        Assert.Contains("10.0.0.5", section.ImpactPreview.ExpectedImpact);

        // M-2: Verification uses iptables -C (exact rule check), not grep
        Assert.Contains("iptables -C INPUT -s 10.0.0.5 -j DROP", section.VerificationCommands[0].Command);
    }

    [Fact]
    public void BuildCountermeasures_OutOfOrderTimestamps_LooksUpByCategory()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var baseTime = DateTime.UtcNow;
        // C-2: LateralMovement occurs BEFORE Beaconing chronologically
        var lateral = new Finding
        {
            Category = FindingCategories.LateralMovement,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "multiple internal hosts",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Lateral movement",
            Details = "Contacted 5 internal hosts"
        };
        var beaconing = new Finding
        {
            Category = FindingCategories.Beaconing,
            Severity = Severity.Medium,
            SourceHost = "192.168.1.100",
            Target = "10.0.0.99:443",
            TimeRangeStart = baseTime.AddMinutes(10),
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Beaconing",
            Details = "Regular intervals"
        };
        var privEsc = new Finding
        {
            Category = FindingCategories.PrivilegeEscalation,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "admin ports in 5min window",
            TimeRangeStart = baseTime.AddMinutes(20),
            TimeRangeEnd = baseTime.AddMinutes(25),
            ShortDescription = "Privilege escalation",
            Details = "6 admin port attempts"
        };
        var traceMap = new TraceMapResult
        {
            Findings = new[] { lateral, beaconing, privEsc },
            Edges = Array.Empty<CorrelationEdge>(),
            CriticalChains = new[]
            {
                new CriticalChain
                {
                    Host = "192.168.1.100",
                    Narrative = "Critical chain detected",
                    // FindingIds sorted by timestamp: lateral first, then beaconing, then privEsc
                    FindingIds = new[] { lateral.Id, beaconing.Id, privEsc.Id }
                }
            }
        };

        var plan = builder.BuildCountermeasures(traceMap);

        Assert.Single(plan.Sections);
        var section = plan.Sections[0];
        // Should still extract attacker IP from Beaconing finding (10.0.0.99), not lateral
        Assert.Contains("iptables -A INPUT -s 10.0.0.99", section.ApplyCommands[0].Command);
    }

    [Fact]
    public void BuildCountermeasures_InvalidAttackerIp_GeneratesBlockedSection()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var baseTime = DateTime.UtcNow;
        var beaconing = new Finding
        {
            Category = FindingCategories.Beaconing,
            Severity = Severity.Medium,
            SourceHost = "192.168.1.100",
            Target = "not-an-ip:443",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Beaconing",
            Details = "Regular intervals"
        };
        var lateral = new Finding
        {
            Category = FindingCategories.LateralMovement,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "multiple internal hosts",
            TimeRangeStart = baseTime.AddMinutes(10),
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Lateral movement",
            Details = "Contacted 5 internal hosts"
        };
        var privEsc = new Finding
        {
            Category = FindingCategories.PrivilegeEscalation,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "admin ports in 5min window",
            TimeRangeStart = baseTime.AddMinutes(20),
            TimeRangeEnd = baseTime.AddMinutes(25),
            ShortDescription = "Privilege escalation",
            Details = "6 admin port attempts"
        };
        var traceMap = new TraceMapResult
        {
            Findings = new[] { beaconing, lateral, privEsc },
            Edges = Array.Empty<CorrelationEdge>(),
            CriticalChains = new[]
            {
                new CriticalChain
                {
                    Host = "192.168.1.100",
                    Narrative = "Critical chain detected",
                    FindingIds = new[] { beaconing.Id, lateral.Id, privEsc.Id }
                }
            }
        };

        var plan = builder.BuildCountermeasures(traceMap);

        Assert.Single(plan.Sections);
        var section = plan.Sections[0];
        Assert.Equal("COUNTERMEASURE-BLOCKED", section.RuleId);
        Assert.Contains("does not contain a valid IP address", section.RiskNote);
        Assert.Empty(section.ApplyCommands);
    }

    [Fact]
    public void BuildCountermeasures_StaleFindingId_SkipsMalformedChain()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var baseTime = DateTime.UtcNow;
        var beaconing = new Finding
        {
            Category = FindingCategories.Beaconing,
            Severity = Severity.Medium,
            SourceHost = "192.168.1.100",
            Target = "10.0.0.5:443",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Beaconing",
            Details = "Regular intervals"
        };
        var lateral = new Finding
        {
            Category = FindingCategories.LateralMovement,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "multiple internal hosts",
            TimeRangeStart = baseTime.AddMinutes(10),
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Lateral movement",
            Details = "Contacted 5 internal hosts"
        };
        var traceMap = new TraceMapResult
        {
            Findings = new[] { beaconing, lateral },
            Edges = Array.Empty<CorrelationEdge>(),
            CriticalChains = new[]
            {
                new CriticalChain
                {
                    Host = "192.168.1.100",
                    Narrative = "Stale chain",
                    FindingIds = new[] { beaconing.Id, lateral.Id, Guid.NewGuid() }
                }
            }
        };

        var plan = builder.BuildCountermeasures(traceMap);

        Assert.Empty(plan.Sections);
    }

    [Fact]
    public void BuildCountermeasures_Ipv6Endpoint_UsesIp6tablesAndTaggedAuditTelemetry()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var baseTime = DateTime.UtcNow;
        var beaconing = new Finding
        {
            Category = FindingCategories.Beaconing,
            Severity = Severity.Medium,
            SourceHost = "2001:db8::100",
            Target = "[2001:db8::5]:443",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Beaconing",
            Details = "Regular intervals"
        };
        var lateral = new Finding
        {
            Category = FindingCategories.LateralMovement,
            Severity = Severity.High,
            SourceHost = "2001:db8::100",
            Target = "multiple internal hosts",
            TimeRangeStart = baseTime.AddMinutes(10),
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Lateral movement",
            Details = "Contacted 5 internal hosts"
        };
        var privEsc = new Finding
        {
            Category = FindingCategories.PrivilegeEscalation,
            Severity = Severity.High,
            SourceHost = "2001:db8::100",
            Target = "admin ports in 5min window",
            TimeRangeStart = baseTime.AddMinutes(20),
            TimeRangeEnd = baseTime.AddMinutes(25),
            ShortDescription = "Privilege escalation",
            Details = "6 admin port attempts"
        };
        var traceMap = new TraceMapResult
        {
            Findings = new[] { beaconing, lateral, privEsc },
            Edges = Array.Empty<CorrelationEdge>(),
            CriticalChains = new[]
            {
                new CriticalChain
                {
                    Host = "2001:db8::100",
                    Narrative = "IPv6 critical chain",
                    FindingIds = new[] { beaconing.Id, lateral.Id, privEsc.Id }
                }
            }
        };

        var plan = builder.BuildCountermeasures(traceMap);

        Assert.Single(plan.Sections);
        var section = plan.Sections[0];
        Assert.Contains("ip6tables -A INPUT -s 2001:db8::5 -j DROP", section.ApplyCommands[0].Command);
        Assert.Contains("ip6tables -C INPUT -s 2001:db8::5 -j DROP", section.VerificationCommands[0].Command);
        var auditd = section.CountermeasureCommands.First(c => c.Type == CountermeasureType.AuditdMonitor);
        Assert.Contains("auditctl -a always,exit -F arch=b64 -S connect", auditd.Command);
        Assert.Contains("vulcanstrace_countermeasure_2001_db8__5", auditd.Command);
        Assert.DoesNotContain("-F addr=", auditd.Command);
    }

    [Fact]
    public void BuildCountermeasures_DuplicateAttackerIp_Deduplicates()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var baseTime = DateTime.UtcNow;
        var beaconing1 = new Finding
        {
            Category = FindingCategories.Beaconing,
            Severity = Severity.Medium,
            SourceHost = "192.168.1.100",
            Target = "10.0.0.5:443",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Beaconing",
            Details = "Regular intervals"
        };
        var lateral1 = new Finding
        {
            Category = FindingCategories.LateralMovement,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "multiple internal hosts",
            TimeRangeStart = baseTime.AddMinutes(10),
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Lateral movement",
            Details = "Contacted 5 internal hosts"
        };
        var privEsc1 = new Finding
        {
            Category = FindingCategories.PrivilegeEscalation,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "admin ports in 5min window",
            TimeRangeStart = baseTime.AddMinutes(20),
            TimeRangeEnd = baseTime.AddMinutes(25),
            ShortDescription = "Privilege escalation",
            Details = "6 admin port attempts"
        };
        // Second chain on a different host but same attacker IP
        var beaconing2 = new Finding
        {
            Category = FindingCategories.Beaconing,
            Severity = Severity.Medium,
            SourceHost = "192.168.1.200",
            Target = "10.0.0.5:443",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Beaconing",
            Details = "Regular intervals"
        };
        var lateral2 = new Finding
        {
            Category = FindingCategories.LateralMovement,
            Severity = Severity.High,
            SourceHost = "192.168.1.200",
            Target = "multiple internal hosts",
            TimeRangeStart = baseTime.AddMinutes(10),
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Lateral movement",
            Details = "Contacted 5 internal hosts"
        };
        var privEsc2 = new Finding
        {
            Category = FindingCategories.PrivilegeEscalation,
            Severity = Severity.High,
            SourceHost = "192.168.1.200",
            Target = "admin ports in 5min window",
            TimeRangeStart = baseTime.AddMinutes(20),
            TimeRangeEnd = baseTime.AddMinutes(25),
            ShortDescription = "Privilege escalation",
            Details = "6 admin port attempts"
        };
        var traceMap = new TraceMapResult
        {
            Findings = new[] { beaconing1, lateral1, privEsc1, beaconing2, lateral2, privEsc2 },
            Edges = Array.Empty<CorrelationEdge>(),
            CriticalChains = new[]
            {
                new CriticalChain
                {
                    Host = "192.168.1.100",
                    Narrative = "Critical chain 1",
                    FindingIds = new[] { beaconing1.Id, lateral1.Id, privEsc1.Id }
                },
                new CriticalChain
                {
                    Host = "192.168.1.200",
                    Narrative = "Critical chain 2",
                    FindingIds = new[] { beaconing2.Id, lateral2.Id, privEsc2.Id }
                }
            }
        };

        var plan = builder.BuildCountermeasures(traceMap);

        // M-1: Only one section should be generated because both chains target the same attacker IP
        Assert.Single(plan.Sections);
        Assert.Equal("COUNTERMEASURE", plan.Sections[0].RuleId);
    }

    [Fact]
    public void Build_Populates_ImpactPreview_Simulation_Fields()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-001",
            Category = "Firewall",
            Severity = Severity.High,
            ShortDescription = "SSH exposed",
            Target = "22",
            Details = @"**Suggested next action:**
1. Restrict SSH: `sudo ufw allow from 10.0.0.5 to any port 22`

**Backup commands:**
1. Save current rules: `sudo iptables-save > /tmp/iptables.backup`

**Rollback hints:**
- Delete the allow rule with `sudo ufw delete allow from 10.0.0.5 to any port 22`"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        var preview = plan.Sections[0].ImpactPreview;
        Assert.NotNull(preview);
        Assert.Contains("[High]", preview.RiskBefore);
        Assert.Contains("resolved", preview.ExpectedRiskAfter, System.StringComparison.OrdinalIgnoreCase);
        Assert.Equal(2, preview.CommandCount); // 1 apply + 1 backup
        Assert.True(preview.RollbackAvailable);
        Assert.False(preview.HasRestartImpact);
        Assert.False(preview.HasLockoutRisk);
    }

    [Fact]
    public void Build_Populates_ImpactPreview_With_LockoutRisk_For_SSH_Related_Commands()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "SSH-001",
            Category = "SSH",
            Severity = Severity.Critical,
            ShortDescription = "Weak SSH config",
            Target = "sshd",
            Details = @"**Suggested next action:**
1. Harden config: `sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config`

**Rollback hints:**
- Restore from backup"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        var preview = plan.Sections[0].ImpactPreview;
        Assert.NotNull(preview);
        Assert.True(preview.HasLockoutRisk);
        Assert.Contains("SSH", preview.LockoutRiskDescription);
    }
}
