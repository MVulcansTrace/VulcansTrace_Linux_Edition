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
        Assert.Contains("Drop default.", preview.ExpectedImpact);
        Assert.DoesNotContain("All incoming traffic is allowed", preview.ExpectedImpact);
        Assert.Equal("sudo iptables -P INPUT ACCEPT", preview.RollbackPath);
        Assert.Equal("sudo iptables -L INPUT | head -n 1", preview.VerificationCommand);
        Assert.True(preview.IsVerificationCommand);
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
    }
}
