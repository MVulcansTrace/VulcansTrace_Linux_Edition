using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Avalonia.ViewModels;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class AgentMessageViewModelTests
{
    [Fact]
    public void ImpactPreviewProperties_PopulatedFromRemediationSection()
    {
        var section = new RemediationSection
        {
            RuleId = "FW-001",
            FindingSummary = "[High] SSH exposed",
            RiskNote = "Remote access is exposed.",
            ImpactPreview = new RemediationImpactPreview
            {
                ExpectedImpact = "SSH will be restricted to 10.0.0.5.",
                RollbackPath = "sudo ufw delete allow from 10.0.0.5 to any port 22",
                VerificationCommand = "sudo ufw status",
                IsVerificationCommand = true
            },
            ApplyCommands = new[]
            {
                new RemediationCommand { Command = "sudo ufw allow from 10.0.0.5 to any port 22", Safety = CommandSafety.ConfigChange }
            },
            RollbackCommands = new[]
            {
                new RemediationCommand { Command = "sudo ufw delete allow from 10.0.0.5 to any port 22", Safety = CommandSafety.ConfigChange }
            }
        };

        var msg = new AgentMessageViewModel { RemediationSection = section };

        Assert.True(msg.HasImpactPreview);
        Assert.Equal("SSH will be restricted to 10.0.0.5.", msg.ImpactPreviewExpectedImpact);
        Assert.Equal("sudo ufw delete allow from 10.0.0.5 to any port 22", msg.ImpactPreviewRollbackPath);
        Assert.Equal("sudo ufw status", msg.ImpactPreviewVerificationCommand);
        Assert.True(msg.IsImpactPreviewVerificationCommand);
        Assert.Equal("Consolas,Monospace", msg.ImpactPreviewVerificationFontFamily);
    }

    [Fact]
    public void ImpactPreviewProperties_NullSection_ReturnEmptyDefaults()
    {
        var msg = new AgentMessageViewModel();

        Assert.False(msg.HasImpactPreview);
        Assert.Equal(string.Empty, msg.ImpactPreviewExpectedImpact);
        Assert.Equal(string.Empty, msg.ImpactPreviewRollbackPath);
        Assert.Equal(string.Empty, msg.ImpactPreviewVerificationCommand);
        Assert.False(msg.IsImpactPreviewVerificationCommand);
        Assert.Equal(string.Empty, msg.ImpactPreviewVerificationFontFamily);
    }

    [Fact]
    public void ImpactPreviewProperties_SectionWithoutImpactPreview_ReturnEmptyDefaults()
    {
        var section = new RemediationSection
        {
            RuleId = "FW-001",
            FindingSummary = "[High] SSH exposed",
            RiskNote = "Remote access is exposed."
        };

        var msg = new AgentMessageViewModel { RemediationSection = section };

        Assert.False(msg.HasImpactPreview);
        Assert.Equal(string.Empty, msg.ImpactPreviewExpectedImpact);
        Assert.Equal(string.Empty, msg.ImpactPreviewRollbackPath);
        Assert.Equal(string.Empty, msg.ImpactPreviewVerificationCommand);
        Assert.False(msg.IsImpactPreviewVerificationCommand);
        Assert.Equal(string.Empty, msg.ImpactPreviewVerificationFontFamily);
    }

    [Fact]
    public void IsRollbackPathCommand_TrueWhenRollbackCommandsExist()
    {
        var section = new RemediationSection
        {
            RuleId = "FW-001",
            FindingSummary = "[High] SSH exposed",
            RiskNote = "Remote access is exposed.",
            RollbackCommands = new[]
            {
                new RemediationCommand { Command = "sudo ufw delete allow from 10.0.0.5 to any port 22", Safety = CommandSafety.ConfigChange }
            }
        };

        var msg = new AgentMessageViewModel { RemediationSection = section };

        Assert.True(msg.IsRollbackPathCommand);
        Assert.Equal("Consolas,Monospace", msg.RollbackPathFontFamily);
    }

    [Fact]
    public void IsRollbackPathCommand_FalseWhenOnlyHintsExist()
    {
        var section = new RemediationSection
        {
            RuleId = "FW-001",
            FindingSummary = "[High] SSH exposed",
            RiskNote = "Remote access is exposed.",
            RollbackHints = new[] { "Revert iptables rules with -D instead of -A." }
        };

        var msg = new AgentMessageViewModel { RemediationSection = section };

        Assert.False(msg.IsRollbackPathCommand);
        Assert.Equal(string.Empty, msg.RollbackPathFontFamily);
    }

    [Fact]
    public void IsRollbackPathCommand_FalseWhenNoRollbackData()
    {
        var section = new RemediationSection
        {
            RuleId = "FW-001",
            FindingSummary = "[High] SSH exposed",
            RiskNote = "Remote access is exposed."
        };

        var msg = new AgentMessageViewModel { RemediationSection = section };

        Assert.False(msg.IsRollbackPathCommand);
        Assert.Equal(string.Empty, msg.RollbackPathFontFamily);
    }
}
