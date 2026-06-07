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
                ExpectedImpactSource = RemediationImpactSource.SuggestedAction,
                RollbackPath = "sudo ufw delete allow from 10.0.0.5 to any port 22",
                RollbackPathKind = RemediationPreviewTextKind.Command,
                VerificationCommand = "sudo ufw status",
                IsVerificationCommand = true,
                VerificationKind = RemediationPreviewTextKind.Command
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
        Assert.Equal(RemediationImpactSource.SuggestedAction, msg.ImpactPreviewExpectedImpactSource);
        Assert.Equal(RemediationPreviewTextKind.Command, msg.ImpactPreviewRollbackPathKind);
        Assert.Equal(RemediationPreviewTextKind.Command, msg.ImpactPreviewVerificationKind);
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
        Assert.Equal(RemediationImpactSource.Generic, msg.ImpactPreviewExpectedImpactSource);
        Assert.Equal(RemediationPreviewTextKind.ManualFallback, msg.ImpactPreviewRollbackPathKind);
        Assert.Equal(RemediationPreviewTextKind.ManualFallback, msg.ImpactPreviewVerificationKind);
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
        Assert.Equal(RemediationImpactSource.Generic, msg.ImpactPreviewExpectedImpactSource);
        Assert.Equal(RemediationPreviewTextKind.ManualFallback, msg.ImpactPreviewRollbackPathKind);
        Assert.Equal(RemediationPreviewTextKind.ManualFallback, msg.ImpactPreviewVerificationKind);
    }

    [Fact]
    public void IsRollbackPathCommand_TrueWhenRollbackCommandsExist()
    {
        var section = new RemediationSection
        {
            RuleId = "FW-001",
            FindingSummary = "[High] SSH exposed",
            RiskNote = "Remote access is exposed.",
            ImpactPreview = new RemediationImpactPreview
            {
                RollbackPath = "sudo ufw delete allow from 10.0.0.5 to any port 22",
                RollbackPathKind = RemediationPreviewTextKind.Command
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
            ImpactPreview = new RemediationImpactPreview
            {
                RollbackPath = "Revert iptables rules with -D instead of -A.",
                RollbackPathKind = RemediationPreviewTextKind.GenericGuidance
            }
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

    [Fact]
    public void ImpactPreviewSimulationProperties_PopulatedFromRemediationSection()
    {
        var section = new RemediationSection
        {
            RuleId = "FW-001",
            FindingSummary = "[High] SSH exposed",
            RiskNote = "Remote access is exposed.",
            ImpactPreview = new RemediationImpactPreview
            {
                ExpectedImpact = "SSH will be restricted.",
                RiskBefore = "[High] Remote access is exposed.",
                ExpectedRiskAfter = "Finding should be resolved.",
                CommandCount = 3,
                RollbackAvailable = true,
                HasRestartImpact = true,
                HasLockoutRisk = true,
                RestartImpactDescription = "Service restart required.",
                LockoutRiskDescription = "SSH config modified."
            },
            ApplyCommands = new[]
            {
                new RemediationCommand { Command = "sudo systemctl restart sshd", Safety = CommandSafety.ServiceRestart }
            }
        };

        var msg = new AgentMessageViewModel { RemediationSection = section };

        Assert.True(msg.HasImpactPreview);
        Assert.Equal("[High] Remote access is exposed.", msg.ImpactPreviewRiskBefore);
        Assert.Equal("Finding should be resolved.", msg.ImpactPreviewExpectedRiskAfter);
        Assert.Equal(3, msg.ImpactPreviewCommandCount);
        Assert.True(msg.ImpactPreviewRollbackAvailable);
        Assert.False(msg.ImpactPreviewRollbackUnavailable);
        Assert.Equal("Yes", msg.ImpactPreviewRollbackAvailabilityLabel);
        Assert.True(msg.ImpactPreviewHasRestartImpact);
        Assert.True(msg.ImpactPreviewHasLockoutRisk);
        Assert.Equal("Service restart required.", msg.ImpactPreviewRestartImpactDescription);
        Assert.Equal("SSH config modified.", msg.ImpactPreviewLockoutRiskDescription);
    }

    [Fact]
    public void ImpactPreviewSimulationProperties_NullSection_ReturnEmptyDefaults()
    {
        var msg = new AgentMessageViewModel();

        Assert.Equal(string.Empty, msg.ImpactPreviewRiskBefore);
        Assert.Equal(string.Empty, msg.ImpactPreviewExpectedRiskAfter);
        Assert.Equal(0, msg.ImpactPreviewCommandCount);
        Assert.False(msg.ImpactPreviewRollbackAvailable);
        Assert.False(msg.ImpactPreviewRollbackUnavailable);
        Assert.Equal("No", msg.ImpactPreviewRollbackAvailabilityLabel);
        Assert.False(msg.ImpactPreviewHasRestartImpact);
        Assert.False(msg.ImpactPreviewHasLockoutRisk);
        Assert.Equal(string.Empty, msg.ImpactPreviewRestartImpactDescription);
        Assert.Equal(string.Empty, msg.ImpactPreviewLockoutRiskDescription);
    }

    [Fact]
    public void ImpactPreviewRollbackUnavailable_TrueWhenPreviewHasNoExplicitRollback()
    {
        var section = new RemediationSection
        {
            RuleId = "FW-001",
            FindingSummary = "[High] SSH exposed",
            RiskNote = "Remote access is exposed.",
            ImpactPreview = new RemediationImpactPreview
            {
                ExpectedImpact = "SSH will be restricted.",
                RollbackAvailable = false
            }
        };

        var msg = new AgentMessageViewModel { RemediationSection = section };

        Assert.True(msg.HasImpactPreview);
        Assert.False(msg.ImpactPreviewRollbackAvailable);
        Assert.True(msg.ImpactPreviewRollbackUnavailable);
        Assert.Equal("No", msg.ImpactPreviewRollbackAvailabilityLabel);
    }
}
