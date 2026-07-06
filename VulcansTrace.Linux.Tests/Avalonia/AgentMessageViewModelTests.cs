using System;
using System.Collections.Generic;
using System.ComponentModel;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Avalonia.ViewModels;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class AgentMessageViewModelTests
{
    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
    public void RemediationSection_Change_RaisesPropertyChanged()
    {
        var section = new RemediationSection
        {
            RuleId = "FW-001",
            FindingSummary = "[High] SSH exposed",
            RiskNote = "Remote access is exposed."
        };
        var msg = new AgentMessageViewModel();
        var changed = new List<string?>();
        msg.PropertyChanged += (s, e) => changed.Add(e.PropertyName);

        msg.RemediationSection = section;

        Assert.Contains(nameof(AgentMessageViewModel.RemediationSection), changed);
        Assert.Contains(string.Empty, changed);
        Assert.True(msg.HasRemediationSection);
    }

    [AvaloniaFact]
    public void FormattedBlocks_ParsesCodeBlock()
    {
        var msg = new AgentMessageViewModel
        {
            Text = "```bash\nsudo ufw status\n```"
        };

        var codeBlock = Assert.Single(msg.FormattedBlocks.OfType<CodeBlock>());
        Assert.Equal("bash", codeBlock.Language);
        Assert.Equal("sudo ufw status", codeBlock.Code);
        Assert.NotNull(codeBlock.CopyCommand);
        Assert.NotNull(codeBlock.ToggleExpandCommand);
        Assert.True(codeBlock.IsExpanded);
    }

    [AvaloniaFact]
    public void CodeBlock_ToggleCommand_FlipsIsExpanded()
    {
        var codeBlock = new CodeBlock("bash", "sudo ufw status", new RelayCommand(_ => { }));

        Assert.True(codeBlock.IsExpanded);

        codeBlock.ToggleExpandCommand.Execute(null);
        Assert.False(codeBlock.IsExpanded);

        codeBlock.ToggleExpandCommand.Execute(null);
        Assert.True(codeBlock.IsExpanded);
    }

    [AvaloniaFact]
    public void CodeBlock_IsExpanded_RaisesPropertyChanged()
    {
        var codeBlock = new CodeBlock("bash", "sudo ufw status", new RelayCommand(_ => { }));
        var changed = new List<string?>();
        codeBlock.PropertyChanged += (s, e) => changed.Add(e.PropertyName);

        codeBlock.IsExpanded = false;

        Assert.Contains(nameof(CodeBlock.IsExpanded), changed);
    }

    [AvaloniaFact]
    public void CodeBlock_PreviewText_TruncatesLongFirstLine()
    {
        var longLine = new string('a', 120);
        var codeBlock = new CodeBlock("bash", $"{longLine}\nsecond line", new RelayCommand(_ => { }));

        Assert.Equal(81, codeBlock.PreviewText.Length);
        Assert.EndsWith("…", codeBlock.PreviewText);
    }

    [AvaloniaFact]
    public void CodeBlock_PreviewText_UsesFirstLine()
    {
        var codeBlock = new CodeBlock("bash", "sudo ufw status\nsudo ufw enable", new RelayCommand(_ => { }));

        Assert.Equal("sudo ufw status", codeBlock.PreviewText);
    }

    [AvaloniaFact]
    public void FormattedBlocks_ParsesInlineCode()
    {
        var msg = new AgentMessageViewModel
        {
            Text = "Run `sudo ufw status`."
        };

        var paragraph = Assert.Single(msg.FormattedBlocks.OfType<ParagraphBlock>());
        Assert.NotEmpty(paragraph.Inlines);
    }

    [AvaloniaFact]
    public void IsError_DefaultsFalse()
    {
        var msg = new AgentMessageViewModel();

        Assert.False(msg.IsError);
    }

    [AvaloniaFact]
    public void IsError_CanBeSet()
    {
        var msg = new AgentMessageViewModel { IsError = true };

        Assert.True(msg.IsError);
    }

    [AvaloniaFact]
    public void AutomationName_ReturnsRoleTimestampAndText()
    {
        var msg = new AgentMessageViewModel
        {
            IsUser = true,
            Text = "hello",
            Timestamp = new DateTime(2026, 7, 2, 14, 30, 0)
        };

        Assert.Equal("You at 14:30: hello", msg.AutomationName);
    }

    [AvaloniaFact]
    public void StreamingText_DoesNotRebuildFormattedBlocks()
    {
        var msg = new AgentMessageViewModel { Text = "initial" };
        var changed = new List<string?>();
        msg.PropertyChanged += (s, e) => changed.Add(e.PropertyName);

        msg.IsStreaming = true;
        msg.StreamingFinalText = "final";
        msg.StreamingText = "fin";

        Assert.Contains(nameof(AgentMessageViewModel.StreamingText), changed);
        Assert.DoesNotContain(nameof(AgentMessageViewModel.FormattedBlocks), changed);
        Assert.Equal("initial", msg.Text);
    }

    [AvaloniaFact]
    public void FlushStreaming_CommitsTextAndClearsStreamingState()
    {
        var msg = new AgentMessageViewModel
        {
            IsStreaming = true,
            StreamingFinalText = "final text",
            StreamingText = "final"
        };

        msg.FlushStreaming();

        Assert.False(msg.IsStreaming);
        Assert.Equal(string.Empty, msg.StreamingText);
        Assert.Equal(string.Empty, msg.StreamingFinalText);
        Assert.Equal("final", msg.Text);
    }

    [AvaloniaFact]
    public void FlushStreaming_WithFinalText_UsesProvidedText()
    {
        var msg = new AgentMessageViewModel
        {
            IsStreaming = true,
            StreamingText = "partial"
        };

        msg.FlushStreaming("full final text");

        Assert.False(msg.IsStreaming);
        Assert.Equal("full final text", msg.Text);
    }

    [AvaloniaFact]
    public void AutomationName_WhenStreaming_UsesFinalText()
    {
        var msg = new AgentMessageViewModel
        {
            IsStreaming = true,
            StreamingFinalText = "the full answer",
            StreamingText = "the",
            Timestamp = new DateTime(2026, 7, 2, 14, 30, 0)
        };

        Assert.Equal("VulcansTrace at 14:30: the full answer", msg.AutomationName);
    }

    [AvaloniaFact]
    public void IsRowVisible_CombinesFilterVisibilityAndStreamingPending()
    {
        var msg = new AgentMessageViewModel { Text = "x" };
        Assert.True(msg.IsRowVisible);

        msg.IsStreamingPending = true;
        Assert.False(msg.IsRowVisible);

        msg.IsVisible = false;
        Assert.False(msg.IsRowVisible);

        // Still hidden by the filter even once its streaming turn arrives.
        msg.IsStreamingPending = false;
        Assert.False(msg.IsRowVisible);

        msg.IsVisible = true;
        Assert.True(msg.IsRowVisible);
    }

    [AvaloniaFact]
    public void IsRowVisible_RaisesWhenSourcesChange()
    {
        var msg = new AgentMessageViewModel { Text = "x" };
        var changed = new List<string?>();
        msg.PropertyChanged += (s, e) => changed.Add(e.PropertyName);

        msg.IsStreamingPending = true;
        Assert.Contains(nameof(AgentMessageViewModel.IsRowVisible), changed);

        changed.Clear();
        msg.IsVisible = false;
        Assert.Contains(nameof(AgentMessageViewModel.IsRowVisible), changed);
    }
}
