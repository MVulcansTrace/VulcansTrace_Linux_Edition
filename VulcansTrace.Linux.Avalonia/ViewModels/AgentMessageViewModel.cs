using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Represents a single message in the agent chat panel.
/// </summary>
public sealed class AgentMessageViewModel : ViewModelBase
{
    private string _text = "";
    private string _details = "";
    private bool _isUser;
    private bool _isInfo;
    private bool _isVisible = true;
    private Severity _severity;
    private DateTime _timestamp;
    private string _category = "";
    private IReadOnlyList<CopyableCommand> _verificationCommands = Array.Empty<CopyableCommand>();
    private RemediationSection? _remediationSection;

    /// <summary>Gets or sets the message text shown to the user.</summary>
    public string Text
    {
        get => _text;
        set => SetField(ref _text, value);
    }

    /// <summary>Gets or sets optional detail text for the message.</summary>
    public string Details
    {
        get => _details;
        set => SetField(ref _details, value);
    }

    /// <summary>Gets or sets whether this message originated from the user.</summary>
    public bool IsUser
    {
        get => _isUser;
        set => SetField(ref _isUser, value);
    }

    /// <summary>Gets or sets whether this message is informational (not a finding).</summary>
    public bool IsInfo
    {
        get => _isInfo;
        set => SetField(ref _isInfo, value);
    }

    /// <summary>Gets or sets whether this message should be visible in the chat panel.</summary>
    public bool IsVisible
    {
        get => _isVisible;
        set => SetField(ref _isVisible, value);
    }

    /// <summary>Gets or sets the finding category label for this message.</summary>
    public string Category
    {
        get => _category;
        set => SetField(ref _category, value);
    }

    /// <summary>Gets or sets the severity level of this message.</summary>
    public Severity Severity
    {
        get => _severity;
        set => SetField(ref _severity, value);
    }

    /// <summary>Gets or sets the timestamp when this message was created.</summary>
    public DateTime Timestamp
    {
        get => _timestamp;
        set => SetField(ref _timestamp, value);
    }

    /// <summary>Gets or sets the verification commands that can be copied from this message.</summary>
    public IReadOnlyList<CopyableCommand> VerificationCommands
    {
        get => _verificationCommands;
        set => SetField(ref _verificationCommands, value);
    }

    /// <summary>Gets whether this message has verification commands to display.</summary>
    public bool HasVerificationCommands => _verificationCommands.Count > 0;

    /// <summary>Gets or sets the interactive remediation section for this message.</summary>
    public RemediationSection? RemediationSection
    {
        get => _remediationSection;
        set
        {
            if (SetField(ref _remediationSection, value))
            {
                OnPropertyChanged(nameof(HasRemediationSection));
                OnPropertyChanged(nameof(HasPreconditions));
                OnPropertyChanged(nameof(HasBackupCommands));
                OnPropertyChanged(nameof(HasApplyCommands));
                OnPropertyChanged(nameof(HasRollbackCommands));
                OnPropertyChanged(nameof(HasRemediationVerificationCommands));
                OnPropertyChanged(nameof(RemediationPreconditions));
                OnPropertyChanged(nameof(RemediationBackupCommands));
                OnPropertyChanged(nameof(RemediationApplyCommands));
                OnPropertyChanged(nameof(RemediationRollbackCommands));
                OnPropertyChanged(nameof(RemediationVerificationCommands));
            }
        }
    }

    /// <summary>Gets whether this message has an interactive remediation section.</summary>
    public bool HasRemediationSection => _remediationSection != null;

    /// <summary>Gets whether the remediation section has preconditions.</summary>
    public bool HasPreconditions => _remediationSection?.Preconditions.Count > 0;

    /// <summary>Gets whether the remediation section has backup commands.</summary>
    public bool HasBackupCommands => _remediationSection?.BackupCommands.Count > 0;

    /// <summary>Gets whether the remediation section has apply commands.</summary>
    public bool HasApplyCommands => _remediationSection?.ApplyCommands.Count > 0;

    /// <summary>Gets whether the remediation section has rollback commands.</summary>
    public bool HasRollbackCommands => _remediationSection?.RollbackCommands.Count > 0;

    /// <summary>Gets whether the remediation section has verification commands.</summary>
    public bool HasRemediationVerificationCommands => _remediationSection?.VerificationCommands.Count > 0;

    /// <summary>Gets the preconditions for the remediation.</summary>
    public IReadOnlyList<string> RemediationPreconditions =>
        _remediationSection?.Preconditions ?? Array.Empty<string>();

    /// <summary>Gets the backup commands as copyable commands.</summary>
    public IReadOnlyList<CopyableCommand> RemediationBackupCommands =>
        ToCopyableCommands(_remediationSection?.BackupCommands);

    /// <summary>Gets the apply commands as copyable commands.</summary>
    public IReadOnlyList<CopyableCommand> RemediationApplyCommands =>
        ToCopyableCommands(_remediationSection?.ApplyCommands);

    /// <summary>Gets the rollback commands as copyable commands.</summary>
    public IReadOnlyList<CopyableCommand> RemediationRollbackCommands =>
        ToCopyableCommands(_remediationSection?.RollbackCommands);

    /// <summary>Gets the verification commands as copyable commands.</summary>
    public IReadOnlyList<CopyableCommand> RemediationVerificationCommands =>
        ToCopyableCommands(_remediationSection?.VerificationCommands);

    private static IReadOnlyList<CopyableCommand> ToCopyableCommands(IReadOnlyList<RemediationCommand>? commands)
    {
        if (commands == null || commands.Count == 0)
            return Array.Empty<CopyableCommand>();

        return commands.Select(c => new CopyableCommand
        {
            DisplayText = c.Command,
            FullCommand = c.Command,
            Safety = c.Safety,
            Analysis = c.Analysis
        }).ToList();
    }

    /// <summary>
    /// Copies the specified command text to the system clipboard.
    /// </summary>
    /// <param name="commandText">The command text to copy to the clipboard.</param>
    public void CopyCommandToClipboard(string commandText)
    {
        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow?.Clipboard?.SetTextAsync(commandText);
        }
    }
}
