using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Windows.Input;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input.Platform;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Messages;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Agent.Suggestions;
using VulcansTrace.Linux.Avalonia.Converters;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Represents a single message in the agent chat panel. Not sealed: UI v2 Phase 2
/// introduces structured card messages (summary card, finding card) as subclasses
/// so the chat ListBox can select per-kind DataTemplates by runtime type.
/// </summary>
public class AgentMessageViewModel : ViewModelBase
{
    private string _text = "";
    private string _details = "";
    private bool _isUser;
    private bool _isInfo;
    private bool _isVisible = true;
    private Severity _severity;
    private DateTime _timestamp;
    private string _category = "";
    private string _confidence = "";
    private string _evidenceSignalsDisplay = "";
    private IReadOnlyList<CopyableCommand> _verificationCommands = Array.Empty<CopyableCommand>();
    private IReadOnlyList<SuggestedFollowUp> _suggestions = Array.Empty<SuggestedFollowUp>();
    private ICommand? _suggestionCommand;
    private RemediationSection? _remediationSection;

    private bool _isError;
    private bool _isProse;
    private bool _isStreaming;
    private bool _isStreamingPending;
    private string _streamingText = "";
    private string _streamingFinalText = "";
    private IReadOnlyList<AgentMessageBlock> _formattedBlocks = Array.Empty<AgentMessageBlock>();
    private string _messageId = AgentMessageFingerprint.NewId();
    private bool _isPinned;
    private ICommand? _togglePinCommand;

    /// <summary>
    /// Initializes a new instance of the <see cref="AgentMessageViewModel"/u003e class
    /// with a unique message identifier.
    /// </summary>
    public AgentMessageViewModel()
    {
    }

    /// <summary>Gets the parsed rich-content blocks for the message bubble.</summary>
    public IReadOnlyList<AgentMessageBlock> FormattedBlocks => _formattedBlocks;

    /// <summary>Gets or sets the message text shown to the user.</summary>
    public string Text
    {
        get => _text;
        set
        {
            if (SetField(ref _text, value))
            {
                RebuildFormattedBlocks();
                OnPropertyChanged(nameof(AutomationName));
                OnPropertyChanged(nameof(CanBePinned));
            }
        }
    }

    /// <summary>Gets or sets the unique identifier for this message instance. Used as the pin primary key.</summary>
    public string MessageId
    {
        get => _messageId;
        set => SetField(ref _messageId, value);
    }

    /// <summary>Gets or sets whether this message is pinned.</summary>
    public bool IsPinned
    {
        get => _isPinned;
        set
        {
            if (SetField(ref _isPinned, value))
            {
                OnPropertyChanged(nameof(PinIcon));
                OnPropertyChanged(nameof(PinTooltip));
            }
        }
    }

    /// <summary>Gets the icon name for the pin action button.</summary>
    public string PinIcon => IsPinned ? "mdi-pin-off" : "mdi-pin-outline";

    /// <summary>Gets the tooltip for the pin action button.</summary>
    public string PinTooltip => IsPinned ? "Unpin message" : "Pin message";

    /// <summary>
    /// Gets whether this message can be pinned: it must have text and must not still be
    /// streaming or queued for streaming.
    /// </summary>
    public bool CanBePinned => !string.IsNullOrWhiteSpace(_text) && !_isStreaming && !_isStreamingPending;

    /// <summary>Gets or sets the command invoked when the pin/unpin button is clicked.</summary>
    public ICommand? TogglePinCommand
    {
        get => _togglePinCommand;
        set => SetField(ref _togglePinCommand, value);
    }

    /// <summary>
    /// Builds a <see cref="PinnedMessage"/> record from the current message state.
    /// </summary>
    public PinnedMessage ToPinnedMessage()
    {
        return new PinnedMessage
        {
            MessageId = _messageId,
            IsUser = _isUser,
            Text = _text,
            Details = _details,
            Category = _category,
            Severity = _severity.ToString(),
            IsInfo = _isInfo,
            IsError = _isError,
            IsProse = _isProse,
            TimestampUtc = _timestamp == DateTime.MinValue ? DateTime.UtcNow : _timestamp.ToUniversalTime()
        };
    }

    /// <summary>Gets or sets whether this message is currently streaming/typewriting its text.</summary>
    public bool IsStreaming
    {
        get => _isStreaming;
        set
        {
            if (SetField(ref _isStreaming, value))
            {
                OnPropertyChanged(nameof(AutomationName));
                OnPropertyChanged(nameof(CanBePinned));
            }
        }
    }

    /// <summary>Gets or sets the partial text revealed while streaming.</summary>
    public string StreamingText
    {
        get => _streamingText;
        set => SetField(ref _streamingText, value);
    }

    /// <summary>
    /// Gets or sets whether this prose message is queued for streaming and should stay
    /// hidden until its turn. Cleared when the message becomes the active streamer and
    /// again when streaming ends, so the row only stays hidden while genuinely waiting.
    /// </summary>
    public bool IsStreamingPending
    {
        get => _isStreamingPending;
        set
        {
            if (SetField(ref _isStreamingPending, value))
            {
                OnPropertyChanged(nameof(IsRowVisible));
                OnPropertyChanged(nameof(CanBePinned));
            }
        }
    }

    /// <summary>Gets or sets the full final text, exposed immediately for accessibility.</summary>
    public string StreamingFinalText
    {
        get => _streamingFinalText;
        set
        {
            if (SetField(ref _streamingFinalText, value))
            {
                OnPropertyChanged(nameof(AutomationName));
            }
        }
    }

    /// <summary>
    /// Ends streaming by committing the final text, rebuilding formatted blocks once,
    /// and clearing streaming state.
    /// </summary>
    public void FlushStreaming(string? finalText = null)
    {
        var text = finalText ?? _streamingText;
        StreamingText = "";
        StreamingFinalText = "";
        IsStreaming = false;
        IsStreamingPending = false;
        if (!string.IsNullOrEmpty(text))
        {
            Text = text;
        }
    }

    /// <summary>Gets or sets whether this message is prose that should be revealed with a typewriter effect.</summary>
    public bool IsProse
    {
        get => _isProse;
        set => SetField(ref _isProse, value);
    }

    /// <summary>Gets or sets whether this message represents an error.</summary>
    public bool IsError
    {
        get => _isError;
        set => SetField(ref _isError, value);
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
        set
        {
            if (SetField(ref _isUser, value))
            {
                OnPropertyChanged(nameof(AutomationName));
            }
        }
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
        set
        {
            if (SetField(ref _isVisible, value))
            {
                OnPropertyChanged(nameof(IsRowVisible));
            }
        }
    }

    /// <summary>
    /// Gets whether the message row should render: visible per the current chat filters and
    /// not still queued for its streaming turn. Bound by the message row so a pending prose
    /// bubble stays hidden until it is actually revealed.
    /// </summary>
    public bool IsRowVisible => _isVisible && !_isStreamingPending;

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

    /// <summary>Gets or sets the detection confidence label for a finding message.</summary>
    public string Confidence
    {
        get => _confidence;
        set
        {
            if (SetField(ref _confidence, value))
            {
                OnPropertyChanged(nameof(HasConfidence));
            }
        }
    }

    /// <summary>Gets or sets the evidence signal names for a finding message.</summary>
    public string EvidenceSignalsDisplay
    {
        get => _evidenceSignalsDisplay;
        set
        {
            if (SetField(ref _evidenceSignalsDisplay, value))
            {
                OnPropertyChanged(nameof(HasEvidenceSignals));
            }
        }
    }

    /// <summary>Gets whether this message has a confidence label to display.</summary>
    public bool HasConfidence => !string.IsNullOrWhiteSpace(_confidence);

    /// <summary>Gets whether this message has evidence signal names to display.</summary>
    public bool HasEvidenceSignals => !string.IsNullOrWhiteSpace(_evidenceSignalsDisplay);

    /// <summary>Gets or sets the timestamp when this message was created.</summary>
    public DateTime Timestamp
    {
        get => _timestamp;
        set
        {
            if (SetField(ref _timestamp, value))
            {
                OnPropertyChanged(nameof(FormattedTimestamp));
                OnPropertyChanged(nameof(ShowTimestamp));
                OnPropertyChanged(nameof(AutomationName));
            }
        }
    }

    /// <summary>Gets a short, user-facing timestamp for the message bubble.</summary>
    public string FormattedTimestamp => _timestamp.ToString("HH:mm");

    /// <summary>Gets whether the timestamp should be shown on the message bubble.</summary>
    public bool ShowTimestamp => _timestamp != DateTime.MinValue;

    /// <summary>Gets a screen-reader-friendly name for this message bubble.</summary>
    public string AutomationName
    {
        get
        {
            var text = _isStreaming && !string.IsNullOrEmpty(_streamingFinalText)
                ? _streamingFinalText
                : _text;
            return $"{(IsUser ? "You" : "VulcansTrace")}{(ShowTimestamp ? $" at {FormattedTimestamp}" : "")}: {text}";
        }
    }

    /// <summary>Gets or sets the verification commands that can be copied from this message.</summary>
    public IReadOnlyList<CopyableCommand> VerificationCommands
    {
        get => _verificationCommands;
        set => SetField(ref _verificationCommands, value);
    }

    /// <summary>Gets whether this message has verification commands to display.</summary>
    public bool HasVerificationCommands => _verificationCommands.Count > 0;

    /// <summary>Gets or sets the contextual follow-up suggestions for this message.</summary>
    public IReadOnlyList<SuggestedFollowUp> Suggestions
    {
        get => _suggestions;
        set
        {
            if (SetField(ref _suggestions, value))
            {
                OnPropertyChanged(nameof(HasSuggestions));
            }
        }
    }

    /// <summary>Gets whether this message has follow-up suggestions to display.</summary>
    public bool HasSuggestions => _suggestions.Count > 0;

    /// <summary>Gets or sets the command invoked when a suggestion chip is clicked.</summary>
    public ICommand? SuggestionCommand
    {
        get => _suggestionCommand;
        set => SetField(ref _suggestionCommand, value);
    }

    private string _sessionId = "";
    private RemediationSessionStatus _sessionStatus;
    private bool _isVerificationResult;

    /// <summary>Gets or sets the remediation session ID for this message.</summary>
    public string SessionId
    {
        get => _sessionId;
        set
        {
            if (SetField(ref _sessionId, value))
            {
                OnPropertyChanged(nameof(HasActiveSession));
            }
        }
    }

    /// <summary>Gets or sets the session status.</summary>
    public RemediationSessionStatus SessionStatus
    {
        get => _sessionStatus;
        set
        {
            if (SetField(ref _sessionStatus, value))
            {
                OnPropertyChanged(nameof(HasActiveSession));
            }
        }
    }

    /// <summary>Gets or sets whether this message represents a verification result.</summary>
    public bool IsVerificationResult
    {
        get => _isVerificationResult;
        set => SetField(ref _isVerificationResult, value);
    }

    private IReadOnlyList<RemediationSessionEvent> _sessionTimeline = Array.Empty<RemediationSessionEvent>();

    /// <summary>Gets or sets the session timeline events for this message.</summary>
    public IReadOnlyList<RemediationSessionEvent> SessionTimeline
    {
        get => _sessionTimeline;
        set
        {
            if (SetField(ref _sessionTimeline, value))
            {
                OnPropertyChanged(nameof(HasSessionTimeline));
            }
        }
    }

    /// <summary>Gets whether this message has a session timeline to display.</summary>
    public bool HasSessionTimeline => _sessionTimeline.Count > 0;

    /// <summary>Gets whether this message has an active session (can be verified).</summary>
    public bool HasActiveSession => !string.IsNullOrEmpty(_sessionId) && _sessionStatus == RemediationSessionStatus.Active;

    /// <summary>Gets or sets the interactive remediation section for this message.</summary>
    public RemediationSection? RemediationSection
    {
        get => _remediationSection;
        set
        {
            if (SetField(ref _remediationSection, value))
            {
                // Notify that every derived remediation property may have changed,
                // rather than firing ~30 individual PropertyChanged events.
                OnPropertyChanged(string.Empty);
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

    /// <summary>Gets whether the remediation section has countermeasure commands.</summary>
    public bool HasCountermeasureCommands => _remediationSection?.CountermeasureCommands.Count > 0;

    /// <summary>Gets the countermeasure commands as copyable commands.</summary>
    public IReadOnlyList<CopyableCommand> CountermeasureCommands =>
        ToCopyableCommands(_remediationSection?.CountermeasureCommands);

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

    /// <summary>Gets whether the remediation section has an impact preview.</summary>
    public bool HasImpactPreview => _remediationSection?.ImpactPreview != null;

    /// <summary>Gets the expected impact text from the impact preview.</summary>
    public string ImpactPreviewExpectedImpact =>
        _remediationSection?.ImpactPreview?.ExpectedImpact ?? string.Empty;

    /// <summary>Gets the rollback path text from the impact preview.</summary>
    public string ImpactPreviewRollbackPath =>
        _remediationSection?.ImpactPreview?.RollbackPath ?? string.Empty;

    /// <summary>Gets the verification command text from the impact preview.</summary>
    public string ImpactPreviewVerificationCommand =>
        _remediationSection?.ImpactPreview?.VerificationCommand ?? string.Empty;

    /// <summary>Gets whether the impact preview verification text is an actual shell command.</summary>
    public bool IsImpactPreviewVerificationCommand => _remediationSection?.ImpactPreview?.VerificationKind == RemediationPreviewTextKind.Command;

    /// <summary>Gets where the impact preview expected impact text came from.</summary>
    public RemediationImpactSource ImpactPreviewExpectedImpactSource =>
        _remediationSection?.ImpactPreview?.ExpectedImpactSource ?? RemediationImpactSource.Generic;

    /// <summary>Gets the kind of rollback path shown in the impact preview.</summary>
    public RemediationPreviewTextKind ImpactPreviewRollbackPathKind =>
        _remediationSection?.ImpactPreview?.RollbackPathKind ?? RemediationPreviewTextKind.ManualFallback;

    /// <summary>Gets the kind of verification text shown in the impact preview.</summary>
    public RemediationPreviewTextKind ImpactPreviewVerificationKind =>
        _remediationSection?.ImpactPreview?.VerificationKind ?? RemediationPreviewTextKind.ManualFallback;

    /// <summary>
    /// Gets whether the rollback path is an actual command (from RollbackCommands)
    /// rather than a prose hint.
    /// </summary>
    public bool IsRollbackPathCommand => _remediationSection?.ImpactPreview?.RollbackPathKind == RemediationPreviewTextKind.Command;

    /// <summary>
    /// Gets the font family for the rollback path: monospace for commands,
    /// default for prose hints.
    /// </summary>
    public string RollbackPathFontFamily => IsRollbackPathCommand ? "Consolas,Monospace" : "";

    /// <summary>
    /// Gets the font family for preview verification: monospace for commands,
    /// default for prose fallbacks.
    /// </summary>
    public string ImpactPreviewVerificationFontFamily => IsImpactPreviewVerificationCommand ? "Consolas,Monospace" : "";

    /// <summary>Gets the risk before applying the remediation.</summary>
    public string ImpactPreviewRiskBefore =>
        _remediationSection?.ImpactPreview?.RiskBefore ?? string.Empty;

    /// <summary>Gets the expected risk after applying the remediation.</summary>
    public string ImpactPreviewExpectedRiskAfter =>
        _remediationSection?.ImpactPreview?.ExpectedRiskAfter ?? string.Empty;

    /// <summary>Gets the total number of apply and backup commands involved.</summary>
    public int ImpactPreviewCommandCount =>
        _remediationSection?.ImpactPreview?.CommandCount ?? 0;

    /// <summary>Gets whether explicit rollback guidance is available.</summary>
    public bool ImpactPreviewRollbackAvailable =>
        _remediationSection?.ImpactPreview?.RollbackAvailable ?? false;

    /// <summary>Gets whether the preview exists but lacks explicit rollback guidance.</summary>
    public bool ImpactPreviewRollbackUnavailable => HasImpactPreview && !ImpactPreviewRollbackAvailable;

    /// <summary>Gets a user-facing rollback availability value.</summary>
    public string ImpactPreviewRollbackAvailabilityLabel => ImpactPreviewRollbackAvailable ? "Yes" : "No";

    /// <summary>Gets whether applying the remediation may require a service restart.</summary>
    public bool ImpactPreviewHasRestartImpact =>
        _remediationSection?.ImpactPreview?.HasRestartImpact ?? false;

    /// <summary>Gets whether applying the remediation poses a lockout risk.</summary>
    public bool ImpactPreviewHasLockoutRisk =>
        _remediationSection?.ImpactPreview?.HasLockoutRisk ?? false;

    /// <summary>Gets the human-readable restart impact description.</summary>
    public string ImpactPreviewRestartImpactDescription =>
        _remediationSection?.ImpactPreview?.RestartImpactDescription ?? string.Empty;

    /// <summary>Gets the human-readable lockout risk description.</summary>
    public string ImpactPreviewLockoutRiskDescription =>
        _remediationSection?.ImpactPreview?.LockoutRiskDescription ?? string.Empty;

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

    private static IReadOnlyList<CopyableCommand> ToCopyableCommands(IReadOnlyList<CountermeasureCommand>? commands)
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
            _ = desktop.MainWindow?.Clipboard?.SetTextAsync(commandText);
        }
    }

    /// <summary>
    /// Opens the specified URL in the default browser.
    /// </summary>
    /// <param name="url">The URL to open.</param>
    public void OpenUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return;

        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch
        {
            // Silently ignore failures from missing browser handlers or sandbox restrictions.
        }
    }

    private void RebuildFormattedBlocks()
    {
        var parser = new MarkdownBlocksConverter();
        _formattedBlocks = parser.Parse(
            _text,
            code => new RelayCommand<string>(_ => CopyCommandToClipboard(code)),
            url => new RelayCommand<string>(_ => OpenUrl(url), _ => !string.IsNullOrWhiteSpace(url)));
        OnPropertyChanged(nameof(FormattedBlocks));
    }
}
