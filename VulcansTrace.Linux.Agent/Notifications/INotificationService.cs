using System;

namespace VulcansTrace.Linux.Agent.Notifications;

/// <summary>
/// Abstraction for sending out-of-band notifications about audit results.
/// </summary>
public interface INotificationService
{
    /// <summary>
    /// Sends a generic notification.
    /// </summary>
    /// <param name="title">Notification title.</param>
    /// <param name="message">Notification body.</param>
    /// <param name="ct">Cancellation token.</param>
    [Obsolete("Unused - prefer NotifyCriticalFindingsAsync")]
    Task NotifyAsync(string title, string message, CancellationToken ct = default);

    /// <summary>
    /// Sends a notification when a scheduled audit produces critical findings.
    /// </summary>
    /// <param name="scheduleName">The friendly name of the schedule that ran.</param>
    /// <param name="criticalCount">Number of critical findings.</param>
    /// <param name="ct">Cancellation token.</param>
    Task NotifyCriticalFindingsAsync(string scheduleName, int criticalCount, CancellationToken ct = default);

    /// <summary>
    /// Sends a signed, autonomous drift-response alert produced by a scheduled audit.
    /// </summary>
    /// <param name="alert">The signed alert payload.</param>
    /// <param name="ct">Cancellation token.</param>
    Task NotifySignedAlertAsync(SignedAlertMessage alert, CancellationToken ct = default);
}

/// <summary>
/// A signed alert payload for autonomous drift-response notifications.
/// </summary>
public sealed record SignedAlertMessage
{
    /// <summary>Notification title.</summary>
    public required string Title { get; init; }

    /// <summary>Compressed, human-readable alert body.</summary>
    public required string Body { get; init; }

    /// <summary>Stable id of the schedule that triggered the alert. Bound into the signature.</summary>
    public required string ScheduleId { get; init; }

    /// <summary>Friendly name of the schedule that triggered the alert.</summary>
    public required string ScheduleName { get; init; }

    /// <summary>
    /// Per-alert cryptographic nonce (hex). Bound into the signature so two alerts over
    /// otherwise-identical content cannot be replayed as one another.
    /// </summary>
    public required string Nonce { get; init; }

    /// <summary>Highest severity observed in the drift findings.</summary>
    public required Core.Severity MaxSeverity { get; init; }

    /// <summary>Total number of drift findings.</summary>
    public required int DriftFindingCount { get; init; }

    /// <summary>Rule IDs of the drift findings.</summary>
    public IReadOnlyList<string> RuleIds { get; init; } = Array.Empty<string>();

    /// <summary>Narratives of any attack chains formed by the current findings.</summary>
    public IReadOnlyList<string> AttackChainNarratives { get; init; } = Array.Empty<string>();

    /// <summary>Summaries of any proactive alerts triggered by regressions.</summary>
    public IReadOnlyList<string> ProactiveAlertSummaries { get; init; } = Array.Empty<string>();

    /// <summary>Human-readable remediation preview, when the schedule allows human-approved remediation.</summary>
    public string? RemediationSummary { get; init; }

    /// <summary>UTC timestamp of the alert.</summary>
    public DateTime TimestampUtc { get; init; } = DateTime.UtcNow;

    /// <summary>
    /// HMAC-SHA256 signature (hex) of the canonical alert payload, or <c>"UNSIGNED"</c>
    /// when no signing key is configured (the payload then cannot be authenticated).
    /// </summary>
    public string Signature { get; init; } = string.Empty;
}
