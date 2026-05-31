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
}
