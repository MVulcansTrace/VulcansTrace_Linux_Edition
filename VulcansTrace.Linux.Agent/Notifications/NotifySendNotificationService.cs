using System.Diagnostics;

namespace VulcansTrace.Linux.Agent.Notifications;

/// <summary>
/// Linux desktop notification service that shells out to <c>notify-send</c>.
/// Falls back silently when <c>notify-send</c> is unavailable.
/// </summary>
public sealed class NotifySendNotificationService : INotificationService
{
    /// <inheritdoc />
    public Task NotifyAsync(string title, string message, CancellationToken ct = default)
    {
        TryNotifySend(title, message);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task NotifyCriticalFindingsAsync(string scheduleName, int criticalCount, CancellationToken ct = default)
    {
        var title = "VulcansTrace: Critical findings detected";
        var message = $"Scheduled audit '{scheduleName}' found {criticalCount} critical issue(s).";
        TryNotifySend(title, message, urgency: "critical");
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task NotifySignedAlertAsync(SignedAlertMessage alert, CancellationToken ct = default)
    {
        var title = alert.Title;
        var body = alert.Body;
        const int maxProse = 220;
        if (body.Length > maxProse)
        {
            body = body[..(maxProse - 3)].TrimEnd() + "...";
        }
        // Append the full signature (not a truncation) so the toast is independently verifiable.
        body += $" [sig:{alert.Signature}]";
        TryNotifySend(title, body, urgency: "critical");
        return Task.CompletedTask;
    }

    private static void TryNotifySend(string title, string message, string urgency = "normal")
    {
        try
        {
            // ArgumentList passes title/message as separate argv entries (no shell), so message
            // content cannot inject additional notify-send arguments.
            var startInfo = new ProcessStartInfo
            {
                FileName = "notify-send",
                ArgumentList = { $"--urgency={urgency}", title, message },
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo);
            process?.WaitForExit(TimeSpan.FromSeconds(5));
        }
        catch
        {
            // Best-effort: silently degrade if notify-send is missing or fails.
        }
    }
}
