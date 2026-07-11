using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using VulcansTrace.Linux.Agent.Reports;

namespace VulcansTrace.Linux.Agent.Notifications;

/// <summary>
/// Webhook notification service that POSTs JSON payloads to a URL.
/// </summary>
public sealed class WebhookNotificationService : INotificationService, IDisposable
{
    private readonly string _webhookUrl;
    private readonly HttpClient _httpClient;
    private readonly Action<string> _errorLogger;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="WebhookNotificationService"/> class.
    /// </summary>
    /// <param name="webhookUrl">The URL to POST notifications to.</param>
    public WebhookNotificationService(string webhookUrl)
    {
        _webhookUrl = webhookUrl ?? throw new ArgumentNullException(nameof(webhookUrl));
        _httpClient = new HttpClient();
        _errorLogger = Console.Error.WriteLine;
    }

    /// <summary>
    /// Initializes a new instance with a custom HTTP handler. Intended for tests that want to
    /// capture requests without opening a real socket.
    /// </summary>
    /// <param name="webhookUrl">The URL to POST notifications to.</param>
    /// <param name="handler">The HTTP message handler to use.</param>
    internal WebhookNotificationService(
        string webhookUrl,
        HttpMessageHandler handler,
        Action<string>? errorLogger = null)
    {
        _webhookUrl = webhookUrl ?? throw new ArgumentNullException(nameof(webhookUrl));
        _httpClient = new HttpClient(handler ?? throw new ArgumentNullException(nameof(handler)));
        _errorLogger = errorLogger ?? Console.Error.WriteLine;
    }

    /// <summary>
    /// Initializes a new instance from notification settings.
    /// </summary>
    /// <param name="settings">The notification settings containing the webhook URL.</param>
    public WebhookNotificationService(NotificationSettings settings)
        : this((settings ?? throw new ArgumentNullException(nameof(settings))).WebhookUrl)
    {
    }

    /// <inheritdoc />
    public Task NotifyAsync(string title, string message, CancellationToken ct = default)
    {
        var payload = new
        {
            title,
            message,
            timestamp = DateTime.UtcNow
        };
        return PostAsync(payload, ct);
    }

    /// <inheritdoc />
    public Task NotifyCriticalFindingsAsync(string scheduleName, int criticalCount, CancellationToken ct = default)
    {
        var payload = new
        {
            title = "VulcansTrace: Critical findings detected",
            message = $"Scheduled audit '{scheduleName}' found {criticalCount} new critical issue(s).",
            scheduleName,
            criticalCount,
            timestamp = DateTime.UtcNow
        };
        return PostAsync(payload, ct);
    }

    /// <inheritdoc />
    public Task NotifySignedAlertAsync(SignedAlertMessage alert, CancellationToken ct = default)
    {
        var payload = new
        {
            title = alert.Title,
            message = alert.Body,
            alert.ScheduleId,
            alert.ScheduleName,
            alert.Nonce,
            alert.MaxSeverity,
            alert.DriftFindingCount,
            alert.RuleIds,
            alert.AttackChainNarratives,
            alert.ProactiveAlertSummaries,
            remediationSummary = alert.RemediationSummary,
            alert.TimestampUtc,
            alert.Signature
        };
        return PostAsync(payload, ct);
    }

    /// <inheritdoc />
    public async Task<bool> SendTestAsync(CancellationToken ct = default)
    {
        // Single attempt, no retry: the test path must report the real outcome so a user can
        // verify the configured URL, not a transient recovery.
        var payload = new
        {
            title = "VulcansTrace: Test notification",
            message = "If you can read this, webhook notification settings are configured correctly.",
            timestamp = DateTime.UtcNow
        };
        try
        {
            var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var response = await _httpClient.PostAsync(_webhookUrl, content, ct);
            return response.IsSuccessStatusCode;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }

    private async Task PostAsync(object payload, CancellationToken ct)
    {
        const int maxRetries = 3;
        var delay = TimeSpan.FromSeconds(1);

        for (var attempt = 1; attempt <= maxRetries; attempt++)
        {
            try
            {
                var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                });
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync(_webhookUrl, content, ct);

                if (response.IsSuccessStatusCode)
                    return;

                var statusCode = (int)response.StatusCode;
                if (statusCode >= 500 && statusCode < 600 && attempt < maxRetries)
                {
                    _errorLogger($"[VulcansTrace] Webhook returned {statusCode} (attempt {attempt}/{maxRetries}), retrying in {delay.TotalSeconds}s...");
                    await Task.Delay(delay, ct);
                    delay = delay.Multiply(2);
                    continue;
                }

                _errorLogger($"[VulcansTrace] Webhook notification returned {statusCode}: {response.ReasonPhrase}");
                return;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // Caller cancellation must propagate, not be retried or swallowed.
                // (HttpClient also throws OperationCanceledException for plain timeouts; those are
                // not cancellation-requested and fall through to the transient retry below.)
                throw;
            }
            catch (Exception ex) when (attempt < maxRetries && IsTransient(ex))
            {
                _errorLogger($"[VulcansTrace] Webhook attempt {attempt}/{maxRetries} failed: {ErrorSanitizer.SanitizeException(ex)}, retrying in {delay.TotalSeconds}s...");
                await Task.Delay(delay, ct);
                delay = delay.Multiply(2);
            }
            catch (Exception ex)
            {
                _errorLogger($"[VulcansTrace] Webhook notification failed: {ErrorSanitizer.SanitizeException(ex)}");
                return;
            }
        }
    }

    private static bool IsTransient(Exception ex)
    {
        return ex is HttpRequestException
            or TaskCanceledException
            or TimeoutException
            or IOException;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _httpClient.Dispose();
    }
}
