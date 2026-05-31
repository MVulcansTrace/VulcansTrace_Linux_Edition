using System.Net;
using System.Text;
using System.Text.Json;

namespace VulcansTrace.Linux.Agent.Notifications;

/// <summary>
/// Webhook notification service that POSTs JSON payloads to a URL.
/// </summary>
public sealed class WebhookNotificationService : INotificationService, IDisposable
{
    private readonly string _webhookUrl;
    private readonly HttpClient _httpClient;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="WebhookNotificationService"/> class.
    /// </summary>
    /// <param name="webhookUrl">The URL to POST notifications to.</param>
    public WebhookNotificationService(string webhookUrl)
    {
        _webhookUrl = webhookUrl ?? throw new ArgumentNullException(nameof(webhookUrl));
        _httpClient = new HttpClient();
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
                    Console.Error.WriteLine($"[VulcansTrace] Webhook returned {statusCode} (attempt {attempt}/{maxRetries}), retrying in {delay.TotalSeconds}s...");
                    await Task.Delay(delay, ct);
                    delay = delay.Multiply(2);
                    continue;
                }

                Console.Error.WriteLine($"[VulcansTrace] Webhook notification returned {statusCode}: {response.ReasonPhrase}");
                return;
            }
            catch (Exception ex) when (attempt < maxRetries && IsTransient(ex))
            {
                Console.Error.WriteLine($"[VulcansTrace] Webhook attempt {attempt}/{maxRetries} failed: {ex.Message}, retrying in {delay.TotalSeconds}s...");
                await Task.Delay(delay, ct);
                delay = delay.Multiply(2);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[VulcansTrace] Webhook notification failed: {ex.Message}");
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
