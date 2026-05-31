using System.Net;
using System.Net.Mail;

namespace VulcansTrace.Linux.Agent.Notifications;

/// <summary>
/// Email notification service using SMTP.
/// </summary>
public sealed class EmailNotificationService : INotificationService
{
    private readonly string _smtpHost;
    private readonly int _smtpPort;
    private readonly string _fromAddress;
    private readonly string _toAddress;
    private readonly string? _username;
    private readonly string? _password;
    private readonly bool _enableSsl;

    /// <summary>
    /// Initializes a new instance of the <see cref="EmailNotificationService"/> class.
    /// </summary>
    /// <param name="smtpHost">SMTP server hostname.</param>
    /// <param name="smtpPort">SMTP server port.</param>
    /// <param name="fromAddress">Sender email address.</param>
    /// <param name="toAddress">Recipient email address.</param>
    /// <param name="username">Optional SMTP username.</param>
    /// <param name="password">Optional SMTP password.</param>
    /// <param name="enableSsl">Whether to use SSL/TLS.</param>
    public EmailNotificationService(
        string smtpHost,
        int smtpPort,
        string fromAddress,
        string toAddress,
        string? username = null,
        string? password = null,
        bool enableSsl = true)
    {
        _smtpHost = smtpHost;
        _smtpPort = smtpPort;
        _fromAddress = fromAddress;
        _toAddress = toAddress;
        _username = username;
        _password = password;
        _enableSsl = enableSsl;
    }

    /// <inheritdoc />
    public Task NotifyAsync(string title, string message, CancellationToken ct = default)
    {
        return SendEmailAsync(title, message, ct);
    }

    /// <inheritdoc />
    public Task NotifyCriticalFindingsAsync(string scheduleName, int criticalCount, CancellationToken ct = default)
    {
        var subject = $"[VulcansTrace] Critical findings in '{scheduleName}'";
        var body = $"Scheduled audit '{scheduleName}' found {criticalCount} new critical issue(s).";
        return SendEmailAsync(subject, body, ct);
    }

    private async Task SendEmailAsync(string subject, string body, CancellationToken ct)
    {
        try
        {
            using var client = new SmtpClient(_smtpHost, _smtpPort);
            client.EnableSsl = _enableSsl;

            if (!string.IsNullOrEmpty(_username) && !string.IsNullOrEmpty(_password))
            {
                client.Credentials = new NetworkCredential(_username, _password);
            }

            var message = new MailMessage(_fromAddress, _toAddress, subject, body);
            await client.SendMailAsync(message, ct);
        }
        catch (Exception ex)
        {
            // Best-effort: log to stderr and degrade silently so the audit itself doesn't fail.
            Console.Error.WriteLine($"[VulcansTrace] Email notification failed: {ex.Message}");
        }
    }
}
