using System.Net;
using System.Net.Mail;
using System.Text;

namespace VulcansTrace.Linux.Agent.Notifications;

/// <summary>
/// Email notification service using SMTP.
/// </summary>
public sealed class EmailNotificationService : INotificationService
{
    private readonly EmailSmtpOptions _smtp;
    private readonly string _fromAddress;
    private readonly string _toAddress;
    private readonly IEmailTransport _transport;

    /// <summary>
    /// Initializes a new instance from explicit SMTP settings.
    /// </summary>
    public EmailNotificationService(
        string smtpHost,
        int smtpPort,
        string fromAddress,
        string toAddress,
        string? username = null,
        string? password = null,
        bool enableSsl = true)
        : this(smtpHost, smtpPort, fromAddress, toAddress, username, password, enableSsl, transport: null)
    {
    }

    /// <summary>
    /// Initializes a new instance from notification settings.
    /// </summary>
    public EmailNotificationService(NotificationSettings settings)
        : this(
            (settings ?? throw new ArgumentNullException(nameof(settings))).EmailSmtpHost,
            settings.EmailSmtpPort,
            settings.EmailFrom,
            settings.EmailTo,
            settings.EmailUsername,
            settings.EmailPassword,
            settings.EmailEnableSsl,
            transport: null)
    {
    }

    /// <summary>
    /// Initializes a new instance with a custom SMTP transport. Intended for tests that want to
    /// capture sent mail without opening a real socket.
    /// </summary>
    internal EmailNotificationService(
        string smtpHost,
        int smtpPort,
        string fromAddress,
        string toAddress,
        string? username,
        string? password,
        bool enableSsl,
        IEmailTransport? transport)
    {
        _smtp = new EmailSmtpOptions
        {
            Host = smtpHost,
            Port = smtpPort,
            EnableSsl = enableSsl,
            Username = username,
            Password = password
        };
        _fromAddress = fromAddress;
        _toAddress = toAddress;
        _transport = transport ?? new SmtpEmailTransport();
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

    /// <inheritdoc />
    public Task NotifySignedAlertAsync(SignedAlertMessage alert, CancellationToken ct = default)
    {
        var subject = $"[VulcansTrace] Drift alert: {alert.MaxSeverity} findings in '{alert.ScheduleName}'";
        // The body carries every field that is bound into the signature (see SignedAlertVerifier)
        // so a recipient can recompute and verify the HMAC without a separate channel.
        var body = new StringBuilder();
        body.AppendLine(alert.Body);
        body.AppendLine();
        body.AppendLine($"Title: {alert.Title}");
        body.AppendLine($"Schedule: {alert.ScheduleName} (id: {alert.ScheduleId})");
        body.AppendLine($"Nonce: {alert.Nonce}");
        body.AppendLine($"Drift findings: {alert.DriftFindingCount}");
        body.AppendLine($"Max severity: {alert.MaxSeverity}");
        body.AppendLine($"Timestamp (UTC): {alert.TimestampUtc:O}");
        if (alert.RuleIds.Count > 0)
        {
            body.AppendLine($"Rule IDs: {string.Join(", ", alert.RuleIds)}");
        }
        if (alert.AttackChainNarratives.Count > 0)
        {
            body.AppendLine();
            body.AppendLine("Attack chains:");
            foreach (var narrative in alert.AttackChainNarratives)
            {
                body.AppendLine($"  - {narrative}");
            }
        }
        if (alert.ProactiveAlertSummaries.Count > 0)
        {
            body.AppendLine();
            body.AppendLine("Proactive alerts:");
            foreach (var summary in alert.ProactiveAlertSummaries)
            {
                body.AppendLine($"  - {summary}");
            }
        }
        if (!string.IsNullOrWhiteSpace(alert.RemediationSummary))
        {
            body.AppendLine();
            body.AppendLine("Remediation proposal:");
            body.AppendLine(alert.RemediationSummary);
        }
        body.AppendLine();
        body.AppendLine($"Signature: {alert.Signature}");
        return SendEmailAsync(subject, body.ToString(), ct);
    }

    /// <inheritdoc />
    public async Task<bool> SendTestAsync(CancellationToken ct = default)
    {
        const string subject = "[VulcansTrace] Test notification";
        const string body = "If you can read this, SMTP notification settings are configured correctly.";
        try
        {
            using var message = new MailMessage(_fromAddress, _toAddress, subject, body);
            await _transport.SendAsync(message, _smtp, ct);
            return true;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            // Unlike SendEmailAsync, the test path surfaces failure so a user can verify settings.
            return false;
        }
    }

    private async Task SendEmailAsync(string subject, string body, CancellationToken ct)
    {
        try
        {
            using var message = new MailMessage(_fromAddress, _toAddress, subject, body);
            await _transport.SendAsync(message, _smtp, ct);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Best-effort: log to stderr and degrade silently so the audit itself doesn't fail.
            Console.Error.WriteLine($"[VulcansTrace] Email notification failed: {ex.Message}");
        }
    }
}

/// <summary>SMTP delivery settings for <see cref="EmailNotificationService"/>.</summary>
internal sealed class EmailSmtpOptions
{
    /// <summary>SMTP server hostname.</summary>
    public required string Host { get; init; }

    /// <summary>SMTP server port.</summary>
    public required int Port { get; init; }

    /// <summary>Whether to use SSL/TLS.</summary>
    public bool EnableSsl { get; init; }

    /// <summary>Optional SMTP username.</summary>
    public string? Username { get; init; }

    /// <summary>Optional SMTP password.</summary>
    public string? Password { get; init; }
}

/// <summary>Abstraction over SMTP delivery so notification tests need no real socket.</summary>
internal interface IEmailTransport
{
    /// <summary>Sends a mail message using the supplied SMTP options.</summary>
    Task SendAsync(MailMessage message, EmailSmtpOptions options, CancellationToken ct);
}

/// <summary>Default SMTP transport backed by <see cref="SmtpClient"/>.</summary>
internal sealed class SmtpEmailTransport : IEmailTransport
{
    /// <inheritdoc />
    public async Task SendAsync(MailMessage message, EmailSmtpOptions options, CancellationToken ct)
    {
        using var client = new SmtpClient(options.Host, options.Port);
        client.EnableSsl = options.EnableSsl;

        if (!string.IsNullOrEmpty(options.Username) && !string.IsNullOrEmpty(options.Password))
        {
            client.Credentials = new NetworkCredential(options.Username, options.Password);
        }

        await client.SendMailAsync(message, ct);
    }
}
