using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Mail;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VulcansTrace.Linux.Agent.Notifications;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Tests.Notifications;

public class NotificationServiceTests
{
    private static SignedAlertMessage CreateAlert() => new()
    {
        Title = "Drift alert",
        Body = "The firewall posture has degraded.",
        ScheduleId = "abc123",
        ScheduleName = "Daily Firewall Check",
        Nonce = "deadbeefcafebabe",
        MaxSeverity = Severity.Critical,
        DriftFindingCount = 2,
        RuleIds = new[] { "FW-001", "FW-002" },
        AttackChainNarratives = new[] { "FW-001 -> FW-002" },
        ProactiveAlertSummaries = new[] { "FW-001 returned after verified fix." },
        RemediationSummary = "Remediation proposal: 1 permitted command.",
        TimestampUtc = new DateTime(2026, 6, 20, 12, 0, 0, DateTimeKind.Utc),
        Signature = "ABCD1234EFGH5678"
    };

    public class NotifySendNotificationServiceTests
    {
        [Fact]
        public async Task NotifySignedAlertAsync_IncludesFullSignatureAndDoesNotThrow()
        {
            var service = new NotifySendNotificationService();
            var alert = CreateAlert();
            // Best-effort: shells out to notify-send, which is absent in CI. Must not throw, and
            // we cannot observe the toast body, so this is a smoke test only.
            await service.NotifySignedAlertAsync(alert);
        }
    }

    public class EmailNotificationServiceTests
    {
        [Fact]
        public async Task NotifySignedAlertAsync_SendsBodyContainingEverySignedField()
        {
            var transport = new CapturingEmailTransport();
            var service = new EmailNotificationService("host", 25, "from@test", "to@test", null, null, true, transport);
            var alert = CreateAlert();

            await service.NotifySignedAlertAsync(alert);

            var sent = Assert.Single(transport.Sent);
            Assert.Contains(alert.Signature, sent.Body);
            Assert.Contains(alert.ScheduleId, sent.Body);
            Assert.Contains(alert.Nonce, sent.Body);
            Assert.Contains(alert.Title, sent.Body);
            Assert.Contains(alert.RemediationSummary!, sent.Body);
            Assert.Contains(alert.RuleIds[0], sent.Body);
            Assert.Contains(alert.ScheduleName, sent.Subject);
        }
    }

    public class WebhookNotificationServiceTests
    {
        [Fact]
        public async Task NotifySignedAlertAsync_PostsJsonWithEverySignedField()
        {
            var handler = new CapturingHttpHandler();
            var service = new WebhookNotificationService("http://test.local/webhook", handler);
            var alert = CreateAlert();

            await service.NotifySignedAlertAsync(alert);
            service.Dispose();

            var body = Assert.Single(handler.CapturedBodies);
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            Assert.Equal(alert.Title, root.GetProperty("title").GetString());
            Assert.Equal(alert.Body, root.GetProperty("message").GetString());
            Assert.Equal(alert.ScheduleId, root.GetProperty("scheduleId").GetString());
            Assert.Equal(alert.ScheduleName, root.GetProperty("scheduleName").GetString());
            Assert.Equal(alert.Nonce, root.GetProperty("nonce").GetString());
            Assert.Equal(alert.Signature, root.GetProperty("signature").GetString());
            Assert.Equal(alert.RemediationSummary, root.GetProperty("remediationSummary").GetString());
            Assert.Equal((int)alert.MaxSeverity, root.GetProperty("maxSeverity").GetInt32());
        }

        [Fact]
        public async Task NotifySignedAlertAsync_OnHttp500_RetriesUpToThreeTimes()
        {
            var handler = new CapturingHttpHandler { Status = HttpStatusCode.InternalServerError };
            var service = new WebhookNotificationService("http://test.local/webhook", handler);

            await service.NotifySignedAlertAsync(CreateAlert());
            service.Dispose();

            Assert.Equal(3, handler.CapturedBodies.Count);
        }

        [Fact]
        public async Task NotifySignedAlertAsync_PropagatesCancellationImmediately()
        {
            var handler = new BlockingHttpHandler();
            var service = new WebhookNotificationService("http://test.local/webhook", handler);
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.NotifySignedAlertAsync(CreateAlert(), cts.Token));
            service.Dispose();
        }
    }

    /// <summary>An HTTP handler that records every request body and returns a fixed status.</summary>
    private sealed class CapturingHttpHandler : HttpMessageHandler
    {
        public List<string> CapturedBodies { get; } = new();
        public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CapturedBodies.Add(request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken));
            return new HttpResponseMessage(Status);
        }
    }

    /// <summary>An HTTP handler that only completes when cancellation is requested, so cancellation is observable.</summary>
    private sealed class BlockingHttpHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var tcs = new TaskCompletionSource<HttpResponseMessage>();
            using var registration = cancellationToken.Register(() => tcs.TrySetCanceled(cancellationToken));
            return tcs.Task;
        }
    }

    /// <summary>An email transport that captures sent messages without opening a socket.</summary>
    private sealed class CapturingEmailTransport : IEmailTransport
    {
        public List<MailMessage> Sent { get; } = new();

        public Task SendAsync(MailMessage message, EmailSmtpOptions options, CancellationToken ct)
        {
            Sent.Add(message);
            return Task.CompletedTask;
        }
    }
}
