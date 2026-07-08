using System;
using VulcansTrace.Linux.Agent.Actions;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class AnalystActionLoggerTests
{
    [Fact]
    public async Task LogAsync_AppendsEntry()
    {
        var store = new InMemoryAnalystActionStore();
        var logger = new AnalystActionLogger(store);

        await logger.LogAsync("cli", AnalystActionType.AuditRan, "FullAudit", "findings=5");

        var all = store.GetAll();
        Assert.Single(all);
        Assert.Equal("cli", all[0].Actor);
        Assert.Equal(AnalystActionType.AuditRan, all[0].ActionType);
        Assert.Equal("FullAudit", all[0].Target);
        Assert.Equal("findings=5", all[0].Details);
        Assert.NotEmpty(all[0].Id);
        Assert.Equal(DateTimeKind.Utc, all[0].TimestampUtc.Kind);
    }

    [Fact]
    public async Task LogAuditAsync_AppendsAuditEntry()
    {
        var store = new InMemoryAnalystActionStore();
        var logger = new AnalystActionLogger(store);

        await logger.LogAuditAsync("avalonia", "FullAudit", "Workstation", 7);

        var entry = Assert.Single(store.GetAll());
        Assert.Equal(AnalystActionType.AuditRan, entry.ActionType);
        Assert.Contains("FullAudit", entry.Target);
        Assert.Contains("Workstation", entry.Details);
        Assert.Contains("7", entry.Details);
    }

    [Fact]
    public async Task LogAsync_SwallowsStoreException()
    {
        var store = new ThrowingAnalystActionStore();
        var logger = new AnalystActionLogger(store);

        var exception = await Record.ExceptionAsync(() => logger.LogAsync("cli", AnalystActionType.AuditRan));

        Assert.Null(exception);
    }

    private sealed class ThrowingAnalystActionStore : IAnalystActionStore
    {
        public event EventHandler? Changed { add { } remove { } }

        public string? PersistenceWarning => "always fails";

        public IReadOnlyList<AnalystActionEntry> GetAll() => throw new InvalidOperationException("get fails");

        public void Append(AnalystActionEntry entry) => throw new InvalidOperationException("append fails");

        public void Clear() => throw new InvalidOperationException("clear fails");
    }
}
