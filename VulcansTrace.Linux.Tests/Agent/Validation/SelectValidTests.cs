using VulcansTrace.Linux.Agent.Validation;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Tests.Agent.Validation;

public sealed class SelectValidTests
{
    private readonly IocEntryValidator _validator = new();

    [Fact]
    public void PartitionsValidAndInvalid_AndCountsRejected()
    {
        var items = new List<IocEntry>
        {
            new() { Type = IocType.IPv4, Value = "1.2.3.4", Source = "test" },
            new() { Type = IocType.FileHash, Value = "not-hex!", Source = "test" }, // invalid
            new() { Type = IocType.IPv4, Value = "5.6.7.8", Source = "test" },
        };

        var valid = _validator.SelectValid(items, out var rejected);

        Assert.Equal(2, valid.Count);
        Assert.Equal(1, rejected);
        Assert.DoesNotContain(valid, e => e.Type == IocType.FileHash);
    }

    [Fact]
    public void AllValid_RejectsNone()
    {
        var items = new List<IocEntry>
        {
            new() { Type = IocType.IPv4, Value = "1.2.3.4", Source = "test" },
            new() { Type = IocType.IPv4, Value = "5.6.7.8", Source = "test" },
        };

        var valid = _validator.SelectValid(items, out var rejected);

        Assert.Equal(2, valid.Count);
        Assert.Equal(0, rejected);
    }

    [Fact]
    public void AllInvalid_ReturnsEmpty_WithoutThrowing()
    {
        var items = new List<IocEntry>
        {
            new() { Type = IocType.FileHash, Value = "not-hex!", Source = "test" },
            new() { Type = IocType.FileHash, Value = "zzz-no", Source = "test" },
        };

        var valid = _validator.SelectValid(items, out var rejected);

        Assert.Empty(valid);
        Assert.Equal(2, rejected);
    }
}
