using FluentValidation.TestHelper;
using VulcansTrace.Linux.Agent.Validation;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Tests.Agent.Validation;

public sealed class IocEntryValidatorTests
{
    private readonly IocEntryValidator _validator = new();

    [Fact]
    public void ValidIPv4_Passes()
    {
        var entry = new IocEntry
        {
            Type = IocType.IPv4,
            Value = "192.168.1.1",
            ThreatScore = 80,
            Source = "STIX",
            ImportedAt = DateTime.UtcNow
        };

        var result = _validator.TestValidate(entry);
        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void InvalidIPv4_Fails()
    {
        var entry = new IocEntry
        {
            Type = IocType.IPv4,
            Value = "not-an-ip",
            ThreatScore = 80,
            Source = "STIX",
            ImportedAt = DateTime.UtcNow
        };

        var result = _validator.TestValidate(entry);
        result.ShouldHaveValidationErrorFor(x => x.Value);
    }

    [Fact]
    public void ValidPort_Passes()
    {
        var entry = new IocEntry
        {
            Type = IocType.Port,
            Value = "443",
            ThreatScore = 50,
            Source = "MISP",
            ImportedAt = DateTime.UtcNow
        };

        var result = _validator.TestValidate(entry);
        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void OutOfRangePort_Fails()
    {
        var entry = new IocEntry
        {
            Type = IocType.Port,
            Value = "99999",
            ThreatScore = 50,
            Source = "MISP",
            ImportedAt = DateTime.UtcNow
        };

        var result = _validator.TestValidate(entry);
        result.ShouldHaveValidationErrorFor(x => x.Value);
    }

    [Fact]
    public void ValidFileHash_Passes()
    {
        var entry = new IocEntry
        {
            Type = IocType.FileHash,
            Value = "abcdef0123456789",
            ThreatScore = 90,
            Source = "STIX",
            ImportedAt = DateTime.UtcNow
        };

        var result = _validator.TestValidate(entry);
        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void NonHexFileHash_Fails()
    {
        var entry = new IocEntry
        {
            Type = IocType.FileHash,
            Value = "not-hex!",
            ThreatScore = 90,
            Source = "STIX",
            ImportedAt = DateTime.UtcNow
        };

        var result = _validator.TestValidate(entry);
        result.ShouldHaveValidationErrorFor(x => x.Value);
    }

    [Fact]
    public void ThreatScoreOutOfRange_Fails()
    {
        var entry = new IocEntry
        {
            Type = IocType.Domain,
            Value = "example.com",
            ThreatScore = 150,
            Source = "STIX",
            ImportedAt = DateTime.UtcNow
        };

        var result = _validator.TestValidate(entry);
        result.ShouldHaveValidationErrorFor(x => x.ThreatScore);
    }

    [Fact]
    public void EmptySource_Fails()
    {
        var entry = new IocEntry
        {
            Type = IocType.Domain,
            Value = "example.com",
            ThreatScore = 50,
            Source = "",
            ImportedAt = DateTime.UtcNow
        };

        var result = _validator.TestValidate(entry);
        result.ShouldHaveValidationErrorFor(x => x.Source);
    }
}
