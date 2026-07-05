using VulcansTrace.Linux.Agent.Findings;
using VulcansTrace.Linux.Agent.Validation;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Validation;

public class PinnedFindingValidatorTests
{
    private readonly PinnedFindingValidator _validator = new();

    [Fact]
    public void ValidFinding_Passes()
    {
        var finding = CreateValidFinding();

        var result = _validator.Validate(finding);

        Assert.True(result.IsValid);
    }

    [Theory]
    [InlineData(nameof(PinnedFinding.Fingerprint))]
    [InlineData(nameof(PinnedFinding.Category))]
    [InlineData(nameof(PinnedFinding.Severity))]
    [InlineData(nameof(PinnedFinding.SourceHost))]
    [InlineData(nameof(PinnedFinding.Target))]
    [InlineData(nameof(PinnedFinding.ShortDescription))]
    public void RequiredField_Empty_Fails(string propertyName)
    {
        var finding = CreateValidFinding();
        finding = propertyName switch
        {
            nameof(PinnedFinding.Fingerprint) => finding with { Fingerprint = "" },
            nameof(PinnedFinding.Category) => finding with { Category = "" },
            nameof(PinnedFinding.Severity) => finding with { Severity = "" },
            nameof(PinnedFinding.SourceHost) => finding with { SourceHost = "" },
            nameof(PinnedFinding.Target) => finding with { Target = "" },
            nameof(PinnedFinding.ShortDescription) => finding with { ShortDescription = "" },
            _ => finding
        };

        var result = _validator.Validate(finding);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.PropertyName == propertyName);
    }

    [Fact]
    public void Notes_MayBeEmpty()
    {
        var finding = CreateValidFinding() with { Notes = "" };

        var result = _validator.Validate(finding);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void PinnedAtUtc_NonUtc_Fails()
    {
        var finding = CreateValidFinding() with { PinnedAtUtc = DateTime.Now };

        var result = _validator.Validate(finding);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.PropertyName == nameof(PinnedFinding.PinnedAtUtc));
    }

    [Fact]
    public void Fingerprint_TooLong_Fails()
    {
        var finding = CreateValidFinding() with { Fingerprint = new string('a', 513) };

        var result = _validator.Validate(finding);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Notes_TooLong_Fails()
    {
        var finding = CreateValidFinding() with { Notes = new string('a', 4001) };

        var result = _validator.Validate(finding);

        Assert.False(result.IsValid);
    }

    private static PinnedFinding CreateValidFinding()
    {
        return new PinnedFinding
        {
            Fingerprint = "fp-valid",
            RuleId = "FW-001",
            Category = "PortScan",
            Severity = "High",
            SourceHost = "192.168.1.1",
            Target = "10.0.0.1",
            ShortDescription = "Test finding",
            Notes = "note",
            PinnedAtUtc = DateTime.UtcNow
        };
    }
}
