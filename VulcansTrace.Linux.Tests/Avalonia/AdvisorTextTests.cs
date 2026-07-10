using System;
using System.Linq;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Avalonia.ViewModels;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class AdvisorTextTests
{
    private const string PerLinePhrase = "risky or unclassified command(s) lack explicit rollback guidance";

    [Fact]
    public void ForBlockedRemediation_Null_ReturnsEmpty()
    {
        var (tip, detail) = AdvisorText.ForBlockedRemediation(null);

        Assert.Equal(string.Empty, tip);
        Assert.Empty(detail);
    }

    [Fact]
    public void ForBlockedRemediation_Valid_ReturnsEmpty()
    {
        var (tip, detail) = AdvisorText.ForBlockedRemediation(ValidationResult.Valid());

        Assert.Equal(string.Empty, tip);
        Assert.Empty(detail);
    }

    [Fact]
    public void ForBlockedRemediation_SingleBlockedSection_TipIsBoundedAndOmitsPerLineText()
    {
        var errors = new[] { $"[SRV-004] Some summary: 2 {PerLinePhrase}." };
        var (tip, detail) = AdvisorText.ForBlockedRemediation(ValidationResult.Invalid(errors));

        Assert.Contains("1 section(s)", tip);
        Assert.DoesNotContain("SRV-004", tip);
        Assert.DoesNotContain(PerLinePhrase, tip);
        Assert.Single(detail);
        Assert.Equal(errors[0], detail[0]);
    }

    [Fact]
    public void ForBlockedRemediation_ManyBlockedSections_TipStaysShortAndDetailIsPreserved()
    {
        // Mirrors the report: SRV-004/003/005, FSYS-002/001, KERN-003/005/007.
        var ruleIds = new[] { "SRV-004", "SRV-003", "SRV-005", "FSYS-002", "FSYS-001", "KERN-003", "KERN-005", "KERN-007" };
        var errors = ruleIds.Select(id => $"[{id}] summary: 3 {PerLinePhrase}.").ToArray();

        var (tip, detail) = AdvisorText.ForBlockedRemediation(ValidationResult.Invalid(errors));

        Assert.Contains($"{ruleIds.Length} section(s)", tip);
        Assert.True(tip.Length < 200, $"Tip should stay short, was {tip.Length} chars: {tip}");
        foreach (var id in ruleIds)
            Assert.DoesNotContain(id, tip);
        Assert.DoesNotContain(PerLinePhrase, tip);

        // No information lost: the per-section detail is preserved verbatim and in order.
        Assert.Equal(errors, detail);
    }

    [Fact]
    public void FormatBlockedRemediationTranscript_Empty_ReturnsNull()
    {
        Assert.Null(AdvisorText.FormatBlockedRemediationTranscript(Array.Empty<string>()));
        Assert.Null(AdvisorText.FormatBlockedRemediationTranscript(null!));
    }

    [Fact]
    public void FormatBlockedRemediationTranscript_WithLines_IncludesCountAndBullets()
    {
        var errors = new[] { "[SRV-004] a", "[FSYS-002] b" };

        var text = AdvisorText.FormatBlockedRemediationTranscript(errors);

        Assert.NotNull(text);
        Assert.Contains("2 section(s) blocked", text);
        Assert.Contains("• [SRV-004] a", text);
        Assert.Contains("• [FSYS-002] b", text);
    }

    [Fact]
    public void FormatBlockedRemediationTranscript_OverCap_AddsOverflowSuffix()
    {
        var errors = Enumerable.Range(0, AdvisorText.MaxInlineDetailLines + 7)
            .Select(i => $"[R-{i:000}] summary").ToArray();

        var text = AdvisorText.FormatBlockedRemediationTranscript(errors)!;

        Assert.Contains($"{errors.Length} section(s) blocked", text);
        Assert.Contains("… and 7 more.", text);
        // The first inline line is present, a line beyond the cap is not inlined.
        Assert.Contains("• [R-000] summary", text);
        Assert.DoesNotContain($"[R-{AdvisorText.MaxInlineDetailLines:000}] summary", text);
    }
}
