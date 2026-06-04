using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Core;

public class MitreTechniqueTests
{
    [Fact]
    public void MitreTechnique_Properties_AreAccessible()
    {
        var technique = new MitreTechnique
        {
            TechniqueId = "T1071.001",
            TechniqueName = "Application Layer Protocol: Web Protocols",
            Tactic = "Command and Control",
            WhyItMatters = "C2 channels frequently use web protocols."
        };

        Assert.Equal("T1071.001", technique.TechniqueId);
        Assert.Equal("Application Layer Protocol: Web Protocols", technique.TechniqueName);
        Assert.Equal("Command and Control", technique.Tactic);
        Assert.Equal("C2 channels frequently use web protocols.", technique.WhyItMatters);
    }

    [Fact]
    public void MitreTechnique_Equality_ValueBased()
    {
        var a = new MitreTechnique { TechniqueId = "T1071.001", TechniqueName = "A", Tactic = "T1", WhyItMatters = "X" };
        var b = new MitreTechnique { TechniqueId = "T1071.001", TechniqueName = "A", Tactic = "T1", WhyItMatters = "X" };
        var c = new MitreTechnique { TechniqueId = "T1071.001", TechniqueName = "B", Tactic = "T2", WhyItMatters = "Y" };

        Assert.Equal(a, b);
        Assert.NotEqual(a, c);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void Finding_DefaultMitreTechniques_IsEmpty()
    {
        var finding = new Finding
        {
            Category = "Test",
            Severity = Severity.Low,
            SourceHost = "1.2.3.4",
            Target = "test",
            TimeRangeStart = DateTime.UtcNow,
            TimeRangeEnd = DateTime.UtcNow,
            ShortDescription = "test",
            Details = "test"
        };

        Assert.NotNull(finding.MitreTechniques);
        Assert.Empty(finding.MitreTechniques);
    }

    [Fact]
    public void Finding_WithMitreTechniques_RoundTrips()
    {
        var techniques = new[]
        {
            new MitreTechnique { TechniqueId = "T1046", TechniqueName = "Network Service Discovery", Tactic = "Discovery", WhyItMatters = "Reconnaissance." }
        };

        var finding = new Finding
        {
            Category = "Test",
            Severity = Severity.Low,
            SourceHost = "1.2.3.4",
            Target = "test",
            TimeRangeStart = DateTime.UtcNow,
            TimeRangeEnd = DateTime.UtcNow,
            ShortDescription = "test",
            Details = "test",
            MitreTechniques = techniques
        };

        Assert.Single(finding.MitreTechniques);
        Assert.Equal("T1046", finding.MitreTechniques[0].TechniqueId);
    }

    [Fact]
    public void Finding_MitreTechniques_NullInit_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new Finding
        {
            Category = "Test",
            Severity = Severity.Low,
            SourceHost = "1.2.3.4",
            Target = "test",
            TimeRangeStart = DateTime.UtcNow,
            TimeRangeEnd = DateTime.UtcNow,
            ShortDescription = "test",
            Details = "test",
            MitreTechniques = null!
        });
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    public void MitreTechnique_EmptyOrWhitespaceTechniqueId_Throws(string invalidId)
    {
        Assert.Throws<ArgumentException>(() => new MitreTechnique
        {
            TechniqueId = invalidId,
            TechniqueName = "Name",
            Tactic = "Tactic",
            WhyItMatters = "Why"
        });
    }

    [Fact]
    public void Finding_WithExpression_PreservesMitreTechniques()
    {
        var technique = new MitreTechnique
        {
            TechniqueId = "T1046",
            TechniqueName = "Network Service Discovery",
            Tactic = "Discovery",
            WhyItMatters = "Reconnaissance."
        };

        var finding = new Finding
        {
            Category = "Test",
            Severity = Severity.Low,
            SourceHost = "1.2.3.4",
            Target = "test",
            TimeRangeStart = DateTime.UtcNow,
            TimeRangeEnd = DateTime.UtcNow,
            ShortDescription = "test",
            Details = "test",
            MitreTechniques = new[] { technique }
        };

        var mutated = finding with { Category = "Mutated" };

        Assert.Single(mutated.MitreTechniques);
        Assert.Equal("T1046", mutated.MitreTechniques[0].TechniqueId);
        Assert.Equal("Mutated", mutated.Category);
    }
}
