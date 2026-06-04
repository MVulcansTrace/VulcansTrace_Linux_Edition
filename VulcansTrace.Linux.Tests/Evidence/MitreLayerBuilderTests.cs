using System.Text.Json;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Evidence;
using Xunit;

namespace VulcansTrace.Linux.Tests.Evidence;

public class MitreLayerBuilderTests
{
    private readonly MitreLayerBuilder _builder = new();

    [Fact]
    public void BuildLayer_EmptyFindings_ReturnsValidLayer()
    {
        var json = _builder.BuildLayer(Array.Empty<Finding>());

        Assert.NotNull(json);
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.StartsWith("VulcansTrace Coverage", root.GetProperty("name").GetString());
        Assert.Equal("enterprise-attack", root.GetProperty("domain").GetString());
        Assert.Empty(root.GetProperty("techniques").EnumerateArray());
    }

    [Fact]
    public void BuildLayer_SingleFinding_MapsTechnique()
    {
        var findings = new[]
        {
            new Finding
            {
                Category = "PortScan",
                Severity = Severity.Medium,
                SourceHost = "10.0.0.1",
                Target = "multiple ports",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Port scan detected",
                Details = "Detected 5 ports.",
                MitreTechniques = new[]
                {
                    new MitreTechnique { TechniqueId = "T1046", TechniqueName = "Network Service Discovery", Tactic = "Discovery", WhyItMatters = "Reconnaissance." }
                }
            }
        };

        var json = _builder.BuildLayer(findings);
        var doc = JsonDocument.Parse(json);
        var techniques = doc.RootElement.GetProperty("techniques").EnumerateArray().ToList();

        Assert.Single(techniques);
        Assert.Equal("T1046", techniques[0].GetProperty("techniqueID").GetString());
        Assert.Equal(1, techniques[0].GetProperty("score").GetInt32());
        Assert.True(techniques[0].GetProperty("enabled").GetBoolean());
    }

    [Fact]
    public void BuildLayer_MultipleFindings_SameTechnique_AggregatesScore()
    {
        var findings = Enumerable.Range(0, 5).Select(_ => new Finding
        {
            Category = "PortScan",
            Severity = Severity.Medium,
            SourceHost = "10.0.0.1",
            Target = "multiple ports",
            TimeRangeStart = DateTime.UtcNow,
            TimeRangeEnd = DateTime.UtcNow,
            ShortDescription = "Port scan detected",
            Details = "Detected 5 ports.",
            MitreTechniques = new[]
            {
                new MitreTechnique { TechniqueId = "T1046", TechniqueName = "Network Service Discovery", Tactic = "Discovery", WhyItMatters = "Reconnaissance." }
            }
        }).ToList();

        var json = _builder.BuildLayer(findings);
        var doc = JsonDocument.Parse(json);
        var techniques = doc.RootElement.GetProperty("techniques").EnumerateArray().ToList();

        Assert.Single(techniques);
        Assert.Equal(5, techniques[0].GetProperty("score").GetInt32());
    }

    [Fact]
    public void BuildLayer_MultipleTechniques_Deduplicates()
    {
        var findings = new[]
        {
            new Finding
            {
                Category = "C2Channel",
                Severity = Severity.High,
                SourceHost = "10.0.0.1",
                Target = "8.8.8.8:443",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "C2 detected",
                Details = "Details.",
                MitreTechniques = new[]
                {
                    new MitreTechnique { TechniqueId = "T1071.001", TechniqueName = "Web Protocols", Tactic = "Command and Control", WhyItMatters = "C2." },
                    new MitreTechnique { TechniqueId = "T1071", TechniqueName = "Application Layer Protocol", Tactic = "Command and Control", WhyItMatters = "C2." }
                }
            }
        };

        var json = _builder.BuildLayer(findings);
        var doc = JsonDocument.Parse(json);
        var techniques = doc.RootElement.GetProperty("techniques").EnumerateArray().ToList();

        Assert.Equal(2, techniques.Count);
        Assert.Contains(techniques, t => t.GetProperty("techniqueID").GetString() == "T1071.001");
        Assert.Contains(techniques, t => t.GetProperty("techniqueID").GetString() == "T1071");
    }

    [Fact]
    public void BuildLayer_ContainsGradient()
    {
        var json = _builder.BuildLayer(Array.Empty<Finding>());
        var doc = JsonDocument.Parse(json);
        var gradient = doc.RootElement.GetProperty("gradient");

        Assert.Equal(0, gradient.GetProperty("minValue").GetInt32());
        Assert.Equal(10, gradient.GetProperty("maxValue").GetInt32());
        var colors = gradient.GetProperty("colors").EnumerateArray().Select(c => c.GetString()).ToList();
        Assert.Equal(2, colors.Count);
    }

    [Fact]
    public void BuildLayer_ContainsVersions()
    {
        var json = _builder.BuildLayer(Array.Empty<Finding>());
        var doc = JsonDocument.Parse(json);
        var versions = doc.RootElement.GetProperty("versions");

        Assert.NotNull(versions.GetProperty("attack").GetString());
        Assert.NotNull(versions.GetProperty("navigator").GetString());
        Assert.NotNull(versions.GetProperty("layer").GetString());
    }

    [Fact]
    public void BuildLayer_CustomName_IsUsed()
    {
        var json = _builder.BuildLayer(Array.Empty<Finding>(), "Custom Layer Name");
        var doc = JsonDocument.Parse(json);

        Assert.Equal("Custom Layer Name", doc.RootElement.GetProperty("name").GetString());
    }

    [Fact]
    public void BuildCoverageLayer_IncludesCoverageTechniquesWithoutFindings()
    {
        var coverage = new[]
        {
            new MitreCoverageSource
            {
                SourceId = "C2ChannelDetector",
                SourceName = "C2 channel detector",
                SourceType = "Detector",
                MitreTechniques = new[]
                {
                    new MitreTechnique { TechniqueId = "T1071.001", TechniqueName = "Application Layer Protocol: Web Protocols", Tactic = "Command and Control", WhyItMatters = "C2 coverage." }
                }
            }
        };

        var json = _builder.BuildCoverageLayer(coverage, Array.Empty<Finding>());
        var doc = JsonDocument.Parse(json);
        var techniques = doc.RootElement.GetProperty("techniques").EnumerateArray().ToList();

        Assert.Single(techniques);
        Assert.Equal("T1071.001", techniques[0].GetProperty("techniqueID").GetString());
        Assert.Equal("command-and-control", techniques[0].GetProperty("tactic").GetString());
        Assert.Equal(0, techniques[0].GetProperty("score").GetInt32());
        Assert.Contains("Covered by Detector: C2ChannelDetector", techniques[0].GetProperty("comment").GetString());
    }

    [Fact]
    public void BuildCoverageLayer_ObservedFindingsScoreCoveredTechnique()
    {
        var coverage = new[]
        {
            new MitreCoverageSource
            {
                SourceId = "PORT-001",
                SourceName = "SSH exposure",
                SourceType = "Rule",
                MitreTechniques = new[]
                {
                    new MitreTechnique { TechniqueId = "T1021", TechniqueName = "Remote Services", Tactic = "Lateral Movement", WhyItMatters = "Remote service coverage." }
                }
            }
        };

        var findings = new[]
        {
            new Finding
            {
                RuleId = "PORT-001",
                Category = "Ports",
                Severity = Severity.High,
                SourceHost = "localhost",
                Target = "22",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "SSH exposed",
                Details = "SSH is reachable.",
                MitreTechniques = coverage[0].MitreTechniques
            }
        };

        var json = _builder.BuildCoverageLayer(coverage, findings);
        var doc = JsonDocument.Parse(json);
        var technique = doc.RootElement.GetProperty("techniques").EnumerateArray().Single();

        Assert.Equal("T1021", technique.GetProperty("techniqueID").GetString());
        Assert.Equal("lateral-movement", technique.GetProperty("tactic").GetString());
        Assert.Equal(1, technique.GetProperty("score").GetInt32());
        Assert.Contains("Observed Finding", technique.GetProperty("metadata").EnumerateArray().Select(m => m.GetProperty("name").GetString()));
    }

    [Fact]
    public void BuildCoverageLayer_SameTechniqueDifferentTactics_ProducesSeparateCells()
    {
        var coverage = new[]
        {
            new MitreCoverageSource
            {
                SourceId = "A",
                SourceName = "Privilege escalation coverage",
                SourceType = "Rule",
                MitreTechniques = new[]
                {
                    new MitreTechnique { TechniqueId = "T1053", TechniqueName = "Scheduled Task/Job", Tactic = "Privilege Escalation", WhyItMatters = "Privilege escalation." }
                }
            },
            new MitreCoverageSource
            {
                SourceId = "B",
                SourceName = "Persistence coverage",
                SourceType = "Rule",
                MitreTechniques = new[]
                {
                    new MitreTechnique { TechniqueId = "T1053", TechniqueName = "Scheduled Task/Job", Tactic = "Persistence", WhyItMatters = "Persistence." }
                }
            }
        };

        var json = _builder.BuildCoverageLayer(coverage, Array.Empty<Finding>());
        var doc = JsonDocument.Parse(json);
        var techniques = doc.RootElement.GetProperty("techniques").EnumerateArray().ToList();

        Assert.Equal(2, techniques.Count);
        Assert.Contains(techniques, t => t.GetProperty("tactic").GetString() == "persistence");
        Assert.Contains(techniques, t => t.GetProperty("tactic").GetString() == "privilege-escalation");
    }

    [Fact]
    public void BuildLayer_DivergentNames_ProducesValidLayerWithoutCrash()
    {
        // Same TechniqueId but different names/tactics — builder should handle deterministically
        var findings = new[]
        {
            new Finding
            {
                Category = "A",
                Severity = Severity.Low,
                SourceHost = "1.1.1.1",
                Target = "t",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "s1",
                Details = "d",
                MitreTechniques = new[] { new MitreTechnique { TechniqueId = "T1046", TechniqueName = "Network Service Discovery", Tactic = "Discovery", WhyItMatters = "W" } }
            },
            new Finding
            {
                Category = "B",
                Severity = Severity.Low,
                SourceHost = "1.1.1.1",
                Target = "t",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "s2",
                Details = "d",
                MitreTechniques = new[] { new MitreTechnique { TechniqueId = "T1046", TechniqueName = "Network Service Discovery", Tactic = "Discovery", WhyItMatters = "W" } }
            },
            new Finding
            {
                Category = "C",
                Severity = Severity.Low,
                SourceHost = "1.1.1.1",
                Target = "t",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "s3",
                Details = "d",
                MitreTechniques = new[] { new MitreTechnique { TechniqueId = "T1046", TechniqueName = "Other Name", Tactic = "Other Tactic", WhyItMatters = "W" } }
            }
        };

        var json = _builder.BuildLayer(findings);
        var doc = JsonDocument.Parse(json);
        var techniques = doc.RootElement.GetProperty("techniques").EnumerateArray().ToList();

        Assert.Equal(2, techniques.Count);
        Assert.Contains(techniques, t =>
            t.GetProperty("techniqueID").GetString() == "T1046" &&
            t.GetProperty("tactic").GetString() == "discovery" &&
            t.GetProperty("score").GetInt32() == 2);
        Assert.Contains(techniques, t =>
            t.GetProperty("techniqueID").GetString() == "T1046" &&
            t.GetProperty("tactic").GetString() == "other-tactic" &&
            t.GetProperty("score").GetInt32() == 1);
    }
}
