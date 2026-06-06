using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Tests.Agent.ThreatIntel;

public class MispParserTests
{
    [Fact]
    public void Parse_EmptyObject_ReturnsEmptyResult()
    {
        var result = MispParser.Parse("{}");
        Assert.Equal(0, result.ImportedCount);
    }

    [Fact]
    public void Parse_InvalidJson_ReturnsWarning()
    {
        var result = MispParser.Parse("not json");
        Assert.Equal(0, result.ImportedCount);
        Assert.NotEmpty(result.Warnings);
    }

    [Fact]
    public void Parse_EventWithIpAttribute_ExtractsIoc()
    {
        var json = @"{
            ""Event"": {
                ""Attribute"": [
                    { ""type"": ""ip-dst"", ""value"": ""192.168.1.1"" }
                ]
            }
        }";

        var result = MispParser.Parse(json);
        Assert.Equal(1, result.ImportedCount);
        Assert.Equal(IocType.IPv4, result.Entries[0].Type);
        Assert.Equal("192.168.1.1", result.Entries[0].Value);
    }

    [Fact]
    public void Parse_EventWithPortAttribute_ExtractsPortIoc()
    {
        var json = @"{
            ""Event"": {
                ""Attribute"": [
                    { ""type"": ""port"", ""value"": ""4444"" }
                ]
            }
        }";

        var result = MispParser.Parse(json);
        Assert.Equal(1, result.ImportedCount);
        Assert.Equal(IocType.Port, result.Entries[0].Type);
        Assert.Equal("4444", result.Entries[0].Value);
    }

    [Fact]
    public void Parse_EventWithHashAttribute_ExtractsHashIoc()
    {
        var json = @"{
            ""Event"": {
                ""Attribute"": [
                    { ""type"": ""sha256"", ""value"": ""AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"" }
                ]
            }
        }";

        var result = MispParser.Parse(json);
        Assert.Equal(1, result.ImportedCount);
        Assert.Equal(IocType.FileHash, result.Entries[0].Type);
        Assert.Equal("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", result.Entries[0].Value);
    }

    [Fact]
    public void Parse_EventWithCompositeValue_ExtractsSecondPart()
    {
        var json = @"{
            ""Event"": {
                ""Attribute"": [
                    { ""type"": ""filename|sha256"", ""value"": ""malware.exe|AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"" }
                ]
            }
        }";

        var result = MispParser.Parse(json);
        Assert.Equal(1, result.ImportedCount);
        Assert.Equal(IocType.FileHash, result.Entries[0].Type);
    }

    [Fact]
    public void Parse_EventWithObjectAttributes_ExtractsIoc()
    {
        var json = @"{
            ""Event"": {
                ""Object"": [
                    {
                        ""Attribute"": [
                            { ""type"": ""domain"", ""value"": ""evil.example.com"" }
                        ]
                    }
                ]
            }
        }";

        var result = MispParser.Parse(json);
        Assert.Equal(1, result.ImportedCount);
        Assert.Equal(IocType.Domain, result.Entries[0].Type);
    }

    [Fact]
    public void Parse_UnsupportedType_SkipsWithWarning()
    {
        var json = @"{
            ""Event"": {
                ""Attribute"": [
                    { ""type"": ""mutex"", ""value"": "" evil_mutex"" }
                ]
            }
        }";

        var result = MispParser.Parse(json);
        Assert.Equal(0, result.ImportedCount);
        Assert.Equal(1, result.SkippedCount);
    }

    [Fact]
    public void Parse_IpDstPortComposite_CreatesTwoIocs()
    {
        var json = @"{
            ""Event"": {
                ""Attribute"": [
                    { ""type"": ""ip-dst|port"", ""value"": ""1.2.3.4|4444"" }
                ]
            }
        }";

        var result = MispParser.Parse(json);
        Assert.Equal(2, result.ImportedCount);
        Assert.Contains(result.Entries, e => e.Type == IocType.IPv4 && e.Value == "1.2.3.4");
        Assert.Contains(result.Entries, e => e.Type == IocType.Port && e.Value == "4444");
    }

    [Fact]
    public void Parse_ThreatLevelId_MapsToConfidence()
    {
        var json = @"{
            ""Event"": {
                ""threat_level_id"": ""1"",
                ""Attribute"": [
                    { ""type"": ""ip-dst"", ""value"": ""10.0.0.1"" }
                ]
            }
        }";

        var result = MispParser.Parse(json);
        Assert.Equal(1, result.ImportedCount);
        Assert.Equal(80, result.Entries[0].ThreatScore);
    }

    [Fact]
    public void Parse_FilenameSha256Composite_SetsAlgorithm()
    {
        var json = @"{
            ""Event"": {
                ""Attribute"": [
                    { ""type"": ""filename|sha256"", ""value"": ""malware.exe|AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"" }
                ]
            }
        }";

        var result = MispParser.Parse(json);
        Assert.Equal(1, result.ImportedCount);
        Assert.Equal(IocType.FileHash, result.Entries[0].Type);
        Assert.Equal("SHA-256", result.Entries[0].Algorithm);
    }
}
