using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Tests.Agent.ThreatIntel;

public class StixParserTests
{
    [Fact]
    public void Parse_EmptyObject_ReturnsEmptyResult()
    {
        var result = StixParser.Parse("{}");
        Assert.Equal(0, result.ImportedCount);
    }

    [Fact]
    public void Parse_InvalidJson_ReturnsWarning()
    {
        var result = StixParser.Parse("not json");
        Assert.Equal(0, result.ImportedCount);
        Assert.NotEmpty(result.Warnings);
    }

    [Fact]
    public void Parse_BundleWithIpv4Addr_ExtractsIoc()
    {
        var json = @"{
            ""type"": ""bundle"",
            ""objects"": [
                { ""type"": ""ipv4-addr"", ""value"": ""192.168.1.1"" }
            ]
        }";

        var result = StixParser.Parse(json);
        Assert.Equal(1, result.ImportedCount);
        Assert.Equal(IocType.IPv4, result.Entries[0].Type);
        Assert.Equal("192.168.1.1", result.Entries[0].Value);
    }

    [Fact]
    public void Parse_BundleWithIndicatorPattern_ExtractsIoc()
    {
        var json = @"{
            ""type"": ""bundle"",
            ""objects"": [
                {
                    ""type"": ""indicator"",
                    ""pattern"": ""[ipv4-addr:value = '10.0.0.5']"",
                    ""confidence"": 85
                }
            ]
        }";

        var result = StixParser.Parse(json);
        Assert.Equal(1, result.ImportedCount);
        Assert.Equal(IocType.IPv4, result.Entries[0].Type);
        Assert.Equal("10.0.0.5", result.Entries[0].Value);
        Assert.Equal(85, result.Entries[0].Confidence);
    }

    [Fact]
    public void Parse_BundleWithPortPattern_ExtractsPortIoc()
    {
        var json = @"{
            ""type"": ""bundle"",
            ""objects"": [
                {
                    ""type"": ""indicator"",
                    ""pattern"": ""[network-traffic:dst_port = 4444]""
                }
            ]
        }";

        var result = StixParser.Parse(json);
        Assert.Equal(1, result.ImportedCount);
        Assert.Equal(IocType.Port, result.Entries[0].Type);
        Assert.Equal("4444", result.Entries[0].Value);
    }

    [Fact]
    public void Parse_BundleWithCompoundIndicatorPattern_ExtractsAllSupportedIocs()
    {
        var json = @"{
            ""type"": ""bundle"",
            ""objects"": [
                {
                    ""type"": ""indicator"",
                    ""pattern"": ""[ipv4-addr:value = '10.0.0.5' AND network-traffic:dst_port = 4444]"",
                    ""confidence"": 85
                }
            ]
        }";

        var result = StixParser.Parse(json);

        Assert.Equal(2, result.ImportedCount);
        Assert.Equal(0, result.SkippedCount);
        Assert.Contains(result.Entries, e => e.Type == IocType.IPv4 && e.Value == "10.0.0.5");
        Assert.Contains(result.Entries, e => e.Type == IocType.Port && e.Value == "4444");
    }

    [Fact]
    public void Parse_BundleWithFileHash_ExtractsHashIoc()
    {
        var json = @"{
            ""type"": ""bundle"",
            ""objects"": [
                {
                    ""type"": ""file"",
                    ""hashes"": {
                        ""SHA-256"": ""AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899""
                    }
                }
            ]
        }";

        var result = StixParser.Parse(json);
        Assert.Equal(1, result.ImportedCount);
        Assert.Equal(IocType.FileHash, result.Entries[0].Type);
        Assert.Equal("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", result.Entries[0].Value);
    }

    [Fact]
    public void Parse_UnparseablePattern_SkipsWithWarning()
    {
        var json = @"{
            ""type"": ""bundle"",
            ""objects"": [
                {
                    ""type"": ""indicator"",
                    ""pattern"": ""complex pattern OR another""
                }
            ]
        }";

        var result = StixParser.Parse(json);
        Assert.Equal(0, result.ImportedCount);
        Assert.Equal(1, result.SkippedCount);
        Assert.NotEmpty(result.Warnings);
    }
}
