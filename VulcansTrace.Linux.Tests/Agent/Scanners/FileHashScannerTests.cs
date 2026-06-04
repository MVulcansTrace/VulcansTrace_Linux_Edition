using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Core.Security;

namespace VulcansTrace.Linux.Tests.Agent.Scanners;

public class FileHashScannerTests
{
    [Fact]
    public void ParseHashLine_ValidLine_ReturnsEntry()
    {
        var line = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899  /tmp/test.txt";

        var result = FileHashScanner.ParseHashLine(line);

        Assert.NotNull(result);
        Assert.Equal("/tmp/test.txt", result.Path);
        Assert.Equal("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", result.Hash);
        Assert.Equal("SHA-256", result.Algorithm);
    }

    [Fact]
    public void ParseHashLine_InvalidLine_ReturnsNull()
    {
        Assert.Null(FileHashScanner.ParseHashLine(""));
        Assert.Null(FileHashScanner.ParseHashLine("short  /tmp/test.txt"));
        Assert.Null(FileHashScanner.ParseHashLine("no hash here"));
    }

    [Fact]
    public void ParseHashLine_UppercaseHash_NormalizesToLowercase()
    {
        var line = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899  /tmp/test.txt";

        var result = FileHashScanner.ParseHashLine(line);

        Assert.NotNull(result);
        Assert.Equal("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", result.Hash);
    }

    [Fact]
    public void ParseHashLine_Md5Line_ReturnsEntry()
    {
        var line = "d41d8cd98f00b204e9800998ecf8427e  /tmp/test.txt";

        var result = FileHashScanner.ParseHashLine(line, 32, "MD5");

        Assert.NotNull(result);
        Assert.Equal("/tmp/test.txt", result.Path);
        Assert.Equal("d41d8cd98f00b204e9800998ecf8427e", result.Hash);
        Assert.Equal("MD5", result.Algorithm);
    }

    [Fact]
    public void ParseHashLine_Sha1Line_ReturnsEntry()
    {
        var line = "da39a3ee5e6b4b0d3255bfef95601890afd80709  /tmp/test.txt";

        var result = FileHashScanner.ParseHashLine(line, 40, "SHA-1");

        Assert.NotNull(result);
        Assert.Equal("/tmp/test.txt", result.Path);
        Assert.Equal("da39a3ee5e6b4b0d3255bfef95601890afd80709", result.Hash);
        Assert.Equal("SHA-1", result.Algorithm);
    }

    [Fact]
    public void Constructor_DefaultValues_AreSet()
    {
        var scanner = new FileHashScanner();
        Assert.Equal("FileHash", scanner.Name);
    }

    [Fact]
    public async Task ScanAsync_WithStoreAndNoHashIocs_SkipsFilesystemHashing()
    {
        var scanner = new FileHashScanner(new InMemoryThreatIntelStore());
        var builder = new ScanDataBuilder();

        await scanner.ScanAsync(builder, CancellationToken.None);

        var data = builder.Build();
        Assert.Empty(data.FileHashes);
        var capability = Assert.Single(data.Capabilities);
        Assert.Equal("file-hash", capability.SourceName);
        Assert.Equal(CapabilityStatus.Unknown, capability.Status);
        Assert.Contains("Skipped", capability.Detail);
    }
}
