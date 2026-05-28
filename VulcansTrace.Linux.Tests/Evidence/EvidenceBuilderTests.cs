using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Security;
using VulcansTrace.Linux.Evidence;
using VulcansTrace.Linux.Evidence.Formatters;
using Xunit;

namespace VulcansTrace.Linux.Tests.Evidence;

public class EvidenceBuilderTests
{
    private static EvidenceBuilder CreateBuilder() =>
        new(new IntegrityHasher(), new CsvFormatter(), new MarkdownFormatter(), new HtmlFormatter(), new JsonFormatter(), new StixFormatter());

    private static readonly byte[] DefaultKey = Encoding.UTF8.GetBytes("0123456789abcdef0123456789abcdef");

    private static AnalysisResult SingleFindingResult() => new()
    {
        TotalLines = 2,
        ParsedLines = 2,
        ParseErrorCount = 0,
        Findings =
        [
            new Finding
            {
                Category = "PortScan",
                Severity = Severity.High,
                SourceHost = "192.168.1.10",
                Target = "multiple hosts/ports",
                TimeRangeStart = DateTime.UnixEpoch,
                TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                ShortDescription = "Port scan detected",
                Details = "Detected 12 distinct destinations."
            }
        ],
        Warnings = ["Sample warning"]
    };

    private static string DefaultLog() =>
        "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

    [Fact]
    public void Build_CreatesManifestAndValidHmac()
    {
        var builder = CreateBuilder();
        var result = SingleFindingResult();
        var logText = DefaultLog();
        var signingKey = DefaultKey;
        var hasher = new IntegrityHasher();
        var timestamp = new DateTime(2024, 1, 2, 3, 4, 5, DateTimeKind.Utc);

        var zipBytes = builder.Build(result, logText, signingKey, timestamp);

        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        var names = zip.Entries.Select(e => e.FullName).ToArray();
        Assert.Contains("findings.csv", names);
        Assert.Contains("log.txt", names);
        Assert.Contains("report.html", names);
        Assert.Contains("summary.md", names);
        Assert.Contains("manifest.json", names);
        Assert.Contains("manifest.hmac", names);
        Assert.Contains("findings.json", names);
        Assert.Contains("findings.stix.json", names);

        var manifestEntry = zip.GetEntry("manifest.json");
        Assert.NotNull(manifestEntry);
        byte[] manifestBytes;
        using (var entryStream = manifestEntry!.Open())
        using (var manifestStream = new MemoryStream())
        {
            entryStream.CopyTo(manifestStream);
            manifestBytes = manifestStream.ToArray();
        }

        using var doc = JsonDocument.Parse(manifestBytes);
        var files = doc.RootElement.GetProperty("files");
        Assert.Equal(6, files.GetArrayLength());
        var fileNames = files.EnumerateArray()
            .Select(e => e.GetProperty("file").GetString())
            .ToArray();
        Assert.Contains("findings.csv", fileNames);
        Assert.Contains("log.txt", fileNames);
        Assert.Contains("report.html", fileNames);
        Assert.Contains("summary.md", fileNames);
        Assert.Contains("findings.json", fileNames);
        Assert.Contains("findings.stix.json", fileNames);

        var warnings = doc.RootElement.GetProperty("warnings");
        Assert.Single(warnings.EnumerateArray());
        Assert.Equal("Sample warning", warnings[0].GetString());

        var hmacEntry = zip.GetEntry("manifest.hmac");
        Assert.NotNull(hmacEntry);
        string hmacText;
        using (var entryStream = hmacEntry!.Open())
        using (var reader = new StreamReader(entryStream, Encoding.UTF8))
        {
            hmacText = reader.ReadToEnd();
        }

        var expectedHmac = Convert.ToHexString(hasher.ComputeHmacSha256(manifestBytes, signingKey)).ToLowerInvariant();
        Assert.Equal(expectedHmac, hmacText);
    }

    [Fact]
    public async Task BuildAsync_ProducesValidZip()
    {
        var builder = CreateBuilder();
        var result = SingleFindingResult();

        var zipBytes = await builder.BuildAsync(result, DefaultLog(), DefaultKey, DateTime.UtcNow);

        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
        Assert.Equal(8, zip.Entries.Count);
    }

    [Fact]
    public void Build_WithCancellation_ThrowsOperationCanceledException()
    {
        var builder = CreateBuilder();
        var result = SingleFindingResult();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.Throws<OperationCanceledException>(() =>
            builder.Build(result, DefaultLog(), DefaultKey, DateTime.UtcNow, cts.Token));
    }

    [Fact]
    public void Build_TimestampBefore1980_ClampsToZipMin()
    {
        var builder = CreateBuilder();
        var result = new AnalysisResult
        {
            TimeRangeStart = DateTime.MinValue,
            TimeRangeEnd = DateTime.MinValue,
            Findings = Array.Empty<Finding>()
        };

        var zipBytes = builder.Build(result, "", DefaultKey, new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc));

        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
        // Should not throw — timestamp gets clamped to 1980-01-01
        var entry = zip.GetEntry("manifest.json");
        Assert.NotNull(entry);
        // Verify clamped to 1980-01-01 regardless of timezone
        Assert.Equal(1980, entry.LastWriteTime.Year);
        Assert.Equal(1, entry.LastWriteTime.Month);
        Assert.Equal(1, entry.LastWriteTime.Day);
    }

    [Fact]
    public void Build_NoProvidedTimestamp_DefaultsToUtcNow()
    {
        var builder = CreateBuilder();
        var before = DateTime.UtcNow;
        var result = new AnalysisResult
        {
            TimeRangeStart = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            TimeRangeEnd = new DateTime(2020, 1, 2, 0, 0, 0, DateTimeKind.Utc),
            Findings = Array.Empty<Finding>()
        };

        var zipBytes = builder.Build(result, "", DefaultKey, (DateTime?)null);

        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
        var entry = zip.GetEntry("manifest.json");
        Assert.NotNull(entry);
        // When no timestamp is provided, uses DateTime.UtcNow (not result.TimeRangeEnd)
        Assert.True(entry.LastWriteTime.Year >= before.Year);
    }

    [Fact]
    public void Build_EmptyFindings_ProducesValidCsv()
    {
        var builder = CreateBuilder();
        var result = new AnalysisResult
        {
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            Findings = Array.Empty<Finding>()
        };

        var zipBytes = builder.Build(result, "log content", DefaultKey, DateTime.UtcNow);

        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
        var csvEntry = zip.GetEntry("findings.csv");
        Assert.NotNull(csvEntry);
        using var stream = csvEntry!.Open();
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var csv = reader.ReadToEnd();
        Assert.Contains("Category,Severity", csv);
        // Header present but no data rows (except the header itself)
        Assert.DoesNotContain("PortScan", csv);
    }

    [Fact]
    public void Build_CsvContainsFindingData()
    {
        var builder = CreateBuilder();
        var result = SingleFindingResult();

        var zipBytes = builder.Build(result, DefaultLog(), DefaultKey, DateTime.UtcNow);

        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
        var csvEntry = zip.GetEntry("findings.csv");
        Assert.NotNull(csvEntry);
        using var stream = csvEntry!.Open();
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var csv = reader.ReadToEnd();
        Assert.Contains("PortScan", csv);
        Assert.Contains("192.168.1.10", csv);
        Assert.Contains("High", csv);
        Assert.Contains("Port scan detected", csv);
    }

    [Fact]
    public void Build_HtmlContainsEncodedFindingData()
    {
        var builder = CreateBuilder();
        var result = SingleFindingResult();

        var zipBytes = builder.Build(result, DefaultLog(), DefaultKey, DateTime.UtcNow);

        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
        var htmlEntry = zip.GetEntry("report.html");
        Assert.NotNull(htmlEntry);
        using var stream = htmlEntry!.Open();
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var html = reader.ReadToEnd();
        Assert.Contains("PortScan", html);
        Assert.Contains("192.168.1.10", html);
        Assert.Contains("VulcansTrace Analysis Report", html);
    }

    [Fact]
    public void Build_LogTxtContainsRawLog()
    {
        var builder = CreateBuilder();
        var logText = "kernel: Jan 19 10:15:32 server SRC=192.168.1.10 PROTO=TCP";
        var result = new AnalysisResult
        {
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            Findings = Array.Empty<Finding>()
        };

        var zipBytes = builder.Build(result, logText, DefaultKey, DateTime.UtcNow);

        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
        var logEntry = zip.GetEntry("log.txt");
        Assert.NotNull(logEntry);
        using var stream = logEntry!.Open();
        using var reader = new StreamReader(stream, Encoding.UTF8);
        Assert.Equal(logText, reader.ReadToEnd());
    }

    [Fact]
    public void Build_TamperedManifest_HmacDoesNotMatch()
    {
        var builder = CreateBuilder();
        var result = SingleFindingResult();
        var logText = DefaultLog();
        var signingKey = DefaultKey;
        var hasher = new IntegrityHasher();
        var timestamp = new DateTime(2024, 6, 15, 12, 0, 0, DateTimeKind.Utc);

        // Build a valid bundle
        var zipBytes = builder.Build(result, logText, signingKey, timestamp);

        // Extract, tamper with manifest, verify HMAC no longer matches
        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        var manifestEntry = zip.GetEntry("manifest.json");
        Assert.NotNull(manifestEntry);
        byte[] manifestBytes;
        using (var entryStream = manifestEntry!.Open())
        using (var manifestStream = new MemoryStream())
        {
            entryStream.CopyTo(manifestStream);
            manifestBytes = manifestStream.ToArray();
        }

        var hmacEntry = zip.GetEntry("manifest.hmac");
        Assert.NotNull(hmacEntry);
        string originalHmac;
        using (var entryStream = hmacEntry!.Open())
        using (var reader = new StreamReader(entryStream, Encoding.UTF8))
        {
            originalHmac = reader.ReadToEnd();
        }

        // Tamper: modify the manifest by replacing a character
        var tamperedManifest = new byte[manifestBytes.Length];
        Array.Copy(manifestBytes, tamperedManifest, manifestBytes.Length);
        if (tamperedManifest.Length > 10)
        {
            tamperedManifest[10] = (byte)(tamperedManifest[10] ^ 0xFF);
        }

        // Compute HMAC of the tampered manifest
        var tamperedHmac = Convert.ToHexString(hasher.ComputeHmacSha256(tamperedManifest, signingKey)).ToLowerInvariant();

        // The tampered HMAC should NOT match the original
        Assert.NotEqual(originalHmac, tamperedHmac);

        // And the original HMAC should match the original manifest (sanity check)
        var expectedOriginalHmac = Convert.ToHexString(hasher.ComputeHmacSha256(manifestBytes, signingKey)).ToLowerInvariant();
        Assert.Equal(expectedOriginalHmac, originalHmac);
    }

    [Fact]
    public void Build_NullTimestamp_WithValidTimeRangeEnd_UsesTimeRangeEnd()
    {
        var builder = CreateBuilder();
        var result = new AnalysisResult
        {
            TimeRangeStart = DateTime.MinValue,
            TimeRangeEnd = new DateTime(2023, 5, 15, 12, 0, 0, DateTimeKind.Utc),
            Findings = Array.Empty<Finding>()
        };

        var zipBytes = builder.Build(result, "", DefaultKey, (DateTime?)null, CancellationToken.None);

        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
        var entry = zip.GetEntry("manifest.json");
        Assert.NotNull(entry);
        Assert.Equal(2023, entry.LastWriteTime.Year);
        Assert.Equal(5, entry.LastWriteTime.Month);
        Assert.Equal(15, entry.LastWriteTime.Day);
    }

    [Fact]
    public void Build_NullTimestamp_TimeRangeEndMinValue_UsesTimeRangeStart()
    {
        var builder = CreateBuilder();
        var result = new AnalysisResult
        {
            TimeRangeStart = new DateTime(2022, 8, 1, 0, 0, 0, DateTimeKind.Utc),
            TimeRangeEnd = DateTime.MinValue,
            Findings = Array.Empty<Finding>()
        };

        var zipBytes = builder.Build(result, "", DefaultKey, (DateTime?)null, CancellationToken.None);

        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
        var entry = zip.GetEntry("manifest.json");
        Assert.NotNull(entry);
        Assert.Equal(2022, entry.LastWriteTime.Year);
        Assert.Equal(8, entry.LastWriteTime.Month);
        Assert.Equal(1, entry.LastWriteTime.Day);
    }

    [Fact]
    public void Build_NullTimestamp_AllMinValue_UsesUnixEpoch()
    {
        var builder = CreateBuilder();
        var result = new AnalysisResult
        {
            TimeRangeStart = DateTime.MinValue,
            TimeRangeEnd = DateTime.MinValue,
            Findings = Array.Empty<Finding>()
        };

        var zipBytes = builder.Build(result, "", DefaultKey, (DateTime?)null, CancellationToken.None);

        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
        var entry = zip.GetEntry("manifest.json");
        Assert.NotNull(entry);
        Assert.Equal(1980, entry.LastWriteTime.Year);
        Assert.Equal(1, entry.LastWriteTime.Month);
        Assert.Equal(1, entry.LastWriteTime.Day);
    }

    [Fact]
    public void Build_NullSigningKey_ThrowsArgumentNullException()
    {
        var builder = CreateBuilder();
        var result = SingleFindingResult();

        Assert.Throws<ArgumentNullException>(() => builder.Build(result, DefaultLog(), null!));
    }

    [Fact]
    public async Task BuildAsync_NullSigningKey_ThrowsArgumentNullException()
    {
        var builder = CreateBuilder();
        var result = SingleFindingResult();

        await Assert.ThrowsAsync<ArgumentNullException>(() => builder.BuildAsync(result, DefaultLog(), null!));
    }

    [Fact]
    public void Build_TimestampAfter2107_ClampsToZipMax()
    {
        var builder = CreateBuilder();
        var result = new AnalysisResult
        {
            TimeRangeStart = DateTime.MinValue,
            TimeRangeEnd = DateTime.MinValue,
            Findings = Array.Empty<Finding>()
        };

        var zipBytes = builder.Build(result, "", DefaultKey, new DateTime(2108, 6, 1, 0, 0, 0, DateTimeKind.Utc));

        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
        var entry = zip.GetEntry("manifest.json");
        Assert.NotNull(entry);
        Assert.Equal(2107, entry.LastWriteTime.Year);
        Assert.Equal(12, entry.LastWriteTime.Month);
        Assert.Equal(31, entry.LastWriteTime.Day);
    }

    [Fact]
    public void Verify_ValidBundle_ReturnsValid()
    {
        var builder = CreateBuilder();
        var result = SingleFindingResult();
        var zipBytes = builder.Build(result, DefaultLog(), DefaultKey);

        var verification = builder.Verify(zipBytes, DefaultKey);

        Assert.True(verification.IsValid);
        Assert.Empty(verification.Issues);
    }

    [Fact]
    public void Verify_TamperedHtml_ReturnsInvalid()
    {
        var builder = CreateBuilder();
        var result = SingleFindingResult();
        var zipBytes = builder.Build(result, DefaultLog(), DefaultKey);

        // Tamper: rebuild the ZIP with modified report.html
        var tamperedZip = TamperFileInZip(zipBytes, "report.html", b =>
        {
            b[0] = (byte)(b[0] ^ 0xFF);
            return b;
        });

        var verification = builder.Verify(tamperedZip, DefaultKey);

        Assert.False(verification.IsValid);
        Assert.Single(verification.Issues, i => i.Contains("report.html") && i.Contains("hash mismatch"));
    }

    [Fact]
    public void Verify_TamperedManifest_ReturnsInvalid()
    {
        var builder = CreateBuilder();
        var result = SingleFindingResult();
        var zipBytes = builder.Build(result, DefaultLog(), DefaultKey);

        // Tamper: modify manifest.json without updating HMAC
        var tamperedZip = TamperFileInZip(zipBytes, "manifest.json", b =>
        {
            b[10] = (byte)(b[10] ^ 0xFF);
            return b;
        });

        var verification = builder.Verify(tamperedZip, DefaultKey);

        Assert.False(verification.IsValid);
        Assert.Contains("HMAC", verification.Issues[0]);
    }

    [Fact]
    public void Verify_WrongKey_ReturnsInvalid()
    {
        var builder = CreateBuilder();
        var result = SingleFindingResult();
        var zipBytes = builder.Build(result, DefaultLog(), DefaultKey);

        var wrongKey = Encoding.UTF8.GetBytes("wrong_key_wrong_key_wrong_key_wrong");
        var verification = builder.Verify(zipBytes, wrongKey);

        Assert.False(verification.IsValid);
        Assert.Contains("HMAC", verification.Issues[0]);
    }

    [Fact]
    public void Verify_MissingManifest_ReturnsInvalid()
    {
        var builder = CreateBuilder();

        // Create a bare ZIP with no manifest
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("dummy.txt");
            using var stream = entry.Open();
            stream.Write(Encoding.UTF8.GetBytes("test"));
        }

        var verification = builder.Verify(ms.ToArray(), DefaultKey);

        Assert.False(verification.IsValid);
        Assert.Contains("manifest.json not found", verification.Issues[0]);
    }

    [Fact]
    public void Build_ManifestIncludesSkippedLineCountAndParseErrors()
    {
        var builder = CreateBuilder();
        var result = new AnalysisResult
        {
            TotalLines = 10,
            ParsedLines = 8,
            SkippedLineCount = 2,
            ParseErrors = ["Failed to parse line 5"],
            Findings = Array.Empty<Finding>()
        };

        var zipBytes = builder.Build(result, "raw log", DefaultKey);

        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
        var manifestEntry = zip.GetEntry("manifest.json");
        Assert.NotNull(manifestEntry);

        using var entryStream = manifestEntry!.Open();
        using var reader = new StreamReader(entryStream, Encoding.UTF8);
        var manifestJson = reader.ReadToEnd();
        var doc = JsonDocument.Parse(manifestJson);

        Assert.Equal(2, doc.RootElement.GetProperty("skippedLineCount").GetInt32());

        var errors = doc.RootElement.GetProperty("parseErrors");
        Assert.Equal(1, errors.GetArrayLength());
        Assert.Equal("Failed to parse line 5", errors[0].GetString());
    }

    [Fact]
    public void Verify_CorruptManifestJson_ReturnsInvalid()
    {
        var builder = CreateBuilder();
        var hasher = new IntegrityHasher();

        // Build a ZIP with a correctly HMAC-signed but malformed manifest.json
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var corruptManifest = Encoding.UTF8.GetBytes("THIS IS NOT JSON {{{}");

            var manifestEntry = zip.CreateEntry("manifest.json");
            using (var stream = manifestEntry.Open())
            {
                stream.Write(corruptManifest, 0, corruptManifest.Length);
            }

            // Compute a valid HMAC over the corrupt manifest so we pass the HMAC check
            var hmac = hasher.ComputeHmacSha256(corruptManifest, DefaultKey);
            var hmacHex = Encoding.UTF8.GetBytes(Convert.ToHexString(hmac).ToLowerInvariant());

            var hmacEntry = zip.CreateEntry("manifest.hmac");
            using (var hmacStream = hmacEntry.Open())
            {
                hmacStream.Write(hmacHex, 0, hmacHex.Length);
            }
        }

        var verification = builder.Verify(ms.ToArray(), DefaultKey);

        Assert.False(verification.IsValid);
        Assert.Contains("Failed to read evidence bundle", verification.Issues[0]);
    }

    [Fact]
    public void Verify_ManifestMissingFilesProperty_ReturnsInvalid()
    {
        var builder = CreateBuilder();
        var hasher = new IntegrityHasher();

        // Build a ZIP with a valid manifest.json that has no "files" property
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var manifestJson = @"{""createdUtc"":""2024-01-01T00:00:00Z""}"u8.ToArray();

            var manifestEntry = zip.CreateEntry("manifest.json");
            using (var stream = manifestEntry.Open())
            {
                stream.Write(manifestJson, 0, manifestJson.Length);
            }

            var hmac = hasher.ComputeHmacSha256(manifestJson, DefaultKey);
            var hmacHex = Encoding.UTF8.GetBytes(Convert.ToHexString(hmac).ToLowerInvariant());

            var hmacEntry = zip.CreateEntry("manifest.hmac");
            using (var hmacStream = hmacEntry.Open())
            {
                hmacStream.Write(hmacHex, 0, hmacHex.Length);
            }
        }

        var verification = builder.Verify(ms.ToArray(), DefaultKey);

        Assert.False(verification.IsValid);
        Assert.Contains("Failed to read evidence bundle", verification.Issues[0]);
    }

    private static byte[] TamperFileInZip(byte[] zipBytes, string targetEntry, Func<byte[], byte[]> tamper)
    {
        // Read all entries from the original ZIP
        using var inputMs = new MemoryStream(zipBytes);
        using var inputZip = new ZipArchive(inputMs, ZipArchiveMode.Read);

        var entries = new Dictionary<string, byte[]>();
        var timestamps = new Dictionary<string, DateTimeOffset>();

        foreach (var entry in inputZip.Entries)
        {
            using var stream = entry.Open();
            using var entryMs = new MemoryStream();
            stream.CopyTo(entryMs);
            var data = entryMs.ToArray();

            if (string.Equals(entry.Name, targetEntry, StringComparison.OrdinalIgnoreCase))
            {
                data = tamper(data);
            }

            entries[entry.FullName] = data;
            timestamps[entry.FullName] = entry.LastWriteTime;
        }

        // Rebuild the ZIP with the tampered entry
        using var outputMs = new MemoryStream();
        using (var outputZip = new ZipArchive(outputMs, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var kvp in entries.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
            {
                var newEntry = outputZip.CreateEntry(kvp.Key, CompressionLevel.Optimal);
                newEntry.LastWriteTime = timestamps[kvp.Key];
                using var stream = newEntry.Open();
                stream.Write(kvp.Value, 0, kvp.Value.Length);
            }
        }

        return outputMs.ToArray();
    }
}
