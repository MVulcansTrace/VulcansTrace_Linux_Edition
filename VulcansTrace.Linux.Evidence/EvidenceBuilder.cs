using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Security;
using VulcansTrace.Linux.Evidence.Formatters;

namespace VulcansTrace.Linux.Evidence;

/// <summary>
/// Builds cryptographically signed evidence packages from analysis results.
/// </summary>
/// <remarks>
/// Creates a ZIP archive containing:
/// <list type="bullet">
/// <item><c>findings.csv</c> - Findings in CSV format</item>
/// <item><c>log.txt</c> - Original log file</item>
/// <item><c>report.html</c> - HTML report</item>
/// <item><c>summary.md</c> - Markdown summary</item>
/// <item><c>manifest.json</c> - File hashes and metadata</item>
/// <item><c>manifest.hmac</c> - HMAC-SHA256 signature for integrity verification</item>
/// </list>
/// </remarks>
public sealed class EvidenceBuilder
{
    private readonly IntegrityHasher _hasher;
    private readonly CsvFormatter _csvFormatter;
    private readonly MarkdownFormatter _markdownFormatter;
    private readonly HtmlFormatter _htmlFormatter;
    private readonly JsonFormatter _jsonFormatter;
    private readonly StixFormatter _stixFormatter;
    private readonly ComplianceScorecardHtmlFormatter? _scorecardHtmlFormatter;
    private readonly ComplianceScorecardMarkdownFormatter? _scorecardMarkdownFormatter;
    private readonly RiskScorecardHtmlFormatter? _riskScorecardHtmlFormatter;
    private readonly RiskScorecardMarkdownFormatter? _riskScorecardMarkdownFormatter;
    private static readonly DateTimeOffset ZipMinTimestamp = new DateTimeOffset(new DateTime(1980, 1, 1, 0, 0, 0, DateTimeKind.Utc));
    private static readonly DateTimeOffset ZipMaxTimestamp = new DateTimeOffset(new DateTime(2107, 12, 31, 23, 59, 59, DateTimeKind.Utc));

    /// <summary>
    /// Initializes a new instance of the <see cref="EvidenceBuilder"/> class.
    /// </summary>
    /// <param name="hasher">The integrity hasher for computing SHA-256 and HMAC signatures.</param>
    /// <param name="csvFormatter">Formatter for CSV output.</param>
    /// <param name="markdownFormatter">Formatter for Markdown output.</param>
    /// <param name="htmlFormatter">Formatter for HTML output.</param>
    /// <param name="jsonFormatter">Formatter for JSON output.</param>
    /// <param name="stixFormatter">Formatter for STIX output.</param>
    /// <param name="scorecardHtmlFormatter">Optional formatter for compliance scorecard HTML.</param>
    /// <param name="scorecardMarkdownFormatter">Optional formatter for compliance scorecard Markdown.</param>
    /// <param name="riskScorecardHtmlFormatter">Optional formatter for risk scorecard HTML.</param>
    /// <param name="riskScorecardMarkdownFormatter">Optional formatter for risk scorecard Markdown.</param>
    public EvidenceBuilder(
        IntegrityHasher hasher,
        CsvFormatter csvFormatter,
        MarkdownFormatter markdownFormatter,
        HtmlFormatter htmlFormatter,
        JsonFormatter? jsonFormatter = null,
        StixFormatter? stixFormatter = null,
        ComplianceScorecardHtmlFormatter? scorecardHtmlFormatter = null,
        ComplianceScorecardMarkdownFormatter? scorecardMarkdownFormatter = null,
        RiskScorecardHtmlFormatter? riskScorecardHtmlFormatter = null,
        RiskScorecardMarkdownFormatter? riskScorecardMarkdownFormatter = null)
    {
        _hasher = hasher;
        _csvFormatter = csvFormatter;
        _markdownFormatter = markdownFormatter;
        _htmlFormatter = htmlFormatter;
        _jsonFormatter = jsonFormatter ?? new JsonFormatter();
        _stixFormatter = stixFormatter ?? new StixFormatter();
        _scorecardHtmlFormatter = scorecardHtmlFormatter;
        _scorecardMarkdownFormatter = scorecardMarkdownFormatter;
        _riskScorecardHtmlFormatter = riskScorecardHtmlFormatter;
        _riskScorecardMarkdownFormatter = riskScorecardMarkdownFormatter;
    }

    /// <summary>
    /// Builds an evidence package synchronously.
    /// </summary>
    /// <param name="result">The analysis result to package.</param>
    /// <param name="rawLog">The original raw log content.</param>
    /// <param name="signingKey">The secret key for HMAC signing.</param>
    /// <param name="analysisTimestampUtc">Optional timestamp override for file dates.</param>
    /// <param name="remediationPlanMarkdown">Optional remediation plan markdown to include as <c>remediation.md</c>.</param>
    /// <returns>A byte array containing the ZIP file contents.</returns>
    public byte[] Build(AnalysisResult result, string rawLog, byte[] signingKey, DateTime? analysisTimestampUtc = null, string? remediationPlanMarkdown = null)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        var timestamp = analysisTimestampUtc ?? DateTime.UtcNow;
        return Build(result, rawLog, signingKey, timestamp, CancellationToken.None, remediationPlanMarkdown);
    }

    /// <summary>
    /// Builds an evidence package asynchronously.
    /// </summary>
    /// <param name="result">The analysis result to package.</param>
    /// <param name="rawLog">The original raw log content.</param>
    /// <param name="signingKey">The secret key for HMAC signing.</param>
    /// <param name="analysisTimestampUtc">Optional timestamp override for file dates.</param>
    /// <param name="cancellationToken">Token to cancel the build operation.</param>
    /// <param name="remediationPlanMarkdown">Optional remediation plan markdown to include as <c>remediation.md</c>.</param>
    /// <returns>A task representing the async operation, containing the ZIP file bytes.</returns>
    public Task<byte[]> BuildAsync(AnalysisResult result, string rawLog, byte[] signingKey, DateTime? analysisTimestampUtc = null, CancellationToken cancellationToken = default, string? remediationPlanMarkdown = null)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        var timestamp = analysisTimestampUtc ?? DateTime.UtcNow;
        return Task.Run(() => Build(result, rawLog, signingKey, timestamp, cancellationToken, remediationPlanMarkdown), cancellationToken);
    }

    /// <summary>
    /// Builds an evidence package with cancellation support.
    /// </summary>
    /// <param name="result">The analysis result to package.</param>
    /// <param name="rawLog">The original raw log content.</param>
    /// <param name="signingKey">The secret key for HMAC signing.</param>
    /// <param name="analysisTimestampUtc">Optional timestamp override for file dates.</param>
    /// <param name="cancellationToken">Token to cancel the build operation.</param>
    /// <param name="remediationPlanMarkdown">Optional remediation plan markdown to include as <c>remediation.md</c>.</param>
    /// <returns>A byte array containing the ZIP file contents.</returns>
    public byte[] Build(AnalysisResult result, string rawLog, byte[] signingKey, DateTime? analysisTimestampUtc, CancellationToken cancellationToken, string? remediationPlanMarkdown = null)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var timestampOffset = NormalizeTimestamp(result, analysisTimestampUtc);
        cancellationToken.ThrowIfCancellationRequested();

        var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["findings.csv"]  = Encoding.UTF8.GetBytes(_csvFormatter.ToCsv(result)),
            ["log.txt"]       = Encoding.UTF8.GetBytes(rawLog ?? string.Empty),
            ["report.html"]   = Encoding.UTF8.GetBytes(_htmlFormatter.ToHtml(result)),
            ["summary.md"]    = Encoding.UTF8.GetBytes(_markdownFormatter.ToMarkdown(result)),
            ["findings.json"] = Encoding.UTF8.GetBytes(_jsonFormatter.Format(result, rawLog ?? string.Empty, timestampOffset.UtcDateTime)),
            ["findings.stix.json"] = Encoding.UTF8.GetBytes(_stixFormatter.Format(result, rawLog ?? string.Empty, timestampOffset.UtcDateTime))
        };

        if (result.ActiveSuppressions.Count > 0)
        {
            files["suppressions.csv"] = Encoding.UTF8.GetBytes(_csvFormatter.ToSuppressionCsv(result));
        }

        if (!string.IsNullOrWhiteSpace(remediationPlanMarkdown))
        {
            files["remediation.md"] = Encoding.UTF8.GetBytes(remediationPlanMarkdown);
        }

        if (result.Scorecard != null)
        {
            if (_scorecardHtmlFormatter != null)
            {
                files["compliance-scorecard.html"] = Encoding.UTF8.GetBytes(_scorecardHtmlFormatter.ToHtml(result.Scorecard));
            }
            if (_scorecardMarkdownFormatter != null)
            {
                files["compliance-scorecard.md"] = Encoding.UTF8.GetBytes(_scorecardMarkdownFormatter.ToMarkdown(result.Scorecard));
            }
        }

        if (result.RiskScorecard != null)
        {
            if (_riskScorecardHtmlFormatter != null)
            {
                files["risk-scorecard.html"] = Encoding.UTF8.GetBytes(_riskScorecardHtmlFormatter.ToHtml(result.RiskScorecard));
            }
            if (_riskScorecardMarkdownFormatter != null)
            {
                files["risk-scorecard.md"] = Encoding.UTF8.GetBytes(_riskScorecardMarkdownFormatter.ToMarkdown(result.RiskScorecard));
            }
        }

        cancellationToken.ThrowIfCancellationRequested();

        var manifestEntries = new List<object>();

        foreach (var kvp in files.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var hash = _hasher.ComputeSha256(kvp.Value);
            var hashHex = Convert.ToHexString(hash).ToLowerInvariant();

            manifestEntries.Add(new
            {
                file = kvp.Key,
                sha256 = hashHex,
                length = kvp.Value.Length
            });
        }

        var manifest = new
        {
            createdUtc = timestampOffset.UtcDateTime,
            files = manifestEntries,
            warnings = result.Warnings,
            parseErrors = result.ParseErrors,
            skippedLineCount = result.SkippedLineCount
        };

        var manifestJson = JsonSerializer.SerializeToUtf8Bytes(manifest, new JsonSerializerOptions
        {
            WriteIndented = true
        });
        cancellationToken.ThrowIfCancellationRequested();

        var manifestHmac = _hasher.ComputeHmacSha256(manifestJson, signingKey);
        cancellationToken.ThrowIfCancellationRequested();

        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var kvp in files.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var entry = zip.CreateEntry(kvp.Key, CompressionLevel.Optimal);
                entry.LastWriteTime = timestampOffset;
                using var entryStream = entry.Open();
                entryStream.Write(kvp.Value, 0, kvp.Value.Length);
            }

            var manifestEntry = zip.CreateEntry("manifest.json", CompressionLevel.Optimal);
            manifestEntry.LastWriteTime = timestampOffset;
            using (var entryStream = manifestEntry.Open())
            {
                cancellationToken.ThrowIfCancellationRequested();
                entryStream.Write(manifestJson, 0, manifestJson.Length);
            }

            var hmacEntry = zip.CreateEntry("manifest.hmac", CompressionLevel.Optimal);
            hmacEntry.LastWriteTime = timestampOffset;
            using (var entryStream = hmacEntry.Open())
            {
                cancellationToken.ThrowIfCancellationRequested();
                // Write as lowercase hex string for interoperability
                var hmacHex = Encoding.UTF8.GetBytes(Convert.ToHexString(manifestHmac).ToLowerInvariant());
                entryStream.Write(hmacHex, 0, hmacHex.Length);
            }
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Verifies the integrity of an evidence bundle.
    /// </summary>
    /// <param name="zipBytes">The ZIP archive bytes to verify.</param>
    /// <param name="signingKey">The secret key used for HMAC signing.</param>
    /// <returns>A <see cref="VerificationResult"/> indicating whether the bundle is valid.</returns>
    public VerificationResult Verify(byte[] zipBytes, byte[] signingKey)
    {
        ArgumentNullException.ThrowIfNull(zipBytes);
        ArgumentNullException.ThrowIfNull(signingKey);

        try
        {
            using var ms = new MemoryStream(zipBytes);
            using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

            // Step 1: Read manifest.json
            var manifestEntry = zip.GetEntry("manifest.json");
            if (manifestEntry == null)
            {
                return VerificationResult.Invalid("manifest.json not found in evidence bundle.");
            }

            byte[] manifestBytes;
            using (var entryStream = manifestEntry.Open())
            using (var manifestStream = new MemoryStream())
            {
                entryStream.CopyTo(manifestStream);
                manifestBytes = manifestStream.ToArray();
            }

            // Step 2: Read manifest.hmac
            var hmacEntry = zip.GetEntry("manifest.hmac");
            if (hmacEntry == null)
            {
                return VerificationResult.Invalid("manifest.hmac not found in evidence bundle.");
            }

            string storedHmacHex;
            using (var entryStream = hmacEntry.Open())
            using (var reader = new StreamReader(entryStream, Encoding.UTF8))
            {
                storedHmacHex = reader.ReadToEnd().Trim();
            }

            // Step 3: Verify HMAC over manifest
            var computedHmacHex = Convert.ToHexString(_hasher.ComputeHmacSha256(manifestBytes, signingKey)).ToLowerInvariant();
            if (computedHmacHex != storedHmacHex)
            {
                return VerificationResult.Invalid("HMAC signature mismatch: manifest has been tampered with or signing key is incorrect.");
            }

            // Step 4: Parse manifest and verify each file hash
            var manifestDoc = JsonDocument.Parse(manifestBytes);
            var filesArray = manifestDoc.RootElement.GetProperty("files");
            var issues = new List<string>();

            foreach (var fileEntry in filesArray.EnumerateArray())
            {
                var fileName = fileEntry.GetProperty("file").GetString()!;
                var expectedHash = fileEntry.GetProperty("sha256").GetString()!;

                var zipFileEntry = zip.GetEntry(fileName);
                if (zipFileEntry == null)
                {
                    issues.Add($"File '{fileName}' listed in manifest but missing from bundle.");
                    continue;
                }

                byte[] fileBytes;
                using (var entryStream = zipFileEntry.Open())
                using (var fileStream = new MemoryStream())
                {
                    entryStream.CopyTo(fileStream);
                    fileBytes = fileStream.ToArray();
                }

                var actualHash = Convert.ToHexString(_hasher.ComputeSha256(fileBytes)).ToLowerInvariant();
                if (actualHash != expectedHash)
                {
                    issues.Add($"File '{fileName}' hash mismatch: contents have been modified.");
                }
            }

            if (issues.Count > 0)
            {
                return VerificationResult.Invalid(issues.ToArray());
            }

            return VerificationResult.Valid();
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or
                                    System.Text.Json.JsonException or KeyNotFoundException)
        {
            return VerificationResult.Invalid($"Failed to read evidence bundle: {ex.Message}");
        }
    }

    private static DateTimeOffset NormalizeTimestamp(AnalysisResult result, DateTime? providedUtc)
    {
        DateTime EnsureUtc(DateTime dt) =>
            dt.Kind switch
            {
                DateTimeKind.Utc => dt,
                DateTimeKind.Local => dt.ToUniversalTime(),
                _ => DateTime.SpecifyKind(dt, DateTimeKind.Utc)
            };

        DateTimeOffset candidate = providedUtc.HasValue
            ? new DateTimeOffset(EnsureUtc(providedUtc.Value))
            : result.TimeRangeEnd != DateTime.MinValue
                ? new DateTimeOffset(EnsureUtc(result.TimeRangeEnd))
                : result.TimeRangeStart != DateTime.MinValue
                    ? new DateTimeOffset(EnsureUtc(result.TimeRangeStart))
                    : new DateTimeOffset(DateTime.SpecifyKind(DateTime.UnixEpoch, DateTimeKind.Utc));

        if (candidate < ZipMinTimestamp) return ZipMinTimestamp;
        if (candidate > ZipMaxTimestamp) return ZipMaxTimestamp;
        return candidate;
    }
}
