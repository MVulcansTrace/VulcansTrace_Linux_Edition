using System.IO.Compression;
using System.Security.Cryptography;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Security;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Evidence;
using VulcansTrace.Linux.Evidence.Formatters;

var exportDir = GetOptionValue(args, "--export", "-e");
var verifyBundle = GetOptionValue(args, "--verify", "-v");
var verifyKeyHex = GetOptionValue(args, "--key", "-k");
var runAll = args.Any(a => a.Equals("--all", StringComparison.OrdinalIgnoreCase));
var intensityOverride = ParseIntensity(GetOptionValue(args, "--intensity", "-i"));

if (!string.IsNullOrWhiteSpace(verifyBundle))
{
    return await VerifyEvidenceBundleAsync(verifyBundle, verifyKeyHex);
}

var logFile = args.FirstOrDefault(a => !a.StartsWith("-", StringComparison.OrdinalIgnoreCase));
if (string.IsNullOrWhiteSpace(logFile))
{
    Console.WriteLine("Usage: TestAnalysis <logfile> [--intensity Low|Medium|High] [--all] [--export <dir>]");
    Console.WriteLine("       TestAnalysis --verify <bundle.zip> --key <64-character-hex-key>");
    Console.WriteLine("Analyzing SAMPLE-LOG-MEDIUM-PROFILE.log by default...");
    logFile = "SAMPLE-LOG-MEDIUM-PROFILE.log";
}

Console.WriteLine("=== VulcansTrace Linux Analysis ===");
Console.WriteLine($"Log File: {logFile}");
Console.WriteLine();

if (!File.Exists(logFile))
{
    Console.WriteLine($"Error: File not found: {logFile}");
    return 1;
}

if (!string.IsNullOrWhiteSpace(exportDir))
{
    Directory.CreateDirectory(exportDir);
}

var logContent = await File.ReadAllTextAsync(logFile);
Console.WriteLine($"Read {logContent.Length} characters from log file");
Console.WriteLine();

var logNormalizer = new LogNormalizer();
var profileProvider = new AnalysisProfileProvider();

var baselineDetectors = new IDetector[]
{
    new PortScanDetector(),
    new FloodDetector(),
    new LateralMovementDetector(),
    new BeaconingDetector(),
    new PolicyViolationDetector(),
    new NoveltyDetector()
};

var linuxDetectors = new IDetector[]
{
    new FlagAnomalyDetector(),
    new MacSpoofingDetector(),
    new KernelModuleDetector(),
    new InterfaceHoppingDetector(),
    new UnusualPacketSizeDetector()
};

var advancedDetectors = new IDetector[]
{
    new C2ChannelDetector(),
    new PrivilegeEscalationDetector()
};

var analyzer = new SentryAnalyzer(logNormalizer, profileProvider, baselineDetectors, linuxDetectors, advancedDetectors, new RiskEscalator());
var evidenceBuilder = CreateEvidenceBuilder();

var intensities = runAll
    ? new[] { IntensityLevel.Low, IntensityLevel.Medium, IntensityLevel.High }
    : new[] { intensityOverride ?? IntensityLevel.Medium };

foreach (var intensity in intensities)
{
    Console.WriteLine($"=== Intensity: {intensity} ===");
    var analysisResult = analyzer.Analyze(logContent, intensity, CancellationToken.None);

    Console.WriteLine($"Total Lines: {analysisResult.TotalLines}");
    Console.WriteLine($"Parsed Lines: {analysisResult.ParsedLines}");
    Console.WriteLine($"Skipped Lines: {analysisResult.SkippedLineCount}");
    Console.WriteLine($"Findings: {analysisResult.Findings.Count}");
    Console.WriteLine($"Parse Errors: {analysisResult.ParseErrorCount}");
    Console.WriteLine($"Warnings: {analysisResult.Warnings.Count}");

    if (analysisResult.TimeRangeStart != DateTime.MinValue && analysisResult.TimeRangeEnd != DateTime.MinValue)
    {
        Console.WriteLine($"Time Range: {analysisResult.TimeRangeStart:yyyy-MM-dd HH:mm:ss} - {analysisResult.TimeRangeEnd:yyyy-MM-dd HH:mm:ss}");
    }

    var categories = analysisResult.Findings
        .GroupBy(f => f.Category)
        .OrderByDescending(g => g.Count())
        .ThenBy(g => g.Key)
        .ToArray();

    if (categories.Length > 0)
    {
        Console.WriteLine("Findings by Category:");
        foreach (var category in categories)
        {
            Console.WriteLine($"  - {category.Key}: {category.Count()}");
        }
    }
    else
    {
        Console.WriteLine("No findings detected at this intensity.");
    }

    var expectedCategories = GetExpectedCategories(logFile, intensity);
    if (expectedCategories.Length > 0)
    {
        var missing = expectedCategories
            .Where(expected => categories.All(c => !c.Key.Equals(expected, StringComparison.OrdinalIgnoreCase)))
            .ToArray();

        if (missing.Length == 0)
        {
            Console.WriteLine("Expectation Check: PASS");
        }
        else
        {
            Console.WriteLine($"Expectation Check: FAIL (missing: {string.Join(", ", missing)})");
        }
    }

    if (!string.IsNullOrWhiteSpace(exportDir))
    {
        var key = GenerateSigningKey();
        var zipBytes = evidenceBuilder.Build(analysisResult, logContent, key, analysisResult.TimeRangeEnd);
        var zipName = $"{Path.GetFileNameWithoutExtension(logFile)}_{intensity}.zip";
        var outputPath = Path.Combine(exportDir, zipName);
        await File.WriteAllBytesAsync(outputPath, zipBytes);

        Console.WriteLine($"Evidence bundle: {outputPath}");
        Console.WriteLine($"Evidence signing key (hex): {Convert.ToHexString(key).ToLowerInvariant()}");
        ValidateEvidenceBundle(outputPath);
    }

    Console.WriteLine();
}

return 0;

static string? GetOptionValue(string[] args, string longName, string shortName)
{
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i].Equals(longName, StringComparison.OrdinalIgnoreCase) || args[i].Equals(shortName, StringComparison.OrdinalIgnoreCase))
        {
            if (i + 1 < args.Length)
            {
                return args[i + 1];
            }
        }
    }

    return null;
}

static async Task<int> VerifyEvidenceBundleAsync(string bundlePath, string? signingKeyHex)
{
    if (string.IsNullOrWhiteSpace(signingKeyHex))
    {
        Console.WriteLine("Usage: TestAnalysis --verify <bundle.zip> --key <64-character-hex-key>");
        return 1;
    }

    if (!File.Exists(bundlePath))
    {
        Console.WriteLine($"Error: File not found: {bundlePath}");
        return 1;
    }

    byte[] signingKey;
    try
    {
        signingKey = Convert.FromHexString(signingKeyHex.Trim());
    }
    catch (FormatException)
    {
        Console.WriteLine("Error: signing key must be hexadecimal.");
        return 1;
    }

    var zipBytes = await File.ReadAllBytesAsync(bundlePath);
    var verification = CreateEvidenceBuilder().Verify(zipBytes, signingKey);

    Console.WriteLine($"Verification: {(verification.IsValid ? "PASS" : "FAIL")}");
    Console.WriteLine(verification.Message);

    foreach (var issue in verification.Issues)
    {
        Console.WriteLine($"  - {issue}");
    }

    return verification.IsValid ? 0 : 1;
}

static EvidenceBuilder CreateEvidenceBuilder() =>
    new(new IntegrityHasher(), new CsvFormatter(), new MarkdownFormatter(), new HtmlFormatter(), new JsonFormatter(), new StixFormatter());

static IntensityLevel? ParseIntensity(string? value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return null;
    }

    if (Enum.TryParse<IntensityLevel>(value, ignoreCase: true, out var parsed))
    {
        return parsed;
    }

    return null;
}

static string[] GetExpectedCategories(string logFile, IntensityLevel intensity)
{
    var fileName = Path.GetFileName(logFile).ToUpperInvariant();

    if (fileName.Contains("LOW-PROFILE") && intensity == IntensityLevel.Low)
    {
        return new[] { "PortScan" };
    }

    if (fileName.Contains("MEDIUM-PROFILE") && intensity == IntensityLevel.Medium)
    {
        return new[] { "PortScan", "LateralMovement" };
    }

    if (fileName.Contains("HIGH-PROFILE") && intensity == IntensityLevel.High)
    {
        return new[] { "PortScan", "LateralMovement" };
    }

    return Array.Empty<string>();
}

static byte[] GenerateSigningKey()
{
    var keyBytes = new byte[32];
    using var rng = RandomNumberGenerator.Create();
    rng.GetBytes(keyBytes);
    return keyBytes;
}

static void ValidateEvidenceBundle(string zipPath)
{
    var required = new[]
    {
        "findings.csv",
        "findings.json",
        "findings.stix.json",
        "report.html",
        "summary.md",
        "log.txt",
        "manifest.json",
        "manifest.hmac"
    };

    using var zip = ZipFile.OpenRead(zipPath);
    var names = zip.Entries.Select(e => e.FullName).ToHashSet(StringComparer.OrdinalIgnoreCase);

    var missing = required.Where(r => !names.Contains(r)).ToArray();
    if (missing.Length == 0)
    {
        Console.WriteLine("Evidence bundle check: PASS (all required files present)");
    }
    else
    {
        Console.WriteLine($"Evidence bundle check: FAIL (missing: {string.Join(", ", missing)})");
    }
}
