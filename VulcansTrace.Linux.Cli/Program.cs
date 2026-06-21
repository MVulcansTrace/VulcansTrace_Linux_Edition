using System.Globalization;
using System.Net;
using System.Net.Mail;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Autonomous;
using VulcansTrace.Linux.Agent.Diagnostics;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Notifications;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Agent.Scheduling;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Security;
using VulcansTrace.Linux.Core.ThreatIntel;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.LogDiff;
using VulcansTrace.Linux.Engine.Live;
using VulcansTrace.Linux.Evidence;

[assembly: InternalsVisibleTo("VulcansTrace.Linux.Tests")]

namespace VulcansTrace.Linux.Cli;

/// <summary>
/// Command-line entry point for headless audits and schedule management.
/// </summary>
public static class Program
{
    /// <summary>
    /// CLI entry point.
    /// </summary>
    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || args[0] == "--help" || args[0] == "-h")
        {
            PrintHelp();
            return 0;
        }

        var command = args[0].ToLowerInvariant();

        // Global flag: override the config directory for every file-backed store. Parsed here (not
        // position-sensitive) so it can appear anywhere after the command, e.g.
        // `vulcanstrace schedule list --config-dir /tmp/vt`.
        var configDir = ParseArg(args, "--config-dir", null);
        if (!string.IsNullOrWhiteSpace(configDir))
            VulcansTraceConfig.OverrideDirectory = configDir;

        try
        {
            return command switch
            {
                "audit" => await RunAuditAsync(args),
                "demo" => await RunDemoAsync(args),
                "diff" => await RunDiffAsync(args),
                "doctor" => await RunDoctorAsync(args),
                "verify-finding" => await RunVerifyFindingAsync(args),
                "schedule" => await RunScheduleAsync(args),
                "session" => await RunSessionAsync(args),
                "threat-intel" => await RunThreatIntelAsync(args),
                _ => PrintError($"Unknown command: {args[0]}")
            };
        }
        catch (OperationCanceledException)
        {
            return 130;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
    }

    private static async Task<int> RunAuditAsync(string[] args)
    {
        var intent = ParseArg(args, "--intent", "FullAudit")!;
        var outputJson = ParseArg(args, "--output-json", null);
        var outputMitre = ParseArg(args, "--output-mitre", null);
        var notifyOnCritical = HasFlag(args, "--notify-on-critical");
        var role = ParseArg(args, "--role", "Workstation")!;

        if (!Enum.TryParse<AgentIntent>(intent, true, out var agentIntent))
        {
            return PrintError($"Unknown intent: {intent}");
        }

        if (!Enum.TryParse<MachineRole>(role, true, out var machineRole))
        {
            return PrintError($"Unknown role: {role}");
        }

        Console.WriteLine($"Running audit: {agentIntent} (role: {machineRole})...");

        using var services = AgentFactory.Create(machineRole);
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        var result = await services.Agent.RunAuditAsync(agentIntent, rawLog: null, cts.Token);

        Console.WriteLine($"Completed at {result.UtcTimestamp:O}");
        Console.WriteLine($"  Passed: {result.PassedCount}, Failed: {result.FailedCount}, Suppressed: {result.SuppressedCount}, Crashed: {result.CrashedCount}");

        var criticalCount = result.AgentFindings.Count(f => f.Severity == Core.Severity.Critical);
        Console.WriteLine($"  Critical findings: {criticalCount}");

        if (result.Narrative != null)
        {
            Console.WriteLine();
            Console.WriteLine(StripMarkdown(result.Narrative.FullText));
        }

        if (!string.IsNullOrEmpty(outputJson))
        {
            if (Directory.Exists(outputJson))
            {
                Console.WriteLine($"  Error: --output-json path is a directory: {outputJson}");
                return 1;
            }

            var directory = Path.GetDirectoryName(outputJson);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var json = JsonSerializer.Serialize(result, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
            await File.WriteAllTextAsync(outputJson, json, cts.Token);
            Console.WriteLine($"  JSON output written to: {outputJson}");
        }

        if (!string.IsNullOrEmpty(outputMitre))
        {
            if (Directory.Exists(outputMitre))
            {
                Console.WriteLine($"  Error: --output-mitre path is a directory: {outputMitre}");
                return 1;
            }

            var directory = Path.GetDirectoryName(outputMitre);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var allFindings = result.AgentFindings.ToList();
            if (result.LogAnalysisResult?.Findings is { Count: > 0 } engineFindings)
            {
                allFindings.AddRange(engineFindings);
            }

            var layer = new MitreLayerBuilder().BuildCoverageLayer(services.MitreCoverageSources, allFindings);
            await File.WriteAllTextAsync(outputMitre, layer, cts.Token);
            Console.WriteLine($"  MITRE layer written to: {outputMitre}");
        }

        if (notifyOnCritical && criticalCount > 0)
        {
            await services.NotificationService.NotifyCriticalFindingsAsync(
                agentIntent.ToString(), criticalCount, cts.Token);
            Console.WriteLine("  Notification sent.");
        }

        var autoFixExitCode = await HandleAutoFixAsync(args, result, services, cts.Token);
        var auditExitCode = criticalCount > 0 ? 2 : 0;
        return Math.Max(auditExitCode, autoFixExitCode);
    }

    private static async Task<int> RunVerifyFindingAsync(string[] args)
    {
        if (args.Length < 2 || args[1].StartsWith("--", StringComparison.Ordinal))
        {
            return PrintError("Rule ID required. Usage: vulcanstrace verify-finding <rule-id> [--role <role>]");
        }

        var ruleId = args[1];
        var role = ParseArg(args, "--role", "Workstation")!;

        if (!Enum.TryParse<MachineRole>(role, true, out var machineRole))
        {
            return PrintError($"Unknown role: {role}");
        }

        using var services = AgentFactory.Create(machineRole);
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        var result = await services.Agent.VerifyFindingAsync(ruleId, cts.Token);
        Console.WriteLine(StripMarkdown(result.Summary));

        if (result.Narrative != null && !string.IsNullOrWhiteSpace(result.Narrative.FullText))
        {
            Console.WriteLine();
            Console.WriteLine(StripMarkdown(result.Narrative.FullText));
        }

        if (result.Summary.Contains("Run an audit first", StringComparison.OrdinalIgnoreCase))
            return 1;

        var stillFailing = result.AgentFindings.Any(f => !string.IsNullOrWhiteSpace(f.RuleId)
            && f.RuleId.Equals(ruleId, StringComparison.OrdinalIgnoreCase));

        return stillFailing ? 2 : 0;
    }

    private static async Task<int> RunDemoAsync(string[] args)
    {
        if (args.Length < 2)
        {
            return PrintError("Demo subcommand required: list, run");
        }

        var sub = args[1].ToLowerInvariant();

        return sub switch
        {
            "list" => RunDemoList(),
            "run" => await RunDemoRunAsync(args),
            _ => PrintError($"Unknown demo subcommand: {sub}")
        };
    }

    private static int RunDemoList()
    {
        Console.WriteLine("Available demo scenarios:");
        Console.WriteLine();
        foreach (var scenario in Enum.GetValues<DemoScenario>())
        {
            var keyword = DemoScenarioNames.ToCliKeyword(scenario);
            var description = DemoScenarioNames.GetDescription(scenario);
            Console.WriteLine($"  {keyword,-22} {description}");
        }
        return 0;
    }

    private static async Task<int> RunDemoRunAsync(string[] args)
    {
        var scenarioKeyword = ParseArg(args, "--scenario", null);
        var durationSeconds = 150;
        if (TryParseArg(args, "--duration", out var durationStr) && durationStr is not null)
        {
            if (!int.TryParse(durationStr, out durationSeconds))
                return PrintError($"--duration must be an integer, got '{durationStr}'.");
        }
        var intensityArg = ParseArg(args, "--intensity", "High")!;
        int? seed = null;
        if (TryParseArg(args, "--seed", out var seedStr) && seedStr is not null)
        {
            if (!int.TryParse(seedStr, out var seedValue))
                return PrintError($"--seed must be an integer, got '{seedStr}'.");
            seed = seedValue;
        }
        var outputEvidence = ParseArg(args, "--output-evidence", null);
        var outputJson = ParseArg(args, "--output-json", null);
        var outputHtml = ParseArg(args, "--output-html", null);
        var outputMitre = ParseArg(args, "--output-mitre", null);
        var signingKeyHex = ParseArg(args, "--signing-key", null);

        if (string.IsNullOrWhiteSpace(scenarioKeyword))
            return PrintError("--scenario is required");

        if (!Enum.TryParse<IntensityLevel>(intensityArg, true, out var intensity))
            return PrintError($"Unknown intensity: {intensityArg}. Use Low, Medium, or High.");

        DemoScenario scenario;
        try
        {
            scenario = DemoScenarioNames.FromCliKeyword(scenarioKeyword);
        }
        catch (ArgumentException)
        {
            return PrintError($"Unknown scenario: {scenarioKeyword}. Use 'vulcanstrace demo list' to see available scenarios.");
        }

        Console.WriteLine($"Running demo: {scenarioKeyword} (intensity: {intensity}, duration: {durationSeconds}s, seed: {seed?.ToString() ?? "random"})");

        using var services = AgentFactory.Create();
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        var runner = new DemoRunner(services.LiveStreamAnalyzer, services.TraceMapCorrelator);
        var result = await runner.RunAsync(scenario, TimeSpan.FromSeconds(durationSeconds), intensity, seed, cts.Token);

        // Build risk scorecard so evidence export includes risk-scorecard.html/md
        var riskBuilder = new VulcansTrace.Linux.Agent.Reports.RiskScorecardBuilder();
        result = result with
        {
            AnalysisResult = result.AnalysisResult with
            {
                RiskScorecard = riskBuilder.Build(result.AnalysisResult.Findings)
            }
        };

        var findings = result.AnalysisResult.Findings;
        var criticalCount = findings.Count(f => f.Severity == Severity.Critical);
        var highCount = findings.Count(f => f.Severity == Severity.High);
        var mediumCount = findings.Count(f => f.Severity == Severity.Medium);
        var lowCount = findings.Count(f => f.Severity == Severity.Low);

        Console.WriteLine();
        Console.WriteLine($"Demo complete: {findings.Count} finding(s)");
        Console.WriteLine($"  Critical: {criticalCount}, High: {highCount}, Medium: {mediumCount}, Low: {lowCount}");
        if (result.TraceMap.Edges.Count > 0)
            Console.WriteLine($"  Correlated edges: {result.TraceMap.Edges.Count}");

        // Export evidence
        if (!string.IsNullOrEmpty(outputEvidence))
        {
            if (Directory.Exists(outputEvidence))
            {
                Console.WriteLine($"  Error: --output-evidence path is a directory: {outputEvidence}");
                return 1;
            }

            var directory = Path.GetDirectoryName(outputEvidence);
            if (!string.IsNullOrWhiteSpace(directory))
                Directory.CreateDirectory(directory);

            byte[] signingKey;
            if (!string.IsNullOrWhiteSpace(signingKeyHex))
            {
                signingKey = Convert.FromHexString(signingKeyHex);
            }
            else
            {
                signingKey = new byte[32];
                Random.Shared.NextBytes(signingKey);
                Console.WriteLine($"  Generated signing key (save this to verify the evidence package): {Convert.ToHexString(signingKey)}");
            }

            var evidenceBytes = services.EvidenceBuilder.Build(
                result.AnalysisResult,
                result.RawLogDescription,
                signingKey,
                analysisTimestampUtc: result.StartTime,
                cancellationToken: cts.Token,
                remediationPlanMarkdown: null,
                traceMap: result.TraceMap);

            await File.WriteAllBytesAsync(outputEvidence, evidenceBytes, cts.Token);
            Console.WriteLine($"  Evidence package written to: {outputEvidence}");
        }

        // Export JSON
        if (!string.IsNullOrEmpty(outputJson))
        {
            if (Directory.Exists(outputJson))
            {
                Console.WriteLine($"  Error: --output-json path is a directory: {outputJson}");
                return 1;
            }

            var directory = Path.GetDirectoryName(outputJson);
            if (!string.IsNullOrWhiteSpace(directory))
                Directory.CreateDirectory(directory);

            var json = JsonSerializer.Serialize(result.AnalysisResult, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
            await File.WriteAllTextAsync(outputJson, json, cts.Token);
            Console.WriteLine($"  JSON output written to: {outputJson}");
        }

        // Export HTML
        if (!string.IsNullOrEmpty(outputHtml))
        {
            if (Directory.Exists(outputHtml))
            {
                Console.WriteLine($"  Error: --output-html path is a directory: {outputHtml}");
                return 1;
            }

            var directory = Path.GetDirectoryName(outputHtml);
            if (!string.IsNullOrWhiteSpace(directory))
                Directory.CreateDirectory(directory);

            var html = new VulcansTrace.Linux.Evidence.Formatters.HtmlFormatter().ToHtml(result.AnalysisResult);
            await File.WriteAllTextAsync(outputHtml, html, cts.Token);
            Console.WriteLine($"  HTML output written to: {outputHtml}");
        }

        // Export MITRE layer
        if (!string.IsNullOrEmpty(outputMitre))
        {
            if (Directory.Exists(outputMitre))
            {
                Console.WriteLine($"  Error: --output-mitre path is a directory: {outputMitre}");
                return 1;
            }

            var directory = Path.GetDirectoryName(outputMitre);
            if (!string.IsNullOrWhiteSpace(directory))
                Directory.CreateDirectory(directory);

            var layer = new MitreLayerBuilder().BuildCoverageLayer(services.MitreCoverageSources, findings);
            await File.WriteAllTextAsync(outputMitre, layer, cts.Token);
            Console.WriteLine($"  MITRE layer written to: {outputMitre}");
        }

        return 0;
    }

    private static async Task<int> RunDiffAsync(string[] args)
    {
        var baselinePath = ParseArg(args, "--baseline", null);
        var incidentPath = ParseArg(args, "--incident", null);
        var outputJson = ParseArg(args, "--output-json", null);
        var outputHtml = ParseArg(args, "--output-html", null);
        var outputEvidence = ParseArg(args, "--output-evidence", null);
        var signingKeyHex = ParseArg(args, "--signing-key", null);
        var intensityArg = ParseArg(args, "--intensity", "Medium")!;

        if (HasFlag(args, "--output-json") && string.IsNullOrWhiteSpace(outputJson))
            return PrintError("--output-json requires a file path");
        if (HasFlag(args, "--output-html") && string.IsNullOrWhiteSpace(outputHtml))
            return PrintError("--output-html requires a file path");
        if (HasFlag(args, "--output-evidence") && string.IsNullOrWhiteSpace(outputEvidence))
            return PrintError("--output-evidence requires a ZIP file path");
        if (HasFlag(args, "--signing-key") && string.IsNullOrWhiteSpace(signingKeyHex))
            return PrintError("--signing-key requires a hex-encoded key");
        if (string.IsNullOrWhiteSpace(baselinePath))
            return PrintError("--baseline is required");
        if (string.IsNullOrWhiteSpace(incidentPath))
            return PrintError("--incident is required");
        if (!File.Exists(baselinePath))
            return PrintError($"Baseline file not found: {baselinePath}");
        if (!File.Exists(incidentPath))
            return PrintError($"Incident file not found: {incidentPath}");
        if (!Enum.TryParse<IntensityLevel>(intensityArg, true, out var intensity))
            return PrintError($"Unknown intensity: {intensityArg}. Use Low, Medium, or High.");

        Console.WriteLine($"Comparing logs...");
        Console.WriteLine($"  Baseline: {baselinePath}");
        Console.WriteLine($"  Incident: {incidentPath}");
        Console.WriteLine($"  Intensity: {intensity}");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        var services = AgentFactory.Create();
        var baselineLog = await File.ReadAllTextAsync(baselinePath, cts.Token);
        var incidentLog = await File.ReadAllTextAsync(incidentPath, cts.Token);

        var baselineResult = services.Analyzer.Analyze(baselineLog, intensity, cts.Token);
        var incidentResult = services.Analyzer.Analyze(incidentLog, intensity, cts.Token);

        var diffAnalyzer = new LogDiffAnalyzer();
        var diffResult = diffAnalyzer.Compare(baselineResult, incidentResult) with
        {
            BaselineLabel = baselinePath,
            IncidentLabel = incidentPath
        };

        Console.WriteLine();
        Console.WriteLine($"  {diffResult.Narrative}");
        Console.WriteLine($"  Patterns: {diffResult.AddedCount} added, {diffResult.RemovedCount} removed, {diffResult.ChangedCount} changed, {diffResult.UnchangedCount} unchanged");
        if (diffResult.Findings.Count > 0)
        {
            Console.WriteLine($"  Findings: {diffResult.AddedFindingsCount} new, {diffResult.RemovedFindingsCount} resolved, {diffResult.ChangedFindingsCount} changed");
        }

        if (!string.IsNullOrEmpty(outputJson))
        {
            if (Directory.Exists(outputJson))
            {
                Console.WriteLine($"  Error: --output-json path is a directory: {outputJson}");
                return 1;
            }

            var directory = Path.GetDirectoryName(outputJson);
            if (!string.IsNullOrWhiteSpace(directory))
                Directory.CreateDirectory(directory);

            var json = JsonSerializer.Serialize(diffResult, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
            await File.WriteAllTextAsync(outputJson, json, cts.Token);
            Console.WriteLine($"  JSON output written to: {outputJson}");
        }

        if (!string.IsNullOrEmpty(outputHtml))
        {
            if (Directory.Exists(outputHtml))
            {
                Console.WriteLine($"  Error: --output-html path is a directory: {outputHtml}");
                return 1;
            }

            var directory = Path.GetDirectoryName(outputHtml);
            if (!string.IsNullOrWhiteSpace(directory))
                Directory.CreateDirectory(directory);

            var html = new VulcansTrace.Linux.Evidence.Formatters.LogDiffHtmlFormatter().ToHtml(diffResult, baselinePath, incidentPath);
            await File.WriteAllTextAsync(outputHtml, html, cts.Token);
            Console.WriteLine($"  HTML output written to: {outputHtml}");
        }

        if (!string.IsNullOrEmpty(outputEvidence))
        {
            if (Directory.Exists(outputEvidence))
            {
                Console.WriteLine($"  Error: --output-evidence path is a directory: {outputEvidence}");
                return 1;
            }

            var directory = Path.GetDirectoryName(outputEvidence);
            if (!string.IsNullOrWhiteSpace(directory))
                Directory.CreateDirectory(directory);

            byte[] signingKey;
            if (!string.IsNullOrWhiteSpace(signingKeyHex))
            {
                signingKey = Convert.FromHexString(signingKeyHex);
            }
            else
            {
                signingKey = new byte[32];
                Random.Shared.NextBytes(signingKey);
                Console.WriteLine($"  Generated signing key (save this to verify the evidence package): {Convert.ToHexString(signingKey)}");
            }

            var evidenceBytes = services.EvidenceBuilder.Build(
                incidentResult,
                incidentLog,
                signingKey,
                analysisTimestampUtc: DateTime.UtcNow,
                cancellationToken: cts.Token,
                remediationPlanMarkdown: null,
                traceMap: null,
                logDiffResult: diffResult);

            await File.WriteAllBytesAsync(outputEvidence, evidenceBytes, cts.Token);
            Console.WriteLine($"  Evidence package written to: {outputEvidence}");
        }

        var hasDiff = diffResult.AddedCount > 0 || diffResult.RemovedCount > 0 || diffResult.ChangedCount > 0
            || diffResult.AddedFindingsCount > 0 || diffResult.RemovedFindingsCount > 0 || diffResult.ChangedFindingsCount > 0;

        return hasDiff ? 2 : 0;
    }

    internal static async Task<int> RunDoctorAsync(string[] args, DoctorService? doctorService = null)
    {
        var outputJson = ParseArg(args, "--output-json", null);

        if (!string.IsNullOrEmpty(outputJson) && Directory.Exists(outputJson))
        {
            Console.WriteLine($"  Error: --output-json path is a directory: {outputJson}");
            return 1;
        }

        Console.WriteLine("VulcansTrace Doctor");
        Console.WriteLine("===================");
        Console.WriteLine();

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        using var services = doctorService is null ? AgentFactory.Create() : null;
        var result = await (doctorService ?? services!.DoctorService).ProbeAsync(cts.Token);

        if (result.Capabilities.Count == 0)
        {
            Console.WriteLine("No capabilities reported.");
        }
        else
        {
            Console.WriteLine("Data source visibility:");
            foreach (var cap in result.Capabilities)
            {
                var icon = cap.Status switch
                {
                    CapabilityStatus.Available => "✅",
                    CapabilityStatus.PermissionLimited => "⚠️ ",
                    CapabilityStatus.Unavailable => "❌",
                    _ => "❓"
                };
                var statusLabel = cap.Status switch
                {
                    CapabilityStatus.Available => "available",
                    CapabilityStatus.PermissionLimited => "permission-limited",
                    CapabilityStatus.Unavailable => "unavailable",
                    _ => "not-checked"
                };
                Console.Write($"  {icon} {cap.SourceName,-20} {statusLabel}");
                if (!string.IsNullOrWhiteSpace(cap.Detail) && cap.Status != CapabilityStatus.Available)
                {
                    var sanitized = cap.Detail.Trim().Replace('\n', ' ').Replace('\r', ' ');
                    if (sanitized.Length > 60)
                    {
                        var si = new StringInfo(sanitized);
                        var safeLength = Math.Min(57, si.LengthInTextElements);
                        sanitized = si.SubstringByTextElements(0, safeLength) + "...";
                    }
                    Console.Write($" ({sanitized})");
                }
                Console.WriteLine();
            }
            Console.WriteLine();

            if (result.PermissionLimitedCount > 0 || result.UnavailableCount > 0 || result.UnknownCount > 0)
            {
                var parts = new List<string>();
                if (result.PermissionLimitedCount > 0)
                    parts.Add($"{result.PermissionLimitedCount} permission-limited");
                if (result.UnavailableCount > 0)
                    parts.Add($"{result.UnavailableCount} unavailable");
                if (result.UnknownCount > 0)
                    parts.Add($"{result.UnknownCount} not checked");
                Console.WriteLine($"Recommendation: {string.Join(" and ", parts)} data source(s). Run with sudo where permission-limited, and review unavailable or not-checked sources before interpreting audit coverage.");
            }
            else
            {
                Console.WriteLine("All data sources are available.");
            }
        }

        if (result.Warnings.Count > 0)
        {
            Console.WriteLine();
            foreach (var warning in result.Warnings)
            {
                Console.WriteLine($"  Warning: {warning}");
            }
        }

        if (!string.IsNullOrEmpty(outputJson))
        {
            var directory = Path.GetDirectoryName(outputJson);
            if (!string.IsNullOrWhiteSpace(directory))
                Directory.CreateDirectory(directory);

            var json = JsonSerializer.Serialize(result, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                Converters = { new JsonStringEnumConverter() }
            });
            await File.WriteAllTextAsync(outputJson, json, cts.Token);
            Console.WriteLine($"  JSON output written to: {outputJson}");
        }

        if (result.IsHealthy)
            return 0;

        return result.UnavailableCount > 0 ? 1 : 2;
    }

    internal static async Task<int> HandleAutoFixAsync(string[] args, AgentResult auditResult, AgentServices services, CancellationToken ct)
    {
        if (!HasFlag(args, "--auto-fix"))
        {
            return 0;
        }

        var dryRun = HasFlag(args, "--dry-run");
        var yes = HasFlag(args, "--yes");
        var allowRestart = HasFlag(args, "--allow-restart");
        var allowPackages = HasFlag(args, "--allow-packages");

        if (auditResult.AgentFindings.Count == 0)
        {
            Console.WriteLine();
            Console.WriteLine("Auto-fix: No findings to remediate.");
            return 0;
        }

        var plan = services.RemediationPlanBuilder.Build(auditResult.AgentFindings);

        var policy = AutoFixPolicy.Standard();
        if (allowRestart)
        {
            policy = policy with { AllowServiceRestart = true };
        }
        if (allowPackages)
        {
            policy = policy with { AllowPackageInstall = true };
        }

        var validation = RemediationPlanValidator.Validate(plan);
        if (dryRun)
        {
            Console.WriteLine();
            if (!validation.IsValid)
            {
                Console.WriteLine("⚠️  VALIDATION WARNINGS:");
                foreach (var err in validation.Errors)
                {
                    Console.WriteLine($"   • {err}");
                }
                Console.WriteLine();
            }
            var preview = RemediationConsoleFormatter.FormatDryRun(plan, policy);
            Console.WriteLine(preview);
            return 0;
        }

        // Live run: show compact preview before confirmation
        var permittedCount = plan.Sections.Sum(s => s.ApplyCommands.Count(c => policy.IsPermitted(c.Safety)));
        var blockedCount = plan.Sections.Sum(s => s.ApplyCommands.Count(c => !policy.IsPermitted(c.Safety)));

        Console.WriteLine();
        Console.WriteLine("============================================");
        Console.WriteLine("  AUTO-FIX CONFIRMATION REQUIRED");
        Console.WriteLine("============================================");
        Console.WriteLine($"Findings: {plan.TotalSections}");
        Console.WriteLine($"Commands to execute: {permittedCount}");
        Console.WriteLine($"Commands blocked by policy: {blockedCount}");
        Console.WriteLine($"Policy: {policy.Describe()}");
        Console.WriteLine();

        foreach (var section in plan.Sections.Where(s => s.ApplyCommands.Count > 0))
        {
            if (section.ImpactPreview != null)
            {
                Console.WriteLine($"  [{section.RuleId}]");
                Console.WriteLine($"    Impact:  {section.ImpactPreview.ExpectedImpact}");
                if (!string.IsNullOrWhiteSpace(section.ImpactPreview.RiskBefore))
                    Console.WriteLine($"    Risk before:  {section.ImpactPreview.RiskBefore}");
                if (!string.IsNullOrWhiteSpace(section.ImpactPreview.ExpectedRiskAfter))
                    Console.WriteLine($"    Risk after:   {section.ImpactPreview.ExpectedRiskAfter}");
                if (section.ImpactPreview.CommandCount > 0)
                    Console.WriteLine($"    Commands:     {section.ImpactPreview.CommandCount}");
                Console.WriteLine($"    Rollback available: {(section.ImpactPreview.RollbackAvailable ? "Yes" : "No")}");
                Console.WriteLine($"    Rollback:     {section.ImpactPreview.RollbackPath}");
                Console.WriteLine($"    Verify:       {section.ImpactPreview.VerificationCommand}");
                if (section.ImpactPreview.HasRestartImpact)
                    Console.WriteLine($"    [RESTART] {section.ImpactPreview.RestartImpactDescription}");
                if (section.ImpactPreview.HasLockoutRisk)
                    Console.WriteLine($"    [LOCKOUT] {section.ImpactPreview.LockoutRiskDescription}");
                Console.WriteLine();
            }
        }

        if (permittedCount == 0)
        {
            Console.WriteLine("No commands are permitted under the current policy. Nothing to do.");
            Console.WriteLine("Use --allow-restart or --allow-packages to expand the policy, or review findings manually.");
            return 0;
        }

        if (!yes)
        {
            Console.Write("Type 'yes' to proceed with auto-fix, or anything else to cancel: ");
            var response = Console.ReadLine()?.Trim();
            if (!string.Equals(response, "yes", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Auto-fix cancelled by user.");
                return 0;
            }
        }
        else
        {
            Console.WriteLine("--yes flag set. Proceeding without interactive confirmation.");
        }

        Console.WriteLine();
        Console.WriteLine("Executing remediation plan...");

        var executionResult = await services.RemediationExecutor.ExecuteAsync(plan, policy, dryRun: false, ct);
        await RecordAutoFixRemediationAttemptsAsync(executionResult, services);

        var output = RemediationConsoleFormatter.FormatExecutionResult(executionResult);
        Console.WriteLine(output);

        if (!executionResult.AllSucceeded)
        {
            Console.WriteLine("⚠️  Some remediation commands failed. Review the output above.");
            return 3;
        }

        Console.WriteLine("✅ All permitted remediation commands completed successfully.");
        return 0;
    }

    private static async Task RecordAutoFixRemediationAttemptsAsync(RemediationExecutionResult executionResult, AgentServices services)
    {
        if (executionResult.IsDryRun)
            return;

        try
        {
            var snapshot = services.MemoryStore.Load();
            if (snapshot == null || snapshot.RuleHistory.Count == 0)
                return;

            var attemptedRuleIds = executionResult.Sections
                .Where(s => s.ApplyResults.Any(r => !r.Skipped))
                .Select(s => s.RuleId)
                .Where(r => !string.IsNullOrWhiteSpace(r) && snapshot.RuleHistory.ContainsKey(r))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (attemptedRuleIds.Count == 0)
                return;

            var timestamp = executionResult.CompletedAtUtc == default
                ? DateTime.UtcNow
                : executionResult.CompletedAtUtc;
            var updatedHistory = new RuleMemoryRecorder().MarkRemediationAttempt(
                attemptedRuleIds,
                timestamp,
                snapshot.RuleHistory);

            await services.MemoryStore.SaveAsync(snapshot with
            {
                UtcTimestamp = DateTime.UtcNow,
                RuleHistory = updatedHistory
            }).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Could not save remediation attempt memory: {ex.Message}");
        }
    }

    private static async Task<int> RunScheduleAsync(string[] args)
    {
        if (args.Length < 2)
        {
            return PrintError("Schedule subcommand required: list, add, edit, delete, enable, disable, run, install-cron, uninstall-cron");
        }

        var sub = args[1].ToLowerInvariant();

        switch (sub)
        {
            case "run":
                return await RunScheduledAuditAsync(args);

            case "remediate":
                return await RunScheduleRemediateAsync(args);

            case "install-cron":
            {
                using var cronServices = AgentFactory.Create();
                return InstallCron(args, cronServices.ScheduleStore);
            }

            case "uninstall-cron":
                return UninstallCron(args);

            default:
            {
                using var services = AgentFactory.Create();
                return sub switch
                {
                    "list" => ListSchedules(services.ScheduleStore),
                    "add" => AddSchedule(args, services.ScheduleStore),
                    "edit" => EditSchedule(args, services.ScheduleStore),
                    "delete" => DeleteSchedule(args, services.ScheduleStore),
                    "enable" => ToggleSchedule(args, services.ScheduleStore, enabled: true),
                    "disable" => ToggleSchedule(args, services.ScheduleStore, enabled: false),
                    _ => PrintError($"Unknown schedule subcommand: {sub}")
                };
            }
        }
    }

    private static int ListSchedules(IScheduleStore store)
    {
        var schedules = store.GetAll();
        if (schedules.Count == 0)
        {
            Console.WriteLine("No schedules configured.");
            return 0;
        }

        var installed = CrontabManager.GetInstalledScheduleIds().ToHashSet(StringComparer.OrdinalIgnoreCase);

        Console.WriteLine($"{"Id",-36} {"Name",-16} {"Intent",-16} {"Role",-11} {"Cron",-14} {"Ch",-6} {"En",-4} {"Dr",-4} {"Thr",-8} {"Rm",-4} {"Cr",-4} {"Last Run"}");
        Console.WriteLine(new string('-', 163));
        foreach (var s in schedules)
        {
            var lastRun = s.LastRunUtc.HasValue ? $"{s.LastRunUtc.Value:u} UTC" : "never";
            var inCron = installed.Contains(s.Id) ? "yes" : "no";
            var drift = s.AutonomousDriftResponse ? "yes" : "no";
            var threshold = s.AutonomousDriftResponse ? s.AutonomousDriftSeverityThreshold.ToString() : "-";
            var remediate = s.AllowAutoRemediate ? "yes" : "no";
            Console.WriteLine($"{s.Id,-36} {s.Name,-16} {s.Intent,-16} {s.MachineRole,-11} {s.CronExpression,-14} {s.NotificationChannel,-6} {s.Enabled,-4} {drift,-4} {threshold,-8} {remediate,-4} {inCron,-4} {lastRun}");
        }
        return 0;
    }

    private static int AddSchedule(string[] args, IScheduleStore store)
    {
        var name = ParseArg(args, "--name", null);
        var intentStr = ParseArg(args, "--intent", null);
        var cron = ParseArg(args, "--cron", null);
        var roleStr = ParseArg(args, "--role", "Workstation");
        var outputDir = ParseArg(args, "--output-dir", null);
        var notifyOnCritical = HasFlag(args, "--notify-on-critical");
        var channelStr = ParseArg(args, "--channel", "Desktop");
        var autonomousDriftResponse = HasFlag(args, "--autonomous-drift-response");
        var driftThresholdStr = ParseArg(args, "--autonomous-drift-threshold", "High");
        var allowRemediate = HasFlag(args, "--allow-remediate");
        var allowRemediationRestart = HasFlag(args, "--allow-remediation-restart");
        var allowRemediationPackages = HasFlag(args, "--allow-remediation-packages");
        var remediationPrefixesStr = ParseArg(args, "--remediation-prefixes", null);
        var requireSignedAlerts = HasFlag(args, "--require-signed-alerts");

        var missingValue = MissingFlagValueError(args, "--role", "--channel", "--autonomous-drift-threshold", "--output-dir", "--remediation-prefixes");
        if (missingValue != null)
            return PrintError(missingValue);

        if (string.IsNullOrWhiteSpace(name))
            return PrintError("--name is required");
        if (string.IsNullOrWhiteSpace(intentStr))
            return PrintError("--intent is required");
        if (string.IsNullOrWhiteSpace(cron))
            return PrintError("--cron is required");
        if (!CronExpressionValidator.IsValid(cron.Trim()))
            return PrintError("Invalid cron expression. Expected 5 fields: minute hour day month weekday");
        if (!Enum.TryParse<AgentIntent>(intentStr, true, out var intent))
            return PrintError($"Unknown intent: {intentStr}");
        if (!Enum.TryParse<MachineRole>(roleStr, true, out var role))
            return PrintError($"Unknown role: {roleStr}");
        if (!Enum.TryParse<NotificationChannel>(channelStr, true, out var channel))
            return PrintError($"Unknown channel: {channelStr}");
        if (!Enum.TryParse<Severity>(driftThresholdStr, true, out var driftThreshold))
            return PrintError($"Unknown severity threshold: {driftThresholdStr}. Use Critical, High, Medium, Low, or Info.");
        if ((allowRemediationRestart || allowRemediationPackages) && !allowRemediate)
            return PrintError("--allow-remediation-restart and --allow-remediation-packages require --allow-remediate.");
        var remediationPrefixes = ParseRemediationPrefixes(remediationPrefixesStr);
        if (store.GetAll().Any(s => s.Name.Equals(name.Trim(), StringComparison.OrdinalIgnoreCase)))
            return PrintError($"A schedule named '{name.Trim()}' already exists.");

        var schedule = new AuditSchedule
        {
            Id = Guid.NewGuid().ToString("N"),
            Name = name.Trim(),
            Intent = intent,
            CronExpression = cron.Trim(),
            MachineRole = role,
            NotifyOnCritical = notifyOnCritical,
            NotificationChannel = channel,
            AutonomousDriftResponse = autonomousDriftResponse,
            AutonomousDriftSeverityThreshold = driftThreshold,
            RequireSignedAlerts = requireSignedAlerts,
            AllowAutoRemediate = allowRemediate,
            AllowRemediationRestart = allowRemediationRestart,
            AllowRemediationPackages = allowRemediationPackages,
            AllowedRemediationRulePrefixes = remediationPrefixes,
            OutputDirectory = outputDir
        };

        store.Save(schedule);
        Console.WriteLine($"Schedule created: {schedule.Id}");
        Console.WriteLine($"  Name: {schedule.Name}");
        Console.WriteLine($"  Intent: {schedule.Intent}");
        Console.WriteLine($"  Role: {schedule.MachineRole}");
        Console.WriteLine($"  Cron: {schedule.CronExpression}");
        Console.WriteLine($"  Channel: {schedule.NotificationChannel}");
        Console.WriteLine($"  Notify on critical: {schedule.NotifyOnCritical}");
        Console.WriteLine($"  Autonomous drift response: {schedule.AutonomousDriftResponse}");
        Console.WriteLine($"  Autonomous drift threshold: {schedule.AutonomousDriftSeverityThreshold}");
        Console.WriteLine($"  Require signed alerts: {schedule.RequireSignedAlerts}");
        Console.WriteLine($"  Allow remediation: {schedule.AllowAutoRemediate}");
        Console.WriteLine($"  Allow remediation restart: {schedule.AllowRemediationRestart}");
        Console.WriteLine($"  Allow remediation packages: {schedule.AllowRemediationPackages}");
        if (schedule.AllowedRemediationRulePrefixes.Count > 0)
            Console.WriteLine($"  Remediation rule prefixes: {string.Join(", ", schedule.AllowedRemediationRulePrefixes)}");
        if (!string.IsNullOrWhiteSpace(schedule.OutputDirectory))
            Console.WriteLine($"  Output directory: {schedule.OutputDirectory}");
        return 0;
    }

    private static int EditSchedule(string[] args, IScheduleStore store)
    {
        var id = ParseArg(args, "--id", null);
        if (string.IsNullOrWhiteSpace(id))
            return PrintError("--id is required");

        var schedule = store.GetById(id);
        if (schedule == null)
            return PrintError($"Schedule not found: {id}");

        var missingValue = MissingFlagValueError(args, "--name", "--intent", "--cron", "--role", "--channel", "--output-dir", "--autonomous-drift-threshold", "--remediation-prefixes");
        if (missingValue != null)
            return PrintError(missingValue);

        var updated = schedule;

        if (TryParseArg(args, "--name", out var name))
        {
            var trimmedName = name!.Trim();
            if (store.GetAll().Any(s => s.Name.Equals(trimmedName, StringComparison.OrdinalIgnoreCase) && !s.Id.Equals(id, StringComparison.OrdinalIgnoreCase)))
                return PrintError($"A schedule named '{trimmedName}' already exists.");
            updated = updated with { Name = trimmedName };
        }

        if (TryParseArg(args, "--intent", out var intentStr))
        {
            if (!Enum.TryParse<AgentIntent>(intentStr, true, out var intent))
                return PrintError($"Unknown intent: {intentStr}");
            updated = updated with { Intent = intent };
        }

        if (TryParseArg(args, "--cron", out var cron))
        {
            if (!CronExpressionValidator.IsValid(cron!.Trim()))
                return PrintError("Invalid cron expression. Expected 5 fields: minute hour day month weekday");
            updated = updated with { CronExpression = cron.Trim() };
        }

        if (TryParseArg(args, "--role", out var roleStr))
        {
            if (!Enum.TryParse<MachineRole>(roleStr, true, out var role))
                return PrintError($"Unknown role: {roleStr}");
            updated = updated with { MachineRole = role };
        }

        if (TryParseArg(args, "--output-dir", out var outDir))
            updated = updated with { OutputDirectory = outDir };

        if (TryParseArg(args, "--channel", out var channelStr))
        {
            if (!Enum.TryParse<NotificationChannel>(channelStr, true, out var channel))
                return PrintError($"Unknown channel: {channelStr}");
            updated = updated with { NotificationChannel = channel };
        }

        if (HasFlag(args, "--notify-on-critical"))
            updated = updated with { NotifyOnCritical = true };
        if (HasFlag(args, "--no-notify-on-critical"))
            updated = updated with { NotifyOnCritical = false };

        if (HasFlag(args, "--autonomous-drift-response"))
            updated = updated with { AutonomousDriftResponse = true };
        if (HasFlag(args, "--no-autonomous-drift-response"))
            updated = updated with { AutonomousDriftResponse = false };

        if (TryParseArg(args, "--autonomous-drift-threshold", out var driftThresholdStr))
        {
            if (!Enum.TryParse<Severity>(driftThresholdStr, true, out var driftThreshold))
                return PrintError($"Unknown severity threshold: {driftThresholdStr}. Use Critical, High, Medium, Low, or Info.");
            updated = updated with { AutonomousDriftSeverityThreshold = driftThreshold };
        }

        if (HasFlag(args, "--require-signed-alerts"))
            updated = updated with { RequireSignedAlerts = true };
        if (HasFlag(args, "--no-require-signed-alerts"))
            updated = updated with { RequireSignedAlerts = false };

        if (HasFlag(args, "--allow-remediate"))
            updated = updated with { AllowAutoRemediate = true };
        if (HasFlag(args, "--no-allow-remediate"))
            updated = updated with { AllowAutoRemediate = false };

        if (HasFlag(args, "--allow-remediation-restart"))
            updated = updated with { AllowRemediationRestart = true };
        if (HasFlag(args, "--no-allow-remediation-restart"))
            updated = updated with { AllowRemediationRestart = false };

        if (HasFlag(args, "--allow-remediation-packages"))
            updated = updated with { AllowRemediationPackages = true };
        if (HasFlag(args, "--no-allow-remediation-packages"))
            updated = updated with { AllowRemediationPackages = false };

        if (TryParseArg(args, "--remediation-prefixes", out var remediationPrefixesStr))
            updated = updated with { AllowedRemediationRulePrefixes = ParseRemediationPrefixes(remediationPrefixesStr) };

        if (HasFlag(args, "--enabled"))
            updated = updated with { Enabled = true };
        if (HasFlag(args, "--disabled"))
            updated = updated with { Enabled = false };

        if ((updated.AllowRemediationRestart || updated.AllowRemediationPackages) && !updated.AllowAutoRemediate)
            return PrintError("--allow-remediation-restart and --allow-remediation-packages require --allow-remediate.");

        store.Save(updated);
        Console.WriteLine($"Schedule updated: {updated.Id}");
        return 0;
    }

    private static int DeleteSchedule(string[] args, IScheduleStore store)
    {
        var id = ParseArg(args, "--id", null);
        if (string.IsNullOrWhiteSpace(id))
            return PrintError("--id is required");

        var schedule = store.GetById(id);
        if (schedule == null)
            return PrintError($"Schedule not found: {id}");

        store.Delete(id);
        Console.WriteLine($"Schedule deleted: {schedule.Name} ({id})");
        return 0;
    }

    private static int ToggleSchedule(string[] args, IScheduleStore store, bool enabled)
    {
        var id = ParseArg(args, "--id", null);
        if (string.IsNullOrWhiteSpace(id))
            return PrintError("--id is required");

        var schedule = store.GetById(id);
        if (schedule == null)
            return PrintError($"Schedule not found: {id}");

        store.Save(schedule with { Enabled = enabled });
        Console.WriteLine($"Schedule {(enabled ? "enabled" : "disabled")}: {schedule.Name} ({id})");
        return 0;
    }

    private static int InstallCron(string[] args, IScheduleStore store)
    {
        var id = ParseArg(args, "--id", null);
        if (string.IsNullOrWhiteSpace(id))
            return PrintError("--id is required");

        var schedule = store.GetById(id);
        if (schedule == null)
            return PrintError($"Schedule not found: {id}");

        var exePath = ParseArg(args, "--exe-path", CrontabManager.DefaultExePath) ?? CrontabManager.DefaultExePath;

        CrontabManager.Install(schedule, exePath);
        Console.WriteLine($"Installed cron entry for schedule '{schedule.Name}' ({id}).");
        Console.WriteLine($"  Cron: {schedule.CronExpression}");
        Console.WriteLine($"  Command: {CrontabManager.BuildRunCommand(exePath, id)}");
        return 0;
    }

    private static int UninstallCron(string[] args)
    {
        var id = ParseArg(args, "--id", null);
        if (string.IsNullOrWhiteSpace(id))
            return PrintError("--id is required");

        CrontabManager.Uninstall(id);
        Console.WriteLine($"Uninstalled cron entry for schedule {id}.");
        return 0;
    }

    private static async Task<int> RunScheduledAuditAsync(string[] args, string? configDirectory = null)
    {
        var id = ParseArg(args, "--id", null);
        if (string.IsNullOrWhiteSpace(id))
            return PrintError("--id is required for schedule run");

        var schedule = JsonFileScheduleStore.CreateDefault(configDirectory).GetById(id);
        if (schedule == null)
            return PrintError($"Schedule not found: {id}");

        if (!schedule.Enabled)
        {
            Console.WriteLine($"Schedule '{schedule.Name}' is disabled. Skipping.");
            return 0;
        }

        Console.WriteLine($"Running scheduled audit: {schedule.Name} ({schedule.Intent}, role: {schedule.MachineRole})...");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        using var services = AgentFactory.Create(schedule.MachineRole, configDirectory);
        var previous = services.AuditHistoryStore.GetAll()
            .FirstOrDefault(e => e.Intent == schedule.Intent);

        var result = await services.Agent.RunAuditAsync(schedule.Intent, rawLog: null, cts.Token);

        var criticalFindings = result.AgentFindings.Where(f => f.Severity == Core.Severity.Critical).ToList();
        var criticalCount = criticalFindings.Count;

        Console.WriteLine($"Completed. Critical findings: {criticalCount}");

        services.ScheduleStore.Save(schedule with { LastRunUtc = DateTime.UtcNow });

        if (!string.IsNullOrWhiteSpace(schedule.OutputDirectory))
        {
            Directory.CreateDirectory(schedule.OutputDirectory);
            var fileName = $"audit_{schedule.Intent}_{DateTime.UtcNow:yyyyMMdd_HHmmss}.json";
            var path = Path.Combine(schedule.OutputDirectory, fileName);
            var json = JsonSerializer.Serialize(result, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
            await File.WriteAllTextAsync(path, json, cts.Token);
            Console.WriteLine($"  Output written to: {path}");
        }

        if (schedule.NotifyOnCritical && criticalCount > 0)
        {
            var previousCriticalFingerprints = previous?.SnapshotFindings
                .Where(sf => sf.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase))
                .Select(sf => sf.Fingerprint ?? $"{sf.RuleId}|{sf.Target}")
                .ToHashSet(StringComparer.OrdinalIgnoreCase)
                ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var newCriticalCount = criticalFindings.Count(f =>
            {
                var fp = f.Fingerprint ?? $"{f.RuleId}|{f.Target}";
                return !previousCriticalFingerprints.Contains(fp);
            });

            if (newCriticalCount > 0)
            {
                var notifier = CreateNotificationService(schedule.NotificationChannel);
                try
                {
                    await notifier.NotifyCriticalFindingsAsync(schedule.Name, newCriticalCount, cts.Token);
                    Console.WriteLine($"  Notification sent via {schedule.NotificationChannel}: {newCriticalCount} new critical finding(s).");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"  Notification failed via {schedule.NotificationChannel}: {ex.Message}");
                }
                finally
                {
                    (notifier as IDisposable)?.Dispose();
                }
            }
            else if (criticalCount > 0 && previousCriticalFingerprints.Count == 0 && previous != null)
            {
                // Pre-fingerprint history entry — we can't tell what's new vs old.
                // Skip notification this time so the user isn't spammed on first run after upgrade.
                Console.WriteLine("  Critical findings detected, but previous history lacks fingerprint data. Notification suppressed for this migration run.");
            }
            else
            {
                Console.WriteLine("  Critical findings detected, but none are new. Notification suppressed.");
            }
        }

        var autoFixExitCode = await HandleAutoFixAsync(args, result, services, cts.Token);

        if (schedule.AutonomousDriftResponse)
        {
            // Best-effort: drift response must never fail the cron run or alter the audit outcome.
            // The already-completed `result` is reused for alert enrichment so we don't run a
            // redundant third full-audit pass.
            var driftNotifier = CreateNotificationService(schedule.NotificationChannel);
            try
            {
                var responder = new AutonomousDriftResponder(
                    services.Agent,
                    services.BaselineStore,
                    driftNotifier,
                    ResolveAlertSigningKey,
                    services.RemediationPlanBuilder);
                await responder.RespondToDriftAsync(schedule, msg => Console.WriteLine($"  {msg}"), result, cts.Token);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"  Autonomous drift response failed: {ex.Message}");
            }
            finally
            {
                (driftNotifier as IDisposable)?.Dispose();
            }
        }

        var auditExitCode = criticalCount > 0 ? 2 : 0;
        return Math.Max(auditExitCode, autoFixExitCode);
    }

    private static byte[]? ResolveAlertSigningKey(string scheduleId)
    {
        var keyHex = Environment.GetEnvironmentVariable("VT_ALERT_SIGNING_KEY");
        if (!string.IsNullOrWhiteSpace(keyHex))
        {
            try
            {
                return Convert.FromHexString(keyHex.Trim());
            }
            catch
            {
                Console.Error.WriteLine("[VulcansTrace] VT_ALERT_SIGNING_KEY is not valid hex; drift alerts will be sent UNSIGNED.");
            }
        }
        return null;
    }

    internal static async Task<int> RunScheduleRemediateAsync(string[] args, string? configDirectory = null)
    {
        var id = ParseArg(args, "--id", null);
        if (string.IsNullOrWhiteSpace(id))
            return PrintError("--id is required for schedule remediate");

        var schedule = JsonFileScheduleStore.CreateDefault(configDirectory).GetById(id);
        if (schedule == null)
            return PrintError($"Schedule not found: {id}");

        if (!schedule.AllowAutoRemediate)
            return PrintError($"Schedule '{schedule.Name}' does not have remediation enabled. Enable it with 'vulcanstrace schedule edit --id {id} --allow-remediate'.");

        var dryRun = HasFlag(args, "--dry-run");
        var yes = HasFlag(args, "--yes");

        Console.WriteLine($"Running remediation for schedule: {schedule.Name} ({schedule.Intent}, role: {schedule.MachineRole})...");

        using var cts = new CancellationTokenSource();
        ConsoleCancelEventHandler cancelHandler = (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };
        Console.CancelKeyPress += cancelHandler;

        try
        {
            using var services = AgentFactory.Create(schedule.MachineRole, configDirectory);
            AgentResult result;
            try
            {
                result = await services.Agent.RunAuditAsync(schedule.Intent, rawLog: null, cts.Token);
            }
            catch (OperationCanceledException)
            {
                Console.Error.WriteLine("Remediation audit cancelled.");
                return 130; // Standard exit code for Ctrl-C cancellation.
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: remediation audit failed: {ex.Message}");
                return 1;
            }

            // Enforce the schedule's rule-prefix scope on what is actually remediated — not just on
            // the alert preview — so a schedule scoped to e.g. "FW" cannot remediate other rules.
            var scopedFindings = RemediationScopeFilter.Apply(result.AgentFindings, schedule.AllowedRemediationRulePrefixes);
            var plan = services.RemediationPlanBuilder.Build(scopedFindings);
            var policy = BuildScheduleRemediationPolicy(schedule);
            var validation = RemediationPlanValidator.Validate(plan);

            if (plan.TotalSections == 0)
            {
                Console.WriteLine("No remediable findings in scope. Nothing to do.");
                return 0;
            }

            var permittedCount = plan.Sections.Sum(s => s.ApplyCommands.Count(c => policy.IsPermitted(c.Safety)));
            var blockedCount = plan.Sections.Sum(s => s.ApplyCommands.Count(c => !policy.IsPermitted(c.Safety)));

            Console.WriteLine();
            Console.WriteLine($"Findings in scope: {plan.TotalSections}");
            Console.WriteLine($"Commands permitted by policy: {permittedCount}");
            Console.WriteLine($"Commands blocked by policy: {blockedCount}");
            Console.WriteLine($"Policy: {policy.Describe()}");

            if (!validation.IsValid)
            {
                Console.WriteLine();
                Console.WriteLine("Validation warnings:");
                foreach (var err in validation.Errors)
                {
                    Console.WriteLine($"  • {err}");
                }
            }

            if (permittedCount == 0)
            {
                Console.WriteLine();
                Console.WriteLine("No commands are permitted under the current policy. Nothing to do.");
                Console.WriteLine("Use --allow-remediate with --allow-remediation-restart or --allow-remediation-packages to expand the policy.");
                return 0;
            }

            var preview = RemediationConsoleFormatter.FormatDryRun(plan, policy);
            Console.WriteLine(preview);

            if (dryRun)
            {
                return 0;
            }

            if (!yes)
            {
                Console.Write("Type 'yes' to execute the remediation plan, or anything else to cancel: ");
                var response = Console.ReadLine()?.Trim();
                if (!string.Equals(response, "yes", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Remediation cancelled by user.");
                    return 0;
                }
            }
            else
            {
                Console.WriteLine("--yes flag set. Proceeding without interactive confirmation.");
            }

            Console.WriteLine();
            Console.WriteLine("Executing remediation plan...");

            var executionResult = await services.RemediationExecutor.ExecuteAsync(plan, policy, dryRun: false, cts.Token);
            await RecordAutoFixRemediationAttemptsAsync(executionResult, services);

            var output = RemediationConsoleFormatter.FormatExecutionResult(executionResult);
            Console.WriteLine(output);

            if (!executionResult.AllSucceeded)
            {
                Console.WriteLine("⚠️  Some remediation commands failed. Review the output above.");
                return 3;
            }

            if (executionResult.TotalCommandsExecuted == 0)
            {
                Console.WriteLine("ℹ️  No remediation commands were executed (all skipped by policy or validation).");
                return 0;
            }

            Console.WriteLine("✅ All permitted remediation commands completed successfully.");
            return 0;
        }
        finally
        {
            // Detach so repeated in-process invocation (notably unit tests) does not accumulate handlers.
            Console.CancelKeyPress -= cancelHandler;
        }
    }

    private static AutoFixPolicy BuildScheduleRemediationPolicy(AuditSchedule schedule) => new()
    {
        AllowReadOnly = true,
        AllowConfigChange = true,
        AllowServiceRestart = schedule.AllowRemediationRestart,
        AllowPackageInstall = schedule.AllowRemediationPackages,
        AllowDestructive = false,
        AllowUnknown = false,
        RequireValidation = true,
        RequireRollbackGuidance = true
    };

    private static async Task<int> RunSessionAsync(string[] args)
    {
        await Task.CompletedTask;

        if (args.Length < 2)
        {
            return PrintError("Session subcommand required: list, show, delete");
        }

        var sub = args[1].ToLowerInvariant();
        using var services = AgentFactory.Create();
        var store = services.SessionStore;

        switch (sub)
        {
            case "list":
                return ListSessions(store);

            case "show":
            {
                var id = ParseArg(args, "--id", null);
                if (string.IsNullOrWhiteSpace(id))
                    return PrintError("--id is required");

                var session = store.Load(id);
                if (session == null)
                    return PrintError($"Session not found: {id}");

                var formatter = new RemediationMarkdownFormatter();
                Console.WriteLine(formatter.FormatSession(session));
                return 0;
            }

            case "delete":
            {
                var id = ParseArg(args, "--id", null);
                if (string.IsNullOrWhiteSpace(id))
                    return PrintError("--id is required");

                var result = await services.Agent.DeleteRemediationSessionAsync(id, CancellationToken.None);
                if (result.Warnings.Count > 0 || result.Summary.Contains("not found", StringComparison.OrdinalIgnoreCase))
                {
                    return PrintError(result.Summary);
                }

                Console.WriteLine(result.Summary);
                return 0;
            }

            default:
                return PrintError($"Unknown session subcommand: {sub}");
        }
    }

    private static int ListSessions(ISessionStore store)
    {
        var sessions = store.List();
        if (sessions.Count == 0)
        {
            Console.WriteLine("No remediation sessions found.");
            return 0;
        }

        Console.WriteLine($"{"Session ID",-12} {"Status",-10} {"Created",-20} {"Finding"}");
        Console.WriteLine(new string('-', 100));
        foreach (var s in sessions)
        {
            var finding = s.RemediationPlan.Sections.FirstOrDefault()?.FindingSummary ?? "N/A";
            var created = s.CreatedAtUtc.ToString("yyyy-MM-dd HH:mm:ss");
            Console.WriteLine($"{s.SessionId,-12} {s.Status,-10} {created,-20} {finding}");
        }
        return 0;
    }

    private static INotificationService CreateNotificationService(NotificationChannel channel)
    {
        return channel switch
        {
            NotificationChannel.Email => CreateEmailService(),
            NotificationChannel.Webhook => CreateWebhookService(),
            _ => new NotifySendNotificationService()
        };
    }

    private static INotificationService CreateEmailService()
    {
        var hostEnv = Environment.GetEnvironmentVariable("VT_EMAIL_SMTP_HOST");
        var host = hostEnv ?? "localhost";
        var port = int.TryParse(Environment.GetEnvironmentVariable("VT_EMAIL_SMTP_PORT"), out var p) ? p : 587;
        var fromAddr = Environment.GetEnvironmentVariable("VT_EMAIL_FROM") ?? "vulcanstrace@localhost";
        var toAddr = Environment.GetEnvironmentVariable("VT_EMAIL_TO") ?? "admin@localhost";
        var user = Environment.GetEnvironmentVariable("VT_EMAIL_USER");
        var pass = Environment.GetEnvironmentVariable("VT_EMAIL_PASS");
        var noSsl = Environment.GetEnvironmentVariable("VT_EMAIL_NO_SSL");
        var disableSsl = noSsl?.Equals("1", StringComparison.OrdinalIgnoreCase) == true
            || noSsl?.Equals("true", StringComparison.OrdinalIgnoreCase) == true
            || noSsl?.Equals("yes", StringComparison.OrdinalIgnoreCase) == true;
        var enableSsl = !disableSsl;

        if (string.IsNullOrWhiteSpace(hostEnv))
            Console.Error.WriteLine("[VulcansTrace] Warning: VT_EMAIL_SMTP_HOST is not set; defaulting to localhost. Email alerts will not be delivered until SMTP is configured.");
        if (!enableSsl && !string.IsNullOrEmpty(user))
            Console.Error.WriteLine("[VulcansTrace] Warning: VT_EMAIL_NO_SSL is set while SMTP credentials are configured — credentials will be sent in plaintext.");

        return new EmailNotificationService(host, port, fromAddr, toAddr, user, pass, enableSsl);
    }

    private static INotificationService CreateWebhookService()
    {
        var urlEnv = Environment.GetEnvironmentVariable("VT_WEBHOOK_URL");
        var url = urlEnv ?? "http://localhost:8080/webhook";
        if (string.IsNullOrWhiteSpace(urlEnv))
            Console.Error.WriteLine("[VulcansTrace] Warning: VT_WEBHOOK_URL is not set; defaulting to localhost. Webhook alerts will not be delivered until it is configured.");
        return new WebhookNotificationService(url);
    }

    private static string? ParseArg(string[] args, string key, string? defaultValue)
    {
        var attachedPrefix = key + "=";
        for (var i = 0; i < args.Length; i++)
        {
            // Space-separated: --key value
            if (args[i].Equals(key, StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                var val = args[i + 1];
                return val.StartsWith("--", StringComparison.Ordinal) ? defaultValue : val;
            }
            // Attached form: --key=value (lets values that begin with '--' be supplied unambiguously)
            if (args[i].StartsWith(attachedPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return args[i][attachedPrefix.Length..];
            }
        }
        return defaultValue;
    }

    private static bool TryParseArg(string[] args, string key, out string? value)
    {
        var attachedPrefix = key + "=";
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i].Equals(key, StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                var val = args[i + 1];
                if (!val.StartsWith("--", StringComparison.Ordinal))
                {
                    value = val;
                    return true;
                }
            }
            if (args[i].StartsWith(attachedPrefix, StringComparison.OrdinalIgnoreCase))
            {
                value = args[i][attachedPrefix.Length..];
                return true;
            }
        }
        value = null;
        return false;
    }

    private static bool HasFlag(string[] args, string flag)
    {
        return args.Any(a => a.Equals(flag, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>True if <paramref name="key"/> appears as a bare <c>--key</c> or attached <c>--key=...</c> token.</summary>
    private static bool IsFlagPresent(string[] args, string key)
    {
        var attached = key + "=";
        return args.Any(a => a.Equals(key, StringComparison.OrdinalIgnoreCase)
                             || a.StartsWith(attached, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>True if <paramref name="key"/> has a consumable value (a non-flag token after it, or an attached <c>--key=...</c>).</summary>
    private static bool HasConsumableValue(string[] args, string key)
    {
        var attached = key + "=";
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i].Equals(key, StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 >= args.Length)
                    return false;
                var next = args[i + 1];
                return !next.StartsWith("--", StringComparison.Ordinal);
            }
            if (args[i].StartsWith(attached, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>Returns an error if any of the given value-bearing flags is present without a consumable value; otherwise null.</summary>
    private static string? MissingFlagValueError(string[] args, params string[] valueFlags)
    {
        foreach (var key in valueFlags)
        {
            if (IsFlagPresent(args, key) && !HasConsumableValue(args, key))
                return $"{key} requires a value.";
        }
        return null;
    }

    private static IReadOnlyList<string> ParseRemediationPrefixes(string? value)
        => RemediationScopeFilter.ParsePrefixes(value);

    private static int PrintError(string message)
    {
        Console.Error.WriteLine($"Error: {message}");
        Console.Error.WriteLine();
        PrintHelp();
        return 1;
    }

    private static async Task<int> RunThreatIntelAsync(string[] args)
    {
        await Task.CompletedTask;

        if (args.Length < 2)
        {
            return PrintError("Threat intel subcommand required: import, status, clear");
        }

        var sub = args[1].ToLowerInvariant();
        using var services = AgentFactory.Create();
        var store = services.ThreatIntelStore;

        return sub switch
        {
            "import" => RunThreatIntelImport(args, store),
            "status" => RunThreatIntelStatus(store),
            "clear" => RunThreatIntelClear(args, store),
            _ => PrintError($"Unknown threat-intel subcommand: {sub}")
        };
    }

    private static int RunThreatIntelImport(string[] args, IThreatIntelStore store)
    {
        var filePath = ParseArg(args, "--file", null);
        var format = ParseArg(args, "--format", "auto")!.ToLowerInvariant();

        if (string.IsNullOrWhiteSpace(filePath))
            return PrintError("--file is required");
        if (!File.Exists(filePath))
            return PrintError($"File not found: {filePath}");

        var json = File.ReadAllText(filePath);

        if (format == "auto")
        {
            if (ThreatIntelFormatDetector.TryDetect(json, out var detectedFormat))
            {
                format = detectedFormat == ThreatIntelBundleFormat.Stix ? "stix" : "misp";
            }
            else
            {
                return PrintError("Could not auto-detect format. Use --format stix or --format misp.");
            }
        }

        if (format != "stix" && format != "misp")
        {
            return PrintError($"Unknown format: {format}. Use stix or misp.");
        }

        ThreatIntelImportResult result;

        try
        {
            result = format == "stix"
                ? StixParser.Parse(json)
                : MispParser.Parse(json);
        }
        catch (Exception ex)
        {
            return PrintError($"Parse error: {ex.Message}");
        }

        store.Import(result.Entries);

        Console.WriteLine($"Imported {result.ImportedCount} IOC(s) from {format.ToUpperInvariant()} bundle.");
        if (result.SkippedCount > 0)
            Console.WriteLine($"  Skipped: {result.SkippedCount}");
        foreach (var warning in result.Warnings)
            Console.WriteLine($"  Warning: {warning}");

        if (!string.IsNullOrWhiteSpace(store.PersistenceWarning))
            Console.WriteLine($"  Note: {store.PersistenceWarning}");

        return 0;
    }

    private static int RunThreatIntelStatus(IThreatIntelStore store)
    {
        var total = store.Count;
        if (total == 0)
        {
            Console.WriteLine("No threat intelligence IOCs loaded.");
            return 0;
        }

        Console.WriteLine($"Threat intelligence IOCs: {total} total");
        foreach (IocType type in Enum.GetValues<IocType>())
        {
            var count = store.CountByType(type);
            if (count > 0)
                Console.WriteLine($"  {type}: {count}");
        }

        if (!string.IsNullOrWhiteSpace(store.PersistenceWarning))
            Console.WriteLine($"  Note: {store.PersistenceWarning}");

        return 0;
    }

    private static int RunThreatIntelClear(string[] args, IThreatIntelStore store)
    {
        var yes = HasFlag(args, "--yes");

        if (!yes)
        {
            Console.Write($"Clear all {store.Count} imported IOCs? Type 'yes' to confirm: ");
            var response = Console.ReadLine()?.Trim();
            if (!string.Equals(response, "yes", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Cancelled.");
                return 0;
            }
        }

        store.Clear();
        Console.WriteLine("All threat intelligence IOCs cleared.");
        return 0;
    }

    private static string StripMarkdown(string markdown)
    {
        if (string.IsNullOrWhiteSpace(markdown))
            return markdown;

        var text = markdown;
        text = System.Text.RegularExpressions.Regex.Replace(text, @"\*\*(.+?)\*\*", "$1");
        text = System.Text.RegularExpressions.Regex.Replace(text, @"_(.+?)_", "$1");
        return text;
    }

    private static void PrintHelp()
    {
        Console.WriteLine("VulcansTrace Linux Edition - CLI");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  Any command also accepts the global flag --config-dir <dir> to override the config directory.");
        Console.WriteLine("  vulcanstrace audit --intent <intent> [--output-json <file>] [--notify-on-critical] [--role <role>] [--auto-fix [--dry-run] [--yes] [--allow-restart] [--allow-packages]]");
        Console.WriteLine("  vulcanstrace demo list");
        Console.WriteLine("  vulcanstrace demo run --scenario <name> [--duration <seconds>] [--intensity <level>] [--seed <int>] [--output-evidence <zip>] [--output-json <file>] [--output-html <file>] [--output-mitre <file>]");
        Console.WriteLine("  vulcanstrace diff --baseline <file> --incident <file> [--output-json <file>] [--output-html <file>] [--output-evidence <zip>] [--signing-key <hex>]");
        Console.WriteLine("  vulcanstrace doctor [--output-json <file>]");
        Console.WriteLine("  vulcanstrace verify-finding <rule-id> [--role <role>]");
        Console.WriteLine("  vulcanstrace schedule list");
        Console.WriteLine("  vulcanstrace schedule add --name <name> --intent <intent> --cron <expr>");
        Console.WriteLine("    [--role <role>] [--channel Desktop|Email|Webhook] [--output-dir <dir>]");
        Console.WriteLine("    [--notify-on-critical] [--autonomous-drift-response] [--autonomous-drift-threshold <severity>] [--require-signed-alerts]");
        Console.WriteLine("    [--allow-remediate] [--allow-remediation-restart] [--allow-remediation-packages] [--remediation-prefixes <prefix1,prefix2>]");
        Console.WriteLine("  vulcanstrace schedule edit --id <id>");
        Console.WriteLine("    [--name <name>] [--intent <intent>] [--cron <expr>] [--role <role>] [--channel <ch>] [--output-dir <dir>]");
        Console.WriteLine("    [--notify-on-critical|--no-notify-on-critical] [--autonomous-drift-response|--no-autonomous-drift-response] [--autonomous-drift-threshold <severity>]");
        Console.WriteLine("    [--require-signed-alerts|--no-require-signed-alerts] [--allow-remediate|--no-allow-remediate]");
        Console.WriteLine("    [--allow-remediation-restart|--no-allow-remediation-restart] [--allow-remediation-packages|--no-allow-remediation-packages] [--remediation-prefixes <prefix1,prefix2>]");
        Console.WriteLine("    [--enabled|--disabled]");
        Console.WriteLine("  vulcanstrace schedule delete --id <id>");
        Console.WriteLine("  vulcanstrace schedule enable --id <id>");
        Console.WriteLine("  vulcanstrace schedule disable --id <id>");
        Console.WriteLine("  vulcanstrace schedule install-cron --id <id> [--exe-path <path>]");
        Console.WriteLine("  vulcanstrace schedule uninstall-cron --id <id>");
        Console.WriteLine("  vulcanstrace schedule run --id <id>");
        Console.WriteLine("  vulcanstrace schedule remediate --id <id> [--dry-run] [--yes]");
        Console.WriteLine("  vulcanstrace session list");
        Console.WriteLine("  vulcanstrace session show --id <id>");
        Console.WriteLine("  vulcanstrace session delete --id <id>");
        Console.WriteLine("  vulcanstrace threat-intel import --file <path> [--format stix|misp|auto]");
        Console.WriteLine("  vulcanstrace threat-intel status");
        Console.WriteLine("  vulcanstrace threat-intel clear [--yes]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --config-dir <dir>         [global] Base config directory for all stores (overrides XDG_CONFIG_HOME)");
        Console.WriteLine("  --intent <name>            Audit intent (FullAudit, FirewallCheck, PortCheck, etc.)");
        Console.WriteLine("  --scenario <name>          Demo scenario: random-mix, c2-beaconing, ssh-bruteforce, privilege-escalation");
        Console.WriteLine("  --duration <seconds>       Demo run duration in seconds (default: 150)");
        Console.WriteLine("  --seed <int>               Random seed for reproducible demo output");
        Console.WriteLine("  --baseline <file>          Baseline log file for diff comparison");
        Console.WriteLine("  --incident <file>          Incident log file for diff comparison");
        Console.WriteLine("  --intensity <level>        Diff analysis intensity: Low, Medium, High (default: Medium)");
        Console.WriteLine("  --output-json <file>       Write the full AgentResult to a JSON file");
        Console.WriteLine("  --output-html <file>       Write the log diff report as HTML");
        Console.WriteLine("  --output-evidence <zip>    Write a signed evidence ZIP including the diff report");
        Console.WriteLine("  --signing-key <hex>        Hex-encoded HMAC signing key for evidence packages");
        Console.WriteLine("  --output-mitre <file>      Write the MITRE ATT&CK Navigator layer JSON");
        Console.WriteLine("  --notify-on-critical       Send a notification if critical findings are found");
        Console.WriteLine("  --no-notify-on-critical    Disable critical notifications (edit only)");
        Console.WriteLine("  --role <role>              Machine role: Workstation, Server, LabBox, Router, DevMachine");
        Console.WriteLine("  --channel <ch>             Notification channel: Desktop, Email, Webhook");
        Console.WriteLine("  --output-dir <dir>         Directory to write scheduled audit JSON results");
        Console.WriteLine("  --autonomous-drift-response    Enable autonomous drift-response alerts");
        Console.WriteLine("  --no-autonomous-drift-response Disable autonomous drift-response alerts (edit only)");
        Console.WriteLine("  --autonomous-drift-threshold   Severity threshold for drift alerts: Critical, High, Medium, Low, Info (default: High)");
        Console.WriteLine("  --require-signed-alerts        Fail closed: never send unsigned drift alerts for this schedule (needs VT_ALERT_SIGNING_KEY)");
        Console.WriteLine("  --no-require-signed-alerts     Allow unsigned drift alerts for this schedule (edit only)");
        Console.WriteLine("  --allow-remediate              Enable human-approved remediation from schedule alerts");
        Console.WriteLine("  --no-allow-remediate           Disable schedule remediation (edit only)");
        Console.WriteLine("  --allow-remediation-restart    Permit remediation commands that restart services");
        Console.WriteLine("  --no-allow-remediation-restart Block service-restart remediation commands (edit only)");
        Console.WriteLine("  --allow-remediation-packages   Permit remediation commands that install/remove packages");
        Console.WriteLine("  --no-allow-remediation-packages Block package remediation commands (edit only)");
        Console.WriteLine("  --remediation-prefixes         Comma-separated rule-id prefixes remediation may target (e.g. FW,KERN)");
        Console.WriteLine("  --enabled / --disabled     Toggle schedule state (edit only)");
        Console.WriteLine("  --exe-path <path>          Path to vulcanstrace binary for cron entries");
        Console.WriteLine("  --auto-fix                 Enable automatic remediation of findings after audit");
        Console.WriteLine("  --dry-run                  With --auto-fix: preview what would change without executing");
        Console.WriteLine("  --yes                      With --auto-fix: skip interactive confirmation");
        Console.WriteLine("  --allow-restart            With --auto-fix: permit service restart commands");
        Console.WriteLine("  --allow-packages           With --auto-fix: permit package install/remove commands");
        Console.WriteLine();
        Console.WriteLine("Environment variables for Email channel:");
        Console.WriteLine("  VT_EMAIL_SMTP_HOST, VT_EMAIL_SMTP_PORT, VT_EMAIL_FROM, VT_EMAIL_TO, VT_EMAIL_USER, VT_EMAIL_PASS, VT_EMAIL_NO_SSL");
        Console.WriteLine("Environment variables for Webhook channel:");
        Console.WriteLine("  VT_WEBHOOK_URL");
        Console.WriteLine("Environment variables for autonomous drift-response signing:");
        Console.WriteLine("  VT_ALERT_SIGNING_KEY       Hex-encoded HMAC-SHA256 key for signing drift alerts (if unset, alerts are sent UNSIGNED)");
        Console.WriteLine("  VT_REQUIRE_SIGNED_ALERTS   When 1/true/yes, unsigned drift alerts are never sent across all schedules (fail closed)");
        Console.WriteLine();
        Console.WriteLine("Exit codes:");
        Console.WriteLine("  0  Success (no critical findings / no diff detected)");
        Console.WriteLine("  1  Error");
        Console.WriteLine("  2  Success with critical findings / diff detected");
        Console.WriteLine("  3  Auto-fix or 'schedule remediate' executed but some commands failed");
    }
}
