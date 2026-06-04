using System.Net;
using System.Net.Mail;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Notifications;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Agent.Scheduling;
using VulcansTrace.Linux.Agent.Sessions;
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

        try
        {
            return command switch
            {
                "audit" => await RunAuditAsync(args),
                "schedule" => await RunScheduleAsync(args),
                "session" => await RunSessionAsync(args),
                _ => PrintError($"Unknown command: {args[0]}")
            };
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

        var services = AgentFactory.Create(machineRole);
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
                Console.WriteLine($"    Rollback: {section.ImpactPreview.RollbackPath}");
                Console.WriteLine($"    Verify:  {section.ImpactPreview.VerificationCommand}");
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

            case "install-cron":
            {
                var store = AgentFactory.Create().ScheduleStore;
                return InstallCron(args, store);
            }

            case "uninstall-cron":
                return UninstallCron(args);

            default:
            {
                var services = AgentFactory.Create();
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

        Console.WriteLine($"{"Id",-36} {"Name",-16} {"Intent",-16} {"Role",-11} {"Cron",-14} {"Ch",-6} {"En",-4} {"Cr",-4} {"Last Run"}");
        Console.WriteLine(new string('-', 135));
        foreach (var s in schedules)
        {
            var lastRun = s.LastRunUtc.HasValue ? $"{s.LastRunUtc.Value:u} UTC" : "never";
            var inCron = installed.Contains(s.Id) ? "yes" : "no";
            Console.WriteLine($"{s.Id,-36} {s.Name,-16} {s.Intent,-16} {s.MachineRole,-11} {s.CronExpression,-14} {s.NotificationChannel,-6} {s.Enabled,-4} {inCron,-4} {lastRun}");
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

        if (HasFlag(args, "--enabled"))
            updated = updated with { Enabled = true };
        if (HasFlag(args, "--disabled"))
            updated = updated with { Enabled = false };

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

    private static async Task<int> RunScheduledAuditAsync(string[] args)
    {
        var id = ParseArg(args, "--id", null);
        if (string.IsNullOrWhiteSpace(id))
            return PrintError("--id is required for schedule run");

        var schedule = JsonFileScheduleStore.CreateDefault().GetById(id);
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

        var services = AgentFactory.Create(schedule.MachineRole);
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

        // Capture previous history entry before appending current result
        var previous = services.AuditHistoryStore.GetAll()
            .FirstOrDefault(e => e.Intent == schedule.Intent);

        // Append current result to history store
        var snapshotFindings = result.AgentFindings.Select(f => new VulcansTrace.Linux.Agent.Reports.AuditSnapshotFinding
        {
            RuleId = f.RuleId ?? "",
            Target = f.Target,
            Severity = f.Severity.ToString(),
            ShortDescription = f.ShortDescription,
            Fingerprint = f.Fingerprint
        }).ToList();

        services.AuditHistoryStore.Append(new VulcansTrace.Linux.Agent.Reports.AuditHistoryEntry
        {
            SnapshotId = Guid.NewGuid().ToString("N")[..8],
            TimestampUtc = result.UtcTimestamp,
            Intent = result.Intent,
            TotalFindings = result.AgentFindings.Count,
            CriticalCount = result.AgentFindings.Count(f => f.Severity == Core.Severity.Critical),
            HighCount = result.AgentFindings.Count(f => f.Severity == Core.Severity.High),
            MediumCount = result.AgentFindings.Count(f => f.Severity == Core.Severity.Medium),
            LowCount = result.AgentFindings.Count(f => f.Severity == Core.Severity.Low),
            InfoCount = result.AgentFindings.Count(f => f.Severity == Core.Severity.Info),
            WarningCount = result.Warnings.Count,
            Exported = false,
            PassedCount = result.PassedCount,
            FailedCount = result.FailedCount,
            SuppressedCount = result.SuppressedCount,
            CrashedCount = result.CrashedCount,
            SnapshotFindings = snapshotFindings
        });

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
                try
                {
                    var notifier = CreateNotificationService(schedule.NotificationChannel);
                    await notifier.NotifyCriticalFindingsAsync(schedule.Name, newCriticalCount, cts.Token);
                    Console.WriteLine($"  Notification sent via {schedule.NotificationChannel}: {newCriticalCount} new critical finding(s).");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"  Notification failed via {schedule.NotificationChannel}: {ex.Message}");
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
        var auditExitCode = criticalCount > 0 ? 2 : 0;
        return Math.Max(auditExitCode, autoFixExitCode);
    }

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
        var host = Environment.GetEnvironmentVariable("VT_EMAIL_SMTP_HOST") ?? "localhost";
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
        return new EmailNotificationService(host, port, fromAddr, toAddr, user, pass, enableSsl);
    }

    private static INotificationService CreateWebhookService()
    {
        var url = Environment.GetEnvironmentVariable("VT_WEBHOOK_URL") ?? "http://localhost:8080/webhook";
        return new WebhookNotificationService(url);
    }

    private static string? ParseArg(string[] args, string key, string? defaultValue)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals(key, StringComparison.OrdinalIgnoreCase))
            {
                var val = args[i + 1];
                return val.StartsWith("--", StringComparison.Ordinal) ? defaultValue : val;
            }
        }
        return defaultValue;
    }

    private static bool TryParseArg(string[] args, string key, out string? value)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals(key, StringComparison.OrdinalIgnoreCase))
            {
                var val = args[i + 1];
                if (!val.StartsWith("--", StringComparison.Ordinal))
                {
                    value = val;
                    return true;
                }
            }
        }
        value = null;
        return false;
    }

    private static bool HasFlag(string[] args, string flag)
    {
        return args.Any(a => a.Equals(flag, StringComparison.OrdinalIgnoreCase));
    }

    private static int PrintError(string message)
    {
        Console.Error.WriteLine($"Error: {message}");
        Console.Error.WriteLine();
        PrintHelp();
        return 1;
    }

    private static void PrintHelp()
    {
        Console.WriteLine("VulcansTrace Linux Edition - CLI");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  vulcanstrace audit --intent <intent> [--output-json <file>] [--notify-on-critical] [--role <role>] [--auto-fix [--dry-run] [--yes] [--allow-restart] [--allow-packages]]");
        Console.WriteLine("  vulcanstrace schedule list");
        Console.WriteLine("  vulcanstrace schedule add --name <name> --intent <intent> --cron <expr> [--role <role>] [--channel Desktop|Email|Webhook] [--notify-on-critical] [--output-dir <dir>]");
        Console.WriteLine("  vulcanstrace schedule edit --id <id> [--name <name>] [--intent <intent>] [--cron <expr>] [--role <role>] [--channel <ch>] [--output-dir <dir>] [--notify-on-critical|--no-notify-on-critical] [--enabled|--disabled]");
        Console.WriteLine("  vulcanstrace schedule delete --id <id>");
        Console.WriteLine("  vulcanstrace schedule enable --id <id>");
        Console.WriteLine("  vulcanstrace schedule disable --id <id>");
        Console.WriteLine("  vulcanstrace schedule install-cron --id <id> [--exe-path <path>]");
        Console.WriteLine("  vulcanstrace schedule uninstall-cron --id <id>");
        Console.WriteLine("  vulcanstrace schedule run --id <id>");
        Console.WriteLine("  vulcanstrace session list");
        Console.WriteLine("  vulcanstrace session show --id <id>");
        Console.WriteLine("  vulcanstrace session delete --id <id>");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --intent <name>            Audit intent (FullAudit, FirewallCheck, PortCheck, etc.)");
        Console.WriteLine("  --output-json <file>       Write the full AgentResult to a JSON file");
        Console.WriteLine("  --output-mitre <file>      Write the MITRE ATT&CK Navigator layer JSON");
        Console.WriteLine("  --notify-on-critical       Send a notification if critical findings are found");
        Console.WriteLine("  --no-notify-on-critical    Disable critical notifications (edit only)");
        Console.WriteLine("  --role <role>              Machine role: Workstation, Server, LabBox, Router, DevMachine");
        Console.WriteLine("  --channel <ch>             Notification channel: Desktop, Email, Webhook");
        Console.WriteLine("  --output-dir <dir>         Directory to write scheduled audit JSON results");
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
        Console.WriteLine();
        Console.WriteLine("Exit codes:");
        Console.WriteLine("  0  Success (no critical findings)");
        Console.WriteLine("  1  Error");
        Console.WriteLine("  2  Success with critical findings");
        Console.WriteLine("  3  Auto-fix executed but some commands failed");
    }
}
