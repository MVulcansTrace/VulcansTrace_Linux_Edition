namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans logging and auditing subsystem configuration: rsyslog, journald, auditd,
/// log rotation, and central log forwarding.
/// </summary>
public sealed class LoggingAuditScanner : IScanner
{
    /// <inheritdoc />
    public string Name => "LoggingAudit";

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var rsyslogActive = await IsServiceActiveAsync("rsyslog", cancellationToken);
        var journaldActive = await IsServiceActiveAsync("systemd-journald", cancellationToken);
        var auditdActive = await IsServiceActiveAsync("auditd", cancellationToken);

        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "systemctl logging services",
            Status = CapabilityStatus.Available,
            Detail = $"rsyslog={rsyslogActive}, journald={journaldActive}, auditd={auditdActive}"
        });

        var (auditRules, auditRulesOk, auditRulesErr) = await ReadAuditdRulesAsync(cancellationToken);
        var auditRulesConfigured = auditRulesOk && auditRules.Count > 0;

        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "auditd rules",
            Status = auditRulesOk ? CapabilityStatus.Available : CapabilityStatus.Unavailable,
            Detail = auditRulesErr
        });

        var logRotationConfigured = CheckLogRotation();
        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "logrotate",
            Status = logRotationConfigured ? CapabilityStatus.Available : CapabilityStatus.Unavailable,
            Detail = logRotationConfigured ? "log rotation configured" : "no log rotation configuration found"
        });

        var (forwardingConfigured, forwardingTargets) = CheckCentralForwarding();
        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "log forwarding",
            Status = forwardingConfigured ? CapabilityStatus.Available : CapabilityStatus.Unavailable,
            Detail = forwardingConfigured ? $"targets: {string.Join(", ", forwardingTargets)}" : "no central forwarding configured"
        });

        builder.SetLoggingAuditConfig(new LoggingAuditConfig
        {
            RsyslogActive = rsyslogActive,
            JournaldActive = journaldActive,
            AuditdActive = auditdActive,
            AuditdRulesConfigured = auditRulesConfigured,
            LogRotationConfigured = logRotationConfigured,
            CentralForwardingConfigured = forwardingConfigured,
            AuditdRules = auditRules.ToArray(),
            ForwardingTargets = forwardingTargets.ToArray(),
            ReadWarning = auditRulesErr
        });
    }

    private static async Task<bool> IsServiceActiveAsync(string serviceName, CancellationToken ct)
    {
        var (output, _, ok) = await RunCommandAsync("systemctl", new[] { "is-active", serviceName }, ct);
        return ok && output?.Trim().Equals("active", StringComparison.OrdinalIgnoreCase) == true;
    }

    /// <summary>
    /// Determines whether an auditd configuration line is an actual audit rule
    /// (watch or syscall rule) rather than a control directive.
    /// </summary>
    internal static bool IsActualAuditdRule(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return false;

        var trimmed = line.Trim();
        if (trimmed.StartsWith('#'))
            return false;

        // Actual rules: -w (watch), -a / -A (add rule).
        // Control directives: -D, -b, -f, -e, -r, -i, -s, -c, --loginuid-immutable, etc.
        return trimmed.StartsWith("-w ", StringComparison.Ordinal) ||
               trimmed.StartsWith("-a ", StringComparison.Ordinal) ||
               trimmed.StartsWith("-A ", StringComparison.Ordinal);
    }

    internal static async Task<(List<string> Rules, bool Ok, string? Error)> ReadAuditdRulesAsync(CancellationToken ct)
    {
        // Prefer auditctl -l (shows live rules) but fall back to reading the rules file.
        var (output, error, ok) = await RunCommandAsync("auditctl", new[] { "-l" }, ct);
        if (ok && !string.IsNullOrWhiteSpace(output))
        {
            var rules = output.Split('\n')
                .Select(l => l.Trim())
                .Where(l => !string.IsNullOrWhiteSpace(l) && !l.StartsWith("No rules", StringComparison.OrdinalIgnoreCase))
                .Where(IsActualAuditdRule)
                .ToList();
            return (rules, true, null);
        }

        return await ReadAuditdRulesFromFileAsync("/etc/audit/audit.rules", error, ct);
    }

    internal static async Task<(List<string> Rules, bool Ok, string? Error)> ReadAuditdRulesFromFileAsync(
        string ruleFile, string? auditctlError, CancellationToken ct)
    {
        try
        {
            if (File.Exists(ruleFile))
            {
                var lines = await File.ReadAllLinesAsync(ruleFile, ct);
                var rules = lines
                    .Select(l => l.Trim())
                    .Where(IsActualAuditdRule)
                    .ToList();
                return (rules, true, null);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return (new List<string>(), false, ex.Message);
        }

        return (new List<string>(), false, auditctlError ?? $"auditctl not available and {ruleFile} not found");
    }

    internal static bool CheckLogRotation()
    {
        if (File.Exists("/etc/logrotate.conf"))
            return true;

        try
        {
            if (Directory.Exists("/etc/logrotate.d") && Directory.EnumerateFiles("/etc/logrotate.d").Any())
                return true;
        }
        catch
        {
            // ignore permission errors
        }

        return false;
    }

    // rsyslog directives that start with @ but are NOT forwarding targets.
    private static readonly HashSet<string> RsyslogKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "include", "version", "moduleload", "module", "begin", "end", "define",
        "ifdef", "ifndef", "else", "endif"
    };

    internal static bool IsForwardingTarget(string part)
    {
        if (string.IsNullOrEmpty(part))
            return false;

        string remainder;
        if (part.StartsWith("@@"))
            remainder = part[2..];
        else if (part.StartsWith('@'))
            remainder = part[1..];
        else
            return false;

        // Strip optional rsyslog action options: @(o)host
        if (remainder.StartsWith('('))
        {
            var closeParen = remainder.IndexOf(')');
            if (closeParen >= 0)
                remainder = remainder[(closeParen + 1)..];
        }

        if (string.IsNullOrEmpty(remainder))
            return false;

        // Reject known rsyslog directives like @include, @version, etc.
        var firstToken = remainder.Split(new[] { ':', '[', '/' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty;
        if (RsyslogKeywords.Contains(firstToken))
            return false;

        return true;
    }

    /// <summary>
    /// Parses a journald.conf line to detect ForwardToSyslog=yes,
    /// tolerating optional whitespace around the equals sign.
    /// </summary>
    internal static bool IsJournaldForwardToSyslogEnabled(string line)
    {
        if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
            return false;

        var parts = line.Split('=', 2);
        if (parts.Length != 2)
            return false;

        var key = parts[0].Trim();
        var value = parts[1].Trim();

        return key.Equals("ForwardToSyslog", StringComparison.OrdinalIgnoreCase) &&
               value.Equals("yes", StringComparison.OrdinalIgnoreCase);
    }

    internal static (bool Configured, List<string> Targets) CheckCentralForwarding()
    {
        var rsyslogPaths = new List<string>();
        if (File.Exists("/etc/rsyslog.conf"))
            rsyslogPaths.Add("/etc/rsyslog.conf");
        try
        {
            if (Directory.Exists("/etc/rsyslog.d"))
                rsyslogPaths.AddRange(Directory.EnumerateFiles("/etc/rsyslog.d", "*.conf"));
        }
        catch { /* ignore */ }

        return CheckCentralForwarding(rsyslogPaths, "/etc/systemd/journald.conf");
    }

    internal static (bool Configured, List<string> Targets) CheckCentralForwarding(
        IEnumerable<string> rsyslogPaths, string? journaldConfPath)
    {
        // Use a HashSet for deduplication — the same target may appear in
        // /etc/rsyslog.conf and again under /etc/rsyslog.d/*.conf.
        var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // rsyslog forwarding: @host (UDP), @@host (TCP), @@[ipv6]:port, @(o)host
        foreach (var path in rsyslogPaths)
        {
            try
            {
                foreach (var line in File.ReadLines(path))
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith('#') || string.IsNullOrWhiteSpace(trimmed))
                        continue;

                    // Scan every word on the line for forwarding targets.
                    // A forwarding directive can appear anywhere (e.g. "*.* @@192.168.1.1:514"),
                    // not just at the start of a line.
                    var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var part in parts)
                    {
                        if (IsForwardingTarget(part))
                            targets.Add(part);
                    }
                }
            }
            catch { /* ignore unreadable files */ }
        }

        // journald forwarding to syslog
        if (!string.IsNullOrEmpty(journaldConfPath))
        {
            try
            {
                if (File.Exists(journaldConfPath))
                {
                    foreach (var line in File.ReadLines(journaldConfPath))
                    {
                        var trimmed = line.Trim();
                        if (trimmed.StartsWith('#') || string.IsNullOrWhiteSpace(trimmed))
                            continue;

                        if (IsJournaldForwardToSyslogEnabled(trimmed))
                        {
                            targets.Add("journald:ForwardToSyslog=yes");
                        }
                    }
                }
            }
            catch { /* ignore */ }
        }

        return (targets.Count > 0, targets.ToList());
    }

    private static async Task<(string? Stdout, string? Stderr, bool Success)> RunCommandAsync(
        string fileName, string[] args, CancellationToken ct)
    {
        return await ScannerCommandRunner.RunAsync(fileName, args, ct);
    }
}
