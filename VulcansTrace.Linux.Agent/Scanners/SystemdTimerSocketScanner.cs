using System.Text.RegularExpressions;

namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans systemd timer and socket units using systemctl.
/// </summary>
public sealed class SystemdTimerSocketScanner : IScanner
{
    /// <inheritdoc />
    public string Name => "SystemdTimerSocket";

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var (unitOutput, unitError, unitOk) = await RunCommandAsync("systemctl", new[]
        {
            "list-units",
            "--type=timer,socket",
            "--all",
            "--no-pager",
            "--no-legend"
        }, cancellationToken);

        var unitStatus = DataSourceCapability.FromCommandResult(unitOk, unitOutput, unitError);
        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "systemctl timer/socket units",
            Status = unitStatus,
            Detail = unitError,
            Command = "systemctl list-units --type=timer,socket --all --no-pager --no-legend"
        });

        if (unitStatus == CapabilityStatus.PermissionLimited)
        {
            builder.AddWarning("Systemd timer/socket scan skipped: permission denied.");
            builder.SetSystemdTimerSocketConfig(new SystemdTimerSocketConfig { ConfigReadable = false });
            return;
        }

        if (!unitOk)
        {
            builder.AddWarning($"Systemd timer/socket scan skipped: 'systemctl' is not available (non-systemd system?). {unitError}");
            builder.SetSystemdTimerSocketConfig(new SystemdTimerSocketConfig { ConfigReadable = false, ReadWarning = unitError });
            return;
        }

        var (timerOutput, timerError, timerOk) = await RunCommandAsync("systemctl", new[]
        {
            "list-timers",
            "--all",
            "--no-pager",
            "--no-legend"
        }, cancellationToken);

        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "systemctl list-timers",
            Status = DataSourceCapability.FromCommandResult(timerOk, timerOutput, timerError),
            Detail = timerError,
            Command = "systemctl list-timers --all --no-pager --no-legend"
        });

        var (socketOutput, socketError, socketOk) = await RunCommandAsync("systemctl", new[]
        {
            "list-sockets",
            "--no-pager",
            "--no-legend"
        }, cancellationToken);

        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "systemctl list-sockets",
            Status = DataSourceCapability.FromCommandResult(socketOk, socketOutput, socketError),
            Detail = socketError,
            Command = "systemctl list-sockets --no-pager --no-legend"
        });

        var timers = new List<SystemdTimer>();
        var sockets = new List<SystemdSocket>();

        ParseUnitOutput(unitOutput, timers, sockets);
        ParseTimerOutput(timerOutput, timers);
        ParseSocketOutput(socketOutput, sockets);

        // Resolve each timer's *configured* frequency from its unit definition. The list-timers
        // LEFT/PASSED columns are next-fire/last-fire times, not the schedule, so deriving an
        // interval from them both mislabels the value and flags timers based on when they last
        // ran. `systemctl show` exposes OnUnitActiveSec (monotonic repeat) and OnCalendar.
        if (timers.Count > 0)
        {
            var timerNames = timers
                .Select(t => t.Name)
                .Where(n => !string.IsNullOrWhiteSpace(n))
                .ToArray();

            if (timerNames.Length > 0)
            {
                var showArgs = new[]
                {
                    "show", "--no-pager",
                    "-p", "Id",
                    "-p", "TimersMonotonic",
                    "-p", "TimersCalendar",
                    "-p", "OnActiveSec",
                    "-p", "OnBootSec",
                    "-p", "OnStartupSec",
                    "-p", "OnUnitActiveSec",
                    "-p", "OnUnitInactiveSec",
                    "-p", "OnUnitSec",
                    "-p", "OnCalendar"
                }.Concat(timerNames).ToArray();

                var (showOutput, showError, showOk) = await RunCommandAsync("systemctl", showArgs, cancellationToken);

                builder.AddCapability(new DataSourceCapability
                {
                    SourceName = "systemctl show timers",
                    Status = DataSourceCapability.FromCommandResult(showOk, showOutput, showError),
                    Detail = showError,
                    Command = "systemctl show -p TimersMonotonic -p TimersCalendar -- *.timer"
                });

                if (showOk && !string.IsNullOrWhiteSpace(showOutput))
                {
                    var intervals = ParseTimerIntervalsFromShow(showOutput);
                    for (int i = 0; i < timers.Count; i++)
                    {
                        if (!string.IsNullOrWhiteSpace(timers[i].Name) &&
                            intervals.TryGetValue(timers[i].Name, out var interval) &&
                            !string.IsNullOrWhiteSpace(interval))
                        {
                            timers[i] = timers[i] with { Interval = interval };
                        }
                    }
                }
            }
        }

        builder.SetSystemdTimerSocketConfig(new SystemdTimerSocketConfig
        {
            ConfigReadable = true,
            Timers = timers,
            Sockets = sockets
        });
    }

    internal static void ParseUnitOutput(string? output, List<SystemdTimer> timers, List<SystemdSocket> sockets)
    {
        if (string.IsNullOrWhiteSpace(output))
            return;

        var lines = output.Split('\n');
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line))
                continue;

            var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4)
                continue;

            var unitName = parts[0];
            var loadState = parts[1];
            var activeState = parts[2];
            var subState = parts[3];

            if (unitName.EndsWith(".timer", StringComparison.OrdinalIgnoreCase))
            {
                timers.Add(new SystemdTimer
                {
                    Name = unitName,
                    Active = activeState.Equals("active", StringComparison.OrdinalIgnoreCase),
                    TriggerUnit = InferTriggerUnit(unitName),
                    NextTrigger = ""
                });
            }
            else if (unitName.EndsWith(".socket", StringComparison.OrdinalIgnoreCase))
            {
                sockets.Add(new SystemdSocket
                {
                    Name = unitName,
                    Listening = activeState.Equals("active", StringComparison.OrdinalIgnoreCase) && subState.Equals("listening", StringComparison.OrdinalIgnoreCase),
                    TriggerUnit = InferTriggerUnit(unitName),
                    ListenAddress = ""
                });
            }
        }
    }

    internal static void ParseTimerOutput(string? output, List<SystemdTimer> timers)
    {
        if (string.IsNullOrWhiteSpace(output))
            return;

        var byName = timers.ToDictionary(t => t.Name, StringComparer.OrdinalIgnoreCase);

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line))
                continue;

            // Format: NEXT LEFT LAST PASSED UNIT ACTIVATES
            // The unit name is the second-to-last token and the activated service the last.
            // (The LEFT/PASSED columns are next/last fire times, not the configured schedule,
            // so the interval is resolved separately from `systemctl show`.)
            var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 7)
                continue;

            var unitName = parts[^2];
            var triggerUnit = parts[^1];

            if (!unitName.EndsWith(".timer", StringComparison.OrdinalIgnoreCase))
                continue;

            if (byName.TryGetValue(unitName, out var existing))
            {
                var index = timers.IndexOf(existing);
                timers[index] = existing with { TriggerUnit = triggerUnit };
            }
            else
            {
                timers.Add(new SystemdTimer
                {
                    Name = unitName,
                    TriggerUnit = triggerUnit
                });
            }
        }
    }

    internal static void ParseSocketOutput(string? output, List<SystemdSocket> sockets)
    {
        if (string.IsNullOrWhiteSpace(output))
            return;

        var byName = sockets.ToDictionary(s => s.Name, StringComparer.OrdinalIgnoreCase);
        var lines = output.Split('\n');

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line))
                continue;

            // Format: LISTEN UNIT ACTIVATES
            // e.g., "/run/systemd/journal/dev-log systemd-journald-dev-log.socket systemd-journald.service"
            var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 3)
                continue;

            var listenAddress = parts[0];
            var unitName = parts[1];
            var triggerUnit = parts[2];

            if (!unitName.EndsWith(".socket", StringComparison.OrdinalIgnoreCase))
                continue;

            if (byName.TryGetValue(unitName, out var existing))
            {
                var index = sockets.IndexOf(existing);
                var updated = existing with
                {
                    Listening = true,
                    TriggerUnit = triggerUnit,
                    ListenAddress = MergeListenAddresses(existing.ListenAddress, listenAddress)
                };
                sockets[index] = updated;
                byName[unitName] = updated;
            }
            else
            {
                var socket = new SystemdSocket
                {
                    Name = unitName,
                    Listening = true,
                    TriggerUnit = triggerUnit,
                    ListenAddress = listenAddress
                };
                sockets.Add(socket);
                byName[unitName] = socket;
            }
        }
    }

    private static string MergeListenAddresses(string? existing, string current)
    {
        if (string.IsNullOrWhiteSpace(existing))
            return current;
        if (string.IsNullOrWhiteSpace(current))
            return existing;

        var addresses = existing
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();
        if (!addresses.Contains(current, StringComparer.OrdinalIgnoreCase))
            addresses.Add(current);

        return string.Join("; ", addresses);
    }

    internal static string? InferTriggerUnit(string unitName)
    {
        if (unitName.EndsWith(".timer", StringComparison.OrdinalIgnoreCase))
            return unitName.Substring(0, unitName.Length - ".timer".Length) + ".service";

        if (unitName.EndsWith(".socket", StringComparison.OrdinalIgnoreCase))
            return unitName.Substring(0, unitName.Length - ".socket".Length) + ".service";

        return null;
    }

    internal static bool IsShortInterval(string interval)
    {
        if (string.IsNullOrWhiteSpace(interval))
            return false;

        var value = interval.Trim();
        if (value.Equals("n/a", StringComparison.OrdinalIgnoreCase))
            return false;

        // `systemctl show` can emit a time span as a bare microsecond count.
        if (long.TryParse(value, out var micros))
            return micros > 0 && micros < 60_000_000;

        // Otherwise parse a systemd duration ("30s", "1min 30s", "500ms", ...) by summing
        // every token. A configured repeat < 60s is what makes a timer "sub-minute".
        var totalMicros = SumDurationMicroseconds(value);
        if (totalMicros.HasValue)
            return totalMicros.GetValueOrDefault() < 60_000_000;

        // OnCalendar keyword / spec: "minutely" is exactly once per minute (the threshold);
        // anything coarser is longer. Arbitrary calendar specs can't be reliably classified
        // for sub-minute frequency without a full calendar parser, so treat them conservatively
        // (never false-positive) rather than guess.
        return false;
    }

    private static readonly Regex DurationTokenRegex = new(
        @"(\d+)\s*(microseconds|microsecond|milliseconds|millisecond|msecs|msec|ms|µs|usec|us|seconds|second|secs|sec|s|minutes|minute|mins|min|m|hours|hour|hrs|hr|h|days|day|d|weeks|week|w|months|month|y|years|year)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Sums every &lt;number&gt;&lt;unit&gt; token in a systemd time span into microseconds.
    /// Returns null when the string contains no recognizable duration tokens.
    /// </summary>
    internal static long? SumDurationMicroseconds(string value)
    {
        var matches = DurationTokenRegex.Matches(value);
        if (matches.Count == 0)
            return null;

        long total = 0;
        foreach (Match m in matches)
        {
            if (!long.TryParse(m.Groups[1].Value, out var amount))
                return null;
            total += amount * UnitToMicroseconds(m.Groups[2].Value.ToLowerInvariant());
        }
        return total;
    }

    private static long UnitToMicroseconds(string unit) => unit switch
    {
        "us" or "µs" or "usec" or "microsecond" or "microseconds" => 1L,
        "ms" or "msec" or "msecs" or "millisecond" or "milliseconds" => 1_000L,
        "s" or "sec" or "secs" or "second" or "seconds" => 1_000_000L,
        "m" or "min" or "mins" or "minute" or "minutes" => 60_000_000L,
        "h" or "hr" or "hrs" or "hour" or "hours" => 3_600_000_000L,
        "d" or "day" or "days" => 86_400_000_000L,
        "w" or "week" or "weeks" => 604_800_000_000L,
        "month" or "months" => 2_592_000_000_000L, // 30 days
        "y" or "year" or "years" => 31_536_000_000_000L,
        _ => 0L
    };

    /// <summary>
    /// Parses multi-unit <c>systemctl show</c> output (with an <c>Id=</c> line per unit) into a
    /// map of unit name to its configured frequency string (the repeat interval or calendar spec).
    /// </summary>
    internal static IReadOnlyDictionary<string, string> ParseTimerIntervalsFromShow(string? output)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(output))
            return result;

        string? currentId = null;
        string? onActive = null;
        string? onBoot = null;
        string? onStartup = null;
        string? onUnitActive = null;
        string? onUnitInactive = null;
        string? onUnitSec = null;
        string? onCalendar = null;
        string? timersMonotonic = null;
        string? timersCalendar = null;

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0)
                continue;

            var eq = line.IndexOf('=');
            if (eq <= 0)
                continue;

            var key = line.Substring(0, eq);
            var val = line.Substring(eq + 1).Trim();

            if (key.Equals("Id", StringComparison.Ordinal))
            {
                if (currentId != null)
                {
                    result[currentId] = ResolveTimerInterval(
                        new[] { onActive, onBoot, onStartup, onUnitActive, onUnitInactive, onUnitSec },
                        onCalendar,
                        timersMonotonic,
                        timersCalendar);
                }
                currentId = val;
                onActive = onBoot = onStartup = onUnitActive = onUnitInactive = onUnitSec = onCalendar = null;
                timersMonotonic = timersCalendar = null;
            }
            else if (currentId != null)
            {
                if (key.Equals("OnActiveSec", StringComparison.Ordinal))
                    onActive = val;
                else if (key.Equals("OnBootSec", StringComparison.Ordinal))
                    onBoot = val;
                else if (key.Equals("OnStartupSec", StringComparison.Ordinal))
                    onStartup = val;
                else if (key.Equals("OnUnitActiveSec", StringComparison.Ordinal))
                    onUnitActive = val;
                else if (key.Equals("OnUnitInactiveSec", StringComparison.Ordinal))
                    onUnitInactive = val;
                else if (key.Equals("OnUnitSec", StringComparison.Ordinal))
                    onUnitSec = val;
                else if (key.Equals("OnCalendar", StringComparison.Ordinal))
                    onCalendar = val;
                else if (key.Equals("TimersMonotonic", StringComparison.Ordinal))
                    timersMonotonic = val;
                else if (key.Equals("TimersCalendar", StringComparison.Ordinal))
                    timersCalendar = val;
            }
        }

        if (currentId != null)
        {
            result[currentId] = ResolveTimerInterval(
                new[] { onActive, onBoot, onStartup, onUnitActive, onUnitInactive, onUnitSec },
                onCalendar,
                timersMonotonic,
                timersCalendar);
        }

        return result;
    }

    /// <summary>
    /// Picks the most meaningful configured-frequency value: the monotonic repeat interval
    /// (OnUnitActiveSec, then its OnUnitSec alias) before the OnCalendar schedule. Empty/infinity
    /// spans and a literal "0" calendar are treated as "no configured repeat".
    /// </summary>
    internal static string ResolveTimerInterval(string? onUnitActiveSec, string? onUnitSec, string? onCalendar)
    {
        return ResolveTimerInterval(new[] { onUnitActiveSec, onUnitSec }, onCalendar, null, null);
    }

    private static string ResolveTimerInterval(
        IEnumerable<string?> monotonicCandidates,
        string? onCalendar,
        string? timersMonotonic,
        string? timersCalendar)
    {
        var allMonotonicCandidates = monotonicCandidates
            .Concat(ExtractTimerPropertyValues(timersMonotonic, @"\bOn[A-Za-z]+Sec=([^;}\r\n]+)"));

        var monotonic = PickShortestConfiguredSpan(allMonotonicCandidates);
        if (!string.IsNullOrWhiteSpace(monotonic))
            return monotonic;

        var calendar = FirstConfiguredCalendar(onCalendar, timersCalendar);
        if (!string.IsNullOrWhiteSpace(calendar))
            return calendar;

        return "";
    }

    private static bool IsConfiguredSpan(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;
        // "infinity" means the timer fires once and does not repeat — not a periodic interval.
        var trimmed = value.Trim();
        return !trimmed.Equals("infinity", StringComparison.OrdinalIgnoreCase) &&
               !trimmed.Equals("0", StringComparison.OrdinalIgnoreCase);
    }

    private static string PickShortestConfiguredSpan(IEnumerable<string?> candidates)
    {
        string? fallback = null;
        string? shortest = null;
        long? shortestMicros = null;

        foreach (var candidate in candidates)
        {
            if (!IsConfiguredSpan(candidate))
                continue;

            var trimmed = candidate!.Trim();
            fallback ??= trimmed;

            var micros = long.TryParse(trimmed, out var rawMicros)
                ? rawMicros
                : SumDurationMicroseconds(trimmed);
            if (!micros.HasValue)
                continue;

            if (!shortestMicros.HasValue || micros.Value < shortestMicros.Value)
            {
                shortestMicros = micros.Value;
                shortest = trimmed;
            }
        }

        return shortest ?? fallback ?? "";
    }

    private static string FirstConfiguredCalendar(string? onCalendar, string? timersCalendar)
    {
        if (!string.IsNullOrWhiteSpace(onCalendar) &&
            !onCalendar.Trim().Equals("0", StringComparison.OrdinalIgnoreCase))
        {
            return onCalendar.Trim();
        }

        return ExtractTimerPropertyValues(timersCalendar, @"\bOnCalendar=([^;}\r\n]+)")
            .FirstOrDefault(v => !string.IsNullOrWhiteSpace(v) &&
                                 !v.Trim().Equals("0", StringComparison.OrdinalIgnoreCase))
            ?.Trim() ?? "";
    }

    private static IEnumerable<string> ExtractTimerPropertyValues(string? value, string pattern)
    {
        if (string.IsNullOrWhiteSpace(value))
            yield break;

        foreach (Match match in Regex.Matches(value, pattern, RegexOptions.IgnoreCase))
        {
            var propertyValue = match.Groups[1].Value.Trim();
            if (!string.IsNullOrWhiteSpace(propertyValue))
                yield return propertyValue;
        }
    }

    internal static bool IsPublicListenAddress(string listenAddress)
    {
        if (string.IsNullOrWhiteSpace(listenAddress))
            return false;

        var lowered = listenAddress.ToLowerInvariant();
        return lowered.Contains("0.0.0.0") || lowered.Contains("[::]") || lowered.Contains(":::") || lowered.Contains("*:");
    }

    private static async Task<(string? Stdout, string? Stderr, bool Success)> RunCommandAsync(
        string fileName, string[] args, CancellationToken ct)
    {
        return await ScannerCommandRunner.RunAsync(fileName, args, ct);
    }
}
