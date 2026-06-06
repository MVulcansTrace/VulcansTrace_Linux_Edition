using System.Runtime.CompilerServices;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Live;

namespace VulcansTrace.Linux.Engine.Live;

/// <summary>
/// Generates realistic synthetic firewall events for demonstration and testing.
/// No privileges required. Simulates normal traffic, port scans, beaconing, and floods.
/// </summary>
public sealed class SyntheticEventSource : IEventSource
{
    private readonly Random _rng;
    private readonly SyntheticPatterns _patterns;

    public string DisplayName => "Synthetic Demo Stream";

    public bool IsAvailable => true;

    public string? UnavailabilityReason => null;

    public SyntheticEventSource(SyntheticPatterns? patterns = null, int? seed = null)
    {
        _rng = seed.HasValue ? new Random(seed.Value) : new Random();
        _patterns = patterns ?? new SyntheticPatterns();
    }

    public async IAsyncEnumerable<UnifiedEvent> StreamAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var normalIps = new[] { "192.168.1.10", "192.168.1.11", "192.168.1.12", "10.0.0.5", "10.0.0.6" };
        var attackIps = new[] { "10.99.99.100", "172.16.0.77" };
        var services = new[] { 22, 80, 443, 53, 3306, 5432, 8080, 8443 };
        var highPorts = Enumerable.Range(30000, 35535).ToArray();

        int eventCounter = 0;
        var startTime = DateTime.UtcNow;

        // Beaconing state
        var beaconNextTime = startTime + TimeSpan.FromSeconds(_patterns.BeaconInitialDelaySeconds);
        var beaconSource = _patterns.FixedAttackSourceIp ?? attackIps[0];
        var beaconDest = _patterns.BeaconDestinationIp;
        var beaconPort = 443;

        while (!cancellationToken.IsCancellationRequested)
        {
            var now = DateTime.UtcNow;
            var elapsed = now - startTime;

            // Determine which pattern to emit this iteration
            double roll = _rng.NextDouble();

            if (_patterns.PortScanEnabled &&
                elapsed >= _patterns.PortScanStart &&
                elapsed <= _patterns.PortScanEnd &&
                roll < _patterns.PortScanProbability)
            {
                // Emit a port-scan burst
                var attacker = _patterns.FixedAttackSourceIp ?? attackIps[_rng.Next(attackIps.Length)];
                var target = _patterns.FixedTargetIp ?? normalIps[_rng.Next(normalIps.Length)];
                int portsInBurst = _rng.Next(3, 8);
                for (int i = 0; i < portsInBurst; i++)
                {
                    yield return CreateEvent(
                        now.AddMilliseconds(_rng.Next(50)),
                        attacker,
                        _rng.Next(40000, 60000),
                        target,
                        highPorts[_rng.Next(highPorts.Length)],
                        "TCP",
                        "SYN",
                        "DROP",
                        PickTtl(_rng));
                }
            }
            else if (_patterns.BeaconingEnabled && now >= beaconNextTime)
            {
                // Emit beacon event
                yield return CreateEvent(
                    now,
                    beaconSource,
                    _rng.Next(40000, 60000),
                    beaconDest,
                    beaconPort,
                    "TCP",
                    "SYN",
                    "DROP",
                    PickTtl(_rng));

                var jitter = _patterns.BeaconJitterSeconds <= 0
                    ? 0
                    : (_rng.NextDouble() * 2 * _patterns.BeaconJitterSeconds) - _patterns.BeaconJitterSeconds;
                beaconNextTime = now + TimeSpan.FromSeconds(_patterns.BeaconIntervalSeconds + jitter);
            }
            else if (_patterns.AdminPortSweepEnabled &&
                     elapsed >= _patterns.AdminPortSweepStart &&
                     elapsed <= _patterns.AdminPortSweepEnd &&
                     roll < _patterns.AdminPortSweepProbability)
            {
                // Emit admin-port sweep burst
                var attacker = _patterns.FixedAttackSourceIp ?? attackIps[_rng.Next(attackIps.Length)];
                var target = _patterns.FixedTargetIp ?? normalIps[_rng.Next(normalIps.Length)];
                int portsInBurst = _rng.Next(_patterns.AdminPortSweepMinEventsPerBurst, _patterns.AdminPortSweepMaxEventsPerBurst + 1);
                for (int i = 0; i < portsInBurst; i++)
                {
                    var adminPort = _patterns.AdminPorts[(eventCounter + i) % _patterns.AdminPorts.Length];
                    yield return CreateEvent(
                        now.AddMilliseconds(_rng.Next(50)),
                        attacker,
                        _rng.Next(40000, 60000),
                        target,
                        adminPort,
                        "TCP",
                        "SYN",
                        "DROP",
                        PickTtl(_rng));
                }
            }
            else if (_patterns.TargetedFloodEnabled &&
                     elapsed >= _patterns.TargetedFloodStart &&
                     elapsed <= _patterns.TargetedFloodEnd &&
                     roll < _patterns.TargetedFloodProbability)
            {
                // Emit targeted flood burst
                var attacker = _patterns.FixedAttackSourceIp ?? attackIps[_rng.Next(attackIps.Length)];
                var target = _patterns.FixedTargetIp ?? normalIps[_rng.Next(normalIps.Length)];
                int burst = _rng.Next(15, 25);
                for (int i = 0; i < burst; i++)
                {
                    yield return CreateEvent(
                        now.AddMilliseconds(_rng.Next(20)),
                        attacker,
                        _rng.Next(40000, 60000),
                        target,
                        _patterns.TargetedFloodPort,
                        "TCP",
                        "SYN",
                        "DROP",
                        PickTtl(_rng));
                }
            }
            else if (_patterns.FloodEnabled &&
                     elapsed >= _patterns.FloodStart &&
                     elapsed <= _patterns.FloodEnd &&
                     roll < _patterns.FloodProbability)
            {
                // Emit flood burst
                var attacker = _patterns.FixedAttackSourceIp ?? attackIps[_rng.Next(attackIps.Length)];
                var target = _patterns.FixedTargetIp ?? normalIps[_rng.Next(normalIps.Length)];
                int burst = _rng.Next(5, 15);
                for (int i = 0; i < burst; i++)
                {
                    yield return CreateEvent(
                        now.AddMilliseconds(_rng.Next(20)),
                        attacker,
                        _rng.Next(40000, 60000),
                        target,
                        services[_rng.Next(services.Length)],
                        "TCP",
                        "SYN",
                        "DROP",
                        PickTtl(_rng));
                }
            }
            else if (_patterns.BackgroundTrafficEnabled)
            {
                // Normal background traffic
                yield return CreateEvent(
                    now,
                    normalIps[_rng.Next(normalIps.Length)],
                    _rng.Next(40000, 60000),
                    normalIps[_rng.Next(normalIps.Length)],
                    services[_rng.Next(services.Length)],
                    _rng.NextDouble() > 0.3 ? "TCP" : "UDP",
                    "SYN",
                    _rng.NextDouble() > 0.1 ? "ACCEPT" : "DROP",
                    PickTtl(_rng));
            }

            eventCounter++;

            // Throttle to avoid spinning too fast; enforce a 1 ms floor so
            // EventDelayMs = 0 cannot create a busy-loop.
            await Task.Delay(Math.Max(1, _patterns.EventDelayMs), cancellationToken).ConfigureAwait(false);
        }
    }

    private static byte PickTtl(Random rng)
    {
        // Realistic distribution: Linux (64), Windows (128), routers (255),
        // and decremented values for routed traffic.
        double roll = rng.NextDouble();
        return roll switch
        {
            < 0.40 => 64,
            < 0.55 => 128,
            < 0.65 => 255,
            < 0.75 => (byte)(64 - rng.Next(1, 4)),
            < 0.85 => (byte)(128 - rng.Next(1, 4)),
            < 0.93 => (byte)(255 - rng.Next(1, 6)),
            _ => (byte)rng.Next(32, 128)
        };
    }

    private static UnifiedEvent CreateEvent(
        DateTime timestamp,
        string srcIp, int srcPort,
        string dstIp, int dstPort,
        string protocol, string flags, string action, byte ttl)
    {
        var linuxSpecific = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["FLAGS"] = flags,
            ["LEN"] = "60",
            ["TTL"] = ttl.ToString(),
            ["MAC"] = "00:00:00:00:00:00"
        };

        return new UnifiedEvent
        {
            Timestamp = timestamp,
            SourceIP = srcIp,
            SourcePort = srcPort,
            DestinationIP = dstIp,
            DestinationPort = dstPort,
            Protocol = protocol,
            Action = action,
            LogFormat = LogFormat.Iptables,
            LinuxSpecific = linuxSpecific
        };
    }
}

/// <summary>
/// Configuration for synthetic event generation patterns.
/// </summary>
public sealed record SyntheticPatterns
{
    /// <summary>Delay between individual synthetic events in milliseconds.</summary>
    public int EventDelayMs { get; init; } = 200;

    /// <summary>Whether to simulate port scan bursts.</summary>
    public bool PortScanEnabled { get; init; } = true;

    /// <summary>Time after start when port scan begins.</summary>
    public TimeSpan PortScanStart { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Time after start when port scan ends.</summary>
    public TimeSpan PortScanEnd { get; init; } = TimeSpan.FromSeconds(45);

    /// <summary>Probability per tick of emitting a port-scan burst.</summary>
    public double PortScanProbability { get; init; } = 0.15;

    /// <summary>Whether to simulate beaconing.</summary>
    public bool BeaconingEnabled { get; init; } = true;

    /// <summary>Base interval between beacon events in seconds.</summary>
    public double BeaconIntervalSeconds { get; init; } = 12.0;

    /// <summary>Delay before the first beacon event.</summary>
    public double BeaconInitialDelaySeconds { get; init; } = 12.0;

    /// <summary>Maximum positive or negative jitter added to beacon intervals.</summary>
    public double BeaconJitterSeconds { get; init; } = 1.0;

    /// <summary>Destination used for beaconing. Defaults to a public resolver so BeaconingDetector can classify it as external.</summary>
    public string BeaconDestinationIp { get; init; } = "8.8.8.8";

    /// <summary>Whether to simulate flood bursts.</summary>
    public bool FloodEnabled { get; init; } = true;

    /// <summary>Time after start when flood begins.</summary>
    public TimeSpan FloodStart { get; init; } = TimeSpan.FromSeconds(20);

    /// <summary>Time after start when flood ends.</summary>
    public TimeSpan FloodEnd { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Probability per tick of emitting a flood burst.</summary>
    public double FloodProbability { get; init; } = 0.08;

    /// <summary>Whether to emit benign filler events when no attack pattern fires.</summary>
    public bool BackgroundTrafficEnabled { get; init; } = true;

    /// <summary>Optional fixed attacker IP for deterministic scenario demos.</summary>
    public string? FixedAttackSourceIp { get; init; }

    /// <summary>Optional fixed target IP for deterministic scenario demos.</summary>
    public string? FixedTargetIp { get; init; }

    // Admin port sweep

    /// <summary>Whether to simulate admin-port sweep bursts.</summary>
    public bool AdminPortSweepEnabled { get; init; } = false;

    /// <summary>Time after start when admin-port sweep begins.</summary>
    public TimeSpan AdminPortSweepStart { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Time after start when admin-port sweep ends.</summary>
    public TimeSpan AdminPortSweepEnd { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Probability per tick of emitting an admin-port sweep burst.</summary>
    public double AdminPortSweepProbability { get; init; } = 0.2;

    /// <summary>Admin ports to sweep.</summary>
    public int[] AdminPorts { get; init; } = new[] { 22, 3389, 5900, 5432, 3306 };

    /// <summary>Minimum events emitted per admin-port sweep burst.</summary>
    public int AdminPortSweepMinEventsPerBurst { get; init; } = 3;

    /// <summary>Maximum events emitted per admin-port sweep burst.</summary>
    public int AdminPortSweepMaxEventsPerBurst { get; init; } = 5;

    // Targeted flood

    /// <summary>Whether to simulate targeted flood bursts.</summary>
    public bool TargetedFloodEnabled { get; init; } = false;

    /// <summary>Target port for the flood burst.</summary>
    public int TargetedFloodPort { get; init; } = 22;

    /// <summary>Time after start when targeted flood begins.</summary>
    public TimeSpan TargetedFloodStart { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Time after start when targeted flood ends.</summary>
    public TimeSpan TargetedFloodEnd { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Probability per tick of emitting a targeted flood burst.</summary>
    public double TargetedFloodProbability { get; init; } = 0.25;
}
