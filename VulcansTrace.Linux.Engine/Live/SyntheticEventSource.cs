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
        var beaconNextTime = startTime + TimeSpan.FromSeconds(_patterns.BeaconIntervalSeconds);
        var beaconSource = attackIps[0];
        var beaconDest = normalIps[0];
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
                var attacker = attackIps[_rng.Next(attackIps.Length)];
                var target = normalIps[_rng.Next(normalIps.Length)];
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

                beaconNextTime = now + TimeSpan.FromSeconds(_patterns.BeaconIntervalSeconds + _rng.NextDouble() * 2 - 1);
            }
            else if (_patterns.FloodEnabled &&
                     elapsed >= _patterns.FloodStart &&
                     elapsed <= _patterns.FloodEnd &&
                     roll < _patterns.FloodProbability)
            {
                // Emit flood burst
                var attacker = attackIps[_rng.Next(attackIps.Length)];
                var target = normalIps[_rng.Next(normalIps.Length)];
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
            else
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

    /// <summary>Whether to simulate flood bursts.</summary>
    public bool FloodEnabled { get; init; } = true;

    /// <summary>Time after start when flood begins.</summary>
    public TimeSpan FloodStart { get; init; } = TimeSpan.FromSeconds(20);

    /// <summary>Time after start when flood ends.</summary>
    public TimeSpan FloodEnd { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Probability per tick of emitting a flood burst.</summary>
    public double FloodProbability { get; init; } = 0.08;
}
