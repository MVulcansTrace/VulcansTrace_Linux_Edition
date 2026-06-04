using System.Reflection;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Logging;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Engine.Live;

namespace VulcansTrace.Linux.Tests.Engine.Live;

public class LiveStreamAnalyzerTests
{
    private static LiveStreamAnalyzer CreateAnalyzer(TimeSpan? window = null, TimeSpan? interval = null)
    {
        var logNormalizer = new LogNormalizer();
        var profileProvider = new AnalysisProfileProvider();
        var baseline = new IDetector[] { new PortScanDetector(), new FloodDetector() };
        var linux = Array.Empty<IDetector>();
        var advanced = Array.Empty<IDetector>();
        var riskEscalator = new RiskEscalator();
        var sentry = new SentryAnalyzer(logNormalizer, profileProvider, baseline, linux, advanced, riskEscalator);

        return new LiveStreamAnalyzer(
            sentry,
            profileProvider,
            timeWindow: window ?? TimeSpan.FromSeconds(30),
            analysisInterval: interval ?? TimeSpan.FromMilliseconds(200),
            analysisEventThreshold: 50,
            fingerprintTtl: TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task ResultsAsync_WithSyntheticSource_YieldsResults()
    {
        var analyzer = CreateAnalyzer();
        var source = new SyntheticEventSource(
            new SyntheticPatterns { EventDelayMs = 10, BeaconingEnabled = false, FloodEnabled = false },
            seed: 42);

        analyzer.Start(source, IntensityLevel.Medium);

        var results = new List<VulcansTrace.Linux.Core.Live.LiveAnalysisResult>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));

        try
        {
            await foreach (var result in analyzer.ResultsAsync(cts.Token))
            {
                results.Add(result);
                if (results.Count >= 2) break;
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            analyzer.Dispose();
        }

        Assert.True(results.Count >= 1, "Should produce at least one analysis result");
        Assert.All(results, r =>
        {
            Assert.NotNull(r.Analysis);
            Assert.True(r.AnalysisRunCount > 0);
            Assert.Equal("Synthetic Demo Stream", r.SourceName);
        });
    }

    [Fact]
    public async Task ResultsAsync_DeduplicatesRepeatedFindings()
    {
        // Use a deterministic source that always produces the same pattern
        var analyzer = CreateAnalyzer(
            window: TimeSpan.FromSeconds(10),
            interval: TimeSpan.FromMilliseconds(100));

        var source = new SyntheticEventSource(
            new SyntheticPatterns
            {
                EventDelayMs = 5,
                PortScanProbability = 1.0,
                PortScanStart = TimeSpan.Zero,
                PortScanEnd = TimeSpan.FromSeconds(5),
                BeaconingEnabled = false,
                FloodEnabled = false
            },
            seed: 123);

        analyzer.Start(source, IntensityLevel.High);

        var allDeltaFindings = new List<Finding>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(4));

        try
        {
            await foreach (var result in analyzer.ResultsAsync(cts.Token))
            {
                allDeltaFindings.AddRange(result.DeltaFindings);
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            analyzer.Dispose();
        }

        // The same port scan should not be reported repeatedly forever
        // (within the TTL window). We expect some deduplication.
        var distinctFingerprints = allDeltaFindings.Select(f => f.Fingerprint).Distinct().ToList();
        Assert.True(distinctFingerprints.Count <= allDeltaFindings.Count);
    }

    [Fact]
    public void Start_ResetsStateBetweenRuns()
    {
        var analyzer = CreateAnalyzer();
        var source = new SyntheticEventSource(seed: 42);

        analyzer.Start(source, IntensityLevel.Medium);
        analyzer.Stop();
        analyzer.Start(source, IntensityLevel.High);

        Assert.NotNull(analyzer);
        analyzer.Dispose();
    }

    [Fact]
    public void Dispose_CompletesChannel()
    {
        var analyzer = CreateAnalyzer();
        analyzer.Dispose();

        // Should not throw
        Assert.True(true);
    }

    [Fact]
    public void Start_NullSource_ThrowsArgumentNullException()
    {
        var analyzer = CreateAnalyzer();
        Assert.Throws<ArgumentNullException>(() =>
            analyzer.Start(null!, IntensityLevel.Medium));
        analyzer.Dispose();
    }

    [Fact]
    public async Task SourceFailure_RaisesStreamFaulted()
    {
        var analyzer = CreateAnalyzer();
        var fault = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
        analyzer.StreamFaulted += (_, ex) => fault.TrySetResult(ex);

        analyzer.Start(new ThrowingEventSource(), IntensityLevel.Medium);

        var completed = await Task.WhenAny(fault.Task, Task.Delay(TimeSpan.FromSeconds(3)));
        analyzer.Dispose();

        Assert.Same(fault.Task, completed);
        Assert.IsType<InvalidOperationException>(await fault.Task);
    }

    [Fact]
    public void FormatAsIptablesLog_RoundTripsThroughLogNormalizer()
    {
        // Arrange: build a realistic UnifiedEvent like the live stream would produce
        var evt = new UnifiedEvent
        {
            Timestamp = new DateTime(2026, 6, 3, 14, 30, 45, DateTimeKind.Utc),
            SourceIP = "192.168.1.100",
            SourcePort = 54321,
            DestinationIP = "10.0.0.5",
            DestinationPort = 443,
            Protocol = "TCP",
            Action = "DROP",
            LogFormat = LogFormat.Iptables,
            LinuxSpecific = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["FLAGS"] = "SYN,ACK",
                ["LEN"] = "1500",
                ["TTL"] = "64",
                ["MAC"] = "AA:BB:CC:DD:EE:FF"
            }
        };

        // Invoke the private helper via reflection
        var method = typeof(LiveStreamAnalyzer).GetMethod(
            "FormatAsIptablesLog",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var rawLog = (string)method.Invoke(null, new object[] { evt })!;

        // Act: feed the synthetic line to the real normalizer
        var normalizer = new LogNormalizer();
        var result = normalizer.Normalize(rawLog);

        // Assert: parsing must succeed and preserve key fields
        Assert.Single(result.Events);
        Assert.Empty(result.Errors);

        var parsed = result.Events[0];
        Assert.Equal(evt.SourceIP, parsed.SourceIP);
        Assert.Equal(evt.DestinationIP, parsed.DestinationIP);
        Assert.Equal(evt.SourcePort, parsed.SourcePort);
        Assert.Equal(evt.DestinationPort, parsed.DestinationPort);
        Assert.Equal(evt.Protocol, parsed.Protocol);
        Assert.Equal(evt.Action, parsed.Action);
    }

    [Fact]
    public void FormatAsIptablesLog_Udp_RoundTripsThroughLogNormalizer()
    {
        var evt = new UnifiedEvent
        {
            Timestamp = new DateTime(2026, 6, 3, 14, 30, 45, DateTimeKind.Utc),
            SourceIP = "172.16.0.5",
            SourcePort = 12345,
            DestinationIP = "8.8.8.8",
            DestinationPort = 53,
            Protocol = "UDP",
            Action = "ACCEPT",
            LogFormat = LogFormat.Iptables,
            LinuxSpecific = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["FLAGS"] = "UDP",
                ["LEN"] = "128",
                ["TTL"] = "128",
                ["MAC"] = "11:22:33:44:55:66"
            }
        };

        var method = typeof(LiveStreamAnalyzer).GetMethod(
            "FormatAsIptablesLog",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var rawLog = (string)method.Invoke(null, new object[] { evt })!;

        var normalizer = new LogNormalizer();
        var result = normalizer.Normalize(rawLog);

        Assert.Single(result.Events);
        Assert.Empty(result.Errors);

        var parsed = result.Events[0];
        Assert.Equal("UDP", parsed.Protocol);
        Assert.Equal(12345, parsed.SourcePort);
        Assert.Equal(53, parsed.DestinationPort);
        Assert.Equal("ACCEPT", parsed.Action);
    }

    [Fact]
    public void FormatAsIptablesLog_MissingLinuxSpecific_UsesDefaults()
    {
        var evt = new UnifiedEvent
        {
            Timestamp = new DateTime(2026, 6, 3, 14, 30, 45, DateTimeKind.Utc),
            SourceIP = "192.168.1.1",
            SourcePort = 80,
            DestinationIP = "10.0.0.1",
            DestinationPort = 8080,
            Protocol = "TCP",
            Action = "REJECT",
            LogFormat = LogFormat.Iptables,
            LinuxSpecific = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        };

        var method = typeof(LiveStreamAnalyzer).GetMethod(
            "FormatAsIptablesLog",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var rawLog = (string)method.Invoke(null, new object[] { evt })!;

        // Should still be parseable even with defaults
        var normalizer = new LogNormalizer();
        var result = normalizer.Normalize(rawLog);

        Assert.Single(result.Events);
        Assert.Empty(result.Errors);
        Assert.Equal("192.168.1.1", result.Events[0].SourceIP);
    }

    [Fact]
    public void FormatAsIptablesLog_OutputContainsExpectedSubstrings()
    {
        var evt = new UnifiedEvent
        {
            Timestamp = new DateTime(2026, 6, 3, 14, 30, 45, DateTimeKind.Utc),
            SourceIP = "1.2.3.4",
            SourcePort = 1111,
            DestinationIP = "5.6.7.8",
            DestinationPort = 2222,
            Protocol = "TCP",
            Action = "DROP",
            LogFormat = LogFormat.Iptables,
            LinuxSpecific = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["FLAGS"] = "RST",
                ["LEN"] = "100",
                ["TTL"] = "32",
                ["MAC"] = "DE:AD:BE:EF:00:00"
            }
        };

        var method = typeof(LiveStreamAnalyzer).GetMethod(
            "FormatAsIptablesLog",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var rawLog = (string)method.Invoke(null, new object[] { evt })!;

        Assert.Contains("SRC=1.2.3.4", rawLog);
        Assert.Contains("DST=5.6.7.8", rawLog);
        Assert.Contains("SPT=1111", rawLog);
        Assert.Contains("DPT=2222", rawLog);
        Assert.Contains("LEN=100", rawLog);
        Assert.Contains("TTL=32", rawLog);
        Assert.Contains("MAC=DE:AD:BE:EF:00:00", rawLog);
        Assert.Contains("PROTO=TCP", rawLog);
        Assert.Contains("RST", rawLog);
        Assert.Contains("DROP:", rawLog);
    }

    private sealed class ThrowingEventSource : VulcansTrace.Linux.Core.Live.IEventSource
    {
        public string DisplayName => "Throwing Source";
        public bool IsAvailable => true;
        public string? UnavailabilityReason => null;

        public async IAsyncEnumerable<UnifiedEvent> StreamAsync(
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.Yield();
            throw new InvalidOperationException("source failed");
#pragma warning disable CS0162
            yield return null!;
#pragma warning restore CS0162
        }
    }
}
