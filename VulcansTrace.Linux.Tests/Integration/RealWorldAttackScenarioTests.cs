using System.Text;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Tests.Helpers;
using Xunit;

namespace VulcansTrace.Linux.Tests.Integration;

/// <summary>
/// Tests using diverse real-world attack scenarios to validate detection effectiveness.
/// </summary>
public class RealWorldAttackScenarioTests
{
    private readonly SentryAnalyzer _analyzer;

    public RealWorldAttackScenarioTests()
    {
        var logNormalizer = new LogNormalizer();
        var profileProvider = new AnalysisProfileProvider();

        // All detector types for comprehensive testing
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
            new C2ChannelDetector()
        };

        var riskEscalator = new RiskEscalator();
        _analyzer = new SentryAnalyzer(logNormalizer, profileProvider, baselineDetectors, linuxDetectors, advancedDetectors, riskEscalator);
    }

    [Fact]
    public void Analyze_RealWorld_DoS_Attack_DetectsFlood()
    {
        // Arrange - Simulate a DoS attack with many connections from a single source
        var log = GenerateFloodAttackLog(TimeSpan.FromMinutes(1), 1000);

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.True(result.ParsedLines > 0);
        // The DoS attack should be detected as Flood at Medium intensity
        Assert.Contains(result.Findings, f => f.Category == "Flood");
    }

    [Fact]
    public void Analyze_RealWorld_PortScan_Attack_DetectsPortScan()
    {
        // Arrange - Simulate a port scan targeting many ports
        var log = GeneratePortScanAttackLog(50, TimeSpan.FromMinutes(10));

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.True(result.ParsedLines > 0);
        Assert.Contains(result.Findings, f => f.Category == "PortScan");
    }

    [Fact]
    public void Analyze_RealWorld_C2_Channel_DetectsC2Activity()
    {
        // Arrange - Simulate C2 channel with periodic communication
        var log = GenerateC2ChannelLog(TimeSpan.FromMinutes(5), TimeSpan.FromHours(2));

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.True(result.ParsedLines > 0);
        Assert.Contains(result.Findings, f => f.Category == "C2Channel");
    }

    [Fact]
    public void Analyze_RealWorld_Lateral_Movement_DetectsLateralMovement()
    {
        // Arrange - Simulate lateral movement across multiple internal hosts
        var log = GenerateLateralMovementLog();

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.True(result.ParsedLines > 0);
        Assert.Contains(result.Findings, f => f.Category == "LateralMovement");
    }

    [Fact]
    public void Analyze_RealWorld_Beaconing_Activity_DetectsBeaconing()
    {
        // Arrange - Simulate beaconing activity with regular intervals
        var log = GenerateBeaconingActivityLog(TimeSpan.FromMinutes(15), TimeSpan.FromHours(6));

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert — Beaconing may be absorbed into C2Channel by the deduplication step.
        Assert.True(result.ParsedLines > 0);
        Assert.Contains(result.Findings, f => f.Category == "Beaconing" || f.Category == "C2Channel");
    }

    [Fact]
    public void Analyze_RealWorld_Mixed_Attack_Scenario_DetectsMultiple()
    {
        // Arrange - Combine multiple attack patterns in one log
        var ddosLog = GenerateFloodAttackLog(TimeSpan.FromMinutes(2), 500);
        var portScanLog = GeneratePortScanAttackLog(30, TimeSpan.FromMinutes(5));
        var c2Log = GenerateC2ChannelLog(TimeSpan.FromMinutes(10), TimeSpan.FromHours(1));

        var mixedLog = ddosLog + Environment.NewLine + portScanLog + Environment.NewLine + c2Log;

        // Act
        var result = _analyzer.Analyze(mixedLog, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.True(result.ParsedLines > 0);
        // Check for presence of multiple attack types (some may overlap with FlagAnomaly)
        Assert.Contains(result.Findings, f => f.Category == "PortScan" || f.Category == "Flood");
        Assert.Contains(result.Findings, f => f.Category == "C2Channel");
        Assert.True(result.Findings.Count > 2); // Should have multiple findings
    }

    private string GenerateFloodAttackLog(TimeSpan duration, int connectionCount)
    {
        var sb = new StringBuilder();
        var startTime = DateTime.UtcNow;
        var endTime = startTime + duration;
        var interval = duration.TotalMilliseconds / connectionCount;

        for (int i = 0; i < connectionCount; i++)
        {
            var timestamp = startTime.AddMilliseconds(i * interval);
            var sourceIp = "192.168.1.2"; // Single source to trigger flood detection
            var destIp = "10.0.0.100"; // Target server
            
            sb.AppendLine($"kernel: {timestamp:MMM dd HH:mm:ss} server IN=eth0 OUT= MAC=00:11:22:33:44:{i:D2} SRC={sourceIp} DST={destIp} PROTO=TCP SPT={50000 + (i % 10000)} DPT=80 LEN=60");
        }

        return sb.ToString();
    }

    private string GeneratePortScanAttackLog(int portCount, TimeSpan duration)
    {
        var sb = new StringBuilder();
        var startTime = DateTime.UtcNow;
        var interval = duration.TotalMilliseconds / portCount;
        var sourceIp = "192.168.1.100";
        var destIp = "10.0.0.50";

        for (int i = 0; i < portCount; i++)
        {
            var timestamp = startTime.AddMilliseconds(i * interval);
            var port = 1 + (i % 65535); // Cycle through ports
            
            sb.AppendLine($"kernel: {timestamp:MMM dd HH:mm:ss} server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC={sourceIp} DST={destIp} PROTO=TCP SPT=54321 DPT={port} LEN=60");
        }

        return sb.ToString();
    }

    private string GenerateC2ChannelLog(TimeSpan interval, TimeSpan totalDuration)
    {
        var sb = new StringBuilder();
        var startTime = DateTime.UtcNow;
        var eventCount = (int)(totalDuration.TotalSeconds / interval.TotalSeconds);
        var sourceIp = "192.168.1.100";
        var destIp = "203.0.113.42"; // Example IP for C2 server

        for (int i = 0; i < eventCount; i++)
        {
            var timestamp = startTime.AddSeconds(i * interval.TotalSeconds);
            
            sb.AppendLine($"kernel: {timestamp:MMM dd HH:mm:ss} server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC={sourceIp} DST={destIp} PROTO=TCP SPT=54321 DPT=443 LEN=60");
        }

        return sb.ToString();
    }

    private string GenerateLateralMovementLog()
    {
        var sb = new StringBuilder();
        var startTime = DateTime.UtcNow;
        var internalIps = new[] { "10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14", "10.0.0.15" };
        var sourceIp = "10.0.0.5"; // Compromised internal host

        for (int i = 0; i < internalIps.Length; i++)
        {
            var timestamp = startTime.AddMinutes(i);
            var destIp = internalIps[i];
            
            sb.AppendLine($"kernel: {timestamp:MMM dd HH:mm:ss} server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC={sourceIp} DST={destIp} PROTO=TCP SPT=54321 DPT=22 LEN=60");
        }

        return sb.ToString();
    }

    private string GenerateBeaconingActivityLog(TimeSpan interval, TimeSpan totalDuration)
    {
        var sb = new StringBuilder();
        var startTime = DateTime.UtcNow;
        var eventCount = (int)(totalDuration.TotalSeconds / interval.TotalSeconds);
        var sourceIp = "192.168.1.100";
        var destIp = "8.8.4.4";

        for (int i = 0; i < eventCount; i++)
        {
            var timestamp = startTime.AddSeconds(i * interval.TotalSeconds);
            
            sb.AppendLine($"kernel: {timestamp:MMM dd HH:mm:ss} server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC={sourceIp} DST={destIp} PROTO=TCP SPT=54321 DPT=80 LEN=60");
        }

        return sb.ToString();
    }

    [Fact]
    public void Analyze_RealWorld_XmasScan_DetectsFlagAnomaly()
    {
        var sb = new StringBuilder();
        var startTime = DateTime.UtcNow;
        for (int i = 0; i < 5; i++)
        {
            var timestamp = startTime.AddSeconds(i);
            sb.AppendLine($"kernel: {timestamp:MMM dd HH:mm:ss} server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=80 LEN=60 FLAGS=FIN,PSH,URG");
        }

        var result = _analyzer.Analyze(sb.ToString(), IntensityLevel.Medium, CancellationToken.None);

        Assert.True(result.ParsedLines > 0);
        Assert.Contains(result.Findings, f => f.Category == "FlagAnomaly");
    }

    [Fact]
    public void Analyze_RealWorld_MacSpoofing_DetectsMacSpoofing()
    {
        var sb = new StringBuilder();
        var startTime = DateTime.UtcNow;
        var macs = new[] { "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03" };
        for (int i = 0; i < 9; i++)
        {
            var timestamp = startTime.AddSeconds(i * 10);
            var mac = macs[i % macs.Length];
            sb.AppendLine($"kernel: {timestamp:MMM dd HH:mm:ss} server IN=eth0 OUT= MAC={mac} SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=80 LEN=60");
        }

        var result = _analyzer.Analyze(sb.ToString(), IntensityLevel.Medium, CancellationToken.None);

        Assert.True(result.ParsedLines > 0);
        Assert.Contains(result.Findings, f => f.Category == "MacSpoofing");
    }

    [Fact]
    public void Analyze_RealWorld_InterfaceHopping_DetectsInterfaceHopping()
    {
        var sb = new StringBuilder();
        var startTime = DateTime.UtcNow;
        var interfaces = new[] { "eth0", "eth1", "wlan0" };
        for (int i = 0; i < 9; i++)
        {
            var timestamp = startTime.AddSeconds(i * 10);
            var iface = interfaces[i % interfaces.Length];
            sb.AppendLine($"kernel: {timestamp:MMM dd HH:mm:ss} server IN={iface} OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=80 LEN=60");
        }

        var result = _analyzer.Analyze(sb.ToString(), IntensityLevel.Medium, CancellationToken.None);

        Assert.True(result.ParsedLines > 0);
        Assert.Contains(result.Findings, f => f.Category == "InterfaceHopping");
    }

    [Fact]
    public void Analyze_RealWorld_KernelModuleActivity_DetectsKernelModule()
    {
        var sb = new StringBuilder();
        var startTime = DateTime.UtcNow;
        var keywords = new[] { "conntrack", "limit", "hashlimit", "quota", "l7" };
        for (int i = 0; i < keywords.Length; i++)
        {
            var timestamp = startTime.AddSeconds(i);
            sb.AppendLine($"kernel: {timestamp:MMM dd HH:mm:ss} server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=80 LEN=60 {keywords[i]}");
        }

        // KernelModule findings are Info severity, which is filtered at Medium intensity.
        var result = _analyzer.Analyze(sb.ToString(), IntensityLevel.High, CancellationToken.None);

        Assert.True(result.ParsedLines > 0);
        Assert.Contains(result.Findings, f => f.Category == "KernelModule");
    }

    [Fact]
    public void Analyze_RealWorld_UnusualPacketSizes_DetectsUnusualPacketSize()
    {
        var sb = new StringBuilder();
        var startTime = DateTime.UtcNow;
        for (int i = 0; i < 5; i++)
        {
            var timestamp = startTime.AddSeconds(i);
            sb.AppendLine($"kernel: {timestamp:MMM dd HH:mm:ss} server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=80 LEN=5000");
        }

        var result = _analyzer.Analyze(sb.ToString(), IntensityLevel.Medium, CancellationToken.None);

        Assert.True(result.ParsedLines > 0);
        Assert.Contains(result.Findings, f => f.Category == "UnusualPacketSize");
    }

    [Fact]
    public void Analyze_RealWorld_Mixed_WithLinuxIndicators_DetectsBaselineAndLinux()
    {
        var sb = new StringBuilder();
        var startTime = DateTime.UtcNow;

        // Port scan with XMAS flags and MAC spoofing
        var macs = new[] { "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02" };
        for (int i = 0; i < 25; i++)
        {
            var timestamp = startTime.AddSeconds(i);
            var mac = macs[i % macs.Length];
            var port = 1000 + i;
            sb.AppendLine($"kernel: {timestamp:MMM dd HH:mm:ss} server IN=eth0 OUT= MAC={mac} SRC=192.168.1.100 DST=10.0.0.50 PROTO=TCP SPT=54321 DPT={port} LEN=60 FLAGS=FIN,PSH,URG");
        }

        var result = _analyzer.Analyze(sb.ToString(), IntensityLevel.Medium, CancellationToken.None);

        Assert.True(result.ParsedLines > 0);
        Assert.Contains(result.Findings, f => f.Category == "PortScan");
        Assert.Contains(result.Findings, f => f.Category == "FlagAnomaly");
        Assert.Contains(result.Findings, f => f.Category == "MacSpoofing");
        Assert.True(result.Findings.Count >= 3);
    }
}
