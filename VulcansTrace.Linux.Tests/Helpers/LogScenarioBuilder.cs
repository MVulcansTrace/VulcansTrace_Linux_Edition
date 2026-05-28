using System.Text;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Tests.Helpers;

public class LogScenarioBuilder
{
    private readonly StringBuilder _logBuilder = new();
    private DateTime _startTime = DateTime.Now;

    public LogScenarioBuilder BuildPortScan(int targetCount, TimeSpan duration)
    {
        // Generate port scan scenario
        var startIp = "192.168.1.100";
        var dstIp = "10.0.0.1";
        var ports = GeneratePortSequence(targetCount);

        foreach (var (port, index) in ports.Select((p, i) => (p, i)))
        {
            var timestamp = _startTime.AddMilliseconds(index * 100);
            var logLine = FormatIptablesLine(timestamp, startIp, dstIp, port);
            _logBuilder.AppendLine(logLine);
        }
        return this;
    }

    public LogScenarioBuilder BuildBeaconing(TimeSpan interval, TimeSpan duration)
    {
        var startIp = "192.168.1.100";
        var dstIp = "8.8.4.4";
        var eventCount = (int)(duration.TotalSeconds / interval.TotalSeconds);

        for (int i = 0; i < eventCount; i++)
        {
            var timestamp = _startTime.AddSeconds(i * interval.TotalSeconds);
            var logLine = FormatIptablesLine(timestamp, startIp, dstIp, 80);
            _logBuilder.AppendLine(logLine);
        }
        return this;
    }

    public LogScenarioBuilder BuildUnusualPacketSizes(int largeCount, int smallCount, int consistentCount)
    {
        var srcIp = "192.168.1.100";
        var dstIp = "10.0.0.1";

        for (int i = 0; i < largeCount; i++)
        {
            var timestamp = _startTime.AddMilliseconds(i * 100);
            _logBuilder.AppendLine(FormatIptablesLineWithLength(timestamp, srcIp, dstIp, 80, 5000));
        }

        for (int i = 0; i < smallCount; i++)
        {
            var timestamp = _startTime.AddMilliseconds((largeCount + i) * 100);
            _logBuilder.AppendLine(FormatIptablesLineWithLength(timestamp, srcIp, dstIp, 80, 20));
        }

        for (int i = 0; i < consistentCount; i++)
        {
            var timestamp = _startTime.AddMilliseconds((largeCount + smallCount + i) * 100);
            _logBuilder.AppendLine(FormatIptablesLineWithLength(timestamp, srcIp, dstIp, 80, 512));
        }

        return this;
    }

    public LogScenarioBuilder BuildInterfaceHopping(string[] interfaces, TimeSpan interval)
    {
        var srcIp = "192.168.1.100";
        var dstIp = "10.0.0.1";

        for (int i = 0; i < interfaces.Length; i++)
        {
            var timestamp = _startTime.AddSeconds(i * interval.TotalSeconds);
            _logBuilder.AppendLine(FormatIptablesLineWithInterface(timestamp, srcIp, dstIp, 80, interfaces[i]));
        }

        return this;
    }

    public string Generate()
    {
        return _logBuilder.ToString();
    }

    private string FormatIptablesLine(DateTime timestamp, string srcIp, string dstIp, int dstPort)
    {
        return $"kernel: {timestamp:MMM dd HH:mm:ss} server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC={srcIp} DST={dstIp} PROTO=TCP SPT=54321 DPT={dstPort}";
    }

    private string FormatIptablesLineWithLength(DateTime timestamp, string srcIp, string dstIp, int dstPort, int length)
    {
        return $"kernel: {timestamp:MMM dd HH:mm:ss} server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC={srcIp} DST={dstIp} PROTO=TCP SPT=54321 DPT={dstPort} LEN={length}";
    }

    private string FormatIptablesLineWithInterface(DateTime timestamp, string srcIp, string dstIp, int dstPort, string iface)
    {
        return $"kernel: {timestamp:MMM dd HH:mm:ss} server IN={iface} OUT= MAC=00:11:22:33:44:55 SRC={srcIp} DST={dstIp} PROTO=TCP SPT=54321 DPT={dstPort} LEN=60";
    }

    private static IEnumerable<int> GeneratePortSequence(int count)
    {
        return Enumerable.Range(1, count).Select(p => 1024 + p);
    }
}
