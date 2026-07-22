using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Core;

public class LogNormalizerTests
{
    private readonly LogNormalizer _normalizer = new();

    [Fact]
    public void DetectFormat_IptablesLine_ReturnsIptables()
    {
        // Arrange
        var logText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var format = _normalizer.DetectFormat(logText);

        // Assert
        Assert.Equal(LogFormat.Iptables, format);
    }

    [Fact]
    public void DetectFormat_NftablesLine_ReturnsNftables()
    {
        // Arrange
        var logText = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var format = _normalizer.DetectFormat(logText);

        // Assert
        Assert.Equal(LogFormat.Nftables, format);
    }

    [Fact]
    public void DetectFormat_UnknownFormat_ReturnsUnknown()
    {
        // Arrange
        var logText = "This is not a recognized log format";

        // Act
        var format = _normalizer.DetectFormat(logText);

        // Assert
        Assert.Equal(LogFormat.Unknown, format);
    }

    [Fact]
    public void Normalize_IptablesLog_ReturnsCorrectEvents()
    {
        // Arrange
        var logText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var result = _normalizer.Normalize(logText);

        // Assert
        Assert.Single(result.Events);
        Assert.Equal(LogFormat.Iptables, result.Events[0].LogFormat);
        Assert.Equal("192.168.1.100", result.Events[0].SourceIP);
    }

    [Fact]
    public void DetectFormat_IptablesLineWithoutKernelPrefix_ReturnsIptables()
    {
        var logText = "Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        var format = _normalizer.DetectFormat(logText);

        Assert.Equal(LogFormat.Iptables, format);
    }

    [Fact]
    public void Normalize_IptablesLineWithoutKernelPrefix_ReturnsEvent()
    {
        var logText = "Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _normalizer.Normalize(logText);

        Assert.Single(result.Events);
        Assert.Equal(LogFormat.Iptables, result.Events[0].LogFormat);
        Assert.Equal("192.168.1.100", result.Events[0].SourceIP);
    }

    [Fact]
    public void Normalize_NftablesLog_ReturnsCorrectEvents()
    {
        // Arrange
        var logText = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var result = _normalizer.Normalize(logText);

        // Assert
        Assert.Single(result.Events);
        Assert.Equal(LogFormat.Nftables, result.Events[0].LogFormat);
        Assert.Equal("192.168.1.100", result.Events[0].SourceIP);
    }

    [Fact]
    public void Normalize_MixedFormats_UsesFirstFormat()
    {
        // Arrange - First line is iptables
        var logText = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22
kernel: Jan 19 10:15:33 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=23";

        // Act
        var result = _normalizer.Normalize(logText);

        // Assert - Normalizer uses first detected format for entire text
        Assert.Equal(2, result.Events.Length);
        Assert.All(result.Events, evt => Assert.Equal(LogFormat.Iptables, evt.LogFormat));
    }

    [Fact]
    public void Normalize_UnknownFormat_ReturnsErrorWithSkippedCount()
    {
        // Arrange
        var logText = "Unknown log format line\nAnother garbage line\nThird bad line";

        // Act
        var result = _normalizer.Normalize(logText);

        // Assert
        Assert.Empty(result.Events);
        Assert.NotEmpty(result.Errors);
        Assert.Equal(3, result.TotalLines);
        Assert.Equal(3, result.SkippedLineCount);
    }

    [Fact]
    public void Normalize_UnknownFormat_PopulatesSkippedLinesDetail()
    {
        // Arrange
        var logText = "Unknown log format line\nAnother garbage line\nThird bad line";

        // Act
        var result = _normalizer.Normalize(logText);

        // Assert - every input line is retained as a skipped line with its 1-based
        // number + raw text, so the System -> Logs "Skipped Lines" detail can show them.
        Assert.Equal(3, result.SkippedLines.Length);
        Assert.Equal(new SkippedLine(1, "Unknown log format line", "Unknown log format"), result.SkippedLines[0]);
        Assert.Equal(new SkippedLine(2, "Another garbage line", "Unknown log format"), result.SkippedLines[1]);
        Assert.Equal(new SkippedLine(3, "Third bad line", "Unknown log format"), result.SkippedLines[2]);
    }

    [Fact]
    public void Normalize_MixedFormatsWithGarbageLine_RecordsSkippedLineAtGlobalIndex()
    {
        // Arrange - an iptables line + an nftables line forces mixed mode; the third
        // line matches no format and must be recorded at its global line index (3).
        var logText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22\n2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22\nthis line matches no format";

        // Act
        var result = _normalizer.Normalize(logText);

        // Assert
        Assert.Equal(2, result.Events.Length);
        Assert.Equal(1, result.SkippedLineCount);
        var skipped = Assert.Single(result.SkippedLines);
        Assert.Equal(3, skipped.LineNumber);
        Assert.Equal("this line matches no format", skipped.Text);
        Assert.Equal("Unknown log format", skipped.Reason);
    }

    [Fact]
    public void Normalize_EmptyInput_ReturnsCleanEmptyResult()
    {
        // Arrange
        var logText = "";

        // Act
        var result = _normalizer.Normalize(logText);

        // Assert
        Assert.Empty(result.Events);
        Assert.Empty(result.Errors);
        Assert.Equal(0, result.TotalLines);
        Assert.Equal(0, result.SkippedLineCount);
    }

    [Fact]
    public void Normalize_MultipleIptablesLines_ReturnsAllEvents()
    {
        // Arrange
        var logText = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22
kernel: Jan 19 10:15:33 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=23
kernel: Jan 19 10:15:34 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=24";

        // Act
        var result = _normalizer.Normalize(logText);

        // Assert
        Assert.Equal(3, result.Events.Length);
        Assert.All(result.Events, evt => Assert.Equal(LogFormat.Iptables, evt.LogFormat));
    }

    [Fact]
    public void Normalize_MultipleNftablesLines_ReturnsAllEvents()
    {
        // Arrange
        var logText = @"2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22
2026-01-19T10:15:33.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=23";

        // Act
        var result = _normalizer.Normalize(logText);

        // Assert
        Assert.Equal(2, result.Events.Length);
        Assert.All(result.Events, evt => Assert.Equal(LogFormat.Nftables, evt.LogFormat));
    }

    [Fact]
    public void DetectFormat_NumericProtocol_ReturnsIptables()
    {
        var logText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=47";

        var format = _normalizer.DetectFormat(logText);

        Assert.Equal(LogFormat.Iptables, format);
    }

    [Fact]
    public void DetectFormat_ProtoIcmpv6_ReturnsIptables()
    {
        var logText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=fe80::1 DST=ff02::1 PROTO=ICMPv6";

        var format = _normalizer.DetectFormat(logText);

        Assert.Equal(LogFormat.Iptables, format);
    }

    [Fact]
    public void DetectFormat_ProtoUdplite_ReturnsIptables()
    {
        var logText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=UDPLITE SPT=12345 DPT=53";

        var format = _normalizer.DetectFormat(logText);

        Assert.Equal(LogFormat.Iptables, format);
    }

    [Fact]
    public void DetectFormat_ProtoSctp_ReturnsIptables()
    {
        var logText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=132";

        var format = _normalizer.DetectFormat(logText);

        Assert.Equal(LogFormat.Iptables, format);
    }

    [Fact]
    public void Normalize_InputExceedsMaxSize_ReturnsError()
    {
        // LogNormalizer caps input at 100 million characters.
        // Create a string that exceeds this limit to verify the guard.
        var oversized = new string('A', 100_000_001);

        var result = _normalizer.Normalize(oversized);

        Assert.Empty(result.Events);
        Assert.Single(result.Errors);
        Assert.Contains("exceeds maximum size", result.Errors[0]);
        Assert.Equal(0, result.TotalLines);
    }

    [Fact]
    public void Normalize_NullInput_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _normalizer.Normalize(null!));
    }

    [Fact]
    public void Normalize_CancelledToken_ThrowsOperationCanceledException()
    {
        var logText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.Throws<OperationCanceledException>(() => _normalizer.Normalize(logText, cts.Token));
    }

    [Fact]
    public void Normalize_CrlfLineEndings_StripsCarriageReturnFromFields()
    {
        // Arrange - Windows-style \r\n line endings should not contaminate parsed fields
        var logText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22\r\n" +
                      "kernel: Jan 19 10:15:33 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=23";

        // Act
        var result = _normalizer.Normalize(logText);

        // Assert
        Assert.Equal(2, result.Events.Length);
        Assert.All(result.Events, evt =>
        {
            Assert.DoesNotContain("\r", evt.LinuxSpecific.GetValueOrDefault("InterfaceIn", ""));
            Assert.DoesNotContain("\r", evt.SourceIP);
            Assert.DoesNotContain("\r", evt.DestinationIP);
        });
    }

    [Fact]
    public void Normalize_InterleavedIptablesAndNftables_ParsesEachDetectedFormat()
    {
        var logText = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22
2026-01-19T10:15:33.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.200 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=23
kernel: Jan 19 10:15:34 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=24";

        var result = _normalizer.Normalize(logText);

        Assert.Equal(3, result.TotalLines);
        Assert.Equal(3, result.Events.Length);
        Assert.Equal(2, result.Events.Count(e => e.LogFormat == LogFormat.Iptables));
        Assert.Single(result.Events, e => e.LogFormat == LogFormat.Nftables);
        Assert.Contains(result.Warnings, warning => warning.Contains("Mixed log formats", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Normalize_IptablesLineWithNfTablesInPayload_ParsesAsIptables()
    {
        // An iptables-format line that happens to mention "nf_tables:" in its message text
        // should still be detected as Iptables, not Nftables.
        var logText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22 message about nf_tables: rule added";

        var result = _normalizer.Normalize(logText);

        Assert.Single(result.Events);
        Assert.Equal(LogFormat.Iptables, result.Events[0].LogFormat);
        Assert.Equal("192.168.1.100", result.Events[0].SourceIP);
        Assert.Equal(0, result.SkippedLineCount);
    }
}
