using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Core;

public class LinuxNftablesParserTests
{
    private readonly LinuxNftablesParser _parser = new();

    [Fact]
    public void Parse_ValidNftablesLine_ParsesAllFields()
    {
        // Arrange
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.100 DST=192.168.1.1 LEN=60 TOS=0x00 TTL=64 ID=12345 PROTO=TCP SPT=54321 DPT=22 SYN ACK";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.Equal("192.168.1.100", evt.SourceIP);
        Assert.Equal("192.168.1.1", evt.DestinationIP);
        Assert.Equal(54321, evt.SourcePort);
        Assert.Equal(22, evt.DestinationPort);
        Assert.Equal("TCP", evt.Protocol);
        Assert.Equal("INPUT", evt.LinuxSpecific["Chain"]);
        Assert.Equal("eth0", evt.LinuxSpecific["InterfaceIn"]);
        Assert.Equal("60", evt.LinuxSpecific["Length"]);
        Assert.Equal("0x00", evt.LinuxSpecific["TOS"]);
        Assert.Equal("64", evt.LinuxSpecific["TTL"]);
        Assert.Equal("12345", evt.LinuxSpecific["ID"]);
        Assert.Contains("SYN", evt.LinuxSpecific["Flags"]);
        Assert.Contains("ACK", evt.LinuxSpecific["Flags"]);
    }

    [Fact]
    public void Parse_DropChain_DerivesCorrectAction()
    {
        // Arrange
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: FORWARD_DROP IN=eth0 OUT=eth1 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        Assert.Equal("DROP", result.Events[0].Action);
        Assert.Equal("FORWARD_DROP", result.Events[0].LinuxSpecific["Chain"]);
    }

    [Fact]
    public void Parse_AcceptChain_DerivesCorrectAction()
    {
        // Arrange
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT_ACCEPT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        Assert.Equal("ACCEPT", result.Events[0].Action);
        Assert.Equal("INPUT_ACCEPT", result.Events[0].LinuxSpecific["Chain"]);
    }

    [Fact]
    public void Parse_MultipleLines_ParsesAll()
    {
        // Arrange
        var logText = @"2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22
2026-01-19T10:15:33.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=23";

        // Act
        var result = _parser.Parse(logText);

        // Assert
        Assert.Equal(2, result.Events.Length);
        Assert.Equal(22, result.Events[0].DestinationPort);
        Assert.Equal(23, result.Events[1].DestinationPort);
    }

    [Fact]
    public void Parse_InvalidLine_SkipsSilently()
    {
        // Arrange
        var logText = @"2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22
Invalid line without proper format";

        // Act
        var result = _parser.Parse(logText);

        // Assert
        Assert.Single(result.Events);
        Assert.Empty(result.Errors);
        Assert.Equal(1, result.SkippedLineCount);
        Assert.Contains("lines skipped", result.Warnings[0]);
    }

    [Fact]
    public void Parse_InvalidLine_PopulatesSkippedLineDetail()
    {
        // Arrange
        var logText = @"2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22
Invalid line without proper format";

        // Act
        var result = _parser.Parse(logText);

        // Assert - the skipped line is retained with its 1-based number + raw text.
        var skipped = Assert.Single(result.SkippedLines);
        Assert.Equal(2, skipped.LineNumber);
        Assert.Equal("Invalid line without proper format", skipped.Text);
        Assert.Contains("SRC/DST/PROTO", skipped.Reason);
    }

    [Fact]
    public void Parse_NftablesLineWithInvalidPort_AddsParseError()
    {
        // Arrange
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=70000 DPT=22";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Empty(result.Events);
        Assert.Single(result.Errors);
        Assert.Contains("Invalid port number", result.Errors[0]);
    }

    [Fact]
    public void Parse_NftablesLineWithInvalidTimestamp_AddsParseError()
    {
        // Arrange
        var logLine = "not-a-date nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Empty(result.Events);
        Assert.Single(result.Errors);
        Assert.Contains("Unable to parse timestamp", result.Errors[0]);
    }

    [Fact]
    public void Parse_NftablesLineWithUdpProtocol_ParsesCorrectly()
    {
        // Arrange
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=UDP SPT=12345 DPT=53";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.Equal("UDP", evt.Protocol);
        Assert.Equal(53, evt.DestinationPort);
    }

    [Fact]
    public void Parse_OutputChain_ParsesCorrectly()
    {
        // Arrange
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: OUTPUT IN= SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=22 DPT=54321";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.Equal("OUTPUT", evt.LinuxSpecific["Chain"]);
        Assert.Equal("", evt.LinuxSpecific["InterfaceIn"]);
    }

    [Fact]
    public void Parse_ForwardChain_ParsesCorrectly()
    {
        // Arrange
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: FORWARD IN=eth0 OUT=eth1 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=80";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.Equal("FORWARD", evt.LinuxSpecific["Chain"]);
        Assert.Equal("eth0", evt.LinuxSpecific["InterfaceIn"]);
        Assert.Equal("eth1", evt.LinuxSpecific["InterfaceOut"]);
    }

    [Fact]
    public void Parse_RejectAction_DerivesCorrectAction()
    {
        // Arrange
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT_REJECT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        Assert.Equal("REJECT", result.Events[0].Action);
    }

    [Fact]
    public void Parse_EmptyInput_ReturnsEmpty()
    {
        // Arrange
        var logText = "";

        // Act
        var result = _parser.Parse(logText);

        // Assert
        Assert.Empty(result.Events);
    }

    [Fact]
    public void Parse_MalformedLogLine_SkipsSilently()
    {
        // Arrange
        var logLine = "This is not a valid nftables log line";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Empty(result.Events);
        Assert.Equal(1, result.SkippedLineCount);
        Assert.Contains("lines skipped", result.Warnings[0]);
    }

    [Fact]
    public void Parse_NftablesLineWithoutRequiredFields_ReturnsNull()
    {
        // Arrange
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0"; // Missing SRC, DST, PROTO

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Empty(result.Events);
    }

    [Fact]
    public void Parse_NftablesLineWithTimestamp_ParsesCorrectly()
    {
        // Arrange
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.Equal(DateTimeKind.Unspecified, evt.Timestamp.Kind);
        Assert.Equal(2026, evt.Timestamp.Year);
        Assert.Equal(1, evt.Timestamp.Month);
        Assert.Equal(19, evt.Timestamp.Day);
        Assert.Equal(10, evt.Timestamp.Hour);
        Assert.Equal(15, evt.Timestamp.Minute);
        Assert.Equal(32, evt.Timestamp.Second);
    }

    [Fact]
    public void Parse_EquivalentInstantsWithDifferentOffsets_NormalizeToSameUtcTimestamp()
    {
        // Arrange — same instant expressed in UTC and +02:00
        var logText = @"2026-01-19T10:15:32Z nf_tables: INPUT IN=eth0 SRC=192.168.1.1 DST=10.0.0.5 PROTO=TCP SPT=12345 DPT=22
2026-01-19T12:15:32+02:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.2 DST=10.0.0.5 PROTO=TCP SPT=12346 DPT=22";

        // Act
        var result = _parser.Parse(logText);

        // Assert — both events should have the exact same timestamp (10:15:32 UTC)
        Assert.Equal(2, result.Events.Length);
        Assert.Equal(result.Events[0].Timestamp, result.Events[1].Timestamp);
        Assert.Equal(10, result.Events[0].Timestamp.Hour);
        Assert.Equal(15, result.Events[0].Timestamp.Minute);
        Assert.Equal(32, result.Events[0].Timestamp.Second);
        // Offset metadata preserved for diagnostics
        Assert.DoesNotContain("TimestampOffset", result.Events[0].LinuxSpecific.Keys);
        Assert.Equal("02:00:00", result.Events[1].LinuxSpecific["TimestampOffset"]);
    }

    [Fact]
    public void Parse_NftablesLineWithoutOffset_ParsesLocalTimestamp()
    {
        // Arrange
        var logLine = "2026-01-19 10:15:32 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.Equal(DateTimeKind.Unspecified, evt.Timestamp.Kind);
        Assert.Equal(2026, evt.Timestamp.Year);
        Assert.Equal(1, evt.Timestamp.Month);
        Assert.Equal(19, evt.Timestamp.Day);
        Assert.Equal(10, evt.Timestamp.Hour);
        Assert.Equal(15, evt.Timestamp.Minute);
        Assert.Equal(32, evt.Timestamp.Second);
    }

    [Fact]
    public void Parse_NftablesLineWithIpv6_ParsesAddresses()
    {
        // Arrange
        var logLine = "2026-01-19 10:15:32 nf_tables: INPUT IN=eth0 SRC=2001:db8::1 DST=2001:db8::2 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.Equal("2001:db8::1", evt.SourceIP);
        Assert.Equal("2001:db8::2", evt.DestinationIP);
    }

    [Fact]
    public void Parse_DefaultInputChain_DerivesUnknownAction()
    {
        // Arrange
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        Assert.Equal("UNKNOWN", result.Events[0].Action);
        Assert.Equal("INPUT", result.Events[0].LinuxSpecific["Chain"]);
    }

    [Fact]
    public void Parse_DefaultOutputChain_DerivesUnknownAction()
    {
        // Arrange
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: OUTPUT IN= SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=22 DPT=54321";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        Assert.Equal("UNKNOWN", result.Events[0].Action);
        Assert.Equal("OUTPUT", result.Events[0].LinuxSpecific["Chain"]);
    }

    [Fact]
    public void Parse_DefaultForwardChain_DerivesUnknownAction()
    {
        // Arrange
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: FORWARD IN=eth0 OUT=eth1 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=80";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        Assert.Equal("UNKNOWN", result.Events[0].Action);
        Assert.Equal("FORWARD", result.Events[0].LinuxSpecific["Chain"]);
    }

    [Fact]
    public void Parse_Ipv6LogLine_ParsesIpv6Fields()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 OUT= SRC=2001:db8::1 DST=2001:db8::2 LEN=80 TC=0 HOPLIMIT=64 FLOWLBL=0 PROTO=TCP SPT=54321 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.Equal("2001:db8::1", evt.SourceIP);
        Assert.Equal("2001:db8::2", evt.DestinationIP);
        Assert.Equal("64", evt.LinuxSpecific["HOPLIMIT"]);
        Assert.Equal("0", evt.LinuxSpecific["TC"]);
        Assert.Equal("0", evt.LinuxSpecific["FLOWLBL"]);
        Assert.Equal("0x00", evt.LinuxSpecific["RES"]);
        Assert.Equal("0", evt.LinuxSpecific["URGP"]);
        Assert.Equal("64240", evt.LinuxSpecific["Window"]);
    }

    [Fact]
    public void Parse_Ipv6LogLine_NoTtlTosFields_EmptyInDictionary()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=2001:db8::1 DST=2001:db8::2 LEN=80 TC=0 HOPLIMIT=64 FLOWLBL=12345 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.Equal("", evt.LinuxSpecific["TTL"]);
        Assert.Equal("", evt.LinuxSpecific["TOS"]);
        Assert.Equal("64", evt.LinuxSpecific["HOPLIMIT"]);
        Assert.Equal("0", evt.LinuxSpecific["TC"]);
        Assert.Equal("12345", evt.LinuxSpecific["FLOWLBL"]);
    }

    [Fact]
    public void Parse_SuppressedCallbacksLine_GeneratesWarning()
    {
        var logText = @"2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22
2026-01-19 10:15:33 myhost kernel: net_ratelimit: 42 callbacks suppressed
2026-01-19T10:15:34.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=23";

        var result = _parser.Parse(logText);

        Assert.Equal(2, result.Events.Length);
        Assert.Empty(result.Errors);
        Assert.Single(result.Warnings);
        Assert.Contains("42 callbacks", result.Warnings[0]);
    }

    [Fact]
    public void Parse_CustomPrefix_DerivesActionFromPrefix()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 myfw: DROP IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("DROP", result.Events[0].Action);
    }

    [Fact]
    public void Parse_NoPrefix_ExtractsTimestampDirectly()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("", result.Events[0].LinuxSpecific["Chain"]);
        Assert.Equal("UNKNOWN", result.Events[0].Action);
        Assert.Equal(DateTimeKind.Unspecified, result.Events[0].Timestamp.Kind);
        Assert.Equal(2026, result.Events[0].Timestamp.Year);
    }

    [Fact]
    public void Parse_FullFeaturedLine_ParsesAllKernelFields()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: FORWARD_DROP IN=eth0 OUT=eth1 MAC=00:11:22:33:44:55 SRC=192.168.1.100 DST=10.0.0.1 LEN=60 TOS=0x10 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=54321 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 UID=1000 GID=1000 MARK=0xabcd PHYSIN=br0 PHYSOUT=eth1";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.Equal("DROP", evt.Action);
        Assert.Equal("FORWARD_DROP", evt.LinuxSpecific["Chain"]);
        Assert.Equal("00:11:22:33:44:55", evt.LinuxSpecific["MAC"]);
        Assert.Equal("0x10", evt.LinuxSpecific["TOS"]);
        Assert.Equal("0x00", evt.LinuxSpecific["PREC"]);
        Assert.Equal("64", evt.LinuxSpecific["TTL"]);
        Assert.Equal("12345", evt.LinuxSpecific["ID"]);
        Assert.Equal("true", evt.LinuxSpecific["DF"]);
        Assert.Equal("64240", evt.LinuxSpecific["Window"]);
        Assert.Equal("0x00", evt.LinuxSpecific["RES"]);
        Assert.Equal("SYN", evt.LinuxSpecific["Flags"]);
        Assert.Equal("0", evt.LinuxSpecific["URGP"]);
        Assert.Equal("1000", evt.LinuxSpecific["UID"]);
        Assert.Equal("1000", evt.LinuxSpecific["GID"]);
        Assert.Equal("0xabcd", evt.LinuxSpecific["MARK"]);
        Assert.Equal("br0", evt.LinuxSpecific["PHYSIN"]);
        Assert.Equal("eth1", evt.LinuxSpecific["PHYSOUT"]);
    }

    [Fact]
    public void Parse_MacAndWindowFields_ParsedCorrectly()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22 WINDOW=64240";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("aa:bb:cc:dd:ee:ff", result.Events[0].LinuxSpecific["MAC"]);
        Assert.Equal("64240", result.Events[0].LinuxSpecific["Window"]);
    }

    [Fact]
    public void Parse_FullEthernetMacTuple_StoresSourceMac()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:08:00 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22 WINDOW=64240";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("00:11:22:33:44:55", result.Events[0].LinuxSpecific["MAC"]);
    }

    [Fact]
    public void Parse_VlanFields_ParsesVprotoAndVid()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0.100 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22 VPROTO=0x0800 VID=100";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("0x0800", result.Events[0].LinuxSpecific["VPROTO"]);
        Assert.Equal("100", result.Events[0].LinuxSpecific["VID"]);
    }

    [Fact]
    public void Parse_IpsecFields_ParsesSpi()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=ESP SPI=0x12345678";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("0x12345678", result.Events[0].LinuxSpecific["SPI"]);
    }

    [Fact]
    public void Parse_IcmpErrorFields_ParsesFragAndMtu()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=10.0.0.1 DST=192.168.1.100 PROTO=ICMP TYPE=3 CODE=4 MTU=1400 FRAG=1500";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("1400", result.Events[0].LinuxSpecific["MTU"]);
        Assert.Equal("1500", result.Events[0].LinuxSpecific["FRAG"]);
    }

    [Fact]
    public void Parse_NumericProtocol_ParsesCorrectly()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=47";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("47", result.Events[0].Protocol);
    }

    [Fact]
    public void Parse_ProtoIcmpv6_ParsesCorrectly()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=fe80::1 DST=ff02::1 PROTO=ICMPv6";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("ICMPV6", result.Events[0].Protocol);
    }

    [Fact]
    public void Parse_ProtoUdplite_ParsesCorrectly()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=UDPLITE SPT=12345 DPT=53";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("UDPLITE", result.Events[0].Protocol);
    }

    [Fact]
    public void Parse_ChainDroptable_DoesNotMatchDrop()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: DROPTABLE IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("UNKNOWN", result.Events[0].Action);
    }

    [Fact]
    public void Parse_ChainAcceptance_DoesNotMatchAccept()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: ACCEPTANCE IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("UNKNOWN", result.Events[0].Action);
    }

    [Fact]
    public void Parse_ChainRejected_DoesNotMatchReject()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: REJECTED IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("UNKNOWN", result.Events[0].Action);
    }

    [Fact]
    public void Parse_ChainBackdrop_DoesNotMatchDrop()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: BACKDROP IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("UNKNOWN", result.Events[0].Action);
    }

    [Fact]
    public void Parse_ChainDropdown_DoesNotMatchDrop()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: DROPDOWN IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("UNKNOWN", result.Events[0].Action);
    }

    [Theory]
    [InlineData("999.999.999.999")]
    [InlineData("1.2.3")]
    [InlineData("256.1.2.3")]
    public void Parse_MalformedIPv4_AddsParseError(string ip)
    {
        var logLine = $"2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC={ip} DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Empty(result.Events);
        Assert.NotEmpty(result.Errors);
    }

    [Fact]
    public void Parse_ValidIPv4MappedIPv6_ParsesSuccessfully()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=::ffff:192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("::ffff:192.168.1.100", result.Events[0].SourceIP);
    }

    [Fact]
    public void Parse_ChainWithDigitSuffix_DoesNotMatchAction()
    {
        // IsWholeToken should treat digits as boundaries, so "DROP123" is not "DROP"
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: DROP123 IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("UNKNOWN", result.Events[0].Action);
    }

    [Fact]
    public void Parse_CustomPrefixBracketedDrop_MatchesDrop()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 [DROP] IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("DROP", result.Events[0].Action);
    }

    [Fact]
    public void Parse_CustomPrefixHyphenatedReject_MatchesReject()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 FW-REJECT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("REJECT", result.Events[0].Action);
    }

    [Fact]
    public void Parse_ChainForwardDrop_MatchesDrop()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: FORWARD_DROP IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("DROP", result.Events[0].Action);
        Assert.Equal("FORWARD_DROP", result.Events[0].LinuxSpecific["Chain"]);
    }

    [Fact]
    public void Parse_ChainInputAccept_MatchesAccept()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT_ACCEPT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("ACCEPT", result.Events[0].Action);
        Assert.Equal("INPUT_ACCEPT", result.Events[0].LinuxSpecific["Chain"]);
    }

    [Fact]
    public void Parse_NullInput_ThrowsArgumentNullException()
    {
        var parser = new LinuxNftablesParser();
        Assert.Throws<ArgumentNullException>(() => parser.Parse(null!));
    }

    [Fact]
    public void Parse_ReorderedDstBeforeSrc_ParsesCorrectly()
    {
        var logLine = "2026-01-19T10:15:32Z nf_tables: INPUT IN=eth0 DST=10.0.0.1 SRC=192.168.1.100 PROTO=TCP SPT=12345 DPT=80";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("192.168.1.100", result.Events[0].SourceIP);
        Assert.Equal("10.0.0.1", result.Events[0].DestinationIP);
    }

    [Fact]
    public void Parse_ReorderedDptBeforeSpt_ParsesCorrectly()
    {
        var logLine = "2026-01-19T10:15:32Z nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP DPT=443 SPT=12345";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal(12345, result.Events[0].SourcePort);
        Assert.Equal(443, result.Events[0].DestinationPort);
    }

    [Fact]
    public void Parse_PrefixedFields_RequiresWordBoundary()
    {
        var logLine = "2026-01-19T10:15:32Z nf_tables: INPUT IN=eth0 ORIGSRC=1.1.1.1 SRC=192.168.1.100 DST=10.0.0.1 ORIGSPT=1 SPT=12345 DPT=80 PROTO=TCP";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("192.168.1.100", result.Events[0].SourceIP);
        Assert.Equal(12345, result.Events[0].SourcePort);
        Assert.Equal(80, result.Events[0].DestinationPort);
    }

    [Fact]
    public void Parse_NftablesChainAccept_DerivesAcceptAction()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: ACCEPT IN=eth0 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=80";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("ACCEPT", result.Events[0].Action);
    }

    [Fact]
    public void Parse_NftablesChainDrop_DerivesDropAction()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: DROP IN=eth0 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=80";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("DROP", result.Events[0].Action);
    }

    [Fact]
    public void Parse_NftablesChainReject_DerivesRejectAction()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: REJECT IN=eth0 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=80";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("REJECT", result.Events[0].Action);
    }

    [Fact]
    public void Parse_NftablesChainInput_DerivesUnknownAction()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=80";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("UNKNOWN", result.Events[0].Action);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65535)]
    public void Parse_PortBoundaryValues_ParsesSuccessfully(int port)
    {
        var logLine = $"2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT={port} DPT={port}";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal(port, result.Events[0].SourcePort);
        Assert.Equal(port, result.Events[0].DestinationPort);
    }

    [Fact]
    public void Parse_PortNegativeValue_AddsParseError()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=-1 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Empty(result.Events);
        Assert.NotEmpty(result.Errors);
        Assert.Contains("Invalid port number", result.Errors[0]);
    }

    [Fact]
    public void Parse_PortNonNumericValue_AddsParseError()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=abc DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Empty(result.Events);
        Assert.NotEmpty(result.Errors);
        Assert.Contains("Invalid port number", result.Errors[0]);
    }

    [Fact]
    public void Parse_PortAboveMaxValue_AddsParseError()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=65536 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Empty(result.Events);
        Assert.NotEmpty(result.Errors);
    }

    [Fact]
    public void Parse_MissingOptionalFields_ParsesRequiredFieldsOnly()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.Equal("192.168.1.100", evt.SourceIP);
        Assert.Equal("10.0.0.1", evt.DestinationIP);
        Assert.Equal("", evt.LinuxSpecific["MAC"]);
        Assert.Equal("", evt.LinuxSpecific["Length"]);
        Assert.Equal("", evt.LinuxSpecific["TOS"]);
        Assert.Equal("", evt.LinuxSpecific["TTL"]);
    }

    [Fact]
    public void Parse_NftablesChainCustomName_DerivesUnknownAction()
    {
        var logLine = "2026-01-19T10:15:32.123456+00:00 nf_tables: MY-CUSTOM-CHAIN IN=eth0 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=80";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("UNKNOWN", result.Events[0].Action);
    }
}
