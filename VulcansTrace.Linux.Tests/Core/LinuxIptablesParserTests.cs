using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Core;

public class LinuxIptablesParserTests
{
    private readonly LinuxIptablesParser _parser = new();

    [Fact]
    public void Parse_ValidIptablesLine_ParsesAllFields()
    {
        // Arrange
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.100 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=54321 DPT=22 WINDOW=64240 RES=0x00 SYN";

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
        Assert.Equal("UNKNOWN", evt.Action);
        Assert.Equal("eth0", evt.LinuxSpecific["InterfaceIn"]);
        Assert.Equal("00:11:22:33:44:55", evt.LinuxSpecific["MAC"]);
        Assert.Equal("60", evt.LinuxSpecific["Length"]);
        Assert.Equal("0x00", evt.LinuxSpecific["TOS"]);
        Assert.Equal("64", evt.LinuxSpecific["TTL"]);
        Assert.Equal("12345", evt.LinuxSpecific["ID"]);
        Assert.Equal("SYN", evt.LinuxSpecific["Flags"]);
    }

    [Fact]
    public void Parse_MultipleLines_ParsesAll()
    {
        // Arrange
        var logText = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22
kernel: Jan 19 10:15:33 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=23";

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
        var logText = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22
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
    public void Parse_IptablesLineWithInvalidPort_AddsParseError()
    {
        // Arrange
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=70000 DPT=22";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Empty(result.Events);
        Assert.Single(result.Errors);
        Assert.Contains("Invalid port number", result.Errors[0]);
    }

    [Fact]
    public void Parse_IptablesLineWithInvalidTimestamp_AddsParseError()
    {
        // Arrange
        var logLine = "kernel: Jan 32 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Empty(result.Events);
        Assert.Single(result.Errors);
        Assert.Contains("Unable to parse timestamp", result.Errors[0]);
    }

    [Fact]
    public void Parse_IptablesLineWithUdpProtocol_ParsesCorrectly()
    {
        // Arrange
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=UDP SPT=12345 DPT=53";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.Equal("UDP", evt.Protocol);
        Assert.Equal(53, evt.DestinationPort);
    }

    [Fact]
    public void Parse_IptablesLineWithoutActionField_SetsDefaultAction()
    {
        // Arrange
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        Assert.Equal("UNKNOWN", result.Events[0].Action);
    }

    [Fact]
    public void Parse_IptablesLineWithAcceptAction_DerivesCorrectAction()
    {
        // Arrange
        var logLine = "kernel: Jan 19 10:15:32 server ACCEPT IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22 SYN";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        Assert.Equal("ACCEPT", result.Events[0].Action);
    }

    [Fact]
    public void Parse_IptablesLineWithDropPrefix_DerivesCorrectAction()
    {
        // Arrange
        var logLine = "kernel: Jan 19 10:15:32 server IPTABLES-DROP IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        Assert.Equal("DROP", result.Events[0].Action);
    }

    [Fact]
    public void Parse_IptablesLineWithFlagsField_StoresInLinuxSpecific()
    {
        // Arrange
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22 SYN";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.True(evt.LinuxSpecific.ContainsKey("Flags"));
        Assert.Equal("SYN", evt.LinuxSpecific["Flags"]);
    }

    [Fact]
    public void Parse_IptablesLineWithMultipleFlags_ParsesAllFlags()
    {
        // Arrange
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22 SYN ACK FIN";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        var flags = result.Events[0].LinuxSpecific["Flags"];
        Assert.Contains("SYN", flags);
        Assert.Contains("ACK", flags);
        Assert.Contains("FIN", flags);
    }

    [Fact]
    public void Parse_IptablesLineWithMultipleInterfaces_ParsesBoth()
    {
        // Arrange
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 OUT=eth1 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.Equal("eth0", evt.LinuxSpecific["InterfaceIn"]);
        Assert.Equal("eth1", evt.LinuxSpecific["InterfaceOut"]);
    }

    [Fact]
    public void Parse_IptablesLineWithFullEthernetMacTuple_StoresSourceMac()
    {
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:08:00 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("00:11:22:33:44:55", result.Events[0].LinuxSpecific["MAC"]);
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
    public void Parse_IptablesLineWithTosField_StoresLinuxSpecificField()
    {
        // Arrange
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 LEN=60 TOS=0x10 PREC=0x00 TTL=64 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.Equal("0x10", evt.LinuxSpecific["TOS"]);
    }

    [Fact]
    public void Parse_IptablesLineWithTimestamp_ParsesExpectedDate()
    {
        // Arrange — referenceDate pinned so the assertion is deterministic; a
        // year-less syslog line is interpreted against the reference year.
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var result = _parser.Parse(logLine, new DateTime(2026, 7, 18));

        // Assert
        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.Equal(2026, evt.Timestamp.Year);
        Assert.Equal(1, evt.Timestamp.Month);
        Assert.Equal(19, evt.Timestamp.Day);
        Assert.Equal(10, evt.Timestamp.Hour);
        Assert.Equal(15, evt.Timestamp.Minute);
        Assert.Equal(32, evt.Timestamp.Second);
    }

    [Fact]
    public void Parse_IptablesLineWithIpv6_ParsesAddresses()
    {
        // Arrange
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=2001:db8::1 DST=2001:db8::2 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.Equal("2001:db8::1", evt.SourceIP);
        Assert.Equal("2001:db8::2", evt.DestinationIP);
    }

    [Fact]
    public void Parse_IptablesLineWithWindowField_ParsesCorrectly()
    {
        // Arrange
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 WINDOW=64240 PROTO=TCP SPT=54321 DPT=22";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.True(evt.LinuxSpecific.ContainsKey("Window"));
        Assert.Equal("64240", evt.LinuxSpecific["Window"]);
    }

    [Fact]
    public void Parse_MalformedLogLine_SkipsSilently()
    {
        // Arrange
        var logLine = "This is not a valid iptables log line";

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Empty(result.Events);
        Assert.Equal(1, result.SkippedLineCount);
        Assert.Contains("lines skipped", result.Warnings[0]);
    }

    [Fact]
    public void Parse_IptablesLineWithoutRequiredFields_ReturnsNull()
    {
        // Arrange
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0"; // Missing SRC, DST, PROTO

        // Act
        var result = _parser.Parse(logLine);

        // Assert
        Assert.Empty(result.Events);
    }

    [Fact]
    public void Parse_Ipv6LogLine_ParsesIpv6Fields()
    {
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=2001:db8::1 DST=2001:db8::2 LEN=80 TC=0 HOPLIMIT=64 FLOWLBL=0 PROTO=TCP SPT=54321 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0";

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
    }

    [Fact]
    public void Parse_Ipv6LogLine_NoTtlTosFields_EmptyInDictionary()
    {
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=2001:db8::1 DST=2001:db8::2 LEN=80 TC=0 HOPLIMIT=64 FLOWLBL=12345 PROTO=TCP SPT=54321 DPT=22";

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
        var logText = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22
Jan 19 10:15:33 myhost kernel: net_ratelimit: 45 callbacks suppressed
kernel: Jan 19 10:15:34 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=23";

        var result = _parser.Parse(logText);

        Assert.Equal(2, result.Events.Length);
        Assert.Empty(result.Errors);
        Assert.Single(result.Warnings);
        Assert.Contains("45 callbacks", result.Warnings[0]);
        Assert.Equal(3, result.TotalLines);
    }

    [Fact]
    public void Parse_NumericProtocol_ParsesCorrectly()
    {
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=47 SPT=0 DPT=0";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("47", result.Events[0].Protocol);
    }

    [Fact]
    public void Parse_ProtoIcmpv6_ParsesCorrectly()
    {
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=fe80::1 DST=ff02::1 PROTO=ICMPv6";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("ICMPV6", result.Events[0].Protocol);
    }

    [Fact]
    public void Parse_FullFeaturedLine_ParsesAllKernelFields()
    {
        var logLine = "kernel: Jan 19 10:15:32 server DROP IN=eth0 OUT=eth1 MAC=00:11:22:33:44:55 SRC=192.168.1.100 DST=10.0.0.1 LEN=60 TOS=0x10 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=54321 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 UID=1000 GID=1000 MARK=0xabcd PHYSIN=br0 PHYSOUT=eth1";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        var evt = result.Events[0];
        Assert.Equal("DROP", evt.Action);
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
    public void Parse_VlanFields_ParsesVprotoAndVid()
    {
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0.100 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22 VPROTO=0x0800 VID=100";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("0x0800", result.Events[0].LinuxSpecific["VPROTO"]);
        Assert.Equal("100", result.Events[0].LinuxSpecific["VID"]);
    }

    [Fact]
    public void Parse_IpsecFields_ParsesSpi()
    {
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=ESP SPI=0x12345678";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("0x12345678", result.Events[0].LinuxSpecific["SPI"]);
    }

    [Fact]
    public void Parse_IcmpErrorFields_ParsesFragAndMtu()
    {
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=10.0.0.1 DST=192.168.1.100 PROTO=ICMP TYPE=3 CODE=4 MTU=1400 FRAG=1500";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("1400", result.Events[0].LinuxSpecific["MTU"]);
        Assert.Equal("1500", result.Events[0].LinuxSpecific["FRAG"]);
    }

    [Fact]
    public void Parse_ProtoUdplite_ParsesCorrectly()
    {
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=UDPLITE SPT=12345 DPT=53";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("UDPLITE", result.Events[0].Protocol);
    }

    [Fact]
    public void Parse_PrefixDroptable_DoesNotMatchDrop()
    {
        var logLine = "kernel: Jan 19 10:15:32 server DROPTABLE IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("UNKNOWN", result.Events[0].Action);
    }

    [Fact]
    public void Parse_PrefixAcceptance_DoesNotMatchAccept()
    {
        var logLine = "kernel: Jan 19 10:15:32 server ACCEPTANCE IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("UNKNOWN", result.Events[0].Action);
    }

    [Fact]
    public void Parse_PrefixRejected_DoesNotMatchReject()
    {
        var logLine = "kernel: Jan 19 10:15:32 server REJECTED IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("UNKNOWN", result.Events[0].Action);
    }

    [Fact]
    public void Parse_PrefixBackdrop_DoesNotMatchDrop()
    {
        var logLine = "kernel: Jan 19 10:15:32 server BACKDROP IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("UNKNOWN", result.Events[0].Action);
    }

    [Fact]
    public void Parse_PrefixDropdown_DoesNotMatchDrop()
    {
        var logLine = "kernel: Jan 19 10:15:32 server DROPDOWN IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

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
        var logLine = $"kernel: Jan 19 10:15:32 server IN=eth0 SRC={ip} DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Empty(result.Events);
        Assert.NotEmpty(result.Errors);
    }

    [Fact]
    public void Parse_ValidIPv4MappedIPv6_ParsesSuccessfully()
    {
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=::ffff:192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("::ffff:192.168.1.100", result.Events[0].SourceIP);
    }

    [Fact]
    public void Parse_PrefixWithDigitSuffix_DoesNotMatchAction()
    {
        // IsWholeToken should treat digits as boundaries, so "DROP123" is not "DROP"
        var logLine = "kernel: Jan 19 10:15:32 server DROP123 IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("UNKNOWN", result.Events[0].Action);
    }

    [Fact]
    public void Parse_PrefixBracketedDrop_MatchesDrop()
    {
        var logLine = "kernel: Jan 19 10:15:32 server [DROP] IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("DROP", result.Events[0].Action);
    }

    [Fact]
    public void Parse_PrefixHyphenatedDrop_MatchesDrop()
    {
        var logLine = "kernel: Jan 19 10:15:32 server SSH-BRUTE-DROP IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("DROP", result.Events[0].Action);
    }

    [Fact]
    public void Parse_PrefixColonSeparatedAccept_MatchesAccept()
    {
        var logLine = "kernel: Jan 19 10:15:32 server INPUT:ACCEPT IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("ACCEPT", result.Events[0].Action);
    }

    [Fact]
    public void ParseTimestamp_JanuaryLogInDecember_StaysInReferenceYear()
    {
        // A January log line read in December is from January of the SAME year
        // (11 months in the past). Logs record past events; the parser must never
        // shift a line into the future.
        var logLine = "kernel: Jan 10 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";
        var referenceDate = new DateTime(2026, 12, 20);

        var timestamp = LinuxIptablesParser.ParseTimestamp(logLine, referenceDate);

        Assert.Equal(2026, timestamp.Year);
        Assert.Equal(1, timestamp.Month);
        Assert.Equal(10, timestamp.Day);
        Assert.Equal(10, timestamp.Hour);
        Assert.Equal(15, timestamp.Minute);
        Assert.Equal(32, timestamp.Second);
    }

    [Fact]
    public void ParseTimestamp_DecemberLogInJuly_AdjustsToPreviousYear()
    {
        // December log parsed in July: Dec 10 with the reference year would be
        // ~5 months in the FUTURE — impossible for a log line — so the parser
        // resolves it to the previous December.
        var logLine = "kernel: Dec 10 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";
        var referenceDate = new DateTime(2026, 7, 1);

        var timestamp = LinuxIptablesParser.ParseTimestamp(logLine, referenceDate);

        Assert.Equal(2025, timestamp.Year);
        Assert.Equal(12, timestamp.Month);
        Assert.Equal(10, timestamp.Day);
    }

    [Fact]
    public void ParseTimestamp_DecemberLogInJanuary_AdjustsToPreviousYear()
    {
        // December log parsed in January: Dec 10 with year 2026 is ~11 months
        // in the future, exceeding the 180-day threshold, so subtract 1 year → 2025.
        var logLine = "kernel: Dec 10 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";
        var referenceDate = new DateTime(2026, 1, 15);

        var timestamp = LinuxIptablesParser.ParseTimestamp(logLine, referenceDate);

        Assert.Equal(2025, timestamp.Year);
        Assert.Equal(12, timestamp.Month);
        Assert.Equal(10, timestamp.Day);
    }

    [Fact]
    public void ParseTimestamp_MidYearLog_NoAdjustment()
    {
        // July log parsed in July: same year, well within 180 days.
        var logLine = "kernel: Jul 15 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";
        var referenceDate = new DateTime(2026, 7, 15);

        var timestamp = LinuxIptablesParser.ParseTimestamp(logLine, referenceDate);

        Assert.Equal(2026, timestamp.Year);
        Assert.Equal(7, timestamp.Month);
        Assert.Equal(15, timestamp.Day);
    }

    [Fact]
    public void Parse_NullInput_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _parser.Parse(null!));
    }

    [Fact]
    public void Parse_ReorderedDstBeforeSrc_ParsesCorrectly()
    {
        var logLine = "Apr 30 14:30:00 host kernel: DROP IN=eth0 DST=10.0.0.1 SRC=192.168.1.100 PROTO=TCP SPT=12345 DPT=80";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("192.168.1.100", result.Events[0].SourceIP);
        Assert.Equal("10.0.0.1", result.Events[0].DestinationIP);
    }

    [Fact]
    public void Parse_ReorderedDptBeforeSpt_ParsesCorrectly()
    {
        var logLine = "Apr 30 14:30:00 host kernel: DROP IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP DPT=443 SPT=12345";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal(12345, result.Events[0].SourcePort);
        Assert.Equal(443, result.Events[0].DestinationPort);
    }

    [Fact]
    public void Parse_PrefixedFields_RequiresWordBoundary()
    {
        var logLine = "Apr 30 14:30:00 host kernel: DROP IN=eth0 ORIGSRC=1.1.1.1 SRC=192.168.1.100 DST=10.0.0.1 ORIGSPT=1 SPT=12345 DPT=80 PROTO=TCP";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal("192.168.1.100", result.Events[0].SourceIP);
        Assert.Equal(12345, result.Events[0].SourcePort);
        Assert.Equal(80, result.Events[0].DestinationPort);
    }

    [Fact]
    public void Parse_WithReferenceDate_UsesProvidedDateForYearInference()
    {
        var logLine = "kernel: Jul 15 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";
        var referenceDate = new DateTime(2024, 7, 15);

        var result = _parser.Parse(logLine, referenceDate);

        Assert.Single(result.Events);
        Assert.Equal(2024, result.Events[0].Timestamp.Year);
        Assert.Equal(7, result.Events[0].Timestamp.Month);
        Assert.Equal(15, result.Events[0].Timestamp.Day);
    }

    [Fact]
    public void Parse_WithReferenceDate_JanuaryLogInDecember_StaysInReferenceYear()
    {
        // A January line read in December is from earlier that same year; the
        // parser must not push it into the future.
        var logLine = "kernel: Jan 10 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";
        var referenceDate = new DateTime(2026, 12, 20);

        var result = _parser.Parse(logLine, referenceDate);

        Assert.Single(result.Events);
        Assert.Equal(2026, result.Events[0].Timestamp.Year);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65535)]
    public void Parse_PortBoundaryValues_ParsesSuccessfully(int port)
    {
        var logLine = $"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT={port} DPT={port}";

        var result = _parser.Parse(logLine);

        Assert.Single(result.Events);
        Assert.Equal(port, result.Events[0].SourcePort);
        Assert.Equal(port, result.Events[0].DestinationPort);
    }

    [Fact]
    public void Parse_PortNegativeValue_AddsParseError()
    {
        // Negative ports are now caught by the independent SourcePortRegex
        // and rejected by ParsePort instead of silently defaulting to 0.
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=-1 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Empty(result.Events);
        Assert.NotEmpty(result.Errors);
        Assert.Contains("Invalid port number", result.Errors[0]);
    }

    [Fact]
    public void Parse_PortNonNumericValue_AddsParseError()
    {
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=abc DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Empty(result.Events);
        Assert.NotEmpty(result.Errors);
        Assert.Contains("Invalid port number", result.Errors[0]);
    }

    [Fact]
    public void Parse_PortAboveMaxValue_AddsParseError()
    {
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=65536 DPT=22";

        var result = _parser.Parse(logLine);

        Assert.Empty(result.Events);
        Assert.NotEmpty(result.Errors);
    }

    [Fact]
    public void Parse_MissingOptionalFields_ParsesRequiredFieldsOnly()
    {
        // No MAC, LEN, TOS, TTL, ID, WINDOW, etc.
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

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
    public void ParseTimestamp_WithinFutureSkewTolerance_StaysInReferenceYear()
    {
        // A line dated ~1 day ahead of the reference is within the clock-skew /
        // timezone tolerance, so the reference year is kept.
        var logLine = "kernel: Jul 2 09:59:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";
        var referenceDate = new DateTime(2026, 7, 1, 10, 0, 0);

        var timestamp = LinuxIptablesParser.ParseTimestamp(logLine, referenceDate);

        Assert.Equal(2026, timestamp.Year);
        Assert.Equal(7, timestamp.Month);
        Assert.Equal(2, timestamp.Day);
    }

    [Fact]
    public void ParseTimestamp_BeyondFutureSkew_AdjustsToPreviousYear()
    {
        // A line dated more than a day ahead of the reference cannot be a real
        // future event, so it resolves to the previous year's occurrence.
        var logLine = "kernel: Jul 3 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";
        var referenceDate = new DateTime(2026, 7, 1);

        var timestamp = LinuxIptablesParser.ParseTimestamp(logLine, referenceDate);

        Assert.Equal(2025, timestamp.Year);
        Assert.Equal(7, timestamp.Month);
        Assert.Equal(3, timestamp.Day);
    }

    [Fact]
    public void ParseTimestamp_OldLogLine_NeverShiftedIntoNextYear()
    {
        // Regression (found 2026-07-18): the previous heuristic moved lines older
        // than 180 days into NEXT year — a January line read on 2026-07-18 was
        // stamped 2027. Historical lines must stay in the past.
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";
        var referenceDate = new DateTime(2026, 7, 18);

        var timestamp = LinuxIptablesParser.ParseTimestamp(logLine, referenceDate);

        Assert.Equal(2026, timestamp.Year);
        Assert.Equal(1, timestamp.Month);
        Assert.Equal(19, timestamp.Day);
    }

    [Fact]
    public void ParseTimestamp_ReturnsUnspecifiedKind()
    {
        var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

        var timestamp = LinuxIptablesParser.ParseTimestamp(logLine);

        Assert.Equal(DateTimeKind.Unspecified, timestamp.Kind);
    }
}
