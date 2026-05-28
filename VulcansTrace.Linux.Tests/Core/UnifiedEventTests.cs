using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Core;

public class UnifiedEventTests
{
    [Fact]
    public void ConnectionKey_WithValidFields_FormatsCorrectly()
    {
        // Arrange
        var evt = new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "192.168.1.100",
            SourcePort = 54321,
            DestinationIP = "192.168.1.1",
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        };

        // Act
        var key = evt.ConnectionKey;

        // Assert
        Assert.Equal("192.168.1.100:54321-192.168.1.1:22-TCP", key);
    }

    [Fact]
    public void UnifiedEvent_WithAllFields_InitializesCorrectly()
    {
        // Arrange & Act
        var evt = new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "192.168.1.100",
            SourcePort = 54321,
            DestinationIP = "192.168.1.1",
            DestinationPort = 22,
            Protocol = "TCP",
            Action = "ACCEPT",
            LogFormat = LogFormat.Iptables,
            LinuxSpecific = new Dictionary<string, string>
            {
                { "InterfaceIn", "eth0" },
                { "MAC", "00:11:22:33:44:55" }
            }
        };

        // Assert
        Assert.Equal("192.168.1.100", evt.SourceIP);
        Assert.Equal(54321, evt.SourcePort);
        Assert.Equal("eth0", evt.LinuxSpecific["InterfaceIn"]);
        Assert.Equal("00:11:22:33:44:55", evt.LinuxSpecific["MAC"]);
    }

    [Fact]
    public void ConnectionKey_WithUdpProtocol_FormatsCorrectly()
    {
        // Arrange
        var evt = new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "10.0.0.1",
            SourcePort = 12345,
            DestinationIP = "10.0.0.2",
            DestinationPort = 53,
            Protocol = "UDP",
            LogFormat = LogFormat.Iptables
        };

        // Act
        var key = evt.ConnectionKey;

        // Assert
        Assert.Equal("10.0.0.1:12345-10.0.0.2:53-UDP", key);
    }

    [Fact]
    public void ConnectionKey_WithDifferentPorts_FormatsCorrectly()
    {
        // Arrange
        var evt = new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "172.16.0.1",
            SourcePort = 80,
            DestinationIP = "172.16.0.2",
            DestinationPort = 443,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        };

        // Act
        var key = evt.ConnectionKey;

        // Assert
        Assert.Equal("172.16.0.1:80-172.16.0.2:443-TCP", key);
    }

    [Fact]
    public void UnifiedEvent_WithEmptyLinuxSpecificDictionary_HandlesGracefully()
    {
        // Arrange & Act
        var evt = new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "192.168.1.100",
            SourcePort = 54321,
            DestinationIP = "192.168.1.1",
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables,
            LinuxSpecific = new Dictionary<string, string>()
        };

        // Assert
        Assert.NotNull(evt.LinuxSpecific);
        Assert.Empty(evt.LinuxSpecific);
    }

    [Fact]
    public void UnifiedEvent_WithMultipleLinuxSpecificFields_StoresAll()
    {
        // Arrange & Act
        var evt = new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "192.168.1.100",
            SourcePort = 54321,
            DestinationIP = "192.168.1.1",
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables,
            LinuxSpecific = new Dictionary<string, string>
            {
                { "InterfaceIn", "eth0" },
                { "InterfaceOut", "eth1" },
                { "MAC", "00:11:22:33:44:55" },
                { "Chain", "INPUT" }
            }
        };

        // Assert
        Assert.Equal(4, evt.LinuxSpecific.Count);
        Assert.Equal("eth0", evt.LinuxSpecific["InterfaceIn"]);
        Assert.Equal("eth1", evt.LinuxSpecific["InterfaceOut"]);
        Assert.Equal("INPUT", evt.LinuxSpecific["Chain"]);
    }

    [Fact]
    public void ConnectionKey_WithIPv6Address_FormatsCorrectly()
    {
        // Arrange
        var evt = new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "2001:0db8:85a3::8a2e:0370:7334",
            SourcePort = 54321,
            DestinationIP = "2001:0db8:85a3::8a2e:0370:7335",
            DestinationPort = 80,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        };

        // Act
        var key = evt.ConnectionKey;

        // Assert
        Assert.Contains("2001:0db8:85a3::8a2e:0370:7334", key);
        Assert.Contains("2001:0db8:85a3::8a2e:0370:7335", key);
        Assert.Contains("TCP", key);
    }

    [Fact]
    public void UnifiedEvent_Timestamp_IsSetCorrectly()
    {
        // Arrange
        var timestamp = DateTime.UtcNow;

        // Act
        var evt = new UnifiedEvent
        {
            Timestamp = timestamp,
            SourceIP = "192.168.1.100",
            SourcePort = 54321,
            DestinationIP = "192.168.1.1",
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        };

        // Assert
        Assert.Equal(timestamp, evt.Timestamp);
    }

    [Fact]
    public void SourceIP_InvalidFormat_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "not-an-ip-address",
            DestinationIP = "192.168.1.1",
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
    }

    [Fact]
    public void DestinationIP_InvalidFormat_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "192.168.1.1",
            DestinationIP = "999.999.999.999",
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
    }

    [Fact]
    public void SourceIP_Empty_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "",
            DestinationIP = "192.168.1.1",
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
    }

    [Fact]
    public void SourcePort_Negative_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "192.168.1.100",
            SourcePort = -1,
            DestinationIP = "192.168.1.1",
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
    }

    [Fact]
    public void SourcePort_Above65535_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "192.168.1.100",
            SourcePort = 65536,
            DestinationIP = "192.168.1.1",
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
    }

    [Fact]
    public void DestinationPort_Above65535_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.1",
            DestinationPort = 70000,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
    }

    [Fact]
    public void Protocol_Empty_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.1",
            Protocol = "",
            LogFormat = LogFormat.Iptables
        });
    }

    [Fact]
    public void Protocol_Whitespace_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.1",
            Protocol = "   ",
            LogFormat = LogFormat.Iptables
        });
    }

    [Fact]
    public void LogFormat_Unknown_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.1",
            Protocol = "TCP",
            LogFormat = LogFormat.Unknown
        });
    }

    [Fact]
    public void Timestamp_DefaultDateTime_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new UnifiedEvent
        {
            Timestamp = default,
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.1",
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
    }

    [Fact]
    public void LinuxSpecific_Null_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.1",
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables,
            LinuxSpecific = null!
        });
    }

    [Fact]
    public void SourcePort_Zero_IsValid()
    {
        var evt = new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "192.168.1.100",
            SourcePort = 0,
            DestinationIP = "192.168.1.1",
            DestinationPort = 0,
            Protocol = "ICMP",
            LogFormat = LogFormat.Iptables
        };

        Assert.Equal(0, evt.SourcePort);
        Assert.Equal(0, evt.DestinationPort);
    }

    [Fact]
    public void SourcePort_65535_IsValid()
    {
        var evt = new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = "192.168.1.100",
            SourcePort = 65535,
            DestinationIP = "192.168.1.1",
            DestinationPort = 65535,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        };

        Assert.Equal(65535, evt.SourcePort);
        Assert.Equal(65535, evt.DestinationPort);
    }

    [Fact]
    public void AnalysisResult_TimeRangeStart_AfterTimeRangeEnd_ThrowsInInitializer()
    {
        Assert.Throws<ArgumentException>(() => new AnalysisResult
        {
            TimeRangeStart = new DateTime(2026, 6, 1, 0, 0, 0, DateTimeKind.Utc),
            TimeRangeEnd = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            Findings = Array.Empty<Finding>()
        });
    }

    [Fact]
    public void AnalysisResult_TimeRangeStart_BeforeTimeRangeEnd_Succeeds()
    {
        var result = new AnalysisResult
        {
            TimeRangeStart = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            TimeRangeEnd = new DateTime(2026, 6, 1, 0, 0, 0, DateTimeKind.Utc),
            Findings = Array.Empty<Finding>()
        };

        Assert.Equal(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), result.TimeRangeStart);
        Assert.Equal(new DateTime(2026, 6, 1, 0, 0, 0, DateTimeKind.Utc), result.TimeRangeEnd);
    }

    [Fact]
    public void Finding_TimeRangeStart_AfterTimeRangeEnd_ThrowsInInitializer()
    {
        Assert.Throws<ArgumentException>(() => new Finding
        {
            Category = "Test",
            SourceHost = "10.0.0.1",
            Target = "10.0.0.2",
            TimeRangeStart = new DateTime(2026, 6, 1, 0, 0, 0, DateTimeKind.Utc),
            TimeRangeEnd = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            ShortDescription = "Test",
            Details = "Test"
        });
    }

    [Fact]
    public void Finding_TimeRangeStart_BeforeTimeRangeEnd_Succeeds()
    {
        var f = new Finding
        {
            Category = "Test",
            SourceHost = "10.0.0.1",
            Target = "10.0.0.2",
            TimeRangeStart = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            TimeRangeEnd = new DateTime(2026, 6, 1, 0, 0, 0, DateTimeKind.Utc),
            ShortDescription = "Test",
            Details = "Test"
        };

        Assert.True(f.TimeRangeStart <= f.TimeRangeEnd);
    }
}
