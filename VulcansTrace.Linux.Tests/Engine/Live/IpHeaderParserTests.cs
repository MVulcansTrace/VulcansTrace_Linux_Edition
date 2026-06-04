using System.Buffers.Binary;
using VulcansTrace.Linux.Engine.Live;

namespace VulcansTrace.Linux.Tests.Engine.Live;

public class IpHeaderParserTests
{
    [Fact]
    public void TryParseIpv4_ValidPacket_ParsesCorrectly()
    {
        var packet = BuildIpv4Packet(protocol: IpHeaderParser.IpProtocolTcp, srcIp: "192.168.1.100", dstIp: "10.0.0.1", totalLength: 60);

        bool ok = IpHeaderParser.TryParseIpv4(packet, out var src, out var dst, out var proto, out var ttl, out var len, out var offset);

        Assert.True(ok);
        Assert.Equal("192.168.1.100", src);
        Assert.Equal("10.0.0.1", dst);
        Assert.Equal(IpHeaderParser.IpProtocolTcp, proto);
        Assert.Equal(64, ttl);
        Assert.Equal(60, len);
        Assert.Equal(20, offset);
    }

    [Fact]
    public void TryParseIpv4_UdpPacket_ParsesCorrectly()
    {
        var packet = BuildIpv4Packet(protocol: IpHeaderParser.IpProtocolUdp, srcIp: "172.16.0.5", dstIp: "8.8.8.8", totalLength: 40);

        bool ok = IpHeaderParser.TryParseIpv4(packet, out var src, out var dst, out var proto, out var ttl, out var len, out var offset);

        Assert.True(ok);
        Assert.Equal(IpHeaderParser.IpProtocolUdp, proto);
        Assert.Equal(64, ttl);
        Assert.Equal("172.16.0.5", src);
        Assert.Equal("8.8.8.8", dst);
    }

    [Fact]
    public void TryParseIpv4_TooShort_ReturnsFalse()
    {
        var packet = new byte[10];
        bool ok = IpHeaderParser.TryParseIpv4(packet, out _, out _, out _, out _, out _, out _);
        Assert.False(ok);
    }

    [Fact]
    public void TryParseIpv4_NonIPv4_ReturnsFalse()
    {
        var packet = new byte[20];
        packet[0] = 0x60; // IPv6 version
        bool ok = IpHeaderParser.TryParseIpv4(packet, out _, out _, out _, out _, out _, out _);
        Assert.False(ok);
    }

    [Fact]
    public void TryParseTcp_ValidHeader_ParsesPortsAndFlags()
    {
        var tcp = new byte[24];
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(0, 2), 54321);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(2, 2), 22);
        tcp[12] = 0x50; // data offset = 5 (20 bytes)
        tcp[13] = 0x02; // SYN flag

        bool ok = IpHeaderParser.TryParseTcp(tcp, out var srcPort, out var dstPort, out var flags);

        Assert.True(ok);
        Assert.Equal(54321, srcPort);
        Assert.Equal(22, dstPort);
        Assert.Equal(0x02, flags);
    }

    [Fact]
    public void TryParseTcp_TooShort_ReturnsFalse()
    {
        var tcp = new byte[10];
        bool ok = IpHeaderParser.TryParseTcp(tcp, out _, out _, out _);
        Assert.False(ok);
    }

    [Fact]
    public void TryParseUdp_ValidHeader_ParsesPortsAndLength()
    {
        var udp = new byte[8];
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(0, 2), 12345);
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(2, 2), 53);
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(4, 2), 32);

        bool ok = IpHeaderParser.TryParseUdp(udp, out var srcPort, out var dstPort, out var length);

        Assert.True(ok);
        Assert.Equal(12345, srcPort);
        Assert.Equal(53, dstPort);
        Assert.Equal(32, length);
    }

    [Fact]
    public void TryParseUdp_TooShort_ReturnsFalse()
    {
        var udp = new byte[4];
        bool ok = IpHeaderParser.TryParseUdp(udp, out _, out _, out _);
        Assert.False(ok);
    }

    private static byte[] BuildIpv4Packet(byte protocol, string srcIp, string dstIp, ushort totalLength)
    {
        var packet = new byte[20];
        packet[0] = 0x45; // Version 4, IHL 5
        packet[1] = 0x00; // DSCP/ECN
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), totalLength);
        packet[8] = 64; // TTL
        packet[9] = protocol;

        WriteIpAddress(packet.AsSpan(12, 4), srcIp);
        WriteIpAddress(packet.AsSpan(16, 4), dstIp);

        return packet;
    }

    private static void WriteIpAddress(Span<byte> target, string ip)
    {
        var parts = ip.Split('.');
        for (int i = 0; i < 4; i++)
        {
            target[i] = byte.Parse(parts[i]);
        }
    }
}
