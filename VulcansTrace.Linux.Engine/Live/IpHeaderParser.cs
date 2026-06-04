using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace VulcansTrace.Linux.Engine.Live;

/// <summary>
/// Parses raw IP, TCP, and UDP headers from byte spans captured via AF_PACKET.
/// All parsing is done without unsafe code using BinaryPrimitives.
/// </summary>
internal static class IpHeaderParser
{
    public const byte IpProtocolTcp = 6;
    public const byte IpProtocolUdp = 17;
    public const byte IpProtocolIcmp = 1;

    /// <summary>
    /// Attempts to parse an IPv4 packet starting at the given span.
    /// Returns source IP, destination IP, protocol, IP total length, and payload offset.
    /// </summary>
    public static bool TryParseIpv4(ReadOnlySpan<byte> packet, out string sourceIp, out string destinationIp, out byte protocol, out byte ttl, out ushort ipTotalLength, out int payloadOffset)
    {
        sourceIp = string.Empty;
        destinationIp = string.Empty;
        protocol = 0;
        ttl = 0;
        ipTotalLength = 0;
        payloadOffset = 0;

        // Minimum IPv4 header: 20 bytes
        if (packet.Length < 20)
            return false;

        byte versionAndIhl = packet[0];
        int version = versionAndIhl >> 4;
        if (version != 4)
            return false;

        int ihl = (versionAndIhl & 0x0F) * 4; // header length in bytes
        if (ihl < 20 || packet.Length < ihl)
            return false;

        ipTotalLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2));
        ttl = packet[8];
        protocol = packet[9];

        sourceIp = FormatIpAddress(packet.Slice(12, 4));
        destinationIp = FormatIpAddress(packet.Slice(16, 4));

        payloadOffset = ihl;
        return true;
    }

    /// <summary>
    /// Attempts to parse a TCP header from the payload span.
    /// </summary>
    public static bool TryParseTcp(ReadOnlySpan<byte> payload, out ushort sourcePort, out ushort destinationPort, out byte flags)
    {
        sourcePort = 0;
        destinationPort = 0;
        flags = 0;

        if (payload.Length < 20)
            return false;

        sourcePort = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(0, 2));
        destinationPort = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2));
        int dataOffset = (payload[12] >> 4) * 4;
        if (dataOffset < 20 || payload.Length < dataOffset)
            return false;

        flags = payload[13];
        return true;
    }

    /// <summary>
    /// Attempts to parse a UDP header from the payload span.
    /// </summary>
    public static bool TryParseUdp(ReadOnlySpan<byte> payload, out ushort sourcePort, out ushort destinationPort, out ushort length)
    {
        sourcePort = 0;
        destinationPort = 0;
        length = 0;

        if (payload.Length < 8)
            return false;

        sourcePort = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(0, 2));
        destinationPort = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2));
        length = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4, 2));
        return true;
    }

    private static string FormatIpAddress(ReadOnlySpan<byte> bytes)
    {
        return $"{bytes[0]}.{bytes[1]}.{bytes[2]}.{bytes[3]}";
    }
}
