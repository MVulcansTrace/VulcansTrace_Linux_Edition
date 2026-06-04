using System.Buffers.Binary;
using System.Net;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine.Live;

namespace VulcansTrace.Linux.Tests.Engine.Live;

public class NflogEventSourceTests
{
    private static readonly byte[] SrcIp = { 192, 168, 1, 100 };
    private static readonly byte[] DstIp = { 10, 0, 0, 5 };

    private static bool InvokeTryParse(ReadOnlySpan<byte> data, out UnifiedEvent? evt)
    {
        return NflogEventSource.TryParseNflogMessage(data, out evt);
    }

    /// <summary>
    /// Builds a minimal valid NFLOG message with an IPv4 TCP payload.
    /// </summary>
    private static byte[] BuildNflogMessage(
        ushort group = 1,
        byte[]? payload = null,
        (ushort type, byte[] data)[]? extraAttrs = null)
    {
        payload ??= BuildTcpPayload(SrcIp, DstIp, srcPort: 54321, dstPort: 443, flags: 0x02);

        // nlmsghdr (16 bytes)
        // nfgenmsg (4 bytes)
        // NFULA_PAYLOAD TLV
        // optional extra TLVs

        var attrs = new List<byte[]>();

        // NFULA_PAYLOAD = 9, from linux/netfilter/nfnetlink_log.h.
        attrs.Add(BuildTlv(9, payload));

        if (extraAttrs != null)
        {
            foreach (var (type, data) in extraAttrs)
            {
                attrs.Add(BuildTlv(type, data));
            }
        }

        int attrTotalLen = attrs.Sum(a => a.Length);
        int nlmsgLen = 16 + 4 + attrTotalLen;

        var msg = new byte[nlmsgLen];
        int offset = 0;

        // nlmsg_len
        BinaryPrimitives.WriteUInt32LittleEndian(msg.AsSpan(offset, 4), (uint)nlmsgLen);
        offset += 4;
        // nlmsg_type = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET
        BinaryPrimitives.WriteUInt16LittleEndian(msg.AsSpan(offset, 2), (ushort)(4 << 8));
        offset += 2;
        // nlmsg_flags
        BinaryPrimitives.WriteUInt16LittleEndian(msg.AsSpan(offset, 2), 0);
        offset += 2;
        // nlmsg_seq
        BinaryPrimitives.WriteUInt32LittleEndian(msg.AsSpan(offset, 4), 0);
        offset += 4;
        // nlmsg_pid
        BinaryPrimitives.WriteUInt32LittleEndian(msg.AsSpan(offset, 4), 0);
        offset += 4;

        // nfgenmsg
        msg[offset++] = 0; // family = AF_UNSPEC
        msg[offset++] = 0; // version
        BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(offset, 2), group);
        offset += 2;

        foreach (var attr in attrs)
        {
            attr.CopyTo(msg, offset);
            offset += attr.Length;
        }

        return msg;
    }

    private static byte[] BuildTlv(ushort type, byte[] data)
    {
        int len = 4 + data.Length;
        int paddedLen = (len + 3) & ~3;
        var tlv = new byte[paddedLen];
        BinaryPrimitives.WriteUInt16LittleEndian(tlv.AsSpan(0, 2), (ushort)len);
        BinaryPrimitives.WriteUInt16LittleEndian(tlv.AsSpan(2, 2), type);
        data.CopyTo(tlv, 4);
        return tlv;
    }

    private static byte[] BuildTcpPayload(byte[] srcIp, byte[] dstIp, ushort srcPort, ushort dstPort, byte flags)
    {
        // IPv4 header (20 bytes) + TCP header (20 bytes)
        var packet = new byte[40];
        packet[0] = 0x45; // version 4, IHL 5
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), 40); // total length
        packet[8] = 64; // TTL
        packet[9] = 6; // TCP protocol
        srcIp.CopyTo(packet, 12);
        dstIp.CopyTo(packet, 16);

        // TCP header
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20, 2), srcPort);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22, 2), dstPort);
        packet[32] = 0x50; // data offset = 5 (20 bytes)
        packet[33] = flags;

        return packet;
    }

    private static byte[] BuildUdpPayload(byte[] srcIp, byte[] dstIp, ushort srcPort, ushort dstPort)
    {
        // IPv4 header (20 bytes) + UDP header (8 bytes)
        var packet = new byte[28];
        packet[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), 28);
        packet[8] = 64;
        packet[9] = 17; // UDP protocol
        srcIp.CopyTo(packet, 12);
        dstIp.CopyTo(packet, 16);

        // UDP header
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20, 2), srcPort);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22, 2), dstPort);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(24, 2), 8); // length

        return packet;
    }

    [Fact]
    public void TryParseNflogMessage_TooShort_ReturnsFalse()
    {
        var data = new byte[10];
        Assert.False(InvokeTryParse(data, out _));
    }

    [Fact]
    public void TryParseNflogMessage_NlmsgLenExceedsData_ReturnsFalse()
    {
        var data = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), 1000); // claim 1000 bytes
        Assert.False(InvokeTryParse(data, out _));
    }

    [Fact]
    public void TryParseNflogMessage_MissingPayload_ReturnsFalse()
    {
        // Message with only a MARK attribute, no payload
        var markAttr = BuildTlv(2, new byte[] { 0, 0, 0, 42 });
        int nlmsgLen = 16 + 4 + markAttr.Length;
        var msg = new byte[nlmsgLen];
        BinaryPrimitives.WriteUInt32LittleEndian(msg.AsSpan(0, 4), (uint)nlmsgLen);
        BinaryPrimitives.WriteUInt16LittleEndian(msg.AsSpan(4, 2), (ushort)(4 << 8));
        markAttr.CopyTo(msg, 20);

        Assert.False(InvokeTryParse(msg, out _));
    }

    [Fact]
    public void TryParseNflogMessage_ValidTcpPayload_ParsesCorrectly()
    {
        var msg = BuildNflogMessage();
        Assert.True(InvokeTryParse(msg, out var evt));
        Assert.NotNull(evt);
        Assert.Equal("192.168.1.100", evt.SourceIP);
        Assert.Equal("10.0.0.5", evt.DestinationIP);
        Assert.Equal(54321, evt.SourcePort);
        Assert.Equal(443, evt.DestinationPort);
        Assert.Equal("TCP", evt.Protocol);
        Assert.Equal("LOGGED", evt.Action);
        Assert.Equal("SYN", evt.LinuxSpecific["FLAGS"]);
        Assert.Equal("64", evt.LinuxSpecific["TTL"]);
    }

    [Fact]
    public void TryParseNflogMessage_ValidUdpPayload_ParsesCorrectly()
    {
        var payload = BuildUdpPayload(SrcIp, DstIp, srcPort: 12345, dstPort: 53);
        var msg = BuildNflogMessage(payload: payload);
        Assert.True(InvokeTryParse(msg, out var evt));
        Assert.NotNull(evt);
        Assert.Equal("UDP", evt.Protocol);
        Assert.Equal(12345, evt.SourcePort);
        Assert.Equal(53, evt.DestinationPort);
        Assert.Equal("UDP", evt.LinuxSpecific["FLAGS"]);
    }

    [Fact]
    public void TryParseNflogMessage_WithTimestamp_UsesKernelTime()
    {
        ulong sec = 1717420000;
        ulong usec = 123456;
        var tsData = new byte[16];
        BinaryPrimitives.WriteUInt64BigEndian(tsData.AsSpan(0, 8), sec);
        BinaryPrimitives.WriteUInt64BigEndian(tsData.AsSpan(8, 8), usec);

        var msg = BuildNflogMessage(extraAttrs: new[] { ((ushort)3, tsData) });
        Assert.True(InvokeTryParse(msg, out var evt));
        Assert.NotNull(evt);

        var expected = DateTime.UnixEpoch + TimeSpan.FromSeconds(sec) + TimeSpan.FromMicroseconds(usec);
        Assert.Equal(expected, evt.Timestamp);
    }

    [Fact]
    public void TryParseNflogMessage_WithMark_ParsesMark()
    {
        var markData = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(markData, 0xDEADBEEF);

        var msg = BuildNflogMessage(extraAttrs: new[] { ((ushort)2, markData) });
        Assert.True(InvokeTryParse(msg, out var evt));
        Assert.NotNull(evt);
        Assert.Equal("3735928559", evt.LinuxSpecific["MARK"]);
    }

    [Fact]
    public void TryParseNflogMessage_WithIfindex_ParsesInterfaces()
    {
        var inData = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(inData, 2);
        var outData = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(outData, 3);

        var msg = BuildNflogMessage(extraAttrs: new[]
        {
            ((ushort)4, inData),
            ((ushort)5, outData)
        });
        Assert.True(InvokeTryParse(msg, out var evt));
        Assert.NotNull(evt);
        Assert.Equal("ifindex2", evt.LinuxSpecific["IN"]);
        Assert.Equal("ifindex3", evt.LinuxSpecific["OUT"]);
    }

    [Fact]
    public void TryParseNflogMessage_WithUid_ParsesUid()
    {
        var uidData = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(uidData, 1000);

        var msg = BuildNflogMessage(extraAttrs: new[] { ((ushort)11, uidData) });
        Assert.True(InvokeTryParse(msg, out var evt));
        Assert.NotNull(evt);
        Assert.Equal("1000", evt.LinuxSpecific["UID"]);
    }

    [Fact]
    public void TryParseNflogMessage_WithHwaddr_ParsesMac()
    {
        var hwData = new byte[8];
        hwData[2] = 0xAA;
        hwData[3] = 0xBB;
        hwData[4] = 0xCC;
        hwData[5] = 0xDD;
        hwData[6] = 0xEE;
        hwData[7] = 0xFF;

        var msg = BuildNflogMessage(extraAttrs: new[] { ((ushort)8, hwData) });
        Assert.True(InvokeTryParse(msg, out var evt));
        Assert.NotNull(evt);
        Assert.Equal("AA:BB:CC:DD:EE:FF", evt.LinuxSpecific["MAC"]);
    }

    [Fact]
    public void TryParseNflogMessage_MultipleAttributes_ParsesAll()
    {
        var markData = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(markData, 42);

        var uidData = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(uidData, 1000);

        var msg = BuildNflogMessage(extraAttrs: new[]
        {
            ((ushort)2, markData),
            ((ushort)11, uidData)
        });
        Assert.True(InvokeTryParse(msg, out var evt));
        Assert.NotNull(evt);
        Assert.Equal("42", evt.LinuxSpecific["MARK"]);
        Assert.Equal("1000", evt.LinuxSpecific["UID"]);
        Assert.Equal("192.168.1.100", evt.SourceIP);
    }

    [Fact]
    public void BuildConfigMessage_HasCorrectNlmsgHeader()
    {
        var msg = NflogEventSource.BuildConfigMessage(group: 5);

        // nlmsg_len at offset 0 (little-endian uint32)
        int nlmsgLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(msg.AsSpan(0, 4));
        Assert.True(nlmsgLen > 0 && nlmsgLen <= msg.Length, "nlmsg_len should be positive and fit in message");

        // nlmsg_type at offset 4 (little-endian uint16) = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG = 0x0401
        ushort nlmsgType = BinaryPrimitives.ReadUInt16LittleEndian(msg.AsSpan(4, 2));
        Assert.Equal(0x0401, nlmsgType);

        // nlmsg_flags at offset 6 = NLM_F_REQUEST = 1
        ushort nlmsgFlags = BinaryPrimitives.ReadUInt16LittleEndian(msg.AsSpan(6, 2));
        Assert.Equal(1, nlmsgFlags);

        // nlmsg_seq at offset 8 = 0
        uint nlmsgSeq = BinaryPrimitives.ReadUInt32LittleEndian(msg.AsSpan(8, 4));
        Assert.Equal(0u, nlmsgSeq);

        // nlmsg_pid at offset 12 = 0
        uint nlmsgPid = BinaryPrimitives.ReadUInt32LittleEndian(msg.AsSpan(12, 4));
        Assert.Equal(0u, nlmsgPid);
    }

    [Fact]
    public void BuildConfigMessage_HasCorrectNfgenmsg()
    {
        var msg = NflogEventSource.BuildConfigMessage(group: 7);

        // nfgenmsg at offset 16
        Assert.Equal(0, msg[16]); // family = AF_UNSPEC
        Assert.Equal(0, msg[17]); // version = NFNETLINK_V0
        ushort resId = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(18, 2));
        Assert.Equal(7, resId);
    }

    [Fact]
    public void BuildConfigMessage_HasCorrectNfulaCfgCmdAttribute()
    {
        var msg = NflogEventSource.BuildConfigMessage(group: 1);

        // Attribute starts at offset 20
        ushort attrLen = BinaryPrimitives.ReadUInt16LittleEndian(msg.AsSpan(20, 2));
        Assert.Equal(5, attrLen); // 2 (len) + 2 (type) + 1 (cmd), excluding padding

        ushort attrType = BinaryPrimitives.ReadUInt16LittleEndian(msg.AsSpan(22, 2));
        Assert.Equal(1, attrType); // NFULA_CFG_CMD

        Assert.Equal(1, msg[24]); // NFULNL_CFG_CMD_BIND

        // Padding should be zero
        Assert.Equal(0, msg[25]);
        Assert.Equal(0, msg[26]);
        Assert.Equal(0, msg[27]);
    }

    [Fact]
    public void BuildConfigMessage_HasPacketCopyModeAttribute()
    {
        var msg = NflogEventSource.BuildConfigMessage(group: 1);

        // Attribute starts after the padded command attribute:
        // 20 + align4(5) = 28
        ushort attrLen = BinaryPrimitives.ReadUInt16LittleEndian(msg.AsSpan(28, 2));
        Assert.Equal(10, attrLen); // 2 + 2 + config_mode(6), excluding padding

        ushort attrType = BinaryPrimitives.ReadUInt16LittleEndian(msg.AsSpan(30, 2));
        Assert.Equal(2, attrType); // NFULA_CFG_MODE

        uint copyRange = BinaryPrimitives.ReadUInt32BigEndian(msg.AsSpan(32, 4));
        Assert.Equal(65535u, copyRange);
        Assert.Equal(2, msg[36]); // NFULNL_COPY_PACKET
        Assert.Equal(0, msg[37]); // struct padding
        Assert.Equal(0, msg[38]); // netlink padding
        Assert.Equal(0, msg[39]); // netlink padding
    }

    [Fact]
    public void BuildConfigMessage_TotalLengthMatchesNlmsgLen()
    {
        var msg = NflogEventSource.BuildConfigMessage(group: 3);

        int nlmsgLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(msg.AsSpan(0, 4));
        Assert.Equal(msg.Length, nlmsgLen);
    }

    [Fact]
    public void BuildConfigMessage_TotalLengthIs40()
    {
        // 16 (nlmsghdr) + 4 (nfgenmsg) + 8 (NFULA_CFG_CMD padded)
        // + 12 (NFULA_CFG_MODE padded) = 40
        var msg = NflogEventSource.BuildConfigMessage(group: 99);
        Assert.Equal(40, msg.Length);
    }

    [Fact]
    public void BuildProtocolBindConfigMessage_UsesAfInetAndPfBind()
    {
        var msg = NflogEventSource.BuildProtocolBindConfigMessage();

        ushort resId = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(18, 2));
        Assert.Equal(2, resId); // AF_INET

        ushort attrLen = BinaryPrimitives.ReadUInt16LittleEndian(msg.AsSpan(20, 2));
        Assert.Equal(5, attrLen);

        ushort attrType = BinaryPrimitives.ReadUInt16LittleEndian(msg.AsSpan(22, 2));
        Assert.Equal(1, attrType); // NFULA_CFG_CMD

        Assert.Equal(3, msg[24]); // NFULNL_CFG_CMD_PF_BIND
        Assert.Equal(28, msg.Length);
    }
}
