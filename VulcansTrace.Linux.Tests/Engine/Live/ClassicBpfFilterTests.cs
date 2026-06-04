using VulcansTrace.Linux.Engine.Live;

namespace VulcansTrace.Linux.Tests.Engine.Live;

public class ClassicBpfFilterTests
{
    [Fact]
    public void TcpOrUdpOnly_ReturnsNonEmptyProgram()
    {
        var prog = ClassicBpfFilter.TcpOrUdpOnly();

        Assert.NotNull(prog);
        Assert.True(prog.Length > 0, "BPF program should contain instructions");
    }

    [Fact]
    public void TcpOrUdpOnly_EndsWithReturn()
    {
        var prog = ClassicBpfFilter.TcpOrUdpOnly();
        var last = prog[^1];

        // RET instruction class is 0x06 (bits 0-2 in classic BPF opcode)
        Assert.Equal(0x06, last.code & 0x07);
    }

    [Fact]
    public void IpProtoAny_ReturnsSingleInstruction()
    {
        var prog = ClassicBpfFilter.IpProtoAny();

        Assert.Single(prog);
        Assert.Equal(65535u, prog[0].k); // ACCEPT
    }

    [Fact]
    public void TcpOrUdpOnly_HasAcceptAndRejectPaths()
    {
        var prog = ClassicBpfFilter.TcpOrUdpOnly();

        uint acceptValue = 65535;
        uint rejectValue = 0;

        bool hasAccept = prog.Any(i => i.k == acceptValue);
        bool hasReject = prog.Any(i => i.k == rejectValue);

        Assert.True(hasAccept, "BPF program should have an ACCEPT path");
        Assert.True(hasReject, "BPF program should have a REJECT path");
    }
}
