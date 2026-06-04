using System.Runtime.InteropServices;

namespace VulcansTrace.Linux.Engine.Live;

/// <summary>
/// Pre-built classic BPF (cBPF) socket filter programs.
/// These are loaded into the kernel via setsockopt(SO_ATTACH_FILTER) on AF_PACKET sockets.
/// Classic BPF is the older BPF instruction set and is the only filter type
/// attachable to packet sockets here without libbpf/clang.
/// </summary>
internal static class ClassicBpfFilter
{
    /// <summary>
    /// BPF instruction class and opcode constants.
    /// </summary>
    private static class Bpf
    {
        // Instruction classes
        public const ushort LD = 0x00;
        public const ushort JMP = 0x05;
        public const ushort RET = 0x06;
        public const ushort ALU = 0x04;

        // Size modifiers
        public const ushort W = 0x00; // word
        public const ushort H = 0x08; // half-word
        public const ushort B = 0x10; // byte

        // Addressing modes
        public const ushort ABS = 0x20;
        public const ushort IMM = 0x00;

        // Jump conditions
        public const ushort JEQ = 0x10;
        public const ushort JSET = 0x40;
        public const ushort JGT = 0x20;

        // ALU operations
        public const ushort ADD = 0x00;
        public const ushort AND = 0x50;
        public const ushort LSH = 0x60;

        // Return values
        public const uint K = 0x00;

        // Helper to build instruction
        public static sock_filter Instruction(ushort code, byte jt, byte jf, uint k) =>
            new() { code = code, jt = jt, jf = jf, k = k };
    }

    /// <summary>
    /// Returns a classic BPF program that accepts only IPv4 TCP or UDP packets.
    /// Drops all other traffic at the kernel level before it reaches userspace.
    /// </summary>
    public static sock_filter[] TcpOrUdpOnly()
    {
        // BPF program logic:
        // 0: ldh [12]          ; load EtherType offset (for SOCK_RAW) or skip for SOCK_DGRAM
        // For SOCK_DGRAM (cooked mode), packet starts at IP header, so we adjust.
        // Actually with SOCK_DGRAM on AF_PACKET, the kernel strips the link-layer header
        // and delivers starting at the IP header. So we can read protocol at offset 9.
        //
        // 0: ldb [9]           ; load IP protocol field
        // 1: jeq #6  tcp_ok    ; if TCP -> accept
        // 2: jeq #17 udp_ok    ; if UDP -> accept
        // 3: ret #0            ; drop everything else
        // tcp_ok: ret #65535   ; accept
        // udp_ok: ret #65535   ; accept

        return
        [
            Bpf.Instruction((ushort)(Bpf.LD | Bpf.B | Bpf.ABS), 0, 0, 9),      // 0: load byte at offset 9 (IP protocol)
            Bpf.Instruction((ushort)(Bpf.JMP | Bpf.JEQ | Bpf.K), 2, 0, 6),     // 1: if == TCP, jump to accept (+2)
            Bpf.Instruction((ushort)(Bpf.JMP | Bpf.JEQ | Bpf.K), 1, 0, 17),    // 2: if == UDP, jump to accept (+1)
            Bpf.Instruction((ushort)(Bpf.RET | Bpf.K), 0, 0, 0),               // 3: drop
            Bpf.Instruction((ushort)(Bpf.RET | Bpf.K), 0, 0, 65535),           // 4: accept
        ];
    }

    /// <summary>
    /// Returns a classic BPF program that accepts all IPv4 packets.
    /// </summary>
    public static sock_filter[] IpProtoAny()
    {
        // For SOCK_DGRAM, we just accept everything (the socket is already IPv4).
        // This is a trivial pass-through filter.
        return
        [
            Bpf.Instruction((ushort)(Bpf.RET | Bpf.K), 0, 0, 65535),
        ];
    }

    /// <summary>
    /// Attaches a classic BPF filter to the given socket file descriptor.
    /// </summary>
    /// <param name="fd">Socket file descriptor.</param>
    /// <param name="filter">BPF instruction array.</param>
    /// <returns>0 on success, -1 on failure with errno set.</returns>
    public static int AttachFilter(int fd, sock_filter[] filter)
    {
        int filterSize = filter.Length * Marshal.SizeOf<sock_filter>();
        IntPtr filterPtr = Marshal.AllocHGlobal(filterSize);
        try
        {
            for (int i = 0; i < filter.Length; i++)
            {
                IntPtr offset = IntPtr.Add(filterPtr, i * Marshal.SizeOf<sock_filter>());
                Marshal.StructureToPtr(filter[i], offset, false);
            }

            if (filter.Length > ushort.MaxValue)
            {
                throw new ArgumentException(
                    $"BPF filter too large: {filter.Length} instructions exceed maximum {ushort.MaxValue}.",
                    nameof(filter));
            }

            var fprog = new sock_fprog
            {
                len = (ushort)filter.Length,
                filter = filterPtr
            };

            int fprogSize = Marshal.SizeOf<sock_fprog>();
            IntPtr fprogPtr = Marshal.AllocHGlobal(fprogSize);
            try
            {
                Marshal.StructureToPtr(fprog, fprogPtr, false);
                return NativeSocket.setsockopt(fd, NativeSocket.SOL_SOCKET, NativeSocket.SO_ATTACH_FILTER, fprogPtr, fprogSize);
            }
            finally
            {
                Marshal.FreeHGlobal(fprogPtr);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(filterPtr);
        }
    }
}
