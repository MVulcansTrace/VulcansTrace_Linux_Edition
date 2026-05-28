using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace VulcansTrace.Linux.Core.Parsing;

internal static class FirewallLogRegex
{
    internal static readonly Regex SourceIpRegex = new(
        @"\bSRC=(?<src_ip>[0-9a-fA-F:.]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex DestinationIpRegex = new(
        @"\bDST=(?<dst_ip>[0-9a-fA-F:.]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex SourcePortRegex = new(
        @"\bSPT=(?<src_port>\S+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex DestinationPortRegex = new(
        @"\bDPT=(?<dst_port>\S+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex ProtocolRegex = new(
        @"\bPROTO=(?<protocol>\w+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex InInterfaceRegex = new(
        @"\bIN=(?<in_interface>\S*)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex OutInterfaceRegex = new(
        @"\bOUT=(?<out_interface>\S*)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex MacRegex = new(
        @"\bMAC=(?<mac>\S+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex FlagRegex = new(
        @"\b(?<flag>SYN|ACK|FIN|PSH|RST|URG|ECE|CWR)\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex WindowRegex = new(
        @"\bWINDOW=(?<window>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex LengthRegex = new(
        @"\bLEN=(?<length>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex TosRegex = new(
        @"\bTOS=(?<tos>0x[0-9a-fA-F]+|\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex TtlRegex = new(
        @"\bTTL=(?<ttl>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex IdRegex = new(
        @"\bID=(?<id>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex HoplimitRegex = new(
        @"\bHOPLIMIT=(?<hoplimit>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex TcRegex = new(
        @"\bTC=(?<tc>0x[0-9a-fA-F]+|\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex FlowlblRegex = new(
        @"\bFLOWLBL=(?<flowlbl>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex PrecRegex = new(
        @"\bPREC=(?<prec>0x[0-9a-fA-F]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex ResRegex = new(
        @"\bRES=(?<res>0x[0-9a-fA-F]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex UrgpRegex = new(
        @"\bURGP=(?<urgp>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex UidRegex = new(
        @"\bUID=(?<uid>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex GidRegex = new(
        @"\bGID=(?<gid>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex MarkRegex = new(
        @"\bMARK=(?<mark>0x[0-9a-fA-F]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex PhysInRegex = new(
        @"\bPHYSIN=(?<physin>\S*)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex PhysOutRegex = new(
        @"\bPHYSOUT=(?<physout>\S*)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex VprotoRegex = new(
        @"\bVPROTO=(?<vproto>0x[0-9a-fA-F]+|\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex VidRegex = new(
        @"\bVID=(?<vid>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex SpiRegex = new(
        @"\bSPI=(?<spi>0x[0-9a-fA-F]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex FragRegex = new(
        @"\bFRAG=(?<frag>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex MtuRegex = new(
        @"\bMTU=(?<mtu>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex DfRegex = new(
        @"\bDF\b",
        RegexOptions.Compiled
    );

    internal static readonly Regex SuppressedRegex = new(
        @"(?<count>\d+)\s+callbacks\s+suppressed",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    internal static readonly Regex PrefixFieldRegex = new(
        @"\b(IN|OUT|SRC|DST|PROTO)=",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    private const int MaxPort = 65535;
    private const int ErrorSnippetMaxLength = 200;

    internal static int ParsePort(string portStr)
    {
        if (!int.TryParse(portStr, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port < 0 || port > MaxPort)
        {
            throw new FormatException($"Invalid port number: '{portStr}'.");
        }

        return port;
    }

    internal static string ExtractFlags(string line)
    {
        var matches = FlagRegex.Matches(line);
        if (matches.Count == 0)
        {
            return string.Empty;
        }

        var flags = new List<string>();
        foreach (Match match in matches)
        {
            if (match.Groups["flag"].Success)
            {
                var value = match.Groups["flag"].Value.ToUpperInvariant();
                if (!flags.Contains(value))
                {
                    flags.Add(value);
                }
            }
        }

        return string.Join(" ", flags);
    }

    internal static bool IsWholeToken(string text, string token)
    {
        var idx = 0;
        while ((idx = text.IndexOf(token, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            var beforeIsBoundary = idx == 0 || !char.IsLetterOrDigit(text[idx - 1]);
            var afterIsBoundary = idx + token.Length >= text.Length || !char.IsLetterOrDigit(text[idx + token.Length]);

            if (beforeIsBoundary && afterIsBoundary)
            {
                return true;
            }

            idx++;
        }

        return false;
    }

    internal static string ExtractPrefix(string line)
    {
        var match = PrefixFieldRegex.Match(line);
        if (!match.Success)
        {
            return line;
        }

        return line[..match.Index];
    }

    internal static string SanitizeLineForError(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return "empty line";
        }

        var builder = new StringBuilder(Math.Min(line.Length, ErrorSnippetMaxLength));
        foreach (var ch in line)
        {
            if (builder.Length >= ErrorSnippetMaxLength)
            {
                break;
            }

            if (ch == '\r' || ch == '\n' || ch == '\t')
            {
                builder.Append(' ');
                continue;
            }

            if (char.IsControl(ch))
            {
                builder.Append('?');
                continue;
            }

            builder.Append(ch);
        }

        var sanitized = builder.ToString().Trim();
        if (line.Length > ErrorSnippetMaxLength)
        {
            sanitized += "...";
        }

        return sanitized;
    }

    internal static Dictionary<string, string> ExtractLinuxSpecific(string line)
    {
        var inInterfaceMatch = InInterfaceRegex.Match(line);
        var outInterfaceMatch = OutInterfaceRegex.Match(line);
        var macMatch = MacRegex.Match(line);
        var flags = ExtractFlags(line);
        var windowMatch = WindowRegex.Match(line);
        var lengthMatch = LengthRegex.Match(line);
        var tosMatch = TosRegex.Match(line);
        var ttlMatch = TtlRegex.Match(line);
        var idMatch = IdRegex.Match(line);
        var hoplimitMatch = HoplimitRegex.Match(line);
        var tcMatch = TcRegex.Match(line);
        var flowlblMatch = FlowlblRegex.Match(line);
        var precMatch = PrecRegex.Match(line);
        var resMatch = ResRegex.Match(line);
        var urgpMatch = UrgpRegex.Match(line);
        var uidMatch = UidRegex.Match(line);
        var gidMatch = GidRegex.Match(line);
        var markMatch = MarkRegex.Match(line);
        var physInMatch = PhysInRegex.Match(line);
        var physOutMatch = PhysOutRegex.Match(line);
        var vprotoMatch = VprotoRegex.Match(line);
        var vidMatch = VidRegex.Match(line);
        var spiMatch = SpiRegex.Match(line);
        var fragMatch = FragRegex.Match(line);
        var mtuMatch = MtuRegex.Match(line);
        var hasDf = DfRegex.IsMatch(line);

        return BuildLinuxSpecificDict(
            inInterfaceMatch.Success ? inInterfaceMatch.Groups["in_interface"].Value : "",
            outInterfaceMatch.Success ? outInterfaceMatch.Groups["out_interface"].Value : "",
            macMatch.Success ? NormalizeMacField(macMatch.Groups["mac"].Value) : "",
            flags,
            windowMatch.Success ? windowMatch.Groups["window"].Value : "",
            lengthMatch.Success ? lengthMatch.Groups["length"].Value : "",
            tosMatch.Success ? tosMatch.Groups["tos"].Value : "",
            ttlMatch.Success ? ttlMatch.Groups["ttl"].Value : "",
            idMatch.Success ? idMatch.Groups["id"].Value : "",
            hoplimitMatch.Success ? hoplimitMatch.Groups["hoplimit"].Value : "",
            tcMatch.Success ? tcMatch.Groups["tc"].Value : "",
            flowlblMatch.Success ? flowlblMatch.Groups["flowlbl"].Value : "",
            precMatch.Success ? precMatch.Groups["prec"].Value : "",
            resMatch.Success ? resMatch.Groups["res"].Value : "",
            urgpMatch.Success ? urgpMatch.Groups["urgp"].Value : "",
            hasDf,
            uidMatch.Success ? uidMatch.Groups["uid"].Value : "",
            gidMatch.Success ? gidMatch.Groups["gid"].Value : "",
            markMatch.Success ? markMatch.Groups["mark"].Value : "",
            physInMatch.Success ? physInMatch.Groups["physin"].Value : "",
            physOutMatch.Success ? physOutMatch.Groups["physout"].Value : "",
            vprotoMatch.Success ? vprotoMatch.Groups["vproto"].Value : "",
            vidMatch.Success ? vidMatch.Groups["vid"].Value : "",
            spiMatch.Success ? spiMatch.Groups["spi"].Value : "",
            fragMatch.Success ? fragMatch.Groups["frag"].Value : "",
            mtuMatch.Success ? mtuMatch.Groups["mtu"].Value : ""
        );
    }

    internal static string NormalizeMacField(string macField)
    {
        if (string.IsNullOrWhiteSpace(macField))
        {
            return string.Empty;
        }

        var parts = macField.Split(':', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 12 && parts.Take(12).All(IsHexOctet))
        {
            return string.Join(":", parts.Skip(6).Take(6));
        }

        return macField;
    }

    private static bool IsHexOctet(string value)
    {
        return value.Length == 2 && value.All(Uri.IsHexDigit);
    }

    internal static Dictionary<string, string> BuildLinuxSpecificDict(
        string inInterface, string outInterface, string mac, string flags,
        string window, string length, string tos, string ttl, string id,
        string hoplimit, string tc, string flowlbl, string prec, string res,
        string urgp, bool hasDf, string uid, string gid, string mark,
        string physIn, string physOut, string vproto, string vid,
        string spi, string frag, string mtu)
    {
        return new Dictionary<string, string>
        {
            { "InterfaceIn", inInterface },
            { "InterfaceOut", outInterface },
            { "MAC", mac },
            { "Flags", flags },
            { "Window", window },
            { "Length", length },
            { "TOS", tos },
            { "TTL", ttl },
            { "ID", id },
            { "HOPLIMIT", hoplimit },
            { "TC", tc },
            { "FLOWLBL", flowlbl },
            { "PREC", prec },
            { "RES", res },
            { "URGP", urgp },
            { "DF", hasDf ? "true" : "" },
            { "UID", uid },
            { "GID", gid },
            { "MARK", mark },
            { "PHYSIN", physIn },
            { "PHYSOUT", physOut },
            { "VPROTO", vproto },
            { "VID", vid },
            { "SPI", spi },
            { "FRAG", frag },
            { "MTU", mtu }
        };
    }
}
