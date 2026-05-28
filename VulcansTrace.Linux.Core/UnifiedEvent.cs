using System.Collections.ObjectModel;
using System.Net;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace VulcansTrace.Linux.Core
{
    /// <summary>
    /// Unified event schema for all firewall log formats.
    /// Normalizes iptables, nftables, and future log sources.
    /// </summary>
    public sealed class UnifiedEvent
    {
        private const int MaxPort = 65535;

        private static readonly Regex StrictIPv4Regex = new(
            @"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
            RegexOptions.Compiled
        );

        private DateTime _timestamp;
        private string _sourceIP = string.Empty;
        private string _destinationIP = string.Empty;
        private int _sourcePort;
        private int _destinationPort;
        private string _action = "UNKNOWN";  // ACCEPT, DROP, REJECT, UNKNOWN
        private string _protocol = string.Empty; // TCP, UDP, ICMP
        private LogFormat _logFormat = LogFormat.Unknown;
        private IReadOnlyDictionary<string, string> _linuxSpecific =
            new ReadOnlyDictionary<string, string>(new Dictionary<string, string>());

        /// <summary>Gets the timestamp when the firewall event occurred.</summary>
        public required DateTime Timestamp
        {
            get => _timestamp;
            init
            {
                if (value == default)
                {
                    throw new ArgumentException("Timestamp must be set.", nameof(Timestamp));
                }
                _timestamp = value;
            }
        }

        /// <summary>Gets the source IP address of the connection attempt.</summary>
        public required string SourceIP
        {
            get => _sourceIP;
            init => _sourceIP = ValidateIp(value, nameof(SourceIP));
        }

        /// <summary>Gets the destination IP address of the connection attempt.</summary>
        public required string DestinationIP
        {
            get => _destinationIP;
            init => _destinationIP = ValidateIp(value, nameof(DestinationIP));
        }

        /// <summary>Gets the source port number of the connection attempt (0 if not applicable).</summary>
        public int SourcePort
        {
            get => _sourcePort;
            init => _sourcePort = ValidatePort(value, nameof(SourcePort));
        }

        /// <summary>Gets the destination port number of the connection attempt (0 if not applicable).</summary>
        public int DestinationPort
        {
            get => _destinationPort;
            init => _destinationPort = ValidatePort(value, nameof(DestinationPort));
        }

        /// <summary>Gets the firewall action taken (ACCEPT, DROP, REJECT, or UNKNOWN).</summary>
        public string Action
        {
            get => _action;
            init => _action = NormalizeNonEmpty(value, nameof(Action)).ToUpperInvariant();
        }

        /// <summary>Gets the network protocol used (e.g., TCP, UDP, ICMP).</summary>
        public required string Protocol
        {
            get => _protocol;
            init => _protocol = NormalizeNonEmpty(value, nameof(Protocol)).ToUpperInvariant();
        }

        /// <summary>Gets the original raw log line before parsing (null if not available).</summary>
        public string? RawLine { get; init; }

        /// <summary>Gets the source log format (Iptables or Nftables).</summary>
        public required LogFormat LogFormat
        {
            get => _logFormat;
            init
            {
                if (value == LogFormat.Unknown)
                {
                    throw new ArgumentException("LogFormat must be specified.", nameof(LogFormat));
                }
                _logFormat = value;
            }
        }

        /// <summary>
        /// Linux-specific fields stored as key-value pairs.
        /// IPv4 core: MAC, InterfaceIn, InterfaceOut, Length, TOS, PREC, TTL, ID, Window, Flags, RES, URGP, DF
        /// IPv6: HOPLIMIT, TC, FLOWLBL
        /// Socket/accounting: UID, GID, MARK
        /// Bridge/VLAN: PHYSIN, PHYSOUT, VPROTO, VID
        /// IPsec/ICMP: SPI, FRAG, MTU
        /// nftables-only: Chain
        /// </summary>
        public IReadOnlyDictionary<string, string> LinuxSpecific
        {
            get => _linuxSpecific;
            init
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(LinuxSpecific));
                }

                _linuxSpecific = new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(value));
            }
        }

        /// <summary>
        /// Determines if this event represents a new unique connection
        /// </summary>
        [JsonIgnore]
        public string ConnectionKey => $"{SourceIP}:{SourcePort}-{DestinationIP}:{DestinationPort}-{Protocol}";

        private static string NormalizeNonEmpty(string value, string name)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException($"{name} must be set.", name);
            }

            return value.Trim();
        }

        private static string ValidateIp(string value, string name)
        {
            var trimmed = NormalizeNonEmpty(value, name);

            // IPAddress.TryParse is overly lenient: it accepts overflow octets
            // (999.999.999.999), short forms (1.2.3), and other non-standard
            // representations. We enforce strict IPv4 validation before falling
            // back to the framework parser for IPv6 and edge-case formats.
            if (trimmed.Contains('.') && !trimmed.Contains(':') && !StrictIPv4Regex.IsMatch(trimmed))
            {
                throw new ArgumentException($"{name} must be a valid IP address.", name);
            }

            if (!IPAddress.TryParse(trimmed, out _))
            {
                throw new ArgumentException($"{name} must be a valid IP address.", name);
            }

            return trimmed;
        }

        private static int ValidatePort(int port, string name)
        {
            if (port < 0 || port > MaxPort)
            {
                throw new ArgumentOutOfRangeException(name, port, $"{name} must be between 0 and {MaxPort}.");
            }

            return port;
        }
    }

    /// <summary>
    /// Result of parsing raw log text
    /// </summary>
    public class ParseResult
    {
        /// <summary>Gets or sets the parsed unified events.</summary>
        public UnifiedEvent[] Events { get; set; } = Array.Empty<UnifiedEvent>();

        /// <summary>Gets or sets the parse errors encountered.</summary>
        public string[] Errors { get; set; } = Array.Empty<string>();

        /// <summary>Gets or sets the parse warnings (e.g., kernel rate-limit suppressed callbacks).</summary>
        public string[] Warnings { get; set; } = Array.Empty<string>();

        /// <summary>Gets or sets the total number of lines inspected.</summary>
        public int TotalLines { get; set; }

        /// <summary>Gets or sets the number of lines skipped because they lacked required fields (SRC/DST/PROTO). A summary warning is emitted when any lines are skipped.</summary>
        public int SkippedLineCount { get; set; }

        /// <summary>Gets the number of parsed events.</summary>
        public int ParsedCount => Events.Length;

        /// <summary>Gets the number of parse errors.</summary>
        public int ErrorCount => Errors.Length;

        /// <summary>Gets the number of parse warnings.</summary>
        public int WarningCount => Warnings.Length;
    }
}
