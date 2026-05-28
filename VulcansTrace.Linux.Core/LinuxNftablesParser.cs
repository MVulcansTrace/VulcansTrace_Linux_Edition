using System.Globalization;
using System.Text.RegularExpressions;
using VulcansTrace.Linux.Core.Logging;
using VulcansTrace.Linux.Core.Parsing;

namespace VulcansTrace.Linux.Core
{
    public class LinuxNftablesParser
    {
        private readonly ILogSink _logSink;
        private const string UnknownAction = "UNKNOWN";

        private static readonly Regex ChainRegex = new(
            @"nf_tables: (?<chain>\S+)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase
        );

        private static readonly Regex NftablesTimestampRegex = new(
            @"^(?<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)",
            RegexOptions.Compiled
        );

        private static readonly Regex TimestampOffsetRegex = new(
            @"(Z|[+-]\d{2}:\d{2})\s*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase
        );

        public LinuxNftablesParser(ILogSink? logSink = null)
        {
            _logSink = logSink ?? NullLogSink.Instance;
        }

        public ParseResult Parse(string logText, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(logText);
            cancellationToken.ThrowIfCancellationRequested();

            var lines = logText.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            return ParseLines(lines, cancellationToken);
        }

        internal ParseResult ParseLines(string[] lines, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var events = new List<UnifiedEvent>();
            var errors = new List<string>();
            var warnings = new List<string>();
            var skippedCount = 0;

            for (var i = 0; i < lines.Length; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var line = lines[i];
                var suppressedMatch = FirewallLogRegex.SuppressedRegex.Match(line);
                if (suppressedMatch.Success)
                {
                    var count = suppressedMatch.Groups["count"].Value;
                    warnings.Add($"Line {i + 1}: kernel rate-limit suppressed {count} callbacks");
                    _logSink.Write(LogLevel.Warning, $"Rate-limit suppressed: {count} callbacks");
                    continue;
                }

                try
                {
                    var evt = ParseLine(line);
                    if (evt != null)
                    {
                        events.Add(evt);
                    }
                    else
                    {
                        skippedCount++;
                    }
                }
                catch (Exception ex) when (ex is FormatException || ex is ArgumentException)
                {
                    var message = $"Failed to parse line: {FirewallLogRegex.SanitizeLineForError(line)} Error: {ex.Message}";
                    errors.Add(message);
                    _logSink.Write(LogLevel.Warning, message, ex);
                }
            }

            if (skippedCount > 0)
            {
                var skipWarning = $"{skippedCount} of {lines.Length} lines skipped (missing required SRC/DST/PROTO fields).";
                warnings.Add(skipWarning);
                _logSink.Write(LogLevel.Warning, skipWarning);
            }

            return new ParseResult
            {
                Events = events.ToArray(),
                Errors = errors.ToArray(),
                Warnings = warnings.ToArray(),
                TotalLines = lines.Length,
                SkippedLineCount = skippedCount
            };
        }

        private UnifiedEvent? ParseLine(string line)
        {
            var srcIpMatch = FirewallLogRegex.SourceIpRegex.Match(line);
            var dstIpMatch = FirewallLogRegex.DestinationIpRegex.Match(line);
            var protocolMatch = FirewallLogRegex.ProtocolRegex.Match(line);
            var chainMatch = ChainRegex.Match(line);

            if (!srcIpMatch.Success || !dstIpMatch.Success || !protocolMatch.Success)
            {
                return null;
            }

            var timestampOffset = ParseTimestamp(line);
            var timestamp = DateTime.SpecifyKind(timestampOffset.UtcDateTime, DateTimeKind.Unspecified);
            var prefix = FirewallLogRegex.ExtractPrefix(line);
            var chain = chainMatch.Success ? chainMatch.Groups["chain"].Value : "";
            if (string.IsNullOrEmpty(chain) && !string.IsNullOrWhiteSpace(prefix))
            {
                var prefixParts = prefix.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (prefixParts.Length > 0)
                {
                    var candidate = prefixParts[^1];
                    if (!NftablesTimestampRegex.IsMatch(candidate))
                    {
                        chain = candidate;
                    }
                }
            }

            var linuxSpecific = FirewallLogRegex.ExtractLinuxSpecific(line);
            linuxSpecific["Chain"] = chain;
            if (timestampOffset.Offset != TimeSpan.Zero)
            {
                linuxSpecific["TimestampOffset"] = timestampOffset.Offset.ToString();
            }

            var (sourcePort, destinationPort) = ParsePorts(line);

            return new UnifiedEvent
            {
                Timestamp = timestamp,
                SourceIP = srcIpMatch.Groups["src_ip"].Value,
                DestinationIP = dstIpMatch.Groups["dst_ip"].Value,
                SourcePort = sourcePort,
                DestinationPort = destinationPort,
                Protocol = protocolMatch.Groups["protocol"].Value.ToUpper(),
                Action = DeriveAction(chain),
                RawLine = line,
                LogFormat = LogFormat.Nftables,
                LinuxSpecific = linuxSpecific
            };
        }

        private static (int SourcePort, int DestinationPort) ParsePorts(string line)
        {
            int sourcePort = 0;
            int destinationPort = 0;

            var srcPortMatch = FirewallLogRegex.SourcePortRegex.Match(line);
            if (srcPortMatch.Success)
            {
                sourcePort = FirewallLogRegex.ParsePort(srcPortMatch.Groups["src_port"].Value);
            }

            var dstPortMatch = FirewallLogRegex.DestinationPortRegex.Match(line);
            if (dstPortMatch.Success)
            {
                destinationPort = FirewallLogRegex.ParsePort(dstPortMatch.Groups["dst_port"].Value);
            }

            return (sourcePort, destinationPort);
        }

        private string DeriveAction(string chain)
        {
            if (string.IsNullOrWhiteSpace(chain))
            {
                return UnknownAction;
            }

            var upper = chain.ToUpperInvariant();
            if (FirewallLogRegex.IsWholeToken(upper, "ACCEPT"))
            {
                return "ACCEPT";
            }

            if (FirewallLogRegex.IsWholeToken(upper, "DROP"))
            {
                return "DROP";
            }

            if (FirewallLogRegex.IsWholeToken(upper, "REJECT"))
            {
                return "REJECT";
            }

            return UnknownAction;
        }

        private static DateTimeOffset ParseTimestamp(string line)
        {
            var tsMatch = NftablesTimestampRegex.Match(line);
            if (!tsMatch.Success)
            {
                throw new FormatException("Unable to parse timestamp.");
            }

            var candidate = tsMatch.Groups["timestamp"].Value;

            if (TimestampOffsetRegex.IsMatch(candidate))
            {
                if (DateTimeOffset.TryParse(candidate, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out var dto))
                {
                    return dto;
                }
            }

            if (DateTime.TryParse(candidate, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out var parsed))
            {
                return new DateTimeOffset(DateTime.SpecifyKind(parsed, DateTimeKind.Unspecified), TimeSpan.Zero);
            }

            throw new FormatException("Unable to parse timestamp.");
        }
    }
}
