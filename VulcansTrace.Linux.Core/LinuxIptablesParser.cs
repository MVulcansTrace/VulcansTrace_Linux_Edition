using System.Globalization;
using System.Text.RegularExpressions;
using VulcansTrace.Linux.Core.Logging;
using VulcansTrace.Linux.Core.Parsing;

namespace VulcansTrace.Linux.Core
{
    public class LinuxIptablesParser
    {
        private const string UnknownAction = "UNKNOWN";
        private const int FutureTimestampThresholdDays = 180;
        private readonly ILogSink _logSink;

        private static readonly Regex TimestampRegex = new(
            @"\b(?<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?<day>\d{1,2})\s+(?<time>\d{2}:\d{2}:\d{2})\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase
        );

        public LinuxIptablesParser(ILogSink? logSink = null)
        {
            _logSink = logSink ?? NullLogSink.Instance;
        }

        public ParseResult Parse(string logText, DateTime? referenceDate = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(logText);
            cancellationToken.ThrowIfCancellationRequested();

            var lines = logText.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            return ParseLines(lines, referenceDate, cancellationToken);
        }

        internal ParseResult ParseLines(string[] lines, DateTime? referenceDate = null, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var effectiveReferenceDate = referenceDate ?? DateTime.Now;
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
                    var evt = ParseLine(line, effectiveReferenceDate);
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

        private UnifiedEvent? ParseLine(string line, DateTime? referenceDate = null)
        {
            var srcIpMatch = FirewallLogRegex.SourceIpRegex.Match(line);
            var dstIpMatch = FirewallLogRegex.DestinationIpRegex.Match(line);
            var protocolMatch = FirewallLogRegex.ProtocolRegex.Match(line);

            if (!srcIpMatch.Success || !dstIpMatch.Success || !protocolMatch.Success)
            {
                return null;
            }

            var timestamp = ParseTimestamp(line, referenceDate);
            var (sourcePort, destinationPort) = ParsePorts(line);

            return new UnifiedEvent
            {
                Timestamp = timestamp,
                SourceIP = srcIpMatch.Groups["src_ip"].Value,
                DestinationIP = dstIpMatch.Groups["dst_ip"].Value,
                SourcePort = sourcePort,
                DestinationPort = destinationPort,
                Protocol = protocolMatch.Groups["protocol"].Value.ToUpper(),
                Action = DeriveAction(line),
                RawLine = line,
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = FirewallLogRegex.ExtractLinuxSpecific(line)
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

        private static string DeriveAction(string line)
        {
            var prefix = FirewallLogRegex.ExtractPrefix(line);
            if (string.IsNullOrWhiteSpace(prefix))
            {
                return UnknownAction;
            }

            var upper = prefix.ToUpperInvariant();
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

        internal static DateTime ParseTimestamp(string line, DateTime? referenceDate = null)
        {
            var match = TimestampRegex.Match(line);
            if (!match.Success)
            {
                throw new FormatException("Unable to parse timestamp from log line.");
            }

            var now = referenceDate ?? DateTime.Now;
            var year = now.Year;
            var month = match.Groups["month"].Value;
            var day = match.Groups["day"].Value;
            var time = match.Groups["time"].Value;
            var candidate = $"{year} {month} {day} {time}";
            string[] formats = ["yyyy MMM d HH:mm:ss", "yyyy MMM dd HH:mm:ss"];

            if (DateTime.TryParseExact(candidate, formats, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out var parsed))
            {
                if (parsed > now.AddDays(FutureTimestampThresholdDays))
                {
                    parsed = parsed.AddYears(-1);
                }
                else if (parsed < now.AddDays(-FutureTimestampThresholdDays))
                {
                    parsed = parsed.AddYears(1);
                }

                return DateTime.SpecifyKind(parsed, DateTimeKind.Unspecified);
            }

            throw new FormatException("Unable to parse timestamp from log line.");
        }
    }
}
