using VulcansTrace.Linux.Core.Logging;

namespace VulcansTrace.Linux.Core
{
    /// <summary>
    /// Orchestrates log parsing and auto-detects log format
    /// </summary>
    public class LogNormalizer
    {
        private static readonly string[] LineSeparators = new[] { "\r\n", "\n" };
        private const int MaxLogSizeChars = 100_000_000;
        private readonly ILogSink _logSink;
        private readonly LinuxIptablesParser _iptablesParser;
        private readonly LinuxNftablesParser _nftablesParser;

        /// <summary>
        /// Initializes a new instance of the <see cref="LogNormalizer"/> class.
        /// </summary>
        /// <param name="logSink">Optional logging sink for diagnostic messages (defaults to null logging).</param>
        public LogNormalizer(ILogSink? logSink = null)
        {
            _logSink = logSink ?? NullLogSink.Instance;
            _iptablesParser = new LinuxIptablesParser(_logSink);
            _nftablesParser = new LinuxNftablesParser(_logSink);
        }

        /// <summary>
        /// Normalizes raw log text into unified events and auto-detects the log format.
        /// </summary>
        /// <param name="logText">The raw log text to normalize (maximum 100MB).</param>
        /// <returns>A <see cref="ParseResult"/> containing normalized events and any parse errors.</returns>
        /// <exception cref="ArgumentException">Thrown when logText exceeds maximum size.</exception>
        /// <exception cref="NotSupportedException">Thrown when detected log format is not supported.</exception>
        public ParseResult Normalize(string logText) => Normalize(logText, null, CancellationToken.None);

        /// <summary>
        /// Normalizes raw log text into unified events and auto-detects the log format.
        /// </summary>
        /// <param name="logText">The raw log text to normalize (maximum 100MB).</param>
        /// <param name="cancellationToken">Token to cancel normalization and parsing.</param>
        /// <returns>A <see cref="ParseResult"/> containing normalized events and any parse errors.</returns>
        /// <exception cref="OperationCanceledException">Thrown when cancellation is requested.</exception>
        public ParseResult Normalize(string logText, CancellationToken cancellationToken)
            => Normalize(logText, null, cancellationToken);

        public ParseResult Normalize(string logText, DateTime? referenceDate, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(logText);
            cancellationToken.ThrowIfCancellationRequested();

            if (logText.Length > MaxLogSizeChars)
            {
                var error = $"Log input exceeds maximum size of {MaxLogSizeChars} characters.";
                _logSink.Write(LogLevel.Error, error);
                return new ParseResult
                {
                    Events = Array.Empty<UnifiedEvent>(),
                    Errors = new[] { error },
                    TotalLines = 0
                };
            }

            var lines = logText.Split(LineSeparators, StringSplitOptions.RemoveEmptyEntries);
            cancellationToken.ThrowIfCancellationRequested();

            if (lines.Length == 0)
            {
                return new ParseResult
                {
                    Events = Array.Empty<UnifiedEvent>(),
                    TotalLines = 0
                };
            }

            var detectedFormats = DetectFormatsFromLines(lines);
            var detectedFormat = detectedFormats.Count == 1 ? detectedFormats[0] : LogFormat.Unknown;
            cancellationToken.ThrowIfCancellationRequested();

            if (detectedFormats.Count > 1)
            {
                return NormalizeMixedFormats(lines, referenceDate, cancellationToken);
            }

            if (detectedFormats.Count == 0)
            {
                _logSink.Write(LogLevel.Warning, "Unknown log format. Supported: iptables, nftables");
            }

            return detectedFormat switch
            {
                LogFormat.Iptables => _iptablesParser.ParseLines(lines, referenceDate, cancellationToken),
                LogFormat.Nftables => _nftablesParser.ParseLines(lines, cancellationToken),
                LogFormat.Unknown => new ParseResult
                {
                    Events = Array.Empty<UnifiedEvent>(),
                    Errors = new[] { "Unknown log format. Supported: iptables, nftables" },
                    TotalLines = lines.Length,
                    SkippedLineCount = lines.Length,
                    SkippedLines = AllLinesSkipped(lines, "Unknown log format")
                },
                _ => throw new NotSupportedException($"Format {detectedFormat} not supported")
            };
        }

        /// <summary>
        /// Detects the log format (iptables or nftables) by analyzing the log text.
        /// </summary>
        /// <param name="logText">The raw log text to analyze for format detection.</param>
        /// <returns>The detected <see cref="LogFormat"/> (Iptables, Nftables, or Unknown).</returns>
        public LogFormat DetectFormat(string logText)
        {
            var lines = logText.Split(LineSeparators, StringSplitOptions.RemoveEmptyEntries);
            return DetectFormatFromLines(lines);
        }

        /// <summary>
        /// Detects the log format from pre-split lines.
        /// </summary>
        private LogFormat DetectFormatFromLines(string[] lines)
        {
            return DetectFormatsFromLines(lines).FirstOrDefault(LogFormat.Unknown);
        }

        private List<LogFormat> DetectFormatsFromLines(string[] lines)
        {
            var formats = new List<LogFormat>(2);

            foreach (var line in lines)
            {
                var format = DetectLineFormat(line);
                if (format != LogFormat.Unknown && !formats.Contains(format))
                {
                    formats.Add(format);
                    // Both formats found — no need to scan further.
                    if (formats.Count == 2)
                        break;
                }
            }

            return formats;
        }

        private static LogFormat DetectLineFormat(string line)
        {
            // Check nftables first. The "nf_tables:" string must appear before the
            // first key-value field (IN=, SRC=, DST=) to be a real nftables format
            // indicator rather than free-text mention in an iptables log message.
            var nfTablesIdx = line.IndexOf("nf_tables:", StringComparison.OrdinalIgnoreCase);
            if (nfTablesIdx >= 0)
            {
                var prefixIdx = line.IndexOf("IN=", StringComparison.OrdinalIgnoreCase);
                if (prefixIdx < 0)
                    prefixIdx = line.IndexOf("SRC=", StringComparison.OrdinalIgnoreCase);

                if (prefixIdx < 0 || nfTablesIdx < prefixIdx)
                {
                    return LogFormat.Nftables;
                }
            }

            if (line.Contains("PROTO=", StringComparison.OrdinalIgnoreCase) &&
                line.Contains("SRC=", StringComparison.OrdinalIgnoreCase) &&
                line.Contains("DST=", StringComparison.OrdinalIgnoreCase))
            {
                return LogFormat.Iptables;
            }

            return LogFormat.Unknown;
        }

        private ParseResult NormalizeMixedFormats(string[] lines, DateTime? referenceDate, CancellationToken cancellationToken)
        {
            var events = new List<UnifiedEvent>();
            var errors = new List<string>();
            var warnings = new List<string> { "Mixed log formats detected; parsed each line using its detected format." };
            var skippedCount = 0;
            var skippedLines = new List<SkippedLine>();

            for (var i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                cancellationToken.ThrowIfCancellationRequested();

                var fmt = DetectLineFormat(line);
                var result = fmt switch
                {
                    LogFormat.Iptables => _iptablesParser.ParseLines(new[] { line }, referenceDate, cancellationToken),
                    LogFormat.Nftables => _nftablesParser.ParseLines(new[] { line }, cancellationToken),
                    _ => new ParseResult
                    {
                        Events = Array.Empty<UnifiedEvent>(),
                        SkippedLineCount = 1
                    }
                };

                events.AddRange(result.Events);
                errors.AddRange(result.Errors);
                // Skip per-parser "1 of 1 lines skipped" warnings — they're noisy in
                // mixed-format mode. Track skips via SkippedLineCount and summarize below.
                if (result.SkippedLineCount > 0)
                {
                    skippedLines.Add(new SkippedLine(
                        i + 1,
                        line,
                        fmt == LogFormat.Unknown
                            ? "Unknown log format"
                            : "Missing required SRC/DST/PROTO fields"));
                }

                skippedCount += result.SkippedLineCount;
            }

            if (skippedCount > 0)
            {
                warnings.Add($"{skippedCount} of {lines.Length} lines skipped (unknown or missing required fields).");
            }

            return new ParseResult
            {
                Events = events.ToArray(),
                Errors = errors.ToArray(),
                Warnings = warnings.ToArray(),
                TotalLines = lines.Length,
                SkippedLineCount = skippedCount,
                SkippedLines = skippedLines.ToArray()
            };
        }

        private static SkippedLine[] AllLinesSkipped(string[] lines, string reason)
        {
            var skipped = new SkippedLine[lines.Length];
            for (var i = 0; i < lines.Length; i++)
            {
                skipped[i] = new SkippedLine(i + 1, lines[i], reason);
            }

            return skipped;
        }
    }

    /// <summary>
    /// Enumeration of supported firewall log formats.
    /// </summary>
    public enum LogFormat
    {
        /// <summary>Log format could not be determined.</summary>
        Unknown,
        /// <summary>Linux iptables kernel log format.</summary>
        Iptables,
        /// <summary>Linux nftables log format.</summary>
        Nftables
    }
}
