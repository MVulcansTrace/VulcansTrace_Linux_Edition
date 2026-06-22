using System.Globalization;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Analysis;

/// <summary>
/// Deterministic cross-scanner validation.
/// Raises or lowers confidence when independent scanner data sources support or contradict
/// the underlying condition. Lack of validation remains neutral.
/// </summary>
internal sealed class CrossScannerValidator
{
    private readonly IReadOnlyDictionary<string, Func<Finding, ScanData, CrossScannerValidationSignal?>> _registry;

    public CrossScannerValidator()
        : this(BuildDefaultRegistry())
    {
    }

    public CrossScannerValidator(IReadOnlyDictionary<string, Func<Finding, ScanData, CrossScannerValidationSignal?>> registry)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
    }

    /// <summary>
    /// Validates findings against independent scanner data, adding evidence signals and
    /// adjusting confidence one level when support or contradiction is found.
    /// </summary>
    public IReadOnlyList<Finding> Validate(
        IReadOnlyList<Finding> findings,
        ScanData scanData,
        ICollection<string> warnings)
    {
        if (findings.Count == 0)
            return findings;

        var validated = new List<Finding>(findings.Count);

        foreach (var finding in findings)
        {
            // Phase 1 covers Critical and High severity rules only.
            // Medium rules are deferred to Phase 2 to keep the validation surface
            // bounded and grounded in strong independent signals.
            if (finding.Severity is not Severity.Critical and not Severity.High)
            {
                validated.Add(finding);
                continue;
            }

            if (string.IsNullOrWhiteSpace(finding.RuleId))
            {
                validated.Add(finding);
                continue;
            }

            var validation = FindValidation(finding, scanData, warnings);
            if (validation == null)
            {
                validated.Add(finding);
                continue;
            }

            var updatedSignals = new List<EvidenceSignal>(finding.EvidenceSignals)
            {
                validation.ToEvidenceSignal()
            };

            validated.Add(finding with
            {
                EvidenceSignals = updatedSignals,
                Confidence = AdjustConfidence(finding.Confidence, validation.Verdict)
            });
        }

        return validated;
    }

    private CrossScannerValidationSignal? FindValidation(Finding finding, ScanData scanData, ICollection<string> warnings)
    {
        if (!_registry.TryGetValue(finding.RuleId!, out var predicate))
            return null;

        try
        {
            return predicate(finding, scanData);
        }
        catch (Exception ex)
        {
            // Validation is advisory. A malformed predicate must not crash the audit,
            // but we surface a warning so the failure is not completely silent.
            warnings.Add($"Cross-scanner validation failed for {finding.RuleId}: {ex.Message}");
            return null;
        }
    }

    private static DetectionConfidence AdjustConfidence(DetectionConfidence current, CrossScannerValidationVerdict verdict) => verdict switch
    {
        CrossScannerValidationVerdict.Supports => RaiseConfidence(current),
        CrossScannerValidationVerdict.Contradicts => LowerConfidence(current),
        _ => current
    };

    private static DetectionConfidence RaiseConfidence(DetectionConfidence current) => current switch
    {
        DetectionConfidence.Unknown => DetectionConfidence.Low,
        DetectionConfidence.Low => DetectionConfidence.Medium,
        DetectionConfidence.Medium => DetectionConfidence.High,
        DetectionConfidence.High => DetectionConfidence.High,
        DetectionConfidence.Confirmed => DetectionConfidence.Confirmed,
        _ => DetectionConfidence.Unknown
    };

    private static DetectionConfidence LowerConfidence(DetectionConfidence current) => current switch
    {
        DetectionConfidence.Unknown => DetectionConfidence.Unknown,
        DetectionConfidence.Low => DetectionConfidence.Unknown,
        DetectionConfidence.Medium => DetectionConfidence.Low,
        DetectionConfidence.High => DetectionConfidence.Medium,
        DetectionConfidence.Confirmed => DetectionConfidence.High,
        _ => DetectionConfidence.Unknown
    };

    private static IReadOnlyDictionary<string, Func<Finding, ScanData, CrossScannerValidationSignal?>> BuildDefaultRegistry()
    {
        return new Dictionary<string, Func<Finding, ScanData, CrossScannerValidationSignal?>>(StringComparer.OrdinalIgnoreCase)
        {
            // Firewall
            // FW-001 has no independent cross-check: only the firewall scanner can know the
            // default INPUT policy. FW-004 is the firewall-active rule itself, so it is also
            // intentionally excluded.
            ["FW-002"] = FirewallValidators.ValidateFw002,

            // Ports (PORT-002 is Medium; deferred to Phase 2)
            ["PORT-003"] = PortValidators.ValidatePort003,

            // Services
            ["SRV-001"] = ServiceValidators.ValidateSrv001,
            ["SRV-002"] = ServiceValidators.ValidateSrv002,
            ["SRV-004"] = ServiceValidators.ValidateSrv004,

            // SSH
            ["SSH-001"] = SshValidators.ValidateSsh,
            ["SSH-002"] = SshValidators.ValidateSsh,
            ["SSH-004"] = SshValidators.ValidateSsh,
            ["SSH-005"] = SshValidators.ValidateSsh,
            ["SSH-006"] = SshValidators.ValidateSsh,

            // Network
            // NET-003 has no independent cross-check: only the interface scanner can report
            // whether an interface is up. NET-002 is limited to confirming that active
            // connections are observable, not the specific suspicious connection.
            ["NET-002"] = NetworkValidators.ValidateNet002,

            // Containers and Kubernetes are intentionally NOT registered. The CTR-*/K8S-*
            // rules draw their findings from the same Containers/KubernetesPods scan data
            // that a validator would read, so there is no independent second source to
            // confirm or contradict them. Validating here would only re-state the rule's
            // own data — tautological "support" and an unreachable "contradicts" branch —
            // inflating confidence without independent evidence. These are excluded on the
            // same grounds as FW-001/FW-004/NET-003 until genuinely independent sources exist.

            // User accounts
            ["USER-001"] = OtherValidators.ValidateUser001
        };
    }

    // =====================================================================
    // Port validators: port exposure vs firewall rules
    // =====================================================================
    internal static class PortValidators
    {
        public static CrossScannerValidationSignal? ValidatePort003(Finding finding, ScanData scanData)
            => ValidatePortAgainstFirewall(finding, scanData, "database", "database port");

        private static CrossScannerValidationSignal? ValidatePortAgainstFirewall(
            Finding finding,
            ScanData scanData,
            string assetKind,
            string assetDescription)
        {
            if (!IsFirewallSourceAvailable(scanData))
                return null;

            if (!TryGetPort(finding, out var port))
                return null;

            if (scanData.FirewallActive)
            {
                var hasAccept = scanData.FirewallRules.Any(r =>
                    IsAcceptRule(r) && MatchesDestinationPort(r, port));

                if (hasAccept)
                {
                    return new CrossScannerValidationSignal
                    {
                        RuleId = finding.RuleId!,
                        Verdict = CrossScannerValidationVerdict.Supports,
                        Name = $"Supports: Firewall ACCEPT confirms exposed {assetKind}",
                        Explanation = $"{finding.RuleId} reports {assetDescription} {port}; the firewall scanner independently confirms an ACCEPT rule for that port."
                    };
                }

                var hasBlock = scanData.FirewallRules.Any(r =>
                    IsBlockRule(r) && MatchesDestinationPort(r, port));

                if (hasBlock)
                {
                    return new CrossScannerValidationSignal
                    {
                        RuleId = finding.RuleId!,
                        Verdict = CrossScannerValidationVerdict.Contradicts,
                        Name = $"Contradicts: Firewall block contradicts exposed {assetKind}",
                        Explanation = $"{finding.RuleId} reports {assetDescription} {port}, but the firewall scanner independently reports a DROP/REJECT rule for that port."
                    };
                }

                return null;
            }

            return new CrossScannerValidationSignal
            {
                RuleId = finding.RuleId!,
                Verdict = CrossScannerValidationVerdict.Supports,
                Name = $"Supports: No active firewall protecting exposed {assetKind}",
                Explanation = $"{finding.RuleId} reports {assetDescription} {port}; the firewall scanner independently reports no active firewall."
            };
        }
    }

    // =====================================================================
    // Service validators: prohibited service vs live listener
    // =====================================================================
    internal static class ServiceValidators
    {
        public static CrossScannerValidationSignal? ValidateSrv001(Finding finding, ScanData scanData)
            => ValidateServiceByPort(finding, scanData, 23, "telnet");

        public static CrossScannerValidationSignal? ValidateSrv002(Finding finding, ScanData scanData)
            => ValidateAnyPort(finding, scanData, new[] { 20, 21 }, "FTP");

        public static CrossScannerValidationSignal? ValidateSrv004(Finding finding, ScanData scanData)
            => ValidateAnyPort(finding, scanData, new[] { 512, 513, 514 }, "r-services");

        private static CrossScannerValidationSignal? ValidateServiceByPort(
            Finding finding,
            ScanData scanData,
            int port,
            string serviceName)
        {
            if (!IsPortSourceAvailable(scanData))
                return null;

            if (HasPublicListener(scanData, port))
            {
                return new CrossScannerValidationSignal
                {
                    RuleId = finding.RuleId!,
                    Verdict = CrossScannerValidationVerdict.Supports,
                    Name = $"Supports: {serviceName} listener confirmed",
                    Explanation = $"{finding.RuleId} reports the {serviceName} service is running; the port scanner independently confirms port {port} is listening."
                };
            }

            return new CrossScannerValidationSignal
            {
                RuleId = finding.RuleId!,
                Verdict = CrossScannerValidationVerdict.Contradicts,
                Name = $"Contradicts: No public {serviceName} listener found",
                Explanation = $"{finding.RuleId} reports the {serviceName} service is running, but the port scanner did not find port {port} listening on a public address."
            };
        }

        private static CrossScannerValidationSignal? ValidateAnyPort(
            Finding finding,
            ScanData scanData,
            int[] ports,
            string serviceName)
        {
            if (!IsPortSourceAvailable(scanData))
                return null;

            var confirmedPort = ports.FirstOrDefault(p => HasPublicListener(scanData, p));

            if (confirmedPort != 0)
            {
                return new CrossScannerValidationSignal
                {
                    RuleId = finding.RuleId!,
                    Verdict = CrossScannerValidationVerdict.Supports,
                    Name = $"Supports: {serviceName} listener confirmed",
                    Explanation = $"{finding.RuleId} reports the {serviceName} service is running; the port scanner independently confirms port {confirmedPort} is listening."
                };
            }

            return new CrossScannerValidationSignal
            {
                RuleId = finding.RuleId!,
                Verdict = CrossScannerValidationVerdict.Contradicts,
                Name = $"Contradicts: No public {serviceName} listener found",
                Explanation = $"{finding.RuleId} reports the {serviceName} service is running, but the port scanner did not find any of ports {string.Join(", ", ports)} listening on a public address."
            };
        }
    }

    // =====================================================================
    // SSH validators: config rule vs reachable SSH service
    // =====================================================================
    internal static class SshValidators
    {
        public static CrossScannerValidationSignal? ValidateSsh(Finding finding, ScanData scanData)
        {
            var serviceSourceAvailable = IsSourceAvailable(scanData, "systemctl");
            var portSourceAvailable = IsPortSourceAvailable(scanData);
            var serviceConfirmed = serviceSourceAvailable && HasSshService(scanData);
            var portConfirmed = portSourceAvailable && HasPublicListener(scanData, 22);

            if (serviceConfirmed && portConfirmed)
            {
                return new CrossScannerValidationSignal
                {
                    RuleId = finding.RuleId!,
                    Verdict = CrossScannerValidationVerdict.Supports,
                    Name = "Supports: SSH service and listener independently confirmed",
                    Explanation = $"{finding.RuleId} reports an SSH configuration issue; the service scanner independently confirms an SSH service is running and the port scanner confirms port 22 is listening, so the configuration is reachable."
                };
            }

            if (portSourceAvailable && !portConfirmed)
            {
                return new CrossScannerValidationSignal
                {
                    RuleId = finding.RuleId!,
                    Verdict = CrossScannerValidationVerdict.Contradicts,
                    Name = "Contradicts: No public SSH listener found",
                    Explanation = $"{finding.RuleId} reports an SSH configuration issue, but the port scanner did not find port 22 listening on a public address, weakening the reachable-exposure claim."
                };
            }

            if (serviceSourceAvailable && !serviceConfirmed)
            {
                return new CrossScannerValidationSignal
                {
                    RuleId = finding.RuleId!,
                    Verdict = CrossScannerValidationVerdict.Contradicts,
                    Name = "Contradicts: No running SSH service found",
                    Explanation = $"{finding.RuleId} reports an SSH configuration issue, but the service scanner did not find a running SSH service, weakening the reachable-exposure claim."
                };
            }

            return null;
        }
    }

    // =====================================================================
    // Firewall validators
    // =====================================================================
    internal static class FirewallValidators
    {
        public static CrossScannerValidationSignal? ValidateFw002(Finding finding, ScanData scanData)
        {
            // FW-002 has a Medium branch ("no explicit SSH rule") and a High branch ("open to any source").
            // Only the High branch claims exposure to any source, so only that branch is validated here.
            if (finding.Severity != Severity.High)
                return null;

            var portSourceAvailable = IsPortSourceAvailable(scanData);
            var interfaceSourceAvailable = IsSourceAvailable(scanData, "ip addr");
            var portConfirmed = portSourceAvailable && HasPublicListener(scanData, 22);
            var interfaceConfirmed = interfaceSourceAvailable && HasNonLoopbackUpInterface(scanData);

            if (portConfirmed && interfaceConfirmed)
            {
                return new CrossScannerValidationSignal
                {
                    RuleId = finding.RuleId!,
                    Verdict = CrossScannerValidationVerdict.Supports,
                    Name = "Supports: SSH listener confirmed on public interface",
                    Explanation = "FW-002 reports SSH is open to any source; the port scanner independently confirms port 22 is listening, and a non-loopback network interface is up."
                };
            }

            if (portSourceAvailable && !portConfirmed)
            {
                return new CrossScannerValidationSignal
                {
                    RuleId = finding.RuleId!,
                    Verdict = CrossScannerValidationVerdict.Contradicts,
                    Name = "Contradicts: No public SSH listener found",
                    Explanation = "FW-002 reports SSH is open to any source, but the port scanner did not find port 22 listening on a public address."
                };
            }

            if (interfaceSourceAvailable && !interfaceConfirmed)
            {
                return new CrossScannerValidationSignal
                {
                    RuleId = finding.RuleId!,
                    Verdict = CrossScannerValidationVerdict.Contradicts,
                    Name = "Contradicts: No non-loopback network interface is up",
                    Explanation = "FW-002 reports SSH is open to any source, but the network scanner did not find an up non-loopback interface."
                };
            }

            return null;
        }

        public static CrossScannerValidationSignal? ValidateFw004(Finding finding, ScanData scanData)
        {
            // FW-004 claims a firewall should be active. The only independent signal we have is
            // whether the firewall capability is available; the firewall scanner itself produces
            // the finding. Treat this as no independent cross-check and return neutral.
            return null;
        }
    }

    // =====================================================================
    // Network validators
    // =====================================================================
    internal static class NetworkValidators
    {
        public static CrossScannerValidationSignal? ValidateNet002(Finding finding, ScanData scanData)
        {
            if (!IsSourceAvailable(scanData, "ss connections"))
                return null;

            if (scanData.ActiveConnections.Count == 0)
                return null;

            // If active connections exist, the network scanner confirms outbound connectivity is
            // observable. This is a weak support signal; it does not confirm the specific
            // suspicious connection reported by NET-002.
            return new CrossScannerValidationSignal
            {
                RuleId = finding.RuleId!,
                Verdict = CrossScannerValidationVerdict.Supports,
                Name = "Supports: Active network connections observable",
                Explanation = "NET-002 reports suspicious outbound connections; the network scanner confirms active connections are observable on the host."
            };
        }
    }

    // =====================================================================
    // Other validators (single-rule or specialized patterns)
    // =====================================================================
    internal static class OtherValidators
    {
        // USER-001: Multiple UID-0 accounts.
        // Support with a remote admin path that could exploit the privilege.
        public static CrossScannerValidationSignal? ValidateUser001(Finding finding, ScanData scanData)
        {
            var sshServiceConfirmed = IsSourceAvailable(scanData, "systemctl") && HasSshService(scanData);
            var sshPortConfirmed = IsPortSourceAvailable(scanData) && HasPublicListener(scanData, 22);

            if (!sshServiceConfirmed || !sshPortConfirmed)
                return null;

            return new CrossScannerValidationSignal
            {
                RuleId = finding.RuleId!,
                Verdict = CrossScannerValidationVerdict.Supports,
                Name = "Supports: Remote SSH path confirms UID-0 exposure",
                Explanation = "USER-001 reports an additional UID-0 account; the service scanner confirms SSH is running and the port scanner confirms port 22 is listening, creating a reachable privilege-escalation path."
            };
        }
    }

    // =====================================================================
    // Shared helpers
    // =====================================================================

    private static bool IsSourceAvailable(ScanData scanData, string sourceName)
    {
        return scanData.Capabilities.Any(c =>
            c.SourceName.Equals(sourceName, StringComparison.OrdinalIgnoreCase) &&
            c.Status == CapabilityStatus.Available);
    }

    private static bool IsPortSourceAvailable(ScanData scanData)
    {
        return IsSourceAvailable(scanData, "ss") || IsSourceAvailable(scanData, "netstat");
    }

    private static bool IsFirewallSourceAvailable(ScanData scanData)
    {
        return IsSourceAvailable(scanData, "iptables") || IsSourceAvailable(scanData, "nftables");
    }

    private static bool HasPublicListener(ScanData scanData, int port)
    {
        return scanData.OpenPorts.Any(p =>
            p.LocalPort == port &&
            (p.LocalAddress is "0.0.0.0" or "::") &&
            (p.State is "LISTEN" or "LISTENING"));
    }

    private static bool HasNonLoopbackUpInterface(ScanData scanData)
    {
        return scanData.NetworkInterfaces.Any(i =>
            i.IsUp &&
            !i.Name.Equals("lo", StringComparison.OrdinalIgnoreCase) &&
            i.Addresses.Any(a => !a.StartsWith("127.", StringComparison.OrdinalIgnoreCase)));
    }

    private static bool HasSshService(ScanData scanData)
    {
        return scanData.RunningServices.Any(s =>
            s.Name.Contains("ssh", StringComparison.OrdinalIgnoreCase) &&
            !s.Name.Contains("sftp", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsAcceptRule(FirewallRule rule) =>
        rule.Target.Equals("ACCEPT", StringComparison.OrdinalIgnoreCase);

    private static bool IsBlockRule(FirewallRule rule) =>
        rule.Target.Equals("DROP", StringComparison.OrdinalIgnoreCase) ||
        rule.Target.Equals("REJECT", StringComparison.OrdinalIgnoreCase);

    private static bool MatchesDestinationPort(FirewallRule rule, int port)
    {
        // LIMITATION: nftables port sets such as "tcp dport { 8080, 8081 }" are not
        // fully handled — the split tokens contain each port, but this loop only
        // checks the immediate token after "dport". Single-port nft rules work.
        if (rule.DestinationPort != null && int.TryParse(rule.DestinationPort, out var rulePort))
            return rulePort == port;

        var portText = port.ToString(CultureInfo.InvariantCulture);
        var tokens = rule.RawLine.Split(new[] { ' ', '\t', ',', ';', '{', '}', '(', ')' }, StringSplitOptions.RemoveEmptyEntries);

        for (var i = 0; i < tokens.Length; i++)
        {
            var token = tokens[i];

            // iptables single-token form: dpt:8080 or dpts:8080 (but not ranges like dpts:1000:2000).
            if (token.StartsWith("dpt:", StringComparison.OrdinalIgnoreCase) ||
                token.StartsWith("dpts:", StringComparison.OrdinalIgnoreCase))
            {
                var afterColon = token[(token.IndexOf(':') + 1)..];
                if (afterColon.Contains('-') || afterColon.Contains(':'))
                    continue;

                if (afterColon.Equals(portText, StringComparison.OrdinalIgnoreCase))
                    return true;

                continue;
            }

            // Two-token forms: "--dport 8080" (iptables) or "dport 8080" (nftables).
            if (i + 1 < tokens.Length &&
                (token.Equals("dport", StringComparison.OrdinalIgnoreCase) ||
                 token.Equals("--dport", StringComparison.OrdinalIgnoreCase)))
            {
                if (tokens[i + 1].Equals(portText, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        return false;
    }

    private static bool TryGetPort(Finding finding, out int port)
    {
        port = 0;

        if (finding.Variables != null &&
            finding.Variables.TryGetValue("port", out var portText) &&
            int.TryParse(portText, NumberStyles.Integer, CultureInfo.InvariantCulture, out port))
        {
            return true;
        }

        // Fallback for findings created before Variables propagation or by tests.
        if (!finding.Target.Contains(':', StringComparison.OrdinalIgnoreCase))
            return false;

        var lastColon = finding.Target.LastIndexOf(':');
        if (lastColon > 0 && int.TryParse(finding.Target[(lastColon + 1)..], out port))
        {
            return true;
        }

        return false;
    }
}
