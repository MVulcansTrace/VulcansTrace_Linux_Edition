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
            if (finding.Severity is not Severity.Critical and not Severity.High and not Severity.Medium)
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
            ["FW-002"] = ValidateFw002,
            ["PORT-002"] = ValidatePort002,
            ["PORT-003"] = ValidatePort003,
            ["SSH-002"] = ValidateSsh002,
            ["SRV-001"] = ValidateSrv001,
            ["USER-001"] = ValidateUser001
        };
    }

    // =====================================================================
    // FW-002: SSH exposed to any source in firewall rules.
    // Validate with live socket state and a public network interface.
    // =====================================================================
    private static CrossScannerValidationSignal? ValidateFw002(Finding finding, ScanData scanData)
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
                Name = "SSH listener confirmed on public interface",
                Explanation = "FW-002 reports SSH is open to any source; the port scanner independently confirms port 22 is listening, and a non-loopback network interface is up."
            };
        }

        if (portSourceAvailable && !portConfirmed)
        {
            return new CrossScannerValidationSignal
            {
                RuleId = finding.RuleId!,
                Verdict = CrossScannerValidationVerdict.Contradicts,
                Name = "No public SSH listener found",
                Explanation = "FW-002 reports SSH is open to any source, but the port scanner did not find port 22 listening on a public address."
            };
        }

        if (interfaceSourceAvailable && !interfaceConfirmed)
        {
            return new CrossScannerValidationSignal
            {
                RuleId = finding.RuleId!,
                Verdict = CrossScannerValidationVerdict.Contradicts,
                Name = "No non-loopback network interface is up",
                Explanation = "FW-002 reports SSH is open to any source, but the network scanner did not find an up non-loopback interface."
            };
        }

        return null;
    }

    // =====================================================================
    // PORT-002: Service listening on all interfaces.
    // PORT-003: Database port exposed to all interfaces.
    // Validate with the firewall scanner. No active firewall or an explicit ACCEPT
    // supports reachability; an explicit DROP/REJECT weakens the exposure claim.
    // =====================================================================
    private static CrossScannerValidationSignal? ValidatePort002(Finding finding, ScanData scanData)
        => ValidatePortAgainstFirewall(finding, scanData, "service", "a service listening on all interfaces on port");

    private static CrossScannerValidationSignal? ValidatePort003(Finding finding, ScanData scanData)
        => ValidatePortAgainstFirewall(finding, scanData, "database", "database port");

    private static CrossScannerValidationSignal? ValidatePortAgainstFirewall(
        Finding finding,
        ScanData scanData,
        string assetKind,
        string assetDescription)
    {
        if (!IsFirewallSourceAvailable(scanData))
            return null;

        if (!TryGetVariable(finding, "port", out var portText) || !int.TryParse(portText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var port))
            return null;

        if (scanData.FirewallActive)
        {
            var hasAccept = scanData.FirewallRules.Any(r =>
                IsAcceptRule(r) &&
                MatchesDestinationPort(r, port));

            if (hasAccept)
            {
                return new CrossScannerValidationSignal
                {
                    RuleId = finding.RuleId!,
                    Verdict = CrossScannerValidationVerdict.Supports,
                    Name = $"Firewall ACCEPT supports exposed {assetKind}",
                    Explanation = $"{finding.RuleId} reports {assetDescription} {port}; the firewall scanner independently confirms an ACCEPT rule for that port."
                };
            }

            var hasBlock = scanData.FirewallRules.Any(r =>
                IsBlockRule(r) &&
                MatchesDestinationPort(r, port));

            if (hasBlock)
            {
                return new CrossScannerValidationSignal
                {
                    RuleId = finding.RuleId!,
                    Verdict = CrossScannerValidationVerdict.Contradicts,
                    Name = $"Firewall block contradicts exposed {assetKind}",
                    Explanation = $"{finding.RuleId} reports {assetDescription} {port}, but the firewall scanner independently reports a DROP/REJECT rule for that port."
                };
            }

            return null;
        }

        return new CrossScannerValidationSignal
        {
            RuleId = finding.RuleId!,
            Verdict = CrossScannerValidationVerdict.Supports,
            Name = $"No active firewall protecting exposed {assetKind}",
            Explanation = $"{finding.RuleId} reports {assetDescription} {port}; the firewall scanner independently reports no active firewall."
        };
    }

    // =====================================================================
    // SSH-002: Password authentication enabled.
    // Validate with running SSH service and live listener.
    // =====================================================================
    private static CrossScannerValidationSignal? ValidateSsh002(Finding finding, ScanData scanData)
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
                Name = "SSH service and listener independently confirmed",
                Explanation = "SSH-002 reports password authentication is enabled; the service scanner independently confirms an SSH service is running and the port scanner confirms port 22 is listening."
            };
        }

        if (portSourceAvailable && !portConfirmed)
        {
            return new CrossScannerValidationSignal
            {
                RuleId = finding.RuleId!,
                Verdict = CrossScannerValidationVerdict.Contradicts,
                Name = "No public SSH listener found",
                Explanation = "SSH-002 reports password authentication is enabled, but the port scanner did not find port 22 listening on a public address, weakening the reachable-exposure claim."
            };
        }

        if (serviceSourceAvailable && !serviceConfirmed)
        {
            return new CrossScannerValidationSignal
            {
                RuleId = finding.RuleId!,
                Verdict = CrossScannerValidationVerdict.Contradicts,
                Name = "No running SSH service found",
                Explanation = "SSH-002 reports password authentication is enabled, but the service scanner did not find a running SSH service, weakening the reachable-exposure claim."
            };
        }

        return null;
    }

    // =====================================================================
    // SRV-001: Telnet service running.
    // Validate with live telnet listener.
    // =====================================================================
    private static CrossScannerValidationSignal? ValidateSrv001(Finding finding, ScanData scanData)
    {
        if (!IsPortSourceAvailable(scanData))
            return null;

        if (HasPublicListener(scanData, 23))
        {
            return new CrossScannerValidationSignal
            {
                RuleId = finding.RuleId!,
                Verdict = CrossScannerValidationVerdict.Supports,
                Name = "Telnet listener confirmed",
                Explanation = "SRV-001 reports the telnet service is running; the port scanner independently confirms port 23 is listening."
            };
        }

        return new CrossScannerValidationSignal
        {
            RuleId = finding.RuleId!,
            Verdict = CrossScannerValidationVerdict.Contradicts,
            Name = "No public Telnet listener found",
            Explanation = "SRV-001 reports the telnet service is running, but the port scanner did not find port 23 listening on a public address."
        };
    }

    // =====================================================================
    // USER-001: Multiple UID-0 accounts.
    // Support with a remote admin path that could exploit the privilege.
    // =====================================================================
    private static CrossScannerValidationSignal? ValidateUser001(Finding finding, ScanData scanData)
    {
        var sshServiceConfirmed = IsSourceAvailable(scanData, "systemctl") && HasSshService(scanData);
        var sshPortConfirmed = IsPortSourceAvailable(scanData) && HasPublicListener(scanData, 22);

        if (!sshServiceConfirmed || !sshPortConfirmed)
            return null;

        return new CrossScannerValidationSignal
        {
            RuleId = finding.RuleId!,
            Verdict = CrossScannerValidationVerdict.Supports,
            Name = "Remote SSH path confirms UID-0 exposure",
            Explanation = "USER-001 reports an additional UID-0 account; the service scanner confirms SSH is running and the port scanner confirms port 22 is listening, creating a reachable privilege-escalation path."
        };
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
            p.LocalAddress is "0.0.0.0" or "::" &&
            p.State is "LISTEN" or "LISTENING");
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

    private static bool TryGetVariable(Finding finding, string key, out string value)
    {
        value = string.Empty;

        // Findings created by FindingAssemblyService do not currently preserve the
        // original RuleResult.Variables dictionary, so we fall back to parsing the port
        // out of the "{address}:{port}" target format used by PORT-002/PORT-003.
        if (!key.Equals("port", StringComparison.OrdinalIgnoreCase))
            return false;

        if (!finding.Target.Contains(':', StringComparison.OrdinalIgnoreCase))
            return false;

        var lastColon = finding.Target.LastIndexOf(':');
        if (lastColon > 0 && int.TryParse(finding.Target[(lastColon + 1)..], out _))
        {
            value = finding.Target[(lastColon + 1)..];
            return true;
        }

        return false;
    }
}
