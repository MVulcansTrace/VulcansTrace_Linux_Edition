using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class EvidenceProvenanceServiceTests
{
    [Fact]
    public async Task BuildProvenanceAsync_PreviousFinding_BuildsEvidenceChain()
    {
        var state = new AgentAuditState();
        var rule = new TestRule();
        var service = CreateService(rule, state);
        var finding = RememberFinding(state, rule, AgentIntent.FirewallCheck);

        var result = await service.BuildProvenanceAsync(new AgentQuery(AgentIntent.ShowEvidence, "TEST-001"), CancellationToken.None);

        Assert.Equal(AgentIntent.ShowEvidence, result.Intent);
        Assert.Same(finding, Assert.Single(result.AgentFindings));
        Assert.Contains("**TEST-001**", result.Summary);
        Assert.Contains("**Detection source**", result.Summary);
        Assert.Contains("Firewall", result.Summary);
        Assert.Contains("iptables -L -n -v", result.Summary);
        Assert.Contains("**Raw evidence**", result.Summary);
        Assert.Contains("Test firewall exposure", result.Summary);
        Assert.Contains("**Rule evaluation**", result.Summary);
        Assert.Contains("Severity: **High**", result.Summary);
        Assert.Contains("**Compliance context**", result.Summary);
        Assert.Contains("CIS 4.5", result.Summary);
        Assert.Contains("**Threat context**", result.Summary);
        Assert.Contains("T1562.004", result.Summary);
        Assert.Empty(result.Warnings);
    }

    [Fact]
    public async Task BuildProvenanceAsync_MissingReference_ReturnsSelectionGuidance()
    {
        var state = new AgentAuditState();
        var service = CreateService(new TestRule(), state);

        var result = await service.BuildProvenanceAsync(new AgentQuery(AgentIntent.ShowEvidence), CancellationToken.None);

        Assert.Equal(AgentIntent.ShowEvidence, result.Intent);
        Assert.Empty(result.AgentFindings);
        Assert.Contains("Please specify a finding", result.Summary);
    }

    [Fact]
    public async Task BuildProvenanceAsync_UnknownReference_ReturnsGuidance()
    {
        var state = new AgentAuditState();
        var service = CreateService(new TestRule(), state);

        var result = await service.BuildProvenanceAsync(new AgentQuery(AgentIntent.ShowEvidence, "NOPE-404"), CancellationToken.None);

        Assert.Equal(AgentIntent.ShowEvidence, result.Intent);
        Assert.Empty(result.AgentFindings);
        Assert.Contains("I don't have a finding matching 'NOPE-404'", result.Summary);
    }

    [Fact]
    public async Task BuildProvenanceAsync_UnknownRuleIdThatExists_RunsSingleRuleExplanation()
    {
        var state = new AgentAuditState();
        var rule = new TestRule();
        var service = CreateService(rule, state);

        var result = await service.BuildProvenanceAsync(new AgentQuery(AgentIntent.ShowEvidence, "TEST-001"), CancellationToken.None);

        Assert.Equal(AgentIntent.ShowEvidence, result.Intent);
        Assert.Single(result.AgentFindings);
        Assert.Equal("TEST-001", result.AgentFindings[0].RuleId);
        Assert.Contains("**Detection source**", result.Summary);
        Assert.Contains("TEST-001", result.Summary);
    }

    [Fact]
    public async Task BuildProvenanceAsync_AttackChainMembership_IsIncluded()
    {
        var state = new AgentAuditState();
        var rule = new TestRule();
        var service = CreateService(rule, state);
        var finding = RememberFinding(state, rule, AgentIntent.FirewallCheck);
        var previousResult = state.LastResult!;
        state.RememberAudit(
            previousResult with
            {
                AttackChains = new[]
                {
                    new AttackChain
                    {
                        RuleIds = new[] { "TEST-001", "SSH-001" },
                        Links = new[]
                        {
                            new AttackChainLink { RuleId = "TEST-001", Stage = AttackChainStage.InitialAccess, StageName = "Initial Access", Severity = Severity.High },
                            new AttackChainLink { RuleId = "SSH-001", Stage = AttackChainStage.Execution, StageName = "Execution", Severity = Severity.High }
                        }
                    }
                }
            },
            AgentIntent.FirewallCheck,
            new[] { ("TEST-001", finding) });

        var result = await service.BuildProvenanceAsync(new AgentQuery(AgentIntent.ShowEvidence, "TEST-001"), CancellationToken.None);

        Assert.Contains("**Attack chain membership**", result.Summary);
        Assert.Contains("TEST-001 → SSH-001", result.Summary);
    }

    [Fact]
    public async Task BuildProvenanceAsync_HistoryAvailable_ShowsHistorySection()
    {
        var state = new AgentAuditState();
        var rule = new TestRule();
        var service = CreateService(rule, state);
        var finding = RememberFinding(state, rule, AgentIntent.FirewallCheck);
        var history = CreateHistory("TEST-001", Severity.High, Severity.High);
        state.Entities.RuleHistory = history.ToDictionary(e => e.Key, e => e.Value, StringComparer.OrdinalIgnoreCase);

        var result = await service.BuildProvenanceAsync(new AgentQuery(AgentIntent.ShowEvidence, "TEST-001"), CancellationToken.None);

        Assert.Contains("**History**", result.Summary);
        Assert.Contains("present in", result.Summary);
        Assert.Contains("audit snapshot(s)", result.Summary);
    }

    [Fact]
    public async Task BuildProvenanceAsync_UsesFocusedFindingWhenNoTargetReference()
    {
        var state = new AgentAuditState();
        var rule = new TestRule();
        var service = CreateService(rule, state);
        var finding = RememberFinding(state, rule, AgentIntent.FirewallCheck);
        state.FocusFinding(finding, finding.RuleId);

        var result = await service.BuildProvenanceAsync(new AgentQuery(AgentIntent.ShowEvidence), CancellationToken.None);

        Assert.Equal(AgentIntent.ShowEvidence, result.Intent);
        Assert.Same(finding, Assert.Single(result.AgentFindings));
    }

    [Fact]
    public async Task BuildProvenanceAsync_SshFinding_AttributesToSshScannerNotPortSs()
    {
        // Regression for the "ss" substring collision: SSH data sources ("/etc/ssh/sshd_config",
        // "sshd -T") both contain "ss", so a loose match mis-attributed the finding to the Port
        // scanner's `ss -tulnp`. The SSH scanner/command must win instead.
        var state = new AgentAuditState();
        var rule = new TestSshRule();
        var service = CreateService(rule, state);
        var caps = new[]
        {
            new DataSourceCapability { SourceName = "ss", Command = "ss -tulnp", Status = CapabilityStatus.Available },
            new DataSourceCapability { SourceName = "sshd -T", Command = "sshd -T", Status = CapabilityStatus.Available },
            new DataSourceCapability { SourceName = "sshd_config", Command = "/etc/ssh/sshd_config", Status = CapabilityStatus.PermissionLimited }
        };
        RememberCustomFinding(state, "SSH-001", "SSH", "PermitRootLogin enabled", Severity.High, caps);

        var result = await service.BuildProvenanceAsync(new AgentQuery(AgentIntent.ShowEvidence, "SSH-001"), CancellationToken.None);

        Assert.DoesNotContain("ss -tulnp", result.Summary);
        Assert.Contains("sshd_config", result.Summary);
        Assert.Contains("sshd -T", result.Summary);
        Assert.Contains("permission-limited", result.Summary);
    }

    [Fact]
    public async Task BuildProvenanceAsync_CrossScannerSignals_RenderSupportsAndContradictsAndNames()
    {
        var state = new AgentAuditState();
        var rule = new TestRule();
        var service = CreateService(rule, state);
        var signals = new[]
        {
            new EvidenceSignal { Source = "CrossScannerValidation", Name = "Supports: SSH listener confirmed on public interface", Explanation = "port scanner confirms port 22" },
            new EvidenceSignal { Source = "CrossScannerValidation", Name = "Contradicts: No public SSH listener found", Explanation = "port scanner disagrees" },
            new EvidenceSignal { Source = "ThreatIntel", Name = "IOC match on ip", Explanation = "matched a known-bad ip" }
        };
        RememberCustomFinding(state, "TEST-001", "Firewall", "Test firewall exposure", Severity.High,
            new[] { new DataSourceCapability { SourceName = "iptables", Command = "iptables -L -n -v", Status = CapabilityStatus.Available } },
            signals);

        var result = await service.BuildProvenanceAsync(new AgentQuery(AgentIntent.ShowEvidence, "TEST-001"), CancellationToken.None);

        Assert.Contains("Cross-scanner validation supports:", result.Summary);
        Assert.Contains("SSH listener confirmed on public interface", result.Summary);
        Assert.Contains("Cross-scanner validation contradicts:", result.Summary);
        Assert.Contains("No public SSH listener found", result.Summary);
        Assert.Contains("ThreatIntel:", result.Summary);
        Assert.Contains("IOC match on ip", result.Summary);
    }

    [Fact]
    public async Task BuildProvenanceAsync_AttackChainWithEmptyLinks_SkipsSection()
    {
        var state = new AgentAuditState();
        var rule = new TestRule();
        var service = CreateService(rule, state);
        var finding = RememberFinding(state, rule, AgentIntent.FirewallCheck);
        var previousResult = state.LastResult!;
        state.RememberAudit(
            previousResult with
            {
                AttackChains = new[]
                {
                    new AttackChain { RuleIds = new[] { "TEST-001" }, Links = Array.Empty<AttackChainLink>() }
                }
            },
            AgentIntent.FirewallCheck,
            new[] { ("TEST-001", finding) });

        var result = await service.BuildProvenanceAsync(new AgentQuery(AgentIntent.ShowEvidence, "TEST-001"), CancellationToken.None);

        Assert.DoesNotContain("**Attack chain membership**", result.Summary);
    }

    [Fact]
    public async Task BuildProvenanceAsync_RuleExistsButPasses_ReportsPassing()
    {
        var state = new AgentAuditState();
        var rule = new TestPassingRule();
        var service = CreateService(rule, state);

        var result = await service.BuildProvenanceAsync(new AgentQuery(AgentIntent.ShowEvidence, "PASS-001"), CancellationToken.None);

        Assert.Equal(AgentIntent.ShowEvidence, result.Intent);
        Assert.Empty(result.AgentFindings);
        Assert.Contains("PASS-001", result.Summary);
        Assert.Contains("currently passing", result.Summary);
    }

    [Fact]
    public async Task BuildProvenanceAsync_HistoryWithTrendAndLastFixed_ShowsBothPhrases()
    {
        var state = new AgentAuditState();
        var rule = new TestRule();
        var service = CreateService(rule, state);
        var finding = RememberFinding(state, rule, AgentIntent.FirewallCheck);
        var now = DateTime.UtcNow;
        state.Entities.RuleHistory = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["TEST-001"] = new RuleMemoryEntry
            {
                RuleId = "TEST-001",
                Category = "Firewall",
                FirstSeenUtc = now.AddDays(-10),
                LastSeenUtc = now,
                SeverityHistory = new[] { new RuleSeveritySnapshot { UtcTimestamp = now.AddDays(-1), Severity = Severity.High } },
                Trend = RuleStatusTrend.Worsening,
                LastSeverity = Severity.High,
                LastVerifiedFixedUtc = now.AddHours(-2)
            }
        };

        var result = await service.BuildProvenanceAsync(new AgentQuery(AgentIntent.ShowEvidence, "TEST-001"), CancellationToken.None);

        Assert.Contains("**History**", result.Summary);
        Assert.Contains("trend is **Worsening**", result.Summary);
        Assert.Contains("last verified fixed", result.Summary);
        Assert.Contains("10 day", result.Summary);
    }

    [Fact]
    public async Task BuildProvenanceAsync_CategoryReference_PrefersFocusedFinding()
    {
        var state = new AgentAuditState();
        var service = CreateService(new TestRule(), state);
        var caps = new[] { new DataSourceCapability { SourceName = "iptables", Command = "iptables -L -n -v", Status = CapabilityStatus.Available } };
        var first = MakeFinding("SSH-001", "SSH", "First SSH issue", Severity.High);
        var second = MakeFinding("SSH-002", "SSH", "Second SSH issue", Severity.High);
        var batch = new AgentResult
        {
            Intent = AgentIntent.SshCheck,
            AgentFindings = new[] { first, second },
            DataSourceCapabilities = caps
        };
        state.RememberAudit(batch, AgentIntent.SshCheck, new[] { ("SSH-001", first), ("SSH-002", second) });
        state.FocusFinding(second, "SSH-002");

        var result = await service.BuildProvenanceAsync(new AgentQuery(AgentIntent.ShowEvidence, "SSH"), CancellationToken.None);

        Assert.Same(second, Assert.Single(result.AgentFindings));
    }

    [Fact]
    public async Task BuildProvenanceAsync_TargetWithBacktick_UsesDoubleBacktickCodeSpan()
    {
        var state = new AgentAuditState();
        var service = CreateService(new TestRule(), state);
        var caps = new[] { new DataSourceCapability { SourceName = "iptables", Command = "iptables -L -n -v", Status = CapabilityStatus.Available } };
        // Simulate a previous finding whose target contains a backtick.
        var backtickFinding = MakeFinding("BACK-001", "Firewall", "Backtick target", Severity.High) with
        {
            Target = "echo `date`"
        };
        var result = new AgentResult
        {
            Intent = AgentIntent.FirewallCheck,
            AgentFindings = new[] { backtickFinding },
            DataSourceCapabilities = caps
        };
        state.RememberAudit(result, AgentIntent.FirewallCheck, new[] { ("BACK-001", backtickFinding) });

        var response = await service.BuildProvenanceAsync(new AgentQuery(AgentIntent.ShowEvidence, "BACK-001"), CancellationToken.None);

        Assert.Contains("`` echo `date` ``", response.Summary);
    }

    [Fact]
    public async Task BuildProvenanceAsync_SingleDigitRuleId_ResolvesFocusedFinding()
    {
        var state = new AgentAuditState();
        var rule = new TestSingleDigitRule();
        var service = CreateService(rule, state);
        var finding = RememberFinding(state, rule, AgentIntent.FirewallCheck);
        state.FocusFinding(finding, "FW-1");

        var result = await service.BuildProvenanceAsync(new AgentQuery(AgentIntent.ShowEvidence, "FW-1"), CancellationToken.None);

        Assert.Same(finding, Assert.Single(result.AgentFindings));
    }

    [Fact]
    public async Task BuildProvenanceAsync_ThreatIntelHashFinding_UsesFileHashCapabilityCommand()
    {
        var state = new AgentAuditState();
        var rule = new TestThreatIntelHashRule();
        var service = CreateService(rule, state);
        var caps = new[]
        {
            new DataSourceCapability { SourceName = "file-hash", Command = "sha256sum/md5sum/sha1sum <files>", Status = CapabilityStatus.Available }
        };
        RememberCustomFinding(state, "TI-003", "ThreatIntel", "Known malicious hash", Severity.Critical, caps);

        var result = await service.BuildProvenanceAsync(new AgentQuery(AgentIntent.ShowEvidence, "TI-003"), CancellationToken.None);

        Assert.Contains("sha256sum/md5sum/sha1sum <files>", result.Summary);
        Assert.Contains("Available", result.Summary);
        Assert.DoesNotContain("threat-intel", result.Summary);
    }

    private static Finding MakeFinding(string ruleId, string category, string shortDescription, Severity severity, IReadOnlyList<EvidenceSignal>? signals = null)
        => new()
        {
            RuleId = ruleId,
            Category = category,
            ShortDescription = shortDescription,
            Severity = severity,
            Target = shortDescription,
            Details = shortDescription,
            Confidence = DetectionConfidence.High,
            EvidenceSignals = signals ?? Array.Empty<EvidenceSignal>()
        };

    private static Finding RememberCustomFinding(
        AgentAuditState state, string ruleId, string category, string shortDescription,
        Severity severity, IReadOnlyList<DataSourceCapability> caps,
        IReadOnlyList<EvidenceSignal>? signals = null, AgentIntent intent = AgentIntent.SshCheck)
    {
        var finding = MakeFinding(ruleId, category, shortDescription, severity, signals);
        var result = new AgentResult { Intent = intent, AgentFindings = new[] { finding }, DataSourceCapabilities = caps };
        state.RememberAudit(result, intent, new[] { (ruleId, finding) });
        return finding;
    }

    private static EvidenceProvenanceService CreateService(IRule rule, AgentAuditState state)
    {
        var explanationProvider = new TestExplanationProvider();
        var scannerCoordinator = new ScannerCoordinator(new[] { new NoopScanner() });
        var ruleEvaluationService = new RuleEvaluationService(new[] { rule }, MachineRole.Server, policyProvider: null);
        var findingAssemblyService = new FindingAssemblyService(explanationProvider, suppressionStore: null);
        var resultComposer = new AgentResultComposer();
        var singleRuleExplanationService = new SingleRuleExplanationService(
            scannerCoordinator,
            ruleEvaluationService,
            findingAssemblyService,
            resultComposer,
            state,
            MachineRole.Server);

        return new EvidenceProvenanceService(
            state,
            ruleEvaluationService,
            singleRuleExplanationService);
    }

    private static Finding RememberFinding(AgentAuditState state, IRule rule, AgentIntent intent)
    {
        var ruleEvaluationService = new RuleEvaluationService(new[] { rule }, MachineRole.Server, policyProvider: null);
        var explanationProvider = new TestExplanationProvider();
        var findingAssemblyService = new FindingAssemblyService(explanationProvider, suppressionStore: null);
        var scanData = new ScanData();
        var evaluated = ruleEvaluationService.EvaluateForIntent(intent, scanData, CancellationToken.None);
        var assembled = findingAssemblyService.Assemble(evaluated.RuleResults.ToList());
        var finding = assembled.AgentFindings[0];
        var result = new AgentResult
        {
            Intent = intent,
            AgentFindings = new[] { finding },
            DataSourceCapabilities = new[]
            {
                new DataSourceCapability { SourceName = "iptables", Command = "iptables -L -n -v", Status = CapabilityStatus.Available }
            }
        };
        state.RememberAudit(result, intent, new[] { (finding.RuleId!, finding) });
        return finding;
    }

    private static IReadOnlyDictionary<string, RuleMemoryEntry> CreateHistory(string ruleId, params Severity[] severities)
    {
        var now = DateTime.UtcNow;
        var snapshots = severities
            .Select((severity, index) => new RuleSeveritySnapshot
            {
                UtcTimestamp = now.AddDays(-(severities.Length - 1 - index)),
                Severity = severity
            })
            .ToArray();

        return new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            [ruleId] = new RuleMemoryEntry
            {
                RuleId = ruleId,
                Category = "Firewall",
                FirstSeenUtc = snapshots[0].UtcTimestamp,
                LastSeenUtc = snapshots[^1].UtcTimestamp,
                SeverityHistory = snapshots,
                Trend = RuleStatusTrend.Stable,
                LastSeverity = snapshots[^1].Severity
            }
        };
    }

    private sealed class NoopScanner : IScanner
    {
        public string Name => "Noop";

        public Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }

    private sealed class TestRule : IRule
    {
        public string Id => "TEST-001";
        public string Category => "Firewall";
        public string Description => "Test firewall exposure";
        public string WhatItChecks => "Tests scanner command tracking";
        public IReadOnlyList<string> SupportedDataSources => new[] { "iptables -L -n -v", "nft list ruleset" };
        public Severity Severity => Severity.High;

        public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
        {
            new CisBenchmarkMapping
            {
                ControlId = "CIS 4.5",
                ControlName = "Implement and Manage a Firewall on Servers",
                WhyItMatters = "Test why it matters",
                BenchmarkReference = "CIS Ubuntu 24.04 LTS 3.5.1.6"
            }
        };

        public IReadOnlyList<MitreTechnique> MitreTechniques => new[]
        {
            new MitreTechnique { TechniqueId = "T1562.004", TechniqueName = "Impair Defenses: Disable or Modify System Firewall", Tactic = "Defense Evasion", WhyItMatters = "Test" }
        };

        public RuleResult Evaluate(ScanData data)
        {
            return RuleResult.Fail(Id, Category, Id, Description, Severity, "0.0.0.0/0:22", cisMappings: CisMappings, mitreTechniques: MitreTechniques);
        }
    }

    private sealed class TestSshRule : IRule
    {
        public string Id => "SSH-001";
        public string Category => "SSH";
        public string Description => "PermitRootLogin enabled";
        public string WhatItChecks => "sshd config";
        public IReadOnlyList<string> SupportedDataSources => new[] { "/etc/ssh/sshd_config", "sshd -T" };
        public Severity Severity => Severity.High;
        public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();
        public IReadOnlyList<MitreTechnique> MitreTechniques => Array.Empty<MitreTechnique>();
        public RuleResult Evaluate(ScanData data) =>
            RuleResult.Fail(Id, Category, Id, Description, Severity, "PermitRootLogin yes");
    }

    private sealed class TestPassingRule : IRule
    {
        public string Id => "PASS-001";
        public string Category => "Test";
        public string Description => "Always passes";
        public string WhatItChecks => "nothing";
        public IReadOnlyList<string> SupportedDataSources => Array.Empty<string>();
        public Severity Severity => Severity.Info;
        public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();
        public IReadOnlyList<MitreTechnique> MitreTechniques => Array.Empty<MitreTechnique>();
        public RuleResult Evaluate(ScanData data) => RuleResult.Pass(Id, Category, Id, Description);
    }

    private sealed class TestSingleDigitRule : IRule
    {
        public string Id => "FW-1";
        public string Category => "Firewall";
        public string Description => "Single-digit rule ID";
        public string WhatItChecks => "tests regex";
        public IReadOnlyList<string> SupportedDataSources => Array.Empty<string>();
        public Severity Severity => Severity.High;
        public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();
        public IReadOnlyList<MitreTechnique> MitreTechniques => Array.Empty<MitreTechnique>();
        public RuleResult Evaluate(ScanData data) => RuleResult.Fail(Id, Category, Id, Description, Severity, "0.0.0.0/0");
    }

    private sealed class TestThreatIntelHashRule : IRule
    {
        public string Id => "TI-003";
        public string Category => "ThreatIntel";
        public string Description => "File hash matches a known malicious hash from threat intel";
        public string WhatItChecks => "Correlates file hashes against imported threat intel hash IOCs";
        public IReadOnlyList<string> SupportedDataSources => new[] { "file-hash" };
        public Severity Severity => Severity.Critical;
        public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();
        public IReadOnlyList<MitreTechnique> MitreTechniques => Array.Empty<MitreTechnique>();
        public RuleResult Evaluate(ScanData data) => RuleResult.Fail(Id, Category, Id, Description, Severity, "known hash");
    }

    private sealed class TestExplanationProvider : IExplanationProvider
    {
        public string GetExplanation(string key, IReadOnlyDictionary<string, string> variables)
        {
            return $"explanation:{key}";
        }

        public StructuredExplanation GetStructuredExplanation(string key, IReadOnlyDictionary<string, string> variables)
        {
            return new StructuredExplanation { WhatWasFound = GetExplanation(key, variables) };
        }

        public StructuredExplanation ParseStructuredFromText(string text)
        {
            return new StructuredExplanation
            {
                WhatWasFound = $"parsed-found:{text}",
                WhyItMatters = $"parsed-why:{text}",
                HowToVerify = "parsed-verify",
                SuggestedNextAction = "parsed-action",
                Confidence = "High",
                Caveats = "parsed-caveat"
            };
        }
    }
}
