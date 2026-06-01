using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Baselines;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Rules.SecurityRules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class SecurityAgentTests
{
    [Fact]
    public async Task AskAsync_HelpQuery_ReturnsHelpResult()
    {
        var agent = CreateAgent();

        var result = await agent.AskAsync("what can you do?", null, CancellationToken.None);

        Assert.Equal(AgentIntent.Help, result.Intent);
        Assert.Contains("help you audit", result.Summary);
    }

    [Fact]
    public async Task AskAsync_FullAudit_RunsRulesAndReturnsFindings()
    {
        var agent = CreateAgent();

        var result = await agent.AskAsync("is my system secure?", null, CancellationToken.None);

        Assert.Equal(AgentIntent.FullAudit, result.Intent);
        Assert.NotNull(result.AgentFindings);
        Assert.NotNull(result.Warnings);
        Assert.NotEmpty(result.Summary);
    }

    [Fact]
    public async Task AskAsync_AmbiguousQuery_ReturnsClarificationWithoutScanning()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new ThrowingScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        var result = await agent.AskAsync("check firewall ports", null, CancellationToken.None);

        Assert.Equal(AgentIntent.Help, result.Intent);
        Assert.Empty(result.AgentFindings);
        Assert.Contains("couple of ways", result.Summary);
        Assert.Contains("firewall", result.Summary);
        Assert.Contains("ports", result.Summary);
    }

    [Fact]
    public async Task RunAuditAsync_FirewallCheck_OnlyFirewallRulesRun()
    {
        var agent = CreateAgent();

        var result = await agent.RunAuditAsync(AgentIntent.FirewallCheck, null, CancellationToken.None);

        Assert.Equal(AgentIntent.FirewallCheck, result.Intent);
        // Even with no real firewall, rules evaluate and may return findings
        Assert.NotNull(result.AgentFindings);
    }

    [Fact]
    public async Task RunAuditAsync_FilePermissionCheck_OnlyFilePermissionRulesRun()
    {
        var agent = CreateAgent();

        var result = await agent.RunAuditAsync(AgentIntent.FilePermissionCheck, null, CancellationToken.None);

        Assert.Equal(AgentIntent.FilePermissionCheck, result.Intent);
        Assert.NotNull(result.AgentFindings);
        // All non-file-permission rules should be filtered out
        Assert.DoesNotContain(result.RuleResults, r => r.Category.Equals("Firewall", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(result.RuleResults, r => r.Category.Equals("SSH", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_KernelCheck_OnlyKernelRulesRun()
    {
        var agent = CreateAgent();

        var result = await agent.RunAuditAsync(AgentIntent.KernelCheck, null, CancellationToken.None);

        Assert.Equal(AgentIntent.KernelCheck, result.Intent);
        Assert.NotNull(result.RuleResults);
        Assert.All(result.RuleResults, r => Assert.Equal("Kernel", r.Category));
        Assert.DoesNotContain(result.RuleResults, r => r.Category.Equals("Firewall", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_Cancellation_ThrowsOperationCanceledException()
    {
        var agent = CreateAgent();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await agent.RunAuditAsync(AgentIntent.FullAudit, null, cts.Token));
    }

    [Fact]
    public async Task ExplainFindingAsync_ReturnsSingleFindingWithRichSummary()
    {
        var agent = CreateAgent();
        var finding = new Finding
        {
            Category = "Test",
            Severity = Severity.Low,
            SourceHost = "localhost",
            Target = "test-target",
            ShortDescription = "Test finding",
            Details = "This is a detailed explanation.",
            TimeRangeStart = DateTime.UtcNow,
            TimeRangeEnd = DateTime.UtcNow
        };

        var result = await agent.ExplainFindingAsync(finding, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Single(result.AgentFindings);
        Assert.Contains("Test finding", result.Summary);
        Assert.Contains("What was found", result.Summary);
        Assert.Contains("Why it matters", result.Summary);
    }

    [Fact]
    public async Task AskAsync_ExplainFinding_WithoutReference_ReturnsGuidance()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        var result = await agent.AskAsync("explain this finding", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Empty(result.AgentFindings);
        Assert.Contains("specify a finding", result.Summary);
    }

    [Fact]
    public async Task AskAsync_ExplainFinding_WithUnknownReference_ReturnsGuidance()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        var result = await agent.AskAsync("explain UNKNOWN-999", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Empty(result.AgentFindings);
        Assert.Contains("don't have a finding matching", result.Summary);
    }

    [Fact]
    public async Task AskAsync_ExplainFinding_AfterAudit_ResolvesByReference()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        // First run an audit to populate last finding state
        var auditResult = await agent.AskAsync("is my system secure?", null, CancellationToken.None);
        Assert.Single(auditResult.AgentFindings);

        // Then ask to explain the finding by its rule ID
        var explainResult = await agent.AskAsync("explain TEST-001", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, explainResult.Intent);
        Assert.Single(explainResult.AgentFindings);
        Assert.Contains("Test finding should be explained", explainResult.Summary);
    }

    [Fact]
    public async Task AskAsync_ExplainFinding_AfterAudit_ResolvesByCategory()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        // First run an audit
        await agent.AskAsync("is my system secure?", null, CancellationToken.None);

        // Then ask to explain by category keyword
        var explainResult = await agent.AskAsync("explain the firewall finding", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, explainResult.Intent);
        Assert.Single(explainResult.AgentFindings);
    }

    [Fact]
    public async Task AskAsync_ExplainFinding_ByRuleId_RunsSingleRule()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        // Ask to explain a specific rule ID without prior audit
        var result = await agent.AskAsync("explain TEST-001", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Single(result.AgentFindings);
        Assert.Equal("Test finding should be explained", result.AgentFindings[0].ShortDescription);
    }

    [Fact]
    public async Task AskAsync_ExplainFinding_ByRuleId_RespectsDisabledPolicy()
    {
        var policyStore = new InMemoryRulePolicyStore();
        policyStore.SetPolicy("TEST-001", MachineRole.Server, new RulePolicy { Enabled = false });
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            machineRole: MachineRole.Server,
            policyProvider: policyStore);

        var result = await agent.AskAsync("explain TEST-001", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Empty(result.AgentFindings);
        Assert.Contains("disabled by policy", result.Summary);
        Assert.Equal(1, result.PassedCount);
        Assert.Equal(0, result.FailedCount);
    }

    [Fact]
    public async Task RunAuditAsync_FindingIncludesRuleId()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        var result = await agent.AskAsync("is my system secure?", null, CancellationToken.None);

        Assert.Single(result.AgentFindings);
        Assert.Equal("TEST-001", result.AgentFindings[0].RuleId);
    }

    [Fact]
    public async Task RunAuditAsync_AllFailuresSuppressed_SummaryShowsNoActiveIssues()
    {
        var suppressionStore = new InMemorySuppressionStore();
        suppressionStore.Add(new SuppressionEntry { RuleId = "TEST-001", Target = "test-target" });
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            suppressionStore: suppressionStore);

        var result = await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        Assert.Empty(result.AgentFindings);
        Assert.Contains("0 active issue", result.Summary);
        Assert.Contains("1 suppressed", result.Summary);
        Assert.Contains(result.Warnings, w => w.Contains("suppressed", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunAuditAsync_ExpiredSuppression_IsResurfacedAsFinding()
    {
        var suppressionStore = new InMemorySuppressionStore();
        suppressionStore.Add(new SuppressionEntry
        {
            RuleId = "TEST-001",
            Target = "test-target",
            ExpiresAt = DateTime.UtcNow.AddMinutes(-1)
        });
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            suppressionStore: suppressionStore);

        var result = await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        Assert.Single(result.AgentFindings);
        Assert.Equal(0, result.SuppressedCount);
        Assert.Equal(1, result.FailedCount);
    }

    [Fact]
    public async Task RunAuditAsync_PopulatesCounts()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysPassRule(), new AlwaysFailRule() },
            new ExplanationProvider());

        var result = await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        Assert.Equal(1, result.PassedCount);
        Assert.Equal(1, result.FailedCount);
        Assert.Equal(2, result.RuleResults.Count);
        Assert.Single(result.AgentFindings);
    }

    [Fact]
    public async Task RunAuditAsync_PopulatesCapabilityReport_WithRealScanners()
    {
        var agent = CreateAgent();

        var result = await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        Assert.NotNull(result.CapabilityReport);
        Assert.Contains("Data sources:", result.CapabilityReport);
    }

    [Fact]
    public async Task RunAuditAsync_CapabilityReport_WithNoopScanner_IsEmpty()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysPassRule() },
            new ExplanationProvider());

        var result = await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        Assert.Equal(string.Empty, result.CapabilityReport);
    }

    [Fact]
    public async Task RunAuditAsync_CapabilityReport_IsDeterministicAndDeduplicated()
    {
        var agent = new SecurityAgent(
            new IScanner[]
            {
                new CapabilityScanner(
                    new DataSourceCapability { SourceName = "systemctl", Status = CapabilityStatus.Unavailable },
                    new DataSourceCapability { SourceName = "iptables", Status = CapabilityStatus.Available },
                    new DataSourceCapability { SourceName = "systemctl", Status = CapabilityStatus.PermissionLimited },
                    new DataSourceCapability { SourceName = "ss", Status = CapabilityStatus.Unknown })
            },
            Array.Empty<IRule>(),
            new ExplanationProvider());

        var result = await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        Assert.Equal("Data sources: iptables available; ss unknown; systemctl permission-limited.", result.CapabilityReport);
    }

    private sealed class AlwaysPassRule : IRule
    {
        public string Id => "TEST-002";
        public string Category => "Network";
        public string Description => "Test rule that always passes";
        public string WhatItChecks => "Test pass";
        public IReadOnlyList<string> SupportedDataSources => new[] { "test" };
        public Severity Severity => Severity.Info;

        public RuleResult Evaluate(ScanData data)
        {
            return RuleResult.Pass(Id, Category, Id, "All good");
        }
    }

    private static SecurityAgent CreateAgent()
    {
        var scanners = new IScanner[]
        {
            new FirewallScanner(),
            new PortScanner(),
            new ServiceScanner(),
            new NetworkScanner(),
            new SshConfigScanner(),
            new FilePermissionScanner(),
            new FilesystemAuditScanner(),
            new KernelHardeningScanner(),
            new UserAccountScanner(),
            new LoggingAuditScanner(),
            new CronJobScanner(),
            new PackageVulnerabilityScanner()
        };

        var rules = new IRule[]
        {
            new FirewallActiveRule(),
            new FirewallDefaultDropRule(),
            new FirewallSshExposureRule(),
            new FirewallStateTrackingRule(),
            new FirewallIcmpRule(),
            new DefaultRouteRule(),
            new SuspiciousConnectionsRule(),
            new NetworkInterfaceUpRule(),
            new LoopbackExposureRule(),
            new TelnetServiceRule(),
            new FtpServiceRule(),
            new SshServiceRule(),
            new LegacyRservicesRule(),
            new UnnecessaryServicesRule(),
            new SshNonDefaultPortRule(),
            new WideOpenServicesRule(),
            new DatabasePortExposureRule(),
            new HighPortListeningRule(),
            new SshPermitRootLoginRule(),
            new SshPasswordAuthenticationRule(),
            new SshMaxAuthTriesRule(),
            new SshProtocolRule(),
            new SshEmptyPasswordsRule(),
            new SshPubkeyAuthenticationRule(),
            new SshX11ForwardingRule(),
            new SshUsePamRule(),
            new ShadowPermissionRule(),
            new PasswdPermissionRule(),
            new SshHostKeyPermissionRule(),
            new RootSshDirectoryPermissionRule(),
            new CronDirectoryWorldWritableRule(),
            new CrontabPermissionRule(),
            new SuspiciousCronEntryRule(),
            new WorldWritableCronScriptRule(),
            new RootCronForNonRootUserRule(),
            new UserSshDirectoryPermissionRule(),
            new WorldWritableFileRule(),
            new UnexpectedSuidSgidRule(),
            new UnownedFileRule(),
            new WorldWritableDirNoStickyRule(),
            new TmpHardeningRule(),
            new AslrEnabledRule(),
            new IpForwardingDisabledRule(),
            new IcmpRedirectsDisabledRule(),
            new SourceRoutingDisabledRule(),
            new KernelModuleLoadingRestrictedRule(),
            new SecureBootEnabledRule(),
            new KernelPointerExposureRestrictedRule(),
            new UidZeroBeyondRootRule(),
            new EmptyPasswordRule(),
            new PasswordAgingRule(),
            new PamPasswordComplexityRule(),
            new PamFaillockConfiguredRule(),
            new PamPasswordQualityDetailedRule(),
            new PamAuthRequiredRule(),
            new InactiveAccountsRule(),
            new DuplicateUidsRule(),
            new MissingHomeDirectoryRule(),
            new LoggingServiceActiveRule(),
            new AuditdActiveRule(),
            new AuditdRulesConfiguredRule(),
            new LogRotationConfiguredRule(),
            new CentralForwardingConfiguredRule(),
            new AuditdPrivilegeEscalationMonitoringRule(),
            new ForwardingUsesTcpRule(),
            new SecurityUpdatesAvailableRule(),
            new UnattendedUpgradesEnabledRule(),
            new CriticalCvesPresentRule()
        };

        var explanationProvider = new ExplanationProvider();
        return new SecurityAgent(scanners, rules, explanationProvider);
    }

    private sealed class NoopScanner : IScanner
    {
        public string Name => "Noop";

        public Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingScanner : IScanner
    {
        public string Name => "Throwing";

        public Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("Scanner should not run for ambiguous queries.");
        }
    }

    private sealed class CapabilityScanner(params DataSourceCapability[] capabilities) : IScanner
    {
        public string Name => "Capability";

        public Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
        {
            foreach (var capability in capabilities)
            {
                builder.AddCapability(capability);
            }

            return Task.CompletedTask;
        }
    }

    private sealed class AlwaysFailRule : IRule
    {
        public string Id => "TEST-001";
        public string Category => "Firewall";
        public string Description => "Test finding should be explained";
        public string WhatItChecks => "Test rule that always fails";
        public IReadOnlyList<string> SupportedDataSources => new[] { "test" };
        public Severity Severity => Severity.Low;

        public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
        {
            new CisBenchmarkMapping
            {
                ControlId = "CIS 4.5",
                ControlName = "Implement and Manage a Firewall on Servers",
                WhyItMatters = "Test why it matters.",
                BenchmarkReference = "CIS Ubuntu 24.04 LTS 3.5.1.3 — Ensure default deny firewall policy"
            }
        };

        public RuleResult Evaluate(ScanData data)
        {
            return RuleResult.Fail(
                Id,
                Category,
                Id,
                Description,
                Severity.Low,
                "test-target",
                cisMappings: CisMappings);
        }
    }

    private sealed class AlwaysCrashRule : IRule
    {
        public string Id => "TEST-003";
        public string Category => "Port";
        public string Description => "Test rule that always crashes";
        public string WhatItChecks => "Test crash";
        public IReadOnlyList<string> SupportedDataSources => new[] { "test" };
        public Severity Severity => Severity.Info;

        public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
        {
            new CisBenchmarkMapping
            {
                ControlId = "CIS 4.1",
                ControlName = "Establish and Maintain a Secure Configuration Process",
                WhyItMatters = "Test crash mapping.",
                BenchmarkReference = "CIS Ubuntu 24.04 LTS 2.2.4 — Ensure SSH server is installed"
            }
        };

        public RuleResult Evaluate(ScanData data)
        {
            throw new InvalidOperationException("Simulated crash");
        }
    }

    [Fact]
    public async Task RunAuditAsync_CrashedRule_AddsCrashResultAndCount()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysPassRule(), new AlwaysCrashRule() },
            new ExplanationProvider());

        var result = await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        Assert.Equal(1, result.PassedCount);
        Assert.Equal(0, result.FailedCount);
        Assert.Equal(1, result.CrashedCount);
        Assert.Equal(2, result.RuleResults.Count);

        var crashResult = result.RuleResults.First(r => r.RuleId == "TEST-003");
        Assert.Equal(RuleStatus.Crashed, crashResult.Status);
        Assert.False(crashResult.Passed);
    }

    [Fact]
    public async Task RunAuditAsync_CrashOnlySummary_DoesNotMentionZeroSuppressions()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysCrashRule() },
            new ExplanationProvider());

        var result = await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        Assert.Contains("0 active issue", result.Summary);
        Assert.Contains("1 rule(s) crashed", result.Summary);
        Assert.DoesNotContain("0 suppressed", result.Summary);
    }

    [Fact]
    public async Task RunAuditAsync_SuppressedRule_HasSuppressedStatus()
    {
        var suppressionStore = new InMemorySuppressionStore();
        suppressionStore.Add(new SuppressionEntry { RuleId = "TEST-001", Target = "test-target" });
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysPassRule(), new AlwaysFailRule() },
            new ExplanationProvider(),
            suppressionStore: suppressionStore);

        var result = await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        Assert.Equal(1, result.PassedCount);
        Assert.Equal(0, result.FailedCount);
        Assert.Equal(1, result.SuppressedCount);
        Assert.Equal(0, result.CrashedCount);
        Assert.Empty(result.AgentFindings);
        Assert.Equal(2, result.RuleResults.Count);

        var suppressedResult = result.RuleResults.First(r => r.RuleId == "TEST-001");
        Assert.Equal(RuleStatus.Suppressed, suppressedResult.Status);
        Assert.False(suppressedResult.Passed);
    }

    [Fact]
    public async Task RunAuditAsync_StatusDefaultsFromPassed_WhenNotExplicitlySet()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysPassRule() },
            new ExplanationProvider());

        var result = await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        var passResult = result.RuleResults.First(r => r.RuleId == "TEST-002");
        Assert.Equal(RuleStatus.Passed, passResult.Status);
        Assert.True(passResult.Passed);
    }

    [Fact]
    public async Task RunAuditAsync_DisabledRule_SkipsRule()
    {
        var policyStore = new InMemoryRulePolicyStore();
        policyStore.SetPolicy("TEST-001", MachineRole.Server, new RulePolicy { Enabled = false });
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            machineRole: MachineRole.Server,
            policyProvider: policyStore);

        var result = await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        Assert.Empty(result.AgentFindings);
        Assert.Equal(1, result.PassedCount);
        Assert.Equal(0, result.FailedCount);
    }

    [Fact]
    public async Task RunAuditAsync_AutoPassRule_ConvertsFailureToPass()
    {
        var policyStore = new InMemoryRulePolicyStore();
        policyStore.SetPolicy("TEST-001", MachineRole.Server, new RulePolicy { AutoPass = true });
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            machineRole: MachineRole.Server,
            policyProvider: policyStore);

        var result = await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        Assert.Empty(result.AgentFindings);
        Assert.Equal(1, result.PassedCount);
        Assert.Equal(0, result.FailedCount);
    }

    [Fact]
    public async Task RunAuditAsync_SeverityOverride_UpdatesSeverity()
    {
        var policyStore = new InMemoryRulePolicyStore();
        policyStore.SetPolicy("TEST-001", MachineRole.Server, new RulePolicy { SeverityOverride = Severity.Critical });
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            machineRole: MachineRole.Server,
            policyProvider: policyStore);

        var result = await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        Assert.Single(result.AgentFindings);
        Assert.Equal(Severity.Critical, result.AgentFindings[0].Severity);
    }

    // ─── Follow-up question tests ───

    [Fact]
    public async Task AskAsync_ShowChanges_WithHistory_ReturnsDiff()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        historyStore.Append(new AuditHistoryEntry
        {
            SnapshotId = "prev-001",
            Intent = AgentIntent.FullAudit,
            SnapshotFindings = new[]
            {
                new AuditSnapshotFinding { RuleId = "TEST-002", Target = "old-target", Severity = "Low", ShortDescription = "Old finding" }
            }
        });

        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            historyStore: historyStore);

        // Run audit to populate last result state
        await agent.AskAsync("audit everything", null, CancellationToken.None);

        // Ask follow-up
        var result = await agent.AskAsync("what changed since the last audit", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ShowChanges, result.Intent);
        Assert.NotNull(result.AuditDiff);
        Assert.NotEmpty(result.Summary);
    }

    [Fact]
    public async Task AskAsync_ShowChanges_WithoutHistory_ReturnsGuidance()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        // Run audit to populate last result state
        await agent.AskAsync("audit everything", null, CancellationToken.None);

        var result = await agent.AskAsync("what changed since the last audit", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ShowChanges, result.Intent);
        Assert.Contains("No audit history available", result.Summary);
    }

    [Fact]
    public async Task AskAsync_ShowChanges_WithoutContext_ReturnsGuidance()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        var result = await agent.AskAsync("what changed since the last audit", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ShowChanges, result.Intent);
        Assert.Contains("Run an audit first", result.Summary);
    }

    [Fact]
    public async Task AskAsync_ExplainCritical_AfterAudit_ReturnsCriticalHigh()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailCriticalRule(), new AlwaysFailHighRule(), new AlwaysFailRule() },
            new ExplanationProvider());

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        var result = await agent.AskAsync("why is this critical", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainCritical, result.Intent);
        Assert.Equal(2, result.AgentFindings.Count);
        Assert.All(result.AgentFindings, f => Assert.True(f.Severity >= Severity.High));
        Assert.Contains("Critical / High Findings", result.Summary);
    }

    [Fact]
    public async Task AskAsync_ExplainCritical_NoCriticalHigh_ReturnsMessage()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        var result = await agent.AskAsync("why is this critical", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainCritical, result.Intent);
        Assert.Empty(result.AgentFindings);
        Assert.Contains("No Critical or High findings", result.Summary);
    }

    [Fact]
    public async Task AskAsync_ExplainCritical_WithoutContext_ReturnsGuidance()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        var result = await agent.AskAsync("why is this critical", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainCritical, result.Intent);
        Assert.Contains("Run an audit first", result.Summary);
    }

    [Fact]
    public async Task AskAsync_FilterCategory_AfterAudit_ReturnsFiltered()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule(), new AlwaysPassRule() },
            new ExplanationProvider());

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        var result = await agent.AskAsync("show only firewall issues", null, CancellationToken.None);

        Assert.Equal(AgentIntent.FilterCategory, result.Intent);
        Assert.All(result.AgentFindings, f => Assert.Equal("Firewall", f.Category));
        Assert.Contains("firewall", result.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AskAsync_FilterCategory_WithoutContext_FallsBackToAudit()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        var result = await agent.AskAsync("show only firewall issues", null, CancellationToken.None);

        // Fallback runs a firewall audit but reports intent as FilterCategory
        Assert.Equal(AgentIntent.FilterCategory, result.Intent);
        Assert.NotNull(result.AgentFindings);
    }

    [Fact]
    public async Task AskAsync_FilterCategory_Fallback_DoesNotOverwriteLastResult()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            historyStore: historyStore);

        // Fallback filter with no prior audit
        var filterResult = await agent.AskAsync("show only firewall issues", null, CancellationToken.None);
        Assert.Equal(AgentIntent.FilterCategory, filterResult.Intent);

        // A subsequent ShowChanges should still report "no previous audit",
        // proving the fallback RunAuditAsync didn't corrupt last result state.
        var changesResult = await agent.AskAsync("what changed since the last audit", null, CancellationToken.None);
        Assert.Equal(AgentIntent.ShowChanges, changesResult.Intent);
        Assert.Contains("No previous audit", changesResult.Summary);
    }

    [Fact]
    public async Task AskAsync_PrioritizeRemediation_AfterAudit_ReturnsPlan()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailCriticalRule(), new AlwaysFailRule() },
            new ExplanationProvider());

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        var result = await agent.AskAsync("what should I fix first", null, CancellationToken.None);

        Assert.Equal(AgentIntent.PrioritizeRemediation, result.Intent);
        Assert.NotNull(result.RemediationPlan);
        Assert.Contains("Remediation Plan", result.Summary);
        Assert.Equal(Severity.Critical, result.AgentFindings[0].Severity);
    }

    [Fact]
    public async Task AskAsync_PrioritizeRemediation_WithoutContext_ReturnsGuidance()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        var result = await agent.AskAsync("what should I fix first", null, CancellationToken.None);

        Assert.Equal(AgentIntent.PrioritizeRemediation, result.Intent);
        Assert.Contains("Run an audit first", result.Summary);
    }

    // ─── Interactive Remediation (FixFinding) tests ───

    [Fact]
    public async Task AskAsync_FixFinding_WithoutContext_ReturnsGuidance()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        var result = await agent.AskAsync("fix FW-001", null, CancellationToken.None);

        Assert.Equal(AgentIntent.FixFinding, result.Intent);
        Assert.Contains("Run an audit first", result.Summary);
    }

    [Fact]
    public async Task AskAsync_FixFinding_WithoutReference_ReturnsGuidance()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        var result = await agent.AskAsync("remediate", null, CancellationToken.None);

        Assert.Equal(AgentIntent.FixFinding, result.Intent);
        Assert.Contains("specify which finding", result.Summary);
    }

    [Fact]
    public async Task AskAsync_FixFinding_WithUnknownReference_ReturnsGuidance()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        var result = await agent.AskAsync("fix UNKNOWN-999", null, CancellationToken.None);

        Assert.Equal(AgentIntent.FixFinding, result.Intent);
        Assert.Contains("couldn't find finding", result.Summary);
    }

    [Fact]
    public async Task AskAsync_FixFinding_AfterAudit_ReturnsRemediationPlan()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        var auditResult = await agent.AskAsync("audit everything", null, CancellationToken.None);
        Assert.Single(auditResult.AgentFindings);

        var result = await agent.AskAsync("fix TEST-001", null, CancellationToken.None);

        Assert.Equal(AgentIntent.FixFinding, result.Intent);
        Assert.NotNull(result.RemediationPlan);
        Assert.Single(result.RemediationPlan.Sections);
        Assert.Contains("Interactive Remediation", result.Summary);
        Assert.Single(result.AgentFindings);
    }

    [Fact]
    public async Task AskAsync_FixFinding_ValidationFailure_ReturnsBlockedMessage()
    {
        // Use a custom explanation provider that yields a risky command without rollback guidance
        var riskyProvider = new CustomExplanationProvider(
            "**Suggested next action:**\n1. Run this: `sudo rm -rf /`\n\n**Risk level:** CRITICAL");

        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            riskyProvider);

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        var result = await agent.AskAsync("fix TEST-001", null, CancellationToken.None);

        Assert.Equal(AgentIntent.FixFinding, result.Intent);
        Assert.NotNull(result.RemediationPlan);
        Assert.Contains("blocked for safety", result.Summary);
        Assert.NotEmpty(result.Warnings);
    }

    private sealed class CustomExplanationProvider(string markdown) : IExplanationProvider
    {
        public string GetExplanation(string key, IReadOnlyDictionary<string, string> variables) => markdown;

        public StructuredExplanation GetStructuredExplanation(string key, IReadOnlyDictionary<string, string> variables)
            => ParseStructuredFromText(markdown);

        public StructuredExplanation ParseStructuredFromText(string text)
        {
            var sections = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var lines = text.Split('\n');
            string? currentKey = null;
            var currentLines = new List<string>();

            foreach (var rawLine in lines)
            {
                var line = rawLine.TrimEnd();
                if (line.StartsWith("**") && line.Contains(":**"))
                {
                    var headerEnd = line.IndexOf(":**");
                    var key = line.Substring(2, headerEnd - 2).Trim();
                    if (currentKey != null)
                        sections[currentKey] = string.Join("\n", currentLines).Trim();
                    currentKey = key;
                    currentLines.Clear();
                    var remainder = line.Substring(headerEnd + 3).TrimStart();
                    if (!string.IsNullOrEmpty(remainder))
                        currentLines.Add(remainder);
                }
                else if (currentKey != null)
                {
                    currentLines.Add(line);
                }
            }

            if (currentKey != null)
                sections[currentKey] = string.Join("\n", currentLines).Trim();

            return new StructuredExplanation
            {
                WhatWasFound = GetSection(sections, "What we found"),
                WhyItMatters = GetSection(sections, "Why this matters"),
                HowToVerify = GetSection(sections, "How to verify"),
                SuggestedNextAction = GetSection(sections, "Suggested next action"),
                Preconditions = GetSection(sections, "Preconditions"),
                BackupCommands = GetSection(sections, "Backup commands"),
                RollbackCommands = GetSection(sections, "Rollback commands"),
                Confidence = GetSection(sections, "Risk level", "Confidence"),
                Caveats = GetSection(sections, "Caveats")
            };
        }

        private static string GetSection(Dictionary<string, string> sections, params string[] keys)
        {
            foreach (var key in keys)
                if (sections.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
                    return value;
            return string.Empty;
        }
    }

    [Fact]
    public async Task AskAsync_ListSuppressed_AfterAudit_ReturnsSuppressed()
    {
        var suppressionStore = new InMemorySuppressionStore();
        suppressionStore.Add(new SuppressionEntry { RuleId = "TEST-001", Target = "test-target" });
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            suppressionStore: suppressionStore);

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        var result = await agent.AskAsync("which findings are suppressed", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ListSuppressed, result.Intent);
        Assert.Contains("Suppressed Findings", result.Summary);
        Assert.Contains("TEST-001", result.Summary);
    }

    [Fact]
    public async Task AskAsync_ListSuppressed_NoneSuppressed_ReturnsMessage()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        var result = await agent.AskAsync("which findings are suppressed", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ListSuppressed, result.Intent);
        Assert.Contains("No findings were suppressed", result.Summary);
    }

    [Fact]
    public async Task AskAsync_ListSuppressed_WithoutContext_ReturnsGuidance()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        var result = await agent.AskAsync("which findings are suppressed", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ListSuppressed, result.Intent);
        Assert.Contains("Run an audit first", result.Summary);
    }

    [Fact]
    public async Task AskAsync_ShowChanges_WhenHistoryContainsCurrentAudit_SkipsToPrevious()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            historyStore: historyStore);

        // Simulate UI flow: run audit, then append to history (as AgentViewModel does)
        var audit1 = await agent.AskAsync("audit everything", null, CancellationToken.None);
        historyStore.Append(new AuditHistoryEntry
        {
            SnapshotId = "snap-1",
            TimestampUtc = audit1.UtcTimestamp,
            Intent = audit1.Intent,
            SnapshotFindings = audit1.AgentFindings.Select(f => new AuditSnapshotFinding
            {
                RuleId = f.RuleId ?? "",
                Target = f.Target,
                Severity = f.Severity.ToString(),
                ShortDescription = f.ShortDescription,
                Fingerprint = f.Fingerprint
            }).ToList()
        });

        // Run second audit
        var audit2 = await agent.AskAsync("audit everything", null, CancellationToken.None);
        historyStore.Append(new AuditHistoryEntry
        {
            SnapshotId = "snap-2",
            TimestampUtc = audit2.UtcTimestamp,
            Intent = audit2.Intent,
            SnapshotFindings = audit2.AgentFindings.Select(f => new AuditSnapshotFinding
            {
                RuleId = f.RuleId ?? "",
                Target = f.Target,
                Severity = f.Severity.ToString(),
                ShortDescription = f.ShortDescription,
                Fingerprint = f.Fingerprint
            }).ToList()
        });

        // Ask what changed — should compare audit2 against audit1, not against itself
        var result = await agent.AskAsync("what changed since the last audit", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ShowChanges, result.Intent);
        Assert.NotNull(result.AuditDiff);
        // Since both audits are identical, there should be no new or resolved findings
        Assert.Equal("No changes between audits.", result.AuditDiff.Narrative);
    }

    [Fact]
    public async Task AskAsync_FilterCategory_AfterSingleRuleExplain_ReturnsFullAuditFilter()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule(), new AlwaysPassRule() },
            new ExplanationProvider());

        // Run full audit first
        await agent.AskAsync("audit everything", null, CancellationToken.None);

        // Explain a single rule by ID (triggers RunSingleRuleAsync)
        var explainResult = await agent.AskAsync("explain TEST-001", null, CancellationToken.None);
        Assert.Equal(AgentIntent.ExplainFinding, explainResult.Intent);

        // Follow-up filter should still operate on the last full audit, not the single-rule result
        var filterResult = await agent.AskAsync("show only firewall issues", null, CancellationToken.None);
        Assert.Equal(AgentIntent.FilterCategory, filterResult.Intent);
        Assert.All(filterResult.AgentFindings, f => Assert.Equal("Firewall", f.Category));
    }

    // ─── Baseline & drift tests ───

    [Fact]
    public async Task AskAsync_SetBaseline_AfterAudit_SavesBaseline()
    {
        var baselineStore = new InMemoryBaselineStore();
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            baselineStore: baselineStore);

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        var result = await agent.AskAsync("set baseline", null, CancellationToken.None);

        Assert.Equal(AgentIntent.SetBaseline, result.Intent);
        Assert.NotNull(result.Baseline);
        Assert.Single(baselineStore.GetAll());
        Assert.True(baselineStore.GetActive(AgentIntent.FullAudit)!.IsActive);
        Assert.Contains("saved", result.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AskAsync_SetBaseline_WithoutAudit_ReturnsGuidance()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        var result = await agent.AskAsync("set baseline", null, CancellationToken.None);

        Assert.Equal(AgentIntent.SetBaseline, result.Intent);
        Assert.Contains("Run an audit first", result.Summary);
    }

    [Fact]
    public async Task AskAsync_CheckDrift_WithBaseline_ReturnsDiff()
    {
        var baselineStore = new InMemoryBaselineStore();
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            baselineStore: baselineStore);

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        await agent.AskAsync("set baseline", null, CancellationToken.None);

        var result = await agent.AskAsync("check drift", null, CancellationToken.None);

        Assert.Equal(AgentIntent.CheckDrift, result.Intent);
        Assert.NotNull(result.BaselineDiff);
        Assert.Contains("No drift detected", result.BaselineDiff.Narrative);
    }

    [Fact]
    public async Task AskAsync_CheckDrift_WithoutBaseline_ReturnsGuidance()
    {
        var baselineStore = new InMemoryBaselineStore();
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            baselineStore: baselineStore);

        var result = await agent.AskAsync("check drift", null, CancellationToken.None);

        Assert.Equal(AgentIntent.CheckDrift, result.Intent);
        Assert.Contains("No baseline set", result.Summary);
    }

    [Fact]
    public async Task AskAsync_CheckDrift_WhenDriftDetected_ReturnsDriftFindings()
    {
        var baselineStore = new InMemoryBaselineStore();
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            baselineStore: baselineStore);

        // First audit with AlwaysFailRule => 1 finding
        await agent.AskAsync("audit everything", null, CancellationToken.None);
        await agent.AskAsync("set baseline", null, CancellationToken.None);

        // Now swap to AlwaysFailCriticalRule => drift (new finding, different rule ID)
        var agent2 = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailCriticalRule() },
            new ExplanationProvider(),
            baselineStore: baselineStore);

        var result = await agent2.AskAsync("check drift", null, CancellationToken.None);

        Assert.Equal(AgentIntent.CheckDrift, result.Intent);
        Assert.NotNull(result.BaselineDiff);
        Assert.True(result.BaselineDiff.HasDrift);
        Assert.NotEmpty(result.AgentFindings);
    }

    [Fact]
    public async Task AskAsync_ShowBaseline_WithBaseline_ReturnsBaseline()
    {
        var baselineStore = new InMemoryBaselineStore();
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            baselineStore: baselineStore);

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        await agent.AskAsync("set baseline", null, CancellationToken.None);

        var result = await agent.AskAsync("show baseline", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ShowBaseline, result.Intent);
        Assert.NotNull(result.Baseline);
        Assert.Single(result.AgentFindings);
    }

    [Fact]
    public async Task AskAsync_ShowBaseline_WithoutBaseline_ReturnsGuidance()
    {
        var baselineStore = new InMemoryBaselineStore();
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            baselineStore: baselineStore);

        var result = await agent.AskAsync("show baseline", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ShowBaseline, result.Intent);
        Assert.Contains("No baseline set", result.Summary);
    }

    [Fact]
    public async Task SetBaselineAsync_SetsBaselineWithCustomName()
    {
        var baselineStore = new InMemoryBaselineStore();
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            baselineStore: baselineStore);

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        var result = await agent.SetBaselineAsync("MyBaseline", "Description", CancellationToken.None);

        Assert.Equal(AgentIntent.SetBaseline, result.Intent);
        Assert.NotNull(result.Baseline);
        Assert.Equal("MyBaseline", result.Baseline.Name);
    }

    [Fact]
    public async Task CheckDriftAsync_WithoutBaseline_ReturnsGuidance()
    {
        var baselineStore = new InMemoryBaselineStore();
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            baselineStore: baselineStore);

        var result = await agent.CheckDriftAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        Assert.Equal(AgentIntent.CheckDrift, result.Intent);
        Assert.Contains("No baseline set", result.Summary);
    }

    [Fact]
    public async Task GetBaselineAsync_WithoutBaseline_ReturnsGuidance()
    {
        var baselineStore = new InMemoryBaselineStore();
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            baselineStore: baselineStore);

        var result = await agent.GetBaselineAsync(AgentIntent.FullAudit, CancellationToken.None);

        Assert.Equal(AgentIntent.ShowBaseline, result.Intent);
        Assert.Contains("No baseline set", result.Summary);
    }

    [Fact]
    public async Task CheckDriftAsync_WithBaseline_ReturnsDiff()
    {
        var baselineStore = new InMemoryBaselineStore();
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            baselineStore: baselineStore);

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        await agent.SetBaselineAsync("TestBaseline", null, CancellationToken.None);

        var result = await agent.CheckDriftAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        Assert.Equal(AgentIntent.CheckDrift, result.Intent);
        Assert.NotNull(result.BaselineDiff);
        Assert.Contains("No drift detected", result.BaselineDiff.Narrative);
    }

    [Fact]
    public async Task GetBaselineAsync_WithBaseline_ReturnsBaseline()
    {
        var baselineStore = new InMemoryBaselineStore();
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            baselineStore: baselineStore);

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        await agent.SetBaselineAsync("TestBaseline", null, CancellationToken.None);

        var result = await agent.GetBaselineAsync(AgentIntent.FullAudit, CancellationToken.None);

        Assert.Equal(AgentIntent.ShowBaseline, result.Intent);
        Assert.NotNull(result.Baseline);
        Assert.Equal("TestBaseline", result.Baseline.Name);
        Assert.Single(result.AgentFindings);
    }

    [Fact]
    public async Task CheckDriftAsync_PreservesLastResult()
    {
        var baselineStore = new InMemoryBaselineStore();
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            baselineStore: baselineStore);

        var auditResult = await agent.AskAsync("audit everything", null, CancellationToken.None);
        await agent.SetBaselineAsync("TestBaseline", null, CancellationToken.None);

        var driftResult = await agent.CheckDriftAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        // After drift check, a follow-up ShowChanges should still work against the original audit
        var changesResult = await agent.AskAsync("what changed since the last audit", null, CancellationToken.None);
        Assert.Equal(AgentIntent.ShowChanges, changesResult.Intent);
    }

    [Fact]
    public async Task ShowBaseline_PreservesOriginalFindingFields()
    {
        var baselineStore = new InMemoryBaselineStore();
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            baselineStore: baselineStore);

        var auditResult = await agent.AskAsync("audit everything", null, CancellationToken.None);
        var originalFinding = auditResult.AgentFindings[0];
        await agent.SetBaselineAsync("TestBaseline", null, CancellationToken.None);

        var result = await agent.GetBaselineAsync(AgentIntent.FullAudit, CancellationToken.None);

        Assert.Equal(AgentIntent.ShowBaseline, result.Intent);
        Assert.Single(result.AgentFindings);

        var reconstructed = result.AgentFindings[0];
        Assert.Equal(originalFinding.RuleId, reconstructed.RuleId);
        Assert.Equal(originalFinding.Category, reconstructed.Category);
        Assert.Equal(originalFinding.Severity, reconstructed.Severity);
        Assert.Equal(originalFinding.Target, reconstructed.Target);
        Assert.Equal(originalFinding.ShortDescription, reconstructed.ShortDescription);
        Assert.Equal(originalFinding.Fingerprint, reconstructed.Fingerprint);
        Assert.Equal(originalFinding.SourceHost, reconstructed.SourceHost);
        // Details should be original plus baseline annotation
        Assert.Contains(originalFinding.Details, reconstructed.Details);
        Assert.Contains("TestBaseline", reconstructed.Details);
    }

    [Fact]
    public async Task SetBaseline_AfterCheckDrift_UsesAuditIntent_NotCheckDrift()
    {
        var baselineStore = new InMemoryBaselineStore();
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            baselineStore: baselineStore);

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        var driftResult = await agent.AskAsync("check drift", null, CancellationToken.None);
        Assert.Equal(AgentIntent.CheckDrift, driftResult.Intent);

        var baselineResult = await agent.AskAsync("set baseline", null, CancellationToken.None);
        Assert.Equal(AgentIntent.SetBaseline, baselineResult.Intent);
        Assert.NotNull(baselineResult.Baseline);
        Assert.Equal(AgentIntent.FullAudit, baselineResult.Baseline.Intent);

        // A subsequent drift check for FullAudit should find this baseline
        var driftResult2 = await agent.CheckDriftAsync(AgentIntent.FullAudit, null, CancellationToken.None);
        Assert.Contains("No drift detected", driftResult2.BaselineDiff!.Narrative);
    }

    [Fact]
    public async Task CheckDriftAsync_WorsenedSeverity_Detected()
    {
        var baselineStore = new InMemoryBaselineStore();
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            baselineStore: baselineStore);

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        await agent.SetBaselineAsync("TestBaseline", null, CancellationToken.None);

        // Same rule ID, but severity escalated via policy override
        var policyStore = new InMemoryRulePolicyStore();
        policyStore.SetPolicy("TEST-001", MachineRole.Server, new RulePolicy { SeverityOverride = Severity.Critical });
        var agent2 = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            baselineStore: baselineStore,
            machineRole: MachineRole.Server,
            policyProvider: policyStore);

        var result = await agent2.CheckDriftAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        Assert.Equal(AgentIntent.CheckDrift, result.Intent);
        Assert.NotNull(result.BaselineDiff);
        Assert.True(result.BaselineDiff.HasDrift);
        Assert.Single(result.BaselineDiff.Diff.WorsenedFindings);
    }

    // =====================================================================
    // CIS Benchmark Mapping flow-through tests
    // =====================================================================

    [Fact]
    public async Task RunSingleRuleAsync_FindingIncludesCisMappings()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        var result = await agent.AskAsync("explain TEST-001", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Single(result.AgentFindings);
        Assert.NotEmpty(result.AgentFindings[0].CisMappings);
        Assert.Contains(result.AgentFindings[0].CisMappings, m => m.ControlId == "CIS 4.5");
        Assert.Contains(result.AgentFindings[0].CisMappings, m => m.BenchmarkReference == "CIS Ubuntu 24.04 LTS 3.5.1.3 — Ensure default deny firewall policy");
    }

    [Fact]
    public async Task RunAuditAsync_CrashedRule_CisMappingsFlowThrough()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysCrashRule() },
            new ExplanationProvider());

        var result = await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        Assert.Equal(1, result.CrashedCount);
        var crashResult = result.RuleResults.First(r => r.Status == RuleStatus.Crashed);
        Assert.NotEmpty(crashResult.CisMappings);
        Assert.Contains(crashResult.CisMappings, m => m.ControlId == "CIS 4.1");
    }

    [Fact]
    public async Task RunAuditAsync_PolicyDisabledRule_CisMappingsFlowThrough()
    {
        var policyStore = new InMemoryRulePolicyStore();
        policyStore.SetPolicy("TEST-001", MachineRole.Server, new RulePolicy { Enabled = false });
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            machineRole: MachineRole.Server,
            policyProvider: policyStore);

        var result = await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        var disabledResult = result.RuleResults.First(r => r.Status == RuleStatus.Passed);
        Assert.NotEmpty(disabledResult.CisMappings);
        Assert.Contains(disabledResult.CisMappings, m => m.ControlId == "CIS 4.5");
    }

    [Fact]
    public async Task RunAuditAsync_ContextualRule_CisMappingsFlowThrough()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailContextualRule() },
            new ExplanationProvider(),
            machineRole: MachineRole.Server);

        var result = await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        Assert.Single(result.RuleResults);
        Assert.False(result.RuleResults[0].Passed);
        Assert.NotEmpty(result.RuleResults[0].CisMappings);
        Assert.Contains(result.RuleResults[0].CisMappings, m => m.ControlId == "CIS 4.8");
        Assert.Contains(result.RuleResults[0].CisMappings, m => m.BenchmarkReference == "CIS Ubuntu 24.04 LTS 5.2.12 — Ensure SSH X11 forwarding is disabled");
    }

    private sealed class AlwaysFailContextualRule : IRule, IContextualRule
    {
        public string Id => "TEST-006";
        public string Category => "SSH";
        public string Description => "Test contextual rule that always fails";
        public string WhatItChecks => "Test contextual fail";
        public IReadOnlyList<string> SupportedDataSources => new[] { "test" };
        public Severity Severity => Severity.Medium;

        public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
        {
            new CisBenchmarkMapping
            {
                ControlId = "CIS 4.8",
                ControlName = "Uninstall or Disable Unnecessary Services",
                WhyItMatters = "Test contextual mapping.",
                BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.2.12 — Ensure SSH X11 forwarding is disabled"
            }
        };

        public RuleResult Evaluate(ScanData data)
            => Evaluate(data, new RuleEvaluationContext(MachineRole.Server, null));

        public RuleResult Evaluate(ScanData data, RuleEvaluationContext context)
        {
            return RuleResult.Fail(Id, Category, Id, Description, Severity.Medium, "test-target", cisMappings: CisMappings);
        }
    }

    private sealed class AlwaysFailCriticalRule : IRule
    {
        public string Id => "TEST-004";
        public string Category => "Firewall";
        public string Description => "Test critical finding";
        public string WhatItChecks => "Test rule that always fails critically";
        public IReadOnlyList<string> SupportedDataSources => new[] { "test" };
        public Severity Severity => Severity.Critical;

        public RuleResult Evaluate(ScanData data)
        {
            return RuleResult.Fail(Id, Category, Id, Description, Severity.Critical, "critical-target");
        }
    }

    [Fact]
    public async Task AskAsync_RiskScore_AfterAudit_ReturnsScorecard()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailCriticalRule(), new AlwaysFailRule() },
            new ExplanationProvider());

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        var result = await agent.AskAsync("what's my risk grade", null, CancellationToken.None);

        Assert.Equal(AgentIntent.RiskScore, result.Intent);
        Assert.NotNull(result.RiskScorecard);
        Assert.Contains("Risk Grade:", result.Summary);
    }

    [Fact]
    public async Task AskAsync_RiskScore_WithoutContext_ReturnsGuidance()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        var result = await agent.AskAsync("show risk score", null, CancellationToken.None);

        Assert.Equal(AgentIntent.RiskScore, result.Intent);
        Assert.Contains("Run an audit first", result.Summary);
    }

    private sealed class AlwaysFailHighRule : IRule
    {
        public string Id => "TEST-005";
        public string Category => "Port";
        public string Description => "Test high finding";
        public string WhatItChecks => "Test rule that always fails with high severity";
        public IReadOnlyList<string> SupportedDataSources => new[] { "test" };
        public Severity Severity => Severity.High;

        public RuleResult Evaluate(ScanData data)
        {
            return RuleResult.Fail(Id, Category, Id, Description, Severity.High, "high-target");
        }
    }
}
