using VulcansTrace.Linux.Agent.Baselines;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Notifications;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Rules.SecurityRules;
using VulcansTrace.Linux.Agent.Scheduling;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Logging;
using VulcansTrace.Linux.Core.Security;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Evidence;
using VulcansTrace.Linux.Evidence.Formatters;

namespace VulcansTrace.Linux.Agent;

/// <summary>
/// Provides a fully wired set of agent services for headless or UI consumption.
/// Centralizes the composition logic that was previously duplicated in Avalonia's MainWindow.
/// </summary>
public static class AgentFactory
{
    /// <summary>
    /// Creates and returns all core agent services with their default implementations.
    /// </summary>
    /// <param name="machineRole">The machine role to use for rule tuning. Defaults to <see cref="MachineRole.Workstation"/>.</param>
    /// <returns>A record containing all wired services.</returns>
    public static AgentServices Create(MachineRole machineRole = MachineRole.Workstation)
    {
        var logSink = new DiagnosticsLogSink();
        var logNormalizer = new LogNormalizer(logSink);
        var profileProvider = new AnalysisProfileProvider();

        var baselineDetectors = new IDetector[]
        {
            new PortScanDetector(),
            new FloodDetector(),
            new LateralMovementDetector(),
            new BeaconingDetector(),
            new PolicyViolationDetector(),
            new NoveltyDetector()
        };

        var linuxDetectors = new IDetector[]
        {
            new FlagAnomalyDetector(),
            new MacSpoofingDetector(),
            new KernelModuleDetector(),
            new InterfaceHoppingDetector(),
            new UnusualPacketSizeDetector()
        };

        var advancedDetectors = new IDetector[]
        {
            new C2ChannelDetector(),
            new PrivilegeEscalationDetector()
        };

        var riskEscalator = new RiskEscalator();
        var analyzer = new SentryAnalyzer(logNormalizer, profileProvider, baselineDetectors, linuxDetectors, advancedDetectors, riskEscalator, logSink);

        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var jsonFormatter = new JsonFormatter();
        var stixFormatter = new StixFormatter();
        var scorecardHtmlFormatter = new ComplianceScorecardHtmlFormatter();
        var scorecardMarkdownFormatter = new ComplianceScorecardMarkdownFormatter();
        var riskScorecardHtmlFormatter = new RiskScorecardHtmlFormatter();
        var riskScorecardMarkdownFormatter = new RiskScorecardMarkdownFormatter();
        var evidenceBuilder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter, jsonFormatter, stixFormatter, scorecardHtmlFormatter, scorecardMarkdownFormatter, riskScorecardHtmlFormatter, riskScorecardMarkdownFormatter);

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

        ISuppressionStore suppressionStore;
        try
        {
            suppressionStore = JsonFileSuppressionStore.CreateDefault();
        }
        catch
        {
            suppressionStore = new InMemorySuppressionStore("Suppression persistence is unavailable. Accepted risks will last only for this session.");
        }

        IRulePolicyProvider? policyProvider;
        try
        {
            var jsonPolicyStore = JsonRulePolicyStore.CreateDefault();
            policyProvider = new DefaultRulePolicyProvider(jsonPolicyStore);
        }
        catch
        {
            policyProvider = new DefaultRulePolicyProvider();
        }

        IAuditHistoryStore auditHistoryStore;
        try
        {
            auditHistoryStore = JsonFileAuditHistoryStore.CreateDefault();
        }
        catch
        {
            auditHistoryStore = new InMemoryAuditHistoryStore("Audit history persistence is unavailable. History will last only for this session.");
        }

        IBaselineStore baselineStore;
        try
        {
            baselineStore = JsonFileBaselineStore.CreateDefault();
        }
        catch
        {
            baselineStore = new InMemoryBaselineStore("Baseline persistence is unavailable. Baselines will last only for this session.");
        }

        IScheduleStore scheduleStore;
        try
        {
            scheduleStore = JsonFileScheduleStore.CreateDefault();
        }
        catch
        {
            scheduleStore = new InMemoryScheduleStore("Schedule persistence is unavailable. Schedules will last only for this session.");
        }

        ISessionStore sessionStore;
        try
        {
            sessionStore = JsonFileSessionStore.CreateDefault();
        }
        catch
        {
            sessionStore = new InMemorySessionStore("Remediation session persistence is unavailable. Sessions will last only for this session.");
        }

        var scorecardBuilder = new ComplianceScorecardBuilder();
        var riskScorecardBuilder = new RiskScorecardBuilder();

        var agent = new SecurityAgent(
            scanners,
            rules,
            explanationProvider,
            analyzer,
            profileProvider,
            suppressionStore,
            machineRole,
            policyProvider,
            auditHistoryStore,
            baselineStore,
            scorecardBuilder,
            riskScorecardBuilder,
            sessionStore);

        var ruleCatalog = new RuleCatalog(rules);
        var notificationService = new NotifySendNotificationService();
        var processRunner = new ProcessRunner();
        var remediationExecutor = new RemediationExecutor(processRunner);
        var remediationPlanBuilder = new RemediationPlanBuilder(explanationProvider);

        return new AgentServices
        {
            Agent = agent,
            Analyzer = analyzer,
            EvidenceBuilder = evidenceBuilder,
            RuleCatalog = ruleCatalog,
            SuppressionStore = suppressionStore,
            AuditHistoryStore = auditHistoryStore,
            BaselineStore = baselineStore,
            PolicyProvider = policyProvider,
            ProfileProvider = profileProvider,
            ScheduleStore = scheduleStore,
            NotificationService = notificationService,
            ProcessRunner = processRunner,
            RemediationExecutor = remediationExecutor,
            RemediationPlanBuilder = remediationPlanBuilder,
            SessionStore = sessionStore
        };
    }
}

/// <summary>
/// Container for all wired agent services produced by <see cref="AgentFactory"/>.
/// </summary>
public sealed record AgentServices : IDisposable
{
    private bool _disposed;
    /// <summary>The primary agent implementation.</summary>
    public required IAgent Agent { get; init; }

    /// <summary>The SentryAnalyzer for log-based threat detection.</summary>
    public required SentryAnalyzer Analyzer { get; init; }

    /// <summary>The evidence builder for exporting results.</summary>
    public required EvidenceBuilder EvidenceBuilder { get; init; }

    /// <summary>Browsable catalog of security rules.</summary>
    public required RuleCatalog RuleCatalog { get; init; }

    /// <summary>Store for suppressed findings.</summary>
    public required ISuppressionStore SuppressionStore { get; init; }

    /// <summary>Store for audit history snapshots.</summary>
    public required IAuditHistoryStore AuditHistoryStore { get; init; }

    /// <summary>Store for configuration baselines.</summary>
    public required IBaselineStore BaselineStore { get; init; }

    /// <summary>Provider for per-role rule policies.</summary>
    public required IRulePolicyProvider PolicyProvider { get; init; }

    /// <summary>Provider for analysis intensity profiles.</summary>
    public required AnalysisProfileProvider ProfileProvider { get; init; }

    /// <summary>Store for recurring audit schedules.</summary>
    public required IScheduleStore ScheduleStore { get; init; }

    /// <summary>Service for out-of-band notifications.</summary>
    public required INotificationService NotificationService { get; init; }

    /// <summary>Process runner for executing shell commands.</summary>
    public required IProcessRunner ProcessRunner { get; init; }

    /// <summary>Orchestrates remediation plan execution.</summary>
    public required RemediationExecutor RemediationExecutor { get; init; }

    /// <summary>Builds remediation plans from findings.</summary>
    public required RemediationPlanBuilder RemediationPlanBuilder { get; init; }

    /// <summary>Store for remediation sessions.</summary>
    public required ISessionStore SessionStore { get; init; }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        (SuppressionStore as IDisposable)?.Dispose();
        (AuditHistoryStore as IDisposable)?.Dispose();
        (BaselineStore as IDisposable)?.Dispose();
        (PolicyProvider as IDisposable)?.Dispose();
        (ScheduleStore as IDisposable)?.Dispose();
        (NotificationService as IDisposable)?.Dispose();
        (ProcessRunner as IDisposable)?.Dispose();
        (SessionStore as IDisposable)?.Dispose();
    }
}
