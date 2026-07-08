using VulcansTrace.Linux.Agent.Actions;
using VulcansTrace.Linux.Agent.Baselines;
using VulcansTrace.Linux.Agent.Diagnostics;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Findings;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Messages;
using VulcansTrace.Linux.Agent.Notifications;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Rules.SecurityRules;
using VulcansTrace.Linux.Agent.Rules.SecurityRules.ThreatIntel;
using VulcansTrace.Linux.Agent.Scheduling;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Logging;
using VulcansTrace.Linux.Core.Security;
using VulcansTrace.Linux.Core.ThreatIntel;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Engine.Live;
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
    /// <param name="configDirectory">
    /// Optional explicit base config directory for the file-backed stores. When null (the default)
    /// stores resolve from XDG_CONFIG_HOME or ~/.config. Tests pass a unique temp dir here so they
    /// never touch the operator's real config or the process-wide environment variable.
    /// </param>
    /// <returns>A record containing all wired services.</returns>
    public static AgentServices Create(MachineRole machineRole = MachineRole.Workstation, string? configDirectory = null)
    {
        var logSink = new DiagnosticsLogSink();
        var logNormalizer = new LogNormalizer(logSink);
        var profileProvider = new AnalysisProfileProvider();

        IThreatIntelStore threatIntelStore;
        try
        {
            threatIntelStore = JsonFileThreatIntelStore.CreateDefault(configDirectory, logSink);
        }
        catch
        {
            threatIntelStore = new InMemoryThreatIntelStore("Threat intel persistence is unavailable. IOCs will last only for this session.");
        }

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
            new PrivilegeEscalationDetector(),
            new ThreatIntelDetector(threatIntelStore)
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
        var traceMapMarkdownFormatter = new TraceMapMarkdownFormatter();
        var traceMapJsonFormatter = new TraceMapJsonFormatter();
        var mitreLayerBuilder = new MitreLayerBuilder();
        var logDiffMarkdownFormatter = new LogDiffMarkdownFormatter();
        var logDiffHtmlFormatter = new LogDiffHtmlFormatter();

        var scanners = new IScanner[]
        {
            new FirewallScanner(),
            new PortScanner(),
            new ServiceScanner(),
            new NetworkScanner(),
            new SshConfigScanner(),
            new FilePermissionScanner(),
            new FilesystemAuditScanner(),
            new FileHashScanner(threatIntelStore),
            new KernelHardeningScanner(),
            new UserAccountScanner(),
            new LoggingAuditScanner(),
            new SudoersScanner(),
            new SystemdTimerSocketScanner(),
            new MacScanner(),
            new BootloaderScanner(),
            new CronJobScanner(),
            new PackageVulnerabilityScanner(),
            new ContainerScanner(),
            new KubernetesScanner(),
            new YaraScanner(
                engine: null,
                customRulesDirectory: Path.Combine(VulcansTraceConfig.GetDirectory(configDirectory), "yara")),
            new ProcessRuntimeScanner()
        };

        var doctorService = new DoctorService(scanners);

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
            new SudoersFilePermissionRule(),
            new SudoersNoPasswordlessFullSudoRule(),
            new SudoersFullSudoRule(),
            new SudoersNoAuthenticateRule(),
            new SudoersSecurePathRule(),
            new SystemdShortTimerIntervalRule(),
            new SystemdPublicSocketRule(),
            new SystemdRedundantSocketServiceRule(),
            new MacFrameworkActiveRule(),
            new MacAppArmorUnconfinedRule(),
            new MacSelinuxEnforcingRule(),
            new BootloaderSecureBootEnabledRule(),
            new NoRescueBootParameterRule(),
            new GrubPasswordSetRule(),
            new KernelModuleLoadRestrictionRule(),
            new SecurityUpdatesAvailableRule(),
            new UnattendedUpgradesEnabledRule(),
            new CriticalCvesPresentRule(),
            new PrivilegedContainerRule(),
            new LatestTagRule(),
            new DockerSocketExposedRule(),
            new ContainerdWeakDefaultsRule(),
            new KnownBadBaseLayerRule(),
            new K8sPrivilegedPodRule(),
            new K8sHostNamespaceRule(),
            new K8sRunAsRootRule(),
            new K8sSecurityContextRule(),
            new ThreatIntelIpRule(threatIntelStore),
            new ThreatIntelPortRule(threatIntelStore),
            new ThreatIntelHashRule(threatIntelStore),
            new YaraMatchRule(),
            new RwxMemoryRegionRule(),
            new LdPreloadInjectionRule(),
            new DeletedBinaryExecutionRule(),
            new OrphanedAnomalousProcessRule(),
            new SuspiciousParentChildRule(),
            new InterpreterRwxMemoryRule()
        };

        var mitreCoverageSources = BuildMitreCoverageSources(
            baselineDetectors.Concat(linuxDetectors).Concat(advancedDetectors),
            rules);
        var evidenceBuilder = new EvidenceBuilder(
            hasher,
            csvFormatter,
            markdownFormatter,
            htmlFormatter,
            jsonFormatter,
            stixFormatter,
            scorecardHtmlFormatter,
            scorecardMarkdownFormatter,
            riskScorecardHtmlFormatter,
            riskScorecardMarkdownFormatter,
            traceMapMarkdownFormatter,
            traceMapJsonFormatter,
            incidentStoryFormatter: new IncidentStoryFormatter(),
            mitreLayerBuilder,
            mitreCoverageSources,
            logDiffMarkdownFormatter,
            logDiffHtmlFormatter,
            new MispFormatter());

        var explanationProvider = new ExplanationProvider();

        ISuppressionStore suppressionStore;
        try
        {
            suppressionStore = JsonFileSuppressionStore.CreateDefault(configDirectory, logSink);
        }
        catch
        {
            suppressionStore = new InMemorySuppressionStore("Suppression persistence is unavailable. Accepted risks will last only for this session.");
        }

        IRulePolicyStore? policyStore = null;
        IRulePolicyProvider? policyProvider;
        try
        {
            var jsonPolicyStore = JsonRulePolicyStore.CreateDefault(configDirectory, logSink);
            policyStore = jsonPolicyStore;
            policyProvider = new DefaultRulePolicyProvider(jsonPolicyStore);
        }
        catch
        {
            policyStore = new InMemoryRulePolicyStore("Rule policy persistence is unavailable. Policy changes will last only for this session.");
            policyProvider = new DefaultRulePolicyProvider(policyStore);
        }

        IAuditHistoryStore auditHistoryStore;
        try
        {
            auditHistoryStore = JsonFileAuditHistoryStore.CreateDefault(configDirectory, logSink: logSink);
        }
        catch
        {
            auditHistoryStore = new InMemoryAuditHistoryStore("Audit history persistence is unavailable. History will last only for this session.");
        }

        IAnalystActionStore analystActionStore;
        try
        {
            analystActionStore = JsonFileAnalystActionStore.CreateDefault(configDirectory, logSink: logSink);
        }
        catch
        {
            analystActionStore = new InMemoryAnalystActionStore("Analyst action log persistence is unavailable. Actions will last only for this session.");
        }

        var analystActionLogger = new AnalystActionLogger(analystActionStore, logSink);

        IBaselineStore baselineStore;
        try
        {
            baselineStore = JsonFileBaselineStore.CreateDefault(configDirectory, logSink);
        }
        catch
        {
            baselineStore = new InMemoryBaselineStore("Baseline persistence is unavailable. Baselines will last only for this session.");
        }

        IScheduleStore scheduleStore;
        try
        {
            scheduleStore = JsonFileScheduleStore.CreateDefault(configDirectory, logSink);
        }
        catch
        {
            scheduleStore = new InMemoryScheduleStore("Schedule persistence is unavailable. Schedules will last only for this session.");
        }

        ISessionStore sessionStore;
        try
        {
            sessionStore = JsonFileSessionStore.CreateDefault(configDirectory, logSink);
        }
        catch
        {
            sessionStore = new InMemorySessionStore("Remediation session persistence is unavailable. Sessions will last only for this session.");
        }

        IAgentMemoryStore memoryStore;
        try
        {
            memoryStore = JsonFileAgentMemoryStore.CreateDefault(configDirectory, logSink);
        }
        catch
        {
            memoryStore = new InMemoryAgentMemoryStore("Agent memory persistence is unavailable. Conversation context will last only for this session.");
        }

        IPinnedFindingStore pinnedFindingStore;
        try
        {
            pinnedFindingStore = JsonFilePinnedFindingStore.CreateDefault(configDirectory, logSink);
        }
        catch
        {
            pinnedFindingStore = new InMemoryPinnedFindingStore("Pinned findings persistence is unavailable. Pins will last only for this session.");
        }

        IPinnedMessageStore pinnedMessageStore;
        try
        {
            pinnedMessageStore = JsonFilePinnedMessageStore.CreateDefault(configDirectory, logSink);
        }
        catch
        {
            pinnedMessageStore = new InMemoryPinnedMessageStore("Pinned messages persistence is unavailable. Pins will last only for this session.");
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
            sessionStore,
            memoryStore: memoryStore);

        var ruleCatalog = new RuleCatalog(rules);

        INotificationSettingsStore notificationSettingsStore;
        try
        {
            notificationSettingsStore = JsonFileNotificationSettingsStore.CreateDefault(configDirectory, logSink);
        }
        catch
        {
            notificationSettingsStore = new InMemoryNotificationSettingsStore("Notification settings persistence is unavailable. Settings will last only for this session.");
        }

        var notificationService = notificationSettingsStore.Settings.CreateNotificationService();
        var processRunner = new ProcessRunner();
        var remediationExecutor = new RemediationExecutor(processRunner);
        var remediationPlanBuilder = new RemediationPlanBuilder(explanationProvider);
        // Give the live stream its own SentryAnalyzer instance so it never
        // contends with the static audit/analysis path for thread-safety.
        var liveStreamAdvancedDetectors = new IDetector[]
        {
            new C2ChannelDetector(),
            new PrivilegeEscalationDetector(),
            new ThreatIntelDetector(threatIntelStore)
        };
        var liveStreamSentryAnalyzer = new SentryAnalyzer(
            logNormalizer, profileProvider, baselineDetectors, linuxDetectors, liveStreamAdvancedDetectors, riskEscalator, logSink);
        var liveStreamAnalyzer = new LiveStreamAnalyzer(liveStreamSentryAnalyzer, profileProvider, logSink, timeWindow: TimeSpan.FromSeconds(180));
        var traceMapCorrelator = new TraceMapCorrelator();

        return new AgentServices
        {
            Agent = agent,
            Analyzer = analyzer,
            EvidenceBuilder = evidenceBuilder,
            MitreCoverageSources = mitreCoverageSources,
            RuleCatalog = ruleCatalog,
            SuppressionStore = suppressionStore,
            AuditHistoryStore = auditHistoryStore,
            AnalystActionStore = analystActionStore,
            AnalystActionLogger = analystActionLogger,
            BaselineStore = baselineStore,
            PolicyProvider = policyProvider,
            PolicyStore = policyStore,
            ProfileProvider = profileProvider,
            ScheduleStore = scheduleStore,
            NotificationSettingsStore = notificationSettingsStore,
            NotificationService = notificationService,
            ProcessRunner = processRunner,
            RemediationExecutor = remediationExecutor,
            RemediationPlanBuilder = remediationPlanBuilder,
            SessionStore = sessionStore,
            MemoryStore = memoryStore,
            PinnedFindingStore = pinnedFindingStore,
            PinnedMessageStore = pinnedMessageStore,
            LiveStreamAnalyzer = liveStreamAnalyzer,
            TraceMapCorrelator = traceMapCorrelator,
            ThreatIntelStore = threatIntelStore,
            DoctorService = doctorService
        };
    }

    private static IReadOnlyList<MitreCoverageSource> BuildMitreCoverageSources(
        IEnumerable<IDetector> detectors,
        IEnumerable<IRule> rules)
    {
        var sources = new List<MitreCoverageSource>();

        foreach (var detector in detectors)
        {
            if (detector.MitreTechniques.Count == 0)
                continue;

            sources.Add(new MitreCoverageSource
            {
                SourceId = detector.GetType().Name,
                SourceName = detector.GetType().Name.Replace("Detector", " detector", StringComparison.Ordinal),
                SourceType = "Detector",
                MitreTechniques = detector.MitreTechniques
            });
        }

        foreach (var rule in rules)
        {
            if (rule.MitreTechniques.Count == 0)
                continue;

            sources.Add(new MitreCoverageSource
            {
                SourceId = rule.Id,
                SourceName = rule.Description,
                SourceType = "Rule",
                MitreTechniques = rule.MitreTechniques
            });
        }

        return sources;
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

    /// <summary>Detector and rule MITRE ATT&CK coverage sources used for Navigator exports.</summary>
    public required IReadOnlyList<MitreCoverageSource> MitreCoverageSources { get; init; }

    /// <summary>Browsable catalog of security rules.</summary>
    public required RuleCatalog RuleCatalog { get; init; }

    /// <summary>Store for suppressed findings.</summary>
    public required ISuppressionStore SuppressionStore { get; init; }

    /// <summary>Store for audit history snapshots.</summary>
    public required IAuditHistoryStore AuditHistoryStore { get; init; }

    /// <summary>Store for analyst action audit log entries.</summary>
    public required IAnalystActionStore AnalystActionStore { get; init; }

    /// <summary>Logger for analyst actions backed by <see cref="AnalystActionStore"/>.</summary>
    public required AnalystActionLogger AnalystActionLogger { get; init; }

    /// <summary>Store for configuration baselines.</summary>
    public required IBaselineStore BaselineStore { get; init; }

    /// <summary>Provider for per-role rule policies.</summary>
    public required IRulePolicyProvider PolicyProvider { get; init; }

    /// <summary>Mutable store for per-role rule policies, falling back to session-only storage if persistence is unavailable.</summary>
    public required IRulePolicyStore? PolicyStore { get; init; }

    /// <summary>Provider for analysis intensity profiles.</summary>
    public required AnalysisProfileProvider ProfileProvider { get; init; }

    /// <summary>Store for recurring audit schedules.</summary>
    public required IScheduleStore ScheduleStore { get; init; }

    /// <summary>Store for global notification settings.</summary>
    public required INotificationSettingsStore NotificationSettingsStore { get; init; }

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

    /// <summary>Store for cross-session agent memory.</summary>
    public required IAgentMemoryStore MemoryStore { get; init; }

    /// <summary>Store for pinned findings.</summary>
    public required IPinnedFindingStore PinnedFindingStore { get; init; }

    /// <summary>Store for pinned agent chat messages.</summary>
    public required IPinnedMessageStore PinnedMessageStore { get; init; }

    /// <summary>Orchestrates live kernel stream analysis.</summary>
    public required LiveStreamAnalyzer LiveStreamAnalyzer { get; init; }

    /// <summary>Correlates findings into trace-map edges and critical chains.</summary>
    public required TraceMapCorrelator TraceMapCorrelator { get; init; }

    /// <summary>Store for imported threat intelligence IOCs.</summary>
    public required IThreatIntelStore ThreatIntelStore { get; init; }

    /// <summary>Self-diagnostic service for probing scanner capabilities.</summary>
    public required DoctorService DoctorService { get; init; }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        (SuppressionStore as IDisposable)?.Dispose();
        (AuditHistoryStore as IDisposable)?.Dispose();
        (AnalystActionStore as IDisposable)?.Dispose();
        (BaselineStore as IDisposable)?.Dispose();
        // DefaultRulePolicyProvider is not IDisposable (no-op above); the mutable JsonRulePolicyStore
        // owns the ReaderWriterLockSlim and is the instance that actually needs releasing.
        (PolicyStore as IDisposable)?.Dispose();
        (PolicyProvider as IDisposable)?.Dispose();
        (ScheduleStore as IDisposable)?.Dispose();
        (NotificationSettingsStore as IDisposable)?.Dispose();
        (NotificationService as IDisposable)?.Dispose();
        (ProcessRunner as IDisposable)?.Dispose();
        (SessionStore as IDisposable)?.Dispose();
        (MemoryStore as IDisposable)?.Dispose();
        (PinnedFindingStore as IDisposable)?.Dispose();
        (PinnedMessageStore as IDisposable)?.Dispose();
        (LiveStreamAnalyzer as IDisposable)?.Dispose();
        (ThreatIntelStore as IDisposable)?.Dispose();
    }
}
