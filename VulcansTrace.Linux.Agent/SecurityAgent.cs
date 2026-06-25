using VulcansTrace.Linux.Agent.Analysis;
using VulcansTrace.Linux.Agent.Baselines;
using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Agent.Suggestions;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;

namespace VulcansTrace.Linux.Agent;

/// <summary>
/// Orchestrates the complete agent audit pipeline: scanning, rule evaluation,
/// optional log analysis, explanation generation, and result assembly.
/// </summary>
public sealed class SecurityAgent : IAgent
{
    private readonly ScannerCoordinator _scannerCoordinator;
    private readonly RuleEvaluationService _ruleEvaluationService;
    private readonly AgentResultComposer _resultComposer;
    private readonly FindingAssemblyService _findingAssemblyService;
    private readonly AgentLogAnalysisService _logAnalysisService;
    private readonly AgentAuditState _auditState;
    private readonly AgentResultFinalizer _resultFinalizer;
    private readonly SingleRuleExplanationService _singleRuleExplanationService;
    private readonly IExplanationProvider _explanationProvider;
    private readonly BaselineDriftService _baselineDriftService;
    private readonly FindingExplanationService _findingExplanationService;
    private readonly AgentFollowUpService _followUpService;
    private readonly GuidedRemediationService _guidedRemediationService;
    private readonly ISuppressionStore? _suppressionStore;
    private readonly IAuditHistoryStore? _historyStore;
    private readonly DialogueManager _dialogueManager;
    private readonly IAgentSuggestionProvider _suggestionProvider;
    private readonly IAgentMemoryStore? _memoryStore;
    private readonly IRuleMemoryRecorder _ruleMemoryRecorder;
    private readonly CategoryCoverageRecorder _categoryCoverageRecorder;
    private readonly IPostureCorrelator _postureCorrelator;
    private readonly INarrativeComposer _narrativeComposer;
    private readonly SystemTrajectoryAnalyzer _systemTrajectoryAnalyzer;
    private readonly ProactiveAlertDetector _proactiveAlertDetector;
    private readonly AttackChainNarrator _attackChainNarrator;
    private readonly RemediationWisdomAnalyzer _remediationWisdomAnalyzer;
    private readonly CrossScannerValidator _crossScannerValidator;
    private readonly EvidenceProvenanceService _evidenceProvenanceService;
    private readonly DiagnosticDialogueService _diagnosticDialogueService;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityAgent"/> class.
    /// </summary>
    /// <param name="scanners">System data scanners.</param>
    /// <param name="rules">Security check rules.</param>
    /// <param name="explanationProvider">Provider for human-readable explanations.</param>
    /// <param name="sentryAnalyzer">Optional SentryAnalyzer for log-based analysis.</param>
    /// <param name="profileProvider">Optional profile provider for SentryAnalyzer intensity profiles.</param>
    /// <param name="suppressionStore">Optional store for rule suppressions.</param>
    /// <param name="machineRole">The machine role used to tune rule strictness.</param>
    /// <param name="policyProvider">Optional provider for per-role rule policies.</param>
    /// <param name="historyStore">Optional store for audit history used by follow-up queries.</param>
    /// <param name="baselineStore">Optional store for configuration baselines.</param>
    /// <param name="scorecardBuilder">Optional builder for CIS compliance scorecards.</param>
    /// <param name="riskScorecardBuilder">Optional builder for risk scorecards.</param>
    /// <param name="sessionStore">Optional store for remediation sessions.</param>
    /// <param name="suggestionProvider">Optional provider for contextual follow-up suggestions.</param>
    /// <param name="memoryStore">Optional store for cross-session conversation memory.</param>
    /// <param name="diagnosticDialogueService">Optional service for recurring-finding diagnostic dialogue.</param>
    public SecurityAgent(
        IEnumerable<IScanner> scanners,
        IEnumerable<IRule> rules,
        IExplanationProvider explanationProvider,
        SentryAnalyzer? sentryAnalyzer = null,
        AnalysisProfileProvider? profileProvider = null,
        ISuppressionStore? suppressionStore = null,
        MachineRole machineRole = MachineRole.Server,
        IRulePolicyProvider? policyProvider = null,
        IAuditHistoryStore? historyStore = null,
        IBaselineStore? baselineStore = null,
        IComplianceScorecardBuilder? scorecardBuilder = null,
        IRiskScorecardBuilder? riskScorecardBuilder = null,
        ISessionStore? sessionStore = null,
        IAgentSuggestionProvider? suggestionProvider = null,
        IAgentMemoryStore? memoryStore = null,
        DiagnosticDialogueService? diagnosticDialogueService = null)
    {
        _scannerCoordinator = new ScannerCoordinator(scanners);
        _ruleEvaluationService = new RuleEvaluationService(rules, machineRole, policyProvider);
        _resultComposer = new AgentResultComposer();
        _explanationProvider = explanationProvider ?? throw new ArgumentNullException(nameof(explanationProvider));
        _findingAssemblyService = new FindingAssemblyService(_explanationProvider, suppressionStore);
        _logAnalysisService = new AgentLogAnalysisService(sentryAnalyzer, profileProvider);
        _auditState = new AgentAuditState();
        _resultFinalizer = new AgentResultFinalizer(_auditState, historyStore, scorecardBuilder, riskScorecardBuilder);
        _singleRuleExplanationService = new SingleRuleExplanationService(
            _scannerCoordinator,
            _ruleEvaluationService,
            _findingAssemblyService,
            _resultComposer,
            _auditState,
            machineRole);
        _baselineDriftService = new BaselineDriftService(
            _auditState,
            baselineStore,
            RunAuditAsync);
        _findingExplanationService = new FindingExplanationService(
            _auditState,
            _ruleEvaluationService,
            _explanationProvider,
            _singleRuleExplanationService);
        _guidedRemediationService = new GuidedRemediationService(
            _auditState,
            new RemediationPlanBuilder(_explanationProvider),
            sessionStore,
            RunAuditAsync);
        _followUpService = new AgentFollowUpService(
            _auditState,
            _explanationProvider,
            historyStore,
            suppressionStore,
            _guidedRemediationService,
            RunAuditAsync);
        _suppressionStore = suppressionStore;
        _historyStore = historyStore;
        _dialogueManager = new DialogueManager();
        _suggestionProvider = suggestionProvider ?? new AgentSuggestionProvider();
        _memoryStore = memoryStore;
        _ruleMemoryRecorder = new RuleMemoryRecorder();
        _categoryCoverageRecorder = new CategoryCoverageRecorder();
        _postureCorrelator = new PostureCorrelator();
        _narrativeComposer = new NarrativeComposer();
        _systemTrajectoryAnalyzer = new SystemTrajectoryAnalyzer();
        _proactiveAlertDetector = new ProactiveAlertDetector();
        _attackChainNarrator = new AttackChainNarrator();
        _remediationWisdomAnalyzer = new RemediationWisdomAnalyzer();
        _crossScannerValidator = new CrossScannerValidator();
        _evidenceProvenanceService = new EvidenceProvenanceService(
            _auditState,
            _ruleEvaluationService,
            _singleRuleExplanationService);
        _diagnosticDialogueService = diagnosticDialogueService ?? new DiagnosticDialogueService();

        RestoreMemorySnapshot();
    }

    /// <inheritdoc />
    public async Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct)
    {
        var agentQuery = _dialogueManager.Resolve(query, _auditState);

        if (agentQuery.IsAmbiguous)
        {
            var clarification = _dialogueManager.BuildClarificationPrompt(agentQuery, _auditState);
            return new AgentResult
            {
                Intent = AgentIntent.Help,
                Summary = clarification,
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        AgentResult result;

        if (agentQuery.Intent == AgentIntent.Help)
        {
            result = new AgentResult
            {
                Intent = AgentIntent.Help,
                Summary = GetHelpText(),
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }
        else if (agentQuery.Intent == AgentIntent.ExplainFinding)
        {
            result = await _findingExplanationService.HandleExplainFindingAsync(agentQuery, ct);
        }
        else if (agentQuery.Intent == AgentIntent.ShowEvidence)
        {
            result = await _evidenceProvenanceService.BuildProvenanceAsync(agentQuery, ct);
        }
        else if (agentQuery.Intent == AgentIntent.InvestigateRecurrence)
        {
            result = await _diagnosticDialogueService.BeginInvestigationAsync(
                _auditState, agentQuery.TargetReference ?? string.Empty, ct);
        }
        else if (agentQuery.Intent == AgentIntent.AnswerDiagnosticQuestion)
        {
            result = await _diagnosticDialogueService.ContinueInvestigationAsync(
                _auditState,
                agentQuery.TargetReference ?? _auditState.Entities.PendingDiagnosticRuleId ?? string.Empty,
                query,
                ct);
        }
        else if (IsBaselineIntent(agentQuery.Intent))
        {
            result = agentQuery.Intent switch
            {
                AgentIntent.SetBaseline => await _baselineDriftService.SetBaselineAsync(agentQuery, ct),
                AgentIntent.CheckDrift => await _baselineDriftService.CheckDriftAsync(agentQuery, ct),
                AgentIntent.ShowBaseline => await _baselineDriftService.ShowBaselineAsync(agentQuery, ct),
                _ => await RunAuditCoreAsync(agentQuery.Intent, rawLog, ct)
            };
        }
        else if (agentQuery.Intent == AgentIntent.StartRemediation)
        {
            result = await _guidedRemediationService.CreateSessionAsync(agentQuery.TargetReference ?? "", ct);
        }
        else if (agentQuery.Intent == AgentIntent.ReportStepResult)
        {
            result = await _guidedRemediationService.HandleReportStepResultAsync(agentQuery, ct);
        }
        else if (agentQuery.Intent == AgentIntent.VerifyRemediation)
        {
            var target = agentQuery.TargetReference ?? "";
            if (!string.IsNullOrWhiteSpace(target) && !IsSessionId(target))
            {
                return await VerifyFindingAsync(target, ct).ConfigureAwait(false);
            }

            result = await _guidedRemediationService.RunVerificationAsync(target, ct);
        }
        else if (agentQuery.Intent == AgentIntent.ListRemediationSessions)
        {
            result = await _guidedRemediationService.ListSessionsAsync(ct);
        }
        else if (agentQuery.Intent == AgentIntent.ResumeRemediation)
        {
            result = await _guidedRemediationService.LoadSessionAsync(agentQuery.TargetReference ?? "", ct);
        }
        else if (agentQuery.Intent == AgentIntent.AddSessionNote)
        {
            var (sessionId, noteText, links) = ParseSessionNoteQuery(query, agentQuery);
            result = await AddSessionNoteAsync(sessionId, noteText, links, ct);
        }
        else if (agentQuery.Intent == AgentIntent.AddStepNote)
        {
            var (sessionId, ruleId, noteText, links) = ParseStepNoteQuery(query, agentQuery);
            result = await AddStepNoteAsync(sessionId, ruleId, noteText, links, ct);
        }
        else if (IsFollowUpIntent(agentQuery.Intent))
        {
            result = await _followUpService.HandleFollowUpAsync(agentQuery, ct);
        }
        else
        {
            result = await RunAuditCoreAsync(agentQuery.Intent, rawLog, ct);
        }

        return await CompleteStructuredResultAsync(query, agentQuery, result).ConfigureAwait(false);
    }

    private void UpdateDialogueContext(string rawQuery, AgentQuery agentQuery, AgentResult result)
    {
        _dialogueManager.PushTurn(_auditState, rawQuery, agentQuery);

        // Update conversation entities for anaphora resolution.
        // Audit intents are handled by RunAuditCoreAsync, which remembers the enriched result.
        // Follow-ups and baseline actions update topic/focus without overwriting
        // LastResult so subsequent follow-ups keep audit context.
        switch (agentQuery.Intent)
        {
            case AgentIntent.ExplainFinding:
            case AgentIntent.ShowEvidence:
                _auditState.Entities.LastIntent = agentQuery.Intent;
                _auditState.Entities.LastTopic = ConversationTopic.Explanation;
                if (result.AgentFindings.Count > 0)
                {
                    var finding = result.AgentFindings[0];
                    _auditState.FocusFinding(finding, finding.RuleId);
                }
                break;

            case AgentIntent.InvestigateRecurrence:
                _auditState.Entities.LastIntent = AgentIntent.InvestigateRecurrence;
                _auditState.Entities.LastTopic = ConversationTopic.Explanation;
                if (!string.IsNullOrWhiteSpace(agentQuery.TargetReference))
                {
                    _auditState.Entities.LastRuleId = agentQuery.TargetReference;
                    _auditState.Entities.LastCategory = null;
                }
                break;

            case AgentIntent.AnswerDiagnosticQuestion:
                _auditState.Entities.LastIntent = AgentIntent.AnswerDiagnosticQuestion;
                _auditState.Entities.LastTopic = ConversationTopic.Explanation;
                break;

            case AgentIntent.FilterCategory when !string.IsNullOrWhiteSpace(agentQuery.TargetReference):
                _auditState.Entities.LastIntent = AgentIntent.FilterCategory;
                _auditState.Entities.LastTopic = ConversationTopic.Audit;
                _auditState.FocusCategory(agentQuery.TargetReference);
                _diagnosticDialogueService.ResetDiagnosticState(_auditState.Entities);
                break;

            case AgentIntent.RiskScore:
                _auditState.Entities.LastIntent = AgentIntent.RiskScore;
                _auditState.Entities.LastTopic = ConversationTopic.Audit;
                var topCategory = result.RiskScorecard?.ByCategory
                    .OrderByDescending(c => c.TotalDeduction)
                    .FirstOrDefault()?.Category;
                if (!string.IsNullOrWhiteSpace(topCategory))
                {
                    _auditState.FocusCategory(topCategory);
                }
                _diagnosticDialogueService.ResetDiagnosticState(_auditState.Entities);
                break;

            case AgentIntent.StartRemediation:
            case AgentIntent.VerifyRemediation:
            case AgentIntent.ResumeRemediation:
            case AgentIntent.ReportStepResult:
                _auditState.Entities.LastIntent = agentQuery.Intent;
                _auditState.Entities.LastTopic = ConversationTopic.Remediation;
                if (result.RemediationSession != null)
                {
                    _auditState.Entities.LastRemediationSession = result.RemediationSession;
                    _auditState.Entities.LastRemediationSessionId = result.RemediationSession.SessionId;
                    _auditState.Entities.ActiveSessionId = result.RemediationSession.SessionId;
                    if (result.RemediationSession.SourceFindings.Count > 0)
                    {
                        _auditState.FocusFinding(result.RemediationSession.SourceFindings[0]);
                    }
                }
                break;

            case AgentIntent.Help:
                _auditState.Entities.LastIntent = AgentIntent.Help;
                _auditState.Entities.LastTopic = ConversationTopic.Help;
                break;

            case AgentIntent.FixFinding:
                _auditState.Entities.LastIntent = AgentIntent.FixFinding;
                _auditState.Entities.LastTopic = ConversationTopic.Remediation;
                if (result.AgentFindings.Count > 0)
                {
                    var finding = result.AgentFindings[0];
                    _auditState.FocusFinding(finding, finding.RuleId);
                }
                break;

            case AgentIntent.ExplainCritical:
            case AgentIntent.ShowChanges:
            case AgentIntent.PrioritizeRemediation:
            case AgentIntent.ListSuppressed:
            case AgentIntent.ListRemediationSessions:
            case AgentIntent.AddSessionNote:
            case AgentIntent.AddStepNote:
                _auditState.Entities.LastIntent = agentQuery.Intent;
                _auditState.Entities.LastTopic = DialogueContext.TopicForIntent(agentQuery.Intent);
                break;

            case AgentIntent.SetBaseline:
            case AgentIntent.CheckDrift:
            case AgentIntent.ShowBaseline:
                _auditState.Entities.LastIntent = agentQuery.Intent;
                _auditState.Entities.LastTopic = DialogueContext.TopicForIntent(agentQuery.Intent);
                _diagnosticDialogueService.ResetDiagnosticState(_auditState.Entities);
                break;

            default:
                // Audit intents update state in RunAuditCoreAsync (RememberAudit on the enriched result);
                // all other non-audit intents use the standard topic mapping so
                // follow-ups have the right context.
                if (DialogueContext.TopicForIntent(agentQuery.Intent) != ConversationTopic.Audit
                    && !IsBaselineIntent(agentQuery.Intent))
                {
                    _auditState.Entities.LastIntent = agentQuery.Intent;
                    _auditState.Entities.LastTopic = DialogueContext.TopicForIntent(agentQuery.Intent);
                }
                else
                {
                    _diagnosticDialogueService.ResetDiagnosticState(_auditState.Entities);
                }
                break;
        }
    }

    /// <summary>
    /// Gets the most recent audit result held by the agent, if any.
    /// </summary>
    public AgentResult? LastResult => _auditState.LastResult;

    /// <inheritdoc />
    public AgentQuery ResolveQuery(string query)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(query);
        return _dialogueManager.Resolve(query, _auditState);
    }

    /// <inheritdoc />
    public async Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
    {
        var result = await RunAuditCoreAsync(intent, rawLog, ct);

        return await AttachSuggestionsAndSaveAsync(result).ConfigureAwait(false);
    }

    private async Task<AgentResult> RunAuditCoreAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        // Phase 1: Run only the scanners that feed the rules for this intent, in parallel.
        // The set is derived from rule data dependencies (RuleEvaluationService.GetRequiredScannerNames),
        // not a hand-maintained intent map, so targeted audits can't be silently data-starved.
        var requiredScanners = _ruleEvaluationService.GetRequiredScannerNames(intent);
        var scannerResult = await _scannerCoordinator.RunAsync(ct, requiredScanners);
        var scanData = scannerResult.ScanData;
        var warnings = scannerResult.Warnings.ToList();
        var capabilityReport = _resultComposer.BuildCapabilityReport(scanData.Capabilities);
        var dataSourceCapabilities = _resultComposer.NormalizeCapabilities(scanData.Capabilities);

        ct.ThrowIfCancellationRequested();

        // Phase 2: Evaluate rules against scan data
        var evaluatedRules = _ruleEvaluationService.EvaluateForIntent(intent, scanData, ct);
        var ruleResults = evaluatedRules.RuleResults.ToList();
        warnings.AddRange(evaluatedRules.Warnings);

        // Phase 3: Mark suppression status, convert rule failures to findings,
        // and collapse similar active findings into representative groups.
        var findingAssembly = _findingAssemblyService.Assemble(ruleResults);
        ruleResults = findingAssembly.RuleResults.ToList();
        var suppressedCount = findingAssembly.SuppressedCount;
        warnings.AddRange(findingAssembly.Warnings);
        var agentFindings = FindingNoiseBudget.Apply(
            findingAssembly.AgentFindings,
            FindingNoiseBudget.DefaultMaxRepresentativesPerCategory,
            warnings,
            producerLabel: "agent rules");

        // Phase 3.5: Deterministic cross-scanner validation.
        // Adjusts confidence when independent scanner data supports or contradicts findings.
        agentFindings = _crossScannerValidator.Validate(agentFindings, scanData, warnings);

        var historyEntries = agentFindings
            .Select(f => (f.RuleId ?? $"__null-{f.Fingerprint}", f))
            .ToList();

        var passedCount = ruleResults.Count(r => r.Status == RuleStatus.Passed);
        var failedCount = ruleResults.Count(r => r.Status == RuleStatus.Failed);
        var crashedCount = ruleResults.Count(r => r.Status == RuleStatus.Crashed);

        // Phase 4: Optional log analysis
        var logAnalysis = await _logAnalysisService.AnalyzeAsync(rawLog, ct);
        var logAnalysisResult = logAnalysis.AnalysisResult;
        warnings.AddRange(logAnalysis.Warnings);

        // Phase 5: Build summary
        var summary = _resultComposer.BuildSummary(intent, agentFindings, logAnalysisResult, ruleResults, suppressedCount, crashedCount);

        // Phase 6 + 7 (computed before finalization). Posture correlations depend only on findings,
        // and attack chains depend on findings + posture correlations. Building them before
        // FinalizeAudit lets the attack chains be persisted with the audit history entry, so the
        // ShowEvidence attack-chain-membership section survives a process restart/rehydrate.
        var postureCorrelations = _postureCorrelator.Correlate(agentFindings);
        var attackChains = _attackChainNarrator.BuildChains(agentFindings, postureCorrelations);

        var result = _resultFinalizer.FinalizeAudit(new AgentResultFinalizationRequest(
            intent,
            agentFindings,
            logAnalysisResult,
            warnings,
            summary,
            ruleResults,
            passedCount,
            failedCount,
            suppressedCount,
            crashedCount,
            capabilityReport,
            dataSourceCapabilities,
            attackChains,
            historyEntries));

        result = result with { PostureCorrelations = postureCorrelations };

        // Phase 8: Detect findings that returned after a verified fix.
        // This runs before Record() so it can see LastVerifiedFixedUtc before it is consumed.
        var proactiveAlerts = _proactiveAlertDetector.Detect(result.AgentFindings, _auditState.Entities.RuleHistory, result.UtcTimestamp);
        result = result with { ProactiveAlerts = proactiveAlerts };

        // Phase 9: Update persistent per-rule memory so future turns can reference history.
        _auditState.Entities.RuleHistory = _ruleMemoryRecorder.Record(result, _auditState.Entities.RuleHistory);

        // Phase 9.5: Update long-horizon category coverage so the agent can surface blind spots.
        _auditState.Entities.CheckedCategories = _categoryCoverageRecorder.Record(
            intent, result.UtcTimestamp, _auditState.Entities.CheckedCategories);

        // Phase 10: Compute system-level trajectory from per-rule trend history.
        var systemTrajectory = _systemTrajectoryAnalyzer.Analyze(result.AgentFindings, _auditState.Entities.RuleHistory);
        result = result with { SystemTrajectory = systemTrajectory };

        // Phase 11: Surface remediation wisdom for rules with repeated fix-and-return cycles.
        var remediationWisdom = _remediationWisdomAnalyzer.Analyze(result.AgentFindings, _auditState.Entities.RuleHistory);
        result = result with { RemediationWisdom = remediationWisdom };

        // Phase 12: Compose a traceable narrative from findings, correlations, and memory.
        var narrative = _narrativeComposer.Compose(result, _auditState.Entities.RuleHistory, _auditState.SnapshotEntities());
        result = result with { Narrative = narrative };

        // Remember the fully enriched result (with attack chains, correlations, trajectory, and
        // narrative) so follow-up intents such as ShowEvidence observe the complete picture.
        // FinalizeAudit no longer remembers on its own, because at that point these enrichments
        // have not yet been applied and would leave LastResult pointing at a stale, chain-less copy.
        _auditState.RememberAudit(result, intent, historyEntries);

        return result;
    }

    private static bool IsFollowUpIntent(AgentIntent intent) => intent switch
    {
        AgentIntent.ShowChanges => true,
        AgentIntent.ExplainCritical => true,
        AgentIntent.FilterCategory => true,
        AgentIntent.PrioritizeRemediation => true,
        AgentIntent.FixFinding => true,
        AgentIntent.ListSuppressed => true,
        AgentIntent.RiskScore => true,
        _ => false
    };

    private static bool IsBaselineIntent(AgentIntent intent) => intent switch
    {
        AgentIntent.SetBaseline => true,
        AgentIntent.CheckDrift => true,
        AgentIntent.ShowBaseline => true,
        _ => false
    };

    /// <inheritdoc />
    public async Task<AgentResult> SetBaselineAsync(string name, string? description, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var query = new AgentQuery(AgentIntent.SetBaseline, name);
        var result = await _baselineDriftService.SetBaselineAsync(query, ct).ConfigureAwait(false);
        return await CompleteStructuredResultAsync(
            string.IsNullOrWhiteSpace(name) ? "set baseline" : $"set baseline {name}",
            query,
            result).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var result = await _baselineDriftService.RunDriftCheckAsync(intent, rawLog, ct).ConfigureAwait(false);
        return await CompleteStructuredResultAsync(
            "check drift",
            new AgentQuery(AgentIntent.CheckDrift, intent.ToString()),
            result).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<AgentResult> GetBaselineAsync(AgentIntent intent, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var result = await _baselineDriftService.ShowBaselineForIntentAsync(intent, ct).ConfigureAwait(false);
        return await CompleteStructuredResultAsync(
            "show baseline",
            new AgentQuery(AgentIntent.ShowBaseline, intent.ToString()),
            result).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<AgentResult> ExplainFindingAsync(Finding finding, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(finding);
        ct.ThrowIfCancellationRequested();

        var result = await _findingExplanationService.ExplainFindingAsync(finding, _auditState.Entities.RuleHistory, ct);

        // Keep the dialogue context consistent with the AskAsync explanation path
        // so pronoun follow-ups like "fix it" work after explaining a selected finding.
        _auditState.Entities.LastIntent = AgentIntent.ExplainFinding;
        _auditState.Entities.LastTopic = ConversationTopic.Explanation;
        _auditState.FocusFinding(finding, finding.RuleId);

        return await AttachSuggestionsAndSaveAsync(result).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<AgentResult> StartRemediationAsync(string findingReference, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var result = await _guidedRemediationService.CreateSessionAsync(findingReference, ct).ConfigureAwait(false);
        return await CompleteStructuredResultAsync(
            $"remediate {findingReference}",
            new AgentQuery(AgentIntent.StartRemediation, findingReference),
            result).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<AgentResult> VerifyRemediationAsync(string sessionId, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var result = await _guidedRemediationService.RunVerificationAsync(sessionId, ct).ConfigureAwait(false);

        UpdateMemoryFromVerification(result);

        return await CompleteStructuredResultAsync(
            $"verify session {sessionId}",
            new AgentQuery(AgentIntent.VerifyRemediation, sessionId),
            result).ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies whether a specific finding has been remediated by re-running
    /// the relevant audit and reporting whether the rule still fails.
    /// </summary>
    public async Task<AgentResult> VerifyFindingAsync(string ruleId, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleId);
        ct.ThrowIfCancellationRequested();

        if (_auditState.LastResult == null)
        {
            return new AgentResult
            {
                Intent = AgentIntent.VerifyRemediation,
                Summary = "Run an audit first, then ask me to verify a specific finding.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        var intent = _auditState.LastResult.Intent;
        var auditResult = await RunAuditCoreAsync(intent, null, ct).ConfigureAwait(false);
        var stillFailing = auditResult.AgentFindings.Any(f => !string.IsNullOrWhiteSpace(f.RuleId)
            && f.RuleId.Equals(ruleId, StringComparison.OrdinalIgnoreCase));

        var summary = stillFailing
            ? $"**{ruleId}** is still failing after re-audit."
            : $"**{ruleId}** is no longer detected. The remediation appears to have worked.";

        var result = auditResult with
        {
            Intent = AgentIntent.VerifyRemediation,
            Summary = summary
        };

        if (!stillFailing)
        {
            _auditState.Entities.RuleHistory = _ruleMemoryRecorder.MarkVerifiedFixed(
                new[] { ruleId },
                auditResult.UtcTimestamp,
                _auditState.Entities.RuleHistory);
        }

        UpdateMemoryFromVerification(result);

        return await CompleteStructuredResultAsync(
            $"verify finding {ruleId}",
            new AgentQuery(AgentIntent.VerifyRemediation, ruleId),
            result).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<AgentResult> UpdateRemediationStepStateAsync(
        string sessionId,
        string ruleId,
        RemediationStepState state,
        CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleId);
        ct.ThrowIfCancellationRequested();

        var result = _guidedRemediationService.UpdateStepState(sessionId, ruleId, state);

        if (ShouldRecordRemediationAttempt(state)
            && result.RemediationSession?.StepStates.TryGetValue(ruleId, out var updatedState) == true
            && updatedState == state)
        {
            StampRemediationAttempt(new[] { ruleId }, result.UtcTimestamp);
        }

        return await CompleteStructuredResultAsync(
            $"mark step {ruleId} {state} in session {sessionId}",
            new AgentQuery(AgentIntent.StartRemediation, sessionId),
            result).ConfigureAwait(false);
    }

    private void UpdateMemoryFromVerification(AgentResult result)
    {
        var verification = result.RemediationSession?.VerificationResult;
        if (verification == null)
            return;

        var fixedRuleIds = verification.FixedFindings
            .Select(f => f.RuleId)
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .ToList();

        if (fixedRuleIds.Count == 0)
            return;

        _auditState.Entities.RuleHistory = _ruleMemoryRecorder.MarkVerifiedFixed(
            fixedRuleIds,
            result.UtcTimestamp,
            _auditState.Entities.RuleHistory);
    }

    /// <inheritdoc />
    public async Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var result = await _guidedRemediationService.MarkSessionExportedAsync(sessionId, ct).ConfigureAwait(false);
        return await CompleteStructuredResultAsync(
            $"mark session exported {sessionId}",
            new AgentQuery(result.Intent, sessionId),
            result).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<AgentResult> ListRemediationSessionsAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var result = await _guidedRemediationService.ListSessionsAsync(ct).ConfigureAwait(false);
        return await CompleteStructuredResultAsync(
            "list sessions",
            new AgentQuery(AgentIntent.ListRemediationSessions),
            result).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<AgentResult> LoadRemediationSessionAsync(string sessionId, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var result = await _guidedRemediationService.LoadSessionAsync(sessionId, ct).ConfigureAwait(false);
        return await CompleteStructuredResultAsync(
            $"resume session {sessionId}",
            new AgentQuery(AgentIntent.ResumeRemediation, sessionId),
            result).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<AgentResult> DeleteRemediationSessionAsync(string sessionId, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var result = await _guidedRemediationService.DeleteSessionAsync(sessionId, ct).ConfigureAwait(false);
        return await CompleteStructuredResultAsync(
            $"delete session {sessionId}",
            new AgentQuery(result.Intent, sessionId),
            result).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<AgentResult> AddSessionNoteAsync(string sessionId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var result = _guidedRemediationService.AddSessionNote(sessionId, text, evidenceLinks);
        return await CompleteStructuredResultAsync(
            $"add note to session {sessionId}",
            new AgentQuery(AgentIntent.AddSessionNote, sessionId),
            result).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<AgentResult> AddStepNoteAsync(string sessionId, string ruleId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var result = _guidedRemediationService.AddStepNote(sessionId, ruleId, text, evidenceLinks);
        return await CompleteStructuredResultAsync(
            $"add step note {ruleId} in session {sessionId}",
            new AgentQuery(AgentIntent.AddStepNote, sessionId),
            result).ConfigureAwait(false);
    }

    private static (string SessionId, string NoteText, IReadOnlyList<string>? Links) ParseSessionNoteQuery(string rawQuery, AgentQuery agentQuery)
    {
        var sessionId = agentQuery.TargetReference ?? "";
        var noteText = rawQuery;
        var links = new List<string>();

        // Strip common keyword prefixes
        var prefixes = new[] { "add note", "session note", "write note" };
        foreach (var prefix in prefixes)
        {
            if (noteText.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                noteText = noteText[prefix.Length..].Trim();
                break;
            }
        }

        // If session ID is embedded in the text, strip it
        if (!string.IsNullOrEmpty(sessionId) && noteText.StartsWith(sessionId, StringComparison.OrdinalIgnoreCase))
        {
            noteText = noteText[sessionId.Length..].Trim();
        }
        else if (noteText.StartsWith("to session ", StringComparison.OrdinalIgnoreCase))
        {
            var afterPrefix = noteText["to session ".Length..].Trim();
            var firstSpace = afterPrefix.IndexOf(' ');
            if (firstSpace > 0)
            {
                sessionId = afterPrefix[..firstSpace];
                noteText = afterPrefix[(firstSpace + 1)..].Trim();
            }
        }

        // Extract evidence links from bracketed or quoted paths
        noteText = ExtractEvidenceLinks(noteText, links);

        return (sessionId, noteText, links.Count > 0 ? links : null);
    }

    private static readonly System.Text.RegularExpressions.Regex SessionIdOnlyRegex = new(
        @"^[0-9a-fA-F]{8}$",
        System.Text.RegularExpressions.RegexOptions.Compiled);

    private static bool IsSessionId(string? value) =>
        !string.IsNullOrWhiteSpace(value) && SessionIdOnlyRegex.IsMatch(value);

    private static (string SessionId, string RuleId, string NoteText, IReadOnlyList<string>? Links) ParseStepNoteQuery(string rawQuery, AgentQuery agentQuery)
    {
        var sessionId = "";
        var ruleId = "";
        var noteText = rawQuery;
        var links = new List<string>();

        var prefixes = new[] { "note for step", "step note", "add step note" };
        foreach (var prefix in prefixes)
        {
            if (noteText.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                noteText = noteText[prefix.Length..].Trim();
                break;
            }
        }

        // Rule ID is the first token after the prefix
        var firstSpace = noteText.IndexOf(' ');
        if (firstSpace > 0)
        {
            ruleId = noteText[..firstSpace];
            noteText = noteText[(firstSpace + 1)..].Trim();
        }
        else if (!string.IsNullOrEmpty(noteText))
        {
            // Single token remaining — could be rule ID if no session ID was parsed
            ruleId = noteText;
            noteText = "";
        }

        // Session ID is the next token if it is an 8-char hex value. This is more
        // deterministic than relying on TargetReference, which may match a hex word
        // later in the note body when multiple 8-char hex substrings are present.
        var secondSpace = noteText.IndexOf(' ');
        var candidate = secondSpace > 0 ? noteText[..secondSpace] : noteText;
        if (SessionIdOnlyRegex.IsMatch(candidate))
        {
            sessionId = candidate;
            noteText = secondSpace > 0 ? noteText[(secondSpace + 1)..].Trim() : "";
        }
        else if (agentQuery.TargetReference is not null && SessionIdOnlyRegex.IsMatch(agentQuery.TargetReference))
        {
            // Fallback to the resolved target reference if it is a valid session ID.
            sessionId = agentQuery.TargetReference;
            if (noteText.StartsWith(sessionId, StringComparison.OrdinalIgnoreCase))
            {
                noteText = noteText[sessionId.Length..].Trim();
            }
            else if (noteText.StartsWith("in session ", StringComparison.OrdinalIgnoreCase))
            {
                var afterPrefix = noteText["in session ".Length..].Trim();
                if (afterPrefix.StartsWith(sessionId, StringComparison.OrdinalIgnoreCase))
                {
                    noteText = afterPrefix[sessionId.Length..].Trim();
                }
            }
        }

        noteText = ExtractEvidenceLinks(noteText, links);

        return (sessionId, ruleId, noteText, links.Count > 0 ? links : null);
    }

    private static string ExtractEvidenceLinks(string text, List<string> links)
    {
        // Replace bracketed paths like [/tmp/file] with the inner content,
        // collecting the content into links.
        text = System.Text.RegularExpressions.Regex.Replace(text, @"\[([^\]]+)\]", m =>
        {
            var value = m.Groups[1].Value;
            links.Add(value);
            return value;
        });

        // Replace backtick-quoted snippets like `command output` with the inner content,
        // collecting the content into links (avoiding duplicates).
        text = System.Text.RegularExpressions.Regex.Replace(text, @"`([^`]+)`", m =>
        {
            var value = m.Groups[1].Value;
            if (!links.Contains(value))
            {
                links.Add(value);
            }
            return value;
        });

        // Collapse extra whitespace left behind by removed wrappers
        return System.Text.RegularExpressions.Regex.Replace(text, @"\s+", " ").Trim();
    }

    private async Task<AgentResult> CompleteStructuredResultAsync(string rawQuery, AgentQuery agentQuery, AgentResult result)
    {
        UpdateDialogueContext(rawQuery, agentQuery, result);
        return await AttachSuggestionsAndSaveAsync(result).ConfigureAwait(false);
    }

    private void StampRemediationAttempt(IEnumerable<string> ruleIds, DateTime timestampUtc)
    {
        var attemptIds = ruleIds.Where(r => !string.IsNullOrWhiteSpace(r)).ToList();
        if (attemptIds.Count == 0)
            return;

        var timestamp = timestampUtc == default ? DateTime.UtcNow : timestampUtc;
        _auditState.Entities.RuleHistory = _ruleMemoryRecorder.MarkRemediationAttempt(
            attemptIds,
            timestamp,
            _auditState.Entities.RuleHistory);
    }

    private static bool ShouldRecordRemediationAttempt(RemediationStepState state) =>
        state is RemediationStepState.InProgress
            or RemediationStepState.Completed
            or RemediationStepState.Failed;

    private async Task<AgentResult> AttachSuggestionsAndSaveAsync(AgentResult result)
    {
        result = result with
        {
            Suggestions = _suggestionProvider.GetSuggestions(result, _auditState.SnapshotEntities())
        };

        await SaveMemorySnapshotAsync().ConfigureAwait(false);
        return result;
    }

    private static readonly TimeSpan MaxMemorySnapshotAge = TimeSpan.FromDays(90);

    private void RestoreMemorySnapshot()
    {
        if (_memoryStore == null)
            return;

        var snapshot = _memoryStore.Load();
        if (snapshot == null)
            return;

        if (DateTime.UtcNow - snapshot.UtcTimestamp > MaxMemorySnapshotAge)
            return;

        var lastResult = RehydrateLastResult(snapshot);

        // If the referenced audit history entry is gone, the focus fields are stale;
        // clear them to avoid half-restored state.
        if (lastResult == null)
        {
            snapshot = snapshot with
            {
                FocusedRuleId = null,
                FocusedCategory = null,
                LastRemediationSessionId = null,
                ActiveSessionId = null,
                LatestAuditSnapshotId = null
            };
        }

        var entities = new EntityFrame
        {
            LastIntent = snapshot.LastIntent,
            LastTopic = snapshot.LastTopic,
            LastAuditIntent = snapshot.LastAuditIntent,
            LastRuleId = snapshot.FocusedRuleId,
            LastCategory = snapshot.FocusedCategory,
            LastRemediationSessionId = snapshot.LastRemediationSessionId,
            ActiveSessionId = snapshot.ActiveSessionId,
            RankedFindings = lastResult?.AgentFindings ?? Array.Empty<Finding>(),
            RuleHistory = snapshot.RuleHistory ?? new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase),
            CheckedCategories = snapshot.CheckedCategories ?? Array.Empty<CategoryAuditEntry>(),
            DiagnosticState = snapshot.DiagnosticState,
            PendingDiagnosticRuleId = snapshot.PendingDiagnosticRuleId,
            PendingDiagnosticQuestion = snapshot.PendingDiagnosticQuestion
        };

        if (!string.IsNullOrWhiteSpace(snapshot.FocusedRuleId) && lastResult != null)
        {
            entities.LastFinding = lastResult.AgentFindings
                .FirstOrDefault(f => !string.IsNullOrWhiteSpace(f.RuleId)
                    && f.RuleId.Equals(snapshot.FocusedRuleId, StringComparison.OrdinalIgnoreCase));
        }

        if (entities.LastFinding == null && lastResult != null && lastResult.AgentFindings.Count > 0)
        {
            entities.LastFinding = lastResult.AgentFindings[0];
            entities.LastRuleId ??= entities.LastFinding.RuleId;
            entities.LastCategory ??= entities.LastFinding.Category;
        }

        _auditState.RestoreState(lastResult, entities);
        if (snapshot.RecentTurns != null)
        {
            _auditState.RestoreHistory(snapshot.RecentTurns);
        }
    }

    private async Task SaveMemorySnapshotAsync()
    {
        if (_memoryStore == null)
            return;

        try
        {
            var snapshot = new AgentMemorySnapshot
            {
                UtcTimestamp = DateTime.UtcNow,
                LastIntent = _auditState.Entities.LastIntent,
                LastTopic = _auditState.Entities.LastTopic,
                LastAuditIntent = _auditState.Entities.LastAuditIntent,
                FocusedRuleId = _auditState.Entities.LastRuleId,
                FocusedCategory = _auditState.Entities.LastCategory,
                LastRemediationSessionId = _auditState.Entities.LastRemediationSessionId,
                ActiveSessionId = _auditState.Entities.ActiveSessionId,
                LatestAuditSnapshotId = GetLatestAuditSnapshotId(),
                RecentTurns = _auditState.History.TakeLast(DialogueContext.MaxHistoryTurns).ToList(),
                RuleHistory = _auditState.Entities.RuleHistory,
                CheckedCategories = _auditState.Entities.CheckedCategories,
                DiagnosticState = _auditState.Entities.DiagnosticState,
                PendingDiagnosticRuleId = _auditState.Entities.PendingDiagnosticRuleId,
                PendingDiagnosticQuestion = _auditState.Entities.PendingDiagnosticQuestion
            };

            await _memoryStore.SaveAsync(snapshot).ConfigureAwait(false);
        }
        catch
        {
            // A throwing custom memory store must not discard the result already built
            // for the user. Built-in stores swallow internally and surface via
            // PersistenceWarning.
        }
    }

    private string? GetLatestAuditSnapshotId()
    {
        if (_historyStore == null || _auditState.LastResult == null)
            return null;

        // Prefer the SnapshotId already stamped on the live result; it is authoritative.
        // Fall back to the newest history entry for the same intent only for legacy data.
        if (!string.IsNullOrWhiteSpace(_auditState.LastResult.SnapshotId))
            return _auditState.LastResult.SnapshotId;

        return _historyStore.GetAll()
            .FirstOrDefault(e => e.Intent == _auditState.LastResult.Intent)?.SnapshotId;
    }

    private AgentResult? RehydrateLastResult(AgentMemorySnapshot snapshot)
    {
        if (_historyStore == null || string.IsNullOrWhiteSpace(snapshot.LatestAuditSnapshotId))
            return null;

        var entry = _historyStore.GetAll()
            .FirstOrDefault(e => e.SnapshotId.Equals(snapshot.LatestAuditSnapshotId, StringComparison.OrdinalIgnoreCase));

        if (entry == null)
            return null;

        // A slim entry cannot provide the complete picture that follow-up intents such as
        // ShowEvidence expect. This should never happen for the latest entry because the history
        // store keeps the newest entries fully detailed, but guard against manual file edits.
        if (entry.IsSlimSummary)
            return null;

        var findings = entry.SnapshotFindings.Select(RehydrateFinding).ToList();
        var riskScorecard = findings.Count > 0
            ? new RiskScorecardBuilder().Build(findings, entry.TimestampUtc)
            : null;

        return new AgentResult
        {
            Intent = entry.Intent,
            AgentFindings = findings,
            UtcTimestamp = entry.TimestampUtc,
            Summary = $"Rehydrated audit from {entry.TimestampUtc:yyyy-MM-dd HH:mm} UTC.",
            PassedCount = entry.PassedCount,
            FailedCount = entry.FailedCount,
            SuppressedCount = entry.SuppressedCount,
            CrashedCount = entry.CrashedCount,
            CapabilityReport = entry.CapabilityReport ?? string.Empty,
            DataSourceCapabilities = entry.DataSourceCapabilities ?? Array.Empty<DataSourceCapability>(),
            AttackChains = entry.AttackChains ?? Array.Empty<AttackChain>(),
            RuleResults = entry.RuleResults,
            Warnings = entry.Warnings,
            LogAnalysisResult = entry.LogAnalysisResult,
            Scorecard = entry.Scorecard,
            RiskScorecard = riskScorecard,
            SnapshotId = entry.SnapshotId
        };
    }

    private static Finding RehydrateFinding(AuditSnapshotFinding snapshot)
    {
        return new Finding
        {
            RuleId = snapshot.RuleId,
            Category = string.IsNullOrWhiteSpace(snapshot.Category) ? "Unknown" : snapshot.Category,
            Severity = ParseSeverityString(snapshot.Severity),
            Confidence = ParseConfidenceString(snapshot.Confidence),
            EvidenceSignals = snapshot.EvidenceSignals,
            SourceHost = "localhost",
            Target = string.IsNullOrWhiteSpace(snapshot.Target) ? "unknown" : snapshot.Target,
            ShortDescription = string.IsNullOrWhiteSpace(snapshot.ShortDescription)
                ? $"Finding {snapshot.RuleId}"
                : snapshot.ShortDescription,
            Details = $"Rehydrated from audit history snapshot for {snapshot.RuleId}.",
            GroupedCount = snapshot.GroupedCount,
            RepresentativeTargets = snapshot.RepresentativeTargets,
            RiskDrivers = snapshot.RiskDrivers,
            Fingerprint = string.IsNullOrWhiteSpace(snapshot.Fingerprint) ? null! : snapshot.Fingerprint
        };
    }

    private static Severity ParseSeverityString(string severity) => severity.ToLowerInvariant() switch
    {
        "info" => Severity.Info,
        "low" => Severity.Low,
        "medium" => Severity.Medium,
        "high" => Severity.High,
        "critical" => Severity.Critical,
        _ => Severity.Info
    };

    private static DetectionConfidence ParseConfidenceString(string? confidence) => confidence?.ToLowerInvariant() switch
    {
        "low" => DetectionConfidence.Low,
        "medium" => DetectionConfidence.Medium,
        "high" => DetectionConfidence.High,
        "confirmed" => DetectionConfidence.Confirmed,
        _ => DetectionConfidence.Unknown
    };

    private static string GetHelpText() =>
        "I can help you audit your Linux system security. Try asking:\n" +
        "• \"Is my system secure?\" or \"Run a full audit\"\n" +
        "• \"Check my firewall\" or \"How's my iptables?\"\n" +
        "• \"What ports are open?\"\n" +
        "• \"What services are running?\"\n" +
        "• \"Who am I talking to?\" (network connections)\n" +
        "• \"Check my ssh\" or \"How's my SSH hardening?\"\n" +
        "• \"Check file permissions\" or \"Are my sensitive files secure?\"\n" +
        "• \"Check my filesystem\" or \"Any SUID binaries?\" or \"World-writable files?\"\n" +
        "• \"Check my user accounts\" or \"Are my passwords strong?\"\n" +
        "• \"Check containers\" or \"Any privileged containers?\"\n" +
        "• \"Check kubernetes\" or \"Any K8s security issues?\"\n" +
        "• \"Run a YARA scan\" or \"Check for malware signatures\"\n" +
        "• \"Check running processes\" or \"Any memory injection?\"\n" +
        "You can also paste a firewall log and ask for analysis.\n" +
        "To explain a specific finding: \"explain FW-001\" or select a finding from the list.\n" +
        "\nFollow-up questions (after an audit):\n" +
        "• \"What changed since the last audit?\"\n" +
        "• \"Why is this critical?\"\n" +
        "• \"Show only firewall issues\"\n" +
        "• \"What should I fix first?\"\n" +
        "• \"Fix FW-001\" — guided step-by-step remediation for a specific finding\n" +
        "• \"Which findings are suppressed?\"\n" +
        "• \"What's my risk grade?\" — show the overall risk scorecard\n" +
        "\nBaseline & drift detection:\n" +
        "• \"Set baseline\" — save the last audit as a known-good snapshot\n" +
        "• \"Check drift\" — compare live config against the saved baseline\n" +
        "• \"Show baseline\" — view the current baseline findings\n" +
        "\nRemediation session management:\n" +
        "• \"List sessions\" — browse all persisted remediation sessions\n" +
        "• \"Resume session <id>\" — reload a previous session to continue remediation\n" +
        "• \"Verify session <id>\" — run before/after verification on a completed session\n" +
        "\nSession notes & evidence:\n" +
        "• \"Add note to session <id> <text>\" — add a session-level note with human context\n" +
        "• \"Note for step <rule-id> in session <id> <text>\" — attach a note to a specific step\n" +
        "  Use backticks for command snippets (`ls -la`) and brackets for file paths ([/tmp/file])\n";}
