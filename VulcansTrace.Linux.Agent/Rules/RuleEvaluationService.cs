using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// Filters and evaluates security rules for an audit intent.
/// </summary>
internal sealed class RuleEvaluationService
{
    private readonly IReadOnlyList<IRule> _rules;
    private readonly MachineRole _machineRole;
    private readonly IRulePolicyProvider? _policyProvider;

    public RuleEvaluationService(
        IEnumerable<IRule> rules,
        MachineRole machineRole,
        IRulePolicyProvider? policyProvider)
    {
        _rules = rules?.ToList() ?? throw new ArgumentNullException(nameof(rules));
        _machineRole = machineRole;
        _policyProvider = policyProvider;
    }

    public IRule? FindRuleById(string ruleId)
    {
        if (string.IsNullOrWhiteSpace(ruleId))
            return null;

        return _rules.FirstOrDefault(r => r.Id.Equals(ruleId, StringComparison.OrdinalIgnoreCase));
    }

    public RuleEvaluationBatchResult EvaluateForIntent(
        AgentIntent intent,
        ScanData scanData,
        CancellationToken ct)
    {
        var ruleResults = new List<RuleResult>();
        var warnings = new List<string>();

        foreach (var rule in FilterRulesByIntent(intent))
        {
            var evaluated = EvaluateRule(rule, scanData, ct);
            ruleResults.Add(evaluated.RuleResult);
            warnings.AddRange(evaluated.Warnings);
        }

        return new RuleEvaluationBatchResult(ruleResults, warnings);
    }

    /// <summary>
    /// Returns the scanner names required to feed every rule that runs for <paramref name="intent"/>,
    /// derived from each rule's category (its primary scanner) plus any declared
    /// <see cref="IRule.RequiredDataFields"/>. Returns null for non-targeted intents (full audit or
    /// non-audit), meaning "run every scanner". Deriving the set from rule data dependencies keeps
    /// scanner selection in sync with the rules so a targeted audit can't be silently data-starved
    /// by a stale hand-maintained intent map.
    /// </summary>
    public IReadOnlyCollection<string>? GetRequiredScannerNames(AgentIntent intent)
    {
        if (!IntentCategoryMap.IsTargetedAudit(intent))
            return null;

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in FilterRulesByIntent(intent))
        {
            if (ScannerDataSources.CategoryToPrimaryScanner.TryGetValue(rule.Category, out var primary))
                names.Add(primary);

            foreach (var field in rule.RequiredDataFields)
            {
                if (ScannerDataSources.ScannerForField(field) is { } scanner)
                    names.Add(scanner);
            }
        }

        return names;
    }

    public SingleRuleEvaluationResult EvaluateRule(
        IRule rule,
        ScanData scanData,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(scanData);
        ct.ThrowIfCancellationRequested();

        var warnings = new List<string>();
        var policy = _policyProvider?.GetPolicy(rule.Id, _machineRole);

        if (policy?.Enabled == false)
        {
            return new SingleRuleEvaluationResult(CreatePolicyDisabledResult(rule), warnings, DisabledByPolicy: true);
        }

        RuleResult result;
        try
        {
            if (rule is IContextualRule contextualRule)
            {
                result = contextualRule.Evaluate(scanData, new RuleEvaluationContext(_machineRole, policy));
            }
            else
            {
                result = rule.Evaluate(scanData);
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Rule {rule.Id} crashed: {ex.GetType().Name}");
            result = RuleResult.Crash(rule.Id, rule.Category, rule.Description, rule.CisMappings, rule.MitreTechniques);
        }

        if (!result.Passed && policy?.AutoPass == true)
        {
            result = result with { Passed = true, Status = RuleStatus.Passed };
        }

        if (policy?.SeverityOverride.HasValue == true && !result.Passed && result.Status != RuleStatus.Crashed)
        {
            result = result with { Severity = policy.SeverityOverride.Value };
        }

        return new SingleRuleEvaluationResult(result, warnings, DisabledByPolicy: false);
    }

    private static RuleResult CreatePolicyDisabledResult(IRule rule)
    {
        return RuleResult.Pass(rule.Id, rule.Category, rule.Id, $"{rule.Description} (disabled by policy)", rule.CisMappings, rule.MitreTechniques);
    }

    private IEnumerable<IRule> FilterRulesByIntent(AgentIntent intent)
    {
        return intent switch
        {
            AgentIntent.FullAudit => _rules,
            AgentIntent.FirewallCheck => _rules.Where(r => r.Category.Equals("Firewall", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.NetworkCheck => _rules.Where(r => r.Category.Equals("Network", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.ServiceCheck => _rules.Where(r => r.Category.Equals("Service", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.PortCheck => _rules.Where(r => r.Category.Equals("Port", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.SshCheck => _rules.Where(r => r.Category.Equals("SSH", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.FilePermissionCheck => _rules.Where(r => r.Category.Equals("FilePermission", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.FilesystemAuditCheck => _rules.Where(r => r.Category.Equals(FindingCategories.FilesystemAudit, StringComparison.OrdinalIgnoreCase)),
            AgentIntent.KernelCheck => _rules.Where(r => r.Category.Equals("Kernel", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.UserAccountCheck => _rules.Where(r => r.Category.Equals(FindingCategories.UserAccount, StringComparison.OrdinalIgnoreCase)),
            AgentIntent.LoggingAuditCheck => _rules.Where(r => r.Category.Equals("Logging", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.SudoersCheck => _rules.Where(r => r.Category.Equals("Sudoers", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.SystemdTimerSocketCheck => _rules.Where(r => r.Category.Equals("Systemd", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.MacCheck => _rules.Where(r => r.Category.Equals("Mac", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.BootloaderCheck => _rules.Where(r => r.Category.Equals("Bootloader", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.CronJobCheck => _rules.Where(r => r.Category.Equals(FindingCategories.CronJob, StringComparison.OrdinalIgnoreCase)),
            AgentIntent.PackageVulnerabilityCheck => _rules.Where(r => r.Category.Equals(FindingCategories.PackageVulnerability, StringComparison.OrdinalIgnoreCase)),
            AgentIntent.ContainerCheck => _rules.Where(r => r.Category.Equals(FindingCategories.Container, StringComparison.OrdinalIgnoreCase)),
            AgentIntent.KubernetesCheck => _rules.Where(r => r.Category.Equals(FindingCategories.Kubernetes, StringComparison.OrdinalIgnoreCase)),
            AgentIntent.ThreatIntelCheck => _rules.Where(r => r.Category.Equals(FindingCategories.ThreatIntel, StringComparison.OrdinalIgnoreCase)),
            AgentIntent.YaraCheck => _rules.Where(r => r.Category.Equals(FindingCategories.Yara, StringComparison.OrdinalIgnoreCase)),
            AgentIntent.ProcessRuntimeCheck => _rules.Where(r => r.Category.Equals(FindingCategories.ProcessRuntime, StringComparison.OrdinalIgnoreCase)),
            _ => Array.Empty<IRule>()
        };
    }
}
