using System.Text.Json;
using FluentValidation;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Persistence;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Validation;
using VulcansTrace.Linux.Core.Logging;

namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// A rule policy store that persists per-role overrides to a JSON file.
/// </summary>
public sealed class JsonRulePolicyStore : IRulePolicyStore, IDisposable
{
    private readonly JsonFilePersistence<Dictionary<string, Dictionary<string, RulePolicy>>> _persistence;
    private readonly IValidator<RulePolicy> _validator = new RulePolicyValidator();
    private readonly ReaderWriterLockSlim _lock = new();
    private Dictionary<string, Dictionary<string, RulePolicy>> _policies = new(StringComparer.OrdinalIgnoreCase);
    private string? _persistenceWarning;
    // True when the on-disk file is presumed valid but could not be read at startup (transient
    // I/O / sharing violation). While set, CommitCandidate must not write the file: doing so would
    // overwrite data we never managed to read with our partial in-memory state (silent data loss).
    private bool _loadIncomplete;

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonRulePolicyStore"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    public JsonRulePolicyStore(string filePath, ILogSink? logSink = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        _persistence = new JsonFilePersistence<Dictionary<string, Dictionary<string, RulePolicy>>>(filePath, JsonOptionsProvider.CamelCaseEnums, logSink: logSink);
        LoadFromDisk();
    }

    /// <summary>
    /// Creates a store in the user's config directory (XDG_CONFIG_HOME or ~/.config).
    /// </summary>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    /// <returns>A configured <see cref="JsonRulePolicyStore"/>.</returns>
    public static JsonRulePolicyStore CreateDefault(string? configDirectory = null, ILogSink? logSink = null)
    {
        var dir = VulcansTraceConfig.GetDirectory(configDirectory);
        Directory.CreateDirectory(dir);
        return new JsonRulePolicyStore(Path.Combine(dir, "policy.json"), logSink);
    }

    /// <summary>
    /// Gets the latest persistence warning, if policy could not be stored durably.
    /// </summary>
    public string? PersistenceWarning => ErrorSanitizer.SanitizeOptional(_persistenceWarning);

    /// <summary>
    /// Sets a policy for the given role and rule.
    /// </summary>
    /// <param name="role">The machine role.</param>
    /// <param name="ruleId">The rule identifier.</param>
    /// <param name="policy">The policy to store.</param>
    public RulePolicySaveResult SetPolicy(MachineRole role, string ruleId, RulePolicy policy)
    {
        var roleKey = role.ToString();
        _lock.EnterWriteLock();
        try
        {
            var candidate = ClonePolicies(_policies);
            if (!candidate.TryGetValue(roleKey, out var roleDict))
            {
                roleDict = new Dictionary<string, RulePolicy>(StringComparer.OrdinalIgnoreCase);
                candidate[roleKey] = roleDict;
            }

            roleDict[ruleId] = policy;
            return CommitCandidate(candidate);
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    RulePolicySaveResult IRulePolicyStore.SetPolicy(string ruleId, MachineRole role, RulePolicy policy)
        => SetPolicy(role, ruleId, policy);

    /// <inheritdoc />
    public RulePolicy? GetPolicy(string ruleId, MachineRole role)
    {
        var roleKey = role.ToString();
        _lock.EnterReadLock();
        try
        {
            if (_policies.TryGetValue(roleKey, out var roleDict) &&
                roleDict.TryGetValue(ruleId, out var policy))
            {
                return policy;
            }

            return null;
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    private void LoadFromDisk()
    {
        try
        {
            var deserialized = _persistence.Load();
            if (deserialized != null)
            {
                // Policies are treated as a single configuration unit: one malformed policy
                // quarantines the entire file rather than leaving the agent with a partial
                // rule set that may not match operator intent.
                _validator.ValidateAllAndThrow(deserialized);
                _policies = NormalizePolicies(deserialized);
            }
            // A missing file or a clean load both leave the live state consistent with disk.
            _loadIncomplete = false;
        }
        catch (Exception ex) when (ex is JsonException or ValidationException)
        {
            // Corrupt or semantically invalid JSON — move it aside so we don't retry a known-bad file.
            // The live file no longer exists, so the (now empty) in-memory state is consistent with disk.
            _persistence.Quarantine();
            _persistenceWarning = $"Could not load saved policy; the file has been quarantined. {ex.Message}";
            _policies = new Dictionary<string, Dictionary<string, RulePolicy>>(StringComparer.OrdinalIgnoreCase);
            _loadIncomplete = false;
        }
        catch (Exception ex)
        {
            // Transient failure (e.g. I/O or sharing violation) — leave the file in place to retry next
            // start, and mark the load incomplete so a later save cannot overwrite data we never read.
            _persistenceWarning = $"Could not load saved policy (will retry next start): {ex.Message}";
            _policies = new Dictionary<string, Dictionary<string, RulePolicy>>(StringComparer.OrdinalIgnoreCase);
            _loadIncomplete = true;
        }
    }

    private static Dictionary<string, Dictionary<string, RulePolicy>> NormalizePolicies(Dictionary<string, Dictionary<string, RulePolicy>> policies)
    {
        var normalized = new Dictionary<string, Dictionary<string, RulePolicy>>(StringComparer.OrdinalIgnoreCase);

        foreach (var (role, rolePolicies) in policies)
        {
            normalized[role] = new Dictionary<string, RulePolicy>(rolePolicies, StringComparer.OrdinalIgnoreCase);
        }

        return normalized;
    }

    private static Dictionary<string, Dictionary<string, RulePolicy>> ClonePolicies(Dictionary<string, Dictionary<string, RulePolicy>> policies)
        => NormalizePolicies(policies);

    private RulePolicySaveResult CommitCandidate(Dictionary<string, Dictionary<string, RulePolicy>> candidate)
    {
        // Validate before touching memory: an invalid candidate must not corrupt the live state.
        try
        {
            _validator.ValidateAllAndThrow(candidate);
        }
        catch (Exception ex)
        {
            _persistenceWarning = $"Could not save policy to disk: {ex.Message}. Invalid policy changes were not saved.";
            return RulePolicySaveResult.Rejected(_persistenceWarning);
        }

        // Apply to in-memory state so the session reflects the edit even if the disk write fails.
        _policies = NormalizePolicies(candidate);

        // If startup could not read the (presumed-valid) file, writing now would replace data we
        // never loaded with our partial state — silent data loss. Keep the edit session-scoped.
        if (_loadIncomplete)
        {
            _persistenceWarning = "Policy saved for this session only — the policy file could not be read at startup, so the change was not written to disk. Restart to retry the load.";
            return RulePolicySaveResult.SavedForSession(_persistenceWarning);
        }

        try
        {
            _persistence.Save(_policies);
            _persistenceWarning = null;
            return RulePolicySaveResult.SavedDurably();
        }
        catch (Exception ex)
        {
            _persistenceWarning = $"Could not save policy to disk: {ex.Message}. Policy changes will last only for this session.";
            return RulePolicySaveResult.SavedForSession(_persistenceWarning);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _lock.Dispose();
    }
}
