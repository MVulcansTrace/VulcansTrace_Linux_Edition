using System.Text.Json;
using System.Text.Json.Serialization;
using VulcansTrace.Linux.Agent;

namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// A rule policy store that persists per-role overrides to a JSON file.
/// </summary>
public sealed class JsonRulePolicyStore : IRulePolicyProvider, IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly string _filePath;
    private readonly ReaderWriterLockSlim _lock = new();
    private Dictionary<string, Dictionary<string, RulePolicy>> _policies = new(StringComparer.OrdinalIgnoreCase);
    private string? _persistenceWarning;

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonRulePolicyStore"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    public JsonRulePolicyStore(string filePath)
    {
        _filePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
        LoadFromDisk();
    }

    /// <summary>
    /// Creates a store in the user's config directory (XDG_CONFIG_HOME or ~/.config).
    /// </summary>
    /// <returns>A configured <see cref="JsonRulePolicyStore"/>.</returns>
    public static JsonRulePolicyStore CreateDefault(string? configDirectory = null)
    {
        var dir = VulcansTraceConfig.GetDirectory(configDirectory);
        Directory.CreateDirectory(dir);
        return new JsonRulePolicyStore(Path.Combine(dir, "policy.json"));
    }

    /// <summary>
    /// Gets the latest persistence warning, if policy could not be stored durably.
    /// </summary>
    public string? PersistenceWarning => _persistenceWarning;

    /// <summary>
    /// Sets a policy for the given role and rule.
    /// </summary>
    /// <param name="role">The machine role.</param>
    /// <param name="ruleId">The rule identifier.</param>
    /// <param name="policy">The policy to store.</param>
    public void SetPolicy(MachineRole role, string ruleId, RulePolicy policy)
    {
        var roleKey = role.ToString();
        _lock.EnterWriteLock();
        try
        {
            if (!_policies.TryGetValue(roleKey, out var roleDict))
            {
                roleDict = new Dictionary<string, RulePolicy>(StringComparer.OrdinalIgnoreCase);
                _policies[roleKey] = roleDict;
            }

            roleDict[ruleId] = policy;
            SaveToDisk();
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

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
            if (!File.Exists(_filePath))
                return;

            var json = File.ReadAllText(_filePath);
            var deserialized = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, RulePolicy>>>(json, JsonOptions);
            if (deserialized != null)
            {
                _policies = NormalizePolicies(deserialized);
            }
        }
        catch
        {
            _persistenceWarning = "Could not load saved policy. Using empty policy store.";
            _policies = new Dictionary<string, Dictionary<string, RulePolicy>>(StringComparer.OrdinalIgnoreCase);
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

    private void SaveToDisk()
    {
        try
        {
            var directory = Path.GetDirectoryName(_filePath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var json = JsonSerializer.Serialize(_policies, JsonOptions);
            File.WriteAllText(_filePath, json);
            _persistenceWarning = null;
        }
        catch (Exception ex)
        {
            _persistenceWarning = $"Could not save policy to disk: {ex.Message}. Policy changes will last only for this session.";
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _lock.Dispose();
    }
}
