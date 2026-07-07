using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for editing a single rule's per-role policy override.
/// </summary>
public sealed class RulePolicyEditViewModel : ViewModelBase
{
    private readonly RuleCatalogItem _rule;
    private readonly IRulePolicyStore _policyStore;
    private readonly Func<Task<bool>>? _confirmDiscardAsync;
    private MachineRole _selectedRole;
    private bool _hasEnabled;
    private bool _enabled;
    private bool _hasSeverityOverride;
    private Severity _severityOverride;
    private bool _hasAutoPass;
    private bool _autoPass;
    private string _parametersText = "";
    private string _validationMessage = "";
    private RulePolicySaveResult? _lastSaveResult;

    // True only while LoadPolicyForRole is programmatically repopulating fields, so user-driven
    // setters can distinguish "operator typed a value" (mark dirty) from "we reloaded a role" (don't).
    private bool _isLoading;
    private bool _isDirty;

    /// <summary>Gets the rule identifier being edited.</summary>
    public string RuleId => _rule.Id;

    /// <summary>Gets the rule description.</summary>
    public string RuleDescription => _rule.Description;

    /// <summary>Gets the available machine roles.</summary>
    public MachineRole[] AvailableRoles { get; } = Enum.GetValues<MachineRole>();

    /// <summary>Gets the available severity values.</summary>
    public Severity[] AvailableSeverities { get; } = new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low, Severity.Info };

    /// <summary>Gets or sets the role whose policy is being edited.</summary>
    /// <remarks>
    /// Switching role reloads the stored policy for that role and clears any dirty marker. The
    /// view is responsible for confirming before discarding unsaved edits (see <see cref="IsDirty"/>
    /// and <see cref="ConfirmDiscardAsync"/>); this setter performs the reload unconditionally.
    /// </remarks>
    public MachineRole SelectedRole
    {
        get => _selectedRole;
        set
        {
            if (SetField(ref _selectedRole, value))
            {
                LoadPolicyForRole(value);
            }
        }
    }

    /// <summary>Gets or sets whether an explicit Enabled override is set.</summary>
    public bool HasEnabled
    {
        get => _hasEnabled;
        set => SetEditableField(ref _hasEnabled, value);
    }

    /// <summary>Gets or sets the Enabled override value.</summary>
    public bool Enabled
    {
        get => _enabled;
        set => SetEditableField(ref _enabled, value);
    }

    /// <summary>Gets or sets whether an explicit SeverityOverride is set.</summary>
    public bool HasSeverityOverride
    {
        get => _hasSeverityOverride;
        set => SetEditableField(ref _hasSeverityOverride, value);
    }

    /// <summary>Gets or sets the severity override value.</summary>
    public Severity SeverityOverride
    {
        get => _severityOverride;
        set => SetEditableField(ref _severityOverride, value);
    }

    /// <summary>Gets or sets whether an explicit AutoPass override is set.</summary>
    public bool HasAutoPass
    {
        get => _hasAutoPass;
        set => SetEditableField(ref _hasAutoPass, value);
    }

    /// <summary>Gets or sets the AutoPass override value.</summary>
    public bool AutoPass
    {
        get => _autoPass;
        set => SetEditableField(ref _autoPass, value);
    }

    /// <summary>
    /// Gets or sets the parameters as newline-separated "key=value" text.
    /// </summary>
    public string ParametersText
    {
        get => _parametersText;
        set => SetEditableField(ref _parametersText, value);
    }

    /// <summary>
    /// Gets or sets a validation/persistence message shown to the operator. Empty when there is
    /// nothing to report; non-empty when <see cref="SavePolicy"/> failed and the dialog should
    /// stay open to display the reason.
    /// </summary>
    public string ValidationMessage
    {
        get => _validationMessage;
        set => SetField(ref _validationMessage, value);
    }

    /// <summary>
    /// Gets a value indicating whether the editor holds edits that have not been saved.
    /// </summary>
    public bool IsDirty => _isDirty;

    /// <summary>
    /// Gets the most recent save outcome, or <c>null</c> before the first save attempt.
    /// </summary>
    public RulePolicySaveResult? LastSaveResult => _lastSaveResult;

    /// <summary>
    /// Initializes a new instance of the <see cref="RulePolicyEditViewModel"/> class.
    /// </summary>
    /// <param name="rule">The rule whose policy is being edited.</param>
    /// <param name="policyStore">The store that persists per-role policies.</param>
    /// <param name="initialRole">The role whose policy is loaded first.</param>
    /// <param name="confirmDiscardAsync">
    /// Optional callback invoked by the view to confirm discarding unsaved edits before switching
    /// role. Returns <c>true</c> to discard, <c>false</c> to keep the current role. When null,
    /// <see cref="ConfirmDiscardAsync"/> returns <c>true</c> (no guard).
    /// </param>
    public RulePolicyEditViewModel(
        RuleCatalogItem rule,
        IRulePolicyStore policyStore,
        MachineRole initialRole = MachineRole.Workstation,
        Func<Task<bool>>? confirmDiscardAsync = null)
    {
        _rule = rule ?? throw new ArgumentNullException(nameof(rule));
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _confirmDiscardAsync = confirmDiscardAsync;
        _selectedRole = initialRole;
        LoadPolicyForRole(initialRole);
    }

    /// <summary>
    /// Asks the operator to confirm discarding unsaved edits. Used by the view before switching
    /// the edited role. Returns <c>true</c> when there is nothing dirty or the operator confirms.
    /// </summary>
    public Task<bool> ConfirmDiscardAsync()
    {
        if (!_isDirty || _confirmDiscardAsync is null)
            return Task.FromResult(true);
        return _confirmDiscardAsync();
    }

    private void LoadPolicyForRole(MachineRole role)
    {
        var policy = _policyStore.GetPolicy(_rule.Id, role);

        // Reloads are programmatic: suppress dirty marking while repopulating, then clear it so
        // the freshly loaded state is considered clean.
        _isLoading = true;
        try
        {
            HasEnabled = policy?.Enabled.HasValue ?? false;
            Enabled = policy?.Enabled ?? true;

            HasSeverityOverride = policy?.SeverityOverride.HasValue ?? false;
            SeverityOverride = policy?.SeverityOverride ?? _rule.Severity;

            HasAutoPass = policy?.AutoPass.HasValue ?? false;
            AutoPass = policy?.AutoPass ?? false;

            ParametersText = policy?.Parameters != null
                ? string.Join(Environment.NewLine, policy.Parameters.Select(kvp => $"{kvp.Key}={kvp.Value}"))
                : "";
        }
        finally
        {
            _isLoading = false;
            SetDirty(false);
        }

        ValidationMessage = string.Empty;
    }

    /// <summary>
    /// Validates and saves the currently edited policy back to the store.
    /// </summary>
    /// <returns>
    /// <c>true</c> if the policy is now active (durably or for this session only); otherwise
    /// <c>false</c> and <see cref="ValidationMessage"/> describes why it was not applied.
    /// </returns>
    public bool SavePolicy()
    {
        _lastSaveResult = null;
        OnPropertyChanged(nameof(LastSaveResult));

        var (parameters, parseErrors) = ParseParameters(ParametersText);
        if (parseErrors.Count > 0)
        {
            ValidationMessage = string.Join(Environment.NewLine, parseErrors);
            return false;
        }

        var policy = new RulePolicy
        {
            Enabled = HasEnabled ? Enabled : null,
            SeverityOverride = HasSeverityOverride ? SeverityOverride : null,
            AutoPass = HasAutoPass ? AutoPass : null,
            Parameters = parameters
        };

        var result = _policyStore.SetPolicy(_rule.Id, SelectedRole, policy);
        _lastSaveResult = result;
        OnPropertyChanged(nameof(LastSaveResult));

        if (result.Outcome == RulePolicySaveOutcome.Rejected)
        {
            ValidationMessage = string.IsNullOrWhiteSpace(result.Message)
                ? "Policy was not saved."
                : result.Message;
            return false;
        }

        ValidationMessage = string.IsNullOrWhiteSpace(result.Message)
            ? string.Empty
            : result.Message;
        SetDirty(false);
        return true;
    }

    /// <summary>
    /// Parses newline-separated "key=value" parameters, collecting any malformed lines instead of
    /// silently dropping them. Blank lines and lines beginning with '#' are ignored.
    /// </summary>
    private static (ImmutableDictionary<string, string> Parameters, IReadOnlyList<string> Errors) ParseParameters(string text)
    {
        var builder = ImmutableDictionary.CreateBuilder<string, string>(StringComparer.OrdinalIgnoreCase);
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(text))
            return (builder.ToImmutable(), errors);

        var lineNumber = 0;
        foreach (var rawLine in text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            lineNumber++;
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#", StringComparison.Ordinal))
                continue;

            var eq = line.IndexOf('=');
            if (eq <= 0)
            {
                errors.Add($"Line {lineNumber}: '{line}' is not a 'key=value' pair.");
                continue;
            }

            var key = line[..eq].Trim();
            var value = line[(eq + 1)..].Trim();
            if (string.IsNullOrEmpty(key))
            {
                errors.Add($"Line {lineNumber}: parameter key is empty.");
                continue;
            }

            builder[key] = value;
        }

        return (builder.ToImmutable(), errors);
    }

    private bool SetEditableField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (SetField(ref field, value, propertyName))
        {
            if (!_isLoading)
                SetDirty(true);
            return true;
        }

        return false;
    }

    private void SetDirty(bool value)
    {
        if (_isDirty == value)
            return;
        _isDirty = value;
        OnPropertyChanged(nameof(IsDirty));
    }
}
