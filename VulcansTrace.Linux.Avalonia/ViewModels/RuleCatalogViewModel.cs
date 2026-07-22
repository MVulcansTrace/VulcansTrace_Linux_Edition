using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Actions;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for displaying and searching the rule catalog, with per-rule policy editing.
/// </summary>
public sealed class RuleCatalogViewModel : ViewModelBase
{
    private string _searchText = "";
    private int _totalRules;
    private RuleCatalogItemViewModel? _selectedItem;
    // Mutable: AgentFactory rebuilds the store when the machine role changes, and the editor must
    // keep writing to the same store instance the active agent reads from. See UpdatePolicyStore.
    private IRulePolicyStore? _policyStore;
    private readonly IDialogService? _dialogService;
    private readonly AnalystActionLogger? _analystActionLogger;
    private MachineRole _currentMachineRole = MachineRole.Workstation;
    private string _policyStatusMessage = "";

    /// <summary>Gets the collection of all catalog items.</summary>
    public ObservableCollection<RuleCatalogItemViewModel> Items { get; } = new();

    /// <summary>Gets the filtered view of catalog items.</summary>
    public ObservableCollection<RuleCatalogItemViewModel> FilteredItems { get; } = new();

    /// <summary>Gets whether any rules are loaded. Drives the never-loaded empty state.</summary>
    public bool HasItems => Items.Count > 0;

    /// <summary>Gets whether the filtered view has any rows to show. Drives DataGrid visibility.</summary>
    public bool HasData => FilteredItems.Count > 0;

    /// <summary>Gets whether rules exist but the search filter excluded all of them.</summary>
    public bool HasNoFilterMatches => Items.Count > 0 && FilteredItems.Count == 0;

    /// <summary>Gets or sets the search text for filtering rules.</summary>
    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetField(ref _searchText, value))
            {
                ApplyFilters();
            }
        }
    }

    /// <summary>Gets the total number of rules in the catalog.</summary>
    public int TotalRules
    {
        get => _totalRules;
        private set => SetField(ref _totalRules, value);
    }

    /// <summary>Gets or sets the selected catalog item.</summary>
    public RuleCatalogItemViewModel? SelectedItem
    {
        get => _selectedItem;
        set
        {
            if (SetField(ref _selectedItem, value))
            {
                EditPolicyCommand?.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>Gets the command to edit the selected rule's policy.</summary>
    public AsyncRelayCommand? EditPolicyCommand { get; private set; }

    /// <summary>Gets a status message describing the most recent policy edit/save outcome.</summary>
    public string PolicyStatusMessage
    {
        get => _policyStatusMessage;
        private set
        {
            if (SetField(ref _policyStatusMessage, value))
                OnPropertyChanged(nameof(HasPolicyStatusMessage));
        }
    }

    /// <summary>Gets whether there is a policy-edit status message to show.</summary>
    public bool HasPolicyStatusMessage => !string.IsNullOrWhiteSpace(_policyStatusMessage);

    /// <summary>
    /// Gets or sets the machine role currently active in the agent. Policy indicators and new
    /// edits target this role, so it must track <see cref="MainViewModel.SelectedMachineRole"/>.
    /// </summary>
    public MachineRole CurrentMachineRole
    {
        get => _currentMachineRole;
        set
        {
            if (SetField(ref _currentMachineRole, value))
                RefreshPolicyOverrides();
        }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RuleCatalogViewModel"/> class.
    /// </summary>
    public RuleCatalogViewModel()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RuleCatalogViewModel"/> class with policy editing support.
    /// </summary>
    public RuleCatalogViewModel(IRulePolicyStore? policyStore, IDialogService? dialogService, AnalystActionLogger? analystActionLogger = null)
    {
        _policyStore = policyStore;
        _dialogService = dialogService;
        _analystActionLogger = analystActionLogger;
        EditPolicyCommand = new AsyncRelayCommand(
            async _ => await EditPolicyAsync(),
            _ => CanEditPolicy(),
            ex =>
            {
                _dialogService?.ShowMessage($"Could not edit rule policy: {ErrorSanitizer.SanitizeException(ex)}", "Policy edit failed");
            });
    }

    /// <summary>
    /// Loads rules from a <see cref="RuleCatalog"/>.
    /// </summary>
    /// <param name="catalog">The rule catalog to load.</param>
    public void LoadCatalog(RuleCatalog catalog)
    {
        Items.Clear();
        FilteredItems.Clear();

        foreach (var item in catalog.Items)
        {
            Items.Add(new RuleCatalogItemViewModel(item));
        }

        TotalRules = Items.Count;
        ApplyFilters();
        RefreshPolicyOverrides();
        OnPropertyChanged(nameof(HasItems));
        OnPropertyChanged(nameof(HasData));
    }

    /// <summary>
    /// Replaces the policy store used for editing. Called when the machine role changes: AgentFactory
    /// rebuilds a fresh store bound to the new agent's provider, and the editor must write to that
    /// same instance or edits would be invisible to the active agent.
    /// </summary>
    public void UpdatePolicyStore(IRulePolicyStore? newStore)
    {
        _policyStore = newStore;
        EditPolicyCommand?.RaiseCanExecuteChanged();
        RefreshPolicyOverrides();
    }

    private void RefreshPolicyOverrides()
    {
        foreach (var item in Items)
            RefreshPolicyOverride(item);
    }

    private void RefreshPolicyOverride(RuleCatalogItemViewModel item)
    {
        var policy = _policyStore?.GetPolicy(item.Id, _currentMachineRole);
        item.PolicyOverrideDisplay = DescribeOverride(policy);
    }

    private static string DescribeOverride(RulePolicy? policy)
    {
        if (policy is null)
            return "\u2014";

        var parts = new List<string>();
        if (policy.Enabled is { } enabled)
            parts.Add(enabled ? "Force-on" : "Disabled");
        if (policy.AutoPass is { } autoPass && autoPass)
            parts.Add("Auto-pass");
        if (policy.SeverityOverride is { } severity)
            parts.Add($"Sev: {severity}");
        if (policy.Parameters.Count > 0)
            parts.Add($"{policy.Parameters.Count} param(s)");

        return string.Join(", ", parts);
    }

    private bool CanEditPolicy() => SelectedItem != null && _policyStore != null && _dialogService != null;

    private async Task EditPolicyAsync()
    {
        if (SelectedItem == null || _policyStore == null || _dialogService == null)
            return;

        var store = _policyStore;
        var dialog = _dialogService;
        var role = CurrentMachineRole;

        // The editor prompts before discarding unsaved edits on a role switch; default to Cancel so
        // an accidental click preserves in-progress work.
        async Task<bool> ConfirmDiscardAsync()
        {
            var choice = await dialog.ShowSelectionDialogAsync(
                "Discard policy edits?",
                "Switching role will discard unsaved edits to this rule's policy.",
                new[] { "Discard", "Cancel" },
                defaultIndex: 1);
            return choice == 0;
        }

        var editVm = new RulePolicyEditViewModel(SelectedItem.Item, store, role, ConfirmDiscardAsync);
        var result = await dialog.ShowRulePolicyEditDialogAsync(editVm);

        // The dialog returns true only when the operator applied a durable or session-only policy;
        // refresh the override indicator for the edited rule.
        if (result == true)
        {
            RefreshPolicyOverride(SelectedItem);
            PolicyStatusMessage = DescribeSaveResult(editVm);
            if (_analystActionLogger is { } actionLogger)
            {
                await actionLogger.LogRulePolicyEditedAsync("avalonia", SelectedItem.Id);
            }
        }
    }

    private static string DescribeSaveResult(RulePolicyEditViewModel editVm)
    {
        return editVm.LastSaveResult?.Outcome switch
        {
            RulePolicySaveOutcome.SessionOnly when !string.IsNullOrWhiteSpace(editVm.ValidationMessage) =>
                editVm.ValidationMessage,
            RulePolicySaveOutcome.SessionOnly =>
                "Policy saved for this session only.",
            RulePolicySaveOutcome.Durable =>
                "Policy saved.",
            _ =>
                string.IsNullOrWhiteSpace(editVm.ValidationMessage) ? "Policy edit completed." : editVm.ValidationMessage
        };
    }

    private void ApplyFilters()
    {
        FilteredItems.Clear();

        var term = _searchText?.Trim();
        if (string.IsNullOrWhiteSpace(term))
        {
            foreach (var item in Items)
            {
                FilteredItems.Add(item);
            }
            OnPropertyChanged(nameof(HasData));
            OnPropertyChanged(nameof(HasNoFilterMatches));
            return;
        }

        foreach (var item in Items)
        {
            if (item.Id.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                item.Category.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                item.Description.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                item.WhatItChecks.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                item.DataSources.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                item.MitreTechniquesDisplay.Contains(term, StringComparison.OrdinalIgnoreCase))
            {
                FilteredItems.Add(item);
            }
        }
        OnPropertyChanged(nameof(HasData));
        OnPropertyChanged(nameof(HasNoFilterMatches));
    }
}
