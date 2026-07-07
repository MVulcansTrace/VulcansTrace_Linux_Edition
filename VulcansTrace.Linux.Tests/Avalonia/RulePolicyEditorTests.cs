using System.Collections.Immutable;
using System.Threading.Tasks;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class RulePolicyEditViewModelTests
{
    [Fact]
    public void Constructor_LoadsExistingPolicy()
    {
        var rule = CreateRule();
        var store = new InMemoryRulePolicyStore();
        store.SetPolicy(rule.Id, MachineRole.Server, new RulePolicy
        {
            Enabled = false,
            SeverityOverride = Severity.Critical,
            AutoPass = true,
            Parameters = ImmutableDictionary.CreateRange(new[] { new KeyValuePair<string, string>("key1", "value1") })
        });

        var vm = new RulePolicyEditViewModel(rule, store, MachineRole.Server);

        Assert.Equal(MachineRole.Server, vm.SelectedRole);
        Assert.True(vm.HasEnabled);
        Assert.False(vm.Enabled);
        Assert.True(vm.HasSeverityOverride);
        Assert.Equal(Severity.Critical, vm.SeverityOverride);
        Assert.True(vm.HasAutoPass);
        Assert.True(vm.AutoPass);
        Assert.Contains("key1=value1", vm.ParametersText);
    }

    [Fact]
    public void Constructor_NoPolicy_LoadsDefaults()
    {
        var rule = CreateRule();
        var store = new InMemoryRulePolicyStore();

        var vm = new RulePolicyEditViewModel(rule, store, MachineRole.Workstation);

        Assert.False(vm.HasEnabled);
        Assert.True(vm.Enabled);
        Assert.False(vm.HasSeverityOverride);
        Assert.False(vm.HasAutoPass);
        Assert.Empty(vm.ParametersText);
    }

    [Fact]
    public void SavePolicy_PersistsChanges()
    {
        var rule = CreateRule();
        var store = new InMemoryRulePolicyStore();
        var vm = new RulePolicyEditViewModel(rule, store, MachineRole.Workstation)
        {
            HasEnabled = true,
            Enabled = false,
            HasSeverityOverride = true,
            SeverityOverride = Severity.High,
            HasAutoPass = true,
            AutoPass = false,
            ParametersText = "treatDefaultAs=Fail\nignoredServices=nfs"
        };

        vm.SavePolicy();

        var saved = store.GetPolicy(rule.Id, MachineRole.Workstation);
        Assert.NotNull(saved);
        Assert.False(saved.Enabled);
        Assert.Equal(Severity.High, saved.SeverityOverride);
        Assert.False(saved.AutoPass);
        Assert.Equal("Fail", saved.Parameters["treatDefaultAs"]);
        Assert.Equal("nfs", saved.Parameters["ignoredServices"]);
    }

    [Fact]
    public void SavePolicy_WithNoOverrides_SavesNulls()
    {
        var rule = CreateRule();
        var store = new InMemoryRulePolicyStore();
        var vm = new RulePolicyEditViewModel(rule, store, MachineRole.Workstation)
        {
            HasEnabled = false,
            HasSeverityOverride = false,
            HasAutoPass = false,
            ParametersText = ""
        };

        vm.SavePolicy();

        var saved = store.GetPolicy(rule.Id, MachineRole.Workstation);
        Assert.NotNull(saved);
        Assert.Null(saved.Enabled);
        Assert.Null(saved.SeverityOverride);
        Assert.Null(saved.AutoPass);
        Assert.Empty(saved.Parameters);
    }

    [Fact]
    public void SelectedRoleChange_ReloadsPolicyForRole()
    {
        var rule = CreateRule();
        var store = new InMemoryRulePolicyStore();
        store.SetPolicy(rule.Id, MachineRole.Server, new RulePolicy { Enabled = false });

        var vm = new RulePolicyEditViewModel(rule, store, MachineRole.Workstation);
        Assert.False(vm.HasEnabled);

        vm.SelectedRole = MachineRole.Server;

        Assert.True(vm.HasEnabled);
        Assert.False(vm.Enabled);
    }

    [Fact]
    public void SavePolicy_ReturnsTrue_AndPersists_WhenValid()
    {
        var rule = CreateRule();
        var store = new InMemoryRulePolicyStore();
        var vm = new RulePolicyEditViewModel(rule, store, MachineRole.Workstation)
        {
            HasEnabled = true,
            Enabled = false
        };

        Assert.True(vm.SavePolicy());
        Assert.Empty(vm.ValidationMessage);
        Assert.False(store.GetPolicy(rule.Id, MachineRole.Workstation)!.Enabled);
    }

    [Fact]
    public void SavePolicy_MalformedParameters_ReturnsFalseAndReportsLine()
    {
        var rule = CreateRule();
        var store = new InMemoryRulePolicyStore();
        var vm = new RulePolicyEditViewModel(rule, store, MachineRole.Workstation)
        {
            ParametersText = "treatDefaultAs=Fail\nthisHasNoEquals"
        };

        Assert.False(vm.SavePolicy());
        Assert.Contains("thisHasNoEquals", vm.ValidationMessage);
        // Nothing was written because validation failed before reaching the store.
        Assert.Null(store.GetPolicy(rule.Id, MachineRole.Workstation));
    }

    [Fact]
    public void SavePolicy_StoreSessionOnlyResult_ReturnsTrueAndSurfacesWarning()
    {
        var rule = CreateRule();
        var store = new FailingRulePolicyStore("the disk is full");
        var vm = new RulePolicyEditViewModel(rule, store, MachineRole.Workstation)
        {
            HasEnabled = true,
            Enabled = false
        };

        Assert.True(vm.SavePolicy());
        Assert.Equal(RulePolicySaveOutcome.SessionOnly, vm.LastSaveResult!.Outcome);
        Assert.Contains("the disk is full", vm.ValidationMessage);
    }

    [Fact]
    public void IsDirty_FalseInitially_TrueAfterEdit_FalseAfterSave()
    {
        var rule = CreateRule();
        var store = new InMemoryRulePolicyStore();
        var vm = new RulePolicyEditViewModel(rule, store, MachineRole.Workstation);
        Assert.False(vm.IsDirty);

        vm.HasEnabled = true;
        Assert.True(vm.IsDirty);

        Assert.True(vm.SavePolicy());
        Assert.False(vm.IsDirty);
    }

    [Fact]
    public void IsDirty_ReloadOnRoleSwitch_ClearsDirty()
    {
        var rule = CreateRule();
        var store = new InMemoryRulePolicyStore();
        var vm = new RulePolicyEditViewModel(rule, store, MachineRole.Workstation)
        {
            HasEnabled = true
        };
        Assert.True(vm.IsDirty);

        vm.SelectedRole = MachineRole.Server;

        Assert.False(vm.IsDirty);
    }

    [Fact]
    public async Task ConfirmDiscardAsync_NoEdits_ReturnsTrueWithoutCallback()
    {
        var rule = CreateRule();
        var store = new InMemoryRulePolicyStore();
        var vm = new RulePolicyEditViewModel(rule, store, MachineRole.Workstation);
        Assert.True(await vm.ConfirmDiscardAsync());
    }

    [Fact]
    public async Task ConfirmDiscardAsync_DirtyEdits_InvokesCallback()
    {
        var rule = CreateRule();
        var store = new InMemoryRulePolicyStore();
        var invoked = false;
        var vm = new RulePolicyEditViewModel(
            rule, store, MachineRole.Workstation,
            confirmDiscardAsync: () => { invoked = true; return Task.FromResult(false); });
        vm.HasEnabled = true; // make dirty

        var discard = await vm.ConfirmDiscardAsync();

        Assert.True(invoked);
        Assert.False(discard);
    }

    private static RuleCatalogItem CreateRule() => new RuleCatalogItem
    {
        Id = "TEST-001",
        Category = "Test",
        Description = "Test rule",
        WhatItChecks = "Checks test",
        Severity = Severity.Medium,
        SupportedDataSources = Array.Empty<string>(),
        ExplanationKey = "TEST-001",
        MitreTechniques = Array.Empty<MitreTechnique>()
    };
}

public class RuleCatalogViewModelTests
{
    [Fact]
    public void EditPolicyCommand_CannotExecute_WhenNoSelection()
    {
        var store = new InMemoryRulePolicyStore();
        var dialog = new TestDialogService();
        var vm = new RuleCatalogViewModel(store, dialog);
        vm.LoadCatalog(new RuleCatalog(new[] { new FakeRule("TEST-001") }));

        Assert.False(vm.EditPolicyCommand!.CanExecute(null));
    }

    [Fact]
    public void EditPolicyCommand_CanExecute_WhenItemSelected()
    {
        var store = new InMemoryRulePolicyStore();
        var dialog = new TestDialogService { RulePolicyResult = true };
        var vm = new RuleCatalogViewModel(store, dialog);
        vm.LoadCatalog(new RuleCatalog(new[] { new FakeRule("TEST-001") }));
        vm.SelectedItem = vm.FilteredItems[0];

        Assert.True(vm.EditPolicyCommand!.CanExecute(null));
    }

    [Fact]
    public async Task EditPolicyCommand_SavesExactlyOnce_AndRefreshesIndicator_WhenDialogReturnsTrue()
    {
        var store = new CountingRulePolicyStore();
        var dialog = new TestDialogService { RulePolicyResult = true };
        dialog.OnShowRulePolicyEdit = editVm =>
        {
            editVm.HasEnabled = true;
            editVm.Enabled = false;
            Assert.True(editVm.SavePolicy()); // the window applies the policy, then closes with true
        };
        var vm = new RuleCatalogViewModel(store, dialog);
        vm.LoadCatalog(new RuleCatalog(new[] { new FakeRule("TEST-001") }));
        vm.SelectedItem = vm.FilteredItems[0];

        vm.EditPolicyCommand!.Execute(null);
        await vm.EditPolicyCommand.ExecutionTask;

        Assert.NotNull(dialog.CapturedViewModel);
        Assert.Equal(MachineRole.Workstation, dialog.CapturedViewModel.SelectedRole);

        var saved = store.GetPolicy("TEST-001", MachineRole.Workstation);
        Assert.NotNull(saved);
        Assert.False(saved.Enabled);

        // The edit flow saves exactly once (no double-save) and refreshes the override indicator.
        Assert.Equal(1, store.SetPolicyCount);
        Assert.Equal("Disabled", vm.SelectedItem!.PolicyOverrideDisplay);
    }

    [Fact]
    public async Task EditPolicyCommand_SessionOnlySave_RefreshesIndicatorAndStatus()
    {
        var store = new CountingRulePolicyStore("policy file unavailable");
        var dialog = new TestDialogService { RulePolicyResult = true };
        dialog.OnShowRulePolicyEdit = editVm =>
        {
            editVm.HasEnabled = true;
            editVm.Enabled = false;
            Assert.True(editVm.SavePolicy());
        };
        var vm = new RuleCatalogViewModel(store, dialog);
        vm.LoadCatalog(new RuleCatalog(new[] { new FakeRule("TEST-001") }));
        vm.SelectedItem = vm.FilteredItems[0];

        vm.EditPolicyCommand!.Execute(null);
        await vm.EditPolicyCommand.ExecutionTask;

        Assert.Equal("Disabled", vm.SelectedItem!.PolicyOverrideDisplay);
        Assert.Contains("policy file unavailable", vm.PolicyStatusMessage);
        Assert.True(vm.HasPolicyStatusMessage);
    }

    [Fact]
    public async Task EditPolicyCommand_DoesNotSave_WhenDialogReturnsFalse()
    {
        var store = new CountingRulePolicyStore();
        var dialog = new TestDialogService { RulePolicyResult = false };
        var vm = new RuleCatalogViewModel(store, dialog);
        vm.LoadCatalog(new RuleCatalog(new[] { new FakeRule("TEST-001") }));
        vm.SelectedItem = vm.FilteredItems[0];

        vm.EditPolicyCommand!.Execute(null);
        await vm.EditPolicyCommand.ExecutionTask;

        Assert.Null(store.GetPolicy("TEST-001", MachineRole.Workstation));
        Assert.Equal(0, store.SetPolicyCount);
    }

    [Fact]
    public async Task EditPolicy_OpensEditorOnCurrentMachineRole()
    {
        var store = new InMemoryRulePolicyStore();
        var dialog = new TestDialogService { RulePolicyResult = true };
        var vm = new RuleCatalogViewModel(store, dialog);
        vm.LoadCatalog(new RuleCatalog(new[] { new FakeRule("TEST-001") }));
        vm.CurrentMachineRole = MachineRole.Server;
        vm.SelectedItem = vm.FilteredItems[0];

        vm.EditPolicyCommand!.Execute(null);
        await vm.EditPolicyCommand.ExecutionTask;

        Assert.Equal(MachineRole.Server, dialog.CapturedViewModel!.SelectedRole);
    }

    [Fact]
    public async Task EditPolicy_Exception_ReportedWithMessageFirstThenTitle()
    {
        var store = new InMemoryRulePolicyStore();
        var dialog = new TestDialogService { RulePolicyResult = true };
        dialog.OnShowRulePolicyEdit = _ => throw new InvalidOperationException("boom");
        var vm = new RuleCatalogViewModel(store, dialog);
        vm.LoadCatalog(new RuleCatalog(new[] { new FakeRule("TEST-001") }));
        vm.SelectedItem = vm.FilteredItems[0];

        vm.EditPolicyCommand!.Execute(null);
        await vm.EditPolicyCommand.ExecutionTask;

        Assert.NotNull(dialog.LastShownMessage);
        Assert.Contains("boom", dialog.LastShownMessage);
        Assert.Equal("Policy edit failed", dialog.LastShownTitle);
    }

    private sealed class FakeRule : IRule
    {
        public FakeRule(string id)
        {
            Id = id;
        }

        public string Id { get; }
        public string Category => "Test";
        public string Description => "Test rule";
        public string WhatItChecks => "Checks test";
        public Severity Severity => Severity.Medium;
        public IReadOnlyList<string> SupportedDataSources => Array.Empty<string>();
        public string ExplanationKey => Id;
        public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();
        public IReadOnlyList<MitreTechnique> MitreTechniques => Array.Empty<MitreTechnique>();

        public RuleResult Evaluate(ScanData data) => RuleResult.Pass(Id, Category, Id, Description);
    }

    private sealed class TestDialogService : IDialogService
    {
        public bool? RulePolicyResult { get; set; }
        public int? SelectionResult { get; set; }
        public RulePolicyEditViewModel? CapturedViewModel { get; private set; }

        // Simulates the real window: when the dialog "opens", the harness can mutate the VM and
        // click Save (calling SavePolicy) before ShowDialog returns — exactly the production flow.
        public Action<RulePolicyEditViewModel>? OnShowRulePolicyEdit { get; set; }

        public string? LastShownMessage { get; private set; }
        public string? LastShownTitle { get; private set; }

        public void ShowMessage(string message, string title)
        {
            LastShownMessage = message;
            LastShownTitle = title;
        }

        public void ShowError(string message, string title) { }
        public Task<string?> ShowSaveFileDialogAsync(string title, string filter, string defaultFileName) => Task.FromResult<string?>(null);
        public Task<string?> ShowOpenFileDialogAsync(string title, string filter) => Task.FromResult<string?>(null);
        public Task<string?> ShowInputDialogAsync(string title, string message, string defaultText = "") => Task.FromResult<string?>(null);

        public Task<bool?> ShowRulePolicyEditDialogAsync(RulePolicyEditViewModel viewModel)
        {
            CapturedViewModel = viewModel;
            OnShowRulePolicyEdit?.Invoke(viewModel);
            return Task.FromResult(RulePolicyResult);
        }

        public Task<int?> ShowSelectionDialogAsync(string title, string message, string[] options, int defaultIndex = 0)
            => Task.FromResult(SelectionResult);
    }
}

// Wraps the in-memory store to count SetPolicy calls — proves the edit flow saves exactly once.
internal sealed class CountingRulePolicyStore : IRulePolicyStore
{
    private readonly InMemoryRulePolicyStore _inner;

    public CountingRulePolicyStore(string? sessionOnlyWarning = null)
    {
        _inner = new InMemoryRulePolicyStore(sessionOnlyWarning);
    }

    public int SetPolicyCount { get; private set; }
    public string? PersistenceWarning => _inner.PersistenceWarning;

    public RulePolicySaveResult SetPolicy(string ruleId, MachineRole role, RulePolicy policy)
    {
        SetPolicyCount++;
        return _inner.SetPolicy(ruleId, role, policy);
    }

    public RulePolicy? GetPolicy(string ruleId, MachineRole role) => _inner.GetPolicy(ruleId, role);
}

// A store that always reports a session-only persistence failure — proves SavePolicy surfaces it.
internal sealed class FailingRulePolicyStore : IRulePolicyStore
{
    private readonly string _warning;
    public FailingRulePolicyStore(string warning) => _warning = warning;
    public string? PersistenceWarning => _warning;
    public RulePolicySaveResult SetPolicy(string ruleId, MachineRole role, RulePolicy policy)
        => RulePolicySaveResult.SavedForSession(_warning);
    public RulePolicy? GetPolicy(string ruleId, MachineRole role) => null;
}
