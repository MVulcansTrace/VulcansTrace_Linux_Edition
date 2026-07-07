using System;
using System.Diagnostics;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Avalonia.Views;

/// <summary>
/// Dialog window for editing a single rule's per-role policy override.
/// </summary>
public partial class RulePolicyEditWindow : Window
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RulePolicyEditWindow"/> class.
    /// </summary>
    public RulePolicyEditWindow()
    {
        InitializeComponent();
    }

    /// <summary>
    /// Gets the view model.
    /// </summary>
    public RulePolicyEditViewModel ViewModel => (RulePolicyEditViewModel)DataContext!;

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }

    private void SaveButton_Click(object? sender, RoutedEventArgs e)
    {
        var vm = ViewModel;
        // SavePolicy persists durably and returns false (with ValidationMessage set) on a malformed
        // policy or a persistence failure; only close on a confirmed durable save.
        if (vm.SavePolicy())
        {
            Close(true);
        }
    }

    private void CancelButton_Click(object? sender, RoutedEventArgs e)
    {
        Close(false);
    }

    // The role ComboBox is bound OneWay so we can intercept selection changes here: if the operator
    // has unsaved edits, confirm before letting the view model reload (which would discard them).
    private async void RoleComboBox_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        try
        {
            if (DataContext is not RulePolicyEditViewModel vm || sender is not ComboBox combo)
                return;
            if (combo.SelectedItem is not MachineRole proposed || proposed == vm.SelectedRole)
                return;

            if (!await vm.ConfirmDiscardAsync())
            {
                // Keep the current role. Reassigning SelectedItem re-fires this handler, but the
                // proposed == vm.SelectedRole guard above short-circuits it, so there's no recursion.
                combo.SelectedItem = vm.SelectedRole;
                return;
            }

            vm.SelectedRole = proposed;
        }
        catch (Exception ex)
        {
            // async-void: an unhandled exception would tear down the process; never let confirm leak.
            Debug.WriteLine($"Role selection change failed: {ex}");
        }
    }
}
