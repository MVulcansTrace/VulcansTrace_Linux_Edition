using System;
using Avalonia.Controls;
using Avalonia.Controls.Templates;

namespace VulcansTrace.Linux.Avalonia;

/// <summary>
/// Locates views for ViewModels by convention: {VmName} -> Views/{VmName}View.
/// </summary>
public sealed class ViewLocator : IDataTemplate
{
    /// <inheritdoc />
    public Control? Build(object? data)
    {
        if (data is null)
            return null;

        var vmType = data.GetType();
        var vmName = vmType.Name;

        // Strip "ViewModel" suffix and append "View"
        var viewName = vmName.EndsWith("ViewModel")
            ? vmName[..^"ViewModel".Length] + "View"
            : vmName + "View";

        var fullName = $"VulcansTrace.Linux.Avalonia.Views.{viewName}";
        var viewType = Type.GetType(fullName);

        if (viewType is null)
        {
            // Fallback: try with the exact VM name + "View"
            fullName = $"VulcansTrace.Linux.Avalonia.Views.{vmName}View";
            viewType = Type.GetType(fullName);
        }

        if (viewType is null)
            return new TextBlock { Text = $"View not found: {fullName}" };

        return (Control)Activator.CreateInstance(viewType)!;
    }

    /// <inheritdoc />
    public bool Match(object? data)
    {
        return data is not null && data.GetType().Name.EndsWith("ViewModel");
    }
}
