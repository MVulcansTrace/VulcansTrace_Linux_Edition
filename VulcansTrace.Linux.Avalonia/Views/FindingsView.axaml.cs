using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.VisualTree;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Avalonia.Views;

public partial class FindingsView : UserControl
{
    private TopLevel? _root;

    public FindingsView()
    {
        InitializeComponent();
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);

        _root = TopLevel.GetTopLevel(this);
        if (_root is not null)
        {
            _root.KeyDown += OnRootKeyDown;
        }
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnDetachedFromVisualTree(e);

        if (_root is not null)
        {
            _root.KeyDown -= OnRootKeyDown;
            _root = null;
        }
    }

    private void OnRootKeyDown(object? sender, KeyEventArgs e)
    {
        if (DataContext is not FindingsViewModel vm)
            return;

        // Ctrl+P toggles pin/unpin on the currently selected finding.
        if (e.Key == Key.P && e.KeyModifiers.HasFlag(KeyModifiers.Control))
        {
            vm.TogglePinSelectedCommand.Execute(null);
            e.Handled = true;
        }
    }
}
