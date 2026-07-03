using System;
using System.Collections.Generic;
using System.Windows.Input;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Base class for a single rendered block inside an agent message bubble.
/// Derives from <see cref="ViewModelBase"/> so subclasses can raise property-change
/// notifications (e.g., <see cref="CodeBlock.IsExpanded"/>).
/// </summary>
public abstract class AgentMessageBlock : ViewModelBase
{
}

/// <summary>
/// A paragraph of inline text elements (runs, bold, italic, links, inline code).
/// </summary>
public sealed class ParagraphBlock : AgentMessageBlock
{
    public ParagraphBlock(IReadOnlyList<object> inlines)
    {
        Inlines = inlines;
    }

    /// <summary>
    /// Gets the inline elements that make up this paragraph.
    /// The objects are Avalonia <see cref="Avalonia.Controls.Documents.Inline"/> instances;
    /// they are stored as <see cref="object"/> to keep the VM layer loosely coupled.
    /// </summary>
    public IReadOnlyList<object> Inlines { get; }
}

/// <summary>
/// A fenced code block with an optional language label, a copy command,
/// and an expandable/collapsible surface.
/// </summary>
public sealed class CodeBlock : AgentMessageBlock
{
    private bool _isExpanded = true;

    public CodeBlock(string language, string code, ICommand copyCommand)
    {
        Language = language;
        Code = code;
        CopyCommand = copyCommand;
        ToggleExpandCommand = new RelayCommand(_ => IsExpanded = !IsExpanded);
    }

    /// <summary>
    /// Gets the declared language for the code block, if any.
    /// </summary>
    public string Language { get; }

    /// <summary>
    /// Gets the raw code content.
    /// </summary>
    public string Code { get; }

    /// <summary>
    /// Gets a one-line preview of the code for the collapsed state.
    /// </summary>
    public string PreviewText
    {
        get
        {
            var firstLine = Code.AsSpan().TrimStart();
            var newlineIndex = firstLine.IndexOf('\n');
            if (newlineIndex >= 0)
                firstLine = firstLine.Slice(0, newlineIndex);

            const int maxLength = 80;
            return firstLine.Length > maxLength
                ? $"{firstLine.Slice(0, maxLength).ToString()}…"
                : firstLine.ToString();
        }
    }

    /// <summary>
    /// Gets or sets whether the code block is expanded.
    /// </summary>
    public bool IsExpanded
    {
        get => _isExpanded;
        set => SetField(ref _isExpanded, value);
    }

    /// <summary>
    /// Gets the command invoked when the user clicks the copy button.
    /// </summary>
    public ICommand CopyCommand { get; }

    /// <summary>
    /// Gets the command invoked when the user expands or collapses the code block.
    /// </summary>
    public ICommand ToggleExpandCommand { get; }
}
