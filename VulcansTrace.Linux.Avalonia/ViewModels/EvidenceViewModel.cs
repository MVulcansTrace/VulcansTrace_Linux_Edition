using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Evidence;
using VulcansTrace.Linux.Avalonia.Services;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for exporting analysis results as a signed evidence bundle.
/// </summary>
public sealed class EvidenceViewModel : ViewModelBase, IDisposable
{
    private readonly EvidenceBuilder _evidenceBuilder;
    private readonly IDialogService _dialogService;
    private CancellationTokenSource? _cancellationTokenSource;

    private string _signingKey = "";
    private byte[]? _signingKeyBytes;
    private bool _isBusy;
    private AnalysisResult? _lastResult;
    private string _logSnapshot = "";
    private DateTime? _analysisTimestamp;

    /// <summary>
    /// Gets the current signing key in hex format.
    /// Generated once per analysis session. All exports for the same analysis share this key.
    /// </summary>
    public string SigningKey
    {
        get => _signingKey;
        private set
        {
            if (SetField(ref _signingKey, value))
            {
                OnPropertyChanged(nameof(MaskedSigningKey));
                RefreshCommandStates();
            }
        }
    }

    /// <summary>Gets the signing key masked for display.</summary>
    public string MaskedSigningKey =>
        string.IsNullOrEmpty(_signingKey)
            ? string.Empty
            : new string('*', _signingKey.Length);

    /// <summary>Gets whether an evidence export is in progress.</summary>
    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (SetField(ref _isBusy, value))
            {
                RefreshCommandStates();
            }
        }
    }

    /// <summary>Gets the command for exporting the evidence bundle.</summary>
    public AsyncRelayCommand ExportEvidenceCommand { get; }

    /// <summary>Gets the command for canceling an export.</summary>
    public RelayCommand CancelExportCommand { get; }

    /// <summary>Gets the command for copying the signing key.</summary>
    public AsyncRelayCommand CopySigningKeyCommand { get; }

    /// <summary>Raised when status text should be updated in the parent view model.</summary>
    public event EventHandler<string>? StatusChanged;

    /// <summary>
    /// Initializes a new instance of the <see cref="EvidenceViewModel"/> class.
    /// </summary>
    /// <param name="evidenceBuilder">Builder that creates the evidence bundle.</param>
    /// <param name="dialogService">Dialog service for UI prompts and messages.</param>
    public EvidenceViewModel(EvidenceBuilder evidenceBuilder, IDialogService dialogService)
    {
        _evidenceBuilder = evidenceBuilder;
        _dialogService = dialogService;

        ExportEvidenceCommand = new AsyncRelayCommand(
            async _ => await ExportEvidenceAsync(),
            _ => CanExportEvidence(),
            ex =>
            {
                _dialogService.ShowError($"Export failed: {ex.Message}", "VulcansTrace");
                StatusChanged?.Invoke(this, "Export failed.");
            });
        CancelExportCommand = new RelayCommand(_ => CancelExport(), _ => CanCancel());
        CopySigningKeyCommand = new AsyncRelayCommand(
            async _ => await CopySigningKeyAsync(),
            _ => !string.IsNullOrEmpty(SigningKey),
            ex =>
            {
                _dialogService.ShowError($"Failed to copy signing key: {ex.Message}", "VulcansTrace");
            });
    }

    /// <summary>
    /// Sets the analysis data used for evidence generation.
    /// </summary>
    /// <param name="result">The analysis result to export.</param>
    /// <param name="logText">The raw log text snapshot.</param>
    /// <param name="timestamp">Optional analysis timestamp.</param>
    public void SetEvidenceContext(AnalysisResult result, string logText, DateTime? timestamp)
    {
        _lastResult = result;
        _logSnapshot = logText;
        _analysisTimestamp = timestamp;
        _signingKeyBytes = GenerateNewSigningKey();
        RefreshCommandStates();
    }

    public void ClearEvidenceContext()
    {
        _lastResult = null;
        _logSnapshot = string.Empty;
        _analysisTimestamp = null;
        _signingKeyBytes = null;
        SigningKey = string.Empty;
        RefreshCommandStates();
    }

    private bool CanExportEvidence() => _lastResult != null && !IsBusy;
    private bool CanCancel() => _isBusy && _cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested;

    private void CancelExport()
    {
        _cancellationTokenSource?.Cancel();
    }

    private void RefreshCommandStates()
    {
        ExportEvidenceCommand.RaiseCanExecuteChanged();
        CancelExportCommand.RaiseCanExecuteChanged();
        CopySigningKeyCommand.RaiseCanExecuteChanged();
    }

    private async Task ExportEvidenceAsync()
    {
        if (_lastResult == null) return;

        IsBusy = true;
        StatusChanged?.Invoke(this, "Exporting evidence bundle...");

        _cancellationTokenSource?.Dispose();
        _cancellationTokenSource = new CancellationTokenSource();
        var token = _cancellationTokenSource.Token;

        var signingKeyBytes = _signingKeyBytes ?? GenerateNewSigningKey();

        try
        {
            await ExportEvidenceCoreAsync(signingKeyBytes, token);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _dialogService.ShowError($"Export failed: {ex.Message}", "VulcansTrace");
            StatusChanged?.Invoke(this, "Export failed.");
        }
        finally
        {
            IsBusy = false;
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
        }
    }

    private async Task ExportEvidenceCoreAsync(byte[] signingKeyBytes, CancellationToken token)
    {
        byte[] zipBytes;
        var failureAction = "build evidence bundle";

        try
        {
            // Use local copies to avoid race conditions if analysis runs again
            var result = _lastResult ?? throw new InvalidOperationException("No analysis result is available for export.");
            var log = _logSnapshot;
            var ts = _analysisTimestamp;

            StatusChanged?.Invoke(this, "Choose evidence bundle location...");
            var fileName = await _dialogService.ShowSaveFileDialogAsync(
                "Save Evidence Bundle",
                "ZIP files (*.zip)|*.zip|All files (*.*)|*.*",
                "VulcansTrace_Evidence.zip");

            if (string.IsNullOrEmpty(fileName))
            {
                StatusChanged?.Invoke(this, "Export cancelled by user.");
                return;
            }

            token.ThrowIfCancellationRequested();
            StatusChanged?.Invoke(this, "Building evidence bundle...");
            failureAction = "build evidence bundle";
            zipBytes = await _evidenceBuilder.BuildAsync(result, log, signingKeyBytes, ts, token);

            token.ThrowIfCancellationRequested();
            failureAction = "save file";
            await File.WriteAllBytesAsync(fileName, zipBytes, token);
            if (!token.IsCancellationRequested)
            {
                _dialogService.ShowMessage("Evidence bundle saved.", "VulcansTrace");
                StatusChanged?.Invoke(this, "Evidence bundle saved.");
            }
        }
        catch (Exception ex)
        {
            if (ex is OperationCanceledException)
            {
                StatusChanged?.Invoke(this, "Export cancelled by user.");
            }
            else
            {
                _dialogService.ShowError($"Failed to {failureAction}: {ex.Message}", "VulcansTrace");
                StatusChanged?.Invoke(this, "Export failed.");
            }
            return;
        }
    }

    private byte[] GenerateNewSigningKey()
    {
        var keyBytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(keyBytes);
        }

        _signingKeyBytes = keyBytes;
        SigningKey = Convert.ToHexString(keyBytes);
        return keyBytes;
    }

    private async Task CopySigningKeyAsync()
    {
        try
        {
            var topLevel = Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime;
            var mainWindow = topLevel?.MainWindow;

            if (mainWindow != null)
            {
                var clipboard = TopLevel.GetTopLevel(mainWindow)?.Clipboard;
                if (clipboard != null)
                {
                    await clipboard.SetTextAsync(SigningKey);
                    _dialogService.ShowMessage("Signing key copied to clipboard.", "VulcansTrace");
                }
                else
                {
                    _dialogService.ShowError("Clipboard not available.", "VulcansTrace");
                }
            }
            else
            {
                _dialogService.ShowError("Clipboard not available.", "VulcansTrace");
            }
        }
        catch (Exception ex)
        {
            _dialogService.ShowError($"Failed to copy signing key: {ex.Message}", "VulcansTrace");
        }
    }

    public void Dispose()
    {
        _cancellationTokenSource?.Cancel();
        _cancellationTokenSource?.Dispose();
        _cancellationTokenSource = null;
    }
}
