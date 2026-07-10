using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Tests.Avalonia;

[Collection(AvaloniaUiTestCollection.Name)]
public sealed class ViewModelBaseTests
{
    [AvaloniaFact]
    public async Task UiOwnedInstance_PropertyChangedOffUiThread_ThrowsInDebug()
    {
        var vm = new TestViewModel();

#if DEBUG
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Task.Run(() => vm.Value = 1));

        Assert.Contains("raised off the UI thread", exception.Message, StringComparison.Ordinal);
#else
        await Task.Run(() => vm.Value = 1);
#endif
    }

    [AvaloniaFact]
    public async Task WorkerOwnedInstance_DoesNotInheritProcessGlobalUiAffinity()
    {
        // Application.Current is active for AvaloniaFact, but this VM is constructed
        // and used entirely by a worker-hosted test. A process-global gate would
        // incorrectly classify it as UI-owned and make parallel full-suite runs fail.
        await Task.Run(() =>
        {
            var vm = new TestViewModel();
            vm.Value = 1;
            Assert.Equal(1, vm.Value);
        });
    }

    private sealed class TestViewModel : ViewModelBase
    {
        private int _value;

        public int Value
        {
            get => _value;
            set => SetField(ref _value, value);
        }
    }
}
