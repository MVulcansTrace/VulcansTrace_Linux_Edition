# Development

## Build

Prerequisites:
- .NET 9.0 SDK
- Standard NuGet restore (packages come from nuget.org; no internal feed required for build)

Build the solution:
```bash
dotnet build
```

Run the Avalonia UI:
```bash
dotnet run --project VulcansTrace.Linux.Avalonia
```

## Tests

Run all tests:
```bash
dotnet test
```

Sample logs used by integration tests live in:
- `VulcansTrace.Linux.Tests/Data/Real/Samples`

## Project Layout

- `VulcansTrace.Linux.Core`: parsing, schema, and logging abstractions.
- `VulcansTrace.Linux.Engine`: detectors, profiles, analysis orchestration.
- `VulcansTrace.Linux.Evidence`: evidence packaging and report formatting.
- `VulcansTrace.Linux.Avalonia`: Avalonia UI, ViewModels, and services.
- `VulcansTrace.Linux.Tests`: xUnit tests.
- `VulcansTrace.Linux.Performance`: performance benchmarks.
- `VulcansTrace.Linux.PerformanceConsole`: console runner for benchmarks.
 
## Evidence Signing Key

The signing key is generated after each completed analysis in the UI. See `docs/HMAC_EVIDENCE.md`
for the step-by-step HMAC signing key flow.

## Adding a Detector

1. Implement `IDetector` in `VulcansTrace.Linux.Engine/Detectors`.
2. Register it in the detector lists used by:
   - `VulcansTrace.Linux.Avalonia/MainWindow.axaml.cs`
   - `tools/TestAnalysis/Program.cs` (optional CLI usage)
3. Add tests in `VulcansTrace.Linux.Tests/Detectors`.
4. Update any relevant profile thresholds in `VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs`.

## Build Policies

`Directory.Build.props` enforces warnings as errors and suppresses `NU1900` (internal feed audit API unavailable). Real vulnerability audit warnings (NU1901–NU1903) remain enabled.
