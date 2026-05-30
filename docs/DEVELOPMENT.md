# Development

## Build

Prerequisites:
- .NET 9.0 SDK
- Standard NuGet restore from the public nuget.org feed

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

## Adding an Agent Scanner or Rule

1. Implement `IScanner` in `VulcansTrace.Linux.Agent/Scanners` and add its output to `ScanDataBuilder` / `ScanData`.
2. Implement `IRule` in `VulcansTrace.Linux.Agent/Rules/SecurityRules`.
3. Register the scanner and rule in:
   - `VulcansTrace.Linux.Avalonia/MainWindow.axaml.cs`
   - `tools/agent-demo/AgentDemo.cs` (optional demo usage)
4. Add explanation templates to `VulcansTrace.Linux.Agent/Explanations/Templates/`.
5. Add `AgentIntent` value to `VulcansTrace.Linux.Agent/Query/AgentIntent.cs` and keywords to `QueryParser.cs`.
6. Add tests in `VulcansTrace.Linux.Tests/Agent` (scanner fixtures, rule behavior, intent parsing).
7. Update `RuleCatalogTests.cs` if adding rules to the catalog.
8. Update docs in `docs/SECURITY_AGENT.md` and `docs/portfolio/16-Security-Agent/`.

## Build Policies

`Directory.Build.props` enforces warnings as errors so restore, build, and vulnerability-audit warnings are treated as release blockers.
