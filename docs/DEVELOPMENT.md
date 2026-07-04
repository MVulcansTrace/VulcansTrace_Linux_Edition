# Development

## Build

Prerequisites:
- .NET 10.0 SDK
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

The test suite contains **2 804 tests** covering unit, integration, detector, evidence, UI, live stream, demo mode, and performance scenarios.

Sample logs used by integration tests live in:
- `VulcansTrace.Linux.Tests/Data/Real/Samples`

## Project Layout

- `VulcansTrace.Linux.Core`: parsing, schema, compliance models, and logging abstractions.
- `VulcansTrace.Linux.Engine`: detectors, profiles, analysis orchestration.
- `VulcansTrace.Linux.Evidence`: evidence packaging and report formatting.
- `VulcansTrace.Linux.Agent`: Security Agent, scanners, rules, policy, scheduling, and notifications.
- `VulcansTrace.Linux.Avalonia`: Avalonia UI, ViewModels, and services.
- `VulcansTrace.Linux.Cli`: headless CLI for audits and schedule management.
- `VulcansTrace.Linux.Tests`: xUnit tests.
- `VulcansTrace.Linux.Performance`: performance benchmarks.
- `VulcansTrace.Linux.PerformanceConsole`: console runner for benchmarks.
 
## Evidence Signing Key

The signing key is generated after each completed analysis in the UI. See `docs/HMAC_EVIDENCE.md`
for the step-by-step HMAC signing key flow.

## Adding a Log Diff Formatter

1. Add a new formatter in `VulcansTrace.Linux.Evidence/Formatters/` (e.g., `LogDiffCsvFormatter`).
2. Register it in `AgentFactory.Create()` and wire it into `EvidenceBuilder`.
3. Add tests in `VulcansTrace.Linux.Tests/Evidence/`.
4. Update `docs/USAGE.md` and `docs/ARCHITECTURE.md`.

## Adding a Live Stream Event Source

1. Implement `IEventSource` in `VulcansTrace.Linux.Engine/Live`.
2. Add the source name to `LiveStreamViewModel.SourceNames` (constant, not magic string).
3. Register the source in `LiveStreamViewModel.ResolveSource()`.
4. Add tests in `VulcansTrace.Linux.Tests/Engine/Live`. Include:
   - Unit tests for the source's event generation/parsing.
   - Round-trip tests if the source uses `FormatAsIptablesLog`.
   - Null guard tests for public entry points.
   - Stress tests for rapid start/stop cycles and dispose-while-running.
5. Update `docs/LIVE_STREAM.md` and `docs/portfolio/17-Live-Stream/README.md`.

## Adding a Detector

1. Implement `IDetector` in `VulcansTrace.Linux.Engine/Detectors`.
2. Register it in `AgentFactory.Create()` in `VulcansTrace.Linux.Agent/AgentFactory.cs`.
3. Add tests in `VulcansTrace.Linux.Tests/Detectors`.
4. Update any relevant profile thresholds in `VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs`.

## Adding an Agent Scanner or Rule

1. Implement `IScanner` in `VulcansTrace.Linux.Agent/Scanners` and add its output to `ScanDataBuilder` / `ScanData`.
2. Implement `IRule` in `VulcansTrace.Linux.Agent/Rules/SecurityRules`.
3. Register the scanner and rule in `AgentFactory.Create()` in `VulcansTrace.Linux.Agent/AgentFactory.cs`.
4. Add explanation templates to `VulcansTrace.Linux.Agent/Explanations/Templates/`.
5. Add `AgentIntent` value to `VulcansTrace.Linux.Agent/Query/AgentIntent.cs` and keywords to `QueryParser.cs`.
6. Add intent/category mapping in `QueryParser.cs` and intent-based rule filtering in `VulcansTrace.Linux.Agent/Rules/RuleEvaluationService.cs`.
7. If the intent is an audit result the UI should export, baseline, or track in history, add it to `IsAuditIntent` in `VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs`.
8. Add tests in `VulcansTrace.Linux.Tests/Agent` and/or `VulcansTrace.Linux.Tests/Avalonia` (scanner fixtures, rule behavior, intent parsing, and UI audit-state behavior).
9. Update `RuleCatalogTests.cs` if adding rules to the catalog.
10. Update docs in `docs/SECURITY_AGENT.md` and `docs/portfolio/16-Security-Agent/`.

## Adding a Posture Correlation Pattern

1. Add a `PostureCorrelationPattern` to `PostureCorrelator.DefaultPatterns()` in `VulcansTrace.Linux.Engine/PostureCorrelator.cs`.
2. Use `{RuleIdA}` and `{RuleIdB}` placeholders in `NarrativeTemplate` so the rendered correlation paragraph is traceable.
3. Add a unit test in `VulcansTrace.Linux.Tests/Engine/PostureCorrelatorTests.cs` covering the new pattern and deduplication behavior.
4. Update `docs/ARCHITECTURE.md`, `docs/SECURITY_AGENT.md`, and `docs/DEMO.md` if the pattern is user-facing.

## Extending the Narrative Composer

1. Update `NarrativeComposer` in `VulcansTrace.Linux.Agent/Dialogue/NarrativeComposer.cs`.
2. Ensure every non-generic paragraph cites source IDs in its rendered text; add the IDs to `Narrative.SourceIds`.
3. Add or update tests in `VulcansTrace.Linux.Tests/Agent/NarrativeComposerTests.cs`, including the `EveryClaimIsTraceable` invariant.
4. Update `docs/ARCHITECTURE.md` and `docs/SECURITY_AGENT.md`.

## Extending Frame-Based NLU

1. Add new entity types to `QueryEntityFrame` in `VulcansTrace.Linux.Agent/Query/QueryEntityFrame.cs`.
2. Implement extraction in `EntityExtractor` in `VulcansTrace.Linux.Agent/Query/EntityExtractor.cs`.
3. If the entity should affect intent resolution, update `DialogueManager.EnrichWithEntityFrame` in `VulcansTrace.Linux.Agent/Dialogue/DialogueManager.cs`.
4. Add tests in `VulcansTrace.Linux.Tests/Agent/EntityExtractorTests.cs` and `VulcansTrace.Linux.Tests/Agent/QueryParserTests.cs`.
5. Update `docs/ARCHITECTURE.md` and `docs/SECURITY_AGENT.md`.

## Making a Rule Auto-Fixable

Auto-fix support is driven by the explanation template. If a rule's explanation includes `BackupCommands`, `ApplyCommands`, `RollbackCommands`, and `VerificationCommands`, the rule automatically becomes eligible for `--auto-fix` and `--dry-run`.

- **ReadOnly** (`CommandSafety.ReadOnly`) commands are always permitted.
- **ConfigChange** (`CommandSafety.ConfigChange`) commands are permitted under the `Standard` and `Aggressive` policies.
- **ServiceRestart** and **PackageInstall** commands require `--allow-restart` / `--allow-packages` and the `Aggressive` policy.
- **Destructive** and **Unknown** commands are never auto-executed.

If `RollbackCommands` are missing for a risky command (`ConfigChange`, `ServiceRestart`, `PackageInstall`, `Destructive`, or `Unknown`), the section is skipped with exit code `2` and a clear warning. Always include rollback guidance for any state-mutating command.

## Packaging

Build a self-contained CLI binary for distribution:

```bash
./scripts/publish-cli.sh
```

This produces `artifacts/publish/vulcanstrace` as a self-contained `linux-x64` executable.

## Build Policies

`Directory.Build.props` enforces warnings as errors so restore, build, and vulnerability-audit warnings are treated as release blockers.
