# Risk Escalation — Design Decisions

Rationale for the key architectural choices in the risk escalation subsystem.

---

## Decision 1: Host-Scoped Correlation Rather Than Global

**Choice**: Correlation rules evaluate findings grouped by `SourceHost`, not across all findings globally.

**Rationale**: The threat model assumes that a single compromised host will exhibit multiple behaviors. Correlating across hosts would produce false positives — for example, two different hosts each performing one category of activity should not trigger escalation. Host-scoping ensures that escalation only fires when there is strong evidence that a single attacker origin is performing multi-category operations.

**Trade-off**: This means cross-host attacker campaigns (e.g., Host A beacons while Host B moves laterally under the same operator) are not detected by the escalation layer. That analysis is better served by a separate campaign-correlation system operating on a different time scale.

---

## Decision 2: Three Fixed Correlation Rules with Time-Range Gating

**Choice**: The correlation rules are hardcoded as three boolean conditions in `RiskEscalator.Escalate`, each gated by `AreTimeRangesCorrelated`.

**Rationale**:
- The rules represent well-documented attacker behavior patterns from the MITRE ATT&CK framework
- Hardcoded rules are auditable, testable, and deterministic — critical for forensic evidence
- Each rule requires that at least one finding pair from the two categories occurs within a 24-hour window, preventing escalation from stale, unrelated findings
- A configurable rule engine would add complexity (parsing, validation, ordering, time-range expression evaluation) without proportional benefit at the current scale
- New rules can be added as single boolean expressions plus a time-range correlation call

**Trade-off**: Adding new correlation rules requires a code change and recompilation rather than a configuration update. This is acceptable because new rules should be accompanied by test coverage and documentation.

---

## Decision 3: Escalate Only Matched Categories

**Choice**: When a correlation rule fires for a host, only findings whose categories participate in the matched rule are escalated to Critical.

**Rationale**: The matched categories carry the correlated evidence. A Novelty or C2Channel finding on the same host may still be important, but it should keep its detector-assigned severity unless it participates in a separate correlation rule. This avoids inflating unrelated or low-signal findings simply because they share a source host.

**Trade-off**: Analysts may still need to review non-escalated findings on the same host to understand full scope. The benefit is more precise severity semantics: Critical means the finding itself participated in a known correlated pattern.

---

## Decision 4: Immutable Record Copies via `with` Expression

**Choice**: Escalation uses `f with { Severity = Severity.Critical, Confidence = ..., EvidenceSignals = ... }` on the `Finding` record rather than mutating the `Severity` property.

**Rationale**:
- `Finding` is a `sealed record` with init-only setters — mutation is not possible by design
- Immutable escalation preserves the original finding state for forensic review
- The `with` expression creates a shallow copy with property overrides, which is allocation-efficient for records
- During escalation, a `Cross-detector correlation` evidence signal is appended and confidence is recalculated via `FindingConfidenceCalculator`, so the escalated finding reflects the stronger combined evidence
- This pattern is idiomatic C# for functional-style data transformations

**Trade-off**: Each escalated finding is a new object allocation. For typical workloads (dozens to hundreds of findings) this is negligible.

---

## Decision 5: Per-Detector Fault Isolation in SentryAnalyzer

**Choice**: Each detector invocation in `SentryAnalyzer.Analyze` is wrapped in an individual try/catch that catches all non-fatal exceptions.

**Rationale**:
- A bug in one detector (e.g., a NullReferenceException from unexpected input) should not prevent other detectors from running
- The escalation layer depends on receiving findings from all healthy detectors — if the pipeline aborted on the first crash, correlation rules would operate on an incomplete finding set
- Fatal exceptions (OutOfMemoryException, StackOverflowException, etc.) are explicitly excluded from the catch so they propagate normally
- `OperationCanceledException` is re-thrown to respect cooperative cancellation

**Trade-off**: A crashing detector is silently disabled for that analysis run, and the only signal is a warning string in the result. The analyst may not notice the warning unless the UI surfaces it prominently.

---

## Decision 6: Parse Error Cap at 500

**Choice**: `SentryAnalyzer` keeps at most 500 parse errors from the normalizer.

```csharp
private const int MaxParseErrorsToKeep = 500;
var errorsToKeep = normalized.Errors.Take(MaxParseErrorsToKeep).ToList();
```

**Rationale**: If a log file is entirely malformed (e.g., a binary file or wrong encoding), the normalizer could produce millions of parse error records. Capping at 500 prevents unbounded memory growth while preserving enough errors to diagnose systemic parsing failures.

**Trade-off**: If there are more than 500 parse errors, the analyst cannot see all of them. This is acceptable because the first 500 errors are usually sufficient to identify the root cause (wrong format, encoding issue, etc.).

---

## Decision 7: Severity Filter Applied After Escalation

**Choice**: `MinSeverityToShow` filtering happens after `RiskEscalator.Escalate` runs, not before.

```csharp
var escalated = _riskEscalator.Escalate(allFindings);
var deduped = DeduplicateBeaconingC2Overlap(escalated);
var visibleFindings = deduped.Where(f => f.Severity >= profile.MinSeverityToShow).ToList();
var filteredFindings = ApplyFindingCap(visibleFindings, profile, warnings);
```

**Rationale**: If filtering happened before escalation, a finding at Medium severity that would be escalated to Critical could be filtered out before the escalator ever sees it. Post-escalation filtering ensures that Critical findings are included in the output regardless of the intensity profile. Filtering also happens before the per-category cap so hidden low-severity findings cannot consume the cap and displace visible findings.

**Trade-off**: The escalator processes all findings including those that would be filtered out anyway. This is a minor performance cost for correctness.

---

## Security Takeaways

- Host-scoped correlation is the correct granularity for identifying compromised machines — global correlation would increase false positives
- Immutable escalation via `with` expressions preserves the original detector output for forensic chain-of-custody
- Per-detector fault isolation ensures that a crashing detector cannot suppress escalation of findings from healthy detectors
- Post-escalation filtering guarantees that Critical findings are never hidden by a restrictive intensity profile
- Hardcoded correlation rules are auditable and deterministic, which is essential for forensic evidence that may be reviewed in incident response
- The 24-hour time-range gate ensures escalation reflects genuinely correlated activity, not coincidental findings from the same host over a long period
