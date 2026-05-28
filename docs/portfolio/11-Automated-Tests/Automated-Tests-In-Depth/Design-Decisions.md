# Design Decisions: Automated Tests

> The test suite was designed to maximize detection confidence through boundary-value analysis, full-pipeline integration, and real-world log validation. Every design choice favors deterministic, independently runnable tests that catch regressions before they reach production.

---

## Decision 1 — Arrange-Act-Assert (AAA) as the Mandatory Pattern

**Decision:** Every test follows the three-phase Arrange-Act-Assert pattern with explicit `// Arrange`, `// Act`, `// Assert` comments.

**Rationale:** The AAA pattern makes test intent immediately clear to any reader. The Arrange section documents the exact preconditions. The Act section is always a single method call, making failures easy to isolate. The Assert section enumerates every verified property. Without this structure, tests become difficult-to-read procedural code that obscures what behavior is being validated.

**Security Rationale:** Clear test structure reduces the risk that a reviewer misses an untested edge case. When every test follows the same structure, deviations stand out.

**Business Value:** Onboarding time for new developers is reduced because the test pattern is consistent across all 40+ files.

---

## Decision 2 — Boundary-Value Analysis at Exact Thresholds

**Decision:** Detector tests probe the exact threshold, one below, and well above — e.g., `targetCount: 15` (at threshold), `targetCount: 14` (just below), `targetCount: 20` and `targetCount: 100` (above).

**Rationale:** The most dangerous detection bugs are off-by-one errors at the threshold boundary. A detector that triggers at 14 instead of 15 produces false positives. One that requires 16 produces false negatives. Testing at the exact boundary proves the comparison operator (`>=`) is correct. Testing one below proves it does not trigger early. Testing well above proves it still works for large inputs.

**Security Rationale:** A single missed port scan due to an off-by-one error could allow an attacker to complete reconnaissance undetected. Boundary-value testing eliminates this class of bug.

**Business Value:** Boundary tests are the most cost-effective tests — they target the highest-risk region of the input space with the fewest test cases.

---

## Decision 3 — Synthetic Log Generation via `LogScenarioBuilder`

**Decision:** A dedicated helper class generates realistic iptables log entries from high-level parameters (`targetCount`, `duration`, `interval`), decoupling test intent from log format details.

**Rationale:** Tests written against raw log text are brittle — any change to the log format breaks every test. `LogScenarioBuilder` encapsulates the format, allowing tests to specify what they want (20-port scan over 3 minutes) rather than how to format it. When the parser evolves, only the builder needs updating.

**Security Rationale:** Decoupling tests from log format means tests continue to validate detection logic even when the parser changes. Tests that break on parser changes obscure whether the detection logic or the formatting is wrong.

**Business Value:** The fluent builder API (`BuildPortScan().Generate()`) is self-documenting and produces readable test code.

---

## Decision 4 — Real-World Log Fixtures in Addition to Synthetic Data

**Decision:** Test data under `Data/Real/Samples/` contains actual iptables and nftables log captures used by integration tests.

**Rationale:** Synthetic tests prove logic but cannot prove that the parser handles real-world formatting quirks — unusual whitespace, unexpected field ordering, kernel version differences, and non-standard field values. Real log fixtures validate that the entire pipeline works on production data.

**Security Rationale:** A parser that works perfectly on synthetic data but fails on real logs is worse than no parser — it provides false confidence. Real-world fixtures catch these gaps.

**Business Value:** Real log fixtures serve double duty as documentation — they show what actual input looks like.

---

## Decision 5 — Full-Pipeline Integration Tests with All Detectors

**Decision:** `SentryAnalyzerTests` constructs the analyzer with all 13+ detector types and exercises the complete pipeline from raw log text through all detector layers to final `AnalysisResult`.

**Rationale:** Unit tests validate individual detectors in isolation but cannot catch interaction bugs — findings being lost during aggregation, risk escalation producing wrong severities, or detectors interfering with each other's state. Integration tests catch these class of bugs.

**Security Rationale:** The pipeline is the actual execution path. Testing only individual components is testing the pieces, not the system. Integration tests prove the pieces work together.

**Business Value:** Integration tests are the highest-value tests for catching regressions from cross-cutting changes like profile modifications or pipeline restructuring.

---

## Decision 6 — Error Injection via `ThrowingDetector` Stub

**Decision:** `SentryAnalyzerTests` includes a private `ThrowingDetector` class that always throws `InvalidOperationException`, used to verify the pipeline's error handling.

**Rationale:** Error handling code is the most likely to contain bugs because it is rarely exercised in normal testing. By injecting a detector that always fails, the test verifies that the pipeline catches the exception, emits a warning containing the detector type and exception type, and continues processing other detectors.

**Security Rationale:** A detector that crashes silently could cause the entire pipeline to fail, losing all findings. Error injection tests prove the pipeline degrades gracefully.

**Business Value:** The error injection pattern is reusable — any new error handling behavior can be tested by modifying the throwing stub.

---

## Decision 7 — Performance Tests with Explicit Time Bounds

**Decision:** Dedicated tests construct 1,000-line and 5,000-line logs and assert that analysis completes within 5 and 15 seconds respectively, with an additional throughput test asserting at least 100 lines/sec.

**Rationale:** Performance regressions are invisible to functional tests — the analysis still produces correct results, just slowly. Without explicit time bounds, a regression that doubles processing time would go undetected until production.

**Security Rationale:** A tool that becomes too slow to use will be bypassed, losing all detection capability. Performance tests prevent this.

**Business Value:** The 5-second threshold for 1,000 lines provides a concrete, measurable performance contract that can be tracked over time.

---

## Summary

| Decision | Trade-off | Benefit |
|---|---|---|
| AAA pattern | More verbose than minimal tests | Clear intent, easy onboarding |
| Boundary-value analysis | More test methods per detector | Eliminates off-by-one detection errors |
| LogScenarioBuilder | Additional helper to maintain | Format-decoupled tests, single update point |
| Real-world fixtures | Must be updated for new log formats | Validates against production data |
| Full-pipeline integration | Slower to run, harder to debug | Catches interaction bugs unit tests miss |
| Error injection via ThrowingDetector | One-off test stub | Proves graceful degradation |
| Performance time bounds | Flaky on slow CI hardware | Prevents invisible performance regressions |

---

## Security Takeaways

1. Every design decision targets the highest-risk testing gaps — threshold boundaries, pipeline interactions, real-world parsing, and error handling
2. The AAA pattern ensures every test is self-documenting, reducing the risk that a reviewer misses an untested edge case
3. Boundary-value analysis is the most cost-effective testing strategy for threshold-based detectors
4. Full-pipeline integration tests are the only way to verify that findings survive the complete detection-to-escalation path
5. Error injection testing proves the system fails safely — a security requirement that is impossible to verify without deliberate fault injection
