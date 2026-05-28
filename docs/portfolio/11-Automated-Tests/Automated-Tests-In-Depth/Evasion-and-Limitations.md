# Evasion and Limitations: Automated Tests

## Known Limitations

| Limitation | Impact | Severity |
|---|---|---|
| No code coverage enforcement | Tests may exist for happy paths while edge cases remain uncovered | Medium |
| No mutation testing | Tests may pass even if detection logic is subtly wrong | High |
| No fuzzing | Parser robustness against adversarial input is not systematically tested | Medium |
| No concurrency tests | Multiple simultaneous analysis runs are not tested | Low |
| Real log fixtures may not cover all formats | Five sample logs are included, which may not represent all kernel versions | Medium |
| No performance regression tracking | Time-bound tests use a fixed threshold but do not track trends over time | Low |
| No UI end-to-end tests | Avalonia tests cover ViewModels but not the actual rendered UI | Low |
| No distributed test execution | Tests run sequentially; no parallel execution validation | Low |

---

### No Code Coverage Enforcement

The test suite validates key detection pathways but does not enforce a minimum code coverage percentage. Paths that are not exercised by tests — error recovery branches, edge cases in parsers, or corner cases in risk escalation — could contain undetected bugs.

**Mitigation options:** Add a code coverage tool (e.g., `coverlet.collector`) and enforce a minimum coverage threshold in CI. Target 80%+ line coverage for detector implementations.

---

### No Mutation Testing

Tests verify that correct inputs produce correct outputs, but they do not verify that incorrect detection logic would be caught. If a developer accidentally changes `>=` to `>` in a threshold comparison, the boundary-value tests should catch it — but this is not systematically verified.

**Mitigation options:** Introduce mutation testing (e.g., Stryker) that deliberately introduces bugs and verifies tests fail. This validates test quality, not just code quality.

---

### No Fuzzing

Parser tests use controlled inputs — either synthetic logs from `LogScenarioBuilder` or real log fixtures. Adversarial inputs like extremely long lines, malformed UTF-8, null bytes, or pathological regex inputs are not systematically generated.

**Mitigation options:** Add fuzz testing with a tool like SharpFuzz to generate adversarial parser inputs. Focus on the regex-heavy parsing code in `LinuxIptablesParser` and `LinuxNftablesParser`.

---

### Real Log Fixtures May Not Cover All Formats

The five sample log files (`iptables-attack.log`, `nftables-traffic.log`, `large-portscan.log`, `iptables-mixed-prefixes.log`, `golden-compromise-timeline.log`) represent specific kernel versions and iptables configurations. Different distributions, kernel versions, and logging configurations may produce different field orderings, additional fields, or different timestamp formats.

**Mitigation options:** Expand the fixture collection with logs from diverse Linux distributions (Ubuntu, RHEL, Alpine, Arch) and kernel versions. Accept community-contributed fixtures.

---

### No Concurrency Tests

The `SentryAnalyzer` and individual detectors are not tested under concurrent access. Current detectors return warnings through `DetectionResult` rather than a shared warning interface, but concurrent analysis is still worth exercising because detector implementations may evolve and analyzer dependencies are shared across a run.

**Mitigation options:** Add concurrency tests that run analysis on multiple threads simultaneously and verify no exceptions or data corruption occur. Alternatively, document that detectors are not thread-safe and must be instantiated per analysis.

---

## Improvement Roadmap

| Improvement | Description | Priority |
|---|---|---|
| Code coverage enforcement | Add `coverlet.collector`, enforce 80%+ line coverage in CI | High |
| Mutation testing | Add Stryker to verify tests catch deliberate bugs | Medium |
| Parser fuzzing | Add SharpFuzz to generate adversarial parser inputs | Medium |
| Expanded log fixtures | Add samples from diverse Linux distributions and kernel versions | Medium |
| Concurrency testing | Add multi-threaded analysis tests | Low |
| Performance trend tracking | Record test execution times and alert on regressions | Low |
| UI end-to-end tests | Add Avalonia integration tests that verify rendered output | Low |
| Property-based testing | Use FsCheck to generate random valid/invalid log inputs | Medium |

---

## Security Takeaways

1. The test suite validates key detection pathways but does not enforce coverage, leaving some code paths untested
2. Mutation testing would provide the strongest validation of test quality — proving tests catch real bugs, not just confirm happy paths
3. Fuzz testing would address the most dangerous gap — adversarial parser inputs that could cause crashes or incorrect event construction
4. Expanding real log fixtures to cover diverse Linux distributions would improve parser robustness confidence
5. The improvement roadmap prioritizes coverage enforcement and mutation testing as the highest-impact additions
