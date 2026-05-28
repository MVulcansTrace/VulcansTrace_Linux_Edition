# Novelty Detection — Design Decisions

> The novelty detector embraces simplicity and restraint — it flags singletons with low severity because one connection is a lead, not a conclusion.

---

## Decision 1: Two-Pass Over Single-Pass

**Decision:** Build the complete frequency dictionary first, then iterate to find singletons.

**Rationale:** A single-pass approach cannot correctly identify singletons. If event A connects to IP X and event B (later in the log) also connects to IP X, a single-pass approach would need to retroactively "un-flag" event A. The two-pass approach avoids this by computing the complete frequency table before making any classification decisions.

**Security Rationale:** Incorrect singleton identification would produce both false positives (flagging events that have duplicates) and false negatives (missing events that appear to be unique but later recur). Both errors undermine the detector's forensic value.

**Business Value:** Correct-by-construction algorithm that requires no deduplication or correction logic.

---

## Decision 2: Composite Key (DestIP, DestPort)

**Decision:** Group by the tuple (DestIP, DestPort) rather than DestIP alone.

**Rationale:** The same external IP might host multiple services on different ports. A web server on port 80 (seen 1,000 times) and an SSH server on port 22 (seen once) should be treated differently. Grouping by IP alone would mark the SSH connection as non-novel because the IP is "popular."

**Security Rationale:** Different ports represent different services with different risk profiles. A singleton on port 443 is less interesting than a singleton on port 22 — but both are singletons and both should be flagged for investigation.

**Business Value:** More granular findings give analysts better context for prioritizing investigation.

---

## Decision 3: Low Severity

**Decision:** Assign `Severity.Low` to all novelty findings.

**Rationale:** A single connection to an external destination could be many things: a user visiting a new website, a one-time API call, a DNS resolution, or a legitimate one-off service interaction. Flagging all singletons as high severity would overwhelm analysts.

**Security Rationale:** Severity should reflect confidence, not potential impact. A singleton is a weak signal — it's worth recording but not worth triggering an incident response.

**Business Value:** Findings are available for deep forensic analysis without polluting high-priority alert channels.

---

## Decision 4: Disabled in Low Profile

**Decision:** Set `EnableNovelty = false` in the Low analysis profile.

**Rationale:** On a busy network, singletons are extremely common. Every unique website visit, every one-time API call, every CDN edge node that a user hits once produces a singleton. In a low-sensitivity context, this noise outweighs the signal.

**Security Rationale:** Enabling novelty detection only in Medium and High profiles ensures the detector runs when operators are prepared to handle the volume and have the resources to investigate.

**Business Value:** Default-off in low-sensitivity mode prevents alert fatigue; operators opt in via profile selection.

---

## Decision 5: Configurable Rarity Threshold

**Decision:** Use `NoveltyMaxGlobalOccurrences` (default 1) to control how many occurrences still qualify as "novel."

**Rationale:** Strict singleton detection (`count == 1`) is the strongest novelty signal but misses near-singletons that may still be suspicious (e.g., a destination contacted exactly twice). A configurable threshold allows operators to trade off between precision and recall. The default of 1 maintains strict singleton semantics; raising it to 2–3 catches double-tap and low-volume probing without requiring code changes.

**Security Rationale:** A fixed threshold of 1 is trivially evaded by connecting twice (the "double-tap" evasion). A configurable threshold lets security teams adapt the detector to their threat model without modifying code.

**Business Value:** One detector serves multiple use cases — strict singleton mode for deep forensic analysis, relaxed rarity mode for broader coverage of low-volume suspicious activity.

---

## Summary

| Decision | Trade-off | Security Outcome |
|---|---|---|
| Two-pass algorithm | Higher memory usage | Correct singleton identification |
| Composite (IP, Port) key | More findings | Service-level granularity |
| Low severity | Findings may be deprioritized | Appropriate confidence level |
| Disabled in Low profile | Misses singletons in quick scans | Avoids noise in low-sensitivity contexts |
| Configurable rarity threshold | Tuning required for environment | Adaptable to different noise levels and threat models |
