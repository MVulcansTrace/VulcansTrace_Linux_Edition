# VulcansTrace UI v2 — Wireframe Spec (DRAFT, iterating)

Status: **Phase 3 implemented (2026-07-19)** — unified single hero input with
Chat↔Analyze intent flip (LogSnippetDetector), prompt chips + slash palette in
the hero, query-cancel in the status bar, and the icon rail with click-opened
group flyouts (M3 machine mode pins the sidebar expanded). Phase 1 shipped
2026-07-18, Phase 2 2026-07-19. **VTCU harness sync (Phase A) + live UI review
done 2026-07-20** (findings A–E recorded in the Phase 3 amendments below; B
fixed). Phase 4 open.

> ## Amendments discovered during Phase 1 implementation
> 1. **No toasts exist.** Transient feedback was modal `IDialogService.ShowMessage`
>    dialogs; M3 machine mode suppresses *informational* modals instead of the
>    specced "toasts → journal" (errors/confirmations stay modal).
> 2. **Hero is titled "New analysis"**, not "What would you like to check?" —
>    the agent chat welcome overlay already owns that line; duplicating it was
>    worse. Single-box Chat↔Analyze intent flip deferred (open question #1).
> 3. **Cancel Export lives in the status bar** next to Cancel (both busy-gated),
>    not in the Session tools menu — menu items vanish when the flyout closes,
>    which made busy-state assertions impossible.
> 4. **M2 shape:** receipts ride `last_action` in the AppStateNode payload plus
>    `EvidenceExported` journal entries (the Avalonia app previously logged
>    nothing for exports — CLI-only).
> 5. **Platform facts measured live (Avalonia 12.0.5/Linux):**
>    `AutomationProperties.AutomationId` never reaches AT-SPI (1/180 nodes);
>    accessible NAME is the live selector currency. Fully transparent
>    (Opacity=0) elements get no automation peer. A TextBlock's peer reports
>    its `Text` as the name, so AppStateNode's JSON rides the Text binding.
> 6. **Icon rail deferred to Phase 2** (flyout a11y needs validation; groups
>    shipped expanded-by-default instead).
> 7. **Computer-Use scene fusion fix** (found via this redesign): paragraph
>    text could be absorbed by the window node, swallowing short control labels;
>    fixed via ranking (text match → tightness) + length-bounded substring
>    matching.
>
> ## Amendments discovered during Phase 2 implementation
> 1. **AT-SPI tree freezes at startup for list items.** On Avalonia 12.0.5/Linux,
>    items added to an ItemsControl after the initial tree sync never get
>    automation peers (verified with cards, plain chat sends, and a resize
>    nudge; `childCount` of the chat list stays frozen). Dynamic thread content
>    is therefore asserted via OCR-visible text in scenarios; peer names only
>    work for startup content. Per-kind ids still ship on the card controls —
>    they light up the day the bridge syncs properly.
> 2. **Chat ListBox is non-virtualizing now.** Virtualization dropped peers for
>    off-viewport items; the thread is bounded, so every item stays realized
>    (and OCR-visible when scrolled to).
> 3. **Welcome message is removed on first card post** and card posts force the
>    chat scroll-to-end — the near-bottom gate stranded the view at the top
>    because cards arrive without a preceding user message.
> 4. **Results-state compaction:** once a thread exists, the hero intro and
>    advisor tip collapse (summary card supersedes the tip) and the agent
>    header subtitle hides — the thread was squeezed to a 28px viewport by
>    hero + agent chrome before this.
> 5. **Finding cards carry the RuleId as visible muted text** — peer names
>    can't be reached (amendment 1), so the machine-legible identifier is
>    on-screen text readable by OCR.
> 6. **Scenario action coords are window-relative.** The harness adds the
>    window origin before driving xdotool; the summary-card scenario scrolls
>    the thread with window-relative coords.
> 7. **Summary card posts on BOTH analysis paths** (log paste and agent audit);
>    before, the log-paste path never wrote to the agent thread at all.
> 8. **Hero chat↔analyze flip and icon rail deferred to Phase 3** (user call):
>    the two-box split stays; prompt chips land with the flip since their
>    content depends on it.
>
> ## Amendments discovered during Phase 3 implementation
> 1. **Single-box Chat↔Analyze flip SHIPPED** (resolves Phase-1 amendment #2 +
>    open question #1's first half, and supersedes Phase-2 amendment #8's
>    deferral): one `HeroInputBox` replaces the log box + chat box;
>    `LogSnippetDetector` (≥3 log-looking lines → Analyze, else Chat) drives the
>    primary button; prompt chips fill without sending; the slash palette moved
>    into the hero; query-cancel moved to the status bar. NOTE: analysis results
>    can no longer be wiped by a chat send — invalidation is gated to log
>    changes only.
> 2. **Icon rail SHIPPED with group flyouts** (resolves Phase-1 amendment #6 +
>    open question #5): `SidebarCollapseToggle` collapses 220→56px; the four
>    group buttons open `MenuFlyout`s re-using the nav `ListBoxItem`s (same
>    AutomationIds, re-parented, as §3 specced). M3 machine mode pins the
>    sidebar expanded, so the contract/scenarios never see the rail.
> 3. **Live UI review (2026-07-20, driven via VTCU) — findings → dispositions:**
>    - **(A) Split input/output IA** — input is pinned top (hero) while the
>      transcript sits in the agent card below, so the reading surface is
>      squeezed under stacked chrome and the eyes jump per turn. NOT changed in
>      Phase 3; recorded as a design principle — *input lives with its thread* —
>      that gates Phase 4 (any new surface taking input must colocate it with
>      its thread). A full relocation of the existing hero input is deferred,
>      gated on hands-on/CI evidence (results-state hero compaction already
>      softens it).
>    - **(B) Empty-state redundancy + stale microcopy + duplicated identity** —
>      FIXED 2026-07-20: the agent-panel header no longer repeats the name +
>      status the status bar carries (now an onboarding avatar+tagline strip
>      that hides when a thread is active), and the empty-state line that read
>      "type your own question below" now points at the hero input above.
>    - **(C) Sidebar section-header hierarchy inversion** — SHIPPED 2026-07-20:
>      the loud blue group bars were the default theme painting the group
>      toggle's *checked* (expanded) state on its template ContentPresenter; a
>      `/template/ ContentPresenter#PART_ContentPresenter` override keeps the
>      header quiet, so the accent now belongs to the selected item only.
>    - **(D) Icon-rail discoverability** — SHIPPED 2026-07-20 (active-indicator
>      half): the rail button now carries a left-accent bar that tracks the
>      selected page's group (same left-accent language as the expanded sidebar)
>      via a new `NavigationGroup.IsActive`, and its tooltip is bound to the
>      group name. The flyout still light-dismisses on window re-activation (a
>      static observe never sees it — the harness asserts it via in-act
>      `control_added`); that part is unchanged.
>    - **(E) Disabled buttons read as "broken" / transcript right gutter /
>      persistent collapsed Agent Tools bar in results state** → DEFERRED to the
>      finding-A / Phase-C layout decision: E2/E3 sit in the same hero/transcript
>      zone as the deferred split-input/output rework (A), so doing them now
>      risks rework, and E1 (disabled-button hints) is marginal/speculative.
>      Not in the 2026-07-20 polish pass (C + D shipped; see that commit).
> 4. **OCR-disambiguation gotcha (harness, tied to B):** the empty-state
>    microcopy contains the substring "Agent Tools", so an unregioned
>    `click_text "Agent Tools"` matches it instead of the toggle bar; the
>    harness now region-constrains that click. Not a product defect — recorded
>    so future OCR drives region-constrain around the empty-state copy.
>

Source: discussion 2026-07-18 (crowding critique + user blueprint v1 + recommendations).

Design goals:
1. Two zones (nav sidebar + content) — the left control panel dies.
2. Agent-first home: the hero *is* the log input and the chat input.
3. One canonical home per action — zero duplicate accessible names.
4. Computer-Use legibility is a build-time contract, not a hope.

---

## 1. Agent home — empty state

```
┌──────────────────┬────────────────────────────────────────────────────────────────────┐
│ ◇ VulcansTrace   │ 🛡 Security Agent            ● Online              [⋯ Session ▾]  │ ← (A)
│              [≪] │                                                                    │
├──────────────────┼────────────────────────────────────────────────────────────────────┤
│                  │ ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐        │
│ ▾ ANALYSIS       │ │🔍 Findings │ │⚠ High/Crit │ │⚠ Warnings  │ │⛔ Parse Err│ ← (B)  │
│   Agent        ● │ │     0      │ │     0      │ │     0      │ │     0      │        │
│   Findings       │ │ cur. scan  │ │ cur. scan  │ │    none    │ │    none    │        │
│   Timeline       │ └────────────┘ └────────────┘ └────────────┘ └────────────┘        │
│   Incident Story │                                                                    │
│                  │ What would you like to check?                              ← (C)  │
│ ▾ MANAGEMENT     │ ┌────────────────────────────────────────────────┐ ┌───────────┐   │
│   Rules          │ │ Ask anything, or paste firewall log lines…     │ │ 💬 Chat   │ ← (D)
│   Threat Intel   │ └────────────────────────────────────────────────┘ └───────────┘   │
│   Suppressions   │ [ Scan latest auth.log ] [ Why is port 443 flagged? ] [ Sweep rest ] │
│   Coverage       │                                                     chips ← (E)    │
│   Compliance     │ ▸ Scan options                                             ← (F)   │
│   Risk           │                                                                    │
│                  │                                                                    │
│ ▾ OPERATIONS     │                                                                    │
│   Schedules      │                                                                    │
│   Notifications  │                                                                    │
│   Live Stream    │                                                                    │
│   Doctor         │                                                                    │
│                  │                                                                    │
│ ▾ SYSTEM         │                                                                    │
│   Analyst Log    │                                                                    │
│   Parse Errors   │                                                                    │
│   Logs           │                                                                    │
└──────────────────┴────────────────────────────────────────────────────────────────────┘
```

## 2. Agent home — results state (hero morphed, input NEVER moves)

```
┌──────────────────┬────────────────────────────────────────────────────────────────────┐
│ ◇ VulcansTrace   │ 🛡 Security Agent      ● Analyzing… 40%  [Cancel]  [⋯ Session ▾]  │ ← (G)
├──────────────────┼────────────────────────────────────────────────────────────────────┤
│                  │ ┌────────────────────────────────────────────────┐ ┌───────────┐   │
│  (nav unchanged) │ │ 42 log lines pasted — analyze this             │ │ 🚀 Analyze│ ← (D')
│                  │ └────────────────────────────────────────────────┘ └───────────┘   │
│                  │ ── Analysis · Jul 18 16:42 · Medium · Workstation ─────────────     │
│                  │ ┌──────────────────────────────────────────────────────────────┐    │
│                  │ │ 🤖 Done. 9 findings — 7 High/Critical, 1 warning.            │    │
│                  │ │ [ Findings 9 ] [ High/Crit 7 ] [ Warnings 1 ] [ Errors 0 ]   │ ← (H)
│                  │ └──────────────────────────────────────────────────────────────┘    │
│                  │ ┌──────────────────────────────────────────────────────────────┐    │
│                  │ │ 🔴 CRITICAL · Port Scan                            12:00–12:20│ ← (I)
│                  │ │ Port scan detected from 45.33.32.156 → multiple ports         │    │
│                  │ │ [ Open in Findings ]                          [ Suppress ▾ ]  │    │
│                  │ └──────────────────────────────────────────────────────────────┘    │
│                  │ ┌──────────────────────────────────────────────────────────────┐    │
│                  │ │ 🟠 HIGH · C2 Channel · interval-beacon pattern …              │    │
│                  │ └──────────────────────────────────────────────────────────────┘    │
│                  │ ▸ 6 more findings — open Findings view                     ← (J) │
│                  │                                                                    │
│                  │  …follow-up agent messages append here…                            │
└──────────────────┴────────────────────────────────────────────────────────────────────┘
```

## 3. Sidebar collapsed to icon rail (SplitView compact mode)

```
┌─────┐
│ ◇   │   Logo
│ [≫] │   Expand toggle (AutomationId: SidebarCollapseToggle)
│ 🔍  │   ANALYSIS group — click opens flyout with the 4 items
│ 🛡  │   MANAGEMENT group flyout
│ ⚙  │   OPERATIONS group flyout
│ ℹ   │   SYSTEM group flyout
└─────┘   Flyout items are the SAME ListBoxItems (same AutomationIds), re-parented.
```

## 4. Findings view — banner cards replace global banners

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ Findings                                                                      │
│ ┌──────────────────────────────────────────────────────────────────────────┐ │
│ │ ⚠ 1 warning detected during analysis — [View]                  [✕ Dismiss]│ │ ← (K)
│ └──────────────────────────────────────────────────────────────────────────┘ │
│ [ All severities ▾ ] [ All rules ▾ ] [ Search findings…            ]        │
│ ───────────────────────────────────────────────────────────────────────────  │
│ 🔴 Port Scan · CRITICAL · 45.33.32.156 → multiple ports · 12:00–12:20        │
│ 🟠 C2 Channel · HIGH · beacon pattern · interval 60s ± 0.5                   │
│ …                                                                            │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Annotations

### (A) Status bar
- Always visible, all views. Left: agent identity. Center: status text.
- Status states: `● Online` (idle) / `● Analyzing… {pct}%` (busy) / `● Offline` (no LLM).
- Right: `⋯ Session tools` MenuFlyout = Export Evidence, Compare Logs, Copy Signing Key.
  One canonical home each; ids unchanged from today (`ExportEvidenceButton` etc.) so existing scenarios keep working.
- Replaces: floating "Working..." text, the WrapPanel button row, the HMAC card's duplicate
  "Copy signing key".

### (B) KPI strip — 4 cards
- Dropped: Skipped Lines (moves to System → Logs page as a detail row).
- Calm when zero (muted, no glow); severity accent glow only when nonzero.
- Every card is a Button, click-through to Findings with the matching filter applied.
  Ids: `KpiFindingsCard`, `KpiHighCriticalCard`, `KpiWarningsCard`, `KpiParseErrorsCard`.

### (C) Hero header
- "What would you like to check?" — shrinks/collapses once a thread exists (animation, one-way).
  The input box does NOT move when this happens.

### (D) Hero input — the core element
- `AutomationId: HeroInputBox`, multiline-capable, fixed position under the header.
- Intent detection (ViewModel heuristic): ≥3 pasted lines matching syslog/firewall patterns
  → primary button label flips `Chat` → `Analyze` (`HeroPrimaryButton`).
  Deterministic: same content, same label. No hidden modes.
- Fallback if users find the flip confusing: two chips above the box (`Ask` / `Analyze a log`).
  Decide after first hands-on.
- Scan options (intensity, machine role) ride along on Analyze; defaults come from settings.

### (E) Suggested-prompt chips
- `WrapPanel` of prompt Buttons (`PromptChipItems`), NOT filters. Filters live in Findings.
- Content: static list first; later, context-aware (e.g., after analysis: "Triage Criticals first").
- Clicking a chip fills the input box (does NOT auto-send).

### (F) Scan options row
- Collapsed by default (`ScanOptionsExpander`, named toggle!). Contains Intensity + Machine role combos
  (ids unchanged: `IntensityComboBox`, `MachineRoleComboBox`) + `Advanced…` button opening a dialog
  with the 13 numerics (they leave the sidebar forever).
- Session HMAC key info moves into the Advanced dialog (read-only masked) + Session tools menu (copy action).

### (G) Busy state
- Status center becomes `Analyzing… {pct}%`; `Cancel` button appears next to it ONLY while busy —
  declared `runtime-gated` in the manifest (pattern already established).
- Everything else stays put. No panel collapses during busy (kills the tools-panel auto-collapse bug class).

### (H) Summary card
- First thread entry after an analysis. KPI chips are the same click-through actions as (B).
- `AutomationId: AnalysisSummaryCard`; chips reuse KPI ids + `Summary` prefix
  (`SummaryFindingsChip`, …) — no name collision with (B).

### (I) Finding cards (inline in thread)
- Top N (≤3) findings rendered as cards: severity dot, rule name, one-line evidence, time range.
- Actions: `Open in Findings` (deep link, applies filter), `Suppress ▾`.
- Ids: `FindingCard{RuleId}`, `FindingCardOpen{RuleId}`, `FindingCardSuppress{RuleId}`.

### (J) "6 more findings" link
- Deep link to Findings view, unfiltered. `AutomationId: ThreadMoreFindingsLink`.

### (K) Findings banner cards
- Global warnings/parse-error banners die. They become dismissible cards at top of the Findings view,
  plus one agent thread message linking there.
- `AutomationId: FindingsWarningsCard`, `FindingsParseErrorsCard`, dismiss = `…DismissButton`.
- KPI cards + nav aliases stay single-sourced (no "Warnings" nav item).

---

## Computer-Use contract (baked into Phase 1, not retrofitted)

1. Every actionable element has an `AutomationProperties.AutomationId` and a unique
   `AutomationProperties.Name`. CI test walks the live a11y tree and fails on violations
   (missing id, duplicate name among actionables).
2. Nav group headers are real ToggleButtons with ids: `NavGroupAnalysisToggle`,
   `NavGroupManagementToggle`, `NavGroupOperationsToggle`, `NavGroupSystemToggle`.
3. Runtime-gated elements (only `CancelAnalysisButton`, busy progress) are declared in
   `features/vulcanstrace.scenarios.json` as runtime-gated.
4. Timeline keeps its canvas, but ships an accessible companion list
   (`TimelineEventsList`, invisible-to-sighted-users option: collapsed by default,
   expands as a normal list view of the same events).
5. No interactive text below ~11px (OCR floor). Muted decorative text exempt.
6. Prefer `IsEnabled=False` over `IsVisible=False` for anything a script might target.
7. One canonical name per action, repo-wide (dedup test in #1 covers it).

The contract above makes the UI *findable*. The three affordances below (M1–M3)
make it *self-describing* — state that is told, not inferred. Each kills a
failure class from the Computer-Use saga.

## Machine legibility (the "walk in the park" layer)

Not pixel work — app-side affordances layered on top of the contract.

### (M1) App state node — told, not inferred
- One hidden-but-accessible node at the root of the a11y tree,
  `AutomationId: AppStateNode`, carrying a compact JSON snapshot:
  `{"view":"agent","busy":false,"last_op":"analyze","last_result":"ok","findings":9,"high_critical":7,"warnings":1}`
- Updated from a single choke point in MainViewModel on every state transition.
- Readiness assertions become `wait until state.busy == false` instead of OCR
  polling / quiescence windows. Kills: settle/wait tuning, the "22 seconds
  later" race class.
- `AgentStatusIndicator` (visible status-bar text) is the human projection of
  the SAME state — one source of truth, two renderings, never divergent.
- Payload is append-only across versions: add fields, never rename or remove.

### (M2) Action journal feed — outcome receipts
- The Analyst Action Log already records operations; promote it to a machine
  feed with structured entries: `{op, status, detail}`, e.g.
  `export_evidence → ok → /path/evidence.zip`.
- Exposed as `ActionJournalList` with per-entry `ActionJournalEntry` ids.
- Assertions read the receipt instead of verifying side effects. Filesystem/zip
  verification stays, but as a separate integrity check — not the primary signal.
- Kills: the export-verification assertion class that forced zip support into
  the harness.

### (M3) Machine mode — `VT_MACHINE_MODE=1`
- One env flag (same philosophy as the `VT_SCENARIO_ID` export hook) rendering
  the deterministic variant of the SAME app:
  - animations off (instant settle)
  - toasts/transient notifications become journal entries (see M2)
  - popups/flyouts render as inline panels where feasible
  - identical views, ids, commands, and state machine — presentation only
- Honest tradeoff: machine-mode runs prove bindings, commands, and flows — not
  the pretty pixels. A small set of human-mode smoke scenarios covers rendering.
- Kills: popup-outside-the-a11y-tree sagas, animation-timing flakes, toast races.

### Phasing note
M1 and M3 are cheap (one ViewModel choke point + env-flag branches at
presentation seams). M2 mostly exists — it needs structured entries and stable
ids. All three land in Phase 1 next to the contract test, so scenarios written
against v2 target them from day one.

## Element inventory (ids stable from day one)

| Element                    | AutomationId                | Notes                              |
|---------------------------|-----------------------------|------------------------------------|
| Sidebar nav list          | `PrimaryNavigationList`     | unchanged from today               |
| Sidebar collapse toggle   | `SidebarCollapseToggle`     | new                                |
| Group toggles             | `NavGroup{Group}Toggle`     | new, ×4                            |
| Agent status text         | `AgentStatusIndicator`      | new                                |
| Session tools menu        | `SessionToolsMenu`          | new flyout host                    |
| Export Evidence           | `ExportEvidenceButton`      | moved, id unchanged                |
| Compare Logs              | `CompareLogsButton`         | moved, id unchanged                |
| Copy Signing Key          | `CopySigningKeyButton`      | moved, id unchanged; HMAC dup dies |
| KPI cards                 | `Kpi*Card` ×4               | now buttons (click-through)        |
| Hero input                | `HeroInputBox`              | new                                |
| Hero primary button       | `HeroPrimaryButton`         | label Chat ↔ Analyze               |
| Prompt chips              | `PromptChipItems`           | new                                |
| Scan options expander     | `ScanOptionsExpander`       | named toggle                       |
| Intensity / Machine role  | `IntensityComboBox`, `MachineRoleComboBox` | unchanged      |
| Advanced scan dialog      | `AdvancedScanOptionsButton` → dialog | 13 numerics move here   |
| Cancel (busy only)        | `CancelAnalysisButton`      | runtime-gated                      |
| Thread list               | `AnalysisThreadList`        | new                                |
| Summary card + chips      | `AnalysisSummaryCard`, `Summary*Chip` | new                     |
| Finding cards             | `FindingCard*`              | new, per-rule suffixes             |
| Findings banner cards     | `FindingsWarningsCard`, `FindingsParseErrorsCard` | replaces global banners |
| Timeline companion list   | `TimelineEventsList`        | Phase 4                            |
| App state node            | `AppStateNode`              | hidden a11y node, JSON state (M1)  |
| Action journal feed       | `ActionJournalList`, `ActionJournalEntry` | structured receipts (M2) |

## Open questions (iterate here)

1. ~~Chat/Analyze auto-flip vs explicit Ask/Analyze chips~~ — RESOLVED: auto-flip
   shipped in Phase 3 (LogSnippetDetector: ≥3 log-looking lines → Analyze, else
   Chat); explicit Ask/Analyze chips remain the documented fallback, gated on
   hands-on/CI evidence (not built preemptively).
2. ~~Cancel placement~~ — RESOLVED: status bar, next to Cancel (busy-gated).
3. Prompt chips: static list vs context-aware rotation. Start static.
4. "Logs" page under SYSTEM: raw log browser + Skipped Lines detail — scope later.
5. ~~Icon-rail flyouts vs always-expanded rail on wide screens~~ — RESOLVED: rail
   shipped in Phase 3 with click-opened group `MenuFlyout`s re-using the nav
   labels; the always-expanded-on-wide alternative was not implemented; M3
   machine mode pins the sidebar expanded.
6. ~~Active Suppressions location~~ — RESOLVED: Suppressions view owns it (top
   expander), remove button renamed "Remove active suppression" (killed the
   duplicate accessible name).
7. M3 coverage check: does "toasts become journal entries" cover ALL transient UI,
   or are there other popups that need inline-panel treatment? Audit during Phase 1.
   → Phase 1 finding: no toasts exist; informational modals are the only
   transient UI and are suppressed by machine mode.
