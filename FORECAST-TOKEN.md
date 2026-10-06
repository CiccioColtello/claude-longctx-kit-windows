# Token forecast (falsifiable)

A token-cost model for the longctx kit, with worked scenarios, sensitivity notes, a
negative scenario, and instructions to verify or refute each claim on your own data.

Sources are tagged inline:

- `[code: <file>, <symbol>]` — a value or behavior read in the shipped code.
- `[measured: token-analysis-raw.txt, 2026-10-06]` — data measured on the maintainers'
  reference workspace (main-loop transcripts of a project that had been running this
  architecture for about two days). Method and caveats below.
- `[assumption: <reasoning>]` — a step that is **not** measured. Never treat these as
  measurements.

## 0. Measurement provenance and caveats

The measured figures used here come from summing fields in Claude Code session
transcripts with `grep` + `awk` — **not** a full JSON parse. The source declares its
own gaps, which are repeated here because they bound every claim built on it:

- Session R1: 4,276 assistant messages, 57 MB transcript, `input_tokens` 108,348,616,
  `output_tokens` 8,907,573, `cache_read_input_tokens` 396,237,440
  [measured: token-analysis-raw.txt, 2026-10-06]. "Input-side" total = input + cache
  read = 504,586,056.
- Session R2: 200 assistant messages, 2.4 MB, input 5,706,759, output 427,153, cache
  read 16,603,392; input-side total 22,310,151
  [measured: token-analysis-raw.txt, 2026-10-06].
- Session R3 reported all-zero sums (empty or different format) and is **excluded**
  [measured: token-analysis-raw.txt, 2026-10-06, declared RESTO].
- `cache_creation` was not measured (field not found with the pattern used).
- Subagent transcripts (~320 MB of the ~381 MB total) were **not** summed; the
  delegation numbers in scenario S3 therefore rest partly on an unmeasured share.
- `.agent/archive/`: 946 files, 34 MB [measured: token-analysis-raw.txt, 2026-10-06].

These numbers describe what the *reference workspace* spent overall. They are **not**
the kit's own cost; the kit's cost is derived in section 2 from the code's caps.

## 1. Baseline model: where tokens can and cannot appear

### 1.1 Session-start injection (the only model-context cost)

| Component | Cap | Source |
|---|---|---|
| Whole injected block | 6000 chars | [code: Invoke-SessionStart.ps1, `$MAX_TOTAL = 6000`] |
| `CONTEXT.md` extract | 1400 chars | [code: Invoke-SessionStart.ps1, `$MAX_CONTEXT`] |
| `STATE.md` extract | 1500 chars | [code: Invoke-SessionStart.ps1, `$MAX_STATE`] |
| `Next action` block (emitted first) | 600 chars | [code: Invoke-SessionStart.ps1, Limit-Text -Max 600] |
| Last 2 decisions | 1300 chars | [code: Invoke-SessionStart.ps1, `$MAX_DECISIONS`] |
| Last 3 failure rows | 700 chars | [code: Invoke-SessionStart.ps1, `$MAX_FAILURES`] |
| Fixed boilerplate (headers, root/session lines, operational rules) | ~0.9 k chars | [assumption: counted from the literal lines in the file; approximate] |

Tokens from characters: `tokens = chars / r`, with `r` = characters per token.
`r = 4` for English Markdown prose is an **assumption**; the plausible
band is 3.5-4.5 (code and JSON tokenize denser, prose looser). At `r = 4`:

- 6000 chars = 1500 tokens. Band: 1333 (r = 4.5) to 1714 (r = 3.5).

The block is injected at **every** SessionStart event, and the registered matcher is
`startup|resume|clear|compact|fork` [code: Invoke-SessionStart.ps1, header]. So a
session with one startup and `K` compactions pays at most `(1 + K) x 1500` tokens of
injection.

Only this hook injects model context: the other hooks write to disk and emit
user-facing `systemMessage` status [code: Write-HookJson call sites across the hooks].

### 1.2 Per-compaction snapshot (disk, not context)

`PreCompact` writes, before any network call: full `STATE.md` (uncapped), last 2
decisions (tail-capped at 1500 chars), last 5 failure rows, and the user's compaction
instructions (capped at 1200 chars); the optional digest is appended afterwards
[code: Invoke-PreCompact.ps1, snapshot composition]. This file is **never injected**
into the model context; its cost is disk only.

- Disk per archive, reference mean: 946 files / 34 MB ~= **36-37 KB per file**
  [derived from measured: token-analysis-raw.txt, 2026-10-06; 34 MiB x 1,048,576 /
  946 = 37,686 B].
- Model-context tokens per snapshot: 0.

### 1.3 Digest (local compute, never API tokens)

When Ollama is reachable, the digest prompt is the fixed instruction (~300 chars
~= 75 tokens at `r = 4`) plus up to 60,000 chars of redacted transcript tail
[code: Invoke-LocalDigest.ps1, `OLLAMA_DIGEST_MAX_INPUT = 60000`]:

- Prompt: <= 60,000 chars ~= **<= 15,000 tokens** at `r = 4` (<= 17,143 at r = 3.5).
- Completion: `num_predict = 1200` -> **<= 1200 tokens** [code: Invoke-LocalDigest.ps1].
- Context window: `num_ctx` default 32768 [code: Invoke-LocalDigest.ps1].
- Timeout: client clamped to at most 45 s, inside a 60 s hook budget
  [code: Invoke-LocalDigest.ps1; code: templates/project-settings.example.windows.json].

Model choice (8 GB -> `qwen3:4b` default, 12-16 GB -> `qwen3:8b`, 24 GB ->
`qwen3:14b`, 32 GB -> `qwen3:32b` / `qwen3:30b-a3b`
[measured: model-variants-DRAFT.md, 2026-10-06]) changes **speed and quality, not
token counts**: the caps above are identical for every model. A model that cannot
finish within the 45 s clamp always degrades to the declared fallback.

## 2. Scenarios

### S1 — Short session, no compaction (20-40 minutes)

Mechanism: one SessionStart injection; no PreCompact/PostCompact; failure rows only
if a tool fails.

Inputs:

- Injected chars `I = B + min(C,1400) + min(S,1500) + min(D,1300) + min(F,700)`,
  `B` ~= 900 [assumption, approximate].

(The real assembly caps the STATE part at 1500 chars *including* the separately
emitted `Next action` block plus 120 chars of overhead, and applies the 6000-char cap
to the final text [code: Invoke-SessionStart.ps1, `$budget` and final `Limit-Text`];
the formula above is the ceiling approximation used throughout these scenarios.)
- Fresh project (shipped templates): `CONTEXT.md` = 343 bytes, `STATE.md` = 715 bytes
  [measured: shipped templates (`core/templates/agent`), byte count 2026-10-06], no decisions/failures.

Arithmetic (fresh): `I = 900 + 343 + 715 = 1958` chars; tokens = 1958 / 4 = **~490**.
Arithmetic (busy project, caps saturated): `I = 6000`; tokens = **1500** (band
1333-1714).

Result: **~0.5 k - 1.5 k tokens per start event**, no snapshot, no digest, no savings.

Sensitivity: linear in injected chars. `r` moves the result by about +/-12%; a second
start event (`resume`/`clear`) doubles the cost; an oversized `STATE.md` cannot push
the block past the 6000-char cap, it only changes what is omitted.

### S2 — 4-hour session, 3 automatic compactions

Mechanism: 1 startup + 3 post-compaction injections; 3 snapshots; up to 3 digests.

Inputs:

- Start events: `1 + K = 4` [code: matcher includes `compact`].
- Injection, worst case: `4 x 6000 = 24,000` chars = **6000 tokens** at `r = 4`.
- Injection, working estimate: ~3500 chars per event
  [assumption: moderate state files] -> `4 x 875` = **3500 tokens**.
- Snapshots: `3 x 37 KB` ~= **111 KB** disk, 0 context tokens
  [derived from measured mean].
- Digests: 3 attempts x (<= 15,000 local prompt tokens + <= 1200 output), local
  compute <= 45 s each [code].

Savings mechanism (this is the point of the kit): after a compaction the model no
longer holds the operational thread. Without state, it re-reads files and re-derives
status. With the kit, the post-compaction injection carries `Next action` (<= 600
chars), the last 2 decisions (<= 1300 chars) and the last 3 failures (<= 700 chars) =
**<= 2600 chars ~= <= 650 tokens** [code: SessionStart caps]. Let `R` be the tokens of
re-exploration actually avoided per compaction:

`net per compaction = R - I_post`, with `I_post <= 650` tokens.

`R` is an **assumption**: 5,000-20,000 tokens per compaction for a real project the
model no longer remembers (rationale: re-reading a handful of source files plus
re-deriving test/status state; a single assistant message in the measured profile
carried ~118 k input-side tokens, so re-exploration turns are not cheap
[derived from measured: 504,586,056 / 4,276 = 118 k, R1]).

Result: gross over the session = `3 x (R - 650)` = **~13 k tokens** (R = 5 k) to
**~58 k tokens** (R = 20 k) avoided, against a paid cost of 3.5 k-6 k tokens. Net of
cost: **~9.6 k to ~54.6 k** with the working injection estimate (3.5 k), or
**~7.1 k to ~52.1 k** against the worst-case injection cost (6 k).

Sensitivity: the result is linear in `R`; doubling `R` doubles net savings. The paid
cost is capped and cannot blow up (6000 chars x events). If `R` ~= 0 — the compaction
summary already carried everything — the scenario flips to a **net cost of
3.5-6 k tokens**. Also note the scale: 6000 tokens of injection is ~0.0012% of the
measured R1 input-side volume [derived from measured] — the kit's value is avoided
re-derivation, not reduced raw volume.

### S3 — Heavy subagent day (6 hours, 6 compactions, 20 delegations)

Mechanism: as S2, plus delegation (each subagent runs in its own context; only its
report returns) and failure memory.

Inputs:

- Start events: `1 + 6 = 7`; worst case `7 x 1500` = **10,500 tokens**; working
  estimate `7 x 900` = **6300 tokens** [assumption, as S2].
- Snapshots: `6 x 37 KB` ~= **222 KB** disk.
- Digests: 6 x <= 45 s local compute.
- Delegations: `N = 20` [assumption]. Per delegation, `F` tokens of reading/log output
  stay inside the subagent and the main loop pays only the report `S`.
  [assumption: F = 20 k-60 k, S = 1.5 k-4 k] -> `F - S` ~= **16.5 k-58 k tokens per
  delegation**, i.e. **~330 k-1.16 M tokens** kept out of the main loop over 20
  delegations.
- Failure memory: injected rows cost <= 700 chars ~= <= 175 tokens; each avoided
  repeat saves its re-discovery cost `Ff` minus 175 [assumption: 3 repeats avoided,
  Ff = 1 k-10 k -> 2.5 k-29.5 k tokens].

Result: dominated by delegation; under the assumptions above, **hundreds of thousands
of tokens** stay out of the main loop. If no delegation happens, S3 collapses to S2.

Sensitivity: linear in `N`, `F` and the repeat-failure rate. The weakest input is `F`:
the reference workspace's subagent transcripts are ~320 MB of ~381 MB total
[measured: token-analysis-raw.txt, 2026-10-06], which proves heavy subagent use but
**was not summed into tokens** (declared RESTO). Treat all of S3 as directional, not
as a measurement.

## 3. SAVINGS mechanism, per scenario, and how to check it

| Scenario | Mechanism | Quantified? | Verification recipe |
|---|---|---|---|
| S1 | None (state continuity only across sessions) | No | A/B a short task with hooks removed |
| S2 | Post-compaction re-injection of `Next action` + decisions + failures replaces re-exploration/re-reading | Only as `R - 650`, `R` assumed | Measure `input_tokens` of the first post-compaction assistant message vs the pre-compaction baseline; A/B with hooks removed |
| S3 | Delegation keeps file/log tokens inside subagent contexts; failure memory prevents repeat failures | Only under assumptions on `F`, `N` | Compare main-loop tool-result tokens during a delegation turn with the subagent transcript size; count duplicate failure rows in `FAILURES.md` |

Unquantified effect (no data to support a number): a smaller main-loop context can
delay the next compaction, which reduces both injection events and re-derivation.
State it as a plausible second-order effect, not a forecast.

## 4. NEGATIVE scenario: when the kit costs more

Honest cases where the kit is a net cost:

1. **Trivial sessions.** A 10-minute question pays 0.5-1.5 k tokens of injection and
   a hook invocation (budget 15 s, usually sub-second) for no benefit. Every
   `resume`/`clear` pays again.
2. **Tiny/fresh projects.** The injection is boilerplate plus empty templates
   (~0.5 k tokens); the state files carry nothing useful yet.
3. **Compactions nobody reads.** Up to 45 s of local compute per compaction (60 s hook
   budget) and ~37 KB of disk per snapshot [derived from measured mean], even if the
   user never opens `.agent/archive/`.
4. **No Ollama installed.** Fast failure, but the fallback path appends a failure row
   on every compaction [code: Invoke-PreCompact.ps1, `digest-local-fallback`], so
   `FAILURES.md` becomes noisy and the injected "last 3 failures" may be all digest
   fallbacks.
5. **Disk growth.** Archives are not pruned: ~37 KB per compaction is ~111 KB/day for
   a 3-compaction daily session, ~40 MB/year [derived from measured mean].
6. **Sensor enabled (opt-in).** Adds a 20 s-budget hook to every matched tool call and
   the false-positive risk documented in `KNOWN-ISSUES.md` (issues 1-2). This is why
   it is not wired by default.

Rule of thumb: **below roughly one compaction per multi-hour session, the kit is a
small net cost**; above it, the savings mechanism in S2 starts to dominate.

## 5. How to verify on your own data

1. **Injection size.** Locate the block between `[AGENT_CONTEXT]` and
   `[/AGENT_CONTEXT]` in a session with a populated `.agent/`, count its characters,
   divide by your measured chars/token ratio. The cap claim is refuted if it exceeds
   6000 characters.
2. **Archive sizes.** PowerShell:
   `Get-ChildItem .agent/archive | Measure-Object -Property Length -Sum -Average`;
   POSIX: `ls -l .agent/archive | awk '{s+=$5;n++} END {print s/n}'`. Compare with the
   ~37 KB mean used here.
3. **Digest behavior.** Open the newest `.agent/archive/*-precompact.md`. The header
   records either `Local digest (model <model>, <N>s)` or
   `Local digest NOT available (fallback)` with the reason. Compare `N` with the
   45 s client clamp.
4. **Token accounting.** Claude Code transcripts are JSONL and (with the field names
   used for this forecast's measurements) carry `input_tokens`, `output_tokens`,
   `cache_read_input_tokens` per assistant message. Sum "input-side" = input + cache
   read, then compare the first post-compaction assistant message with the
   pre-compaction baseline. If a field name differs in your version and the sum comes
   back all-zero (as happened for one session in the source data), record
   "not measurable" — do not substitute an estimate.
5. **A/B.** Keep a copy of `settings.json`, remove the kit's hook entries, run an
   equivalent session, and compare total input-side tokens and time-between-compactions.
   This is the only clean attribution method.
6. **Repeat-failure check.** Count identical `Cause`/`Error` rows in `.agent/FAILURES.md`
   over a week. Each duplicate is a repeat the injected last-3 rows did not prevent.

## 6. Falsification log

Each statement below is a claim of this forecast; each can be checked and refuted by a
reader with their own session.

1. **6000-char cap.** *This forecast is wrong if a normally-populated project's
   injected block ever exceeds 6000 characters* (check: count the characters between
   the markers; the cap is applied to the whole assembled text
   [code: Invoke-SessionStart.ps1, final `Limit-Text -Max $MAX_TOTAL`]).
2. **Post-compaction re-injection.** *This forecast is wrong if SessionStart does not
   fire after a compaction in your setup* (check: presence of a fresh
   `[AGENT_CONTEXT]` block immediately after each compaction; without it, S2's
   4-event arithmetic and its cost/savings both collapse).
3. **Disk arithmetic.** *This forecast is wrong if mean archive size on a
   3-compaction session is below ~18 KB or above ~75 KB* (2x off the ~37 KB mean), or
   if something undocumented prunes the archive directory.
4. **Snapshot-first under a kill.** *This forecast is wrong if, after a PreCompact
   timeout, the newest archive contains no snapshot section* — the design claims the
   snapshot is written before the digest call [code: Invoke-PreCompact.ps1, ordering
   comment]. This failure mode is not covered by the shipped automated tests.
5. **Cost floor.** *This forecast is wrong if a trivial no-compaction session shows a
   kit-attributable delta above ~3000 tokens per SessionStart event on your meter*
   (2x the 1500-token worst case at `r = 4`; measure A/B).
