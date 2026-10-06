# Usage analysis

Who the longctx kit is for, which workflows it changes, what it costs, and what it
does not do.

Scope note: this document describes the kit as shipped. Every quantitative claim is
tagged with its source: `[code: file, symbol]` for a value read in the shipped code,
`[measured: token-analysis-raw.txt, 2026-10-06]` for data measured on the maintainers'
reference workspace, `[assumption: ...]` for a reasoning step that is not measured.

---

## 1. Who this is for

The kit targets one profile: **long Claude Code sessions on a real project**, where
the context window fills up and compaction is part of the normal working day.

Typical users:

- **Multi-hour sessions.** One task that runs for 2-6 hours, with several automatic
  compactions (`PreCompact` / `PostCompact` fire on `manual|auto`
  [code: templates/project-settings.example.windows.json]).
- **Compaction-heavy work.** Refactors, bug hunts, migrations: the kind of work where
  losing "what was I doing and what did I already decide" costs more than the tokens
  the summary saves.
- **Multi-day projects.** Work resumes tomorrow; the state file, not the chat history,
  is the durable artifact.
- **Projects with repeated failures.** The same broken command or failing test comes
  back; a persistent failure log stops the loop.
- **Token-cost-sensitive users.** Large exploration passes are delegated to subagents
  so the main loop holds conclusions, not file dumps.

The kit is *not* a chat-memory product and *not* a security tool. It is a small,
deterministic state layer around Claude Code's own compaction.

## 2. What the kit is, in one paragraph

Hooks persist a project-local state directory (`.agent/` with `STATE.md`,
`DECISIONS.md`, `FAILURES.md`, `CONTEXT.md` and `archive/`). `SessionStart` injects a
bounded extract of that state into the session. `PreCompact` writes a deterministic
snapshot of the state to `.agent/archive/` and optionally adds a digest produced by a
**local** Ollama model. `PostCompact` archives the compaction summary and updates
`STATE.md`. `PostToolUseFailure` appends one redacted failure row. An **opt-in**
`PreToolUse` sensor adds a deny policy for destructive commands and sensitive files
(off by default). Five subagents and three skills are included for delegation. No
project code is required and nothing is sent off the machine: the digest client
accepts only loopback endpoints [code: Invoke-LocalDigest.ps1, Test-LocalOllamaHost].

## 3. Workflows that actually change

### 3.1 Surviving compaction

Without the kit, a compaction substitutes a model-written summary for the raw
history: the operational thread (what is next, what was decided, what already failed)
is whatever the summary happened to keep.

With the kit the sequence is deterministic:

1. **Before** compaction, `PreCompact` writes `.agent/archive/<stamp>-precompact.md`
   containing the **full** `STATE.md`, the last 2 decisions, the last 5 failure rows
   and any user instructions passed to the compaction
   [code: Invoke-PreCompact.ps1, snapshot composition].
2. The snapshot is written **before** the local digest call, so a hook killed during
   the digest still leaves a usable archive [code: Invoke-PreCompact.ps1, ordering].
3. **After** compaction, `PostCompact` writes the summary to the archive and updates
   `STATE.md` with a `Last compaction` section (summary head capped at 400 chars)
   [code: Invoke-PostCompact.ps1, $MAX_SUMMARY and Limit-Text -Max 400].
4. `SessionStart` runs again with matcher `compact` and re-injects the state
   (caps in section 4.2) [code: Invoke-SessionStart.ps1 registration
   `startup|resume|clear|compact|fork`].

So the post-compaction model does not have to reverse-engineer the session; it gets
`Next action` and the latest decisions/failures in a fixed format.

### 3.2 Resuming with `Next action`

The single most useful field is `Next action`. At every session start the hook
extracts it first, emits it as its own block (capped at 600 chars) **before** the rest
of `STATE.md`, and then emits the remainder of the state with a reduced budget
[code: Invoke-SessionStart.ps1, `Next action (explicit excerpt)` + `$budget`].

This changes the resume workflow from "read the last session and guess" to "start from
the line the previous session wrote for you". It also works across `resume`, `clear`
and `fork`, not just after compaction.

### 3.3 Failure memory

Every tool failure that is not a user interrupt appends **one redacted line** to
`.agent/FAILURES.md`: timestamp, component, command (truncated), first line of the
error, cause [code: Invoke-PostToolUseFailure.ps1]. Deduplication is on the last row,
and the file rotates past 300 rows keeping the newest 150
[code: Hook-Common.ps1, Add-FailureRecord, `MaxRows = 300`]. The last 3 rows are
injected at session start (cap 700 chars) [code: Invoke-SessionStart.ps1,
`$MAX_FAILURES = 700`].

The workflow change: a failure that repeats is visible before it is repeated, and the
audit trail of "this was already tried" survives compaction.

### 3.4 Delegation to subagents and skills

Five subagents are shipped (`repo-explorer`, `test-diagnostician`, `log-compressor`,
`context-archivist`, `security-auditor`) plus three skills (`long-context`,
`context-maintenance`, `repo-exploration`). Each subagent runs with its own context
window; only its final report returns to the main loop. The intended pattern is:
"where is X / why does this test fail / what do these 4,000 log lines say" is answered
in a subagent, and the main session keeps the conclusion.

This is where the largest token savings live for exploration-heavy work (mechanism and
arithmetic in `FORECAST-TOKEN.md`, scenario S3), and it is also the most
assumption-dependent part of the forecast.

### 3.5 Local digest (optional)

If a local Ollama instance is reachable, `PreCompact` sends it the redacted **tail**
of the transcript (at most 1,200,000 bytes read; at most 60,000 chars sent, after
truncation marked `[truncated <N> leading characters]`) and stores the reply in the
archive alongside the deterministic snapshot
[code: Invoke-PreCompact.ps1, `$TRANSCRIPT_TAIL_BYTES = 1200000`;
code: Invoke-LocalDigest.ps1, `OLLAMA_DIGEST_MAX_INPUT = 60000`].

Properties, stated honestly:

- **Local only.** Any non-loopback host is refused; redirects are refused
  (fail-closed) [code: Invoke-LocalDigest.ps1, `Test-LocalOllamaHost` and
  `-MaximumRedirection 0`].
- **Best effort, never blocking.** On timeout/absence the compaction proceeds and the
  archive declares the fallback with a reason; the failure is also logged
  [code: Invoke-PreCompact.ps1, `Local digest NOT available (fallback)`].
- **Not a security authority.** It produces text for an archive; it decides nothing.
- **Model sizing.** Default `qwen3:4b`; the intended mapping of available RAM/VRAM to
  model is 8 GB -> `qwen3:4b` (default), 12-16 GB -> `qwen3:8b`, 24 GB -> `qwen3:14b`,
  32 GB -> `qwen3:32b` or `qwen3:30b-a3b`
  [draft: model-variants-DRAFT.md, 2026-10-06 — preliminary sizing numbers, not yet
  validated tier-by-tier on real hardware; treat the mapping as guidance, not as a
  measurement]. Configuration is
  `.agent/ollama.env` (KEY=VALUE, non-secret values only) or the defaults
  [code: Invoke-LocalDigest.ps1, `$script:DigestDefaults`]. A larger model improves
  archive quality, not safety: see `KNOWN-ISSUES.md` for the 45-second client clamp,
  which limits how slow a digest model can be before it always falls back.

## 4. The cost side of the ledger

What the user pays, in latency, tokens and disk.

### 4.1 Hook latency budget per event

Registered timeouts, as shipped:

| Event | Registered timeout | Notes |
|---|---|---|
| `SessionStart` | 15 s | [code: templates/project-settings.example.windows.json] |
| `PostToolUseFailure` | 15 s | same file |
| `PreCompact` | 60 s | internal digest client is clamped to at most 45 s [code: Invoke-LocalDigest.ps1] |
| `PostCompact` | 15 s | same file |
| `PreToolUse` (opt-in) | 20 s | [code: lib/merge-claude-settings.ps1, KitEvents] |

All hooks are **fail-open**: any error path exits 0 with a user-visible message, so a
broken hook cannot block a session [code: catch blocks in all hooks]. The worst case
is a bounded wait, not a hung session.

Practical reading [assumption: not measured here]: on a normal machine the local file
operations (state read/write, failure row, snapshot) should finish in well under a
second; the only event with a real budget is `PreCompact`, and only when a digest model
is slow. Without Ollama, the digest attempt fails quickly (connection refused) and the
snapshot-only archive is written.

### 4.2 Injection tokens per session

- Hard cap on the whole injected block: **6000 characters**
  [code: Invoke-SessionStart.ps1, `$MAX_TOTAL = 6000`].
- Per-section caps: `CONTEXT.md` 1400, `STATE.md` 1500 (of which `Next action` up to
  600 plus 120 chars of overhead), last 2 decisions 1300, last 3 failure rows 700
  [code: Invoke-SessionStart.ps1, `$MAX_CONTEXT` / `$MAX_STATE` /
  `$MAX_DECISIONS` / `$MAX_FAILURES`].
- The block is injected at **every** `SessionStart` event, and the matcher includes
  `compact` [code: Invoke-SessionStart.ps1 registration]. A session with one startup
  and K compactions therefore pays at most `(1 + K) x 6000` characters of injection
  (at a mixed-text ratio of about 4 chars/token
  [assumption: ratio; see FORECAST-TOKEN.md], about 1500 tokens per event, worst
  case).
- Only `SessionStart` injects model context; the other hooks emit user-facing status
  messages and write to disk [code: Write-HookJson call sites].

### 4.3 Disk

- Each compaction adds a snapshot file to `.agent/archive/`. On the reference
  workspace this directory reached **946 files / 34 MB** in about two days of use,
  i.e. about 36-37 KB per archive on average
  [measured: token-analysis-raw.txt, 2026-10-06].
- `FAILURES.md` rotates past 300 rows (keeps 150) and `denied-actions.log` past 500
  rows (keeps 250) [code: Hook-Common.ps1, `Add-FailureRecord` / `Add-DeniedRecord`].
- The archive directory itself is **not** pruned automatically (see
  `KNOWN-ISSUES.md`). Archives are plain Markdown; deleting them by hand is safe.

### 4.4 What is *not* paid

- The snapshot and the digest never enter the model context: they are written to
  `.agent/archive/`. There is no API-token cost for them.
- The digest runs on your machine: the cost is local compute and up to 45 s of wall
  clock per compaction when a model is configured and slow.

## 5. Qualitative scenarios

**Bug hunt across two days.** Day 1: reproduce, narrow, write `Next action`. Day 2:
the first thing injected is that `Next action`, plus the last failures, so the session
does not restart with a re-exploration pass. The archive from the Day-1 compaction is
still on disk if the human wants the fuller picture.

**Multi-hour feature with 3 compactions.** Each compaction: snapshot written first,
optional digest added, then a re-injection of up to 6000 chars. The thread survives;
the cost is bounded and predictable (section 4.2).

**Log-heavy triage day.** Large build/test outputs are pushed to `log-compressor`;
the main loop holds the actionable lines. Failures that repeat are in `FAILURES.md`
and are injected at the next start.

**Long-lived project.** `CONTEXT.md` describes structure and commands so it does not
have to be re-derived; `DECISIONS.md` records durable choices so they are not
re-litigated after every compaction.

## 6. Adoption notes

- **Zero code changes.** Nothing in the project is modified except `.claude/` and the
  new `.agent/` directory. A `.gitignore` fragment is shipped for projects that do not
  want `.agent/` in version control
  [code: templates/gitignore-fragment.txt].
- **5-minute install.** Copy the kit, run the installer (dry-run by default;
  `-Apply` to execute), which performs a **non-destructive, idempotent** merge of the
  hook entries and the `permissions.deny` fragment into an existing `settings.json`:
  existing hooks, keys and deny rules are left untouched, and an unreadable JSON file
  is an error rather than an overwrite [code: lib/merge-claude-settings.ps1, header
  and param block; CHANGELOG.md 0.1.0]. Exact commands: see `README.md`.
- **Sensor off by default.** The `PreToolUse` policy sensor is only wired with the
  opt-in switch (`-WithSensor`); the default install uses Claude Code's native
  `permissions.deny` rules [code: lib/merge-claude-settings.ps1, `optIn = $true`].
- **Digest off by default.** No Ollama, no digest; everything else behaves identically
  [code: Invoke-PreCompact.ps1 fallback path].
- **Coexistence (read before double-registering).** Claude Code runs user-level and
  project-level `SessionStart` hooks **both**, with no de-duplication, so the kit
  carries an exactly-once guard. The guard stays silent only on positive evidence: a
  hook copy running from **outside** the project exits without injecting only when the
  project's `.claude/settings.json` mentions `Invoke-SessionStart.ps1` **and** a
  project-local copy exists at
  `<project>/.claude/hooks/Invoke-SessionStart.ps1` — that copy is then the single
  injector. A copy running from **inside** the project always injects, and anything
  else injects (fail-open). Residual edge: a project that registers the user-level hook
  path without shipping a local copy can receive the `[AGENT_CONTEXT]` block twice.
  Verify that an `[AGENT_CONTEXT]` block actually appears after install;
  see `KNOWN-ISSUES.md` issue 8.

## 7. Limits: what the kit does NOT do

- It does not control or replace Claude Code's compaction. It archives around it.
- It is not a security boundary. The digest model is not an authority, and the
  optional sensor is a heuristic, not a parser (see `KNOWN-ISSUES.md`, issues 1-2).
- It does not reduce the model's context window, and it does not make a session
  cheap: it caps what *it* adds at 6000 chars per start event.
- It does not prune archives, summarise old ones, or sync state between machines.
  `.agent/` is per project, on disk, local.
- It is Windows-tested; the macOS path is BETA and largely not executed — the
  merge-engine `-SelfTest` first ran on a macOS runner via CI on 2026-10-06 (red on a
  null `$env:TEMP`, class fixed; re-run pending) [measured: CHANGELOG.md, 0.1.0
  notes; GitHub Actions runs, 2026-10-06].
- Failure memory is bounded: past 300 rows the oldest half is rotated out, so very old
  failures are no longer injected (they remain in the archive copy made at rotation).
