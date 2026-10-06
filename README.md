# longctx kit — Windows

Deterministic Claude Code hooks that make **long sessions and compactions survivable** on Windows.

Long sessions lose their working state at the compaction boundary: the transcript is summarized,
details are dropped, and the next session starts from a lossy memory of what happened. This kit moves
the durable part of that state out of the transcript and onto disk — a project-local `.agent/` folder —
and puts four hooks around the session life cycle that write it, snapshot it and re-inject it:

- at **session start**, a compact context (project state, the explicit `Next action`, the latest
  decisions and the latest failures) is injected automatically, so the first useful action does not
  depend on what the summary kept;
- **before compaction**, a deterministic snapshot is written to `.agent/archive/` *first*, then
  optionally extended with a digest produced by a **local** Ollama model (best-effort: no Ollama, no
  problem);
- **after compaction**, the summary is archived and `STATE.md` is updated;
- on **tool failure**, one redacted line is appended to `.agent/FAILURES.md` instead of being lost in
  a long transcript.

Everything runs locally. The only network call the kit can make is to a loopback Ollama endpoint. No
telemetry, no cloud; text written to state files — and text sent to the local model — passes through
the redactor first (see [Security & privacy](#security--privacy) for what it does and does not catch).

> **On macOS?** Use the macOS variant of this kit:
> <https://github.com/CiccioColtello/claude-longctx-kit-mac>.

---

## How it works

```
SessionStart ── inject compact context from .agent/
                (CONTEXT, STATE + explicit "Next action", last 2 decisions, last 3 failures;
                 hard cap 6000 chars)
      │
      ▼
   work ──────── tool failure? ──> one redacted row appended to .agent/FAILURES.md
      │
      ▼
 PreCompact ─── 1. deterministic snapshot -> .agent/archive/<ts>-precompact.md      (ALWAYS)
                2. redacted tail of the transcript -> LOCAL Ollama -> digest        (best-effort)
                   unavailable / slow / empty model = declared fallback; the
                   compaction is never blocked or delayed beyond the hook budget
      │
      ▼
PostCompact ─── summary -> .agent/archive/<ts>-compact-summary.md
                STATE.md updated ("Last compaction", "Updated") + archive/INDEX.md
      │
      ▼
next session ── SessionStart re-injects the updated state   (loop)
```

Optional, installed only on request: a **PreToolUse deny gate** (the "sensor") that blocks destructive
commands and shell-level reads of sensitive files before they run. It is **off by default** and marked
beta — see [Security & privacy](#security--privacy) and `KNOWN-ISSUES.md`.

---

## What you get

- **Hooks (5)**
  - `Invoke-SessionStart.ps1` — injects the `.agent/` context at session start (read-only).
  - `Invoke-PreCompact.ps1` — deterministic pre-compaction snapshot + optional local digest.
  - `Invoke-PostCompact.ps1` — archives the compaction summary, updates `STATE.md` and `archive/INDEX.md`.
  - `Invoke-PostToolUseFailure.ps1` — one redacted failure row per reproducible tool error.
  - `Block-Destructive.ps1` — opt-in PreToolUse deny gate (**default off**, beta).
- **Subagents (5)**: `repo-explorer`, `test-diagnostician`, `log-compressor`, `context-archivist`,
  `security-auditor` — so exploration and huge logs stay out of the main context.
- **Skills (3)**: `long-context`, `context-maintenance`, `repo-exploration`.
- **CLI helpers (2)**: `Filter-File.ps1` (redact + limit a log or transcript file to stdout),
  `Invoke-Digest.ps1` (run a local digest by hand).
- **`longctx` CLI**: `init` (create `.agent/` in a project from the shipped templates and append the
  `.gitignore` fragment).
- **Non-destructive settings merge**: hooks and deny rules are merged into `~/.claude/settings.json`,
  never overwritten; a `.bak-<stamp>` backup is written before any change; a second run with nothing to
  add does not touch the file at all.
- **Install / verify / uninstall scripts**: install and uninstall are dry-run by default (`-Apply` to
  execute); verify is a read-only health check (exit 1 on failure).

---

## Requirements

| | |
|---|---|
| **Claude Code** | 2.1.x (the Windows path here was verified with **2.1.291**). `permissions.deny` rules that also block Edit/Write need **2.1.228 or newer**. |
| **OS / shell** | Windows 10 or 11. Windows PowerShell **5.1** (built into Windows) or PowerShell 7 (`pwsh`). |
| **Disk** | The kit is small (core: 30 files, ~0.25 MB; the whole repository stays under 1 MB). `.agent/` grows with use: one markdown snapshot per compaction plus rotated logs. |
| **Rights** | None beyond your own user account. Everything installs under `%USERPROFILE%\.claude\`. No registry, firewall, service or machine-wide changes. |
| **Optional** | [Ollama](https://ollama.com) for the local digest only. Without it every hook still works (see [Local digest](#local-digest-optional)). |
| **Tested with** | Windows 11 Pro, Claude Code 2.1.291. The macOS build of this kit is **BETA and untested** — see [Status & verification](#status--verification). |

No admin rights are needed at any step.

---

## Quick start (Windows)

```powershell
# 0. Get the repository (clone or unzip) and open PowerShell in its root.

# 1. Dry run — this is the DEFAULT: it prints what would be installed, writes nothing.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1

# 2. Apply for real.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Apply

# 3. Health check (read-only; exits 1 on failure).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1

# 4. In each project you want the kit in, from the project root:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\.claude\longctx\bin\longctx.ps1" init
```

Installer options (all optional):

| Option | Effect |
|---|---|
| `-Apply` | Actually install. Without it, the installer only reports (dry run). |
| `-KitRoot <path>` | Where the kit is copied. Default: `%USERPROFILE%\.claude\longctx`, resolved by an OS-aware helper (on Windows `USERPROFILE` first, then `HOME`; on macOS/Linux `HOME` first, then `USERPROFILE`; the system user-profile folder as a last resort — never a silent relative path). |
| `-WithSensor` | Also install the opt-in PreToolUse deny gate (`Block-Destructive.ps1`). Default: off. |
| `-SkipSettings` | Copy files only; do not touch `~/.claude/settings.json` (no hooks, no deny rules). |

`longctx init` does only two things in a project: create `.agent/` from the templates and append the
`.gitignore` fragment (`.agent/`, `.claude/settings.local.json`). It does **not** wire project-level
hooks — user-level installation is the normal path.

---

## What gets installed, exactly

### Files

The contents of `core/` are copied to `~/.claude/longctx/`:

```
~/.claude/longctx/
├─ .claude/hooks/      Invoke-SessionStart.ps1, Invoke-PreCompact.ps1, Invoke-PostCompact.ps1,
│                      Invoke-PostToolUseFailure.ps1, Block-Destructive.ps1 (sensor),
│                      Hook-Common.ps1, Filter-AgentText.ps1, Hook-Inline.ps1, Invoke-LocalDigest.ps1
├─ .claude/agents/     5 subagents
├─ .claude/skills/     3 skills
├─ lib/                merge-claude-settings.ps1 (settings merge engine, with -SelfTest)
├─ scripts/            Invoke-Digest.ps1, Filter-File.ps1
├─ tests/              smoke.ps1 (portable smoke harness), probe-hardening.ps1 (deny-gate
│                      + ownership-gate security probe, real child processes)
├─ templates/          .agent templates, .gitignore fragment, deny fragment, project-settings examples
└─ bin/                longctx.ps1 (init CLI)
```

Nothing is written outside `~/.claude/` during installation.

### Settings changes

The installer merges the kit into `~/.claude/settings.json` using
`core/lib/merge-claude-settings.ps1`:

- **Hook events** — four are added by default: `SessionStart`, `PostToolUseFailure`, `PreCompact`
  (60 s timeout, because of the optional digest) and `PostCompact`. The hooks are invoked in exec form:

  ```
  powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <kit>\<hook>.ps1
  ```

  A fifth event, `PreToolUse`, is added only with `-WithSensor` (20 s timeout).

- **`permissions.deny`** — 11 `Read(...)` rules are added, **add-only** (nothing is removed from your
  existing allow/ask/deny lists): `./.env`, `**/.env`, `./.env.*`, `**/.env.*`, `**/*.pem`, `**/*.key`,
  `~/.ssh/**`, `~/.aws/**`, `**/.git-credentials`, `**/mcp.json`, `**/*.kdbx`. With Claude Code
  >= 2.1.228 these rules also block edits/writes to those paths, not just reads.

- **Merge semantics** — existing user hooks, arbitrary keys and existing deny rules are preserved. An
  entry counts as "already present" only if it points at this kit's `KitRoot`, so re-running the
  installer cannot duplicate it. If there is nothing to add, the file is **not rewritten at all**
  (byte-identical). Before any write, a backup is created next to the file:
  `settings.json.bak-<yyyyMMdd-HHmmss>`. If `settings.json` is not valid JSON (or contains invalid
  UTF-8 bytes) the merge fails closed and **nothing** is written.

---

## The `.agent/` state folder

This is the kit's memory. It lives in the **project**, next to (not inside) `.claude/`. The templates
are in `core/templates/agent/` and are created by `longctx init`.

| File | Written by | Content |
|---|---|---|
| `.agent/CONTEXT.md` | you / `context-archivist` | Project structure, entrypoints, commands, constraints — what the next session must not re-discover. |
| `.agent/STATE.md` | you, plus `PostCompact` | Goal, Phase, Modified files, Tests, Known failures, Decisions pending, **Next action**, `Updated`, `Last compaction`. The `Next action` section is surfaced first at session start. |
| `.agent/DECISIONS.md` | you / `context-archivist` | Append-only durable decisions: decision, motivation, rejected alternatives, consequences. The **last 2** are injected at session start. |
| `.agent/FAILURES.md` | `PostToolUseFailure`, `PreCompact`, the hooks' fail-open recorder, you | One redacted row per reproducible error (timestamp, component, command/path masked, first line of the error, cause, next verification). The **last 3** are injected. Deduped against the previous row; past 300 rows the full file is archived to `archive/failures-<ts>.md` and the live file keeps the newest half. |
| `.agent/denied-actions.log` | `Block-Destructive` (sensor only) | Audit of blocked actions: timestamp, rule id, tool, redacted detail. Past 500 rows the full file is archived to `archive/denied-<ts>.log` and the live file keeps the newest half. |
| `.agent/archive/` | `PreCompact`, `PostCompact`, rotations | `<ts>-precompact.md`, `<ts>-compact-summary.md`, rotated logs, and `INDEX.md`. |
| `.agent/ollama.env` | you (optional) | `KEY=VALUE` config for the local digest. See [Local digest](#local-digest-optional). |

Snapshots are written atomically and under a per-project lock, so two hooks writing at the same second
cannot lose a file or interleave a read-modify-write. All hook errors are fail-open: if a hook breaks,
the session continues; the hook records the failure in `.agent/FAILURES.md` (when the folder exists)
and shows a warning in the session where the event allows one.

---

## The exactly-once guard

Claude Code runs **both** user-level and project-level `SessionStart` hooks, with no de-duplication. A
project that wires the session-start hook itself *while* the user-level install is active would inject
the `.agent/` context **twice** into the same session — duplicated context and duplicated token cost.

The kit prevents this with a guard inside `Invoke-SessionStart.ps1`. The guard stays silent only on
**positive evidence** that the project's own copy is the single injector:

- The running hook copy must run from **outside** the project (the user-level install), **and** the
  project's `.claude/settings.json` **or** `.claude/settings.local.json` must mention
  `Invoke-SessionStart.ps1` (case-insensitive text search; the shipped example
  `templates/project-settings.example.windows.json` does), **and** a
  project-local copy must exist at `<project>/.claude/hooks/Invoke-SessionStart.ps1`.
- Only then does the outside copy exit silently: the project copy is the injector, so a project with
  both registrations still injects exactly once.
- A hook copy running from **inside** the project always injects, and anything else injects too — no
  mention, no project-local copy, or a missing/unreadable settings file: the guard fails **open**. A
  bare filename mention in project settings can no longer silence every copy at once (that dead-lock
  was found during review and fixed).
- The same guard shape protects the other three event hooks (`PreCompact`, `PostCompact`,
  `PostToolUseFailure`): a project wired the documented way runs each event exactly once — one
  snapshot, one archive, one failure row, one digest call per compaction.

Residual edge, fail-open by design: a project that registers the *user-level* hook path without
shipping a local copy at the conventional location receives the injected `[AGENT_CONTEXT]` block
twice. Double waste is preferred over a dead feature.

Practical consequence: to opt a single project out of the user-level injection, give that project its
own copy of the hook and register it in `<project>/.claude/settings.json` (copy the shipped example as
a starting point).

---

## Security & privacy

**Redaction before storage.** Every piece of text the kit writes to `.agent/` — or sends to the local
model — passes through a redactor first: private-key blocks, `key=value` secrets, credentials embedded
in URLs, JWTs, Telegram bot tokens, and provider token formats (AWS, Google, GitHub, Slack,
OpenAI-style `sk-`/`pk-`/`rk-` keys), plus long hex/base64 blobs. Which rules fired is recorded (rule
ids only) in the archive header. If the redaction library were missing, a reduced high-value rule set
still runs and the degradation is recorded once — redaction is never silently skipped.

**Sensitive-path classifier.** A shared classifier (file names, extensions and path segments) covers
`.env` and `.env.*`, `*.pem`, `*.key`, `*.pfx`, `*.p12`, `*.kdbx`, `.ssh/`, `.aws/`, `.gnupg/`, `.kube/`,
`credentials*`, `mcp.json`, `*.tfstate` and more. Hooks refuse to read, print or archive such files,
and mask references in logs as `[SENSITIVE_FILE] <name>`. If a path cannot be resolved safely, the
classifier is fail-closed (treated as sensitive).

**Deny defaults.** The installer adds the 11 `permissions.deny` `Read(...)` rules listed above. They are
add-only; customize or remove them in `~/.claude/settings.json` under `permissions.deny` (or with
`uninstall.ps1 -RemoveDenyRules`).

**What those deny rules do not stop** (documented behavior of Claude Code, worth knowing): `Read`/`Edit`
rules apply to the built-in file tools and to recognized Bash file commands. They do **not** govern
unnamed reads such as `grep -r` or arbitrary subprocesses. OS-level enforcement would require Claude
Code's sandbox. Treat the rules as an accident guard, not as a boundary against a determined bypass.

**The opt-in sensor.** `Block-Destructive.ps1` (installed only with `-WithSensor`) is a PreToolUse
**deny** gate: it blocks destructive command classes (recursive/forced deletes, `git reset`/`clean`/
`restore`, force-push, privilege escalation, registry/firewall/service changes, package installs,
`iex`, `cmd /c`, DB migrations, on-chain transactions, deploys, disk operations) and shell-level reads
of sensitive files. It logs a redacted row to `.agent/denied-actions.log`. It is marked **beta**: it is
heuristic, not a shell parser, and known false positives exist for read-only commands that merely
*mention* a protected path — see `KNOWN-ISSUES.md`. Keep it off if you prefer the native deny rules
alone. It is fail-open on infrastructure errors (a broken hook never bricks a session), and it has no
environment variable to disable it: it is removed by editing the settings or uninstalling.

**No telemetry, no cloud.** The hooks make no network calls except to the local digest endpoint, which
must be a loopback address; a non-local `OLLAMA_HOST` is refused, and HTTP redirects are not followed
(fail closed). Nothing the kit produces is sent anywhere.

**The local model is not a security authority.** It writes prose for the archive. It has no vote on
what is allowed, blocked, or considered safe.

---

## Local digest (optional)

Before compaction, the kit can append a digest of the (redacted) tail of the transcript to the
snapshot, produced by a **local** Ollama model. The deterministic snapshot is always written *first*;
the digest is a bonus.

- **Without Ollama** (not installed, not running, no model pulled, too slow, empty answer): the
  snapshot still exists and contains a `## Local digest NOT available (fallback)` section stating
  the reason. The compaction proceeds. A row is recorded in `FAILURES.md` so the fallback is never
  silent.
- **Config** lives in the project, not in a global file: `.agent/ollama.env` (`KEY=VALUE`; `#`
  comments and blank lines allowed; unknown keys are ignored). Missing values fall back to defaults
  baked into `core/.claude/hooks/Invoke-LocalDigest.ps1`:

| Key | Default | Meaning |
|---|---|---|
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | Must be loopback (`127.0.0.1`, `localhost`, `::1`); anything else is refused. |
| `OLLAMA_DIGEST_MODEL` | `qwen3:4b` | Model tag used for the digest. |
| `OLLAMA_DIGEST_TIMEOUT` | `45` | Seconds. Clamped to the 5–45 s range: the PreCompact hook budget is 60 s, so **values above 45 have no effect.** |
| `OLLAMA_DIGEST_MAX_INPUT` | `60000` | Characters fed to the model; truncation is marked inside the material. |
| `OLLAMA_CONTEXT_LENGTH` | `32768` | Context window requested from the model (`num_ctx`). Lower it on small machines. |

- The digest request disables the model's "thinking" channel, runs at temperature 0.2 with a bounded
  output length, and marks the result explicitly if the model hit the token limit mid-answer.

### Hardware variants (8 → 32 GB+)

Pick the largest model your machine can keep comfortably resident. Ollama uses GPU VRAM when the model
fits there and CPU + RAM otherwise (partial offload works but is slower); the digest competes with your
editor and agent for that memory, so leave headroom. Sizes below are approximate Q4 download sizes and
are **not** shipped with the kit — `ollama pull <tag>` fetches them.

| RAM / VRAM available | Model (`OLLAMA_DIGEST_MODEL`) | Approx. download | Where it fits | Expected trade-off |
|---|---|---|---|---|
| **8 GB** | `qwen3:4b` (**default**) | ~2.6 GB | RAM-only or a small GPU. On a tight machine also set `OLLAMA_CONTEXT_LENGTH=16384`. | Fastest; coarsest summaries. The right default for 8 GB. |
| **12 GB** | `qwen3:8b` (or `qwen2.5:7b`) | ~5.2 GB | RAM-only with reduced context; comfortable in ~8 GB VRAM. | Better structure and faithfulness on long transcripts; slightly slower. |
| **16 GB** | `qwen3:8b` recommended; `qwen3:14b` only with ~10 GB free | ~5.2 GB / ~9.3 GB | 8b: RAM-only or GPU. 14b: GPU VRAM preferred, CPU possible but slow. | 14b gives more faithful summaries if it fits; watch latency. |
| **24 GB** | `qwen3:14b` | ~9.3 GB | GPU VRAM preferred; CPU works but is slower. | Noticeably better on long, dense transcripts. |
| **32 GB+** | `qwen3:32b` (~20 GB) or `qwen3:30b-a3b` (~18.6 GB, MoE with ~3B active) | ~20 GB / ~18.6 GB | GPU VRAM if available; either fits RAM-only on a 32 GB machine. | Highest quality; `30b-a3b` is faster at similar memory. On CPU, a large model can exceed the 45 s digest budget and fall back — that is expected, not an error. |

How to switch (per project):

```ini
# <project>/.agent/ollama.env

# Optional: smaller context on small machines.
OLLAMA_CONTEXT_LENGTH=16384
OLLAMA_DIGEST_MODEL=qwen3:8b
```

```powershell
ollama pull qwen3:8b
```

Formatting rules for this file (it is a simple parser, not a full config language): one `KEY=VALUE`
per line; blank lines and lines starting with `#` are skipped; everything after `=` is the value, so
**no inline comments** — a trailing `; note` would become part of the value.

Nothing else changes: the digest stays optional, local-only and best-effort, and the model is **not** a
security authority.

---

## Usage tips

- **Start from `Next action`.** The session-start injection surfaces it explicitly; keep it concrete
  and update it at the end of every meaningful task (`STATE.md`).
- **Delegate the context-heavy work.** The five subagents exist so exploration and big logs happen in
  an isolated context; the main loop should contain conclusions, not file dumps.
- **Filter big logs instead of pasting them:**
  ```powershell
  powershell.exe -NoProfile -File "$env:USERPROFILE\.claude\longctx\scripts\Filter-File.ps1" -Path "C:\logs\build.log" -Max 4000 -Tail > filtered.txt
  ```
  The original file is never modified; sensitive files are refused outright; redaction findings are
  reported on stderr.
- **Run a digest by hand** (for example on `STATE.md`):
  ```powershell
  powershell.exe -NoProfile -File "$env:USERPROFILE\.claude\longctx\scripts\Invoke-Digest.ps1" -TextFile "$PWD\.agent\STATE.md"
  ```
- **Tell the compaction what matters.** `/compact <instructions>` is captured by `PreCompact` and
  stored in the snapshot under "User instructions for compaction".
- **After a compaction**, if the summary lost a detail, read it back from `.agent/archive/` instead of
  reconstructing from memory; `archive/INDEX.md` lists what is there.

---

## Uninstall

```powershell
# Preview (default, writes nothing)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1

# Apply
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1 -Apply
```

Uninstall removes the kit's hook entries and leaves everything that is yours untouched (other hooks,
other settings keys, and — unless you ask — the deny rules you may have customized). Explicit flags:

- `-RemoveDenyRules` — also remove the deny rules the kit added.
- `-RemoveFiles` — also delete the copied kit directory (`~/.claude/longctx`).

Your projects' `.agent/` folders are project data and are never touched by the uninstaller.

---

## Troubleshooting

**1. "Agent state missing" / no context is injected.**
The project has no `.agent/` folder. Run `longctx init` from the project root (or copy
`core/templates/agent/*` there yourself). Injection starts on the next session.

**2. The context appears twice.**
The guard only stays silent on positive evidence: the project's `.claude/settings.json` (or
`.claude/settings.local.json`) must mention
`Invoke-SessionStart.ps1` **and** a project-local copy must exist at
`<project>/.claude/hooks/Invoke-SessionStart.ps1`. A project that registers the hook some other way
(a renamed copy, or a path pointing at the user-level install) is not recognized as the injector, so
both copies inject — that is the declared fail-open residual edge. Keep exactly one registration per
event, or ship the project-local copy. An unreadable `<project>/.claude/settings.json` also makes the
guard inject (fail-open): fix its JSON.

**3. The snapshot has no digest.**
Expected and safe: the deterministic snapshot is still there. The fallback section names the reason —
Ollama not running, model not pulled (`ollama pull <tag>`), timeout, empty answer, or a non-local
`OLLAMA_HOST` (refused by design). Check `.agent/FAILURES.md` for the recorded cause. Remember that
`OLLAMA_DIGEST_TIMEOUT` is clamped to 45 s.

**4. A deny rule blocks something legitimate.**
The built-in rules are pattern-based. Look up the blocked path in
`~/.claude/settings.json` → `permissions.deny` and remove or narrow the rule (or run
`uninstall.ps1 -RemoveDenyRules` when uninstalling). With the sensor installed, the audit trail is in
`.agent/denied-actions.log`, with the rule id.

**5. With `-WithSensor`, a harmless read-only command was blocked.**
Known beta behavior: the gate's write detection is heuristic, and a read-only command that *mentions*
a protected path (for example a listing that prints `C:\Program Files\...`) can be denied. Re-run a
leaner command, use a dedicated tool, or remove the sensor entry from `~/.claude/settings.json`.
See `KNOWN-ISSUES.md`.

**6. Hooks do not run at all.**
Run `verify.ps1` (it is read-only and exits 1 on failure). Check that `~/.claude/settings.json` is
valid JSON and contains the kit's hook entries, and that the Claude Code version supports the hook
events you rely on (the write-blocking half of the deny rules needs >= 2.1.228).

---

## Status & verification

- **Windows: tested.** The Windows path was exercised on **Windows 11 with Claude Code 2.1.291**
  under both Windows PowerShell 5.1 and PowerShell 7: the hook contract, the settings-merge
  `-SelfTest` matrix (44 checks, including the `KitRoot`
  home-resolution cases 9a/9b/9c, the two-saves/two-distinct-backups case 10a, the
  invalid-UTF-8 fail-closed cases 4c/4d, the 25-level deep-structure case 11a, the StrictMode
  member-access cases 12a-f — hook entries without `args`, as found in real settings.json
  files — and the fail-closed shape cases 13a-d), the smoke
  harness (22 checks, including the in-project guard discriminator and the
  scan-budget boundary: at-limit allowed, over-limit denied `[input-oversize]`,
  at-limit with a quote denied `[scanner-budget]`), and the shipped security probe
  (`core/tests/probe-hardening.ps1`, 19 checks: deny-gate rule ids including the
  quote-split evasions, the failure-log masking, and the `KitRoot` ownership /
  settings-dir refusal in both installers).
- **macOS: BETA, largely not executed.** The shell adapters and the smoke harness have not run on a
  Mac; the merge-engine `-SelfTest` has run twice on a macOS runner via CI on 2026-10-06 and exposed
  two Windows-only assumptions in the selftest itself — a null `$env:TEMP` sandbox root, then the
  case-14 lock simulation (FileShare locks are advisory on Unix) — both fixed at class level; the
  re-run after the second fix is pending. The intended manual validation steps are in
  `TEST-PLAN-MAC.md` (macOS repository).
- **CI: executed twice (2026-10-06), re-run pending.** `.github/workflows/ci.yml` (matrix:
  `windows-latest`, `macos-latest`): the Windows legs were green in both runs; the macOS legs went
  red on two Windows-only assumptions inside the selftest itself (null `$env:TEMP`, then the
  case-14 lock simulation), fixed since. It remains an executable specification of the intended
  matrix; no secrets and no deploy steps.
- **Coverage and remainder (COPERTURA / RESTO).** What is covered, with which test, and what is not
  covered is stated in `COPERTURA-RESTO.md` (the verification ledger), `KNOWN-ISSUES.md` and
  `ANALISI-USO.md`; the macOS remainder is enumerated in `TEST-PLAN-MAC.md`. Nothing in this README
  should be read as a stronger claim than those documents.
- **Language.** The repository is entirely in English: documentation, code comments, hook messages
  and the shipped templates.

---

## Links

- [`ANALISI-USO.md`](ANALISI-USO.md) — usage and token analysis of a workspace running this
  architecture (what the state files actually save).
- [`FORECAST-TOKEN.md`](FORECAST-TOKEN.md) — token/cost forecast model for long sessions.
- [`KNOWN-ISSUES.md`](KNOWN-ISSUES.md) — known limits, beta status of the sensor, false positives,
  workarounds.
- [`COPERTURA-RESTO.md`](COPERTURA-RESTO.md) — the verification ledger: what is covered (with the
  test that proves it) and what is not.
- [`CHANGELOG.md`](CHANGELOG.md) — version history (current: 0.1.0).
- macOS kit: `TEST-PLAN-MAC.md` and the same documents in the macOS repository.

---

## License

MIT — see [`LICENSE`](LICENSE).

Author: **CiccioColtello** — <https://github.com/CiccioColtello>
