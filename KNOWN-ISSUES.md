# Known issues

Honest, numbered list of the issues shipped with this kit. Every entry states symptom,
impact, cause, workaround and status. Nothing here is invented: each item is backed by
the code, by the observed incidents recorded during development of the opt-in sensor,
or by the project changelog. Items marked "derived" are consequences read directly out
of the shipped code rather than observed failures.

---

## 1. The PreToolUse sensor is opt-in and beta; its deny-log redaction is incomplete

**Symptom.** When the sensor is enabled, `.agent/denied-actions.log` (and, in some
paths, `FAILURES.md`) can contain raw sensitive-path references or partial raw command
text, even though the log is documented as "redacted".

**Impact.** A local audit file may hold more of the original command than intended.
Since the file lives in the project's `.agent/` directory, this is a local-exposure
issue, not a transmission issue — but it is still a redaction gap.

**Cause.** The deny record goes through two redaction stages
[code: .claude/hooks/Hook-Common.ps1, `Add-DeniedRecord`]:
`Remove-SensitiveTokensFromCommand` (table-driven; it masks only the file families the
sensitive-path tables recognize, and its walk is explicitly best-effort — tokens the
canonicalization cannot process are skipped
[code: `Remove-SensitiveTokensFromCommand` doc comment]) and `Remove-SensitiveContent`
(12 regex rules for secret *shapes*; a novel or unusual format is not matched
[code: .claude/hooks/Filter-AgentText.ps1, `$script:RedactionRules`]). In addition, the
degradation path is not redacted: when the primary log write fails, `Add-DeniedRecord`
passes the **raw** detail to `Add-DegradationRow`, which writes it to the twin channel
(`FAILURES.md`, or `denied-actions.log` for the other degradation kinds)
[code: Hook-Common.ps1, `Add-DeniedRecord` catch + `Add-DegradationRow`].
Quote-split / glued references (`cat ."env"`, `~/."claude"/settings.json`) used to
pass both stages raw; they are now re-classified against the **de-quoted** spelling
and masked as well — a second, span-based masking pass walks the original
quote-inclusive spans right-to-left and replaces each one whose stripped form the
scanner classifies as sensitive [code: Hook-Common.ps1,
`Remove-SensitiveTokensFromCommand`, quoted-twin pass; RED/GREEN probe: the glued
row leaked the raw path before the fix, reads `[SENSITIVE_FILE] <name>` after it].
The gap described above still stands for references whose *stripped* spelling
matches nothing in the sensitive-path tables.

**Workaround.** Keep the sensor off (default). If it is on, treat `.agent/` as
sensitive local output: delete `denied-actions.log` when it is no longer needed, and do
not publish `.agent/` in a repository or share it in bug reports.

**Status.** Open — this, together with the false-positive rate (issue 2), is why the
sensor is **not wired by default**: the merged settings only include it with the
explicit opt-in switch [code: lib/merge-claude-settings.ps1, `optIn = $true`].

## 2. Sensor false positives: read-only commands can be denied as "writes"

**Symptom.** A command that writes nothing is denied with
`[protected-path-write]` ("write to a protected area or a sensitive file via shell").
Two real incidents observed during development (2026-10-06, in the reference
workspace):

- **Case A (PowerShell, ~10:52).** A probe command that checked whether a CLI tool was
  present and listed a program directory as a fallback branch. The command wrote
  nothing. It was denied as a protected-path write. A/B check: the *same* command with
  the literal output string "not installed" removed was **allowed** — the incident
  record's hypothesis is that a write-verb token matched inside a literal string, and
  the protected directory (`C:\Program Files\...`) mentioned in the same command
  supplied the second stage of the heuristic.
- **Case B (Bash, ~11:05).** A pure read-only listing: `ls -la` on the user's global
  Claude config directory plus `wc -c` on two files inside it. No write verb was
  present. Denied as a protected-path write. The mechanism was **not isolated** in the
  incident record (candidates: read access to the protected global-config tree being
  classified as a write, or a flag token misread as a write verb); the equivalent A/B
  check was not completed.

**Impact.** Occasional blocked read-only commands; the agent cannot approve them, so
the user must re-run them outside Claude Code (the deny message says so). It costs
interruptions, not correctness.

**Cause.** The shell branch of the sensor is a declared two-stage heuristic — a write
verb anywhere in the command string plus a path token that canonicalizes into a
protected area — and explicitly "not a shell parser"
[code: .claude/hooks/Block-Destructive.ps1, `Get-CommandProtectedPathHit` doc comment].
Two consequences are known and declared in the code: quoted text is classified as if
it were a command (`echo "rm -rf"` is intentionally blocked
[code: Block-Destructive.ps1, comment on the command rules]), and over-block is
preferred over a bypassable exception in at least one case
[code: `package-install` rule comment).

**Workaround.** Re-run the command manually outside Claude Code; or use the dedicated
tools (`Read`, `Glob`, `Grep`) instead of shell for read-only access; or avoid literal
trigger words/paths in the same command. If you maintain the rules, edit
`Block-Destructive.ps1` — there is deliberately no environment bypass.

**Status.** Open — inherent to the heuristic; mitigated in practice by the sensor
being opt-in.

## 3. The local digest is best-effort and is not a security authority

**Symptom.** A compaction archive may contain a digest section, or a declared fallback
("Local digest NOT available") naming the reason; a digest may also be marked
"(digest TRUNCATED: token limit reached - partial material)" when the model hit
`num_predict = 1200` [code: .claude/hooks/Invoke-LocalDigest.ps1, `done_reason`].

**Impact.** Archive quality varies with the local model and hardware. Nothing else in
the kit depends on the digest: the deterministic snapshot is always present, and the
digest decides nothing.

**Cause.** By design: the digest calls a local Ollama model, refuses non-loopback hosts
and redirects, and gives up on timeout (client clamped to at most 45 s inside a 60 s
hook budget) [code: Invoke-LocalDigest.ps1, `Test-LocalOllamaHost`,
`-MaximumRedirection 0`, timeout clamp]. A local model can also summarise incorrectly.

**Workaround.** Treat digest text as untrusted notes, never as evidence; use the
deterministic snapshot (`State at compaction time`) when it matters. Keep the
digest model fast enough to finish inside 45 s (see issue 11).

**Status.** Open, by design.

## 4. (Resolved) Comments, templates, agents and skills used to be in Italian

**Symptom (historical).** The core `.ps1` comments, the `.agent` state templates, the
description text of the five subagents and three skills, and the user-facing hook
messages were written in Italian.

**Impact.** Cosmetic for an English-speaking audience: harder to read, harder to
customise, no functional effect.

**Cause.** Historical: the kit was developed in an Italian-language workspace.

**Workaround.** None needed now: the 2026-10-06 revision translated the whole
repository to English (code comments, hook and status messages, templates, agents and
skills). Translate locally only if you prefer different wording.

**Status.** Closed (was cosmetic). Kept with its number so the cross-references from the
other documents stay valid.

## 5. macOS path is untested (BETA)

**Symptom.** The macOS install adapters and the macOS hook wiring are shipped but have
never been executed on macOS.

**Impact.** A macOS user may hit path/quoting differences not seen on Windows.

**Cause.** Development and testing happened on Windows only. The changelog states the
macOS path is BETA and untested; `TEST-PLAN-MAC.md` records the intended validation
steps; the CI workflow first ran on 2026-10-06 (on push) and its macOS leg failed in
7 s on a null `$env:TEMP` (class fixed in the same round; re-run pending) [measured:
GitHub Actions runs, 2026-10-06; CHANGELOG.md, 0.1.0 notes].

**Partial mitigation (measured).** The PowerShell half of the macOS repository is now
byte-identical to the Windows one (`tools/verify-parity.ps1`: 31/31 core files,
exit 0; the two `install.ps1`/`uninstall.ps1` copies are byte-identical too), and the
security probe was executed against the macOS tree itself — ownership / settings-dir
refusal and the quote-split deny cases pass there under both interpreters
[measured: `core/tests/probe-hardening.ps1` on the macOS repo, 19 PASS / 0 FAIL under
Windows PowerShell 5.1 and pwsh 7]. What remains untested is the part only a real Mac
can exercise: the `.sh` adapters, path semantics, and pwsh-as-the-default-hook-
interpreter.

**Workaround.** Use the Windows path, or validate the macOS steps from
`TEST-PLAN-MAC.md` before relying on it. Report what breaks.

**Status.** Open.

## 6. Compaction deadline: a killed hook leaves the snapshot, not the digest

**Symptom.** If the `PreCompact` process is killed while the digest call is running
(hook timeout, machine sleep, user interrupt), the archive contains the deterministic
snapshot but no digest, or no fallback note explaining why.

**Impact.** A degraded archive with no digest — the snapshot (the part the kit relies
on) is intact.

**Cause / design.** `PreCompact` deliberately writes the snapshot **before** calling
the local model, then rewrites the file with the digest if it succeeds
[code: .claude/hooks/Invoke-PreCompact.ps1, "Snapshot written IMMEDIATELY, before
calling the local model" comment]. That ordering is what limits the damage of a
kill mid-digest.

**Workaround.** None required for correctness. If you need the digest, make the model
fast enough that the 45 s clamp is rarely hit.

**Status.** Open — mitigated by design, but **not covered by automated tests**: no
shipped test simulates a hook killed mid-digest (see issue 7).

## 7. The shipped tests cover the core contract only, not Claude Code integration

**Symptom.** The automated tests that ship with the kit exercise the merge engine
(`merge-claude-settings.ps1 -SelfTest`, a 44-check case matrix including the `KitRoot`
home-resolution cases 9a/9b/9c, the two-saves/two-distinct-backups case 10a, the
invalid-UTF-8 fail-closed cases 4c/4d, the 25-level deep-structure case 11a, the
StrictMode member-access cases 12a-f — hook entries without `args`, as found in real
settings.json files — and the fail-closed shape cases 13a-d), a
portable smoke harness (`core/tests/smoke.ps1`, 22 checks including the in-project
exactly-once guard discriminator and the scan-budget boundary cases), and a shipped
security probe (`core/tests/probe-hardening.ps1`, 19 checks: deny-gate rule ids
including the quote-split evasions, the log masking, and the `KitRoot` ownership /
settings-dir refusal in both installers), plus a syntax lint of shell files on the
macOS leg [measured: .github/workflows/ci.yml, step list].

**Impact.** A hook change can pass the harness and still misbehave inside a real
Claude Code session — for example: not firing on an event, injecting a malformed
context block, or the exactly-once guard choosing the wrong injector in a configuration
the harness does not cover. Those behaviors are not asserted by any shipped test.

**Cause.** Scope: the harness tests the hooks' deterministic contract in isolation;
a full integration test would need Claude Code itself in the loop.

**Workaround.** After any local change to the hooks, run one short real session and
check: (a) the `[AGENT_CONTEXT]` block appears at startup (and after a `/compact`),
(b) a deliberate tool failure adds one row to `.agent/FAILURES.md`, (c) the archive
directory gains a file after a compaction. The CI workflow (first executed 2026-10-06)
is not proof of integration either.

**Status.** Open.

---

Items 8-12 below are **derived** from the shipped code and the measured reference data
rather than observed incidents.

## 8. Exactly-once guard: residual double-injection edge when a project registers the user-level hook path (derived)

**Symptom (found during review, fixed).** An earlier revision of the guard was a plain
substring search: if `<project>/.claude/settings.json` existed and mentioned
`Invoke-SessionStart.ps1`, **every** copy of the hook exited 0 with no output —
including the project-level copy that was supposed to inject. A project whose settings
registered the hook could therefore lose the `.agent/` context silently.

**Resolution.** The dead-lock is fixed. The shipped guard stays silent only on
**positive evidence** [code: .claude/hooks/Invoke-SessionStart.ps1, exactly-once guard
comment block]:

- a copy running from **inside** the project always injects (project-level wiring
  wins as the injector);
- a copy running **outside** the project (the user-level install) stays silent only
  when the project's `.claude/settings.json` mentions `Invoke-SessionStart.ps1`
  **and** a project-local copy exists at
  `<project>/.claude/hooks/Invoke-SessionStart.ps1` — that copy is then the single
  injector;
- everything else injects. A bare filename mention in project settings is not enough
  to silence any copy, and a missing or unreadable settings file fails open.

The smoke harness asserts the discriminator (a hook copy running from inside the
project must inject), which is RED against the old guard
[code: core/tests/smoke.ps1, project-wiring case].

**Scope of the guard (measured).** The guard is a shared helper
[code: Hook-Common.ps1, `Test-ProjectLocalInjector`] and is applied by **all
four** event hooks that can do work — `Invoke-SessionStart`, `Invoke-PreCompact`,
`Invoke-PostCompact`, `Invoke-PostToolUseFailure` — not only by the injector, and it
scans **both** `<project>/.claude/settings.json` and
`<project>/.claude/settings.local.json`. An earlier revision guarded only the
injector and read only `settings.json`, which let a project wired the documented way
run the other three events twice (two snapshots, two failure rows, up to two 45 s
digest calls per compaction). The 4-hook × 5-configuration matrix (user-only; mention
in `settings.json`; mention only in `settings.local.json`; local copy without mention;
project copy) is green on both interpreters [internal probe `p6-exactly-once.ps1`,
20 PASS / 0 FAIL — the probe is a development artifact, not shipped].

**Residual limitation (documented, by design).** A project that registers the
*user-level* hook path without shipping a local copy at the conventional location
receives the injected `[AGENT_CONTEXT]` block **twice**. That is the declared
fail-open trade-off — double waste is preferred over a dead feature. The shipped
project-settings templates avoid it by registering
`${CLAUDE_PROJECT_DIR}/.claude/hooks/Invoke-SessionStart.ps1`
[code: templates/project-settings.example.windows.json and .mac.json] and shipping the
local copy.

**Workaround.** To opt a single project out of the user-level injection, ship the
project-local copy and register it in `<project>/.claude/settings.json` (copy the
shipped example as a starting point). Otherwise keep exactly one registration per
event, and verify after install that one `[AGENT_CONTEXT]` block actually appears.

**Status.** Closed as a defect; the residual double-injection edge is Open (declared,
fail-open by design).

## 9. Archives are never pruned automatically (derived)

**Symptom.** `.agent/archive/` grows without bound. On the reference workspace it
reached 946 files / 34 MB in about two days of use (about 36-37 KB per snapshot)
[measured: token-analysis-raw.txt, 2026-10-06].

**Impact.** Disk growth on long-lived projects: a 3-compaction daily session is roughly
40 MB/year (derived from the measured mean). Nothing breaks; backups and repository
scanners see more files.

**Cause.** Rotation exists only for `FAILURES.md` (past 300 rows keep 150) and
`denied-actions.log` (past 500 rows keep 250) [code: .claude/hooks/Hook-Common.ps1,
`Add-FailureRecord` / `Add-DeniedRecord`]. PreCompact/PostCompact only append.

**Workaround.** Delete old files in `.agent/archive/` by hand; they are plain Markdown.
Keep `INDEX.md` if you want the human-readable list.

**Status.** Open (by design; a retention policy is not implemented).

## 10. A machine without Ollama accumulates one "digest fallback" failure row per compaction (derived)

**Symptom.** `FAILURES.md` gains a `digest-local-fallback` row on every compaction
that had no usable local model.

**Impact.** Two concrete effects: the file fills faster (rotation kicks in at 300
rows), and the **injected** "last 3 failures" at session start can be entirely digest
fallbacks, hiding real tool failures [code: .claude/hooks/Invoke-SessionStart.ps1,
last-3-rows injection].

**Cause.** The digest fallback is deliberately recorded as a failure so that it is
never silent [code: .claude/hooks/Invoke-PreCompact.ps1, `Add-FailureRecord ...
Cause 'digest-local-fallback'`].

**Workaround.** Run Ollama for real digests, or periodically trim the fallback rows
from `FAILURES.md` by hand.

**Status.** Open (by design; the trade-off is declared in the code).

## 11. `OLLAMA_DIGEST_TIMEOUT` above 45 seconds has no effect (derived)

**Symptom.** Setting `OLLAMA_DIGEST_TIMEOUT=90` (as sometimes suggested for larger,
slower models) changes nothing: the client clamps the timeout to at most 45 s.

**Impact.** A model that needs more than 45 s to summarise the (up to 60,000-char)
prompt will **always** degrade to the fallback, no matter how the timeout is
configured — the digest never appears in the archives.

**Cause.** Deliberate clamp to stay inside the 60 s `PreCompact` hook budget
[code: .claude/hooks/Invoke-LocalDigest.ps1, `if ($timeout -gt 45) { $timeout = 45 }`;
code: templates/project-settings.example.windows.json, `"timeout": 60`].

**Workaround.** Use a model that finishes the digest well inside 45 s on your hardware
(smaller model, or reduce `OLLAMA_DIGEST_MAX_INPUT`), or accept snapshot-only
archives.

**Status.** Open (by design; the clamp is documented in the code but is worth
repeating here because it contradicts the usual "raise the timeout" advice).

## 12. The opt-in sensor's home-root protections are Windows-only in v0.1.0 (derived)

**Symptom.** The opt-in `PreToolUse` sensor
(`core/.claude/hooks/Block-Destructive.ps1`) builds its protected home/AppData roots by
string concatenation with Windows separators (for example
`$script:HomeDir + '\.claude'`), so on macOS those specific home-root rules do not
match real paths.

**Impact.** With `-WithSensor` on macOS, a shell write aimed at the protected home
roots (for example the user-level `~/.claude/settings.json`) is not caught by those
rules. The pattern-based rules are unaffected: recursive/forced deletes, `git reset` /
`clean` / `restore`, force-push, `curl | sh`, privilege escalation and shell-level
sensitive-file reads still match by pattern, separator-agnostically.

**Cause.** v0.1.0 limitation: the home-root list was written for Windows path shapes
[code: Block-Destructive.ps1, `$script:ProtectedWriteRoots` construction]. Declared,
not fixed — the file carries open M1/M2 findings from the security campaign.

**Workaround.** The sensor is opt-in and **off by default**: the default install uses
only the native `permissions.deny` fragment (`Read(...)` rules), which is
separator-agnostic. Keep the sensor off on macOS, or treat its home-root protections as
Windows-only and rely on the pattern rules.

**Status.** Open (declared; Windows-only rule scope in v0.1.0).

## 13. A `settings.json` with duplicate keys is silently normalized on write (derived)

**Symptom.** If the existing `~/.claude/settings.json` contains duplicate keys (for
example `"model"` twice), the merge reads it with `ConvertFrom-Json` and writes back a
document where only the **last** occurrence survives; the file changes more than the
kit's own additions.

**Impact.** A settings file that was already non-canonical (duplicate keys are valid
JSON text but ambiguous) is canonicalized by the first write. Nothing of the kit's
making is lost, and a `.bak-<stamp>` backup is always taken first, but the diff will
show more than the hook entries.

**Cause.** `ConvertFrom-Json` collapses duplicate keys (last-wins) and the merge
rewrites the parsed object [code: lib/merge-claude-settings.ps1, `Merge-ClaudeSettings`
+ `Save-ClaudeSettings`]. Failing on duplicate keys is possible but would refuse a file
that JSON itself accepts; not implemented in v0.1.0.

**Workaround.** None needed normally. If your settings file has duplicate keys, clean
them up first (the backup taken before the first merge has the original).

**Status.** Open (declared; behavior of the JSON layer, not a kit defect).

## 14. No kill-switch: there is no switch to disable the hooks without uninstalling (derived)

**Symptom.** After a user-level install, every session in every project runs the four
hooks. There is no environment variable, flag or settings key that turns them off
while keeping the install; the only off switches are `uninstall.ps1` (removes the
wiring, keeps the files) or removing the entries by hand.

**Impact.** A user who wants the kit in some projects but not others cannot express
that with a switch: they must not install user-level, or they uninstall. The injection
is small (see `FORECAST-TOKEN.md`) and fail-open, so the practical cost is low.

**Cause.** Deliberate v0.1.0 scope: the kit is "install once at user level" by design
[code: README, install model]. A project-level opt-out is possible via the documented
project-local wiring, but that is a manual configuration, not a switch.

**Workaround.** `uninstall.ps1` (dry-run first) removes the kit wiring and leaves the
files; re-run `install.ps1 -Apply` to re-enable.

**Status.** Open (by design in v0.1.0).

## 15. CI is not pinning-proof (derived)

**Symptom.** `.github/workflows/ci.yml` (first executed 2026-10-06) uses floating
references: `actions/checkout@v4` (a tag, not a commit SHA) and the runner labels
`windows-latest` / `macos-latest`.

**Impact.** What executes is whatever the tag and the runner image happen to be at
that moment — a moved tag or an updated runner image changes the environment without
any change in this repository. One run is also not a stability proof.

**Cause.** Staged as an executable specification of the intended matrix; pinning was
deferred [code: .github/workflows/ci.yml].

**Workaround.** Before relying on CI, pin `actions/checkout` to a commit SHA and
consider versioned runner images.

**Status.** Open (executed 2026-10-06: Windows leg green, macOS leg red on the null
`$env:TEMP` class — fixed, re-run pending; see also `COPERTURA-RESTO.md`).

## 16. Scan budget: very long commands are denied fail-closed by the opt-in sensor (derived)

**Symptom.** With the sensor installed, a `Bash` command whose text is at or beyond
the scanner budget (200,000 characters) is denied — `[input-oversize]` above the
limit, and `[scanner-budget]` when the raw command is at the limit but the
quote-stripped spelling used for the sensitive-token scan would exceed it. A benign
command that long is refused anyway.

**Impact.** False positive on extreme inputs only; a 200,000-character tool call is
far outside normal use (the scanner exists so a hostile input cannot make the hook
run unbounded work). The denial is declared in the rule id, never silent.

**Cause / design.** Deliberate fail-closed budget in the shared scanner
[code: Hook-Common.ps1, `Get-ScanBudgetVerdict` + the `[input-oversize]` /
`[scanner-budget]` rule ids in `Block-Destructive.ps1`]. The budget estimate is the
sum of the raw text and the quoted twin **only when the two differ**; an earlier
revision summed them unconditionally, doubling the estimate and denying commands at
exactly the declared limit (boundary case: 200,000 characters, no quotes — denied
before the fix, allowed after). The boundary is asserted by the shipped smoke harness
(three cases: at-limit allowed, over-limit denied as `[input-oversize]`, at-limit
with a quote denied as `[scanner-budget]`).

**Workaround.** Split the command, or raise the budget constant if you knowingly
need longer single calls. Everything below the limit is unaffected.

**Status.** Open (by design; boundary asserted by shipped tests).
