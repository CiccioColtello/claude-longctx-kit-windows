# Coverage and Rest — verification ledger

This document records, honestly and mechanically, what was verified before release
and what was **not**, with the evidence that produced each claim. If a claim is not
listed under "Coverage", treat it as unverified.

Verification date: 2026-10-06 (re-run after the post-audit fix campaign, again
after the StrictMode member-access class fix, and again after campaign #3 — classes
F1–F8 plus the scan-budget boundary class; the numbers below describe the state
**after** the fixes, with the macOS core mirrored byte-for-byte).
Toolchain: Windows 11, Windows PowerShell 5.1 and PowerShell 7 (pwsh).

## Coverage (proven, with the evidence that proves it)

**1. Core parity between the two repositories.**
`tools/verify-parity.ps1` hashes every file of `core/` in both repos (SHA-256 via
.NET, hidden files included) and compares byte-by-byte: **31/31 core files identical**,
exit 0, re-run after the last campaign #3 mirror. The two root `install.ps1` /
`uninstall.ps1` copies are byte-identical as well. OS-specific differences are excluded
by design: they live only in root files (shell adapters, docs) and in the two settings
examples.

**2. English-only repositories (language directive).**
- Mechanical residue scan across every file of both repos (four pattern classes:
  Italian function words, the ASCII-escaped Italian copula, accented Latin
  characters, known Italian phrases): 45 files in the Windows repo, 49 in the macOS
  repo (this document and the repos' `.gitattributes` included; `.git/` and the
  internal `STAGE-REPORT.txt` excluded). All remaining matches (50 word-list hits on
  Windows, 53 on macOS — the macOS extra being `TEST-PLAN-MAC.md` and `verify.sh`,
  macOS-only files) are English `non-*` compounds and similar (`non-destructive`,
  `non-local`, `non-loopback`, `non-canonical`, `non-zero`); **0 real Italian sites**
  in both repos — every detected match classified by hand. Re-run after the campaign
  #3 documentation edits.
- PowerShell syntax: parse-check of every `.ps1` file in both repos (19 each):
  **0 parse failures**, under both Windows PowerShell 5.1 and pwsh 7.
- Shell syntax (macOS leg of the CI specification, executed locally): `bash -n` over
  `install.sh`, `uninstall.sh`, `verify.sh` in the macOS repo: **syntax OK, exit 0**
  for all three (Git Bash on Windows — syntax only; real macOS execution stays in
  Rest, item 1).
- Coordinated literals (strings written by one file AND asserted by another) are
  verified to match exactly, and are exercised live by the smoke run:
  - `## State at compaction time (deterministic)` — writer `Invoke-PreCompact.ps1`
    (line 149), assert `core/tests/smoke.ps1` (line 242).
  - `## Local digest NOT available (fallback)` — writer `Invoke-PreCompact.ps1`
    (line 220), assert `core/tests/smoke.ps1` (line 244).
  - Doc-vs-code quotes used by the manual test plans were aligned with the shipped
    code: `## Next action (explicit excerpt)`, `(STATE.md updated)`, the cause
    codes (`input-unreadable`, `digest-local-fallback`), and the truncation markers
    (`[truncated <N> leading characters]` / `[truncated <N> trailing characters]`).

**3. Behavior tests, run from the staged repositories (post-translation, post-fix).**
- Settings-merge selftest (`core/lib/merge-claude-settings.ps1 -SelfTest`):
  **44 PASS / 0 FAIL** under Windows PowerShell 5.1 **and under PowerShell 7
  (pwsh)**, exit 0 in both runs; the same 44/0 on the macOS repository (both
  interpreters; its core is byte-identical). The selftest block itself now runs under
  `Set-StrictMode -Version Latest` — the same mode the production callers use
  (before this fix it ran non-strict and structurally could not see the
  StrictMode member-access class). Includes the
  home-resolution matrix (USERPROFILE/HOME combinations; never a silent relative
  fallback), the two-saves-two-distinct-backups case, the invalid-UTF-8
  fail-closed cases 4c/4d, the 25-level deep-structure case 11a, the StrictMode
  member-access cases 12a-f (hook entries without `args`, entries without
  `hooks`, null/string elements — the shape found in the operator's real
  settings.json) and the fail-closed shape cases 13a-d (non-object
  `hooks`/`root`/`permissions` refuse; null-valued members are treated as empty).
  - **Both new cases discriminate**: run against a pre-fix copy of the library
    (preserved from the macOS repo before the core sync), invalid UTF-8 did **not**
    throw (`threw=False`) and the 25-hop marker read `""` instead of `sentinel-deep`
    [evidence: `red-probe-postverdict.ps1` output, 2026-10-06]. After the fix both
    checks pass — the tests are RED against the old code and GREEN against the new.
- Smoke harness (`core/tests/smoke.ps1`): **22 PASS / 0 FAIL** under both Windows
  PowerShell 5.1 and PowerShell 7 (pwsh) on the Windows repository, and under pwsh on
  the macOS repository, re-run after the campaign #3 fixes. It runs
  the real shipped hooks in a sandbox project; includes the in-project guard
  discriminator (the project copy must inject), both coordinated markers above, and
  the three scan-budget boundary cases (at-limit allowed; over-limit denied
  `[input-oversize]`; at-limit with a quote denied `[scanner-budget]`).
  - **The budget-boundary cases discriminate**: with the pre-fix unconditional sum
    re-injected into a kit copy (fault injection, one anchor hit asserted), the
    at-limit case fails — 1 FAIL / 21 PASS, exit 1
    [evidence: `boundary-fi.ps1` output, 2026-10-06]. The same boundary case is what
    first failed (1/619) on the source workspace's contract harness, which is how
    the class was found.
  - **Scope of "under pwsh":** the harness itself ran under both interpreters; on
    Windows the hooks it launches are started with `powershell.exe` in both runs
    (by design: `Get-HookInterpreter` returns `powershell.exe` on Windows, `pwsh`
    elsewhere). Hook execution under pwsh is therefore exercised only on the macOS
    leg — which is BETA and unexecuted (Rest, item 1).
- Shipped security probe (`core/tests/probe-hardening.ps1`): **19 PASS / 0 FAIL** on
  the Windows repository under both interpreters, and on the macOS repository under
  both interpreters — four green legs. It runs the shipped hooks and both installers
  as real child processes and asserts: deny-gate rule ids on destructive / privilege /
  git-force commands **including the quote-split evasions**, allowed benign commands
  (a quoted word that merely looks like a path included), the failure-log masking of
  a glued reference, and the `KitRoot` ownership gate (home-ancestor and settings-dir
  refusal by `install.ps1` AND `uninstall.ps1`; the default shape still accepted;
  `settings.json` byte-untouched).

**4. Hygiene (release gate).**
Automated scan of every file in both repos across 11 categories — 4 personal-data
patterns (user paths, user token, drive letter, private identity), 6 secret
patterns (AWS key, private-key block, GitHub token, Slack token, api-key
assignment, password assignment), and 1 double-substitution canary:
**0 occurrences in every category, in both repos**.

*Deliberate, operator-directed exception (2026-10-06): the public alias
**CiccioColtello** is credited as author and copyright holder in `LICENSE` and
`README.md`. It is a public handle, not private identity, so it was removed from
the private-identity pattern; that pattern still forbids the real name, the
personal e-mail and the city.*

**5. Build provenance.**
Staging engine exit 0 on both repos with per-file SHA-256 recorded at stage time;
core byte-identity between the two repos holds after every subsequent edit
(re-asserted by the finalize pass after the translation campaign and again after
the fix campaign). The release snapshot is frozen with
`freeze-manifest.ps1` (SHA-256 per shipped file, excluding `.git/` and the
internal `STAGE-REPORT.txt`).

**6. Post-audit fix campaign — what changed and how each item is verified.**
- **macOS script loading (class: backslash is not a path separator on macOS).**
  `Invoke-Digest.ps1` and `Filter-File.ps1` dot-sourced `Hook-Common.ps1` with a
  backslash inside the `Join-Path` child; on pwsh/macOS the backslash becomes part
  of the file name and the load fails. Fixed to forward slashes at all 3 runtime
  callsites; class sweep found no other `Join-Path`/`::Combine` callsite passing a
  backslash child (the sensor's backslash paths are declared Windows-only,
  KNOWN-ISSUES #12). Verified: both scripts parse and execute under pwsh on
  Windows; real macOS execution stays in Rest.
- **Merge rewrite fidelity (class: silent truncation).** The save path used
  `ConvertTo-Json -Depth 20`; a deeper structure was silently turned into strings
  on rewrite. Now `-Depth 100`, covered by selftest 11a (RED-proved above).
- **Fail-closed settings reads (class: silent corruption).** The merge library,
  `uninstall.ps1` and `verify.ps1` now read `settings.json` with a strict UTF-8
  decoder (`throwOnInvalidBytes`): invalid bytes are a hard error and **nothing is
  written**, exactly like invalid JSON. Covered for the library by selftest 4c/4d
  (RED-proved above); the uninstall/verify copies are code-reviewed and
  parse-checked, not unit-tested (Rest, item 7).
- **Truthful injected claims (class: doc-vs-code inside generated text).** The
  `active hooks:` list and the PreToolUse line in the injected block are now
  conditional on the sensor actually being registered (project + user settings are
  scanned); `-WithSensor -Os mac` prints the Windows-only scope warning. The
  `.agent`-missing message prints the exact runnable activation command when the
  kit layout resolves. Verified: smoke 12/0 re-run (checked: no shipped assertion
  is coupled to those strings, so the change cannot be falsely masked by the
  harness); the wording itself is not asserted by any shipped test (Rest, item 7).
- **OS-aware home resolution (class: environment-order mismatch).** The four root
  scripts (`install.ps1`, `uninstall.ps1`, `verify.ps1`, `bin/longctx.ps1`) now
  resolve the home with the same order as the merge library (USERPROFILE first on
  Windows, HOME first elsewhere). Covered for the library by selftest 9a/9b/9c;
  the root scripts' own helper copies are not asserted by a shipped test (Rest).
- **Install-side warning for the macOS sensor.** `install.ps1 -WithSensor -Os mac`
  now prints the KNOWN-ISSUES #12 scope warning; verified by dry-run output.
- **StrictMode member access on user JSON (class: direct property access).** The
  merge library scanned existing hook entries with direct `$entry.hooks`/`$h.args`
  access, while production callers dot-source it under
  `Set-StrictMode -Version Latest`; a real settings.json whose hook element has no
  `args` (shape found on the operator machine, names/types only:
  `{"type":"command","command":"...","timeout":30}`) aborted the whole install
  with `PropertyNotFoundException` — and the selftest never set StrictMode, so it
  structurally could not see the class (it was green while the dry-run was red).
  Fixed: `Test-OurEntry` now uses the same defensive `PSObject.Properties`
  pattern as the other three scanners (`uninstall.ps1` Test-OurHook,
  `verify.ps1` Get-OurHookFiles, `bin/longctx.ps1` Test-KitEntry — swept, all
  three were already safe); non-object `hooks`/`permissions`/root now fail
  **closed** instead of being silently mis-merged (pre-fix they reported
  `updated` and the added hooks would have been dropped at save time —
  fail-open); null-valued members are treated as empty; the selftest runs under
  StrictMode. Proven: 2x2 probe matrix (pre-fix vs post-fix library x
  Windows PowerShell 5.1 / pwsh 7) — pre-fix, 11 of 14 hostile shapes AND a
  sandbox copy of the real settings.json threw on both interpreters; post-fix,
  none of the realistic shapes throws, the real file merges
  (`updated, added=4, deny=11`), the non-object shapes fail closed with honest
  messages, and the installer dry-run on the real machine exits 0 (it exited 1
  before the fix). Selftest 41/0 on both interpreters. No settings content was
  ever printed: the real file was only copied to a sandbox and parsed, structure
  names/types only [evidence: `repro-strict.ps1` output, 2026-10-06].

**7. Campaign #3 — classes F1–F8 and the scan-budget boundary.**
Each class was found by a discriminating probe (RED against the pre-fix code), fixed
at every callsite (class sweep, not per-symptom patch), and re-proved GREEN. The
probes below are development artifacts (internal build workspace, not shipped); the
*observable contract* of the classes is now asserted by the two shipped tests
(`core/tests/smoke.ps1`, `core/tests/probe-hardening.ps1`) for the cases listed.

- **F1 — deny-rule delimiter classes.** Several sensor rules could not match the same
  command invoked with a leading path (`/bin/rm -rf`, `./rm -rf`). Sweep: every rule
  of the table extracted and structurally checked for a separator in its initial
  delimiter class + an invocation-form matrix: **47 PASS / 0 FAIL** on the Windows
  and on the macOS hooks copy [`p1-deny.ps1`]. The F7 cases below are asserted by the
  shipped probe.
- **F2 — ownership prefix / ancestor / settings-dir gate.** `-KitRoot` equal to a
  home ancestor, or to the settings dir (`<home>/.claude`), is refused (exit 2) by
  `install.ps1` and `uninstall.ps1`, with `settings.json` byte-untouched; the default
  shape is still accepted. Matrix: **9 PASS / 0 FAIL** on the Windows repo and on the
  macOS repo [`p2-ownership.ps1`; the macOS copies previously diverged — no
  settings-dir gate — and were fixed and re-mirrored]. Shipped in
  `core/tests/probe-hardening.ps1` (leg B).
- **F3 — non-OS-aware canonicalization.** The sensitive-path matcher canonicalized
  with Windows semantics regardless of flavor; a POSIX trailing space / trailing dot
  segment was rewritten as if Windows. Now flavor-aware (`windows` / `posix` /
  `auto`). Matrix: **9 PASS / 0 FAIL** on both hooks copies, including the 16-value
  Windows battery and the POSIX rows [`p3-posix.ps1`]. The POSIX rows executed
  through the PowerShell path on Windows; a real POSIX filesystem remains in Rest.
- **F4 — parity tool proved parity over a subset.** `tools/verify-parity.ps1` did not
  enumerate hidden files, so everything under `.claude/` was invisible while the tool
  printed `PARITY OK`; it now enumerates hidden files and refuses (exit 2) when it
  cannot prove coverage of `.claude/` in both cores. Matrix (fake trees): hidden
  divergence → PARITY FAIL; missing `.claude/` → refused exit 2; hidden file on one
  side only → exit 1: **4 PASS / 0 FAIL** [`p4-parity.ps1`]. The 31/31 result above is
  produced by the fixed tool.
- **F5 — settings save: retry + temp cleanup.** `Save-ClaudeSettings` retries the
  atomic replace and cleans its temporary file in a `finally`; a locked target no
  longer leaves an orphan `.tmp`. Matrix: target locked with `FileShare::None` →
  pre-fix RED (orphan present) vs post-fix GREEN (no orphan, honest error). This one
  is asserted by a development probe only — no shipped test exercises the locked
  target (Rest, item 13).
- **F6 — exactly-once guard asymmetry.** The guard lived only in the injector and read
  only `settings.json`; a project wired the documented way ran the other three event
  hooks twice. Now a shared helper applied by all four hooks, scanning
  `settings.json` **and** `settings.local.json`. Matrix (4 hooks × 5 configurations):
  **20 PASS / 0 FAIL** on both trees [`p6-exactly-once.ps1`]. Shipped: the smoke
  harness asserts the in-project discriminator.
- **F7 — quote-split deny evasion + log-masking twin.** `cat ."env"` /
  `~/."claude"/settings.json` were allowed by the gate (the quotes split the token)
  and kept raw in the failure log once denied by another rule. The gate now scans the
  de-quoted spelling; the masker re-classifies the original quote-inclusive spans.
  Matrix: **13 PASS / 0 FAIL** on both trees (deny with the right rule id; the glued
  row masked; benign commands unchanged) [`p7-deny-glue.ps1`]. Shipped in
  `probe-hardening.ps1`.
- **F8 — degraded fallback without `Filter-AgentText.ps1`.** A hooks copy missing the
  filter library made `Limit-Text` undefined: `SessionStart` injected nothing and
  `PreCompact`/`PostCompact` wrote nothing — a silent fail-open. The degradation path
  now carries a minimal `Limit-Text` twin and records the reduced-redaction
  degradation row. Matrix: **5 PASS / 0 FAIL** on both trees (effect present, row
  recorded) [`p8-degraded.ps1`]. The source workspace's Italian-locale variant of the
  row was asserted separately [`p8-e-locale.ps1`].
- **Scan-budget boundary (found live by the source workspace's contract harness).**
  The budget estimate summed raw + quote-stripped text **unconditionally**, doubling
  the estimate for commands with no quotes and denying a command at exactly the
  declared 200,000-character limit. Fixed at every budget callsite in the shipped
  hooks (scanner, masker, protected-path scan, gate early check) with a conditional
  sum. RED-proved by fault injection on a kit copy: at-limit case fails (1/21, exit
  1) with the unconditional sum re-injected [`boundary-fi.ps1`]; GREEN asserted by the
  three shipped smoke checks.

**8. The same fixes in the operator's live workspace (outside the repos).**
The private source workspace that this kit was extracted from received
the F7 and F8 fixes and the conditional-sum fix as well, and its own contract
harnesses were re-run green in sequence: hook contract **619 PASS / 0 FAIL**, failure
matrix **229 PASS / 0 FAIL**, BOM normalization clean. This is context for why the
classes were found, not a shipped deliverable; the workspace is not part of either
repository.

## Rest (NOT proven — do not claim these)

1. **macOS runtime.** No macOS machine was available. The `.sh` installers
   (`install.sh`, `uninstall.sh`, `verify.sh`) were reviewed and syntax-checked
   (`bash -n`, exit 0, Git Bash on Windows) but never executed,
   and the pwsh smoke was never run under real macOS. The backslash-path fix in
   the two scripts is reasoned from the pwsh path semantics and exercised under
   pwsh on Windows only. Partial mitigation: the macOS repository's PowerShell half
   is byte-identical to the Windows one (§1) and the shipped security probe passes
   against the macOS tree under both interpreters on Windows (§7, F2). `TEST-PLAN-MAC.md`
   is the manual procedure that closes this gap; until it is executed on a Mac, the
   macOS variant is BETA.
2. **Local digest content.** The smoke harness forces the fallback branch (no
   reachable Ollama) and asserts only the declared fail-open behavior; the
   quality/content of a real digest answer is never asserted.
3. **Opt-in PreToolUse sensor.** `Block-Destructive.ps1` ships opt-in (off by
   default) and is not exercised by the smoke harness (which declares this
   explicitly). The shipped security probe (`core/tests/probe-hardening.ps1`) does
   exercise it, but only a curated subset of the rule table (deny ids including the
   quote-split evasions, the masking, the ownership gate); no shipped canary asserts
   that each individual rule of the table fires. Known
   open items are tracked in `KNOWN-ISSUES.md` (items 1, 2, 12 and 16).
4. **Concurrency.** Multi-process/lock contention on the state files was not
   exercised.
5. **Translation completeness.** A finite word-list scan cannot prove the absence
   of every possible Italian word; coverage rests on four scan pattern classes
   plus per-file agent reports and manual classification of every hit.
6. **`STAGE-REPORT.txt`** (both repos, gitignored, not distributed) is an internal
   build artifact whose hashes and sizes predate the English translation pass;
   they are stale by design.
7. **Hostile/exotic `settings.json` inputs — partial coverage.** Covered:
   invalid JSON and invalid UTF-8 fail closed (selftest 4b/4c/4d); hook entries
   without `args`/`hooks`, null/string elements and null-valued
   `hooks`/`permissions` merge cleanly (selftest 12a-f, 13d); non-object
   `hooks`/`permissions`/root fail closed (selftest 13a-c). NOT covered:
   duplicate keys are collapsed last-wins on rewrite (KNOWN-ISSUES #13) and not
   asserted; very large files and exotic encodings (e.g. UTF-16 with BOM) are
   not exercised. Also not asserted: the injected-claim wording (item 6 above),
   the root scripts' own home helper and the uninstall/verify strict-read
   copies.
8. **Watchdog/deadline paths not asserted.** No shipped test kills a hook
   mid-digest or exercises the 45 s clamp boundary; the fallback branch is
   asserted, the timing behavior is not (KNOWN-ISSUES #6 and #11).
9. **Installer/uninstaller end-to-end never executed by the harness.** The
   `-Apply` paths (file copy + settings write + backup) are not run by any shipped
   test; dry-run output was reviewed. The first real execution is the operator
   activation on Windows (manual, one machine, not a shipped test).
10. **T3/T8 stress matrices not shipped.** The large-state injection and
    cap-boundary stress matrices live in the internal build workspace only.
11. **CI executed once (2026-10-06), not pinning-proof.** `.github/workflows/ci.yml`
    uses `actions/checkout@v4` (tag, not SHA) and floating runner labels
    (KNOWN-ISSUES #15). First run: `windows-latest` leg green; `macos-latest` leg
    red in 7 s on a null `$env:TEMP` in the merge-engine selftest — class fix
    applied (OS-aware sandbox root; RED->GREEN proven locally), re-run pending.
    One run is not a stability proof.
12. **Uninstall semantic deviation (declared).** `permissions.deny` rules are kept
    by default on uninstall; removal requires the explicit `-RemoveDenyRules`
    switch. Declared deviation, not covered by shipped tests.
13. **Settings-save lock behavior (F5) not asserted by any shipped test.** The
    retry/no-orphan contract was proven with a development probe that locks the
    target (`FileShare::None`); the shipped smoke exercises only the normal save
    path.
14. **Campaign #3 class probes are not shipped.** `p1`–`p4`, `p6`–`p8`,
    `boundary-fi` and `p8-e-locale` live in the internal build workspace. Their
    observable contracts that ARE shipped: F7 deny + masking and F2 ownership /
    settings-dir (shipped probe), F6 in-project discriminator and the scan-budget
    boundary (shipped smoke). The F1 structural sweep, F3 flavor matrix, F4 parity
    invariant and F5 lock matrix have no shipped equivalent.
15. **macOS shell adapters: syntax only.** `bash -n` proves the three `.sh` files
    parse; nothing about their runtime behavior on macOS is proven (see item 1).
16. Anything not listed under Coverage is unverified: assume it.

## Evidence locations (internal build workspace, not distributed)

- Staging: `stage-kit-v2.ps1` + `STAGE-REPORT.txt`
- Finalize: `finalize-kit.ps1` + `FINALIZE-REPORT.txt` (core sync, BOM
  normalization, parity assert, hygiene scan, expected files)
- Scanners: `check-residue.ps1`, `check-parse.ps1`
- RED probes: `red-probe-postverdict.ps1` (pre-fix vs post-fix discrimination)
- Campaign #3 class probes: `p1-deny.ps1` (F1), `p2-ownership.ps1` (F2),
  `p3-posix.ps1` (F3), `p4-parity.ps1` (F4), `p6-exactly-once.ps1` (F6),
  `p7-deny-glue.ps1` (F7), `p8-degraded.ps1` + `p8-e-locale.ps1` (F8),
  `boundary-fi.ps1` (scan-budget boundary fault injection), plus the
  `mirror-core.ps1` core-mirror + SHA-256 compare used for the macOS sync
- Freeze: `freeze-manifest.ps1` → `MANIFEST-FINAL.sha256` (release snapshot)
- Tests: `core/lib/merge-claude-settings.ps1 -SelfTest`, `core/tests/smoke.ps1`,
  `core/tests/probe-hardening.ps1`, `tools/verify-parity.ps1`
