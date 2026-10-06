#requires -Version 5.1
<#
.SYNOPSIS
    Black-box smoke test of the longctx kit (shipped hooks, taken from the kit tree).
.DESCRIPTION
    Builds a %TEMP% sandbox that mimics a project (fresh directory, .agent from the
    templates, CLAUDE_PROJECT_DIR) and executes the SHIPPED hook copies with realistic
    JSON stdin, asserting the observable contract:

      (1) SessionStart       -> stdout JSON with [AGENT_CONTEXT] and the project root
      (2) exactly-once guard -> project settings registering Invoke-SessionStart.ps1
                                AND a project-local hook copy: the hook running from
                                OUTSIDE the project exits 0 with EMPTY stdout
      (3) project wiring     -> the hook copy running from INSIDE the project always
                                injects [AGENT_CONTEXT] (discriminator case: it is RED
                                against the old bare-mention guard, which dead-locked
                                the in-project injector)
      (4) PreCompact         -> .agent/archive/*-precompact.md with the snapshot header
      (5) PostCompact        -> STATE.md with "## Last compaction" (+ *-compact-summary.md)
      (6) PostToolUseFailure -> FAILURES.md with a data row for the tool
      (7) digest unavailable -> declared fail-open (exit 0, archive written, fallback
                                section present)
      (8) large state files  -> "Next action" beyond a 20,000-char STATE.md prefix and the
                                newest decision beyond a 60,000-char DECISIONS.md prefix are
                                extracted and injected (caps live in the injection, not in
                                the read); a >20,000-char STATE.md survives the PostCompact
                                rewrite intact
      (9) .agent missing     -> exit 0 with an actionable init hint
     (10) empty stdin        -> exit 0 and the injected context declares 'input-missing'
     (11) longctx init       -> creates .agent/{STATE,DECISIONS,FAILURES,CONTEXT}.md and the
                                project then injects normally (skipped when the kit bin is
                                not next to the hooks copy)
     (12) budget boundary    -> the shipped gate: exactly 200000 chars (no quotes) is NOT
                                denied, 200001 -> [input-oversize], at-limit WITH a quote
                                (quote-stripped twin differs) -> [scanner-budget]

    The sandbox is NEVER cleaned up (deliberate: no recursive deletion in a test):
    the path is printed at the end for inspection.

    Portable: Windows PowerShell 5.1, pwsh 7 on Windows, pwsh 7 on macOS. The hook
    interpreter is 'powershell.exe' on Windows and 'pwsh' elsewhere (detected with
    $env:OS -eq 'Windows_NT'); paths are joined with [System.IO.Path]::Combine.
.NOTES
    -HooksDir / -TemplatesDir: overrides to point at a COPY of the kit (used for the
    discriminance proof: copy core elsewhere, break one thing, run that copy's smoke
    -> it must go red on the right assert).
#>

[CmdletBinding()]
param(
    [string]$HooksDir = '',
    [string]$TemplatesDir = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Pass = 0
$script:Fail = 0

function Get-HookInterpreter {
    <# 'powershell.exe' on Windows, 'pwsh' elsewhere (never a hardcoded absolute path). #>
    [CmdletBinding()]
    param()
    if ($env:OS -eq 'Windows_NT') { return 'powershell.exe' }
    return 'pwsh'
}

function Check {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Ok,
        [AllowEmptyString()][string]$Detail = ''
    )
    if ($Ok) {
        $script:Pass++
        Write-Host ('PASS  ' + $Name)
    } else {
        $script:Fail++
        Write-Host ('FAIL  ' + $Name)
        if ($Detail) { Write-Host ('      detail: ' + $Detail) }
    }
}

function Read-TextRaw {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
        return [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    } catch { return '' }
}

function Get-DirFiles {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Dir, [Parameter(Mandatory)][string]$Filter)
    if (-not (Test-Path -LiteralPath $Dir -PathType Container)) { return @() }
    return @(Get-ChildItem -LiteralPath $Dir -Filter $Filter -File -ErrorAction SilentlyContinue)
}

function Invoke-Hook {
    <#
        Runs ONE shipped hook with JSON stdin. Returns @{ Exit; Out; Err }.
        The child interpreter receives CLAUDE_PROJECT_DIR = $ProjectDir (the caller
        process environment is always restored).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HookPath,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Stdin,
        [Parameter(Mandatory)][string]$ProjectDir,
        [Parameter(Mandatory)][string]$ErrFile
    )
    $exe = Get-HookInterpreter
    $hooksArgs = @('-NoProfile', '-NonInteractive')
    if ($env:OS -eq 'Windows_NT') { $hooksArgs += @('-ExecutionPolicy', 'Bypass') }
    $hooksArgs += @('-File', $HookPath)

    $prev = $env:CLAUDE_PROJECT_DIR
    $env:CLAUDE_PROJECT_DIR = $ProjectDir
    $out = @()
    $code = -1
    try {
        $out = @($Stdin | & $exe @hooksArgs 2> $ErrFile)
        $code = $LASTEXITCODE
    } finally {
        # Restore the caller environment (no file removal).
        if ($null -eq $prev) { [System.Environment]::SetEnvironmentVariable('CLAUDE_PROJECT_DIR', $null) }
        else { $env:CLAUDE_PROJECT_DIR = $prev }
    }
    $errText = ''
    if (Test-Path -LiteralPath $ErrFile) {
        try { $errText = [System.IO.File]::ReadAllText($ErrFile) } catch { $errText = '' }
    }
    return @{ Exit = $code; Out = ($out -join "`n"); Err = $errText }
}

function Get-HookContext {
    <# Extracts hookSpecificOutput.additionalContext from a hook's stdout JSON ('' when absent/unparseable). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Out)
    if ([string]::IsNullOrWhiteSpace($Out)) { return '' }
    try {
        $o = $Out | ConvertFrom-Json -ErrorAction Stop
        $so = $o.PSObject.Properties['hookSpecificOutput']
        if ($so -and $so.Value) {
            $ac = $so.Value.PSObject.Properties['additionalContext']
            if ($ac) { return [string]$ac.Value }
        }
    } catch { }
    return ''
}

# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------

$hooks = $HooksDir
if (-not $hooks) { $hooks = [System.IO.Path]::Combine($PSScriptRoot, '..', '.claude', 'hooks') }
$tpl = $TemplatesDir
if (-not $tpl) { $tpl = [System.IO.Path]::Combine($PSScriptRoot, '..', 'templates') }
try { $hooks = [System.IO.Path]::GetFullPath($hooks) } catch { }
try { $tpl = [System.IO.Path]::GetFullPath($tpl) } catch { }

$required = @('Invoke-SessionStart.ps1', 'Invoke-PreCompact.ps1', 'Invoke-PostCompact.ps1', 'Invoke-PostToolUseFailure.ps1', 'Hook-Common.ps1')
$missing = @()
foreach ($f in $required) {
    if (-not (Test-Path -LiteralPath ([System.IO.Path]::Combine($hooks, $f)) -PathType Leaf)) { $missing += $f }
}
if ($missing.Count -gt 0) {
    Write-Host ('ERROR (prerequisite): shipped hooks not found in ' + $hooks)
    Write-Host ('  missing: ' + ($missing -join ', '))
    exit 2
}
if (-not (Test-Path -LiteralPath ([System.IO.Path]::Combine($tpl, 'agent', 'STATE.md')) -PathType Leaf)) {
    Write-Host ('ERROR (prerequisite): templates not found in ' + $tpl)
    exit 2
}

$root = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), 'longctx-smoke-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
$project = [System.IO.Path]::Combine($root, 'project')
$agentDir = [System.IO.Path]::Combine($project, '.agent')
$archiveDir = [System.IO.Path]::Combine($agentDir, 'archive')
$transcript = [System.IO.Path]::Combine($root, 'transcript.jsonl')
[void](New-Item -ItemType Directory -Force -Path $agentDir)
foreach ($f in @('STATE.md', 'DECISIONS.md', 'FAILURES.md', 'CONTEXT.md')) {
    Copy-Item -LiteralPath ([System.IO.Path]::Combine($tpl, 'agent', $f)) -Destination ([System.IO.Path]::Combine($agentDir, $f))
}

$enc = New-Object System.Text.UTF8Encoding($false)
# Digest deterministically UNAVAILABLE: non-local host -> instant refusal, no network
# traffic, no dependency on whether Ollama is running on the host.
[System.IO.File]::WriteAllText(
    [System.IO.Path]::Combine($agentDir, 'ollama.env'),
    "OLLAMA_HOST=http://203.0.113.1:11434`nOLLAMA_DIGEST_MODEL=qwen3:4b`n",
    $enc)
[System.IO.File]::WriteAllText(
    $transcript,
    '{"type":"user","message":{"role":"user","content":"smoke test line for longctx"}}' + "`n" +
    '{"type":"assistant","message":{"role":"assistant","content":"second test line"}}' + "`n",
    $enc)

Write-Host 'longctx smoke (black-box, shipped hooks)'
Write-Host ('  hook interpreter : ' + (Get-HookInterpreter))
Write-Host ('  hooks            : ' + $hooks)
Write-Host ('  sandbox          : ' + $root)
Write-Host ''

# ---------------------------------------------------------------------------
# (1) SessionStart
# ---------------------------------------------------------------------------
$err1 = [System.IO.Path]::Combine($root, 'stderr-1.txt')
$json1 = (@{ hook_event_name = 'SessionStart'; source = 'startup'; cwd = $project } | ConvertTo-Json -Compress)
$r1 = Invoke-Hook -HookPath ([System.IO.Path]::Combine($hooks, 'Invoke-SessionStart.ps1')) -Stdin $json1 -ProjectDir $project -ErrFile $err1
$obj1 = $null
$parseOk = $false
try { $obj1 = $r1.Out | ConvertFrom-Json -ErrorAction Stop; $parseOk = ($null -ne $obj1) } catch { $parseOk = $false }
Check -Name 'SessionStart: exit 0 and valid stdout JSON' -Ok (($r1.Exit -eq 0) -and $parseOk) -Detail ('exit=' + $r1.Exit + ' stdout(0..120)=' + $r1.Out.Substring(0, [Math]::Min(120, $r1.Out.Length)) + ' stderr=' + $r1.Err)

$ctx = ''
if ($parseOk) {
    $so = $obj1.PSObject.Properties['hookSpecificOutput']
    if ($so -and $so.Value) {
        $ac = $so.Value.PSObject.Properties['additionalContext']
        if ($ac) { $ctx = [string]$ac.Value }
    }
}
Check -Name 'SessionStart: additionalContext with [AGENT_CONTEXT] and the project root' -Ok ($ctx.Contains('[AGENT_CONTEXT]') -and $ctx.Contains($project)) -Detail ('context(0..160)=' + $ctx.Substring(0, [Math]::Min(160, $ctx.Length)))

# ---------------------------------------------------------------------------
# (2) exactly-once guard: the project registers Invoke-SessionStart.ps1 AND holds
#     a project-local hook copy -> the OUT-OF-PROJECT (repo) hook must stay silent.
# ---------------------------------------------------------------------------
$projClaude = [System.IO.Path]::Combine($project, '.claude')
$projHooks = [System.IO.Path]::Combine($projClaude, 'hooks')
[void](New-Item -ItemType Directory -Force -Path $projHooks)
[System.IO.File]::WriteAllText(
    [System.IO.Path]::Combine($projClaude, 'settings.json'),
    "{ `"hooks`": { `"SessionStart`": [ { `"hooks`": [ { `"type`": `"command`", `"command`": `"powershell.exe`", `"args`": [ `"-File`", `"`${CLAUDE_PROJECT_DIR}/.claude/hooks/Invoke-SessionStart.ps1`" ] } ] } ] } }",
    $enc)
# Project-local copy of the whole hook set: the wiring a project would install.
foreach ($f in @(Get-ChildItem -LiteralPath $hooks -File -Filter '*.ps1')) {
    Copy-Item -LiteralPath $f.FullName -Destination ([System.IO.Path]::Combine($projHooks, $f.Name))
}
$err2 = [System.IO.Path]::Combine($root, 'stderr-2.txt')
$r2 = Invoke-Hook -HookPath ([System.IO.Path]::Combine($hooks, 'Invoke-SessionStart.ps1')) -Stdin $json1 -ProjectDir $project -ErrFile $err2
Check -Name 'guard exactly-once: out-of-project hook exits 0' -Ok ($r2.Exit -eq 0) -Detail ('exit=' + $r2.Exit + ' stderr=' + $r2.Err)
Check -Name 'guard exactly-once: out-of-project hook stdout EMPTY' -Ok ($r2.Out.Trim().Length -eq 0) -Detail ('stdout=' + $r2.Out.Substring(0, [Math]::Min(200, $r2.Out.Length)))

# ---------------------------------------------------------------------------
# (3) project wiring (discriminator): the hook copy running from INSIDE the
#     project must always inject. RED against the old bare-mention guard (it
#     silenced every copy: the in-project injector got zero injection).
# ---------------------------------------------------------------------------
$err3 = [System.IO.Path]::Combine($root, 'stderr-3.txt')
$r3 = Invoke-Hook -HookPath ([System.IO.Path]::Combine($projHooks, 'Invoke-SessionStart.ps1')) -Stdin $json1 -ProjectDir $project -ErrFile $err3
Check -Name 'project wiring: in-project hook copy injects [AGENT_CONTEXT]' -Ok (($r3.Exit -eq 0) -and $r3.Out.Contains('[AGENT_CONTEXT]')) -Detail ('exit=' + $r3.Exit + ' stdout(0..120)=' + $r3.Out.Substring(0, [Math]::Min(120, $r3.Out.Length)) + ' stderr=' + $r3.Err)

# ---------------------------------------------------------------------------
# (4)+(7) PreCompact (digest unavailable: non-local host)
# ---------------------------------------------------------------------------
$err4 = [System.IO.Path]::Combine($root, 'stderr-4.txt')
$json4 = (@{ hook_event_name = 'PreCompact'; trigger = 'manual'; session_id = 'smoke-session'; transcript_path = $transcript; cwd = $project } | ConvertTo-Json -Compress)
$r4 = Invoke-Hook -HookPath ([System.IO.Path]::Combine($hooks, 'Invoke-PreCompact.ps1')) -Stdin $json4 -ProjectDir $project -ErrFile $err4
$preFiles = @(Get-DirFiles -Dir $archiveDir -Filter '*-precompact.md')
Check -Name 'PreCompact: exit 0 and archive *-precompact.md created' -Ok (($r4.Exit -eq 0) -and ($preFiles.Count -eq 1)) -Detail ('exit=' + $r4.Exit + ' files=' + $preFiles.Count + ' stderr=' + $r4.Err)

$preText = ''
if ($preFiles.Count -ge 1) { $preText = Read-TextRaw -Path $preFiles[0].FullName }
Check -Name 'PreCompact: header "## State at compaction time"' -Ok ($preText.Contains('## State at compaction time')) -Detail ('archive=' + $preText.Substring(0, [Math]::Min(200, $preText.Length)))

Check -Name 'digest unavailable: declared fail-open (exit 0, fallback section)' -Ok (($r4.Exit -eq 0) -and $preText.Contains('## Local digest NOT available (fallback)')) -Detail ('exit=' + $r4.Exit)

# ---------------------------------------------------------------------------
# (5) PostCompact
# ---------------------------------------------------------------------------
$err5 = [System.IO.Path]::Combine($root, 'stderr-5.txt')
$json5 = (@{ hook_event_name = 'PostCompact'; trigger = 'manual'; compact_summary = 'Smoke-test summary: goal, decisions, next step.'; cwd = $project } | ConvertTo-Json -Compress)
$r5 = Invoke-Hook -HookPath ([System.IO.Path]::Combine($hooks, 'Invoke-PostCompact.ps1')) -Stdin $json5 -ProjectDir $project -ErrFile $err5
$stateText = Read-TextRaw -Path ([System.IO.Path]::Combine($agentDir, 'STATE.md'))
Check -Name 'PostCompact: STATE.md with "## Last compaction"' -Ok (($r5.Exit -eq 0) -and $stateText.Contains('## Last compaction')) -Detail ('exit=' + $r5.Exit + ' stderr=' + $r5.Err)
$sumFiles = @(Get-DirFiles -Dir $archiveDir -Filter '*-compact-summary.md')
Check -Name 'PostCompact: archive *-compact-summary.md created' -Ok ($sumFiles.Count -eq 1) -Detail ('files=' + $sumFiles.Count)

# ---------------------------------------------------------------------------
# (6) PostToolUseFailure
# ---------------------------------------------------------------------------
$failPath = [System.IO.Path]::Combine($agentDir, 'FAILURES.md')
$rowsBefore = @((Read-TextRaw -Path $failPath) -split "`n" | Where-Object { $_ -match '^\| \d{4}-' }).Count
$err6 = [System.IO.Path]::Combine($root, 'stderr-6.txt')
$json6 = (@{ hook_event_name = 'PostToolUseFailure'; tool_name = 'Bash'; tool_input = @{ command = 'npm test' }; error = 'exit code 1: red suite'; is_interrupt = $false; cwd = $project } | ConvertTo-Json -Compress -Depth 5)
$r6 = Invoke-Hook -HookPath ([System.IO.Path]::Combine($hooks, 'Invoke-PostToolUseFailure.ps1')) -Stdin $json6 -ProjectDir $project -ErrFile $err6
$failText = Read-TextRaw -Path $failPath
$rowsAfter = @($failText -split "`n" | Where-Object { $_ -match '^\| \d{4}-' }).Count
Check -Name 'PostToolUseFailure: exit 0 and FAILURES.md with one more data row' -Ok (($r6.Exit -eq 0) -and ($rowsAfter -gt $rowsBefore)) -Detail ('exit=' + $r6.Exit + ' rows ' + $rowsBefore + ' -> ' + $rowsAfter + ' stderr=' + $r6.Err)
$toolRow = [regex]::IsMatch($failText, '(?m)^\| \d{4}-\d{2}-\d{2} [\d:]+ \| Bash \|')
Check -Name 'PostToolUseFailure: data row for the Bash tool' -Ok $toolRow -Detail 'no row with the Bash component'

# ---------------------------------------------------------------------------
# (8) LARGE state files: the caps belong to the INJECTION, never to the READ.
#     Regression guards for the "cap applied BEFORE extraction" class:
#       - STATE.md: the "Next action" section BEYOND a 20,000-char prefix must
#         still be extracted and injected (the STATE read is FULL; the budget is
#         applied downstream by Limit-Text).
#       - DECISIONS.md: the NEWEST decision beyond a 60,000-char prefix must
#         still be injected (append-only file: the read uses -KeepTail).
#       - PostCompact: STATE.md is REWRITTEN, so a >20,000-char state must
#         survive intact (a read cap there would become permanent state loss).
#     The hook used here is the PROJECT-LOCAL copy: with the project
#     registration in place (section 2) it is the injector; the out-of-project
#     copy stays silent by design.
#     Discriminating fault injection (manual, against a hooks COPY: copy core
#     elsewhere, then): add -MaxChars 20000 to the STATE read in
#     Invoke-SessionStart.ps1 / remove -KeepTail from the DECISIONS read /
#     add -MaxChars 20000 to the STATE read in Invoke-PostCompact.ps1 -> this
#     section goes red on the right assert.
# ---------------------------------------------------------------------------
$fillLine = 'T3 filler line 0123456789012345678901234567890123456789' + "`n"   # 56 chars
$nextSentinel = 'T3-NEXT-ACTION-SENTINEL'
$keepSentinel = 'T3-POSTCOMPACT-KEEP-MARKER'
$decSentinel = 'T3-LATEST-DECISION-SENTINEL'
# ~36k chars: the Next action heading sits at ~30,800 (beyond a 20,000 cap) and the
# keep-marker at ~33,100 (beyond it too); the section body >600 chars exercises the
# downstream cap, which keeps the HEAD (sentinel first).
$stateBig = ($fillLine * 550) + "`n## Next action`n" + $nextSentinel + ': proceed with the smoke assertions.' + "`n" + ($fillLine * 40) + "`n" + $keepSentinel + "`n" + ($fillLine * 60)
# ~61.7k chars: the sentinel is the very last line (a head-only 60,000-char read
# would never reach it).
$decBig = ($fillLine * 1100) + "`n## T3 latest decision`n" + $decSentinel + ': kept by the -KeepTail read (append-only file).' + "`n"
$enc8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText([System.IO.Path]::Combine($agentDir, 'STATE.md'), $stateBig, $enc8)
[System.IO.File]::WriteAllText([System.IO.Path]::Combine($agentDir, 'DECISIONS.md'), $decBig, $enc8)

$err8 = [System.IO.Path]::Combine($root, 'stderr-8.txt')
$r8 = Invoke-Hook -HookPath ([System.IO.Path]::Combine($projHooks, 'Invoke-SessionStart.ps1')) -Stdin $json1 -ProjectDir $project -ErrFile $err8
$ctx8 = Get-HookContext -Out $r8.Out
Check -Name 'STATE.md >20k: "Next action" beyond the 20k prefix is extracted and injected' -Ok (($r8.Exit -eq 0) -and $ctx8.Contains('## Next action (explicit excerpt)') -and $ctx8.Contains($nextSentinel)) -Detail ('exit=' + $r8.Exit + ' marker=' + $ctx8.Contains('## Next action (explicit excerpt)') + ' sentinel=' + $ctx8.Contains($nextSentinel) + ' stderr=' + $r8.Err)
Check -Name 'DECISIONS.md >60k: the NEWEST decision survives (-KeepTail read)' -Ok $ctx8.Contains($decSentinel) -Detail ('sentinel=' + $ctx8.Contains($decSentinel) + ' ctx(0..120)=' + $ctx8.Substring(0, [Math]::Min(120, $ctx8.Length)))

$err8b = [System.IO.Path]::Combine($root, 'stderr-8b.txt')
$r8b = Invoke-Hook -HookPath ([System.IO.Path]::Combine($hooks, 'Invoke-PostCompact.ps1')) -Stdin $json5 -ProjectDir $project -ErrFile $err8b
$stateBigAfter = Read-TextRaw -Path ([System.IO.Path]::Combine($agentDir, 'STATE.md'))
Check -Name 'PostCompact >20k STATE.md: rewritten without losing the tail' -Ok (($r8b.Exit -eq 0) -and $stateBigAfter.Contains($keepSentinel) -and $stateBigAfter.Contains('## Last compaction') -and $stateBigAfter.Length -gt 20000) -Detail ('exit=' + $r8b.Exit + ' len=' + $stateBigAfter.Length + ' marker=' + $stateBigAfter.Contains($keepSentinel) + ' stderr=' + $r8b.Err)

# ---------------------------------------------------------------------------
# (9) .agent missing: still exit 0, with an actionable hint (the exact command
#     when the kit layout resolves next to this hooks copy, the generic hint
#     otherwise). No crash, no silent empty injection.
# ---------------------------------------------------------------------------
$projNo = [System.IO.Path]::Combine($root, 'project-noagent')
[void](New-Item -ItemType Directory -Force -Path $projNo)
$err9 = [System.IO.Path]::Combine($root, 'stderr-9.txt')
$r9 = Invoke-Hook -HookPath ([System.IO.Path]::Combine($hooks, 'Invoke-SessionStart.ps1')) -Stdin $json1 -ProjectDir $projNo -ErrFile $err9
$ctx9 = Get-HookContext -Out $r9.Out
$kitBin = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($hooks, '..', '..', 'bin', 'longctx.ps1'))
$hintOk = $ctx9.Contains('Agent state missing') -and ($ctx9.Contains('init'))
if (Test-Path -LiteralPath $kitBin -PathType Leaf) { $hintOk = $hintOk -and $ctx9.Contains('longctx.ps1') }
Check -Name 'missing .agent: exit 0 + init hint (runnable command when the kit tree resolves)' -Ok (($r9.Exit -eq 0) -and $hintOk) -Detail ('exit=' + $r9.Exit + ' ctx=' + $ctx9 + ' stderr=' + $r9.Err)

# ---------------------------------------------------------------------------
# (10) empty stdin: a hook must never crash on it, and the injected context
#      DECLARES the unusable input instead of silently under-injecting.
# ---------------------------------------------------------------------------
$err10 = [System.IO.Path]::Combine($root, 'stderr-10.txt')
$r10 = Invoke-Hook -HookPath ([System.IO.Path]::Combine($projHooks, 'Invoke-SessionStart.ps1')) -Stdin '' -ProjectDir $project -ErrFile $err10
$ctx10 = Get-HookContext -Out $r10.Out
Check -Name 'empty stdin: exit 0 and the injection declares input-missing' -Ok (($r10.Exit -eq 0) -and $ctx10.Contains('input-missing')) -Detail ('exit=' + $r10.Exit + ' declares=' + $ctx10.Contains('input-missing') + ' stderr=' + $r10.Err)

# ---------------------------------------------------------------------------
# (11) longctx init: the hint printed in (9) is a real, runnable bootstrap.
#      Uses the kit bin next to this hooks copy (skipped, not failed, when smoke
#      runs against a hooks-only copy without bin/).
# ---------------------------------------------------------------------------
$binArgs = @('-NoProfile', '-NonInteractive')
if ($env:OS -eq 'Windows_NT') { $binArgs += @('-ExecutionPolicy', 'Bypass') }
if (Test-Path -LiteralPath $kitBin -PathType Leaf) {
    $err11 = [System.IO.Path]::Combine($root, 'stderr-11.txt')
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'   # native stderr must not become a terminating error on PS 5.1
    try {
        $outBin = @(& (Get-HookInterpreter) @($binArgs + @('-File', $kitBin, 'init', '-ProjectDir', $projNo)) 2> $err11)
        $code11 = $LASTEXITCODE
    } finally { $ErrorActionPreference = $prevEap }
    $made11 = @()
    foreach ($f in @('STATE.md', 'DECISIONS.md', 'FAILURES.md', 'CONTEXT.md')) {
        if (Test-Path -LiteralPath ([System.IO.Path]::Combine($projNo, '.agent', $f)) -PathType Leaf) { $made11 += $f }
    }
    Check -Name 'longctx init: creates .agent/{STATE,DECISIONS,FAILURES,CONTEXT}.md (exit 0)' -Ok (($code11 -eq 0) -and ($made11.Count -eq 4)) -Detail ('exit=' + $code11 + ' files=' + ($made11 -join ',') + ' out=' + (($outBin -join ' ') -replace '\r?\n', ' ').Trim())
    $err11b = [System.IO.Path]::Combine($root, 'stderr-11b.txt')
    $r11b = Invoke-Hook -HookPath ([System.IO.Path]::Combine($hooks, 'Invoke-SessionStart.ps1')) -Stdin $json1 -ProjectDir $projNo -ErrFile $err11b
    $ctx11b = Get-HookContext -Out $r11b.Out
    Check -Name 'after longctx init: SessionStart injects .agent (hint path closes the loop)' -Ok (($r11b.Exit -eq 0) -and $ctx11b.Contains('[AGENT_CONTEXT]') -and (-not $ctx11b.Contains('Agent state missing'))) -Detail ('exit=' + $r11b.Exit + ' missing-hint=' + $ctx11b.Contains('Agent state missing'))
} else {
    Write-Host ('SKIP  longctx init leg: kit bin not found next to the hooks copy (' + $kitBin + ')')
}

# ---------------------------------------------------------------------------
# (12) scan-budget boundary (class found LIVE by the source workspace's contract
#      harness): the estimate must never ANTICIPATE the declared limit. A command
#      of exactly ScanBudgetMaxChars (200000) characters carries no quotes -> the
#      quote-stripped twin IS the raw text -> the estimate must be the raw text
#      alone (raw+raw doubled it and denied at the boundary) and the gate must NOT
#      deny it. 200001 chars stay fail-closed ('input-oversize'), and an at-limit
#      command WITH a quote (twin differs: the scanner really walks two texts) is
#      denied fail-closed with the honest 'scanner-budget' label.
# ---------------------------------------------------------------------------
$gateHook = [System.IO.Path]::Combine($hooks, 'Block-Destructive.ps1')
$cmdAtLimit = 'echo x; ' * 25000                 # exactly 200000 characters
$cmdOver = $cmdAtLimit + 'x'                     # 200001
$cmdAtLimitQ = $cmdAtLimit.Substring(0, 199997) + '"ab'   # 200000 chars incl. one quote
$gateJson = (@{ tool_name = 'Bash'; tool_input = @{ command = $cmdAtLimit } } | ConvertTo-Json -Compress -Depth 5)
$err12 = [System.IO.Path]::Combine($root, 'stderr-12.txt')
$r12a = Invoke-Hook -HookPath $gateHook -Stdin $gateJson -ProjectDir $project -ErrFile $err12
Check -Name 'budget boundary: exactly 200000 chars (no quotes) is NOT denied (limit not anticipated)' -Ok (($cmdAtLimit.Length -eq 200000) -and ($r12a.Exit -eq 0) -and (-not ($r12a.Out -match '"permissionDecision":"deny"'))) -Detail ('len=' + $cmdAtLimit.Length + ' exit=' + $r12a.Exit + ' out=' + $r12a.Out.Trim().Substring(0, [Math]::Min(120, $r12a.Out.Trim().Length)))
$gateJson2 = (@{ tool_name = 'Bash'; tool_input = @{ command = $cmdOver } } | ConvertTo-Json -Compress -Depth 5)
$r12b = Invoke-Hook -HookPath $gateHook -Stdin $gateJson2 -ProjectDir $project -ErrFile $err12
Check -Name 'budget boundary: 200001 chars denied fail-closed [input-oversize]' -Ok (($r12b.Exit -eq 0) -and ($r12b.Out -match '"permissionDecision":"deny"') -and ($r12b.Out -match '\[input-oversize\]')) -Detail ('exit=' + $r12b.Exit + ' out=' + $r12b.Out.Trim().Substring(0, [Math]::Min(120, $r12b.Out.Trim().Length)))
$gateJson3 = (@{ tool_name = 'Bash'; tool_input = @{ command = $cmdAtLimitQ } } | ConvertTo-Json -Compress -Depth 5)
$r12c = Invoke-Hook -HookPath $gateHook -Stdin $gateJson3 -ProjectDir $project -ErrFile $err12
Check -Name 'budget boundary: at-limit WITH a quote (twin differs) denied fail-closed [scanner-budget]' -Ok (($cmdAtLimitQ.Length -eq 200000) -and ($r12c.Exit -eq 0) -and ($r12c.Out -match '"permissionDecision":"deny"') -and ($r12c.Out -match '\[scanner-budget\]')) -Detail ('len=' + $cmdAtLimitQ.Length + ' exit=' + $r12c.Exit + ' out=' + $r12c.Out.Trim().Substring(0, [Math]::Min(120, $r12c.Out.Trim().Length)))

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host ('PASS: ' + $script:Pass + ' | FAIL: ' + $script:Fail)
Write-Host ''
Write-Host 'COVERAGE (what was proven):'
Write-Host '  - Shipped SessionStart: exit code, parseable stdout JSON, [AGENT_CONTEXT] marker and project root in the injected context.'
Write-Host '  - Exactly-once guard (new semantics): project settings registering Invoke-SessionStart.ps1 + a project-local hook copy -> the OUT-OF-PROJECT hook exits 0 with empty stdout.'
Write-Host '  - Project wiring discriminator: the hook copy running from INSIDE the project injects [AGENT_CONTEXT] (RED against the old bare-mention guard, which dead-locked the in-project injector).'
Write-Host '  - Shipped PreCompact: exit 0, .agent/archive/*-precompact.md with the snapshot header.'
Write-Host '  - Shipped PostCompact: exit 0, STATE.md updated ("## Last compaction") and *-compact-summary.md archived.'
Write-Host '  - Shipped PostToolUseFailure: exit 0, FAILURES.md gains a data row for the Bash tool.'
Write-Host '  - Digest unavailable (non-local OLLAMA_HOST in .agent/ollama.env): declared fail-open, exit 0, fallback section in the archive.'
Write-Host '  - Large state files: Next action beyond a 20,000-char STATE.md prefix and the newest decision beyond a 60,000-char DECISIONS.md prefix are injected; a >20,000-char STATE.md survives the PostCompact rewrite.'
Write-Host '  - Missing .agent: exit 0 with an actionable init hint; empty stdin: exit 0 with the input-missing declaration; longctx init bootstraps .agent/ and the project then injects.'
Write-Host '  - Scan-budget boundary on the shipped gate: exactly 200000 chars (no quotes) is NOT denied (the estimate sums the quote-stripped twin ONLY when it differs); 200001 chars -> [input-oversize]; at-limit WITH a quote -> [scanner-budget] (two real passes).'
Write-Host ''
Write-Host 'REST (what is NOT covered):'
Write-Host '  - No assertion on local digest content (needs a reachable Ollama: the fallback branch is forced here).'
Write-Host '  - No assertion on the PreToolUse gate beyond the scan-budget boundary (rule table, sensitive-token classification, protected-area writes: dedicated matrices); Hook-Inline/rotations/limits (dedicated matrices).'
Write-Host '  - The large-state asserts check the GREEN contract: their discriminator power was proven separately by fault injection on a kit COPY (STATE read + -MaxChars 20000 / DECISIONS read without -KeepTail / PostCompact STATE read + -MaxChars 20000 -> exactly those 3 FAIL, exit 1; 16 PASS), not by this run.'
Write-Host '  - The budget-boundary asserts check the GREEN contract: their discriminator power was proven separately (the boundary case failed 1/619 on the source workspace before the conditional-sum fix), not by this run.'
Write-Host '  - The longctx init leg is skipped (not failed) when smoke runs against a hooks-only copy without bin/.'
Write-Host '  - Concurrent multi-process writes and lock cases are not exercised.'
Write-Host '  - The sandbox is never cleaned up: the path is printed above for inspection.'
Write-Host ''

if ($script:Fail -gt 0) { exit 1 }
exit 0
