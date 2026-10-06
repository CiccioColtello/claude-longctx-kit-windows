#requires -Version 5.1
<#
.SYNOPSIS
    SessionStart hook: injects the project's compact context (.agent/*.md).
.DESCRIPTION
    - Read-only: writes nothing.
    - Overall cap 6000 characters (deviation declared from the spec: avoids adding
      ~7k tokens to every session alongside the global hook already present).
    - Explicit fallback: if .agent is missing or the files are empty, emits a short warning.
    - Never blocks the session: any error -> exit 0.
.NOTES
    Registered on: SessionStart (startup|resume|clear|compact|fork)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$MAX_TOTAL = 6000
$MAX_CONTEXT = 1400
$MAX_STATE = 1500
$MAX_DECISIONS = 1300
$MAX_FAILURES = 700

try {
    . (Join-Path $PSScriptRoot 'Hook-Common.ps1')

    # M15/L8 (class CB/CA): stdin PRESENT but unreadable treated as missing ->
    # 'session: unknown' with no warning (the injected context could be
    # silently incomplete). Read-only UNCHANGED: no line written; the
    # unusable payload is DECLARED in the injected context.
    $inState = Get-HookInput -Detailed
    $input0 = $inState.Object
    if ($null -eq $input0) { $input0 = @{} }
    $inputNote = ''
    if ($inState.ParseError) { $inputNote = 'input-unreadable: stdin present but the JSON is not readable - the injected context may be incomplete' }
    elseif (-not $inState.HadInput) { $inputNote = 'input-missing: no payload on stdin - the injected context may be incomplete' }
    $projectDir = Get-ProjectDir -InputObject $input0
    $source = Get-JsonProp -Object $input0 -Name 'source' -Default 'unknown'
    if ($inState.ParseError) { $source = 'input-unreadable' }
    elseif (-not $inState.HadInput) { $source = 'input-missing' }
    $agentDir = Get-AgentDir -ProjectDir $projectDir
    # ---------------------------------------------------------------------------
    # EXACTLY-ONCE GUARD (kit variant): implementation SHARED by the 4 event
    # hooks in Hook-Common (Test-ProjectLocalInjector; campaign #3, class F6:
    # the registration mention is now read in .claude/settings.json AND in
    # .claude/settings.local.json -- a registration in the local file used to
    # produce a DOUBLE injection). Fail-open everywhere: any doubt -> inject.
    # ---------------------------------------------------------------------------
    if (Test-ProjectLocalInjector -SelfPath $PSCommandPath -ProjectDir $projectDir -HookFileName 'Invoke-SessionStart.ps1') { exit 0 }

    # Injected claims must match the real registration (class: doc-vs-code inside
    # the injected text). The PreToolUse deny sensor is OPT-IN: it is reported as
    # active only when the settings that actually register hooks (project and
    # user) mention Block-Destructive.
    $sensorWired = $false
    try {
        $candFiles = @()
        if ($projectDir) { $candFiles += [System.IO.Path]::Combine($projectDir, '.claude', 'settings.json') }
        # OS-aware home, same order as the merge library (Get-KitRootDefault):
        # USERPROFILE first on Windows (a POSIX-shaped HOME from Git Bash would
        # produce a wrong path), HOME first elsewhere.
        $home_ = ''
        if ($env:OS -eq 'Windows_NT') { $home_ = $env:USERPROFILE; if (-not $home_) { $home_ = $env:HOME } }
        else { $home_ = $env:HOME; if (-not $home_) { $home_ = $env:USERPROFILE } }
        if ($home_) { $candFiles += (Join-Path (Join-Path $home_ '.claude') 'settings.json') }
        foreach ($cf in $candFiles) {
            if ([System.IO.File]::Exists($cf)) {
                $cr = [System.IO.File]::ReadAllText($cf, [System.Text.Encoding]::UTF8)
                if ($cr.IndexOf('Block-Destructive', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $sensorWired = $true; break }
            }
        }
    } catch { $sensorWired = $false }

    # The init hint must be runnable as printed: when the kit layout resolves,
    # print the exact command (kit bin + interpreter); otherwise keep the generic
    # hint (the CLI is deliberately not on PATH).
    $kitBin = ''
    try { $kitBin = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'bin', 'longctx.ps1') } catch { $kitBin = '' }

    if (-not (Test-Path -LiteralPath $agentDir)) {
        $hint = "Run 'longctx init' in this project to activate the kit (see the kit README for the full invocation)."
        if ($kitBin -and [System.IO.File]::Exists($kitBin)) {
            $interp = 'pwsh'
            if ($env:OS -eq 'Windows_NT') { $interp = 'powershell.exe' }
            $hint = 'Activate the kit in this project: ' + $interp + ' -NoProfile -File "' + $kitBin + '" init'
        }
        Write-HookJson -EventName 'SessionStart' -AdditionalContext ("[AGENT_CONTEXT]`nAgent state missing: " + $agentDir + " does not exist. " + $hint + "`n[/AGENT_CONTEXT]")
        exit 0
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('[AGENT_CONTEXT]')
    [void]$sb.AppendLine('# Project context (auto-generated)')
    [void]$sb.AppendLine('root: ' + $projectDir)
    # M12 (class CA): RAW source inside the injected markdown (newline -> new
    # line, leading '##' -> fake section in the session context).
    [void]$sb.AppendLine('session: ' + (ConvertTo-SafeInline -Text $source -Max 60) + ' | ' + (Get-HumanStamp))
    $hookList = 'session-start, pre-compact, post-compact, post-tool-failure'
    if ($sensorWired) { $hookList += ', pre-tool-use(policy deny)' }
    [void]$sb.AppendLine('active hooks: ' + $hookList)
    if ($inputNote) { [void]$sb.AppendLine('WARNING: ' + $inputNote) }
    [void]$sb.AppendLine('')

    # CONTEXT.md - L9 (campaign #2, class CB): "missing" and "present but
    # unreadable" were merged (Read-TextFileSafe returns '' in both cases):
    # a PRESENT and locked file disappeared from the context WITHOUT warning. Now the
    # unreadable case is DECLARED; missing/empty stays omitted (normal
    # behavior, unchanged).
    $stCtx = Read-TextFileState -Path (Join-Path $agentDir 'CONTEXT.md') -MaxChars 20000
    if (-not $stCtx.Ok) {
        [void]$sb.AppendLine('WARNING: CONTEXT.md UNREADABLE (' + (ConvertTo-SafeInline -Text ([string]$stCtx.Error) -Max 120) + '): section potentially incomplete')
    } elseif ($stCtx.Text) {
        [void]$sb.AppendLine('## .agent/CONTEXT.md (excerpt)')
        [void]$sb.AppendLine((Limit-Text -Text ([string]$stCtx.Text) -Max $MAX_CONTEXT))
        [void]$sb.AppendLine('')
    }

    # STATE.md - "Next action" is the most important operational field and can fall
    # beyond the limited-text cutoff: it is emitted FIRST as an explicit
    # excerpt, then the rest of STATE.
    # M1 (class SA, "cap applied BEFORE extraction"): the read is FULL
    # (no -MaxChars) — the 20,000 cap truncated the tail and the extraction ran on the
    # prefix: Next action beyond 20,000 NEVER injected (measured: 21,192). The
    # injection budget stays downstream (Limit-Text), not in the read.
    # L9: explicit tri-state (see the CONTEXT.md block).
    $stState = Read-TextFileState -Path (Join-Path $agentDir 'STATE.md')
    $state = [string]$stState.Text
    if (-not $stState.Ok) {
        [void]$sb.AppendLine('WARNING: STATE.md UNREADABLE (' + (ConvertTo-SafeInline -Text ([string]$stState.Error) -Max 120) + '): section potentially incomplete')
    } elseif ($state) {
        [void]$sb.AppendLine('## .agent/STATE.md')
        $nextAction = Get-MarkdownSection -Text $state -Title 'Next action'
        if ($nextAction) {
            [void]$sb.AppendLine('## Next action (explicit excerpt)')
            [void]$sb.AppendLine((Limit-Text -Text $nextAction -Max 600))
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('## STATE.md (excerpt)')
            $budget = $MAX_STATE - [Math]::Min($nextAction.Length, 600) - 120
            if ($budget -lt 300) { $budget = 300 }
            [void]$sb.AppendLine((Limit-Text -Text $state -Max $budget))
        } else {
            [void]$sb.AppendLine((Limit-Text -Text $state -Max $MAX_STATE))
        }
        [void]$sb.AppendLine('')
    }

    # DECISIONS.md -> latest 2 decisions
    # M1 (class SA): append-only, the LATEST live in the TAIL -> -KeepTail (the
    # truncated head is marked "[truncated N leading characters]"); with a head cut
    # the "latest 2" were the PREFIX ones (real file 65.495 > 60.000 cap: never the
    # true latest).
    $stDec = Read-TextFileState -Path (Join-Path $agentDir 'DECISIONS.md') -MaxChars 60000 -KeepTail
    $dec = [string]$stDec.Text
    if (-not $stDec.Ok) {
        [void]$sb.AppendLine('WARNING: DECISIONS.md UNREADABLE (' + (ConvertTo-SafeInline -Text ([string]$stDec.Error) -Max 120) + '): section potentially incomplete')
    } elseif ($dec) {
        $blocks = @([regex]::Split($dec, '(?m)^## ') | Where-Object { $_.Trim().Length -gt 0 })
        $lastTwo = @($blocks | Select-Object -Last 2)
        if ($lastTwo.Count -gt 0) {
            $decText = '## ' + ($lastTwo -join "`n## ")
            [void]$sb.AppendLine('## .agent/DECISIONS.md (latest decisions)')
            # M1 (2nd wave, ASSEMBLY): the join is in file order (second-to-last,
            # last): a head cut at the section cap kept the SECOND-TO-LAST and
            # threw away the NEWEST decision -> -KeepTail (the tail is the newest).
            [void]$sb.AppendLine((Limit-Text -Text $decText -Max $MAX_DECISIONS -KeepTail))
            [void]$sb.AppendLine('')
        }
    }

    # FAILURES.md -> latest 3 data rows
    # M1 (class SA): same class as DECISIONS — append-only, latest rows in
    # the tail -> -KeepTail (today under cap, but as it grows the prefix loses them).
    $stFail = Read-TextFileState -Path (Join-Path $agentDir 'FAILURES.md') -MaxChars 60000 -KeepTail
    $fail = [string]$stFail.Text
    if (-not $stFail.Ok) {
        [void]$sb.AppendLine('WARNING: FAILURES.md UNREADABLE (' + (ConvertTo-SafeInline -Text ([string]$stFail.Error) -Max 120) + '): section potentially incomplete')
    } elseif ($fail) {
        $rows = @($fail -split "`n" | Where-Object { $_ -match '^\| \d{4}-' } | Select-Object -Last 3)
        if ($rows.Count -gt 0) {
            [void]$sb.AppendLine('## .agent/FAILURES.md (latest failures)')
            # M1 (2nd wave, ASSEMBLY): rows in increasing chronological order
            # (the NEWEST is the last one): a head cut kept the old ones and
            # lost the most recent -> -KeepTail.
            [void]$sb.AppendLine((Limit-Text -Text ($rows -join "`n") -Max $MAX_FAILURES -KeepTail))
            [void]$sb.AppendLine('')
        }
    }

    [void]$sb.AppendLine('## Project operating rules')
    if ($sensorWired) {
        [void]$sb.AppendLine('- PreToolUse deny sensor: ACTIVE - destructive commands and sensitive files are blocked by the deny gate.')
    } else {
        [void]$sb.AppendLine('- PreToolUse deny sensor: not installed (opt-in, -WithSensor); the merged permissions.deny rules for sensitive files still apply.')
    }
    [void]$sb.AppendLine('- Heavy exploration/logs: use the subagents (.claude/agents) instead of filling the main context.')
    [void]$sb.AppendLine('- End of task: update .agent/STATE.md (Goal/Phase/Modified files/Tests/Next action).')
    [void]$sb.AppendLine('- New architectural decision: add it to .agent/DECISIONS.md.')
    [void]$sb.AppendLine('- Never put secrets in .agent/: the hooks redact, but do not paste .env or keys.')
    [void]$sb.AppendLine('[/AGENT_CONTEXT]')

    $text = $sb.ToString()
    $text = Limit-Text -Text $text -Max $MAX_TOTAL

    Write-HookJson -EventName 'SessionStart' -AdditionalContext $text
    exit 0
} catch {
    # Explicit fallback: never block session startup. INLINE recorder
    # (class F9): the old catch re-dot-sourced Hook-Common to record —
    # if the library is broken, it failed again and the empty catch swallowed everything.
    try {
        $pd = $env:CLAUDE_PROJECT_DIR
        if (-not $pd) { $pd = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
        $agentDir = Join-Path $pd '.agent'
        if (Test-Path -LiteralPath $agentDir) {
            $msg = $_.Exception.Message -replace '\r?\n', ' '
            $msg = $msg -replace '\|', '/'
            # B2 (campaign #3, zero-dependency inline: here the library may be the
            # very cause of the error): the cut does not split a surrogate pair.
            if ($msg.Length -gt 160) {
                $cut = 160
                if ([char]::IsHighSurrogate($msg[$cut - 1]) -and [char]::IsLowSurrogate($msg[$cut])) { $cut-- }
                $msg = $msg.Substring(0, $cut) + '...'
            }
            $row = '| ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + ' | Invoke-SessionStart | hook | ' + $msg + ' | hook-error (fail-open, recorder inline) | rerun |' + "`n"
            # L1 (campaign #2, class LA): the row goes through Hook-Inline.ps1 (gate
            # mutex + retry on transient contention). Library missing or broken ->
            # bare append as before: never worse than before, and here an exception
            # is never propagated.
            $inlineRowWritten = $false
            $inlineLib = Join-Path $PSScriptRoot 'Hook-Inline.ps1'
            if (Test-Path -LiteralPath $inlineLib) {
                try { . $inlineLib } catch { }
            }
            if (Get-Command -Name 'Add-InlineRow' -CommandType Function -ErrorAction SilentlyContinue) {
                try { $inlineRowWritten = [bool](Add-InlineRow -Path (Join-Path $agentDir 'FAILURES.md') -Row $row -ProjectDir $pd) } catch { $inlineRowWritten = $false }
            }
            if (-not $inlineRowWritten) {
                $enc = New-Object System.Text.UTF8Encoding($false)
                [System.IO.File]::AppendAllText((Join-Path $agentDir 'FAILURES.md'), $row, $enc)
            }
        }
        $json = '{"systemMessage":"WARNING: SessionStart hook failed - .agent context NOT injected (fail-open recorded in .agent/FAILURES.md)."}'
        [Console]::Out.Write($json)
    } catch { }
    exit 0
}
