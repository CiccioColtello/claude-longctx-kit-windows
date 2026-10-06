#requires -Version 5.1
<#
.SYNOPSIS
    PreCompact hook: archives a deterministic snapshot + local digest (best-effort).
.DESCRIPTION
    Execution order:
      1. Deterministic snapshot ALWAYS: STATE.md, latest decisions, latest failures,
         trigger and custom_instructions -> .agent/archive/<TS>-precompact.md
      2. Digest from the LOCAL model (qwen3:4b) on the transcript tail, redacted and limited.
         If Ollama is offline/slow the compaction CONTINUES and the archive stays valid
         (explicit fallback, declared in the file and to the user via systemMessage).
    Does not modify STATE.md (PostCompact does). Never blocks the compaction: exit 0.
.NOTES
    Registered on: PreCompact (manual|auto). Hook timeout: 60s (internal digest: 45s).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TRANSCRIPT_TAIL_BYTES = 1200000

try {
    . (Join-Path $PSScriptRoot 'Hook-Common.ps1')
    . (Join-Path $PSScriptRoot 'Invoke-LocalDigest.ps1')

    # DETAILED input (class F21): without -Detailed a malformed stdin produced
    # $null and the hook went on with the DEFAULTS (trigger 'auto', state read halfway):
    # a snapshot was created FABRICATED from input that had never been read.
    $inState = Get-HookInput -Detailed
    $input0 = $inState.Object
    if (-not $inState.HadInput -or $inState.ParseError) {
        $pd = $env:CLAUDE_PROJECT_DIR
        if (-not $pd) { $pd = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
        $cause = 'input-missing'
        if ($inState.ParseError) { $cause = 'input-unreadable' }
        [void](Add-FailureRecord -ProjectDir $pd -Component 'Invoke-PreCompact' -Command 'hook' -ErrorText ('unusable stdin (' + $cause + '); snapshot NOT created') -Cause $cause)
        Write-HookJson -EventName 'PreCompact' -SystemMessage ('PreCompact: unusable input (' + $cause + ') - no snapshot created; details in .agent/FAILURES.md')
        exit 0
    }
    $projectDir = Get-ProjectDir -InputObject $input0
    # EXACTLY-ONCE (campaign #3, class F6): with the documented opt-out setup
    # (user-level install + the project's own copy/registration) this copy stays
    # SILENT when the project holds its own registration (settings.json OR
    # settings.local.json) and its own copy of this hook -- otherwise the two
    # registrations ran it TWICE per event (double snapshot + up to 2x45s digest).
    if (Test-ProjectLocalInjector -SelfPath $PSCommandPath -ProjectDir $projectDir -HookFileName 'Invoke-PreCompact.ps1') { exit 0 }
    $trigger = Get-JsonProp -Object $input0 -Name 'trigger' -Default 'auto'
    $custom = [string](Get-JsonProp -Object $input0 -Name 'custom_instructions' -Default '')
    $transcript = [string](Get-JsonProp -Object $input0 -Name 'transcript_path' -Default '')
    $sessionId = [string](Get-JsonProp -Object $input0 -Name 'session_id' -Default '')

    # M11 (class CA): transcript_path reached the reader WITHOUT filters: a SENSITIVE
    # path (e.g. .env) was read, redacted and archived; a non-.jsonl file likewise.
    # EXPLICIT tri-state (rejected / present / not found): the rejection is declared
    # in the file and recorded, never silent. Only an EXISTING file with a non-.jsonl
    # extension is rejected: missing directories and paths follow the fallback branch
    # unchanged (contract J: 'empty or unreadable ... tail' / 'not available').
    $transcriptBlocked = $false
    $transcriptRejectReason = ''
    if ($transcript) {
        $tIsSensitive = $false
        try { if (Test-SensitivePath -Path $transcript) { $tIsSensitive = $true } } catch { }
        if ($tIsSensitive) {
            $transcriptBlocked = $true
            $transcriptRejectReason = 'sensitive path'
        } elseif ((Test-Path -LiteralPath $transcript -PathType Leaf) -and
                  ([System.IO.Path]::GetExtension($transcript).ToLowerInvariant() -ne '.jsonl')) {
            $transcriptBlocked = $true
            $transcriptRejectReason = 'extension is not .jsonl'
        }
        if ($transcriptBlocked) {
            $tName = Get-SensitiveLabel -Path $transcript
            if ($transcriptRejectReason -eq 'sensitive path') { $tName = '[SENSITIVE_FILE] ' + $tName }
            [void](Add-FailureRecord -ProjectDir $projectDir -Component 'Invoke-PreCompact' -Command 'transcript' -ErrorText ('transcript_path rejected (' + $transcriptRejectReason + '): ' + $tName + '; local digest skipped') -Cause 'transcript-rejected')
        }
    }

    $agentDir = Get-AgentDir -ProjectDir $projectDir
    $archiveDir = Get-ArchiveDir -ProjectDir $projectDir
    if (-not (Test-Path -LiteralPath $archiveDir)) { [void](New-Item -ItemType Directory -Force -Path $archiveDir) }

    # --- 1. Deterministic snapshot (under the project mutex) -----------------
    # Unique-name choice + state reads + first write in the SAME
    # critical section (class finding #27, full sweep): the check-then-act of
    # Get-UniqueFilePath and the read-modify-write of concurrent state files
    # silently lost archives/rows. The digest downstream stays OUTSIDE the lock
    # (slow network operation): the rewrite reuses an already claimed path.
    $agentLock = Enter-AgentLock -ProjectDir $projectDir
    try {
        $stamp = Get-HookStamp
        $fileName = $stamp + '-precompact.md'
        # Unique name: two snapshots in the same second must not overwrite each other.
        $archivePath = Get-UniqueFilePath -Path (Join-Path $archiveDir $fileName)
        $fileName = Split-Path -Leaf $archivePath

        # M10 (class CB): "missing" and "present but UNREADABLE" were merged —
        # Read-TextFileSafe returns '' in both cases and the snapshot declared
        # "(missing or empty)" even when the state EXISTS but is not readable
        # (false diagnosis) without recording anything. Now the tri-state is explicit and
        # the unreadable case produces a marker + a row in FAILURES.md.
        # M1 (class SA): FULL read — the pre-compact snapshot must contain the
        # WHOLE state (with the 20,000 cap "Next action" beyond the threshold disappeared
        # from the archive too).
        $stState = Read-TextFileState -Path (Join-Path $agentDir 'STATE.md')
        $state = [string]$stState.Text
        if (-not $stState.Ok) {
            $state = '(STATE.md UNREADABLE: ' + [string]$stState.Error + ')'
            [void](Add-FailureRecord -ProjectDir $projectDir -Component 'Invoke-PreCompact' -Command 'hook' -ErrorText ('STATE.md present but unreadable (' + [string]$stState.Error + '): snapshot without real state') -Cause 'state-unreadable')
        } elseif (-not $state) { $state = '(STATE.md missing or empty)' }

        # M1 (class SA): -KeepTail — the latest decisions live in the tail.
        $stDec = Read-TextFileState -Path (Join-Path $agentDir 'DECISIONS.md') -MaxChars 60000 -KeepTail
        $decTail = ''
        if (-not $stDec.Ok) {
            $decTail = '(DECISIONS.md UNREADABLE: ' + [string]$stDec.Error + ')'
            [void](Add-FailureRecord -ProjectDir $projectDir -Component 'Invoke-PreCompact' -Command 'hook' -ErrorText ('DECISIONS.md present but unreadable (' + [string]$stDec.Error + '): code omits the latest decisions') -Cause 'decisions-unreadable')
        } elseif ($stDec.Text) {
            $blocks = @([regex]::Split([string]$stDec.Text, '(?m)^## ') | Where-Object { $_.Trim().Length -gt 0 })
            $lastTwo = @($blocks | Select-Object -Last 2)
            if ($lastTwo.Count -gt 0) { $decTail = '## ' + ($lastTwo -join "`n## ") }
        }

        # M1 (class SA): -KeepTail — the latest rows live in the tail.
        $stFail = Read-TextFileState -Path (Join-Path $agentDir 'FAILURES.md') -MaxChars 60000 -KeepTail
        $failTail = ''
        if (-not $stFail.Ok) {
            $failTail = '(FAILURES.md UNREADABLE: ' + [string]$stFail.Error + ')'
            [void](Add-FailureRecord -ProjectDir $projectDir -Component 'Invoke-PreCompact' -Command 'hook' -ErrorText ('FAILURES.md present but unreadable (' + [string]$stFail.Error + '): code omits the latest failures') -Cause 'failures-unreadable')
        } elseif ($stFail.Text) {
            $rows = @([string]$stFail.Text -split "`n" | Where-Object { $_ -match '^\| \d{4}-' } | Select-Object -Last 5)
            if ($rows.Count -gt 0) { $failTail = $rows -join "`n" }
        }

        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('# Pre-compaction snapshot')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('- timestamp: ' + (Get-HumanStamp))
        # M12 (class CA): RAW trigger/session_id inside markdown: a newline in the
        # value opened a new line and a leading '##' became a REAL SECTION.
        [void]$sb.AppendLine('- trigger: ' + (ConvertTo-SafeInline -Text $trigger))
        [void]$sb.AppendLine('- session: ' + (ConvertTo-SafeInline -Text $sessionId -Max 40))
        $transcriptNote = 'not provided'
        if ($transcript) {
            if ($transcriptBlocked) { $transcriptNote = 'rejected (' + $transcriptRejectReason + ')' }
            elseif (Test-Path -LiteralPath $transcript -PathType Leaf) { $transcriptNote = 'available (redacted tail, not archived in full)' }
            else { $transcriptNote = 'not found' }
        }
        [void]$sb.AppendLine('- transcript: ' + $transcriptNote)
        [void]$sb.AppendLine('')
        if ($custom) {
            [void]$sb.AppendLine('## User instructions for compaction')
            [void]$sb.AppendLine((Limit-Text -Text (Remove-SensitiveContent -Text $custom) -Max 1200))
            [void]$sb.AppendLine('')
        }
        [void]$sb.AppendLine('## State at compaction time (deterministic)')
        [void]$sb.AppendLine('```')
        # M1 (2nd wave, ASSEMBLY): the 4,000 cap at the HEAD cut the tail here too:
        # "Next action" beyond 4,000 disappeared from the archive (measured: 21,192).
        # The deterministic snapshot must contain the WHOLE state (no cap).
        [void]$sb.AppendLine($state)
        [void]$sb.AppendLine('```')
        if ($decTail) {
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('## Latest decisions')
            # M1 (2nd wave): join in file order (second-to-last, last): -KeepTail
            # keeps the NEWEST decision instead of truncating it with the 1,500 cap.
            [void]$sb.AppendLine((Limit-Text -Text $decTail -Max 1500 -KeepTail))
        }
        if ($failTail) {
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('## Latest recorded failures')
            [void]$sb.AppendLine($failTail)
        }

        # Snapshot written IMMEDIATELY, before calling the local model: if the process
        # is killed during the digest (60s hook timeout), the archive exists
        # anyway. Writing only at the end meant a TOTAL and silent loss
        # when the slow call went wrong (class: data kept in memory across
        # a slow, killable operation).
        Write-TextFileAtomic -Path $archivePath -Text $sb.ToString()
    } finally {
        Exit-AgentLock -Lock $agentLock
    }

    # --- 2. Local digest (best-effort) --------------------------------------
    $digestOk = $false
    $digestNote = ''
    if ($transcriptBlocked) {
        # The rejection is already recorded upstream (cause transcript-rejected): here the
        # explicit reason stays in the fallback, so the archive does NOT pretend "not available".
        $digestNote = 'transcript rejected (' + $transcriptRejectReason + ')'
    } elseif ($transcript -and (Test-Path -LiteralPath $transcript)) {
        $tailRaw = Read-FileTailText -Path $transcript -MaxBytes $TRANSCRIPT_TAIL_BYTES
        # ALWAYS initialized: it was used outside the branch that assigned it and, with
        # StrictMode, an unreadable transcript made the hook die silently.
        # DIRECT form (class F22: the comma-wrapping `, ([string[]]@())` created an
        # array with 1 EMPTY element -> Count 1 -> empty "redaction" comment row).
        $findings = [string[]]@()
        if ($tailRaw) {
            $tailClean = Remove-SensitiveContent -Text $tailRaw
            # DIRECT form (no @()): the producer always returns an unrolled array.
            $findings = Get-RedactionFindings -Text $tailRaw
            $res = Invoke-OllamaDigest -Text $tailClean -ProjectDir $projectDir
            if ($res.Ok) {
                $digestOk = $true
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine('## Local digest (model ' + $res.Model + ', ' + $res.ElapsedSec + 's)')
                [void]$sb.AppendLine($res.Text)
            } else {
                $digestNote = $res.Error
            }
        } else {
            $digestNote = 'empty or unreadable transcript tail'
        }
        if ($findings.Count -gt 0) {
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('<!-- redaction applied to the material passed to the local model: ' + ($findings -join ', ') + ' -->')
        }
    } else {
        $digestNote = 'transcript not available'
    }

    if (-not $digestOk) {
        if (-not $digestNote) { $digestNote = 'reason not recorded' }
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('## Local digest NOT available (fallback)')
        [void]$sb.AppendLine('reason: ' + $digestNote)
        [void]$sb.AppendLine('Consequence: this archive contains only the deterministic snapshot.')
        [void]$sb.AppendLine('No data was sent outside the machine.')
        # The fallback must not be SILENT: it is recorded in FAILURES.md.
        [void](Add-FailureRecord -ProjectDir $projectDir -Component 'PreCompact-digest' -Command 'ollama' -ErrorText ('local digest not available: ' + $digestNote) -Cause 'digest-local-fallback')
    }

    # Rewrite with the digest (the snapshot was already on disk: see above).
    Write-TextFileAtomic -Path $archivePath -Text $sb.ToString()
    [void](Add-ArchiveIndexEntry -ProjectDir $projectDir -FileName $fileName -Note ('precompact/' + (ConvertTo-SafeInline -Text $trigger -Max 60) + $(if ($digestOk) { ' + local digest' } else { ' without digest' })))

    if ($digestOk) {
        Write-HookJson -EventName 'PreCompact' -SystemMessage ('Context archived: .agent/archive/' + $fileName)
    } else {
        Write-HookJson -EventName 'PreCompact' -SystemMessage ('Context archived without local digest (' + $digestNote + '): .agent/archive/' + $fileName)
    }
    exit 0
} catch {
    # Declared fail-open, but NEVER silent (class F9): the old catch re-dot-sourced
    # Hook-Common.ps1 to record the error — if the library is exactly what is broken,
    # the dot-source fails again and the empty inner catch swallowed everything: no
    # row, no warning. Here the recorder is INLINE and does not depend on Hook-Common.
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
            $row = '| ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + ' | Invoke-PreCompact | hook | ' + $msg + ' | hook-error (fail-open, recorder inline) | rerun |' + "`n"
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
        $json = '{"systemMessage":"WARNING: PreCompact hook failed - compaction continued without a complete snapshot (fail-open recorded in .agent/FAILURES.md)."}'
        [Console]::Out.Write($json)
    } catch { }
    exit 0
}
