#requires -Version 5.1
<#
.SYNOPSIS
    PostCompact hook: archives the compaction summary and updates .agent/STATE.md.
.DESCRIPTION
    - Writes .agent/archive/<TS>-compact-summary.md (redacted and limited summary).
    - Updates STATE.md: "Last compaction" section + "Updated" field.
    - Updates .agent/archive/INDEX.md.
    - Never blocks: any error -> exit 0.
.NOTES
    Registered on: PostCompact (manual|auto).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$MAX_SUMMARY = 60000

function Set-StateSection {
    <# Replaces (or adds) a "## Title" section in the markdown text. #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Body
    )
    $section = '## ' + $Title + "`n" + $Body.TrimEnd() + "`n"
    $pattern = '(?ms)^## ' + [regex]::Escape($Title) + '\r?\n.*?(?=^## |\z)'
    $m = [regex]::Match($Text, $pattern)
    if ($m.Success) {
        $before = $Text.Substring(0, $m.Index)
        $after = $Text.Substring($m.Index + $m.Length)
        return $before + $section + $after
    }
    return $Text.TrimEnd() + "`n`n" + $section
}

try {
    . (Join-Path $PSScriptRoot 'Hook-Common.ps1')

    # DETAILED input (class F21): with the plain Get-HookInput a malformed stdin
    # gave $null and the hook went on with the defaults, ARCHIVING an empty summary and
    # REWRITING STATE.md as if nothing had happened.
    $inState = Get-HookInput -Detailed
    $input0 = $inState.Object
    if (-not $inState.HadInput -or $inState.ParseError) {
        $pd = $env:CLAUDE_PROJECT_DIR
        if (-not $pd) { $pd = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
        $cause = 'input-missing'
        if ($inState.ParseError) { $cause = 'input-unreadable' }
        [void](Add-FailureRecord -ProjectDir $pd -Component 'Invoke-PostCompact' -Command 'hook' -ErrorText ('unusable stdin (' + $cause + '); summary NOT archived') -Cause $cause)
        Write-HookJson -EventName 'PostCompact' -SystemMessage ('PostCompact: unusable input (' + $cause + ') - no summary archived; details in .agent/FAILURES.md')
        exit 0
    }
    $projectDir = Get-ProjectDir -InputObject $input0
    # EXACTLY-ONCE (campaign #3, class F6): with the documented opt-out setup
    # (user-level install + the project's own copy/registration) this copy stays
    # SILENT when the project holds its own registration (settings.json OR
    # settings.local.json) and its own copy of this hook -- otherwise the two
    # registrations ran it TWICE per event (double archive + double INDEX row).
    if (Test-ProjectLocalInjector -SelfPath $PSCommandPath -ProjectDir $projectDir -HookFileName 'Invoke-PostCompact.ps1') { exit 0 }
    $trigger = Get-JsonProp -Object $input0 -Name 'trigger' -Default 'auto'
    $summary = [string](Get-JsonProp -Object $input0 -Name 'compact_summary' -Default '')

    $agentDir = Get-AgentDir -ProjectDir $projectDir
    $archiveDir = Get-ArchiveDir -ProjectDir $projectDir
    if (-not (Test-Path -LiteralPath $archiveDir)) { [void](New-Item -ItemType Directory -Force -Path $archiveDir) }

    # SINGLE critical section (class finding #27, full sweep): unique archive
    # name + write + index + read-modify-write of STATE.md under the
    # project mutex. Add-ArchiveIndexEntry/Add-FailureRecord nest the same
    # mutex (reentrant on the same thread): no deadlock. All operations are
    # local/fast: no network call inside the lock.
    $agentLock = Enter-AgentLock -ProjectDir $projectDir
    try {
        $stamp = Get-HookStamp
        $fileName = $stamp + '-compact-summary.md'
        # Unique name: two archives in the same second must not overwrite each other.
        $archivePath = Get-UniqueFilePath -Path (Join-Path $archiveDir $fileName)
        $fileName = Split-Path -Leaf $archivePath

        $clean = Remove-SensitiveContent -Text $summary
        $clean = Limit-Text -Text $clean -Max $MAX_SUMMARY
        # DIRECT form (no @()): the producer always returns an unrolled array.
        $findings = Get-RedactionFindings -Text $summary

        # M12 (class CA): RAW trigger inside markdown/pipe. A newline opened a
        # new line and a leading '##' became a REAL SECTION (archive, INDEX,
        # STATE.md). Neutralized inline: newline->space, '|'->'/', headings -> '[##] '.
        $header = "# Compaction summary`n`n- timestamp: " + (Get-HumanStamp) + "`n- trigger: " + (ConvertTo-SafeInline -Text $trigger) + "`n"
        if ($findings.Count -gt 0) { $header += '- redaction applied: ' + ($findings -join ', ') + "`n" }
        $header += "`n---`n`n"
        Write-TextFileAtomic -Path $archivePath -Text ($header + $clean)
        [void](Add-ArchiveIndexEntry -ProjectDir $projectDir -FileName $fileName -Note ('postcompact/' + (ConvertTo-SafeInline -Text $trigger -Max 60)))

        # --- STATE.md update ----------------------------------------------------
        $statePath = Join-Path $agentDir 'STATE.md'
        $state = ''
        # Read-TextFileState (class F17): Read-TextFileSafe does NOT distinguish "0 byte"
        # from "unreadable" — an empty state file (0 byte) ended up in the
        # "present but unreadable" branch: false diagnosis in FAILURES.md and skipped update.
        # Here: missing or empty -> the caller's template is correct; a REAL read
        # error -> it is recorded and skipped without overwriting.
        # No read cap: the text is REWRITTEN, a silent truncation
        # would become a permanent loss of state.
        $st = Read-TextFileState -Path $statePath
        if ($st.Ok) { $state = $st.Text }
        else {
            # PRESENT but unreadable file: do not rebuild the template (it would
            # overwrite the real state with fake content). It is recorded and the update skipped.
            [void](Add-FailureRecord -ProjectDir $projectDir -Component 'Invoke-PostCompact' -Command 'STATE.md' -ErrorText ('STATE.md present but unreadable (' + $st.Error + '): update skipped, no overwrite') -Cause 'state-unreadable')
            Write-HookJson -EventName 'PostCompact' -SystemMessage ('Compaction archived (.agent/archive/' + $fileName + '), but STATE.md is unreadable: update skipped.')
            exit 0
        }
        if (-not $state) {
            $state = "# Current Agent State`n`n## Goal`nnot recorded`n`n## Phase`nunknown`n`n## Modified files`nunknown`n`n## Tests`nnot run`n`n## Known failures`nnone`n`n## Decisions pending`nnone`n`n## Next action`nread .agent/archive/" + $fileName + "`n"
        }

        # "Last compaction" section text: the <analysis>...</analysis> block is dropped
        # and the summary's markdown headings are neutralized, since they would
        # otherwise break the section (a "## X" from the summary would become a STATE section).
        $headText = $clean
        $idx = $headText.LastIndexOf('</analysis>')
        if ($idx -ge 0) { $headText = $headText.Substring($idx + 11) }
        $headText = [regex]::Replace($headText, '(?m)^(#{1,6})[ \t]+', '[$1] ')
        $head = Limit-Text -Text $headText.Trim() -Max 400
        $body = (Get-HumanStamp) + ' | trigger: ' + (ConvertTo-SafeInline -Text $trigger) + "`n`n" + $head
        $state = Set-StateSection -Text $state -Title 'Last compaction' -Body $body
        $state = Set-StateSection -Text $state -Title 'Updated' -Body (Get-HumanStamp)
        Write-TextFileAtomic -Path $statePath -Text $state
    } finally {
        Exit-AgentLock -Lock $agentLock
    }

    Write-HookJson -EventName 'PostCompact' -SystemMessage ('Compaction recorded: .agent/archive/' + $fileName + ' (STATE.md updated)')
    exit 0
} catch {
    # Fail-open NEVER silent (class F9): INLINE recorder, independent of Hook-Common.
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
            $row = '| ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + ' | Invoke-PostCompact | hook | ' + $msg + ' | hook-error (fail-open, recorder inline) | rerun |' + "`n"
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
        $json = '{"systemMessage":"WARNING: PostCompact hook failed - STATE.md may not have been updated (fail-open recorded in .agent/FAILURES.md)."}'
        [Console]::Out.Write($json)
    } catch { }
    exit 0
}
