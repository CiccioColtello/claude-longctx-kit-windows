#requires -Version 5.1
<#
.SYNOPSIS
    PostToolUseFailure hook: records the failure in .agent/FAILURES.md (redacted).
.DESCRIPTION
    - Writes ONE redacted row: timestamp, tool, truncated command/path, truncated
      first line of the error. No full output, no transcript.
    - Skips user interrupts (is_interrupt).
    - Dedup against the last row; automatic rotation past 300 rows (see Hook-Common).
    - Silent: does not consume context. Any error -> exit 0.
.NOTES
    Registered on: PostToolUseFailure (all tools).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    . (Join-Path $PSScriptRoot 'Hook-Common.ps1')

    # M15/L8 (class CB/CA): stdin PRESENT but unreadable was treated as
    # missing -> the defaults ('unknown'/'tool-failure') produced a FABRICATED
    # row: a tool failure we do not even know happened.
    # With input missing: no event -> silent exit (the hook contract).
    # With input unreadable: ONE dedicated row 'input-unreadable', never fake.
    $inState = Get-HookInput -Detailed
    $input0 = $inState.Object
    if (-not $inState.HadInput) { exit 0 }
    if ($inState.ParseError) {
        $pd = $env:CLAUDE_PROJECT_DIR
        if (-not $pd) { $pd = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
        [void](Add-FailureRecord -ProjectDir $pd -Component 'Invoke-PostToolUseFailure' -Command 'hook' -ErrorText 'stdin present but unreadable (invalid JSON): tool failure NOT recordable, no fabricated row' -Cause 'input-unreadable')
        exit 0
    }
    $projectDir = Get-ProjectDir -InputObject $input0
    # EXACTLY-ONCE (campaign #3, class F6): with the documented opt-out setup
    # (user-level install + the project's own copy/registration) this copy stays
    # SILENT when the project holds its own registration (settings.json OR
    # settings.local.json) and its own copy of this hook -- otherwise the two
    # registrations recorded the SAME failure row TWICE.
    if (Test-ProjectLocalInjector -SelfPath $PSCommandPath -ProjectDir $projectDir -HookFileName 'Invoke-PostToolUseFailure.ps1') { exit 0 }
    $toolName = [string](Get-JsonProp -Object $input0 -Name 'tool_name' -Default 'unknown')
    $toolInput = Get-JsonProp -Object $input0 -Name 'tool_input'
    $isInterrupt = Get-JsonProp -Object $input0 -Name 'is_interrupt' -Default $false
    $errObj = Get-JsonProp -Object $input0 -Name 'error'

    if ($isInterrupt -eq $true) { exit 0 }

    $detail = ''
    $cmd = Get-JsonProp -Object $toolInput -Name 'command'
    # M14 (class CA): the RAW command ended up in FAILURES.md/'denied-actions.log'
    # ('cat .env' in clear). Masking with the tokenizer SHARED with the gate
    # (Get-CommandSensitiveTokenHit): '[SENSITIVE_FILE] <name>'.
    if ($cmd) { $detail = Remove-SensitiveTokensFromCommand -Command ([string]$cmd) }
    if (-not $detail) {
        $fp = Get-JsonProp -Object $toolInput -Name 'file_path'
        if (-not $fp) { $fp = Get-JsonProp -Object $toolInput -Name 'notebook_path' }
        if ($fp) {
            if (Test-SensitivePath -Path ([string]$fp)) {
                $detail = '[SENSITIVE_FILE] ' + (Get-SensitiveLabel -Path ([string]$fp))
            } else {
                $detail = [string]$fp
            }
        }
    }

    $errText = ''
    if ($errObj) {
        $errText = [string]$errObj
    } else {
        $errText = [string](Get-JsonProp -Object $input0 -Name 'error' -Default '')
    }
    if ($errText) { $errText = ($errText -split "`n")[0] }

    [void](Add-FailureRecord -ProjectDir $projectDir -Component $toolName -Command $detail -ErrorText $errText -Cause 'tool-failure')
    exit 0
} catch {
    # Fail-open NEVER silent (class F9): this catch used to be bare - a library
    # error made the failure row LOST without a trace. INLINE recorder,
    # independent of Hook-Common (in case the library is the broken one).
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
            $row = '| ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + ' | Invoke-PostToolUseFailure | hook | ' + $msg + ' | hook-error (fail-open, recorder inline) | rerun |' + "`n"
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
        $json = '{"systemMessage":"WARNING: PostToolUseFailure hook failed - the tool failure was NOT recorded (fail-open recorded in .agent/FAILURES.md)."}'
        [Console]::Out.Write($json)
    } catch { }
    exit 0
}
