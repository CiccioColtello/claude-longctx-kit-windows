#requires -Version 5.1
<#
.SYNOPSIS
    CLI entry point for the local digest (Ollama). Uses the hooks library.
.DESCRIPTION
    This script IS an entry point: invoke it, do not dot-source it. The
    .claude/hooks/Invoke-LocalDigest.ps1 library stays pure (no param()) so it is
    not re-bound when it is dot-sourced by other hooks.

.EXAMPLE
    powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "D:\my project\core\scripts\Invoke-Digest.ps1" -Prompt "text to summarize"
.EXAMPLE
    powershell.exe -NoProfile -File "D:\my project\core\scripts\Invoke-Digest.ps1" -TextFile "D:\my project\.agent\STATE.md"
#>

[CmdletBinding()]
param(
    [string]$Prompt = '',
    [string]$TextFile = '',
    [string]$ProjectDir = '',
    [int]$TimeoutSec = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    if ([string]::IsNullOrWhiteSpace($ProjectDir)) {
        $ProjectDir = Split-Path -Parent $PSScriptRoot
    }
    # Hook-Common (includes Filter-AgentText): needed for the sensitive-file
    # check and for redaction BEFORE sending to the local model.
    # Forward slashes in the Join-Path child: on pwsh/macOS a backslash is NOT a
    # path separator (it would become part of the file name and the load fails).
    . (Join-Path $ProjectDir '.claude/hooks/Hook-Common.ps1')
    . (Join-Path $ProjectDir '.claude/hooks/Invoke-LocalDigest.ps1')

    $text = $Prompt
    if (-not $text -and $TextFile) {
        if (-not (Test-Path -LiteralPath $TextFile)) {
            Write-HookErrorRaw -Text ('file not found: ' + $TextFile + "`n")
            exit 1
        }
        if (Test-SensitivePath -Path $TextFile) {
            Write-HookErrorRaw -Text ('[SENSITIVE_FILE] ' + [System.IO.Path]::GetFileName($TextFile) + ' - rejected: sensitive files are not read or sent.' + "`n")
            exit 1
        }
        $text = [System.IO.File]::ReadAllText($TextFile, [System.Text.Encoding]::UTF8)
    }
    if ([string]::IsNullOrWhiteSpace($text)) {
        Write-HookErrorRaw -Text ('usage: Invoke-Digest.ps1 -Prompt "<text>" | -TextFile "<file>" [-ProjectDir <path>] [-TimeoutSec N]' + "`n")
        exit 1
    }

    # Redaction ALWAYS before sending (defense in depth: even -Prompt can
    # contain a secret pasted by the operator).
    $found = Get-RedactionFindings -Text $text
    if ($found.Count -gt 0) { Write-HookErrorRaw -Text ('redaction applied: ' + ($found -join ', ') + "`n") }
    $text = Remove-SensitiveContent -Text $text

    $res = Invoke-OllamaDigest -Text $text -ProjectDir $ProjectDir -TimeoutSec $TimeoutSec
    if ($res.Ok) {
        # DETERMINISTIC bytes with redirected stdout (class F15): the digest contains
        # accents; [Console]::Out would use the process OEM code page.
        Write-HookOutputRaw -Text $res.Text
        exit 0
    } else {
        Write-HookErrorRaw -Text ('digest not available: ' + $res.Error + "`n")
        exit 2
    }
} catch {
    # If Hook-Common is the broken one, Write-HookErrorRaw does not exist: direct fallback.
    $m = 'Invoke-Digest: non-fatal error: ' + $_.Exception.Message
    if (Get-Command -Name 'Write-HookErrorRaw' -ErrorAction SilentlyContinue) { Write-HookErrorRaw -Text ($m + "`n") }
    else { [Console]::Error.WriteLine($m) }
    exit 2
}
