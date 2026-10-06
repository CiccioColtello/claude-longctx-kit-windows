#requires -Version 5.1
<#
.SYNOPSIS
    CLI entry point: redacts and caps a file (log, transcript, agent output) to stdout.
.DESCRIPTION
    Uses the .claude/hooks/Filter-AgentText.ps1 library (which stays pure, no param()).
    The ORIGINAL is never modified: the filtered output goes to stdout. To save it,
    redirect it yourself. No content is sent anywhere else.

.EXAMPLE
    powershell.exe -NoProfile -File "D:\my project\core\scripts\Filter-File.ps1" -Path "C:\log\build.log" -Max 4000 > filtered.txt
.EXAMPLE
    powershell.exe -NoProfile -File "D:\my project\core\scripts\Filter-File.ps1" -Path "C:\log\build.log" -Tail
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [int]$Max = 4000,
    [switch]$Tail,
    [string]$ProjectDir = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    if ([string]::IsNullOrWhiteSpace($ProjectDir)) {
        $ProjectDir = Split-Path -Parent $PSScriptRoot
    }
    # Hook-Common also includes Filter-AgentText and provides Test-SensitivePath.
    # Forward slashes in the Join-Path child: on pwsh/macOS a backslash is NOT a
    # path separator (it would become part of the file name and the load fails).
    . (Join-Path $ProjectDir '.claude/hooks/Hook-Common.ps1')

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-HookErrorRaw -Text ('file not found: ' + $Path + "`n")
        exit 1
    }
    # A sensitive file is neither printed NOR redacted: it must not be read at all.
    if (Test-SensitivePath -Path $Path) {
        Write-HookErrorRaw -Text ('[SENSITIVE_FILE] ' + [System.IO.Path]::GetFileName($Path) + ' - rejected: sensitive files are not read or printed.' + "`n")
        exit 1
    }

    $raw = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    $clean = Remove-SensitiveContent -Text $raw
    # DIRECT form (no @()): the producer never unrolls its array,
    # and @() would nest it into a single element (verified under PS 5.1).
    $findings = Get-RedactionFindings -Text $raw
    if ($Tail) {
        $clean = Limit-Text -Text $clean -Max $Max -KeepTail
    } else {
        $clean = Limit-Text -Text $clean -Max $Max
    }
    # DETERMINISTIC bytes (class F15): with redirected stdout [Console]::Out would use the
    # process OEM code page -> mojibake accents in the filtered file.
    Write-HookOutputRaw -Text $clean

    if ($findings.Count -gt 0) {
        Write-HookErrorRaw -Text ('[redaction applied: ' + ($findings -join ', ') + ']' + "`n")
    }
    exit 0
} catch {
    # If Hook-Common is the broken one, Write-HookErrorRaw does not exist: direct fallback.
    $m = 'Filter-File: non-fatal error: ' + $_.Exception.Message
    if (Get-Command -Name 'Write-HookErrorRaw' -ErrorAction SilentlyContinue) { Write-HookErrorRaw -Text ($m + "`n") }
    else { [Console]::Error.WriteLine($m) }
    exit 2
}
