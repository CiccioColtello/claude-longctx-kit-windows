#requires -Version 5.1
<#
.SYNOPSIS
    Shared library for project hooks (dot-sourced).
.DESCRIPTION
    Exposes ONLY functions: it does not read stdin, does not write stdout.
    Compatible with Windows PowerShell 5.1 and PowerShell 7.x.
    Includes Filter-AgentText.ps1 (redaction + capping) if present next to this file.
.NOTES
    Usage from every hook:
        . (Join-Path $PSScriptRoot 'Hook-Common.ps1')
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Library directory resolved defensively: $PSScriptRoot may not be
# reliable when the file is dot-sourced from another script. Order:
#   1) $MyInvocation.MyCommand.Path  (path of the dot-sourced file)
#   2) $PSScriptRoot                  (fallback)
#   3) current directory              (last fallback)
$script:HookCommonDir = ''
try {
    if ($MyInvocation.MyCommand.Path) { $script:HookCommonDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
} catch { }
if (-not $script:HookCommonDir) { try { $script:HookCommonDir = $PSScriptRoot } catch { } }
if (-not $script:HookCommonDir) { $script:HookCommonDir = (Get-Location).Path }

$script:FilterScriptPath = Join-Path $script:HookCommonDir 'Filter-AgentText.ps1'
$script:FilterDegraded = $true
if (Test-Path -LiteralPath $script:FilterScriptPath) {
    try {
        . $script:FilterScriptPath
        $script:FilterDegraded = $false
    } catch {
        $script:FilterDegraded = $true
    }
}
# MINIMAL redaction FALLBACK (class F10): without Filter-AgentText the callers must
# NOT skip redaction (secrets in cleartext in FAILURES.md/denied-actions.log).
# Here the same functions are defined with a REDUCED set of high-value rules,
# and the degradation is recorded once per process (Register-FilterDegradation)
# on the first written record: never silent.
if ($script:FilterDegraded) {
    $script:FallbackRedactionRules = @(
        @{ Id = 'fb_private_key'; Pattern = '(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----'; Replace = '[REDACTED:PRIVATE_KEY]' },
        @{ Id = 'fb_keyvalue';    Pattern = '(?i)((?:api[_-]?key|apikey|secret|password|passwd|pwd|token|bearer|authorization|credential|private[_-]?key|mnemonic|passphrase|access[_-]?key)[A-Za-z0-9_.-]{0,20})\s*[:=]\s*("[^"\r\n]*"|\x27[^\x27\r\n]*\x27|Bearer\s+\S+|\S+)'; Replace = '$1=[REDACTED]' },
        @{ Id = 'fb_aws';         Pattern = '\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'; Replace = '[REDACTED:AWS_KEY]' },
        @{ Id = 'fb_sk';          Pattern = '\bsk-[A-Za-z0-9_-]{20,}\b'; Replace = '[REDACTED:API_KEY]' },
        @{ Id = 'fb_jwt';         Pattern = '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'; Replace = '[REDACTED:JWT]' },
        @{ Id = 'fb_github';      Pattern = '\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{16,}\b'; Replace = '[REDACTED:GITHUB]' },
        @{ Id = 'fb_hex';         Pattern = '\b[0-9a-fA-F]{64,}\b'; Replace = '[REDACTED:HEX]' }
    )

    function Remove-SensitiveContent {
        <# DEGRADED fallback: never the complete rule set, only the high-value ones. #>
        [CmdletBinding()]
        param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
        if ($Text -eq '') { return '' }
        $t = $Text
        foreach ($r in $script:FallbackRedactionRules) {
            try { $t = [regex]::Replace($t, $r.Pattern, $r.Replace) } catch { }
        }
        return $t
    }

    function Get-RedactionFindings {
        [CmdletBinding()]
        param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
        $found = New-Object System.Collections.Generic.List[string]
        foreach ($r in $script:FallbackRedactionRules) {
            try { if ([regex]::IsMatch($Text, $r.Pattern)) { [void]$found.Add($r.Id) } } catch { }
        }
        return , ([string[]]$found.ToArray())
    }

    function Limit-Text {
        <#
            F8 (campaign #3, discovered live while probing the F6 guard): the degraded
            branch defined the redaction rules but NOT the capping helper, so with
            Filter-AgentText.ps1 missing/unreadable the 3 event hooks that call
            Limit-Text (SessionStart, PreCompact, PostCompact) DIED with
            'Limit-Text not recognized' -> fail-open: no context injected, no
            snapshot, no archive -- the declared degradation was in fact a full stop.
            Minimal twin of the real function (same signature and markers,
            including -KeepTail and the surrogate-pair cut): a DEGRADED cap is
            acceptable, a dead hook is not. No drift risk on the rules: this
            function has no redaction logic.
        #>
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
            [Parameter(Mandatory)][int]$Max,
            [switch]$KeepTail
        )
        if ([string]::IsNullOrEmpty($Text)) { return '' }
        if ($Max -le 0 -or $Text.Length -le $Max) { return $Text }
        if ($KeepTail) {
            $k = $Text.Length - $Max
            if ([char]::IsLowSurrogate($Text[$k])) { $k++ }
            return '[truncated ' + $k + " leading characters]`n" + $Text.Substring($k)
        }
        $k = $Max
        if ([char]::IsHighSurrogate($Text[$k - 1]) -and [char]::IsLowSurrogate($Text[$k])) { $k-- }
        return $Text.Substring(0, $k) + "`n[truncated " + ($Text.Length - $k) + ' trailing characters]'
    }
}

$script:FilterDegradationNoticed = $false
function Register-FilterDegradation {
    <#
        Records ONCE per process that redaction is running in degraded mode
        (Filter-AgentText missing/unreadable). Best-effort write via
        direct AppendAllText: it must not depend on the functions that could
        be exactly the broken ones.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectDir)
    if (-not $script:FilterDegraded) { return }
    if ($script:FilterDegradationNoticed) { return }
    try {
        $agentDir = Join-Path $ProjectDir '.agent'
        if (-not (Test-Path -LiteralPath $agentDir)) { return }
        $row = '| ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + ' | Hook-Common | Filter-AgentText.ps1 | redaction library MISSING: MINIMAL (degraded) fallback redaction applied | filter-missing (explicit fallback) | restore Filter-AgentText.ps1 |' + "`n"
        # L1 (campaign #2, class LA): the row was neither serialized with the gate
        # mutex nor retried on transient contention: under a reader holding
        # FAILURES.md for a few ms the row vanished (same class as the 5 hook
        # catches, fixed via Hook-Inline). Here: mutex + retry-open ~4000 ms; last
        # resort: bare append (never worse than before).
        $rowWritten = $false
        $lock = $null
        try {
            $lock = Enter-AgentLock -ProjectDir $ProjectDir
            $rowPath = Join-Path $agentDir 'FAILURES.md'
            $rowBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($row)
            $rowSw = [System.Diagnostics.Stopwatch]::StartNew()
            while ($rowSw.ElapsedMilliseconds -lt 4000) {
                try {
                    $fs = New-Object System.IO.FileStream($rowPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
                    try {
                        $fs.Write($rowBytes, 0, $rowBytes.Length)
                        $fs.Flush()
                    } finally { $fs.Dispose() }
                    $rowWritten = $true
                    break
                } catch { Start-Sleep -Milliseconds 60 }
            }
        } catch { $rowWritten = $false } finally {
            Exit-AgentLock -Lock $lock
        }
        if (-not $rowWritten) {
            [System.IO.File]::AppendAllText((Join-Path $agentDir 'FAILURES.md'), $row, (New-Object System.Text.UTF8Encoding($false)))
        }
        # M13 (campaign #2, class CB): the flag is set ONLY after the SUCCESSFUL append.
        # Before, it was set FIRST: a failed append made the row vanish FOREVER
        # in the process (flag "already noticed" with no write at all) and the registration
        # was no longer retryable.
        $script:FilterDegradationNoticed = $true
    } catch { }
}

# ---------------------------------------------------------------------------
# Input / JSON
# ---------------------------------------------------------------------------

function Get-HookInput {
    <#
        Reads the JSON payload from the hook's stdin.
        Without -Detailed it returns the object (or $null), as before: used by the
        non-critical hooks, for which an unreadable input = no action (best-effort,
        declared in DECISIONS.md).
        With -Detailed it returns @{ Object; HadInput; ParseError }: it lets the gate
        PreToolUse distinguish "no input" (silent exit) from "input
        PRESENT but unreadable" (fail-open, but RECORDED in FAILURES.md).
        The bytes are decoded as explicit UTF-8, without depending on the
        console codepage; the leading BOM is removed if present.
    #>
    [CmdletBinding()]
    param([switch]$Detailed)
    $state = @{ Object = $null; HadInput = $false; ParseError = $false }
    try {
        if ([Console]::IsInputRedirected) {
            $raw = ''
            try {
                $ms = New-Object System.IO.MemoryStream
                [Console]::OpenStandardInput().CopyTo($ms)
                $raw = [System.Text.Encoding]::UTF8.GetString($ms.ToArray())
            } catch {
                # explicit fallback: read via Console (ambient encoding)
                try { $raw = [Console]::In.ReadToEnd() } catch { $raw = '' }
            }
            if ($raw.Length -gt 0 -and $raw[0] -eq [char]0xFEFF) { $raw = $raw.Substring(1) }
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                $state.HadInput = $true
                try { $state.Object = ($raw | ConvertFrom-Json) } catch { $state.ParseError = $true }
            }
        }
    } catch {
        $state.ParseError = $true
    }
    if ($Detailed) { return $state }
    return $state.Object
}

function Get-JsonProp {
    <# Safe access to a property (StrictMode-safe). #>
    [CmdletBinding()]
    param(
        $Object,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    if ($null -eq $prop.Value) { return $Default }
    return $prop.Value
}

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

function Get-ProjectDir {
    <#
        Project root for POLICY and STATE. Order: $env:CLAUDE_PROJECT_DIR ->
        input.cwd -> two levels above the hooks.
        The env comes BEFORE the cwd (class F5/F16): the payload cwd can be
        ANY folder (e.g. C:\Windows, C:\Users\user) and it moved the project
        root, wrongly exempting the protected areas from the project-exemption and
        making the audit rows land (or get lost) in the wrong place.
        Claude Code always provides CLAUDE_PROJECT_DIR to the hooks: the fallback on
        cwd remains only for manual/test invocations without the env.
    #>
    [CmdletBinding()]
    param($InputObject)
    $dir = $env:CLAUDE_PROJECT_DIR
    if (-not $dir) { $dir = Get-JsonProp -Object $InputObject -Name 'cwd' }
    if (-not $dir) {
        $dir = Split-Path -Parent (Split-Path -Parent $script:HookCommonDir)
    }
    return [string]$dir
}

function Get-AgentDir {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectDir)
    return (Join-Path $ProjectDir '.agent')
}

function Get-ArchiveDir {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectDir)
    return (Join-Path (Get-AgentDir -ProjectDir $ProjectDir) 'archive')
}

function Get-HookStamp {
    <# Compact local timestamp for file names (sortable). #>
    [CmdletBinding()]
    param()
    return (Get-Date).ToString('yyyyMMdd-HHmmss')
}

function Get-HumanStamp {
    [CmdletBinding()]
    param()
    return (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
}

# ---------------------------------------------------------------------------
# Path security normalization and cross-process lock
# ---------------------------------------------------------------------------

function Get-PathHash {
    <# Short, stable hash of a path (used for mutex names). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    try {
        $sha = [System.Security.Cryptography.SHA1]::Create()
        try {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text.ToLowerInvariant())
            $hex = ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '')
            return $hex.Substring(0, 16)
        } finally { $sha.Dispose() }
    } catch { return 'nohash' }
}

function Test-PathKeyWindows {
    <#
        OS gate for the path-key normalization (campaign #3, class F3).
        'auto' = the platform, from the .NET separator ('\' on Windows, '/' elsewhere);
        'windows'/'posix' force the semantics and exist as a TEST SEAM so the probe
        exercises BOTH branches on one host. Production callers never pass the
        flavor: they always get the platform behavior.
    #>
    [CmdletBinding()]
    param([ValidateSet('auto', 'windows', 'posix')][string]$Flavor = 'auto')
    if ($Flavor -eq 'windows') { return $true }
    if ($Flavor -eq 'posix') { return $false }
    return ([System.IO.Path]::DirectorySeparatorChar -eq '\')
}

function Get-PathKeySeparator {
    <# Native separator of the path-key flavor (see Test-PathKeyWindows). #>
    [CmdletBinding()]
    param([ValidateSet('auto', 'windows', 'posix')][string]$Flavor = 'auto')
    if (Test-PathKeyWindows -Flavor $Flavor) { return '\' }
    return '/'
}

function Get-NormalizedPathKey {
    <#
        Normalizes a path for SECURITY COMPARISONS (not for filesystem use).
        OS-AWARE (campaign #3, class F3): the WINDOWS rewrites below are applied
        only where they are true. On POSIX they REWROTE legitimate paths (before:
        "/Users/x/.ssh" became "\Users\x\.ssh" -- a RELATIVE name, so GetFullPath
        dropped the root and every comparison ran on a path that does not exist;
        the junction walk could no longer split it either -- mac-only bypass):
        - Trim; \\?\ and \\.\ prefixes removed
        - '/' -> '\' separators (without this "C:/x/.ssh/k" bypasses the comparisons)
        - ADS suffix (":stream") removed
        - GetFullPath
        - trailing space/dot of each segment removed (Windows ignores them:
          "C:\Windows \System32" is the same directory as "C:\Windows\System32")
        POSIX branch: NO separator rewrite, NO ADS strip ('\' and ':' are LEGAL
        file-name characters there), NO per-segment trim (trailing space/dot are
        significant): Trim, GetFullPath with the native '/', return.
        Returns '' if the path is not normalizable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Path,
        [ValidateSet('auto', 'windows', 'posix')][string]$Flavor = 'auto'
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $isWin = Test-PathKeyWindows -Flavor $Flavor
    $p = $Path.Trim()
    if ($isWin) {
        if ($p.Length -ge 4 -and ($p.StartsWith('\\?\') -or $p.StartsWith('//?/'))) { $p = $p.Substring(4) }
        if ($p.Length -ge 4 -and ($p.StartsWith('\\.\') -or $p.StartsWith('//./'))) { $p = $p.Substring(4) }
        $p = $p -replace '/', '\'
        # ADS (class F1): any ':' AFTER the drive letter opens a stream
        # ("file:stream", "file:stream:$DATA", "file::$DATA"). The previous regex
        # (':[^\\:]+$') did not recognize the forms with MORE than one ':' (e.g. "::$DATA").
        # The ':' of "C:" (the only legitimate one in a Windows path) is preserved.
        $colonAt = -1
        if ($p.Length -ge 2 -and $p[1] -eq ':' -and [char]::IsLetter($p[0])) {
            $colonAt = $p.IndexOf(':', 2)
        } else {
            $colonAt = $p.IndexOf(':')
        }
        if ($colonAt -ge 0) { $p = $p.Substring(0, $colonAt) }
    }
    try { $p = [System.IO.Path]::GetFullPath($p) } catch { }
    if (-not $isWin) { return $p }   # POSIX: native '/', significant trailing space/dot
    if ($p.StartsWith('\\')) { return $p }   # UNC: no per-segment normalization
    $segs = @($p -split '\\')
    for ($i = 1; $i -lt $segs.Count; $i++) {
        $segs[$i] = ([string]$segs[$i]).TrimEnd(' ', '.')
    }
    return ($segs -join '\')
}

# C1 (campaign #3): canonicalization limits and sentinel. Get-CanonicalPath
# returns '' ONLY on failure (fail-closed): chains over 64 hops, reparse
# cycles, paths over 1024 characters, unexpected errors.
$script:CanonicalMaxHops = 64
$script:CanonicalMaxPathChars = 1024

function Get-CanonicalPath {
    <#
        Normalized path + per-prefix reparse point (junction/symlink) resolution,
        with limited hops (anti-loop). It closes the "junction inside
        the project -> protected area" bypass: the comparison happens on the REAL path.
        FAIL-CLOSED (C1, campaign #3): '' is the ERROR sentinel, returned
        when the path is not reliably resolvable (chain over 64 hops,
        reparse cycle, over 1024 characters, unexpected error). Callers
        treat it as "not verifiable" (Test-SensitivePath denies). Before: hop limit
        of 8 with the return of the PARTIAL path (chain of 9 junctions -> allow) and
        catch -> $key (fail-open on any exception).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $key = Get-NormalizedPathKey -Path $Path
    if (-not $key) { return '' }
    if ($key.Length -gt $script:CanonicalMaxPathChars) { return '' }
    # F3: native separator for the walk (was the literal '\' -- inert on POSIX).
    $sep = Get-PathKeySeparator
    if ($sep -eq '\' -and $key.StartsWith('\\')) { return $key }
    try {
        $resolved = $key
        $hops = 0
        # Cycle: the same normalized path seen again -> the chain does not terminate.
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
        while ($true) {
            $norm = Get-NormalizedPathKey -Path $resolved
            if (-not $norm) { return '' }
            if ($norm.Length -gt $script:CanonicalMaxPathChars) { return '' }
            if (-not $seen.Add($norm)) { return '' }
            $changed = $false
            $segs = @($norm.TrimEnd($sep) -split ([regex]::Escape($sep)))
            $acc = ([string]$segs[0]).TrimEnd($sep)
            for ($i = 1; $i -lt $segs.Count; $i++) {
                $acc = $acc + $sep + $segs[$i]
                try {
                    $it = Get-Item -LiteralPath $acc -Force -ErrorAction Stop
                    $lt = [string]$it.LinkType
                    if ($lt -eq 'Junction' -or $lt -eq 'SymbolicLink') {
                        $tgt = ''
                        $t = @($it.Target)
                        if ($t.Count -gt 0 -and $t[0]) { $tgt = [string]$t[0] }
                        if ($tgt) {
                            if (-not [System.IO.Path]::IsPathRooted($tgt)) {
                                $tgt = Join-Path (Split-Path -Parent $acc) $tgt
                            }
                            $rest = ''
                            if ($i -lt ($segs.Count - 1)) { $rest = ($segs[($i + 1)..($segs.Count - 1)] -join $sep) }
                            if ($rest) { $tgt = $tgt + $sep + $rest }
                            $resolved = $tgt
                            $changed = $true
                            # ONE hop = one RESOLUTION (iteration with a change).
                            $hops++
                            if ($hops -gt $script:CanonicalMaxHops) { return '' }
                            break
                        }
                    }
                } catch { }
            }
            if (-not $changed) { return $norm }
        }
    } catch {
        return ''
    }
}

function Get-MarkdownSection {
    <# Extracts the body of the "## Title" section (up to the next "## " or end of file). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Title
    )
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $pattern = '(?ms)^## ' + [regex]::Escape($Title) + '[ \t]*\r?\n(.*?)(?=^## |\z)'
    $m = [regex]::Match($Text, $pattern)
    if (-not $m.Success) { return '' }
    return $m.Groups[1].Value.Trim()
}

function Enter-AgentLock {
    <#
        Acquires the project cross-process mutex and returns it (@{Mutex; Held})
        for a SCRIPT-SCOPE critical section: the variables stay visible and
        the section is 'exit-safe' (to be used with try/finally + Exit-AgentLock).
        Best-effort like Invoke-WithAgentLock: on timeout it returns Held=$false and
        proceeds anyway (a hook must never block for long).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectDir,
        [int]$TimeoutMs = 4000
    )
    try {
        $name = 'Local\claude-agent-state-' + (Get-PathHash -Text $ProjectDir)
        $mutex = New-Object System.Threading.Mutex($false, $name)
        $held = $false
        try {
            $held = $mutex.WaitOne($TimeoutMs)
        } catch [System.Threading.AbandonedMutexException] {
            $held = $true   # mutex abandoned by a dead process: the lock is ours anyway
        } catch {
            $held = $false
        }
        return @{ Mutex = $mutex; Held = $held }
    } catch {
        return $null
    }
}

function Exit-AgentLock {
    <# Releases (if acquired) and disposes the mutex returned by Enter-AgentLock. #>
    [CmdletBinding()]
    param([AllowNull()]$Lock)
    if (-not $Lock) { return }
    try {
        if ($Lock.Held) { try { [void]$Lock.Mutex.ReleaseMutex() } catch { } }
    } finally {
        try { $Lock.Mutex.Dispose() } catch { }
    }
}

function Invoke-WithAgentLock {
    <#
        Runs $ScriptBlock under a per-project cross-process mutex: the hooks
        run in separate PROCESSES (possibly concurrent) and the state files are
        read-modify-write. Without a lock two concurrent hooks overwrite each other
        (audit and failure rows lost). Short timeout: if the lock is not obtained it
        proceeds anyway (best-effort: a hook must never block for long).
        Thin wrapper of Enter-AgentLock/Exit-AgentLock (same semantics as before).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectDir,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [int]$TimeoutMs = 4000
    )
    $lock = Enter-AgentLock -ProjectDir $ProjectDir -TimeoutMs $TimeoutMs
    try {
        & $ScriptBlock
    } finally {
        Exit-AgentLock -Lock $lock
    }
}

# ---------------------------------------------------------------------------
# Text I/O (UTF-8 without BOM, atomic write)
# ---------------------------------------------------------------------------

# B2/C7 (campaign #3): STRICT UTF-8 decoding. With permissive decoding the invalid
# bytes become U+FFFD SILENTLY (corrupted data presented as valid, and U+FFFD
# has NULL collation weight: '�Z' -eq 'Z' is true in PS 5.1 — poisoned comparisons).
# With strict decoding the unreadable is EXPLICIT ('' / Ok=$false).
$script:StrictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)

function Get-SafeCutIndex {
    <#
        B2 (campaign #3): cut index that NEVER splits a surrogate pair
        (emoji/supplementary): the caller cuts Substring(0, <return>) for the
        head and Substring(<return>) for the tail (-KeepTail).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [int]$Index,
        [switch]$KeepTail
    )
    if ($Index -le 0) { return 0 }
    if ($Index -ge $Text.Length) { return $Text.Length }
    if ($KeepTail) {
        # Head cut: if the character AT the index is an orphan low surrogate (second
        # half of a pair), the tail starts one character later.
        if ([char]::IsLowSurrogate($Text[$Index])) { return $Index + 1 }
        return $Index
    }
    # Tail cut: if the character BEFORE the index is an orphan high surrogate (first
    # half of a pair), the head ends one character earlier.
    if ([char]::IsHighSurrogate($Text[$Index - 1]) -and [char]::IsLowSurrogate($Text[$Index])) { return $Index - 1 }
    return $Index
}

function Read-TextFileSafe {
    <#
        Reads a text file. Returns '' if missing or unreadable. Throws no
        exceptions. C7: STRICT decoding — a file with invalid non-UTF-8 bytes is
        unreadable (never silent U+FFFD). B2: truncation does not split surrogate
        pairs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxChars = 0
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return '' }
        $text = [System.IO.File]::ReadAllText($Path, $script:StrictUtf8)
        if ($MaxChars -gt 0 -and $text.Length -gt $MaxChars) {
            # EXPLICIT truncation (never silent): the consumer must see that text is missing.
            $k = Get-SafeCutIndex -Text $text -Index $MaxChars
            $text = $text.Substring(0, $k) + "`n[truncated " + ($text.Length - $k) + ' trailing characters]'
        }
        return $text
    } catch {
        return ''
    }
}

function Read-TextFileState {
    <#
        Read for STATE files that get REWRITTEN: it distinguishes "missing" (the
        caller template is correct) from "present but unreadable" (overwriting
        with the template would be a TOTAL loss of state — class of finding #32:
        Read-TextFileSafe returns '' in BOTH cases and the callsites interpreted
        every read fault as "file missing"). C7: STRICT decoding — invalid
        non-UTF-8 bytes -> Ok=$false (never rewrite over corrupted state).
        -KeepTail: truncates the HEAD (keeps the tail, for logs) instead of the tail.
        B2: both truncations do not split surrogate pairs.
        Always returns a hashtable @{ Ok; Absent; Text; Error }: never exceptions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxChars = 0,
        [switch]$KeepTail
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            return @{ Ok = $true; Absent = $true; Text = ''; Error = '' }
        }
        $text = [System.IO.File]::ReadAllText($Path, $script:StrictUtf8)
        if ($MaxChars -gt 0 -and $text.Length -gt $MaxChars) {
            if ($KeepTail) {
                $k = $text.Length - $MaxChars
                $k = Get-SafeCutIndex -Text $text -Index $k -KeepTail
                $text = '[truncated ' + $k + " leading characters]`n" + $text.Substring($k)
            } else {
                $k = Get-SafeCutIndex -Text $text -Index $MaxChars
                $text = $text.Substring(0, $k) + "`n[truncated " + ($text.Length - $k) + ' trailing characters]'
            }
        }
        return @{ Ok = $true; Absent = $false; Text = $text; Error = '' }
    } catch {
        return @{ Ok = $false; Absent = $false; Text = ''; Error = $_.Exception.Message }
    }
}

function Read-FileTailText {
    <#
        Reads only the tail of a large file (seek, without loading everything into memory).
        B2: the seek may fall in the MIDDLE of a multibyte UTF-8 character: the
        leading continuation bytes (10xxxxxx) are discarded before decoding. C7:
        STRICT decoding (invalid bytes -> '').
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxBytes = 2000000
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return '' }
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $len = $fs.Length
            if ($len -le 0) { return '' }
            $start = [Math]::Max(0, $len - $MaxBytes)
            [void]$fs.Seek($start, [System.IO.SeekOrigin]::Begin)
            $count = [int]($len - $start)
            $buf = New-Object byte[] $count
            $read = $fs.Read($buf, 0, $count)
            $off = 0
            while ($off -lt $read -and (($buf[$off] -band 0xC0) -eq 0x80)) { $off++ }
            return $script:StrictUtf8.GetString($buf, $off, $read - $off)
        } finally {
            $fs.Dispose()
        }
    } catch {
        return ''
    }
}

function Write-TextFileAtomic {
    <# Atomic UTF-8 write without BOM: temporary file in the same folder + move.
       - Short retry on the move: if a reader keeps the file open without FileShare.Delete
         the replace fails; a typical reader keeps it for a few ms (contention probe:
         ~half of the writes failed with a reader in a tight loop).
       - The temp is ALWAYS cleaned up if the move fails (class: intermediate artifact
         without cleanup on the error branch; evidence: 7714 orphan .tmp-* in .probe).
       - M5 (campaign #2): the retry parameters are INJECTABLE for tests
         (defaults UNCHANGED 3 x 25 ms). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [int]$MoveAttempts = 3,
        [int]$MoveSleepMs = 25
    )
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        [void](New-Item -ItemType Directory -Force -Path $dir)
    }
    # L7 (campaign #2, class LC): a kill between the tmp write and the move
    # left an orphan .tmp-*.txt forever (the existing cleanup covers only the
    # IN-PROCESS error branch). Sweep of ONLY stale tmps (> 10 min: no
    # legitimate writer keeps them that long) in the destination directory; per-file
    # errors must never prevent the current write.
    if ($dir) {
        try {
            $staleCut = (Get-Date).AddMinutes(-10)
            foreach ($stale in @(Get-ChildItem -LiteralPath $dir -Filter '.tmp-*.txt' -File -Force -ErrorAction SilentlyContinue)) {
                if ($stale.LastWriteTime -lt $staleCut) {
                    try { [System.IO.File]::Delete($stale.FullName) } catch { }
                }
            }
        } catch { }
    }
    $tmp = Join-Path $dir ('.tmp-' + [Guid]::NewGuid().ToString('N') + '.txt')
    $enc = New-Object System.Text.UTF8Encoding($false)
    try {
        [System.IO.File]::WriteAllText($tmp, $Text, $enc)
        $attempts = 0
        while ($true) {
            $attempts++
            try {
                Move-Item -LiteralPath $tmp -Destination $Path -Force
                break
            } catch {
                # If the temp is gone the move succeeded (reported late).
                if (-not (Test-Path -LiteralPath $tmp)) { break }
                if ($attempts -ge $MoveAttempts) { throw }
                Start-Sleep -Milliseconds $MoveSleepMs
            }
        }
    } catch {
        if (Test-Path -LiteralPath $tmp) {
            try { [System.IO.File]::Delete($tmp) } catch { }
        }
        throw
    }
}

function Get-UniqueFilePath {
    <#
        Returns a free path: if the file already exists, it appends -2, -3... before
        the extension. Needed for names based only on the timestamp (seconds):
        two rotations/archives in the same second must not overwrite each other.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $Path }
    $dir = Split-Path -Parent $Path
    $base = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    $ext = [System.IO.Path]::GetExtension($Path)
    for ($i = 2; $i -lt 1000; $i++) {
        $candidate = Join-Path $dir ($base + '-' + $i + $ext)
        if (-not (Test-Path -LiteralPath $candidate)) { return $candidate }
    }
    # L5 (campaign #2, class LF): with ALL 998 numeric names taken the
    # old code returned $Path — the TAKEN name — and the caller wrote
    # OVER it (silent overwrite). Fallback: 8-hex GUID suffix
    # verified free; only if even 100 GUID candidates turn out taken
    # (practically impossible) $null is returned: the caller must NEVER
    # receive a taken path.
    for ($g = 0; $g -lt 100; $g++) {
        $candidate = Join-Path $dir ($base + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + $ext)
        if (-not (Test-Path -LiteralPath $candidate)) { return $candidate }
    }
    return $null
}

function Test-ProjectLocalInjector {
    <#
        EXACTLY-ONCE GUARD (kit variant), shared by the 4 event hooks
        (campaign #3, class F6: only Invoke-SessionStart had a guard, and it read
        ONLY .claude/settings.json -- a registration in .claude/settings.local.json
        produced a DOUBLE run; the 3 other hooks had no guard at all). Fail-open
        everywhere: any doubt -> $false (the caller acts).
          1. This copy runs from INSIDE the project (project-level wiring) ->
             $false: ALWAYS act.
          2. This copy runs OUTSIDE the project (user-level install) AND the
             project has BOTH its own registration in .claude/settings.json OR
             .claude/settings.local.json mentioning THIS hook file AND its own
             local copy at <project>/.claude/hooks/<file> -> $true: stay SILENT
             (the project copy is the actor: one run even with user+project
             registration).
          3. Everything else -> $false. Silence requires POSITIVE evidence of a
             project-local actor: a bare filename mention in project settings is
             NOT enough (that is exactly the config that would otherwise silence
             every copy at once).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$SelfPath,
        [Parameter(Mandatory)][AllowEmptyString()][string]$ProjectDir,
        [Parameter(Mandatory)][string]$HookFileName
    )
    if (-not $SelfPath -or -not $ProjectDir) { return $false }
    try {
        $selfFull = [System.IO.Path]::GetFullPath($SelfPath)
        $projFull = [System.IO.Path]::GetFullPath($ProjectDir).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
        $insideProject = $selfFull.StartsWith($projFull + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)
        if ($insideProject) { return $false }
        $localHook = [System.IO.Path]::Combine($ProjectDir, '.claude', 'hooks', $HookFileName)
        if (-not [System.IO.File]::Exists($localHook)) { return $false }
        foreach ($setName in @('settings.json', 'settings.local.json')) {
            $p = [System.IO.Path]::Combine($ProjectDir, '.claude', $setName)
            if ([System.IO.File]::Exists($p)) {
                # Permissive read is correct here (fail-open direction: an
                # unreadable settings file -> no mention -> the caller acts).
                $raw = [System.IO.File]::ReadAllText($p, [System.Text.Encoding]::UTF8)
                if ($raw.IndexOf($HookFileName, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
            }
        }
        return $false
    } catch { return $false }
}

# ---------------------------------------------------------------------------
# Hook output
# ---------------------------------------------------------------------------

function Write-HookOutputRaw {
    <#
        Writes text to the hook's stdout with DETERMINISTIC bytes.
        With redirected stdout (real harness and tests) the bytes are explicit UTF-8: the
        consumer (Claude Code) reads UTF-8 JSON, while [Console]::Out would use the
        console codepage of the child process, which depends on where it runs: a
        message with accents would reach the consumer as mojibake (or invalid).
        With stdout on the console (manual run) [Console]::Out remains in use, which renders
        accents correctly on the console.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    if ([Console]::IsOutputRedirected) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        # OpenStandardOutput does not own the std handle: it must not be closed here.
        $stream = [Console]::OpenStandardOutput()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        return
    }
    [Console]::Out.Write($Text)
    [Console]::Out.Flush()
}

function Write-HookErrorRaw {
    <#
        Writes text to the hook's STDERR with DETERMINISTIC bytes (class F15):
        with redirected stderr (2>) [Console]::Error would use the OEM codepage of the
        child process -> mojibake accents in the output files of tests and
        consumers. Same strategy as Write-HookOutputRaw.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    if ([Console]::IsErrorRedirected) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        # OpenStandardError does not own the std handle: it must not be closed here.
        $stream = [Console]::OpenStandardError()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        return
    }
    [Console]::Error.Write($Text)
    [Console]::Error.Flush()
}

function Write-HookPlain {
    <# Writes text to the hook's stdout (used for additionalContext or messages). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    Write-HookOutputRaw -Text $Text
}

function Write-HookJson {
    <#
        Emits the hook response JSON.
        - AdditionalContext -> hookSpecificOutput.additionalContext
        - PermissionDecision (allow|deny|ask) -> hookSpecificOutput.permissionDecision
        - Reason -> hookSpecificOutput.permissionDecisionReason
        - SystemMessage -> systemMessage (visible to the user)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EventName,
        [string]$AdditionalContext,
        [ValidateSet('allow', 'deny', 'ask')][string]$PermissionDecision,
        [string]$Reason,
        [string]$SystemMessage
    )
    $specific = [ordered]@{ hookEventName = $EventName }
    if ($PSBoundParameters.ContainsKey('AdditionalContext')) { $specific['additionalContext'] = $AdditionalContext }
    if ($PSBoundParameters.ContainsKey('PermissionDecision')) {
        $specific['permissionDecision'] = $PermissionDecision
    }
    if ($PSBoundParameters.ContainsKey('Reason')) { $specific['permissionDecisionReason'] = $Reason }

    $payload = [ordered]@{ hookSpecificOutput = $specific }
    if ($PSBoundParameters.ContainsKey('SystemMessage')) { $payload['systemMessage'] = $SystemMessage }

    $json = $payload | ConvertTo-Json -Depth 6 -Compress
    Write-HookOutputRaw -Text $json
}

# ---------------------------------------------------------------------------
# Sensitive file classification (no content, name only)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Sensitive path table (SINGLE source of truth: Test-SensitivePath uses it
# and the suites enumerate it — class F11: a badly written or removed entry
# must fail its own test case, not pass silently).
# ---------------------------------------------------------------------------
$script:SensitiveExactNames = @(
    '.netrc', '_netrc', '.npmrc', '.pypirc', '.htpasswd', '.git-credentials',
    '.pgpass', '.my.cnf', '.dockercfg',
    'credentials', 'credentials.json', 'credentials.xml', 'secrets.json', 'secrets.yaml', 'secrets.yml',
    'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'authorized_keys',
    'keystore', 'keystore.json', 'wallet.dat', 'seed.txt', 'mnemonic.txt',
    'mcp.json', '.mcp.json', 'claude_desktop_config.json',
    'token.json', 'tokens.json', 'auth.json', 'cookies.txt', 'cookies.json'
)
$script:SensitiveEnvNames = @('env.local', 'env.production', 'env.development', 'env.staging', 'env.test')
$script:SensitiveExtensions = @('pem', 'key', 'pfx', 'p12', 'jks', 'keystore', 'ppk', 'asc', 'gpg', 'kdbx', 'der', 'csr', 'tfstate', 'tfvars', 'jwk', 'p8', 'ovpn')
# Segment entries in the UNIVERSAL comparison shape ('/'-separated, see
# Test-SensitivePathText; campaign #3, class F3): the previous '\'-shaped
# entries ('.config\gcloud') only ever matched the Windows rewrite.
$script:SensitiveSegments = @('.ssh', '.aws', '.gnupg', '.kube', '.docker', '.azure', '.terraform', '.pulumi', '.config/gcloud', '.config/gh', '.config/hub', 'AppData/Roaming/gcloud')

function Test-SensitivePathText {
    <#
        C2/M9 (campaign #3): PURE part of the "sensitive path" classification
        (file name + segments), ZERO filesystem access. Used (a) by the command
        scanner as an ECONOMIC phase before the canonicalization walk and
        (b) by Test-SensitivePath on the canonical path. Always the same tables:
        no copy, no drift between the two uses.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$PathText)
    if ([string]::IsNullOrWhiteSpace($PathText)) { return $false }

    $name = ''
    try { $name = [System.IO.Path]::GetFileName($PathText) } catch { $name = $PathText }
    if (-not $name) { $name = $PathText }
    $n = $name.ToLowerInvariant()
    # UNIVERSAL comparison shape (class F3): separators normalized to '/' on BOTH
    # OSes ('/' and '\' both map to '/'). On POSIX a '\' can be a legal file-name
    # character: treating it as a separator can only CREATE segment matches
    # (over-deny, the fail-closed direction) and can never hide a real '/'-segment.
    $p = ($PathText.ToLowerInvariant() -replace '\\', '/').TrimEnd('/')

    # .env and .env.* (any variant; no exception, even for templates)
    if ($n -match '^\.env(\.|$)') { return $true }
    if ($script:SensitiveEnvNames -contains $n) { return $true }
    if ($n -eq '.envrc') { return $true }

    # Known exact names (script-level table: see $script:SensitiveExactNames)
    if ($script:SensitiveExactNames -contains $n) { return $true }

    # Extensions of infrastructure keys/certificates/secrets (exposed table)
    if ($n -match ('\.(' + (($script:SensitiveExtensions | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')$')) { return $true }

    # Delimited keywords in the file name (avoids false positives like "tokenizer.py")
    if ($n -match '(^|[._-])(secret|secrets|credential|credentials|password|passwd|apikey|api[_-]key|private[_-]key|access[_-]token|refresh[_-]token|auth[_-]token|seed|mnemonic)([._-]|$)') { return $true }

    # Sensitive path segments (universal '/' shape, class F3;
    # exposed table: $script:SensitiveSegments)
    $segRe = '/(' + (($script:SensitiveSegments | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')(/|$)'
    if ($p -match $segRe) { return $true }
    if ($p -match '/\.claude/(mcp\.json|\.credentials\.json)$') { return $true }

    return $false
}

function Test-SensitivePath {
    <#
        Returns $true if the path must be considered sensitive: it must NOT be
        read, printed, archived or sent.
        Rule: comparison on the file NAME and on known path segments, on the CANONICAL
        path (separators, ADS, trailing space/dot, junction): without canonicalization
        "C:/Users/x/.ssh/id_rsa" or a path with a trailing space bypass the comparisons.
        FAIL-CLOSED (C1, campaign #3): if canonicalization fails ('' from
        Get-CanonicalPath: chain over 64 hops, cycle, over 1024 characters, error)
        the path is considered SENSITIVE: an unresolvable path is not
        verifiable, and an allow would be bypassable with a junction chain.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }

    # Two steps (C1, revised in the field — discriminating case: the shell ':'
    # token): the '' sentinel of Get-CanonicalPath CONFLATED two cases:
    #   (a) the input is NOT a path (normalization itself produces nothing:
    #       bare ':', '::', fragments) -> not a sensitive path -> allow;
    #   (b) the input IS a path but is not reliably resolvable (chain
    #       over 64 hops, reparse cycle, over 1024 characters, error) ->
    #       FAIL-CLOSED: not verifiable -> sensitive.
    $key = Get-NormalizedPathKey -Path $Path
    if (-not $key) { return $false }
    $canon = Get-CanonicalPath -Path $Path
    if (-not $canon) { return $true }

    return (Test-SensitivePathText -PathText $canon)
}

function Get-SensitiveLabel {
    <# Redacted label to use in logs: file name only, never the full path. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)
    try { return [System.IO.Path]::GetFileName($Path) } catch { return '[SENSITIVE_FILE]' }
}

function ConvertTo-SafeInline {
    <#
        M12 (campaign #2, class CA): value derived from the payload written inside
        markdown or pipe-delimited rows. A NEWLINE in the value creates a NEW ROW
        and a heading ('## ...') at the head of that row becomes a real SECTION
        (archive, INDEX, STATE.md, context injected by SessionStart).
        Neutralization: newline -> space, '|' -> '/' (pipe-delimited formats),
        markdown headings at start of line -> '[##] heading' (same form already used by
        PostCompact for the summary), explicit cap with '...'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [int]$Max = 200
    )
    if ($Text -eq '') { return '' }
    $t = $Text -replace '\r?\n', ' '
    $t = $t -replace '\|', '/'
    $t = [regex]::Replace($t, '(?m)^(#{1,6})[ \t]+', '[$1] ')
    $t = $t.Trim()
    if ($Max -gt 0 -and $t.Length -gt $Max) { $t = $t.Substring(0, (Get-SafeCutIndex -Text $t -Index $Max)) + '...' }
    return $t
}

function Add-DegradationRow {
    <#
        M9 (campaign #2, class CB): an audit row must NOT vanish silently
        when the write to the PRIMARY channel fails (after the existing retries of
        Write-TextFileAtomic). Here the TWIN channel is attempted with a direct append:
          denied        -> FAILURES.md   (dedicated cause 'channel-degradation')
          failure/index -> denied-actions.log
        If the twin also fails (or .agent does not exist): ONE line on stderr,
        last resort. Never exceptions; always returns $false (the caller has already
        lost the primary). The twin has NO retries of its own: single append,
        best-effort declared in DECISIONS.md (REST).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectDir,
        [Parameter(Mandatory)][ValidateSet('denied', 'failure', 'index')][string]$Kind,
        [AllowEmptyString()][string]$Detail = '',
        [AllowEmptyString()][string]$Cause = ''
    )
    $det = '[REDACTION-FAILED]'
    # C6 (campaign #3): masking of sensitive references (same scanner as the
    # gate) BEFORE the generic redaction; then minimal fallback (class F10).
    try { $det = [string](Remove-SensitiveContent -Text (Remove-SensitiveTokensFromCommand -Command ([string]$Detail))) } catch { }
    $det = (($det -replace '\r?\n', ' ') -replace '\|', '/').Trim()
    if ($det.Length -gt 180) { $det = $det.Substring(0, (Get-SafeCutIndex -Text $det -Index 180)) + '...' }
    $cau = (([string]$Cause -replace '\r?\n', ' ') -replace '\|', '/').Trim()
    if ($cau.Length -gt 80) { $cau = $cau.Substring(0, (Get-SafeCutIndex -Text $cau -Index 80)) + '...' }
    if (-not $cau) { $cau = 'not recorded' }
    try {
        $agentDir = Get-AgentDir -ProjectDir $ProjectDir
        if (Test-Path -LiteralPath $agentDir) {
            $enc = New-Object System.Text.UTF8Encoding($false)
            if ($Kind -eq 'denied') {
                $row = '| ' + (Get-HumanStamp) + ' | Hook-Common | denied | channel-degradation: ' + $det + ' | primary (denied-actions.log) not writable (' + $cau + '): row redirected here | check locks/permissions |' + "`n"
                [System.IO.File]::AppendAllText((Join-Path $agentDir 'FAILURES.md'), $row, $enc)
            } else {
                $line = (Get-HumanStamp) + ' | DENY | channel-degradation | Hook-Common | ' + $Kind + ' (' + $cau + '): ' + $det + "`n"
                [System.IO.File]::AppendAllText((Join-Path $agentDir 'denied-actions.log'), $line, $enc)
            }
            return $false
        }
    } catch { }
    # Last resort: NEVER silence. One line on stderr, no exception to the caller.
    try { [Console]::Error.WriteLine('[hook-degradation] ' + $Kind + ' (' + $cau + '): ' + $det) } catch { }
    return $false
}

function Get-DequotedCommandText {
    <#
        F7 (campaign #3): the shell REMOVES quotes before building arguments, so
        'cat ."env"' reaches the shell as 'cat .env' -- but a tokenizer that stops
        at the quote sees only '.' and 'env', and the mixed outside/inside-quote
        GLUE evaded both the sensitive gate and the log masking (same bypass for
        write targets: 'Set-Content C:\"Windows"\...'). Returns the command with
        ALL quote characters removed, for the scanners to classify as a SECOND
        source. Fail-closed direction: stripping quotes can only GLUE fragments
        of one shell word (create hits), never hide a hit the raw pass would
        have found. Not a shell parser: backslash escapes and $'...' forms are
        not interpreted (declared remainder).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Command)
    if ([string]::IsNullOrEmpty($Command)) { return [string]$Command }
    return ($Command -replace '"', '') -replace "'", ''
}

function Get-CommandSensitiveTokenHit {
    <#
        H1 (campaign #2): parity between the shell channel <-> tool-file channel on the
        sensitive FAMILIES, generated FROM the 4 tables of Hook-Common. The catch-all regex
        'secret-token' was a HAND COPY of the families: every entry that the file
        channel denied and the copy did not list remained allowed via shell (5/5 env
        names, bare 'keystore', 11 keywords in the file name, 12 segments in
        relative form). Here every token of the command is classified with the SAME
        Test-SensitivePath as the file channel: no copy, no possible drift.
        Forms: bare tokens or quoted (the tokenizer isolates the quoted content),
        --opt=value / -Opt:value prefixes (the value after the last
        delimiter is also tried). Purely alphanumeric BARE words (e.g. search argument
        `rg password`) remain allowed: the file channel 'keywords' family
        detects only INSIDE a file name, while exact names and env variants
        (keystore, credentials) remain covered -- via tables -- even as bare words.
        Guard of metadata-only verbs IDENTICAL to the catch-all one (project
        decision: Test-Path/Get-Item/Resolve-Path on a bare command).
        Best-effort: a token that canonicalization does not process is skipped.
        Budget (C2, campaign #3): the walk cost is limited by
        Get-ScanBudgetVerdict; over budget the scan does NOT proceed and returns the
        marker '[SCANNER-OVERSIZE]' (fail-closed: the caller treats it as a
        hit). NO fixed cap on the number of tokens (the old cap 64 silently
        lost a sensitive reference beyond the 64th token).
        M14 (campaign #2): DEFINITION MOVED here from Block-Destructive -- single copy
        shared with the registration channel. -All returns ALL distinct tokens
        found (array, for log masking); -IgnoreMetadataGuard skips the
        metadata verb guard (which the GATE needs for the allow of read-only
        commands: for log masking the sensitive reference must still be
        covered even under Test-Path/Get-Item).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Command,
        [switch]$All,
        [switch]$IgnoreMetadataGuard
    )
    if ([string]::IsNullOrWhiteSpace($Command)) { if ($All) { return , ([string[]]@()) }; return '' }
    if (-not $IgnoreMetadataGuard -and ($Command -match '(?is)^\s*(?:test-path|test-anypath|get-item|resolve-path)\b[^\r\n;&|]*\s*$')) { if ($All) { return , ([string[]]@()) }; return '' }
    # F7 (campaign #3): the quote-stripped twin of the command (the shell removes
    # quotes before execution: 'cat ."env"' reads .env; see
    # Get-DequotedCommandText). Classified below as a SECOND source.
    $deq = Get-DequotedCommandText -Command $Command
    # C2 (use #2): walk budget. THE ESTIMATE MUST BOUND BOTH PASSES: it runs on
    # the raw text AND its quote-stripped twin (same length order). The sum is
    # taken ONLY when the twin DIFFERS: with no quote characters the twin IS the
    # raw text, and adding it doubles the estimate, ANTICIPATING the limit (a
    # command of exactly ScanBudgetMaxChars chars was classified 'oversize' ->
    # fail-closed deny on a declared limit that was never exceeded). Found live by
    # the source workspace's contract harness (its 200000-char boundary case).
    $budgetText = $Command
    if ($deq -ne $Command) { $budgetText = $Command + ' ' + $deq }
    $budget = Get-ScanBudgetVerdict -Text $budgetText
    if ($budget -eq 'oversize') { if ($All) { return , ([string[]]@($script:ScanOversizeMarker)) }; return $script:ScanOversizeMarker }
    if ($budget -eq 'empty') { if ($All) { return , ([string[]]@()) }; return '' }

    $cands = New-Object System.Collections.Generic.List[string]
    # Shell tokens: delimiters space, ; & |, quotes, open parentheses (same
    # tokenizer as the protected areas check, but WITHOUT the absolute path filter:
    # a relative reference to a sensitive file is as sensitive as an absolute one).
    foreach ($m in [regex]::Matches($Command, '[^\s;&|("'']+')) {
        $t = $m.Value.TrimEnd(')', '}', ',')
        if ($t) { [void]$cands.Add($t) }
    }
    # Quote-stripped twin (F7): no quote characters remain -> the tokenizer class
    # drops the quote delimiters. Purely ADDITIVE candidates (a hit found here is
    # a reference the shell really sees).
    if ($deq -ne $Command) {
        foreach ($m in [regex]::Matches($deq, '[^\s;&|(]+')) {
            $t = $m.Value.TrimEnd(')', '}', ',')
            if ($t) { [void]$cands.Add($t) }
        }
    }
    $hits = New-Object System.Collections.Generic.List[string]
    $seenHit = @{}
    # C2/A3 (campaign #3): NO fixed cap on the number of tokens. The walk cost is
    # limited by the BUDGET declared at the top (Get-ScanBudgetVerdict); the old cap
    # of 64 silently lost a sensitive reference beyond the 64th token.
    foreach ($tok in $cands) {
        # The WHOLE token is tried and, if there is a --opt=value / -Opt:value prefix,
        # also the VALUE: it is the value that is the file reference.
        $tests = New-Object System.Collections.Generic.List[string]
        [void]$tests.Add($tok)
        $i = [Math]::Max($tok.LastIndexOf([char]'='), $tok.LastIndexOf([char]':'))
        if ($i -ge 0 -and $i -lt ($tok.Length - 1)) { [void]$tests.Add($tok.Substring($i + 1)) }
        foreach ($t in $tests) {
            if (-not $t) { continue }
            try {
                $hitTok = $false
                if ($t -match '^[A-Za-z0-9]+$') {
                    # Bare word: only EXACT NAMES and env variants (the same tables).
                    # Bare keywords (password/secret/seed/...) would give
                    # over-block on text searches: allow, REST declared.
                    $tn = $t.ToLowerInvariant()
                    $hitTok = ($script:SensitiveExactNames -contains $tn) -or ($script:SensitiveEnvNames -contains $tn)
                } else {
                    # C2 (use #1): ECONOMIC phase (zero filesystem) before the walk:
                    # the vast majority of tokens is classified without IO.
                    $hitTok = Test-SensitivePathText -PathText $t
                    if (-not $hitTok) { $hitTok = Test-SensitivePath -Path $t }
                }
                if ($hitTok) {
                    if (-not $All) { return $t }
                    if (-not $seenHit.ContainsKey($t)) { $seenHit[$t] = $true; [void]$hits.Add($t) }
                    break
                }
            } catch { }
        }
    }
    if ($All) { return , ([string[]]$hits.ToArray()) }
    return ''
}

function Remove-SensitiveTokensFromCommand {
    <#
        M14 (campaign #2, class CA): the command of a failed tool ended up RAW in
        FAILURES.md ("cat .env", "type ..\secrets\prod.pem"): the sensitive file
        reference remained in cleartext in the logs. Here the ORIGINAL command is scanned
        once with the same gate scanner (Get-CommandSensitiveTokenHit
        -All -IgnoreMetadataGuard) and every token found is replaced with
        '[SENSITIVE_FILE] <file name>' (name only, never the path: same label
        as the tool-file channel). Replacement in ONE pass on the ORIGINAL text: the
        inserted placeholders are not re-scanned.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $Command }
    # C2 (use #2, registration side): command over budget -> EXPLICIT placeholder.
    # Never the raw text, never an unlimited walk: here it is not possible to verify what
    # the command contains, so it is not written.
    # F7: the SAME combined estimate as the gate (raw + quote-stripped twin),
    # with the sum applied ONLY when the twin differs (with no quotes there is no
    # second pass to bound: adding the identical text would anticipate the limit).
    $deqAll = Get-DequotedCommandText -Command $Command
    $budgetText = $Command
    if ($deqAll -ne $Command) { $budgetText = $Command + ' ' + $deqAll }
    if ((Get-ScanBudgetVerdict -Text $budgetText) -eq 'oversize') { return '[REDACTED:oversize-command]' }
    # DIRECT assignment, without @(...): the producer returns the comma-wrapped array
    # (DIRECT form, see F22) and @() ADDS a level of nesting instead of
    # removing it -> foreach received the ARRAY as a single element and the
    # [string] binding of Get-SensitiveLabel exploded (BINDING exception, outside every
    # internal catch: the caller lost the row). Class verified live (M14 RED).
    $hits = @()
    try { $hits = Get-CommandSensitiveTokenHit -Command $Command -All -IgnoreMetadataGuard } catch { $hits = @() }
    if ($null -eq $hits) { $hits = @() }
    if ($hits.Count -eq 0) { return $Command }
    $out = $Command
    foreach ($h in $hits) {
        if (-not $h) { continue }
        $label = '[SENSITIVE_FILE] ' + (Get-SensitiveLabel -Path ([string]$h))
        try { $out = $out.Replace([string]$h, $label) } catch { }
    }
    # F7 (campaign #3): the literal pass above cannot mask a reference that the shell
    # builds ACROSS quotes ('cat ."env"'): '.env' is not a substring of '."env"', so
    # the raw command was logged unmasked (the gate denies it; the LOG leaked it).
    # Second pass, span-based: quote-INCLUSIVE tokens (spaces/&/|/() still delimit),
    # a token containing a quote is re-classified through the SAME scanner on its
    # quote-STRIPPED form (no duplicated rules: one classifier) and, on a hit, the
    # WHOLE raw span -- quotes included -- is replaced. Right-to-left by offset so
    # the earlier spans stay valid. No fixed cap: bounded by the budget checked above.
    $spans = New-Object System.Collections.Generic.List[object]
    foreach ($m in [regex]::Matches($out, '[^\s;&|()]+')) {
        $tok = $m.Value
        if ($tok.IndexOf('"') -lt 0 -and $tok.IndexOf("'") -lt 0) { continue }
        $deqTok = ($tok -replace '"', '') -replace "'", ''
        if (-not $deqTok -or $deqTok -eq $tok) { continue }
        $tkHits = @()
        try { $tkHits = Get-CommandSensitiveTokenHit -Command $deqTok -All -IgnoreMetadataGuard } catch { $tkHits = @() }
        if ($null -eq $tkHits) { $tkHits = @() }
        if ($tkHits.Count -eq 0) { continue }
        $label = '[SENSITIVE_FILE] ' + (Get-SensitiveLabel -Path ([string]$tkHits[0]))
        [void]$spans.Add(@{ I = $m.Index; L = $m.Length; T = $label })
    }
    for ($i = $spans.Count - 1; $i -ge 0; $i--) {
        $s = $spans[$i]
        $out = $out.Substring(0, [int]$s.I) + [string]$s.T + $out.Substring([int]$s.I + [int]$s.L)
    }
    return $out
}

# C2 (campaign #3): scan walk budget. A command may contain tokens that
# force expensive canonicalizations (each segment = one Get-Item): without a budget the
# gate would hang for minutes (DoS of the hook = gate effectively disabled).
# TRI-STATE verdict: 'empty' (nothing to scan), 'clean', 'oversize' (fail-closed:
# not fully verifiable -> the caller denies).
$script:ScanBudgetMaxChars = 200000
$script:ScanBudgetMaxMs = 2000
$script:ScanBudgetWalkTokenMs = 2.0
$script:ScanBudgetSegSqMs = 0.0045
$script:ScanOversizeMarker = '[SCANNER-OVERSIZE]'

function Get-ScanBudgetVerdict {
    <#
        Estimates the canonicalization walk cost of the command (SAME tokenizer
        as the scanner; purely alphanumeric tokens are NEVER walked:
        bare word -> in-memory tables only). Cost per non-word token:
        fixed ScanBudgetWalkTokenMs + segments^2 * ScanBudgetSegSqMs (resolution
        is per-prefix: the cost grows with the square of the segments). Returns
        'oversize' as soon as the estimate exceeds ScanBudgetMaxMs, 'empty' if there is
        nothing to scan, 'clean' otherwise. PURE: no filesystem access.
        The parameter is named -Text: CONTRACT name with the tests (TF) — do not
        rename it without updating the contract.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return 'empty' }
    if ($Text.Length -gt $script:ScanBudgetMaxChars) { return 'oversize' }
    $est = 0.0
    foreach ($m in [regex]::Matches($Text, '[^\s;&|("'']+')) {
        $t = $m.Value.TrimEnd(')', '}', ',')
        if (-not $t) { continue }
        if ($t -match '^[A-Za-z0-9]+$') { continue }
        $seg = $t.Length - $t.Replace('\', '').Replace('/', '').Length
        $est += $script:ScanBudgetWalkTokenMs + (($seg * $seg) * $script:ScanBudgetSegSqMs)
        if ($est -gt $script:ScanBudgetMaxMs) { return 'oversize' }
    }
    return 'clean'
}

# ---------------------------------------------------------------------------
# Failure log (.agent/FAILURES.md)
# ---------------------------------------------------------------------------

function Add-FailureRecord {
    <#
        Adds a redacted row to .agent/FAILURES.md.
        - Throws no exceptions (best-effort): returns $true/$false.
        - Skips identical duplicates present in the last rows.
        - Rotates the file into .agent/archive if it exceeds MaxRows rows.
        - -Stamp allows an INJECTED timestamp (deterministic dedup tests:
          the comparison includes the timestamp, and two calls across a
          second change do not deduplicate — class F25).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectDir,
        [Parameter(Mandatory)][string]$Component,
        [AllowEmptyString()][string]$Command = '',
        [AllowEmptyString()][string]$ErrorText = '',
        [AllowEmptyString()][string]$Cause = 'auto',
        [int]$MaxRows = 300,
        [AllowEmptyString()][string]$Stamp = ''
    )
    try {
        $agentDir = Get-AgentDir -ProjectDir $ProjectDir
        if (-not (Test-Path -LiteralPath $agentDir)) { return $false }
        Register-FilterDegradation -ProjectDir $ProjectDir
        # Cross-process lock: read-modify-write without a lock loses rows when two hooks
        # (different processes) write to the same file at the same moment.
        return (Invoke-WithAgentLock -ProjectDir $ProjectDir -ScriptBlock {
        try {
        $path = Join-Path $agentDir 'FAILURES.md'

        $cell = {
            param([string]$s, [int]$max)
            $t = $s
            # C6/M14: masking of sensitive references with the SAME scanner as the
            # gate, BEFORE the generic redaction (one pass on the ORIGINAL text:
            # the inserted placeholders are not re-scanned). Always: with
            # Filter-AgentText missing the minimal fallback defined at the top
            # of the library kicks in (class F10: before, redaction was SKIPPED).
            try { $t = [string](Remove-SensitiveTokensFromCommand -Command $t) } catch { }
            $t = Remove-SensitiveContent -Text $t
            $t = ($t -replace '\r?\n', ' ')
            $t = ($t -replace '\|', '/')
            if ($t.Length -gt $max) { $t = $t.Substring(0, (Get-SafeCutIndex -Text $t -Index $max)) + '...' }
            return $t.Trim()
        }

        $stamp = $Stamp
        if (-not $stamp) { $stamp = Get-HumanStamp }
        $comp = & $cell $Component 40
        $cmd = & $cell $Command 140
        $err = & $cell $ErrorText 160
        $cau = & $cell $Cause 80
        $row = '| ' + $stamp + ' | ' + $comp + ' | ' + $cmd + ' | ' + $err + ' | ' + $cau + ' | rerun |'

        # Present-but-unreadable: do NOT rewrite with the template (total loss of
        # state). The distinction comes from Read-TextFileState (finding #32).
        $st = Read-TextFileState -Path $path
        if (-not $st.Ok) {
            # M9 (class CB): the row must not vanish silently - twin channel
            # (denied-actions.log) with a dedicated cause.
            return (Add-DegradationRow -ProjectDir $ProjectDir -Kind 'failure' -Detail ([string]$Component + ' :: ' + [string]$Command) -Cause 'primary-unreadable')
        }
        $existing = $st.Text
        if ($st.Absent -or -not $existing) {
            $existing = "# Failures`n`nReproducible failures recorded by the hooks (PostToolUseFailure, PreCompact) or manually.`nNo full output, no secrets: only the first redacted line of the error.`n`n| Timestamp | Component | Command | Error | Cause | Next verification |`n|---|---|---|---|---|---|`n"
        }
        $existing = $existing -replace '(?m)^\| _\(no failures recorded\)_ \|.*\r?\n?', ''

        # Dedup: if the last row is identical, do not add it.
        $lines = $existing -split "`n"
        for ($i = $lines.Count - 1; $i -ge 0; $i--) {
            if ($lines[$i].Trim().Length -gt 0) {
                if ($lines[$i].Trim() -eq $row) { return $true }
                break
            }
        }

        $content = $existing.TrimEnd() + "`n" + $row + "`n"

        # Rotation with HYSTERESIS: the rotated file keeps HALF of the limit, not the
        # whole limit. Keeping the whole limit the file would stay close to
        # the threshold and EVERY following append would re-rotate (class: threshold without
        # hysteresis -> one archive per row). Empty rows are not stitched back
        # into the head (`-split` produces a final empty element that became an
        # empty row at every rotation).
        $dataRows = @($content -split "`n" | Where-Object { $_ -match '^\| \d{4}-' })
        if ($dataRows.Count -gt $MaxRows) {
            $keep = [int][Math]::Floor($MaxRows / 2)
            if ($keep -lt 1) { $keep = 1 }
            $archiveDir = Get-ArchiveDir -ProjectDir $ProjectDir
            if (-not (Test-Path -LiteralPath $archiveDir)) { [void](New-Item -ItemType Directory -Force -Path $archiveDir) }
            $tail = $dataRows[($dataRows.Count - $keep)..($dataRows.Count - 1)]
            $head = @($content -split "`n" | Where-Object { $_.Trim().Length -gt 0 -and $_ -notmatch '^\| \d{4}-' })
            $rotated = ($head -join "`n") + "`n" + ($tail -join "`n") + "`n"
            Write-TextFileAtomic -Path (Get-UniqueFilePath -Path (Join-Path $archiveDir ('failures-' + (Get-HookStamp) + '.md'))) -Text $content
            Write-TextFileAtomic -Path $path -Text $rotated
        } else {
            Write-TextFileAtomic -Path $path -Text $content
        }
        return $true
        } catch {
            # M9 (class CB): write failed AFTER the existing retries - the row must
            # still be tracked on the twin channel, never lost silently.
            return (Add-DegradationRow -ProjectDir $ProjectDir -Kind 'failure' -Detail ([string]$Component + ' :: ' + [string]$Command) -Cause 'primary-not-writable')
        }
        })
    } catch {
        return $false
    }
}

function Add-DeniedRecord {
    <# Audit of the actions blocked by the policy (one redacted row per event). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectDir,
        [Parameter(Mandatory)][string]$Tool,
        [AllowEmptyString()][string]$Detail = '',
        [Parameter(Mandatory)][string]$RuleId,
        [int]$MaxRows = 500
    )
    try {
        $agentDir = Get-AgentDir -ProjectDir $ProjectDir
        if (-not (Test-Path -LiteralPath $agentDir)) { return $false }
        Register-FilterDegradation -ProjectDir $ProjectDir
        # Cross-process lock (see Add-FailureRecord): the audit must not lose rows.
        return (Invoke-WithAgentLock -ProjectDir $ProjectDir -ScriptBlock {
        try {
        $path = Join-Path $agentDir 'denied-actions.log'
        $detail = $Detail
        # C6 (campaign #3): masking at the ENTRY (gate scanner) BEFORE the
        # generic redaction: the sensitive reference must NEVER touch the log
        # in cleartext (the registration channel is the last one to see the commands).
        try { $detail = [string](Remove-SensitiveTokensFromCommand -Command ([string]$detail)) } catch { }
        # Always (class F10): minimal fallback if Filter-AgentText is missing.
        $detail = Remove-SensitiveContent -Text $detail
        # The format is ' | '-delimited: a pipe in the command created extra columns
        # (class F24, parity with Add-FailureRecord/Add-ArchiveIndexEntry).
        $detail = ($detail -replace '\r?\n', ' ') -replace '\|', '/'
        $detail = $detail.Trim()
        if ($detail.Length -gt 180) { $detail = $detail.Substring(0, (Get-SafeCutIndex -Text $detail -Index 180)) + '...' }
        $line = (Get-HumanStamp) + ' | DENY | ' + $RuleId + ' | ' + $Tool + ' | ' + $detail + "`n"
        # Present-but-unreadable: do NOT rewrite with the template (finding #32).
        $st = Read-TextFileState -Path $path
        if (-not $st.Ok) {
            # M9 (class CB): the deny must be tracked ANYWAY (twin channel FAILURES.md).
            return (Add-DegradationRow -ProjectDir $ProjectDir -Kind 'denied' -Detail ([string]$Tool + ' :: ' + [string]$Detail) -Cause 'primary-unreadable')
        }
        $existing = $st.Text
        if ($st.Absent -or -not $existing) {
            $existing = "# Actions blocked by the project policy (PreToolUse deny)`n# Format: timestamp | outcome | rule | tool | redacted detail`n"
        }
        $content = $existing.TrimEnd() + "`n" + $line

        # Rotation beyond MaxRows data rows (like FAILURES.md): the audit log must
        # not grow without limit; the full copy goes to .agent/archive.
        # Hysteresis: HALF of the limit is kept, otherwise every append re-rotates.
        $dataRows = @($content -split "`n" | Where-Object { $_ -match '^\d{4}-\d{2}-\d{2} ' })
        if ($dataRows.Count -gt $MaxRows) {
            $keep = [int][Math]::Floor($MaxRows / 2)
            if ($keep -lt 1) { $keep = 1 }
            $archiveDir = Get-ArchiveDir -ProjectDir $ProjectDir
            if (-not (Test-Path -LiteralPath $archiveDir)) { [void](New-Item -ItemType Directory -Force -Path $archiveDir) }
            $tail = $dataRows[($dataRows.Count - $keep)..($dataRows.Count - 1)]
            $head = @($content -split "`n" | Where-Object { $_.Trim().Length -gt 0 -and $_ -notmatch '^\d{4}-\d{2}-\d{2} ' })
            Write-TextFileAtomic -Path (Get-UniqueFilePath -Path (Join-Path $archiveDir ('denied-' + (Get-HookStamp) + '.log'))) -Text $content
            Write-TextFileAtomic -Path $path -Text (($head -join "`n") + "`n" + ($tail -join "`n") + "`n")
        } else {
            Write-TextFileAtomic -Path $path -Text $content
        }
        return $true
        } catch {
            # M9 (class CB): write failed AFTER the retries - row on the twin channel.
            return (Add-DegradationRow -ProjectDir $ProjectDir -Kind 'denied' -Detail ([string]$Tool + ' :: ' + [string]$Detail) -Cause 'primary-not-writable')
        }
        })
    } catch {
        return $false
    }
}

function Add-ArchiveIndexEntry {
    <# Index of the archives produced by compactions. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectDir,
        [Parameter(Mandatory)][string]$FileName,
        [AllowEmptyString()][string]$Note = ''
    )
    try {
        return (Invoke-WithAgentLock -ProjectDir $ProjectDir -ScriptBlock {
        try {
        $archiveDir = Get-ArchiveDir -ProjectDir $ProjectDir
        if (-not (Test-Path -LiteralPath $archiveDir)) { [void](New-Item -ItemType Directory -Force -Path $archiveDir) }
        $path = Join-Path $archiveDir 'INDEX.md'
        # Present-but-unreadable: do NOT rewrite with the template (finding #32).
        $st = Read-TextFileState -Path $path
        if (-not $st.Ok) {
            # M9 (class CB): the index entry must not vanish silently (twin:
            # denied-actions.log).
            return (Add-DegradationRow -ProjectDir $ProjectDir -Kind 'index' -Detail ([string]$FileName + ' ' + [string]$Note) -Cause 'primary-unreadable')
        }
        $existing = $st.Text
        if ($st.Absent -or -not $existing) { $existing = "# Context archive`n`n| Timestamp | File | Note |`n|---|---|---|`n" }
        $note = $Note -replace '\|', '/'
        if ($note.Length -gt 120) { $note = $note.Substring(0, (Get-SafeCutIndex -Text $note -Index 120)) + '...' }
        $row = '| ' + (Get-HumanStamp) + ' | ' + $FileName + ' | ' + $note.Trim() + ' |'
        Write-TextFileAtomic -Path $path -Text ($existing.TrimEnd() + "`n" + $row + "`n")
        return $true
        } catch {
            # M9 (class CB): write failed AFTER the retries - row on the twin channel.
            return (Add-DegradationRow -ProjectDir $ProjectDir -Kind 'index' -Detail ([string]$FileName + ' ' + [string]$Note) -Cause 'primary-not-writable')
        }
        })
    } catch {
        return $false
    }
}
