# Hook-Inline.ps1 — contention-proof INLINE recorder for fail-open catches.
#
# L1 (campaign #2, class LA): the 5 fail-open catches of the hooks appended the
# row with BARE [IO.File]::AppendAllText: without the gate mutex a concurrent
# append against a read-modify-write by another hook could get lost, and
# without retry a TRANSIENT contention (a reader holding FAILURES.md with
# FileShare.Read for a few ms) made the row vanish — the recording of the
# fail-open failed exactly when it was needed.
#
# This library is ZERO-DEPENDENCY (it does not use Hook-Common: it is the
# recorder of the "the library is broken" case) and has no side effects at
# dot-source time (only function definitions). It NEVER throws: the caller is a catch.
#
# Semantics of Add-InlineRow:
#   1) cross-process gate mutex: name 'Local\claude-agent-state-' + hash of the
#      ProjectDir — SAME name used by Enter-AgentLock (Hook-Common), to
#      serialize against the RMW critical sections of the other hooks;
#   2) retry-open up to ~4000 ms (sleep 60 ms, FileShare.Read): transient
#      contention resolves when the holder closes;
#   3) last resort: bare append (never worse than before).
#
#   Moreover (L1, second layer found by GREEN Q1d): the line terminator
#   is an INVARIANT of the recorder — the written row ALWAYS ends with "`n".
#   An unterminated row, written concurrently, merges with the following
#   one into a single line (Q1d: rows=1 with BOTH tokens of the two appenders:
#   "no interleaving" violated at the TRANSPORT level). Idempotent for the
#   callsites that already pass the terminator themselves (all 6 production ones:
#   5 fail-open catches + Register-FilterDegradation).

function Get-InlinePathHash {
    <# EXACT replica of Get-PathHash (Hook-Common) but with a DISTINCT name: the
       mutex name must match the one of Enter-AgentLock, without shadowing the
       Hook-Common functions when both are loaded. #>
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

function Add-InlineRow {
    <#
        Appends ONE row to an audit file (.agent) durably and returns
        $true if the row was written (even via fallback), $false otherwise.
        It NEVER throws: the worst outcome matches the previous behavior
        (bare best-effort append).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Row,
        [Parameter(Mandatory)][string]$ProjectDir
    )
    $enc = New-Object System.Text.UTF8Encoding($false)
    $mutex = $null
    $held = $false
    try {
        # Destination directory missing: nothing to do (avoids burning
        # 4000 ms of retry on a path that cannot exist).
        $rowDir = ''
        try { $rowDir = Split-Path -Parent $Path } catch { $rowDir = '' }
        if (-not $rowDir) { return $false }
        if (-not (Test-Path -LiteralPath $rowDir)) { return $false }

        # Line terminator: INVARIANT of the RECORDER (see file header).
        # Same principle as Add-FailureRecord, which adds the terminator itself
        # at write time; here an unterminated row would merge with the
        # following one (rows=1 with both tokens, measured by Q1d).
        if (-not $Row.EndsWith("`n")) { $Row += "`n" }

        # 1) Gate mutex (same name as Enter-AgentLock).
        try {
            $name = 'Local\claude-agent-state-' + (Get-InlinePathHash -Text $ProjectDir)
            $mutex = New-Object System.Threading.Mutex($false, $name)
            try { $held = $mutex.WaitOne(4000) }
            catch [System.Threading.AbandonedMutexException] { $held = $true }
            catch { $held = $false }
        } catch {
            $mutex = $null
            $held = $false
        }

        # 2) Retry-open on transient contention (sharing violation by the holder).
        $written = $false
        try {
            $bytes = $enc.GetBytes($Row)
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            while ($sw.ElapsedMilliseconds -lt 4000) {
                try {
                    $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
                    try {
                        $fs.Write($bytes, 0, $bytes.Length)
                        $fs.Flush()
                    } finally { $fs.Dispose() }
                    $written = $true
                    break
                } catch { Start-Sleep -Milliseconds 60 }
            }
        } catch { $written = $false }

        # 3) Last resort: bare append as before.
        $okFinal = $written
        if (-not $written) {
            try {
                [System.IO.File]::AppendAllText($Path, $Row, $enc)
                $okFinal = $true
            } catch { $okFinal = $false }
        }
        return $okFinal
    } catch {
        return $false
    } finally {
        if ($held -and $mutex) { try { [void]$mutex.ReleaseMutex() } catch { } }
        if ($mutex) { try { $mutex.Dispose() } catch { } }
    }
}
