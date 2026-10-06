#requires -Version 5.1
<#
.SYNOPSIS
    longctx uninstaller: remove ONLY the kit wiring from the user-level settings
    (and, explicitly requested, the KitRoot tree).
.DESCRIPTION
    An entry is ours iff any of its hooks' args contains a path starting with KitRoot.
    Everything else (user hooks, user keys, permissions.allow/ask, unrelated deny
    rules) is left untouched. Mixed entries (one of our hooks together with a user
    hook in the same entry) lose only our hook.

    - permissions.deny: LEFT IN PLACE by default (documented); with -RemoveDenyRules
      the rules listed in the kit's templates/settings-deny-fragment.json are removed
      (and only those).
    - -RemoveFiles (explicit) removes the KitRoot tree; without it the tree is kept.
      The removal requires -Apply and refuses to run unless KitRoot looks like a kit
      install (a drive root, '/' or the home directory are always refused).

    DRY RUN IS THE DEFAULT. The settings file is backed up (".bak-<stamp>") before
    any write and is written ONLY when something actually changes. An unreadable
    settings.json is a hard error: the file is never overwritten.

    Run it, do not dot-source it (it uses exit).

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File uninstall.ps1
.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File uninstall.ps1 -Apply -RemoveDenyRules
.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File uninstall.ps1 -Apply -RemoveFiles
#>

[CmdletBinding()]
param(
    [string]$KitRoot = '',
    [switch]$DryRun,
    [switch]$Apply,
    [switch]$RemoveDenyRules,
    [switch]$RemoveFiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExitOk = 0
$ExitError = 1
$ExitPrereq = 2

function Get-HomeDir {
    <# OS-aware home: USERPROFILE first on Windows (a POSIX-shaped HOME from Git
       Bash would produce a wrong path), HOME first elsewhere; the system profile
       folder as the last resort. Same order as Get-KitRootDefault in the merge
       library. #>
    [CmdletBinding()]
    param()
    $h = ''
    if ($env:OS -eq 'Windows_NT') { $h = $env:USERPROFILE; if (-not $h) { $h = $env:HOME } }
    else { $h = $env:HOME; if (-not $h) { $h = $env:USERPROFILE } }
    if (-not $h) { $h = [System.Environment]::GetFolderPath('UserProfile') }
    if (-not $h) { return '' }
    return [string]$h
}

function Test-SafeKitRoot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)
    if (-not $Path) { return $false }
    $full = ''
    try { $full = [System.IO.Path]::GetFullPath($Path) } catch { return $false }
    if ($full -match '^[A-Za-z]:[\\/]?$') { return $false }
    if ($full -eq '/' -or $full -eq '\') { return $false }
    $hCmp = Get-HomeDir
    if ($hCmp) {
        $h = ''
        try { $h = [System.IO.Path]::GetFullPath($hCmp) } catch { $h = '' }
        if ($h) {
            $f = $full.TrimEnd('\', '/')
            $ht = $h.TrimEnd('\', '/')
            if ($f -eq $ht) { return $false }
            # Ancestor gate (campaign #3, class F2): the home dir itself was refused,
            # but its ANCESTORS were not -- KitRoot="C:\Users" would make the kit
            # swallow other users' trees (and -RemoveFiles would delete under them).
            if ($ht.StartsWith($f + '\', [System.StringComparison]::OrdinalIgnoreCase) -or
                $ht.StartsWith($f + '/', [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
            # Settings-dir gate (campaign #3, F2 residual): KitRoot="~/.claude" -- the
            # directory that CONTAINS the user settings and the user hooks -- was still
            # accepted: every hook under it (user wiring included) would look 'ours',
            # so uninstall would REMOVE USER HOOKS.
            $sd = ''
            try { $sd = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($h, '.claude')) } catch { $sd = '' }
            if ($sd) {
                $sdt = $sd.TrimEnd('\', '/')
                if ($f -eq $sdt) { return $false }
                if ($sdt.StartsWith($f + '\', [System.StringComparison]::OrdinalIgnoreCase) -or
                    $sdt.StartsWith($f + '/', [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
            }
        }
    }
    return $true
}

function Test-UnderRoot {
    <# True when $Path is inside (or equal to) $Root WITH a path boundary. A bare
       string prefix is NOT enough: "C:\home\.claude-backup\x.ps1" starts with
       "C:\home\.claude" but is a FOREIGN path (campaign #3, class F2). #>
    [CmdletBinding()]
    param([string]$Path, [string]$Root)
    $r = [string]$Root
    if (-not $Path -or -not $r) { return $false }
    $r = $r.TrimEnd('\', '/')
    if (-not $r) { return $false }
    if (-not $Path.StartsWith($r, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    if ($Path.Length -eq $r.Length) { return $true }
    $c = $Path[$r.Length]
    return ($c -eq '\' -or $c -eq '/')
}

function Test-OurHook {
    <# $true if any arg of this hook is a path starting with KitRoot. #>
    [CmdletBinding()]
    param($Hook, [Parameter(Mandatory)][string]$Root)
    if ($null -eq $Hook) { return $false }
    $ap = $Hook.PSObject.Properties['args']
    if (-not $ap) { return $false }
    foreach ($a in @($ap.Value)) {
        $s = [string]$a
        if (Test-UnderRoot -Path $s -Root $Root) { return $true }
    }
    return $false
}

function Get-DenyFragmentPath {
    <# Kit's deny fragment: the installed copy first, the repo payload as fallback. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root)
    $c1 = [System.IO.Path]::Combine($Root, 'templates', 'settings-deny-fragment.json')
    if (Test-Path -LiteralPath $c1 -PathType Leaf) { return $c1 }
    $c2 = [System.IO.Path]::Combine($PSScriptRoot, 'core', 'templates', 'settings-deny-fragment.json')
    if (Test-Path -LiteralPath $c2 -PathType Leaf) { return $c2 }
    return ''
}

# ---------------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------------

$apply = $Apply.IsPresent -and -not $DryRun.IsPresent
if ($Apply.IsPresent -and $DryRun.IsPresent) {
    Write-Host 'NOTE: both -Apply and -DryRun were given: -DryRun wins, nothing will be written.'
}

$homeDir = Get-HomeDir
if (-not $KitRoot) {
    if (-not $homeDir) {
        Write-Host 'ERROR (prerequisite): cannot resolve the home directory ($env:HOME / $env:USERPROFILE are both empty).'
        Write-Host '  Pass -KitRoot explicitly.'
        exit $ExitPrereq
    }
    $KitRoot = [System.IO.Path]::Combine($homeDir, '.claude', 'longctx')
}
try { $KitRoot = [System.IO.Path]::GetFullPath($KitRoot) } catch { }

# KitRoot is the ownership PREFIX for the hook entries: an unsafe value (drive
# root, "/", the home directory itself OR AN ANCESTOR of the home dir) would make
# every absolute user hook look like ours and DELETE user wiring. Refused up front,
# like install.ps1 does (campaign #3, class F2: ancestors were not refused before).
if (-not (Test-SafeKitRoot -Path $KitRoot)) {
    Write-Host ('ERROR (prerequisite): refusing unsafe -KitRoot: ' + $KitRoot)
    Write-Host '  A drive root, "/" or the home directory itself are never valid kit roots.'
    exit $ExitPrereq
}

$settingsPath = ''
if ($homeDir) { $settingsPath = [System.IO.Path]::Combine($homeDir, '.claude', 'settings.json') }
$mergeLib = [System.IO.Path]::Combine($PSScriptRoot, 'core', 'lib', 'merge-claude-settings.ps1')

$denyRules = @()
$denyFragmentPath = ''
if ($RemoveDenyRules) {
    $denyFragmentPath = Get-DenyFragmentPath -Root $KitRoot
    if (-not $denyFragmentPath) {
        Write-Host 'ERROR (prerequisite): -RemoveDenyRules given but the deny fragment was not found'
        Write-Host ('  (looked in ' + [System.IO.Path]::Combine($KitRoot, 'templates') + ' and ' + [System.IO.Path]::Combine($PSScriptRoot, 'core', 'templates') + ').')
        exit $ExitPrereq
    }
    try {
        $frag = ([System.IO.File]::ReadAllText($denyFragmentPath, [System.Text.Encoding]::UTF8)) | ConvertFrom-Json -ErrorAction Stop
        $fp = $frag.PSObject.Properties['permissions']
        if ($fp -and $fp.Value) {
            $dp = $fp.Value.PSObject.Properties['deny']
            if ($dp -and $dp.Value) { $denyRules = @($dp.Value) }
        }
    } catch {
        Write-Host ('ERROR (prerequisite): deny fragment unreadable: ' + $denyFragmentPath)
        exit $ExitPrereq
    }
    if ($denyRules.Count -eq 0) {
        Write-Host ('ERROR (prerequisite): deny fragment contains no rules: ' + $denyFragmentPath)
        exit $ExitPrereq
    }
}

# ---------------------------------------------------------------------------
# Read the settings (read-only). Unreadable JSON = hard error, never overwrite.
# ---------------------------------------------------------------------------

$obj = $null
$settingsExist = $false
if ($settingsPath -and (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
    $settingsExist = $true
    $raw = ''
    try { $raw = [System.IO.File]::ReadAllText($settingsPath, (New-Object System.Text.UTF8Encoding($false, $true))) }
    catch {
        Write-Host ('ERROR: cannot read the settings file: ' + $settingsPath)
        Write-Host ('  ' + $_.Exception.Message)
        exit $ExitError
    }
    if ($raw.Trim().Length -gt 0) {
        try { $obj = $raw | ConvertFrom-Json -ErrorAction Stop }
        catch {
            Write-Host ('ERROR: settings.json is not valid JSON - NOTHING was changed: ' + $settingsPath)
            Write-Host ('  ' + $_.Exception.Message)
            exit $ExitError
        }
    }
}

# ---------------------------------------------------------------------------
# Plan: remove kit hook entries
# ---------------------------------------------------------------------------

$removedEntries = 0
$removedHooks = 0
$removedEvents = @()
$perEvent = [ordered]@{}

if ($null -ne $obj) {
    $hp = $obj.PSObject.Properties['hooks']
    if ($hp -and $hp.Value) {
        $hooks = $hp.Value
        # StrictMode-safe: enumerate through the property objects; a direct
        # @($hooks.PSObject.Properties.Name) throws when "hooks" is present but
        # EMPTY ({}), which is exactly the state left after a full uninstall.
        foreach ($evt in @($hooks.PSObject.Properties | ForEach-Object { $_.Name })) {
            $cur = @($hooks.$evt)
            $keepEvents = @()
            $goneEntries = 0
            $goneHooks = 0
            foreach ($e in $cur) {
                if ($null -eq $e) { continue }
                $ep = $e.PSObject.Properties['hooks']
                if (-not $ep -or -not $ep.Value) { $keepEvents += $e; continue }
                $keepHooks = @()
                foreach ($h in @($ep.Value)) {
                    if (Test-OurHook -Hook $h -Root $KitRoot) { $goneHooks++ } else { $keepHooks += $h }
                }
                if ($keepHooks.Count -eq 0) {
                    $goneEntries++      # entry entirely ours: drop it
                } else {
                    if ($goneHooks -gt 0) { $e.hooks = $keepHooks }   # mixed entry: keep the user hooks
                    $keepEvents += $e
                }
            }
            if ($goneEntries -gt 0 -or $goneHooks -gt 0) {
                $perEvent[$evt] = @{ Entries = $goneEntries; Hooks = $goneHooks }
                $removedEntries += $goneEntries
                $removedHooks += $goneHooks
                if ($keepEvents.Count -eq 0) {
                    [void]($hooks.PSObject.Properties.Remove($evt))
                    $removedEvents += $evt
                } else {
                    $hooks.$evt = $keepEvents
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Plan: remove kit deny rules (only with -RemoveDenyRules)
# ---------------------------------------------------------------------------

$denyRemoved = 0
$denyKept = 0
if ($RemoveDenyRules -and $null -ne $obj) {
    $pp = $obj.PSObject.Properties['permissions']
    if ($pp -and $pp.Value) {
        $perm = $pp.Value
        $dp = $perm.PSObject.Properties['deny']
        if ($dp -and $dp.Value) {
            $cur = @($dp.Value)
            $keep = @($cur | Where-Object { $denyRules -notcontains [string]$_ })
            $denyRemoved = $cur.Count - $keep.Count
            $denyKept = $keep.Count
            if ($denyRemoved -gt 0) { $perm.deny = $keep }
        }
    }
}

$settingsChanged = ($removedEntries -gt 0) -or ($removedHooks -gt 0) -or ($denyRemoved -gt 0)

# ---------------------------------------------------------------------------
# Plan: KitRoot tree removal (explicit -RemoveFiles)
# ---------------------------------------------------------------------------

$kitExists = Test-Path -LiteralPath $KitRoot -PathType Container
$kitFiles = @()
$kitBytes = 0
if ($RemoveFiles -and $kitExists) {
    $kitFiles = @(Get-ChildItem -LiteralPath $KitRoot -Recurse -File -Force -ErrorAction SilentlyContinue)
    foreach ($f in $kitFiles) { $kitBytes += [int64]$f.Length }
}

# ---------------------------------------------------------------------------
# Report the plan
# ---------------------------------------------------------------------------

$mode = 'DRY RUN (nothing will be written)'
if ($apply) { $mode = 'APPLY' }
Write-Host ('longctx uninstall - ' + $mode)
Write-Host ('home               : ' + $(if ($homeDir) { $homeDir } else { '(unresolved)' }))
Write-Host ('kit root           : ' + $KitRoot)
Write-Host ('settings file      : ' + $(if ($settingsPath) { $settingsPath } else { '(unresolved)' }))
if ($RemoveDenyRules) { Write-Host ('deny rules         : REMOVE the kit rules (' + $denyRules.Count + ' in the fragment, from ' + $denyFragmentPath + ')') }
else { Write-Host 'deny rules         : keep (default: kit deny rules are left in place)' }
if ($RemoveFiles) { Write-Host 'files              : REMOVE the KitRoot tree (explicit -RemoveFiles)' }
else { Write-Host 'files              : keep (default: the KitRoot tree is left in place)' }
Write-Host ''

Write-Host '[1/2] settings: remove kit hook entries'
if (-not $settingsExist) {
    Write-Host '      no settings file: nothing to remove'
} elseif (-not $settingsChanged) {
    Write-Host '      no kit hook entries (and no kit deny rules) found: settings unchanged'
} else {
    foreach ($k in $perEvent.Keys) {
        $v = $perEvent[$k]
        Write-Host ('      ' + $k + ': ' + $v.Entries + ' entry removed (' + $v.Hooks + ' hooks)')
    }
    if ($denyRemoved -gt 0) { Write-Host ('      permissions.deny: ' + $denyRemoved + ' kit rules removed (' + $denyKept + ' left)') }
    if ($removedEvents.Count -gt 0) { Write-Host ('      empty event keys removed: ' + ($removedEvents -join ', ')) }
    Write-Host ('      total: ' + $removedEntries + ' entries, ' + $removedHooks + ' hooks removed')
}
Write-Host ''

Write-Host '[2/2] files: KitRoot tree'
if (-not $RemoveFiles) {
    Write-Host ('      left in place (default): ' + $KitRoot)
} elseif (-not $kitExists) {
    Write-Host ('      not present: ' + $KitRoot)
} else {
    Write-Host ('      removal plan: ' + $kitFiles.Count + ' files, ' + [Math]::Round(($kitBytes / 1MB), 2) + ' MB')
    $shown = 0
    foreach ($f in $kitFiles) {
        if ($shown -ge 40) { Write-Host ('      ... and ' + ($kitFiles.Count - 40) + ' more'); break }
        Write-Host ('      - ' + $f.FullName)
        $shown++
    }
    if ($apply) {
        $markers = @(
            [System.IO.Path]::Combine($KitRoot, 'bin', 'longctx.ps1'),
            [System.IO.Path]::Combine($KitRoot, '.claude', 'hooks', 'Invoke-SessionStart.ps1'),
            [System.IO.Path]::Combine($KitRoot, 'templates', 'settings-deny-fragment.json')
        )
        $looksLikeKit = $false
        foreach ($m in $markers) { if (Test-Path -LiteralPath $m -PathType Leaf) { $looksLikeKit = $true; break } }
        if (-not (Test-SafeKitRoot -Path $KitRoot)) {
            Write-Host ('      REFUSED: unsafe -KitRoot target: ' + $KitRoot)
            exit $ExitError
        }
        if (-not $looksLikeKit) {
            Write-Host '      REFUSED: this directory does not look like a longctx install'
            Write-Host '      (none of bin/longctx.ps1, .claude/hooks/Invoke-SessionStart.ps1, templates/settings-deny-fragment.json is present).'
            Write-Host '      Nothing was deleted: inspect the path or remove it manually.'
            exit $ExitError
        }
    }
}
Write-Host ''

# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

$backup = $null
$settingsWritten = $false
if ($apply -and $settingsChanged) {
    if (-not (Test-Path -LiteralPath $mergeLib -PathType Leaf)) {
        Write-Host ('ERROR (prerequisite): merge library not found: ' + $mergeLib)
        Write-Host '  Cannot write the settings safely: nothing was changed.'
        exit $ExitPrereq
    }
    # Configure the library at dot-source time so its KitRoot closure is ours.
    . $mergeLib -KitRoot $KitRoot
    $backup = Save-ClaudeSettings -Path $settingsPath -Root $obj
    $settingsWritten = $true
}

$filesDeleted = 0
if ($apply -and $RemoveFiles -and $kitExists) {
    # Recursive removal through .NET (this script never uses Remove-Item). Reached
    # only with the explicit -RemoveFiles -Apply combination and after the checks
    # printed above (safe target + kit markers present + list already shown).
    $filesDeleted = $kitFiles.Count
    [System.IO.Directory]::Delete($KitRoot, $true)
}

Write-Host 'summary'
Write-Host ('      settings changed: ' + $(if ($settingsChanged) { 'yes' } else { 'no' }))
if ($settingsChanged) {
    Write-Host ('      entries removed : ' + $removedEntries + ' entries, ' + $removedHooks + ' hooks')
    if ($RemoveDenyRules) { Write-Host ('      deny removed    : ' + $denyRemoved) }
    if ($settingsWritten) {
        if ($backup) { Write-Host ('      backup          : ' + $backup) }
        else { Write-Host '      backup          : (none)' }
        Write-Host ('      settings written: ' + $settingsPath)
    } else {
        Write-Host '      settings written: no (dry run)'
    }
} else {
    Write-Host '      settings written: no (nothing to change: no write, no backup)'
}
if ($RemoveFiles) {
    if ($apply) { Write-Host ('      files deleted   : ' + $filesDeleted) }
    else { Write-Host ('      files to delete : ' + $kitFiles.Count + ' (dry run: nothing deleted)') }
} else {
    Write-Host '      files deleted   : 0 (left in place; use -RemoveFiles to delete the tree)'
}
Write-Host ''
if (-not $apply) { Write-Host 'Nothing was written (dry run). Re-run with -Apply to execute the plan.' }
exit $ExitOk
