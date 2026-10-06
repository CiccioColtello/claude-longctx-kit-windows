#requires -Version 5.1
<#
.SYNOPSIS
    longctx installer: copy the kit into KitRoot and wire the user-level Claude Code settings.
.DESCRIPTION
    Steps:
      (1) plan/print every action
      (2) copy <repo>\core\* into KitRoot (dirs created; identical files are skipped)
      (3) merge the kit hook entries + permissions.deny rules into
          <home>/.claude/settings.json via core/lib/merge-claude-settings.ps1
          (add-only; the settings file is written ONLY when something changed)
      (4) print a summary (files copied, hook entries added, deny rules added, backup
          path) and the next steps

    DRY RUN IS THE DEFAULT: without -Apply nothing is written. -DryRun is accepted
    explicitly (and wins if both switches are given).

    Never modifies anything else in ~/.claude. An unreadable settings.json is a hard
    error: the file is never overwritten.

    Run it, do not dot-source it (it uses exit).

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1            # dry run
.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1 -Apply
.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1 -Apply -WithSensor
#>

[CmdletBinding()]
param(
    [string]$KitRoot = '',
    [switch]$DryRun,
    [switch]$Apply,
    [switch]$WithSensor,
    [ValidateSet('windows', 'mac')][string]$Os = '',
    [switch]$SkipSettings
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
    <# Refuses obviously dangerous targets (drive root, '/', '.', the home dir itself). #>
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
            # swallow other users' trees.
            if ($ht.StartsWith($f + '\', [System.StringComparison]::OrdinalIgnoreCase) -or
                $ht.StartsWith($f + '/', [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
            # Settings-dir gate (campaign #3, F2 residual): KitRoot="~/.claude" -- the
            # directory that CONTAINS the user settings and the user hooks -- was still
            # accepted: every hook under it (user wiring included) would look 'ours'.
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

function Get-FileHashSafe {
    <# SHA-256 hex; '' when unreadable. .NET only: works also where Get-FileHash is unavailable. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $fs = [System.IO.File]::OpenRead($Path)
            try {
                return ([System.BitConverter]::ToString($sha.ComputeHash($fs)) -replace '-', '')
            } finally { $fs.Dispose() }
        } finally { $sha.Dispose() }
    } catch { return '' }
}

function Get-CoreFiles {
    <# All files under <repo>\core, as @{ Rel; Src; Dst; Identical }. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$CoreDir, [Parameter(Mandatory)][string]$Root)
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($f in @(Get-ChildItem -LiteralPath $CoreDir -Recurse -File -Force)) {
        $rel = $f.FullName.Substring($CoreDir.Length).TrimStart('\', '/')
        $dst = [System.IO.Path]::Combine($Root, $rel)
        $identical = $false
        if (Test-Path -LiteralPath $dst -PathType Leaf) {
            $a = Get-FileHashSafe -Path $f.FullName
            $b = Get-FileHashSafe -Path $dst
            if ($a -and $b -and ($a -eq $b)) { $identical = $true }
        }
        $list.Add([pscustomobject]@{ Rel = $rel; Src = $f.FullName; Dst = $dst; Identical = $identical })
    }
    return $list
}

# ---------------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------------

$apply = $Apply.IsPresent -and -not $DryRun.IsPresent
if ($Apply.IsPresent -and $DryRun.IsPresent) {
    Write-Host 'NOTE: both -Apply and -DryRun were given: -DryRun wins, nothing will be written.'
}

if (-not $Os) {
    $Os = 'mac'
    if ($env:OS -eq 'Windows_NT') { $Os = 'windows' }
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

$coreDir = [System.IO.Path]::Combine($PSScriptRoot, 'core')
try { $coreDir = [System.IO.Path]::GetFullPath($coreDir) } catch { }
$mergeLib = [System.IO.Path]::Combine($coreDir, 'lib', 'merge-claude-settings.ps1')
$denyFragment = [System.IO.Path]::Combine($coreDir, 'templates', 'settings-deny-fragment.json')

$settingsPath = ''
if ($homeDir) { $settingsPath = [System.IO.Path]::Combine($homeDir, '.claude', 'settings.json') }

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $coreDir -PathType Container)) {
    Write-Host ('ERROR (prerequisite): kit payload not found: ' + $coreDir)
    Write-Host '  install.ps1 must sit next to the "core" directory of the kit repository.'
    exit $ExitPrereq
}
if (-not (Test-SafeKitRoot -Path $KitRoot)) {
    Write-Host ('ERROR (prerequisite): refusing unsafe -KitRoot: ' + $KitRoot)
    exit $ExitPrereq
}
if (-not $SkipSettings) {
    if (-not $mergeLib -or -not (Test-Path -LiteralPath $mergeLib -PathType Leaf)) {
        Write-Host ('ERROR (prerequisite): merge library not found: ' + $mergeLib)
        exit $ExitPrereq
    }
    if (-not $settingsPath) {
        Write-Host 'ERROR (prerequisite): cannot resolve the user settings path (home not resolvable).'
        Write-Host '  Use -SkipSettings to install the files only.'
        exit $ExitPrereq
    }
    if (-not (Test-Path -LiteralPath $denyFragment -PathType Leaf)) {
        Write-Host ('ERROR (prerequisite): deny fragment not found: ' + $denyFragment)
        exit $ExitPrereq
    }
}

# ---------------------------------------------------------------------------
# Plan: files
# ---------------------------------------------------------------------------

$coreFiles = Get-CoreFiles -CoreDir $coreDir -Root $KitRoot
$nNew = 0; $nReplace = 0; $nIdentical = 0
foreach ($f in $coreFiles) {
    if ($f.Identical) { $nIdentical++ }
    elseif (Test-Path -LiteralPath $f.Dst -PathType Leaf) { $nReplace++ }
    else { $nNew++ }
}
$nCopied = $nNew + $nReplace

# ---------------------------------------------------------------------------
# Plan: settings (in-memory; nothing is written here). Done BEFORE any write so
# an unreadable settings.json aborts the whole run with zero side effects.
# ---------------------------------------------------------------------------

$merge = $null
$mergeError = ''
if (-not $SkipSettings) {
    try {
        # The merge library takes its configuration (KitRoot/Os/DenyFragment/sensor) at
        # dot-source time; Merge-ClaudeSettings itself only takes -Path. Its KitRoot
        # closure is therefore bound to OUR install target before any merge runs.
        . $mergeLib -KitRoot $KitRoot -Os $Os -DenyFragment $denyFragment -WithSensor:$WithSensor.IsPresent
        $merge = Merge-ClaudeSettings -Path $settingsPath
    } catch {
        $mergeError = $_.Exception.Message
    }
}

if ($mergeError) {
    Write-Host ''
    Write-Host 'ERROR: settings merge refused - NOTHING was written (no files copied, no settings touched).'
    Write-Host ('  ' + $mergeError)
    exit $ExitError
}

# ---------------------------------------------------------------------------
# Report the plan
# ---------------------------------------------------------------------------

$mode = 'DRY RUN (nothing will be written)'
if ($apply) { $mode = 'APPLY' }
Write-Host ('longctx install - ' + $mode)
Write-Host ('home               : ' + $(if ($homeDir) { $homeDir } else { '(unresolved)' }))
Write-Host ('kit root           : ' + $KitRoot)
if ($SkipSettings) { Write-Host 'settings file      : (skipped: -SkipSettings)' }
else { Write-Host ('settings file      : ' + $settingsPath) }
Write-Host ('source             : ' + $coreDir)
Write-Host ('os wiring          : ' + $Os)
$sensorTxt = 'off (default)'
if ($WithSensor) { $sensorTxt = 'ON (PreToolUse deny gate)' }
Write-Host ('sensor (PreToolUse): ' + $sensorTxt)
if ($WithSensor -and $Os -eq 'mac') {
    Write-Host '  WARNING: on macOS the sensor home-root protections are Windows-only in v0.1.0'
    Write-Host '  (KNOWN-ISSUES.md #12); pattern-based rules still apply. Recommended: keep it off.'
}
Write-Host ''

Write-Host ('[1/3] files: copy core\* -> kit root (' + $coreFiles.Count + ' files)')
foreach ($f in $coreFiles) {
    $tag = 'new       '
    if ($f.Identical) { $tag = 'identical ' }
    elseif (Test-Path -LiteralPath $f.Dst -PathType Leaf) { $tag = 'replace   ' }
    Write-Host ('  ' + $tag + ' ' + ($f.Rel -replace '\\', '/'))
}
Write-Host ('      plan: ' + $nCopied + ' to write (new ' + $nNew + ', replace ' + $nReplace + '), ' + $nIdentical + ' identical')
Write-Host ''

if ($SkipSettings) {
    Write-Host '[2/3] settings: SKIPPED (-SkipSettings)'
} else {
    $evtList = 'SessionStart, PostToolUseFailure, PreCompact, PostCompact'
    if ($WithSensor) { $evtList = $evtList + ', PreToolUse (sensor)' }
    Write-Host '[2/3] settings: merge kit wiring (add-only, user entries untouched)'
    Write-Host ('      hooks to add : ' + $evtList)
    Write-Host ('      deny rules   : from ' + $denyFragment)
    Write-Host ('      merge result : ' + $merge.Result + ' (' + $merge.Added + ' hook entries, ' + $merge.DenyAdded + ' deny rules)')
}
Write-Host ''

# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

$backup = $null
$filesWritten = 0
if ($apply) {
    foreach ($f in $coreFiles) {
        if ($f.Identical) { continue }
        $dir = Split-Path -Parent $f.Dst
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            [void](New-Item -ItemType Directory -Force -Path $dir)
        }
        Copy-Item -LiteralPath $f.Src -Destination $f.Dst -Force
        $filesWritten++
    }
    if (-not $SkipSettings) {
        if ($merge.Result -ne 'unchanged') {
            $settingsDir = Split-Path -Parent $settingsPath
            if ($settingsDir -and -not (Test-Path -LiteralPath $settingsDir)) {
                # Creating ~/.claude when missing is expected and correct (documented
                # behaviour); nothing else inside it is touched.
                [void](New-Item -ItemType Directory -Force -Path $settingsDir)
            }
            $backup = Save-ClaudeSettings -Path $settingsPath -Root $merge.Root
        }
    }
}

Write-Host '[3/3] summary'
Write-Host ('      files copied    : ' + $filesWritten + ' of ' + $coreFiles.Count + ' (new ' + $nNew + ', replaced ' + $nReplace + ', identical ' + $nIdentical + ')')
if ($SkipSettings) {
    Write-Host '      settings result : skipped (-SkipSettings)'
    Write-Host '      hooks added     : 0'
    Write-Host '      deny added      : 0'
    Write-Host '      backup          : (none)'
} else {
    Write-Host ('      settings result : ' + $merge.Result)
    Write-Host ('      hooks added     : ' + $merge.Added)
    Write-Host ('      deny added      : ' + $merge.DenyAdded)
    if ($backup) { Write-Host ('      backup          : ' + $backup) }
    else { Write-Host '      backup          : (none: settings file not modified)' }
}
Write-Host ''
if (-not $apply) {
    Write-Host 'Nothing was written (dry run). Re-run with -Apply to execute the plan.'
} else {
    $exeHint = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File'
    if ($Os -eq 'mac') { $exeHint = 'pwsh -NoProfile -File' }
    Write-Host 'Next steps:'
    Write-Host ('  1. in a project: ' + $exeHint + ' "' + [System.IO.Path]::Combine($KitRoot, 'bin', 'longctx.ps1') + '" init')
    Write-Host '  2. restart Claude Code so the new hooks are picked up'
    Write-Host '  3. inspect the registered hooks with /hooks'
}
exit $ExitOk
