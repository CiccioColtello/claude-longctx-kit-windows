#requires -Version 5.1
<#
.SYNOPSIS
    longctx -- kit entry-point CLI (init / status).
.DESCRIPTION
    Invoke it, do not dot-source it (it uses 'exit').

      init   : prepares the CURRENT project (.agent/ from the templates + the kit
               .gitignore fragment). Idempotent: existing .agent files are NOT
               overwritten unless -Force is given.
      status : read-only snapshot: .agent presence in the project, kit installation
               (KitRoot), user settings wiring, the project exactly-once guard (the
               project .claude/settings.json registers Invoke-SessionStart.ps1 ->
               the user-level hook stays silent) and the STATE "Updated" /
               "Last compaction" stamps.

    Portable: Windows PowerShell 5.1 and pwsh 7 (Windows/macOS). No Windows-only
    cmdlet; the home directory resolves from $env:HOME then $env:USERPROFILE; paths
    are joined with [System.IO.Path]::Combine.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<KitRoot>\bin\longctx.ps1" init
.EXAMPLE
    pwsh -NoProfile -File "<KitRoot>/bin/longctx.ps1" status -ProjectDir /path/to/project
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Command = '',
    [string]$ProjectDir = '',
    [string]$KitRoot = '',
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AgentFiles = @('STATE.md', 'DECISIONS.md', 'FAILURES.md', 'CONTEXT.md')
$script:KeyFiles = @(
    '.claude/hooks/Invoke-SessionStart.ps1',
    '.claude/hooks/Invoke-PreCompact.ps1',
    '.claude/hooks/Invoke-PostCompact.ps1',
    '.claude/hooks/Invoke-PostToolUseFailure.ps1',
    '.claude/hooks/Block-Destructive.ps1',
    '.claude/hooks/Hook-Common.ps1',
    'lib/merge-claude-settings.ps1',
    'templates/agent/STATE.md',
    'templates/settings-deny-fragment.json',
    'bin/longctx.ps1',
    'tests/smoke.ps1',
    'tests/probe-hardening.ps1'
)
$script:Events = @('SessionStart', 'PostToolUseFailure', 'PreCompact', 'PostCompact')

# ---------------------------------------------------------------------------
# Base helpers (portable, zero dependencies)
# ---------------------------------------------------------------------------

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

function Get-DefaultKitRoot {
    <# Default KitRoot: <home>/.claude/longctx. #>
    [CmdletBinding()]
    param()
    $home_ = Get-HomeDir
    if (-not $home_) { return '' }
    return [System.IO.Path]::Combine($home_, '.claude', 'longctx')
}

function Get-TemplatesDir {
    <# templates/ next to the kit: 'core/templates' in the repo, '<KitRoot>/templates' installed. #>
    [CmdletBinding()]
    param()
    $p = [System.IO.Path]::Combine($PSScriptRoot, '..', 'templates')
    try { $p = [System.IO.Path]::GetFullPath($p) } catch { }
    return $p
}

function Get-ProjectDirOrDefault {
    [CmdletBinding()]
    param([string]$Requested)
    if ($Requested) {
        return [System.IO.Path]::GetFullPath($Requested)
    }
    return [System.IO.Path]::GetFullPath((Get-Location).Path)
}

function Get-SectionText {
    <# Body of the "## Title" section (StrictMode-safe: regex on text, no properties). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Title
    )
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $m = [regex]::Match($Text, '(?ms)^## ' + [regex]::Escape($Title) + '[ \t]*\r?\n(.*?)(?=^## |\z)')
    if (-not $m.Success) { return '' }
    return $m.Groups[1].Value.Trim()
}

function Read-TextSafe {
    <# Explicit UTF-8 read; '' when missing/unreadable (never throws). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return '' }
        return [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    } catch { return '' }
}

function Test-UnderRoot {
    <# True when $Path is inside (or equal to) $Root WITH a path boundary. A bare
       string prefix is NOT enough: "C:\home\.claude-backup\x.ps1" starts with
       "C:\home\.claude" but is a FOREIGN path (campaign #3, class F2): status
       would report the kit as wired where only a foreign entry exists. #>
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

function Test-KitEntry {
    <# $true if the entry contains a kit hook (one arg is a path under KitRoot). #>
    [CmdletBinding()]
    param($Entry, [Parameter(Mandatory)][string]$Root)
    if ($null -eq $Entry) { return $false }
    $hp = $Entry.PSObject.Properties['hooks']
    if (-not $hp) { return $false }
    foreach ($h in @($hp.Value)) {
        if ($null -eq $h) { continue }
        $ap = $h.PSObject.Properties['args']
        if (-not $ap) { continue }
        foreach ($a in @($ap.Value)) {
            $s = [string]$a
            if (Test-UnderRoot -Path $s -Root $Root) { return $true }
        }
    }
    return $false
}

# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

function Test-GitignoreFragmentPresent {
    <# $true when ALL "payload" lines of the fragment are already in .gitignore. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$GitignorePath, [Parameter(Mandatory)][AllowEmptyString()][string]$FragmentText)
    if (-not (Test-Path -LiteralPath $GitignorePath)) { return $false }
    $raw = Read-TextSafe -Path $GitignorePath
    $have = @{}
    foreach ($l in @($raw -split "`n")) {
        $t = ([string]$l).Trim()
        if ($t) { $have[$t] = $true }
    }
    $payload = @($FragmentText -split "`n" | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne '' -and -not $_.StartsWith('#') })
    if ($payload.Count -eq 0) { return $false }
    foreach ($p in $payload) { if (-not $have.ContainsKey($p)) { return $false } }
    return $true
}

function Invoke-Init {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Project, [string]$Templates, [switch]$ForceOverwrite)
    if (-not (Test-Path -LiteralPath $Project -PathType Container)) {
        Write-Host ('ERROR: project directory does not exist: ' + $Project)
        return 2
    }
    if (-not (Test-Path -LiteralPath $Templates -PathType Container)) {
        Write-Host ('ERROR: kit templates not found: ' + $Templates)
        Write-Host 'The kit looks incomplete: reinstall (install.ps1 -Apply).'
        return 2
    }

    Write-Host 'longctx init'
    Write-Host '------------'
    Write-Host ('project  : ' + $Project)

    $agentDir = [System.IO.Path]::Combine($Project, '.agent')
    if (-not (Test-Path -LiteralPath $agentDir)) {
        [void](New-Item -ItemType Directory -Force -Path $agentDir)
        Write-Host ('.agent   : created (' + $agentDir + ')')
    } else {
        Write-Host ('.agent   : already present (' + $agentDir + ')')
    }
    foreach ($f in $script:AgentFiles) {
        $src = [System.IO.Path]::Combine($Templates, 'agent', $f)
        $dst = [System.IO.Path]::Combine($agentDir, $f)
        if (Test-Path -LiteralPath $dst) {
            if ($ForceOverwrite) {
                Copy-Item -LiteralPath $src -Destination $dst -Force
                Write-Host ('  ~ ' + $f + ' (overwritten with -Force)')
            } else {
                Write-Host ('  = ' + $f + ' (already exists: kept)')
            }
        } else {
            Copy-Item -LiteralPath $src -Destination $dst
            Write-Host ('  + ' + $f + ' (created from template)')
        }
    }

    # .gitignore: kit fragment (not duplicated when the payload lines are already there)
    $fragPath = [System.IO.Path]::Combine($Templates, 'gitignore-fragment.txt')
    $frag = Read-TextSafe -Path $fragPath
    if (-not $frag) {
        Write-Host ('.gitignore: fragment not found (' + $fragPath + '): skipped')
    } else {
        $giPath = [System.IO.Path]::Combine($Project, '.gitignore')
        if (Test-GitignoreFragmentPresent -GitignorePath $giPath -FragmentText $frag) {
            Write-Host '.gitignore: fragment already present: no change'
        } else {
            $enc = New-Object System.Text.UTF8Encoding($false)
            $block = $frag.TrimEnd() + "`n"
            if (Test-Path -LiteralPath $giPath) {
                $cur = Read-TextSafe -Path $giPath
                $sep = "`n"
                if ($cur.Length -eq 0 -or $cur.EndsWith("`n")) { $sep = '' }
                [System.IO.File]::AppendAllText($giPath, $sep + $block, $enc)
                Write-Host '.gitignore: fragment appended'
            } else {
                [System.IO.File]::WriteAllText($giPath, $block, $enc)
                Write-Host '.gitignore: created with the kit fragment'
            }
        }
    }

    Write-Host ''
    Write-Host 'next steps:'
    Write-Host '  1. restart Claude Code in this project: the SessionStart hook injects .agent/ at every session.'
    Write-Host '  2. open .agent/STATE.md and fill in "Next action": it is the starting point of every session.'
    Write-Host '  3. check the registered hooks with /hooks.'
    Write-Host '  4. (optional) local digest: .agent/ollama.env (OLLAMA_HOST, OLLAMA_DIGEST_MODEL).'
    Write-Host '     The local model is best-effort and is NOT a security authority.'
    Write-Host '  5. (optional) PROJECT-level wiring: see templates/project-settings.example.*.json in the kit.'
    return 0
}

# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

function Get-KitInstallInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root)
    $present = 0
    $missing = @()
    foreach ($rel in $script:KeyFiles) {
        $p = [System.IO.Path]::Combine($Root, ($rel -replace '/', [string][System.IO.Path]::DirectorySeparatorChar))
        if (Test-Path -LiteralPath $p -PathType Leaf) { $present++ } else { $missing += $rel }
    }
    return @{ Present = $present; Total = $script:KeyFiles.Count; Missing = $missing }
}

function Get-SettingsInfo {
    <# Read-only: JSON validity + kit wiring + PreToolUse sensor. Never throws. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Root)
    $info = @{ Exists = $false; Valid = $false; Error = ''; Events = @{}; Sensor = $false }
    foreach ($e in $script:Events) { $info.Events[$e] = $false }
    if (-not (Test-Path -LiteralPath $Path)) { return $info }
    $info.Exists = $true
    $raw = ''
    try { $raw = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8) }
    catch { $info.Error = $_.Exception.Message; return $info }
    $obj = $null
    try { $obj = $raw | ConvertFrom-Json -ErrorAction Stop }
    catch { $info.Error = $_.Exception.Message; return $info }
    if ($null -eq $obj) { return $info }
    $info.Valid = $true
    $hp = $obj.PSObject.Properties['hooks']
    if (-not $hp -or $null -eq $hp.Value) { return $info }
    $hooks = $hp.Value
    foreach ($e in @($script:Events + 'PreToolUse')) {
        $ep = $hooks.PSObject.Properties[$e]
        if (-not $ep) { continue }
        $found = $false
        foreach ($entry in @($ep.Value)) {
            if (Test-KitEntry -Entry $entry -Root $Root) { $found = $true; break }
        }
        if ($e -eq 'PreToolUse') { $info.Sensor = $found } else { $info.Events[$e] = $found }
    }
    return $info
}

function Invoke-Status {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Project, [Parameter(Mandatory)][string]$Root)
    Write-Host 'longctx status'
    Write-Host '--------------'
    Write-Host ('project       : ' + $Project)

    $agentDir = [System.IO.Path]::Combine($Project, '.agent')
    $stateText = ''
    if (Test-Path -LiteralPath $agentDir -PathType Container) {
        $have = @()
        foreach ($f in $script:AgentFiles) {
            if (Test-Path -LiteralPath ([System.IO.Path]::Combine($agentDir, $f)) -PathType Leaf) { $have += $f }
        }
        if ($have.Count -eq $script:AgentFiles.Count) {
            Write-Host ('.agent        : present (' + ($have -join ', ') + ')')
        } else {
            Write-Host ('.agent        : present but incomplete (' + $have.Count + '/' + $script:AgentFiles.Count + '): ' + ($have -join ', '))
            Write-Host '                -> run: longctx init (existing files are kept)'
        }
        $stateText = Read-TextSafe -Path ([System.IO.Path]::Combine($agentDir, 'STATE.md'))
    } else {
        Write-Host '.agent        : MISSING'
        Write-Host '                -> run: longctx init'
    }

    # STATE.md stamps (when present)
    if ($stateText) {
        $upd = (Get-SectionText -Text $stateText -Title 'Updated') -split "`n" | Select-Object -First 1
        $lc = (Get-SectionText -Text $stateText -Title 'Last compaction') -split "`n" | Select-Object -First 1
        $upd = ([string]$upd).Trim()
        $lc = ([string]$lc).Trim()
        if ($upd -or $lc) {
            if (-not $upd) { $upd = '(not present)' }
            if (-not $lc) { $lc = '(not present)' }
            Write-Host ('stamps        : Updated: ' + $upd)
            Write-Host ('                Last compaction: ' + $lc)
        }
    }

    # Kit installation
    $kit = Get-KitInstallInfo -Root $Root
    if ($kit.Present -eq $kit.Total) {
        Write-Host ('kit install   : ' + $Root + ' -> OK (' + $kit.Present + '/' + $kit.Total + ' key files)')
    } elseif ($kit.Present -gt 0) {
        Write-Host ('kit install   : ' + $Root + ' -> INCOMPLETE (' + $kit.Present + '/' + $kit.Total + ' key files)')
        Write-Host ('                missing: ' + (@($kit.Missing | Select-Object -First 6) -join ', '))
    } else {
        Write-Host ('kit install   : ' + $Root + ' -> NOT INSTALLED')
        Write-Host '                -> install: install.ps1 -Apply'
    }

    # User settings wiring
    $home_ = Get-HomeDir
    $settingsPath = ''
    if ($home_) { $settingsPath = [System.IO.Path]::Combine($home_, '.claude', 'settings.json') }
    if (-not $settingsPath) {
        Write-Host 'user settings : home not resolvable ($env:HOME / $env:USERPROFILE are both empty)'
    } elseif (-not (Test-Path -LiteralPath $settingsPath)) {
        Write-Host ('user settings : ' + $settingsPath + ' -> MISSING (no wiring)')
    } else {
        $info = Get-SettingsInfo -Path $settingsPath -Root $Root
        if (-not $info.Valid) {
            Write-Host ('user settings : ' + $settingsPath + ' -> UNREADABLE (invalid JSON)')
            Write-Host ('                detail: ' + $info.Error)
        } else {
            $parts = @()
            $wired = 0
            foreach ($e in $script:Events) {
                $yes = [bool]$info.Events[$e]
                if ($yes) { $wired++ }
                $label = 'no'
                if ($yes) { $label = 'yes' }
                $parts += ($e + '=' + $label)
            }
            $sens = 'no'
            if ($info.Sensor) { $sens = 'yes' }
            $parts += ('PreToolUse(sensor)=' + $sens)
            Write-Host ('user settings : ' + $settingsPath + ' -> valid; wired events: ' + $wired + '/' + $script:Events.Count)
            Write-Host ('                ' + ($parts -join '  '))
            if ($wired -eq 0) { Write-Host '                -> no kit hooks: run install.ps1 -Apply' }
        }
    }

    # Project exactly-once guard
    $projSettings = [System.IO.Path]::Combine($Project, '.claude', 'settings.json')
    $projLocalHook = [System.IO.Path]::Combine($Project, '.claude', 'hooks', 'Invoke-SessionStart.ps1')
    if (Test-Path -LiteralPath $projSettings -PathType Leaf) {
        $raw = Read-TextSafe -Path $projSettings
        $mentions = ($raw.IndexOf('Invoke-SessionStart.ps1', [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        $localCopy = Test-Path -LiteralPath $projLocalHook -PathType Leaf
        Write-Host ('project guard : ' + $projSettings)
        if ($mentions -and $localCopy) {
            Write-Host '                registers Invoke-SessionStart.ps1 and holds a local copy:'
            Write-Host '                the OUT-OF-PROJECT (user-level) SessionStart hook stays SILENT here'
            Write-Host '                (exactly-once guard); the in-project copy is the injector.'
        } elseif ($mentions) {
            Write-Host '                registers Invoke-SessionStart.ps1 but has NO local copy at'
            Write-Host ('                ' + $projLocalHook)
            Write-Host '                -> fail-open: the user-level hook injects the context normally.'
        } else {
            Write-Host '                no kit SessionStart wiring -> the user-level hook injects normally.'
        }
    } else {
        Write-Host ('project guard : ' + $projSettings + ' missing')
        Write-Host '                -> the user-level hook injects the context normally.'
    }
    return 0
}

# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------

try {
    $cmd = ''
    if ($Command) { $cmd = $Command.Trim().ToLowerInvariant() }

    if ($cmd -eq '' -or $cmd -eq 'help' -or $cmd -eq '-h' -or $cmd -eq '--help') {
        Write-Host 'usage: longctx.ps1 <init|status> [-ProjectDir <path>] [-KitRoot <path>] [-Force]'
        Write-Host ''
        Write-Host '  init    prepares .agent/ in the project + the .gitignore fragment (idempotent)'
        Write-Host '  status  project state, kit installation and settings wiring (read-only)'
        if (-not $cmd) { exit 2 }
        exit 0
    }

    $proj = Get-ProjectDirOrDefault -Requested $ProjectDir
    if (-not (Test-Path -LiteralPath $proj -PathType Container)) {
        Write-Host ('ERROR: project directory does not exist: ' + $proj)
        exit 2
    }

    if ($cmd -eq 'init') {
        exit (Invoke-Init -Project $proj -Templates (Get-TemplatesDir) -ForceOverwrite:$Force)
    }
    if ($cmd -eq 'status') {
        $root = $KitRoot
        if (-not $root) {
            $mine = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, '..'))
            if (Test-Path -LiteralPath ([System.IO.Path]::Combine($mine, '.claude', 'hooks', 'Invoke-SessionStart.ps1'))) {
                $root = $mine   # running from the kit tree (repo or installed)
            } else {
                $root = Get-DefaultKitRoot
            }
        }
        if (-not $root) {
            Write-Host 'ERROR: KitRoot not resolvable (use -KitRoot).'
            exit 2
        }
        exit (Invoke-Status -Project $proj -Root ([System.IO.Path]::GetFullPath($root)))
    }

    Write-Host ('ERROR: unknown command: ' + $Command)
    Write-Host 'usage: longctx.ps1 <init|status> [-ProjectDir <path>] [-KitRoot <path>] [-Force]'
    exit 2
} catch {
    Write-Host ('ERROR: ' + $_.Exception.Message)
    exit 1
}
