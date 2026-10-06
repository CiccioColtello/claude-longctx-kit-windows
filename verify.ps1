#requires -Version 5.1
<#
.SYNOPSIS
    longctx verify: read-only health check of an install.
.DESCRIPTION
    Checks (each printed as PASS/FAIL; exit 1 if any FAIL):
      1. files   : the KitRoot tree contains every expected file
      2. files   : hook files in KitRoot are byte-identical to the repo copy (hash spot-check)
      3. settings: the user settings.json is valid JSON
      4. settings: kit hook entries are present on the expected events, and the hook
                   files they point to exist
      5. settings: the kit permissions.deny rules are present
      6. probe   : only with -InvokeProbe: executes the INSTALLED SessionStart hook with
                   sample JSON stdin in a throwaway sandbox project and asserts the
                   output JSON contains [AGENT_CONTEXT]

    Reads only: nothing is written outside the probe sandbox (which is never cleaned
    up, so it can be inspected).

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File verify.ps1
.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File verify.ps1 -InvokeProbe
#>

[CmdletBinding()]
param(
    [string]$KitRoot = '',
    [switch]$InvokeProbe
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Pass = 0
$script:Fail = 0

$script:ExpectedFallback = @(
    '.claude/hooks/Block-Destructive.ps1',
    '.claude/hooks/Filter-AgentText.ps1',
    '.claude/hooks/Hook-Common.ps1',
    '.claude/hooks/Hook-Inline.ps1',
    '.claude/hooks/Invoke-LocalDigest.ps1',
    '.claude/hooks/Invoke-PostCompact.ps1',
    '.claude/hooks/Invoke-PostToolUseFailure.ps1',
    '.claude/hooks/Invoke-PreCompact.ps1',
    '.claude/hooks/Invoke-SessionStart.ps1',
    '.claude/agents/context-archivist.md',
    '.claude/agents/log-compressor.md',
    '.claude/agents/repo-explorer.md',
    '.claude/agents/security-auditor.md',
    '.claude/agents/test-diagnostician.md',
    '.claude/skills/context-maintenance/SKILL.md',
    '.claude/skills/long-context/SKILL.md',
    '.claude/skills/repo-exploration/SKILL.md',
    'lib/merge-claude-settings.ps1',
    'scripts/Filter-File.ps1',
    'scripts/Invoke-Digest.ps1',
    'templates/agent/CONTEXT.md',
    'templates/agent/DECISIONS.md',
    'templates/agent/FAILURES.md',
    'templates/agent/STATE.md',
    'templates/gitignore-fragment.txt',
    'templates/project-settings.example.mac.json',
    'templates/project-settings.example.windows.json',
    'templates/settings-deny-fragment.json',
    'bin/longctx.ps1',
    'tests/smoke.ps1',
    'tests/probe-hardening.ps1'
)

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

function Join-Rel {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)][string]$Rel)
    $r = $Rel -replace '/', [string][System.IO.Path]::DirectorySeparatorChar
    return [System.IO.Path]::Combine($Base, $r)
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

function Check {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Ok,
        [AllowEmptyString()][string]$Detail = ''
    )
    if ($Ok) { $script:Pass++; Write-Host ('PASS  ' + $Name) }
    else {
        $script:Fail++
        Write-Host ('FAIL  ' + $Name)
        if ($Detail) { Write-Host ('      detail: ' + $Detail) }
    }
}

function Info {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text)
    Write-Host ('INFO  ' + $Text)
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

function Get-OurHookFiles {
    <# Args of this entry that are paths under KitRoot (the hook file paths we wired). #>
    [CmdletBinding()]
    param($Entry, [Parameter(Mandatory)][string]$Root)
    $out = @()
    if ($null -eq $Entry) { return $out }
    $hp = $Entry.PSObject.Properties['hooks']
    if (-not $hp -or -not $hp.Value) { return $out }
    foreach ($h in @($hp.Value)) {
        if ($null -eq $h) { continue }
        $ap = $h.PSObject.Properties['args']
        if (-not $ap) { continue }
        foreach ($a in @($ap.Value)) {
            $s = [string]$a
            if (Test-UnderRoot -Path $s -Root $Root) { $out += $s }
        }
    }
    return $out
}

function Invoke-Hook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HookPath,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Stdin,
        [Parameter(Mandatory)][string]$ProjectDir,
        [Parameter(Mandatory)][string]$ErrFile
    )
    $exe = 'pwsh'
    if ($env:OS -eq 'Windows_NT') { $exe = 'powershell.exe' }
    $hArgs = @('-NoProfile', '-NonInteractive')
    if ($env:OS -eq 'Windows_NT') { $hArgs += @('-ExecutionPolicy', 'Bypass') }
    $hArgs += @('-File', $HookPath)
    $prev = $env:CLAUDE_PROJECT_DIR
    $env:CLAUDE_PROJECT_DIR = $ProjectDir
    $out = @()
    $code = -1
    try {
        $out = @($Stdin | & $exe @hArgs 2> $ErrFile)
        $code = $LASTEXITCODE
    } finally {
        if ($null -eq $prev) { [System.Environment]::SetEnvironmentVariable('CLAUDE_PROJECT_DIR', $null) }
        else { $env:CLAUDE_PROJECT_DIR = $prev }
    }
    return @{ Exit = $code; Out = ($out -join "`n") }
}

# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

$homeDir = Get-HomeDir
if (-not $KitRoot) {
    if (-not $homeDir) {
        Write-Host 'FAIL  prerequisites: cannot resolve the home directory ($env:HOME / $env:USERPROFILE are both empty)'
        Write-Host ''
        Write-Host 'verify: 0 PASS / 1 FAIL'
        exit 1
    }
    $KitRoot = [System.IO.Path]::Combine($homeDir, '.claude', 'longctx')
}
try { $KitRoot = [System.IO.Path]::GetFullPath($KitRoot) } catch { }

$settingsPath = ''
if ($homeDir) { $settingsPath = [System.IO.Path]::Combine($homeDir, '.claude', 'settings.json') }

$repoCore = [System.IO.Path]::Combine($PSScriptRoot, 'core')
try { $repoCore = [System.IO.Path]::GetFullPath($repoCore) } catch { }
$repoCoreAvailable = Test-Path -LiteralPath $repoCore -PathType Container

Write-Host 'longctx verify'
Write-Host ('  kit root      : ' + $KitRoot)
Write-Host ('  settings file : ' + $(if ($settingsPath) { $settingsPath } else { '(unresolved)' }))
if ($repoCoreAvailable) { Write-Host ('  payload ref   : ' + $repoCore + '  (source of the expected list and of the hash spot-check)') }
else { Write-Host '  payload ref   : (not available: built-in expected list, hash spot-check skipped)' }
Write-Host ''

# ---------------------------------------------------------------------------
# 1. KitRoot tree
# ---------------------------------------------------------------------------

$expected = @()
if ($repoCoreAvailable) {
    foreach ($f in @(Get-ChildItem -LiteralPath $repoCore -Recurse -File -Force)) {
        $expected += $f.FullName.Substring($repoCore.Length).TrimStart('\', '/')
    }
} else {
    $expected = $script:ExpectedFallback
}
$missing = @()
foreach ($rel in $expected) {
    if (-not (Test-Path -LiteralPath (Join-Rel -Base $KitRoot -Rel $rel) -PathType Leaf)) { $missing += $rel }
}
Check -Name ('files: kit tree present (' + ($expected.Count - $missing.Count) + '/' + $expected.Count + ' expected files)') -Ok ($missing.Count -eq 0) -Detail ('missing: ' + (@($missing | Select-Object -First 6) -join ', '))

# ---------------------------------------------------------------------------
# 2. Hook hashes vs the repo copy
# ---------------------------------------------------------------------------

if ($repoCoreAvailable) {
    $repoHooks = [System.IO.Path]::Combine($repoCore, '.claude', 'hooks')
    $kitHooks = [System.IO.Path]::Combine($KitRoot, '.claude', 'hooks')
    $checked = 0
    $mismatch = @()
    if (Test-Path -LiteralPath $repoHooks -PathType Container) {
        foreach ($f in @(Get-ChildItem -LiteralPath $repoHooks -File -Force)) {
            $checked++
            $dst = [System.IO.Path]::Combine($kitHooks, $f.Name)
            if (-not (Test-Path -LiteralPath $dst -PathType Leaf)) { $mismatch += ($f.Name + ' (missing)'); continue }
            $a = Get-FileHashSafe -Path $f.FullName
            $b = Get-FileHashSafe -Path $dst
            if (-not ($a -and $b -and ($a -eq $b))) { $mismatch += ($f.Name + ' (hash differs)') }
        }
    }
    Check -Name ('files: hook hashes match the repo copy (' + ($checked - $mismatch.Count) + '/' + $checked + ')') -Ok (($checked -gt 0) -and ($mismatch.Count -eq 0)) -Detail (($mismatch | Select-Object -First 6) -join ', ')
} else {
    Info 'files: hash spot-check skipped (repo payload not available next to verify.ps1)'
}

# ---------------------------------------------------------------------------
# 3/4/5. Settings
# ---------------------------------------------------------------------------

$expectedEvents = @('SessionStart', 'PostToolUseFailure', 'PreCompact', 'PostCompact')
$settingsObj = $null
$settingsRaw = ''
$settingsValid = $false
$settingsReadError = ''
if (-not $settingsPath) {
    $settingsReadError = 'home not resolvable'
} elseif (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
    $settingsReadError = 'file not found'
} else {
    try {
        $settingsRaw = [System.IO.File]::ReadAllText($settingsPath, (New-Object System.Text.UTF8Encoding($false, $true)))
        if ($settingsRaw.Trim().Length -eq 0) { $settingsReadError = 'file is empty' }
        else {
            $settingsObj = $settingsRaw | ConvertFrom-Json -ErrorAction Stop
            $settingsValid = ($null -ne $settingsObj)
            if (-not $settingsValid) { $settingsReadError = 'empty JSON document' }
        }
    } catch {
        $settingsReadError = $_.Exception.Message
    }
}
Check -Name 'settings: user settings.json is valid JSON' -Ok $settingsValid -Detail ($settingsPath + ' -> ' + $settingsReadError)

$eventReport = @()
$eventsOk = $settingsValid
if ($settingsValid) {
    $hp = $settingsObj.PSObject.Properties['hooks']
    foreach ($evt in $expectedEvents) {
        $found = $false
        $fileOk = $false
        if ($hp -and $hp.Value) {
            $ep = $hp.Value.PSObject.Properties[$evt]
            if ($ep -and $ep.Value) {
                foreach ($entry in @($ep.Value)) {
                    $files = @(Get-OurHookFiles -Entry $entry -Root $KitRoot)
                    if ($files.Count -gt 0) {
                        $found = $true
                        # the last path arg is the -File value
                        if (Test-Path -LiteralPath ([string]$files[$files.Count - 1]) -PathType Leaf) { $fileOk = $true }
                        break
                    }
                }
            }
        }
        if ($found -and $fileOk) { $eventReport += ($evt + '=ok') }
        elseif ($found) { $eventReport += ($evt + '=hook-file-missing') }
        else { $eventReport += ($evt + '=MISSING') }
        if (-not ($found -and $fileOk)) { $eventsOk = $false }
    }
    # sensor (opt-in): informational only
    $sensorFound = $false
    if ($hp -and $hp.Value) {
        $sp = $hp.Value.PSObject.Properties['PreToolUse']
        if ($sp -and $sp.Value) {
            foreach ($entry in @($sp.Value)) {
                if (@(Get-OurHookFiles -Entry $entry -Root $KitRoot).Count -gt 0) { $sensorFound = $true; break }
            }
        }
    }
} else {
    $eventReport += 'settings not readable'
    $sensorFound = $false
}
Check -Name 'settings: kit entries on the 4 expected events (and hook files exist)' -Ok $eventsOk -Detail ($eventReport -join ' ')
if ($sensorFound) { Info 'settings: PreToolUse sensor present (opt-in enabled)' }
else { Info 'settings: PreToolUse sensor absent (opt-in, default off)' }

# deny rules
$denyOk = $false
$denyDetail = ''
if ($settingsValid) {
    $fragPath = ''
    $c1 = [System.IO.Path]::Combine($KitRoot, 'templates', 'settings-deny-fragment.json')
    if (Test-Path -LiteralPath $c1 -PathType Leaf) { $fragPath = $c1 }
    elseif ($repoCoreAvailable) {
        $c2 = [System.IO.Path]::Combine($repoCore, 'templates', 'settings-deny-fragment.json')
        if (Test-Path -LiteralPath $c2 -PathType Leaf) { $fragPath = $c2 }
    }
    if (-not $fragPath) {
        $denyDetail = 'deny fragment not found'
    } else {
        try {
            $frag = ([System.IO.File]::ReadAllText($fragPath, [System.Text.Encoding]::UTF8)) | ConvertFrom-Json -ErrorAction Stop
            $rules = @()
            $fp = $frag.PSObject.Properties['permissions']
            if ($fp -and $fp.Value) {
                $dp = $fp.Value.PSObject.Properties['deny']
                if ($dp -and $dp.Value) { $rules = @($dp.Value) }
            }
            $have = @()
            $pp = $settingsObj.PSObject.Properties['permissions']
            if ($pp -and $pp.Value) {
                $dp = $pp.Value.PSObject.Properties['deny']
                if ($dp -and $dp.Value) { $have = @($dp.Value) }
            }
            $absent = @($rules | Where-Object { $have -notcontains [string]$_ })
            $denyOk = ($rules.Count -gt 0) -and ($absent.Count -eq 0)
            $denyDetail = ('present ' + ($rules.Count - $absent.Count) + '/' + $rules.Count + '; absent: ' + (@($absent | Select-Object -First 4) -join ', '))
        } catch {
            $denyDetail = ('fragment unreadable: ' + $_.Exception.Message)
        }
    }
} else {
    $denyDetail = 'settings not readable'
}
Check -Name 'settings: kit permissions.deny rules present' -Ok $denyOk -Detail $denyDetail

# ---------------------------------------------------------------------------
# 6. Probe (opt-in): execute the INSTALLED SessionStart hook in a sandbox
# ---------------------------------------------------------------------------

if ($InvokeProbe) {
    $hookPath = [System.IO.Path]::Combine($KitRoot, '.claude', 'hooks', 'Invoke-SessionStart.ps1')
    if (-not (Test-Path -LiteralPath $hookPath -PathType Leaf)) {
        Check -Name 'probe: installed SessionStart hook injects [AGENT_CONTEXT]' -Ok $false -Detail ('hook not found: ' + $hookPath)
    } else {
        $probeRoot = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), 'longctx-verify-probe-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        $proj = [System.IO.Path]::Combine($probeRoot, 'project')
        $agentDir = [System.IO.Path]::Combine($proj, '.agent')
        [void](New-Item -ItemType Directory -Force -Path $agentDir)
        $tplAgent = [System.IO.Path]::Combine($KitRoot, 'templates', 'agent')
        if (Test-Path -LiteralPath $tplAgent -PathType Container) {
            foreach ($f in @(Get-ChildItem -LiteralPath $tplAgent -File -Force)) {
                Copy-Item -LiteralPath $f.FullName -Destination ([System.IO.Path]::Combine($agentDir, $f.Name))
            }
        }
        $errFile = [System.IO.Path]::Combine($probeRoot, 'stderr.txt')
        $stdin = (@{ hook_event_name = 'SessionStart'; source = 'startup'; cwd = $proj } | ConvertTo-Json -Compress)
        $r = Invoke-Hook -HookPath $hookPath -Stdin $stdin -ProjectDir $proj -ErrFile $errFile
        $ctx = ''
        $parseOk = $false
        try {
            $o = $r.Out | ConvertFrom-Json -ErrorAction Stop
            $so = $o.PSObject.Properties['hookSpecificOutput']
            if ($so -and $so.Value) {
                $ac = $so.Value.PSObject.Properties['additionalContext']
                if ($ac) { $ctx = [string]$ac.Value; $parseOk = $true }
            }
        } catch { $parseOk = $false }
        Check -Name 'probe: installed SessionStart hook injects [AGENT_CONTEXT]' -Ok (($r.Exit -eq 0) -and $parseOk -and $ctx.Contains('[AGENT_CONTEXT]')) -Detail ('exit=' + $r.Exit + ' sandbox=' + $probeRoot + ' stdout(0..160)=' + $r.Out.Substring(0, [Math]::Min(160, $r.Out.Length)))
    }
} else {
    Info 'probe: skipped (use -InvokeProbe to execute the installed SessionStart hook)'
}

Write-Host ''
Write-Host ('verify: ' + $script:Pass + ' PASS / ' + $script:Fail + ' FAIL')
if ($script:Fail -gt 0) { exit 1 }
exit 0
