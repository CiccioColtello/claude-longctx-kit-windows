#requires -Version 5.1
<#
.SYNOPSIS
    Security probe for the shipped kit: deny gate (Block-Destructive) and the
    KitRoot ownership gate (install.ps1 / uninstall.ps1).
.DESCRIPTION
    Runs the SHIPPED files as real child processes against a %TEMP% sandbox and
    asserts the observable security contract:

      A. deny gate       - destructive / privilege / git-force commands are DENIED with
                           the expected rule id, INCLUDING the quote-split evasions
                           ('cat ."env"', '~/."claude"/settings.json'); benign commands
                           (a quoted word that merely looks like a path included) are
                           ALLOWED; the failure logger MASKS the glued reference.
      B. ownership gate  - -KitRoot equal to an ANCESTOR of the home dir, or to the
                           SETTINGS DIR (<home>/.claude), is refused with exit 2 by
                           install.ps1 AND uninstall.ps1 (the uninstall is the severe
                           one: every user hook under it would look 'ours'); the
                           default shape (<home>/.claude/longctx) is still accepted
                           (no over-refusal) and the settings file stays byte-untouched.

    Read-only with respect to the repository: the sandbox lives under the system temp
    directory and is never cleaned up (no recursive deletion in a probe): the path is
    printed at the end for inspection.
    Portable: Windows PowerShell 5.1 and pwsh 7 (Windows/macOS).
.NOTES
    RED discriminator: run it against a pre-campaign #3 hooks copy (no dequoted
    candidate pass in the gate) -> leg A goes red on the F7 cases (allow instead of
    deny); against a pre-fix installer (no settings-dir gate) -> leg B goes red on the
    settings-dir cases. This is how the macOS divergence of install.ps1/uninstall.ps1
    was confirmed.
#>

[CmdletBinding()]
param(
    [string]$HooksDir = '',
    [string]$RepoRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Pass = 0
$script:Fail = 0

function Get-HookInterpreter {
    <# 'powershell.exe' on Windows, 'pwsh' elsewhere (same rule as the hooks). #>
    [CmdletBinding()]
    param()
    if ($env:OS -eq 'Windows_NT') { return 'powershell.exe' }
    return 'pwsh'
}

function Check {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Ok,
        [AllowEmptyString()][string]$Detail = ''
    )
    if ($Ok) {
        $script:Pass++
        Write-Host ('PASS  ' + $Name)
    } else {
        $script:Fail++
        Write-Host ('FAIL  ' + $Name)
        if ($Detail) { Write-Host ('      detail: ' + $Detail) }
    }
}

# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------
$here = $PSScriptRoot
$hooks = $HooksDir
if (-not $hooks) { $hooks = [System.IO.Path]::Combine($here, '..', '.claude', 'hooks') }
$repo = $RepoRoot
if (-not $repo) { $repo = [System.IO.Path]::Combine($here, '..', '..') }
try { $hooks = [System.IO.Path]::GetFullPath($hooks) } catch { }
try { $repo = [System.IO.Path]::GetFullPath($repo) } catch { }

$need = @('Block-Destructive.ps1', 'Hook-Common.ps1', 'Invoke-PostToolUseFailure.ps1')
$missing = @()
foreach ($f in $need) {
    if (-not (Test-Path -LiteralPath ([System.IO.Path]::Combine($hooks, $f)) -PathType Leaf)) { $missing += $f }
}
if ($missing.Count -gt 0) {
    Write-Host ('ERROR (prerequisite): shipped hooks not found in ' + $hooks)
    Write-Host ('  missing: ' + ($missing -join ', '))
    exit 2
}

$root = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), 'longctx-probe-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
$proj = [System.IO.Path]::Combine($root, 'project')
[void](New-Item -ItemType Directory -Force -Path ([System.IO.Path]::Combine($proj, '.agent')))

Write-Host 'longctx security probe (shipped files, real processes)'
Write-Host ('  hook interpreter : ' + (Get-HookInterpreter))
Write-Host ('  hooks            : ' + $hooks)
Write-Host ('  repo             : ' + $repo)
Write-Host ('  sandbox          : ' + $root)
Write-Host ''

# ---------------------------------------------------------------------------
# A. deny gate: one real Block-Destructive process per case.
# ---------------------------------------------------------------------------
function Invoke-BashGate {
    <# Runs the shipped gate with one Bash payload; returns stdout/stderr/exit. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Command)
    $json = '{"tool_name":"Bash","tool_input":{"command":' + ($Command | ConvertTo-Json -Compress) + '}}'
    $errFile = [System.IO.Path]::Combine($root, ('err-' + [Guid]::NewGuid().ToString('N').Substring(0, 6) + '.txt'))
    $exe = Get-HookInterpreter
    $argv = @('-NoProfile', '-NonInteractive')
    if ($env:OS -eq 'Windows_NT') { $argv += @('-ExecutionPolicy', 'Bypass') }
    $argv += @('-File', [System.IO.Path]::Combine($hooks, 'Block-Destructive.ps1'))
    $prev = $env:CLAUDE_PROJECT_DIR
    $env:CLAUDE_PROJECT_DIR = $proj
    $out = @()
    try { $out = @($json | & $exe @argv 2> $errFile) } finally {
        if ($null -eq $prev) { [System.Environment]::SetEnvironmentVariable('CLAUDE_PROJECT_DIR', $null) }
        else { $env:CLAUDE_PROJECT_DIR = $prev }
    }
    $err = ''
    if (Test-Path -LiteralPath $errFile) { $err = [System.IO.File]::ReadAllText($errFile) }
    return @{ Out = ($out -join "`n"); Err = $err; Exit = $LASTEXITCODE }
}

$denyCases = @(
    # class F1: the same rule must fire when the binary is reached via a path
    @{ N = 'rm -rf via absolute path';          C = '/bin/rm -rf /tmp/probe-x';              R = 'rm-recursive-force' }
    @{ N = 'del /f /s /q via absolute path';    C = 'C:\tools\del /f /s /q C:\tmp';          R = 'windows-del-flags' }
    @{ N = 'ri -Recurse via absolute path';     C = 'C:\tools\ri -Recurse x';                R = 'ps-remove-recursive' }
    @{ N = 'sudo via absolute path';            C = '/usr/bin/sudo rm x';                    R = 'privilege-escalation' }
    @{ N = 'git push +refspec (force)';         C = 'git push origin +main';                 R = 'git-push-force' }
    @{ N = 'git reset --hard';                  C = 'git reset --hard HEAD~1';               R = 'git-reset' }
    # class F7: quote-split references (RED against a pre-fix gate: allowed)
    @{ N = 'quote-split ."env"';                C = 'cat ."env"';                            R = 'secret-token' }
    @{ N = 'quote-split ~/."claude"/settings';  C = 'Set-Content ~/."claude"/settings.json x'; R = 'protected-path-write' }
    # controls: denied before and after (no regression)
    @{ N = 'control: plain .env read';          C = 'cat .env';                              R = 'secret-read' }
)
foreach ($c in $denyCases) {
    $r = Invoke-BashGate -Command $c.C
    $denied = ($r.Out -match '"permissionDecision":"deny"')
    $ruleOk = ($r.Out -match ('\[' + [regex]::Escape($c.R) + '\]'))
    Check -Name ('deny: ' + $c.N + ' -> ' + $c.R) -Ok ($denied -and $ruleOk) -Detail ('denied=' + $denied + ' rule=' + $ruleOk + ' exit=' + $r.Exit + ' out=' + $r.Out.Trim() + ' err=' + $r.Err.Trim())
}

$allowCases = @(
    @{ N = 'ls -la';                             C = 'ls -la' }
    @{ N = 'git push without force';             C = 'git push origin main' }
    @{ N = 'quoted word in a search';            C = 'rg -n "api" docs/notes.md' }
    # quoting must not become a WRITE: reading the protected file is allowed
    @{ N = 'quoted READ of the protected file';  C = 'Get-Content ~/."claude"/settings."json"' }
)
foreach ($c in $allowCases) {
    $r = Invoke-BashGate -Command $c.C
    $denied = ($r.Out -match '"permissionDecision":"deny"')
    Check -Name ('allow: ' + $c.N) -Ok ((-not $denied) -and ($r.Exit -eq 0)) -Detail ('denied=' + $denied + ' exit=' + $r.Exit + ' out=' + $r.Out.Trim() + ' err=' + $r.Err.Trim())
}

# ---------------------------------------------------------------------------
# A2. log masking: the failure logger must MASK the glued reference instead of
#     storing it verbatim (RED against a pre-fix hooks copy: raw leak).
# ---------------------------------------------------------------------------
function Invoke-FailureLog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Command)
    $json = '{"tool_name":"Bash","tool_input":{"command":' + ($Command | ConvertTo-Json -Compress) + '},"error":"probe"}'
    $errFile = [System.IO.Path]::Combine($root, ('err-' + [Guid]::NewGuid().ToString('N').Substring(0, 6) + '.txt'))
    $exe = Get-HookInterpreter
    $argv = @('-NoProfile', '-NonInteractive')
    if ($env:OS -eq 'Windows_NT') { $argv += @('-ExecutionPolicy', 'Bypass') }
    $argv += @('-File', [System.IO.Path]::Combine($hooks, 'Invoke-PostToolUseFailure.ps1'))
    $prev = $env:CLAUDE_PROJECT_DIR
    $env:CLAUDE_PROJECT_DIR = $proj
    $failFile = [System.IO.Path]::Combine($proj, '.agent', 'FAILURES.md')
    # fresh file per case: the assertions are about THIS command's row only
    if (Test-Path -LiteralPath $failFile) { [System.IO.File]::Delete($failFile) }
    $out = @()
    try { $out = @($json | & $exe @argv 2> $errFile) } finally {
        if ($null -eq $prev) { [System.Environment]::SetEnvironmentVariable('CLAUDE_PROJECT_DIR', $null) }
        else { $env:CLAUDE_PROJECT_DIR = $prev }
    }
    $txt = ''
    if (Test-Path -LiteralPath $failFile) { $txt = [System.IO.File]::ReadAllText($failFile) }
    return @{ Out = ($out -join "`n"); Exit = $LASTEXITCODE; Log = $txt }
}

$rMask = Invoke-FailureLog -Command 'cat ."env"'
$maskedOk = ($rMask.Log -match '\[SENSITIVE_FILE\]') -and (-not $rMask.Log.Contains('."env"'))
Check -Name 'mask: quote-split reference is replaced in FAILURES.md' -Ok ($maskedOk -and ($rMask.Exit -eq 0)) -Detail ('masked=' + ($rMask.Log -match '\[SENSITIVE_FILE\]') + ' leaked=' + $rMask.Log.Contains('."env"') + ' row=' + (($rMask.Log -split "`n") | Select-Object -Last 1))

$rKeep = Invoke-FailureLog -Command 'echo hello world'
$keepOk = ($rKeep.Log.Contains('echo hello world')) -and (-not ($rKeep.Log -match '\[SENSITIVE_FILE\]'))
Check -Name 'mask control: a benign command is stored verbatim' -Ok $keepOk -Detail ('verbatim=' + $rKeep.Log.Contains('echo hello world') + ' row=' + (($rKeep.Log -split "`n") | Select-Object -Last 1))

# ---------------------------------------------------------------------------
# B. KitRoot ownership gate: real install.ps1 / uninstall.ps1 processes with a
#    FAKE home (USERPROFILE + HOME both redirected inside the sandbox).
# ---------------------------------------------------------------------------
$installer = [System.IO.Path]::Combine($repo, 'install.ps1')
$uninstaller = [System.IO.Path]::Combine($repo, 'uninstall.ps1')
if ((-not (Test-Path -LiteralPath $installer -PathType Leaf)) -or (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf))) {
    Write-Host ('SKIP  ownership gate leg: installer scripts not found under ' + $repo)
} else {
    function Invoke-Child {
        <# Runs an installer script as a real child process with a redirected fake home.
           NOTE: the host flags live in $psFlags -- naming them $argv would CLOBBER the
           $Argv parameter (PowerShell variables are case-insensitive). #>
        [CmdletBinding()]
        param([Parameter(Mandatory)][string]$Script, [Parameter(Mandatory)][string[]]$Argv, [Parameter(Mandatory)][string]$FakeHome)
        $prevU = $env:USERPROFILE; $prevH = $env:HOME
        $prevEap = $ErrorActionPreference
        $env:USERPROFILE = $FakeHome; $env:HOME = $FakeHome
        # native stderr + EAP Stop on PS 5.1 -> NativeCommandError: keep it non-terminating here
        $ErrorActionPreference = 'Continue'
        $psFlags = @('-NoProfile', '-NonInteractive')
        if ($env:OS -eq 'Windows_NT') { $psFlags += @('-ExecutionPolicy', 'Bypass') }
        $psFlags += @('-File', $Script)
        $psArgs = @($psFlags + $Argv)   # splatting needs a VARIABLE, not an inline @() expression
        try {
            $out = @(& (Get-HookInterpreter) @psArgs 2>&1)
            return @{ Out = ($out | Out-String); Code = $LASTEXITCODE }
        } finally {
            $ErrorActionPreference = $prevEap
            $env:USERPROFILE = $prevU; $env:HOME = $prevH
        }
    }

    $homeB = [System.IO.Path]::Combine($root, 'b-home')
    [void](New-Item -ItemType Directory -Force -Path $homeB)
    $ancestor = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($homeB, '..'))
    $settingsDir = [System.IO.Path]::Combine($homeB, '.claude')

    $r = Invoke-Child -Script $installer -Argv @('-KitRoot', $ancestor, '-DryRun') -FakeHome $homeB
    Check -Name 'gate: install refuses a -KitRoot ANCESTOR of the home dir' -Ok (($r.Code -eq 2) -and ($r.Out -match 'refusing unsafe -KitRoot')) -Detail ('code=' + $r.Code + ' out=' + ($r.Out -replace '\r?\n', ' ').Trim())

    $r = Invoke-Child -Script $installer -Argv @('-KitRoot', $settingsDir, '-DryRun') -FakeHome $homeB
    Check -Name 'gate: install refuses the SETTINGS DIR as -KitRoot' -Ok (($r.Code -eq 2) -and ($r.Out -match 'refusing unsafe -KitRoot')) -Detail ('code=' + $r.Code + ' out=' + ($r.Out -replace '\r?\n', ' ').Trim())

    # The severe one: uninstall with -KitRoot = settings dir would treat USER hooks as
    # 'ours' and delete them. It must refuse AND leave settings.json byte-untouched.
    [void](New-Item -ItemType Directory -Force -Path $settingsDir)
    $settingsPath = [System.IO.Path]::Combine($settingsDir, 'settings.json')
    $enc = New-Object System.Text.UTF8Encoding($false)
    $foreignHook = [System.IO.Path]::Combine($settingsDir, 'hooks', 'user-hook.ps1')
    $settingsJson = '{ "hooks": { "SessionStart": [ { "hooks": [ { "type": "command", "args": [ "-File", "' + ($foreignHook -replace '\\', '\\') + '" ] } ] } ] } }'
    [System.IO.File]::WriteAllText($settingsPath, $settingsJson, $enc)
    $before = [System.IO.File]::ReadAllBytes($settingsPath)
    $r = Invoke-Child -Script $uninstaller -Argv @('-KitRoot', $settingsDir, '-Apply') -FakeHome $homeB
    $after = [System.IO.File]::ReadAllBytes($settingsPath)
    $same = ($before.Length -eq $after.Length)
    if ($same) { for ($i = 0; $i -lt $before.Length; $i++) { if ($before[$i] -ne $after[$i]) { $same = $false; break } } }
    Check -Name 'gate: uninstall refuses the SETTINGS DIR and leaves settings.json untouched' -Ok (($r.Code -eq 2) -and ($r.Out -match 'refusing unsafe -KitRoot') -and $same) -Detail ('code=' + $r.Code + ' untouched=' + $same + ' out=' + ($r.Out -replace '\r?\n', ' ').Trim())

    $default = [System.IO.Path]::Combine($homeB, '.claude', 'longctx')
    $r = Invoke-Child -Script $installer -Argv @('-KitRoot', $default, '-DryRun') -FakeHome $homeB
    Check -Name 'gate control: the DEFAULT shape (<home>/.claude/longctx) is still accepted' -Ok (($r.Code -ne 2) -and ($r.Out -notmatch 'refusing unsafe -KitRoot')) -Detail ('code=' + $r.Code + ' out=' + ($r.Out -replace '\r?\n', ' ').Trim())
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host ('PASS: ' + $script:Pass + ' | FAIL: ' + $script:Fail)
Write-Host ''
Write-Host 'COVERAGE (what was proven):'
Write-Host '  - Deny gate (real Block-Destructive process): destructive/privilege/git-force forms denied with the expected rule id, path-prefixed binaries included.'
Write-Host '  - Quote-split evasions (class F7): cat ."env" and ~/."claude"/settings.json denied; the quoted READ of a protected file is still allowed.'
Write-Host '  - Log masking: the glued reference is replaced by [SENSITIVE_FILE] ... in FAILURES.md; benign commands stay verbatim.'
Write-Host '  - Ownership gate (real install/uninstall): ancestor of home and the settings dir refused, settings.json byte-untouched, default KitRoot shape accepted.'
Write-Host ''
Write-Host 'REST (what is NOT covered):'
Write-Host '  - Only a curated subset of the rule table is exercised (the full 36-rule matrix and the delimiter-class sweep live in the development probes, not here).'
Write-Host '  - The ownership gate is exercised through install.ps1/uninstall.ps1 only (verify.ps1/status read-only paths and the .sh wrappers are not invoked).'
Write-Host '  - The macOS leg of the probes is not executed by this run on Windows (the same PowerShell code paths are, via the shared core).'
Write-Host '  - The sandbox is never cleaned up: the path is printed above for inspection.'
Write-Host ''

if ($script:Fail -gt 0) { exit 1 }
exit 0
