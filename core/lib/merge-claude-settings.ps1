#requires -Version 5.1
# merge-claude-settings.ps1 -- non-destructive MERGE of Claude Code settings.json files.
# Adds the kit hook entries and the permissions.deny rules WITHOUT touching anything
# of the user's: existing hooks, arbitrary keys and deny rules already present stay.
# Idempotent (re-runnable): when there is nothing to add, Result = 'unchanged'
# and the caller MUST NOT write the file (zero-byte write: file untouched).
# Fail-safe: unreadable JSON = error, NEVER an overwrite.
#
# PreToolUse sensor (Block-Destructive): OPT-IN with -WithSensor, default OFF
# (native permissions.deny rules = default preset).
#
# -SelfTest: case matrix in a %TEMP% sandbox, prints PASS/FAIL (exit 1 when red).
param(
    [string]$KitRoot = '',
    [ValidateSet('windows','mac')][string]$Os = 'windows',
    [switch]$WithSensor,
    [string]$DenyFragment = '',
    [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'

function Get-KitRootDefault {
    # Default KitRoot: user home + .claude/longctx.
    # Per-OS rule: on Windows $env:USERPROFILE wins (HOME of Git Bash can be
    # in POSIX form '/c/Users/...' and would produce a wrong path); elsewhere (macOS/
    # Linux) $env:HOME wins. Final fallback: system user folder. Never a
    # silent relative path (on macOS USERPROFILE is absent: Combine('') gave
    # '.claude\longctx' relative to the CWD — bug closed 2026-10-06, selftest case 9c).
    $isWin = ($env:OS -eq 'Windows_NT')
    if ($isWin) {
        $base = $env:USERPROFILE
        if (-not $base) { $base = $env:HOME }
    } else {
        $base = $env:HOME
        if (-not $base) { $base = $env:USERPROFILE }
    }
    if (-not $base) { $base = [System.Environment]::GetFolderPath('UserProfile') }
    if (-not $base) { return '' }
    return [System.IO.Path]::Combine($base, '.claude', 'longctx')
}

if (-not $KitRoot) { $KitRoot = Get-KitRootDefault }
if (-not $DenyFragment) { $DenyFragment = [System.IO.Path]::Combine($KitRoot, 'templates', 'settings-deny-fragment.json') }

$script:KitEvents = [ordered]@{
    SessionStart        = @{ matcher = 'startup|resume|clear|compact|fork'; timeout = 15; status = $null;
                             file = 'Invoke-SessionStart.ps1' }
    PreToolUse          = @{ matcher = 'Bash|PowerShell|Write|Edit|Read|NotebookEdit|Grep|Glob|MultiEdit'; timeout = 20; status = 'Checking security policy...';
                             file = 'Block-Destructive.ps1'; optIn = $true }
    PostToolUseFailure  = @{ matcher = $null; timeout = 15; status = $null;
                             file = 'Invoke-PostToolUseFailure.ps1' }
    PreCompact          = @{ matcher = 'manual|auto'; timeout = 60; status = 'Archiving context (local digest, best-effort)...';
                             file = 'Invoke-PreCompact.ps1' }
    PostCompact         = @{ matcher = 'manual|auto'; timeout = 15; status = $null;
                             file = 'Invoke-PostCompact.ps1' }
}

function New-KitHookEntry {
    param([string]$EventName)
    $spec = $script:KitEvents[$EventName]
    $exe = if ($Os -eq 'mac') { 'pwsh' } else { 'powershell.exe' }
    $argsList = @('-NoProfile', '-NonInteractive')
    if ($Os -eq 'windows') { $argsList += @('-ExecutionPolicy', 'Bypass') }
    $hookPath = [System.IO.Path]::Combine($KitRoot, '.claude', 'hooks', $spec.file)
    $argsList += @('-File', $hookPath)
    $h = [ordered]@{ type = 'command'; command = $exe; args = $argsList; timeout = $spec.timeout }
    if ($spec.status) { $h['statusMessage'] = $spec.status }
    $entry = [ordered]@{}
    if ($spec.matcher) { $entry['matcher'] = $spec.matcher }
    $entry['hooks'] = @([pscustomobject]$h)
    return [pscustomobject]$entry
}

function Test-UnderRoot {
    <# True when $Path is inside (or equal to) $Root WITH a path boundary. A bare
       string prefix is NOT enough: "C:\home\.claude-backup\x.ps1" starts with
       "C:\home\.claude" but is a FOREIGN path (campaign #3, class F2): the merge
       would treat a foreign settings entry as ours and skip wiring the real one. #>
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

function Test-OurEntry {
    # true if the entry contains a kit hook (path of our hook among the args).
    # StrictMode-safe (class: direct member access on user JSON, observed
    # 2026-10-06): real settings.json files contain hook elements WITHOUT "args"
    # and entries WITHOUT "hooks" (also null/string elements occur). Direct
    # access threw PropertyNotFoundException under Set-StrictMode -Version
    # Latest (install.ps1) and aborted the whole merge; every unrecognized shape
    # is simply "not ours". Same defensive pattern as Test-OurHook (uninstall),
    # Get-OurHookFiles (verify) and Test-KitEntry (bin/longctx).
    param($Entry)
    if ($null -eq $Entry) { return $false }
    $hp = $Entry.PSObject.Properties['hooks']
    if (-not $hp) { return $false }
    foreach ($h in @($hp.Value)) {
        if ($null -eq $h) { continue }
        $ap = $h.PSObject.Properties['args']
        if (-not $ap) { continue }
        foreach ($a in @($ap.Value)) {
            $s = [string]$a
            if (Test-UnderRoot -Path $s -Root $KitRoot) { return $true }
        }
    }
    return $false
}

function Get-Sha256Hex {
    # SHA256 via .NET: robust even in environments where Get-FileHash is not resolvable
    # (observed: powershell.exe launched from Git Bash with a polluted PSModulePath -> CommandNotFound).
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try { return [BitConverter]::ToString($sha.ComputeHash($fs)).Replace('-', '') }
        finally { $fs.Dispose() }
    } finally { $sha.Dispose() }
}

function Merge-ClaudeSettings {
    # Returns: Result = 'installed'|'updated'|'unchanged'; Root = settings object;
    # Added = hooks added; DenyAdded = deny rules added.
    [CmdletBinding()]
    param([string]$Path)
    $existing = $null
    if (Test-Path -LiteralPath $Path) {
        # STRICT UTF-8 read (class: silent corruption): invalid bytes must fail
        # closed exactly like invalid JSON, not be silently replaced with U+FFFD
        # and rewritten. Same decoder as Hook-Common.ps1 (throwOnInvalidBytes).
        try {
            $raw = [System.IO.File]::ReadAllText($Path, (New-Object System.Text.UTF8Encoding($false, $true)))
            if ($raw.Trim().Length -gt 0) { $existing = $raw | ConvertFrom-Json -ErrorAction Stop }
        }
        catch { throw ("settings.json unreadable (invalid JSON or invalid UTF-8): {0} -- NO modification applied. Detail: {1}" -f $Path, $_.Exception.Message) }
    }
    if ($null -eq $existing) { $existing = [pscustomobject]@{} }
    elseif ($existing -isnot [System.Management.Automation.PSCustomObject]) {
        # Shape guard (same class as Test-OurEntry): a non-object root would be
        # silently "merged" against a string wrapper and the added hooks would
        # never reach the file (fail-OPEN). Refuse instead, like unreadable JSON.
        throw ("settings.json root is not a JSON object -- NO modification applied. Detail: the file parses but its top level is " + $existing.GetType().Name + ".")
    }

    # StrictMode/shape-safe: "hooks" may be ABSENT or null (-> fresh empty
    # object: null carries no data), but a non-object value would be silently
    # mis-merged and lost at save time -> fail CLOSED.
    $hp = $existing.PSObject.Properties['hooks']
    if ($hp -and $null -ne $hp.Value -and $hp.Value -isnot [System.Management.Automation.PSCustomObject]) {
        throw ("settings.json 'hooks' is not a JSON object -- NO modification applied.")
    }
    if (-not $hp -or $null -eq $hp.Value) {
        $emptyHooks = [pscustomobject]@{}
        if ($hp) { $existing.hooks = $emptyHooks } else { $existing | Add-Member -NotePropertyName hooks -NotePropertyValue $emptyHooks }
    }
    $hooks = $existing.hooks
    $added = 0
    foreach ($evt in $script:KitEvents.Keys) {
        $spec = $script:KitEvents[$evt]
        if ($spec.ContainsKey('optIn') -and $spec.optIn -and -not $WithSensor) { continue }
        $cur = @()
        if ($hooks.PSObject.Properties[$evt]) { $cur = @($hooks.$evt) }
        $have = $false
        foreach ($e in $cur) { if (Test-OurEntry -Entry $e) { $have = $true; break } }
        if (-not $have) {
            $new = @($cur) + @(New-KitHookEntry -EventName $evt)
            if ($hooks.PSObject.Properties[$evt]) { $hooks.$evt = $new }
            else { $hooks | Add-Member -NotePropertyName $evt -NotePropertyValue $new }
            $added++
        }
    }

    # permissions.deny: ADD-ONLY (never a removal, never touching allow/ask).
    $denyAdded = 0
    if ($DenyFragment -and (Test-Path -LiteralPath $DenyFragment)) {
        $fragRaw = [System.IO.File]::ReadAllText($DenyFragment, [System.Text.Encoding]::UTF8)
        $frag = $null
        try { $frag = $fragRaw | ConvertFrom-Json -ErrorAction Stop }
        catch { throw ("deny fragment unreadable: {0} -- NO modification applied." -f $DenyFragment) }
        $rules = @($frag.permissions.deny)
        # Same shape guard as hooks (null -> fresh empty object; non-object -> fail closed).
        $pp = $existing.PSObject.Properties['permissions']
        if ($pp -and $null -ne $pp.Value -and $pp.Value -isnot [System.Management.Automation.PSCustomObject]) {
            throw ("settings.json 'permissions' is not a JSON object -- NO modification applied.")
        }
        if (-not $pp -or $null -eq $pp.Value) {
            $emptyPerm = [pscustomobject]@{}
            if ($pp) { $existing.permissions = $emptyPerm } else { $existing | Add-Member -NotePropertyName permissions -NotePropertyValue $emptyPerm }
        }
        $perm = $existing.permissions
        $curDeny = @()
        if ($perm.PSObject.Properties['deny']) { $curDeny = @($perm.deny) }
        foreach ($r in $rules) {
            if ("$r".Trim().Length -eq 0) { continue }
            if (-not ($curDeny -contains $r)) { $curDeny += $r; $denyAdded++ }
        }
        if ($denyAdded -gt 0) {
            if ($perm.PSObject.Properties['deny']) { $perm.deny = $curDeny }
            else { $perm | Add-Member -NotePropertyName deny -NotePropertyValue $curDeny }
        }
    }

    $total = $added + $denyAdded
    $result = if ($total -eq 0) { 'unchanged' } elseif (Test-Path -LiteralPath $Path) { 'updated' } else { 'installed' }
    return [pscustomobject]@{ Result = $result; Root = $existing; Added = $added; DenyAdded = $denyAdded }
}

function Save-ClaudeSettings {
    # Backup ALWAYS before writing; atomic write temp+move; returns the backup path or $null.
    # MUST BE CALLED ONLY WHEN Result != 'unchanged' (otherwise it would rewrite an identical file).
    # The backup name includes milliseconds + a unique suffix: two close writes
    # CANNOT overwrite the same .bak (bug observed 2026-10-06, case 10a).
    param([string]$Path, $Root)
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $backup = $null
    if (Test-Path -LiteralPath $Path) {
        $backup = '{0}.bak-{1}' -f $Path, $stamp
        $n = 1
        while (Test-Path -LiteralPath $backup) {
            $backup = '{0}.bak-{1}-{2}' -f $Path, $stamp, $n
            $n++
        }
        Copy-Item -LiteralPath $Path -Destination $backup
    }
    # -Depth 100 (maximum): the old -Depth 20 SILENTLY truncated deeper structures
    # into strings ('@{...}') when rewriting the user's file (class: silent data
    # loss). Real settings.json files are ~5 levels deep.
    $json = $Root | ConvertTo-Json -Depth 100
    $tmp = '{0}.tmp-{1}' -f $Path, $PID
    [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
    # Campaign #3, class F5: a transient lock on the target (AV, editor, concurrent
    # writer) used to make the single Move-Item throw, leaving the install HALF
    # applied AND an orphan .tmp-<PID> next to settings.json -- the most critical
    # file of the kit. Same contract as Write-TextFileAtomic (Hook-Common.ps1):
    # retry 3 x 25 ms, the temp is ALWAYS cleaned up when the move ultimately
    # fails (the error still propagates: honest failure, never a silent one).
    try {
        $attempts = 0
        while ($true) {
            $attempts++
            try {
                Move-Item -LiteralPath $tmp -Destination $Path -Force
                break
            } catch {
                # If the temp is gone the move succeeded (reported late).
                if (-not (Test-Path -LiteralPath $tmp)) { break }
                if ($attempts -ge 3) { throw }
                Start-Sleep -Milliseconds 25
            }
        }
    } catch {
        if (Test-Path -LiteralPath $tmp) {
            try { [System.IO.File]::Delete($tmp) } catch { }
        }
        throw
    }
    return $backup
}

if ($SelfTest) {
    # The production callers (install.ps1, bin/longctx.ps1) dot-source this
    # library under Set-StrictMode -Version Latest. Without this line the
    # selftest ran NON-strict and structurally could not see the whole
    # StrictMode member-access class (argless hooks etc.; RED proof
    # 2026-10-06: the real-settings dry-run threw while the selftest was green).
    Set-StrictMode -Version Latest
    # HERMETIC sandbox (campaign #3, class A-hermetic): the name was fixed
    # ('merge-selftest-<PID>') and never cleaned, so a RERUN picked up the previous
    # run's files (observed: same code -> 37 PASS / 4 FAIL) and every run littered
    # %TEMP% (53 stale dirs counted). Fresh unique dir per run + cleanup at the end.
    # Sandbox root, OS-aware: $env:TEMP does not exist outside Windows (macOS and
    # Linux use TMPDIR), and Join-Path on a null Path aborted the whole selftest
    # (RED on the first real CI run, macos-latest leg, 2026-10-06). GetTempPath()
    # honors TMPDIR on Unix and TMP/TEMP/USERPROFILE on Windows -- the same pattern
    # smoke.ps1, probe-hardening.ps1 and verify.ps1 already use.
    $tempRoot = [System.IO.Path]::GetTempPath()
    $sb = Join-Path $tempRoot ('merge-selftest-' + $PID + '-' + ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    [void](New-Item -ItemType Directory -Path $sb -Force)
    $pass = 0; $fail = 0
    function Check([string]$name, [bool]$ok) {
        if ($ok) { Write-Host ("PASS  " + $name); $script:pass++ } else { Write-Host ("FAIL  " + $name); $script:fail++ }
    }

    # test deny fragment in the sandbox (3 rules; 1 will already be present in the test files)
    $frag = Join-Path $sb 'deny-fragment.json'
    @'
{ "permissions": { "deny": [ "Read(./.env)", "Read(**/*.pem)", "Read(~/.ssh/**)" ] } }
'@ | Set-Content -LiteralPath $frag -Encoding UTF8
    $oldFrag = $DenyFragment; $DenyFragment = $frag

    # case 1: missing file -> installed, 4 events (default without sensor), valid JSON, 3 deny rules
    $p1 = Join-Path $sb 'case1.json'
    $r = Merge-ClaudeSettings -Path $p1
    $b = Save-ClaudeSettings -Path $p1 -Root $r.Root
    $j1 = [System.IO.File]::ReadAllText($p1) | ConvertFrom-Json
    $names1 = @($j1.hooks.PSObject.Properties | ForEach-Object { $_.Name })
    Check '1a installed on a missing file (4 hooks + 3 deny)' ($r.Result -eq 'installed' -and $r.Added -eq 4 -and $r.DenyAdded -eq 3)
    Check '1b no backup created (file did not exist)' ($null -eq $b)
    Check '1c 4 events present (no PreToolUse by default)' ($names1.Count -eq 4 -and -not ($names1 -contains 'PreToolUse'))
    Check '1d deny rules present and re-readable' ((@($j1.permissions.deny)).Count -eq 3)
    Check '1e JSON re-readable' ($null -ne $j1)

    # case 2: user keys + user hook on SessionStart + user deny -> preserved + ours added
    $p2 = Join-Path $sb 'case2.json'
    @'
{
  "env": { "FOO": "bar" },
  "model": "opus",
  "permissions": { "deny": [ "Read(./.env)" ], "allow": [ "Bash(ls *)" ] },
  "hooks": {
    "SessionStart": [ { "hooks": [ { "type": "command", "command": "echo", "args": ["hello"] } ] } ]
  }
}
'@ | Set-Content -LiteralPath $p2 -Encoding UTF8
    $r2 = Merge-ClaudeSettings -Path $p2
    $null = Save-ClaudeSettings -Path $p2 -Root $r2.Root
    $j2 = [System.IO.File]::ReadAllText($p2) | ConvertFrom-Json
    Check '2a updated (4 hooks; deny +2 of 3)' ($r2.Result -eq 'updated' -and $r2.Added -eq 4 -and $r2.DenyAdded -eq 2)
    Check '2b user env preserved' ("$($j2.env.FOO)" -eq 'bar')
    Check '2c user model preserved' ("$($j2.model)" -eq 'opus')
    Check '2d user hook on SessionStart present' ((@($j2.hooks.SessionStart)).Count -eq 2)
    Check '2e user hook intact (echo)' (@($j2.hooks.SessionStart[0].hooks)[0].command -eq 'echo')
    Check '2f backup created' (@(Get-ChildItem ($p2 + '.bak-*')).Count -eq 1)
    Check '2g user deny NOT duplicated and allow intact' ((@($j2.permissions.deny)).Count -eq 3 -and (@($j2.permissions.allow)).Count -eq 1)

    # case 3: idempotence -> second run unchanged, no duplicates
    $r3 = Merge-ClaudeSettings -Path $p2
    Check '3a second run unchanged' ($r3.Result -eq 'unchanged' -and $r3.Added -eq 0 -and $r3.DenyAdded -eq 0)
    $j3 = $r3.Root
    $cnt = 0
    foreach ($h in @($j3.hooks.SessionStart)) { if (Test-OurEntry -Entry $h) { $cnt++ } }
    Check '3b only one of our entries on SessionStart' ($cnt -eq 1)

    # case 4: malformed JSON -> throw, file NOT touched
    $p4 = Join-Path $sb 'case4.json'
    Set-Content -LiteralPath $p4 -Value '{ this is not json' -Encoding UTF8
    $h4a = Get-Sha256Hex -Path $p4
    $threw = $false
    try { $null = Merge-ClaudeSettings -Path $p4 } catch { $threw = $true }
    $h4b = Get-Sha256Hex -Path $p4
    Check '4a malformed JSON -> error' $threw
    Check '4b file not touched' ($h4a -eq $h4b)

    # case 4c/4d: INVALID UTF-8 bytes -> error, file NOT touched (strict read).
    # Discriminating: with a permissive decoder this file parses as valid JSON
    # (U+FFFD replacement) and the merge would proceed.
    $p4c = Join-Path $sb 'case4c.json'
    $b1 = [System.Text.Encoding]::ASCII.GetBytes('{"a":"')
    $b2 = [System.Text.Encoding]::ASCII.GetBytes('"}')
    $allb = New-Object System.Collections.Generic.List[byte]
    $allb.AddRange($b1)
    $allb.Add([byte]0xFF)
    $allb.AddRange($b2)
    [System.IO.File]::WriteAllBytes($p4c, $allb.ToArray())
    $h4c = Get-Sha256Hex -Path $p4c
    $threw4c = $false
    try { $null = Merge-ClaudeSettings -Path $p4c } catch { $threw4c = $true }
    $h4d = Get-Sha256Hex -Path $p4c
    Check '4c invalid UTF-8 bytes -> error' $threw4c
    Check '4d file not touched (invalid bytes)' ($h4c -eq $h4d)

    # case 5: existing user PreToolUse -> preserved; sensor NOT added by default
    $p5 = Join-Path $sb 'case5.json'
    @'
{ "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [ { "type": "command", "command": "mycancmd" } ] } ] } }
'@ | Set-Content -LiteralPath $p5 -Encoding UTF8
    $r5 = Merge-ClaudeSettings -Path $p5
    $j5 = $r5.Root
    Check '5a default: PreToolUse stays at 1 entry (user)' ((@($j5.hooks.PreToolUse)).Count -eq 1)
    $c5b = @(@($j5.hooks.PreToolUse)[0].hooks)[0].command
    Check '5b user entry intact' ($c5b -eq 'mycancmd')
    $WithSensor = $true
    $r5s = Merge-ClaudeSettings -Path $p5
    $WithSensor = $false
    $j5s = $r5s.Root
    Check '5c -WithSensor: 2 entries, user first' ((@($j5s.hooks.PreToolUse)).Count -eq 2)
    Check '5d -WithSensor: kit entry second' (Test-OurEntry -Entry (@($j5s.hooks.PreToolUse)[1]))

    # case 6: mac variant in the template (pwsh, no ExecutionPolicy)
    $old = $Os; $Os = 'mac'
    $e = New-KitHookEntry -EventName 'SessionStart'
    $Os = $old
    Check '6a mac: command pwsh' ($e.hooks[0].command -eq 'pwsh')
    Check '6b mac: no ExecutionPolicy' (-not (@($e.hooks[0].args) -contains '-ExecutionPolicy'))

    # case 7: no-op detection = the caller does not write; identical file hash
    $h7a = Get-Sha256Hex -Path $p2
    $r7 = Merge-ClaudeSettings -Path $p2
    if ($r7.Result -ne 'unchanged') { $null = Save-ClaudeSettings -Path $p2 -Root $r7.Root }
    $h7b = Get-Sha256Hex -Path $p2
    Check '7a unchanged -> no rewrite (identical bytes)' ($h7a -eq $h7b)

    # case 8: 0-byte settings (file EXISTS) -> 'updated' (not 'installed': the file was there), not an error
    $p8 = Join-Path $sb 'case8.json'
    [System.IO.File]::WriteAllText($p8, '', (New-Object System.Text.UTF8Encoding($false)))
    $r8 = Merge-ClaudeSettings -Path $p8
    Check '8a 0-byte file -> updated (4 hooks)' ($r8.Result -eq 'updated' -and $r8.Added -eq 4)

    # case 9: default KitRoot resolution (mac: HOME-first; windows: USERPROFILE-first;
    # final fallback = system user folder; NEVER a silent relative path).
    $savU = $env:USERPROFILE; $savH = $env:HOME; $savOS = $env:OS
    $env:USERPROFILE = ''; $env:HOME = $sb
    $r9a = Get-KitRootDefault
    $env:USERPROFILE = 'C:\Users\probe'; $env:HOME = $sb
    $r9b = Get-KitRootDefault
    $env:USERPROFILE = ''; $env:HOME = ''
    $r9c = Get-KitRootDefault
    $env:USERPROFILE = $savU; $env:HOME = $savH; $env:OS = $savOS
    Check '9a USERPROFILE missing + HOME -> ABSOLUTE root under HOME' ([System.IO.Path]::IsPathRooted($r9a) -and $r9a.StartsWith($sb))
    if ($env:OS -eq 'Windows_NT') {
        Check '9b both present on Windows -> USERPROFILE wins' ($r9b.StartsWith('C:\Users\probe'))
    } else {
        Check '9b both present elsewhere -> HOME wins' ($r9b.StartsWith($sb))
    }
    Check '9c both missing -> ABSOLUTE fallback path (never relative)' ([System.IO.Path]::IsPathRooted($r9c))

    # case 10: two close Saves on an EXISTING file -> TWO distinct backups (same-second collision).
    # Note: the FIRST Save of a just-created file does not back up (semantics of 'installed', see 1b/8a).
    $p10 = Join-Path $sb 'case10.json'
    $r10 = Merge-ClaudeSettings -Path $p10
    $b10create = Save-ClaudeSettings -Path $p10 -Root $r10.Root   # creates: no backup
    $r10b = Merge-ClaudeSettings -Path $p10
    $b10a = Save-ClaudeSettings -Path $p10 -Root $r10b.Root       # backup #1
    $r10c = Merge-ClaudeSettings -Path $p10
    $b10b = Save-ClaudeSettings -Path $p10 -Root $r10c.Root       # backup #2
    Check '10a two close Saves -> two distinct backups' ($null -eq $b10create -and $null -ne $b10a -and $null -ne $b10b -and $b10a -ne $b10b -and (Test-Path -LiteralPath $b10a) -and (Test-Path -LiteralPath $b10b))

    # case 11: a structure nested 25 levels survives merge+save.
    # Discriminating: with ConvertTo-Json -Depth 20 the deepest levels were
    # silently replaced by strings ('@{...}') at save time.
    $p11 = Join-Path $sb 'case11.json'
    $node = [pscustomobject]@{ marker = 'sentinel-deep' }
    for ($i = 1; $i -le 25; $i++) { $node = [pscustomobject]@{ level = $i; inner = $node } }
    $deepDoc = [pscustomobject]@{ custom = [pscustomobject]@{ settings = $node } }
    [System.IO.File]::WriteAllText($p11, ($deepDoc | ConvertTo-Json -Depth 100), (New-Object System.Text.UTF8Encoding($false)))
    $r11 = Merge-ClaudeSettings -Path $p11
    $null = Save-ClaudeSettings -Path $p11 -Root $r11.Root
    $j11 = [System.IO.File]::ReadAllText($p11) | ConvertFrom-Json
    $leaf = $j11.custom.settings
    for ($i = 0; $i -lt 25; $i++) { $leaf = $leaf.inner }
    Check '11a structure nested 25 levels survives merge+save' ("$($leaf.marker)" -eq 'sentinel-deep')

    # case 12: StrictMode member-access class -- real-world hook entries WITHOUT
    # "args" / WITHOUT "hooks" / with null and string elements. Observed on a real
    # settings.json: {"type":"command","command":"...","timeout":30} (no args).
    # Discriminating: pre-fix, under Set-StrictMode -Version Latest, the merge
    # threw PropertyNotFoundException 'args' (RED proof vs the pre-fix library,
    # 2026-10-06); before the fix the selftest itself ran non-strict and passed.
    $p12 = Join-Path $sb 'case12.json'
    @'
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "existing-no-args", "timeout": 30 } ] },
      { "matcher": "startup" },
      { "hooks": [ null, "bare" ] }
    ]
  }
}
'@ | Set-Content -LiteralPath $p12 -Encoding UTF8
    $r12 = Merge-ClaudeSettings -Path $p12
    $null = Save-ClaudeSettings -Path $p12 -Root $r12.Root
    $j12 = [System.IO.File]::ReadAllText($p12) | ConvertFrom-Json
    Check '12a argless/valueless entries -> merge proceeds (updated, 4 added)' ($r12.Result -eq 'updated' -and $r12.Added -eq 4)
    Check '12b user entries preserved (3 + ours = 4)' ((@($j12.hooks.SessionStart)).Count -eq 4)
    Check '12c argless user hook intact' ((@(@($j12.hooks.SessionStart)[0].hooks)[0].command) -eq 'existing-no-args')
    $u12 = @(@($j12.hooks.SessionStart)[2].hooks)
    Check '12d null/string hook elements preserved' ($u12.Count -eq 2 -and $null -eq $u12[0] -and "$($u12[1])" -eq 'bare')
    $r12b = Merge-ClaudeSettings -Path $p12
    Check '12e idempotent second run (unchanged)' ($r12b.Result -eq 'unchanged')
    $argless = [pscustomobject]@{ hooks = @([pscustomobject]@{ type = 'command'; command = 'x' }) }
    Check '12f unit: argless entry and null entry are "not ours"' ((-not (Test-OurEntry -Entry $argless)) -and (-not (Test-OurEntry -Entry $null)))

    # case 13: non-object "hooks"/"permissions"/root -> fail CLOSED (throw; file NOT
    # touched). Before this fix these shapes were silently "merged" against a string
    # wrapper and a save would have dropped the hooks without any error (fail-open).
    $p13 = Join-Path $sb 'case13.json'
    Set-Content -LiteralPath $p13 -Value '{"hooks":"not-an-object"}' -Encoding UTF8
    $h13a = Get-Sha256Hex -Path $p13
    $threw13a = $false
    try { $null = Merge-ClaudeSettings -Path $p13 } catch { $threw13a = $true }
    $h13b = Get-Sha256Hex -Path $p13
    Check '13a hooks not an object -> error, file untouched' ($threw13a -and $h13a -eq $h13b)

    $p13b = Join-Path $sb 'case13b.json'
    Set-Content -LiteralPath $p13b -Value '"just-a-string"' -Encoding UTF8
    $threw13b = $false
    try { $null = Merge-ClaudeSettings -Path $p13b } catch { $threw13b = $true }
    Check '13b root not an object -> error' $threw13b

    $p13c = Join-Path $sb 'case13c.json'
    Set-Content -LiteralPath $p13c -Value '{"permissions":"x"}' -Encoding UTF8
    $threw13c = $false
    try { $null = Merge-ClaudeSettings -Path $p13c } catch { $threw13c = $true }
    Check '13c permissions not an object -> error' $threw13c

    # null-valued members carry no data -> treated as empty, NOT an error
    $p13d = Join-Path $sb 'case13d.json'
    Set-Content -LiteralPath $p13d -Value '{"hooks":null,"permissions":null}' -Encoding UTF8
    $threw13d = $false
    $r13d = $null
    try { $r13d = Merge-ClaudeSettings -Path $p13d } catch { $threw13d = $true }
    Check '13d null hooks/permissions -> treated as empty (updated, 4 + 3)' ((-not $threw13d) -and $r13d.Result -eq 'updated' -and $r13d.Added -eq 4 -and $r13d.DenyAdded -eq 3)

    # case 14: F5 discriminator -- an UNWRITABLE target. Save must fail CLOSED and,
    # above all, must NOT leave the temp file behind (pre-F5: single Move-Item, temp
    # orphaned on every failure -- RED proof, 2026-10-06) and must NOT alter the
    # existing file. Two platform simulations, same three assertions:
    #   Windows: the target is held open (FileAccess.Read + FileShare.Read): the
    #     BACKUP copy succeeds, only the replace fails (mandatory locks).
    #   macOS/Linux: locks are advisory and a rename over an open file always
    #     succeeds, so the equivalent unwritable condition is a read-only sandbox
    #     directory -- the save fails with EACCES at its first write. (The orphaned-
    #     temp RED stays a Windows-only discrimination: only mandatory locks fail
    #     the Move after the temp exists.)
    # Unix branch first executed live on the macos CI leg, 2026-10-06: found by the
    # re-run as 43 PASS / 1 FAIL (14a), the Windows-only lock simulation.
    $p14 = Join-Path $sb 'case14.json'
    $r14 = Merge-ClaudeSettings -Path $p14
    $null = Save-ClaudeSettings -Path $p14 -Root $r14.Root   # creates: no backup
    $h14before = Get-Sha256Hex -Path $p14
    $r14b = Merge-ClaudeSettings -Path $p14
    $threw14 = $false
    if ($env:OS -eq 'Windows_NT') {
        $fs14 = $null
        try {
            $fs14 = New-Object System.IO.FileStream($p14, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            try { $null = Save-ClaudeSettings -Path $p14 -Root $r14b.Root } catch { $threw14 = $true }
        } finally {
            if ($fs14) { $fs14.Close() }
        }
    } else {
        # UnixFileMode exists from .NET 7 up (pwsh 7.4 on the macOS runners).
        $oldMode = [System.IO.File]::GetUnixFileMode($sb)
        $roMode = [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserExecute
        try {
            [System.IO.File]::SetUnixFileMode($sb, $roMode)
            try { $null = Save-ClaudeSettings -Path $p14 -Root $r14b.Root } catch { $threw14 = $true }
        } finally {
            [System.IO.File]::SetUnixFileMode($sb, $oldMode)
        }
    }
    $orphans14 = @(Get-ChildItem -LiteralPath $sb -Filter 'case14.json.tmp-*' -ErrorAction SilentlyContinue)
    $h14after = Get-Sha256Hex -Path $p14
    Check '14a locked target -> Save fails CLOSED (throws)' $threw14
    Check '14b locked target -> NO orphan temp left behind' ($orphans14.Count -eq 0)
    Check '14c locked target -> existing file unchanged' ($h14before -eq $h14after)

    $DenyFragment = $oldFrag
    Write-Host ("SELFTEST: " + $pass + " PASS / " + $fail + " FAIL")
    # Hermetic sandbox cleanup (best-effort: the artifacts are evidence only on FAIL,
    # and the failure summary has already been printed).
    try { [System.IO.Directory]::Delete($sb, $true) } catch { }
    if ($fail -gt 0) { exit 1 }
    exit 0
}

# installer usage: Merge-ClaudeSettings -Path <settings>; if Result != 'unchanged' -> Save-ClaudeSettings
Write-Host 'merge-claude-settings.ps1: library loaded (use -SelfTest for the matrix).'
