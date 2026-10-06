#requires -Version 5.1
<#
.SYNOPSIS
    PreToolUse hook (deny mode): blocks destructive operations, privilege escalation,
    global configuration changes and access to sensitive files.
.DESCRIPTION
    Mode chosen by the operator: FULL BLOCK (permissionDecision = "deny").
    A blocked command is NOT executed and can NOT be approved by the agent:
    run it manually outside Claude Code, or remove the rule below.

    Properties:
      - Declarative rules (Id + Pattern + Desc): auditable and testable one by one.
      - The block reason does NOT contain the full command (only the rule Id);
        the redacted and truncated detail goes to .agent/denied-actions.log for the audit.
      - Fail-open on INFRASTRUCTURE errors (unreadable input, exception): the
        session does not break, the anomaly is recorded in .agent/FAILURES.md.
        Fail-open is a declared choice: see .agent/DECISIONS.md.
      - No bypass, no environment variable to disable it: only editing the file.
.NOTES
    Registered on: PreToolUse, matcher "Bash|PowerShell|Write|Edit|Read|NotebookEdit|Grep|Glob|MultiEdit".
    Hook timeout: 20s.
    Declared limit: the CONTENT of the Write/Edit tools is not analyzed (only the
    path); the command branch covers shell writes to protected areas with
    a two-stage heuristic (write verb + canonical path token).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Rules on COMMANDS (Bash / PowerShell tools)
# ---------------------------------------------------------------------------
# Note on the initial classes: the delimiter class (quote, whitespace, ; & |, parens)
# includes command cases inside quoting, e.g. bash -c "rm -rf /", AND invocations by
# absolute path (/bin/rm -rf, C:\Windows\System32\cmd.exe /c ...): campaign #3, class F1
# -- the class used to omit the path separators, so any absolute-path invocation
# bypassed the rule. Every rule with this class was swept (17 occurrences).
# Intended side effect: even `echo "rm -rf"` gets blocked.
$script:CommandRules = @(
    @{ Id = 'rm-recursive-force'; Desc = 'recursive or forced removal (rm -r/-f/-rf)'; Pattern = '(?i)(^|[\s;&|("''\\/])rm\s+(?:[^\s;&|]+\s+)*?(?:-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-[a-z]*r\b|-[a-z]*R\b|-[a-z]*f\b|--recursive|--force|--no-preserve-root)' },
    @{ Id = 'find-delete'; Desc = 'find with -delete'; Pattern = '(?i)\bfind\b[^\r\n;&|]*-delete\b' },
    # PowerShell abbreviations: EVERY valid prefix of the parameter (not just the full
    # form or "rec"/"for"): "Remove-Item -r" and "-fo" are valid and previously passed.
    @{ Id = 'ps-remove-recursive'; Desc = 'Remove-Item/ri/rm/del/rd with -Recurse'; Pattern = '(?i)(^|[\s;&|("''\\/])(remove-item|\bri\b|rm|rmdir|\brd\b|del|erase)\b[^\r\n;&|]*\s-(?:r|re|rec|recur|recurse)\b' },
    @{ Id = 'ps-remove-force'; Desc = 'Remove-Item/ri/rm/del/rd with -Force'; Pattern = '(?i)(^|[\s;&|("''\\/])(remove-item|\bri\b|rm|rmdir|\brd\b|del|erase)\b[^\r\n;&|]*\s-(?:f|fo|for|forc|force)\b' },
    @{ Id = 'pipeline-remove'; Desc = 'mass removal in a pipeline (Get-ChildItem ... | Remove-Item)'; Pattern = '(?i)\|\s*(remove-item|\bri\b|del\b|erase\b|rmdir|\brd\b)\b' },
    @{ Id = 'dotnet-delete'; Desc = 'deletion via .NET ([IO.File]::Delete, [IO.Directory]::Delete)'; Pattern = '(?i)\[(?:system\.)?io\.(?:file|directory|fileinfo|directoryinfo)\]::delete' },
    @{ Id = 'windows-rd-sq'; Desc = 'rd/rmdir with /s or /q'; Pattern = '(?i)(^|[\s;&|("''\\/])(rd|rmdir)\s+[^\r\n;&|]*/(s|q)\b' },
    @{ Id = 'windows-del-flags'; Desc = 'del/erase with /f, /s or /q'; Pattern = '(?i)(^|[\s;&|("''\\/])(del|erase)\s+[^\r\n;&|]*/(f|s|q)\b' },
    # Git (class F18): the subcommand must be reached by SKIPPING the global options
    # (`git -C <dir>`, `git -c k=v`, `git --git-dir=...`) and by recognizing `git.exe`.
    # The following fragment is identical in all git rules (the harness B0
    # requires Pattern as a single-quoted literal: no shared variable) and every
    # rule has a case with global options in the matrix, so a divergence breaks.
    # (Campaign #2, M2: the note was FALSE for git-checkout-discard / git-push-delete /
    # git-config-global — zero cases with global options. The cases now exist and the
    # harness B0b checks the 20 critical alternatives one by one, including
    # all 8 git rules.)
    #   \bgit(?:\.exe)?\b(?:[ \t]+(?: -C/-c <value> | --git-dir/... <value|=value>
    #                                       | -x/--flag[=value] ))*[ \t]+
    @{ Id = 'git-reset'; Desc = 'git reset (also with -C/-c/--git-dir)'; Pattern = '(?i)\bgit(?:\.exe)?\b(?:[ \t]+(?:(?:-[cC][ \t]+(?:"[^"]*"|[^\s;&|"]+))|(?:--(?:git-dir|work-tree|namespace|exec-path|config-env)(?:[ \t]+(?:"[^"]*"|[^\s;&|"]+)|=(?:[^\s;&|"]+|"[^"]*")))|(?:-{1,2}[A-Za-z][A-Za-z0-9-]*(?:=[^\s;&|"]+)?)))*[ \t]+reset\b' },
    @{ Id = 'git-clean'; Desc = 'git clean (also with -C/-c/--git-dir)'; Pattern = '(?i)\bgit(?:\.exe)?\b(?:[ \t]+(?:(?:-[cC][ \t]+(?:"[^"]*"|[^\s;&|"]+))|(?:--(?:git-dir|work-tree|namespace|exec-path|config-env)(?:[ \t]+(?:"[^"]*"|[^\s;&|"]+)|=(?:[^\s;&|"]+|"[^"]*")))|(?:-{1,2}[A-Za-z][A-Za-z0-9-]*(?:=[^\s;&|"]+)?)))*[ \t]+clean\b' },
    @{ Id = 'git-checkout-discard'; Desc = 'git checkout that discards changes (-- or .)'; Pattern = '(?i)\bgit(?:\.exe)?\b(?:[ \t]+(?:(?:-[cC][ \t]+(?:"[^"]*"|[^\s;&|"]+))|(?:--(?:git-dir|work-tree|namespace|exec-path|config-env)(?:[ \t]+(?:"[^"]*"|[^\s;&|"]+)|=(?:[^\s;&|"]+|"[^"]*")))|(?:-{1,2}[A-Za-z][A-Za-z0-9-]*(?:=[^\s;&|"]+)?)))*[ \t]+checkout[ \t]+(?:[^\s;&|]+[ \t]+)*(--|\.)' },
    @{ Id = 'git-restore'; Desc = 'git restore (also with -C/-c/--git-dir)'; Pattern = '(?i)\bgit(?:\.exe)?\b(?:[ \t]+(?:(?:-[cC][ \t]+(?:"[^"]*"|[^\s;&|"]+))|(?:--(?:git-dir|work-tree|namespace|exec-path|config-env)(?:[ \t]+(?:"[^"]*"|[^\s;&|"]+)|=(?:[^\s;&|"]+|"[^"]*")))|(?:-{1,2}[A-Za-z][A-Za-z0-9-]*(?:=[^\s;&|"]+)?)))*[ \t]+restore\b' },
    @{ Id = 'git-push-force'; Desc = 'git push --force / -f'; Pattern = '(?i)\bgit(?:\.exe)?\b(?:[ \t]+(?:(?:-[cC][ \t]+(?:"[^"]*"|[^\s;&|"]+))|(?:--(?:git-dir|work-tree|namespace|exec-path|config-env)(?:[ \t]+(?:"[^"]*"|[^\s;&|"]+)|=(?:[^\s;&|"]+|"[^"]*")))|(?:-{1,2}[A-Za-z][A-Za-z0-9-]*(?:=[^\s;&|"]+)?)))*[ \t]+push\b[^\r\n;&|]*(--force-with-lease|--force|[ \t]-f\b|[ \t]\+(?=[^\s;&|]))'},
    @{ Id = 'git-push-delete'; Desc = 'git push --delete / :ref'; Pattern = '(?i)\bgit(?:\.exe)?\b(?:[ \t]+(?:(?:-[cC][ \t]+(?:"[^"]*"|[^\s;&|"]+))|(?:--(?:git-dir|work-tree|namespace|exec-path|config-env)(?:[ \t]+(?:"[^"]*"|[^\s;&|"]+)|=(?:[^\s;&|"]+|"[^"]*")))|(?:-{1,2}[A-Za-z][A-Za-z0-9-]*(?:=[^\s;&|"]+)?)))*[ \t]+push\b[^\r\n;&|]*(--delete|[ \t]-d\b|[ \t]:[^\s]+)' },
    @{ Id = 'git-commit'; Desc = 'git commit (also with -C/-c/--git-dir)'; Pattern = '(?i)\bgit(?:\.exe)?\b(?:[ \t]+(?:(?:-[cC][ \t]+(?:"[^"]*"|[^\s;&|"]+))|(?:--(?:git-dir|work-tree|namespace|exec-path|config-env)(?:[ \t]+(?:"[^"]*"|[^\s;&|"]+)|=(?:[^\s;&|"]+|"[^"]*")))|(?:-{1,2}[A-Za-z][A-Za-z0-9-]*(?:=[^\s;&|"]+)?)))*[ \t]+commit\b' },
    @{ Id = 'privilege-escalation'; Desc = 'privilege escalation (sudo, runas, Start-Process -Verb RunAs)'; Pattern = '(?i)(^|[\s;&|("''\\/])sudo\b|-verb\s+runas\b|(^|[\s;&|("''\\/])runas\b' },
    @{ Id = 'registry-write'; Desc = 'Windows registry modification'; Pattern = '(?i)(^|[\s;&|("''\\/])(reg(\.exe)?\s+(add|delete|import|copy|save|restore)|regedit|New-ItemProperty|Set-ItemProperty|Remove-ItemProperty)[^\r\n;&|]*(hklm|hkcu|hkey_)|(HKLM:|HKEY_LOCAL_MACHINE)' },
    @{ Id = 'firewall'; Desc = 'firewall modification'; Pattern = '(?i)\bnetsh(\.exe)?\s+(advfirewall|firewall)|New-NetFirewallRule|Set-NetFirewallProfile|Remove-NetFirewallRule|Disable-NetFirewallRule|\biptables\b|\bufw\s+(allow|deny|delete|disable|reset)\b' },
    @{ Id = 'windows-service'; Desc = 'creation/modification of Windows services'; Pattern = '(?i)(^|[\s;&|("''\\/])(sc(\.exe)?\s+(start|stop|config|delete|create|failure)|Set-Service|New-Service|Remove-Service)\b' },
    @{ Id = 'execution-policy-profile'; Desc = 'execution policy or PowerShell profile'; Pattern = '(?i)Set-ExecutionPolicy|\$PROFILE|Microsoft\.PowerShell_profile|Microsoft\.PowerShellISE_profile' },
    # Intentional over-block: `npm ci --dry-run` is blocked. An exception for --dry-run
    # would be bypassable (`npm ci; echo "--dry-run"`), so the false positive is preferred.
    @{ Id = 'package-install'; Desc = 'package/dependency installation, also in dry-run (ask the operator for confirmation)'; Pattern ='(?i)\b(npm|pnpm|yarn)\s+(i|install|add|ci)\b|\bpip3?\s+install\b|\bpython[0-9.]*\s+-m\s+pip\s+install\b|\b(cargo|go)\s+(install|get)\b|\b(apt|apt-get|dnf|yum|pacman|brew|zypper)\s+(install|add|-S)\b|\bwinget\s+(install|add)\b|\bchoco\s+install\b|\bscoop\s+install\b|\bnpx\s+(-y|--yes)\b|\bbunx\b|\bnpm\s+(exec|x)\b|\byarn\s+dlx\b|\bpnpm\s+dlx\b' },
    @{ Id = 'download-pipe-exec'; Desc = 'download executed as code (curl|sh, iex on the web)'; Pattern = '(?i)(curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod|irm)[^\r\n;&|]*(\|\s*(bash|sh|zsh|pwsh|powershell|iex|Invoke-Expression))|\b(bash|sh|zsh)\s*<\(|(iwr|Invoke-WebRequest|irm|Invoke-RestMethod)[^\r\n;&|]*\|\s*(iex|Invoke-Expression)' },
    @{ Id = 'invoke-expression'; Desc = 'Invoke-Expression / iex'; Pattern = '(?i)(^|[\s;&|=(\\/])iex\b|Invoke-Expression\b' },
    @{ Id = 'cmd-c'; Desc = 'cmd /c with a compound command'; Pattern = '(?i)(^|[\s;&|\\/])cmd(\.exe)?\s*/c\b' },
    # (?m) (class F8): without it, `DELETE FROM users` followed by a newline + `GO`/`WHERE` did NOT
    # trigger (`$` = end of the WHOLE string). Now `$` = end of line; `[ \t]` does not cross
    # the newline; `(?=\bLIMIT\b)` covers the bulk DELETE with LIMIT and without WHERE.
    # `DELETE FROM t WHERE ...` on the same line stays allowed (WHERE guard).
    @{ Id = 'db-destructive'; Desc = 'DROP/TRUNCATE/DELETE without WHERE or database migration'; Pattern = '(?im)\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA|INDEX)|\bDELETE\s+FROM\s+[^\s;]+?[ \t]*(?:;|$|(?=\bLIMIT\b))' },
    @{ Id = 'db-migration'; Desc = 'database migration'; Pattern = '(?i)\b(prisma|knex|typeorm)\s+migrate|\balembic\s+(upgrade|downgrade)|\bflyway\s+(migrate|clean)|\bmanage\.py\s+(migrate|flush)|\bdotnet\s+ef\s+database\s+update|\brails\s+db:(migrate|drop|reset)|\bsequelize\s+db:migrate' },
    @{ Id = 'blockchain-tx'; Desc = 'on-chain transaction / contract deploy'; Pattern = '(?i)\bcast\s+send\b|\bforge\s+script\b[^\r\n;&|]*--broadcast|\bforge\s+create\b|sendRawTransaction|eth_sendTransaction|sendTransaction\s*\(|\.sendTransaction\b|\bhardhat\b[^\r\n;&|]*\b(deploy|run)\b|\btruffle\s+migrate\b|\bsolana\b[^\r\n;&|]*\btransfer\b' },
    @{ Id = 'deploy-infra'; Desc = 'deploy/infrastructure'; Pattern = '(?i)\bterraform\s+(apply|destroy|import)\b|\bkubectl\s+(apply|delete|replace|scale|drain)\b|\bdocker\s+(push|system\s+prune)\b|\bhelm\s+(install|upgrade|uninstall)\b|\bfly\s+deploy\b|\bvercel\s+--prod\b|\bnetlify\s+deploy\b|\bheroku\s+(deploy|push)\b|\bansible-playbook\b|\bscp\b[^\r\n;&|]*\s/(var/www|etc|usr|opt)' },
    # Note: `\bdd\s+if=` can NOT sit inside the `\b(…)\b` group — the alternative ends
    # with '=' and a \b after a non-word character can never succeed (dead rule).
    @{ Id = 'disk-filesystem'; Desc = 'disk/filesystem operations or shutdown'; Pattern = '(?i)\b(Format-Volume|Clear-Disk|Initialize-Disk|diskpart|mkfs(\.\w+)?|cipher(\.exe)?\s+/w|shutdown|Restart-Computer|Stop-Computer)\b|\bdd\s+if=' },
    @{ Id = 'git-config-global'; Desc = 'git config --global (also with -C/-c/--git-dir)'; Pattern = '(?i)\bgit(?:\.exe)?\b(?:[ \t]+(?:(?:-[cC][ \t]+(?:"[^"]*"|[^\s;&|"]+))|(?:--(?:git-dir|work-tree|namespace|exec-path|config-env)(?:[ \t]+(?:"[^"]*"|[^\s;&|"]+)|=(?:[^\s;&|"]+|"[^"]*")))|(?:-{1,2}[A-Za-z][A-Za-z0-9-]*(?:=[^\s;&|"]+)?)))*[ \t]+config[ \t]+--global\b' },
    @{ Id = 'env-persist'; Desc = 'persistent environment variables (setx, SetEnvironmentVariable)'; Pattern = '(?i)(^|[\s;&|("''\\/])setx\b|\[Environment\]::SetEnvironmentVariable|\[System\.Environment\]::SetEnvironmentVariable' },
    @{ Id = 'scheduled-task'; Desc = 'scheduled tasks'; Pattern = '(?i)(^|[\s;&|("''\\/])schtasks\b|New-ScheduledTask|Register-ScheduledTask|Unregister-ScheduledTask' },
    # PARITY sweep with the Test-SensitivePath classifier (finding #25/#1 on the shell
    # channel): the families that the tool-file channel already blocked but that this list did not
    # enumerate — .envrc (the \b of `\.env\b` does not exist between 'env' and 'r'), the path
    # SEGMENTS (.ssh/.aws/.gnupg/.kube/.docker/.azure/.terraform/.pulumi: `cat ~/.ssh/config`
    # passed while the Read tool on the same path was denied) and the extensions/
    # modern key names (p12, jks, keystore, ppk, ovpn, jwk, p8, seed.txt, ...).
    @{ Id = 'secret-read'; Desc = 'reading a sensitive file via shell (.env, keys, credentials)'; Pattern = '(?i)(^|[\s;&|("''\\/])(cat|type|more|less|head|tail|get-content|gc|select-string|sls|strings|xxd|od|nano|vim|rg|findstr|awk|sed|python[0-9.]*|perl|node|jq|fc)\b[^\r\n;&|]*(\.env\b|\.env\.[a-z]+|\.envrc\b|\.pem\b|\.key\b|\.pfx\b|\.p12\b|\.jks\b|\.keystore\b|\.ppk\b|\.asc\b|\.gpg\b|\.kdbx\b|\.der\b|\.csr\b|\.ovpn\b|\.jwk\b|\.p8\b|id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys|\.netrc|_netrc|\.pypirc|\.htpasswd|\.my\.cnf|\.dockercfg|credentials\.xml|claude_desktop_config\.json|wallet\.dat|seed\.txt|mnemonic\.txt|token\.json|tokens\.json|auth\.json|cookies\.(txt|json)|credentials|secrets?\.(json|ya?ml)|\.mcp\.json|mcp\.json|\.pgpass|\.npmrc|\.git-credentials|\.tfstate\b|\.tfvars\b|[\\/]\.(ssh|aws|gnupg|kube|docker|azure|terraform|pulumi)([\\/]|$))' },
    # Same parity as the shell channel (finding #25): .envrc and the key families
    # that `\.env|\.pem|\.key` alone left out.
    @{ Id = 'secret-read-dotnet'; Desc = 'reading a sensitive file via .NET (ReadAllText/Bytes/Lines)'; Pattern = '(?i)\[(?:system\.)?io\.file\]::readall(?:text|bytes|lines)[^\r\n;&|]*(\.envrc|\.env|\.pem|\.key|\.p12|\.jks|\.keystore|\.ppk|\.asc|\.gpg|\.kdbx|authorized_keys|id_rsa|id_dsa|id_ecdsa|credentials|secrets|\.npmrc|\.netrc|_netrc|\.pypirc|\.htpasswd|\.pgpass|\.tfstate|\.tfvars|[\\/]\.(ssh|aws|gnupg|kube|docker|azure|terraform|pulumi)[\\/])' },
    # Shell channel parity also for copy/archiving/sending (finding #25):
    # .envrc, .pgpass, tfstate/tfvars, modern keys, .ssh/.aws/... SEGMENTS .
    @{ Id = 'secret-export'; Desc = 'copy/archiving/sending of sensitive files'; Pattern = '(?i)(^|[\s;&|("''\\/])(cp|copy|copy-item|scp|rsync|tar|zip|compress-archive|curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod|7z)\b[^\r\n;&|]*(\.env\b|\.env\.[a-z]+|\.envrc\b|\.pem\b|\.key\b|\.pfx\b|\.p12\b|\.jks\b|\.keystore\b|\.ppk\b|\.asc\b|\.gpg\b|\.kdbx\b|id_rsa|id_dsa|id_ecdsa|id_ed25519|\.netrc|_netrc|\.pgpass|\.tfstate\b|\.tfvars\b|credentials|secrets?\.(json|ya?ml)|wallet\.dat|[\\/]\.(ssh|aws|gnupg|kube|docker|azure|terraform|pulumi)([\\/]|$))' },
    # Note: the `$env:VAR ... |` branch was removed — it triggered on ANY variable followed by a
    # pipe (e.g. `$env:TEMP -File | ...`) without there being a dump: over-block on data.
    @{ Id = 'env-dump'; Desc = 'full dump of environment variables'; Pattern = '(?i)(^|[\s;&|("''\\/])(printenv|env)\s*($|[;&|])|(get-childitem|gci|dir|ls|get-item)\s+(-path\s+)?env:|\[(?:system\.)?environment\]::getenvironmentvariables' },
    # Catch-all for sensitive TOKEN (class F2/F7): the nominal rules above cover the listed
    # verbs, but any unforeseen reader (grep, sort, openssl, ssh-keygen, ...)
    # passed. Here the criterion is INVERTED: the REFERENCE to a sensitive
    # file/path is denied (name families, not verb+token pairs), with ONE single
    # explicit exception: metadata-only verbs (Test-Path/Test-AnyPath/Get-Item/Resolve-Path)
    # on a bare command -> allow (project decision, allow case in the harness B).
    # The guard \A...\z is anchored to the WHOLE string (with (?s) the token is searched also
    # on following lines; without the anchor the guard would be bypassable by making the
    # match start further ahead). It is the LAST rule: every existing Id stays unchanged.
    @{ Id = 'secret-token'; Desc = 'reference to a sensitive file/path in the command (catch-all; metadata-only verbs exempted)'; Pattern = '(?is)\A(?!\s*(?:test-path|test-anypath|get-item|resolve-path)\b[^\r\n;&|]*\s*\z).*?(?:\.env\b|\.env\.[a-z0-9]+|\.envrc\b|\.pem\b|\.key\b|\.pfx\b|\.p12\b|\.jks\b|\.keystore\b|\.ppk\b|\.asc\b|\.gpg\b|\.kdbx\b|\.der\b|\.csr\b|\.ovpn\b|\.jwk\b|\.p8\b|id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys|wallet\.dat|seed\.txt|mnemonic\.txt|token\.json|tokens\.json|auth\.json|cookies\.(?:txt|json)|credentials|secrets?\.(?:json|ya?ml)|\.mcp\.json|mcp\.json|claude_desktop_config\.json|\.pgpass\b|\.npmrc\b|\.netrc\b|_netrc\b|\.pypirc\b|\.htpasswd\b|\.my\.cnf\b|\.dockercfg\b|\.git-credentials\b|\.tfstate\b|\.tfvars\b|[\\/]\.(?:ssh|aws|gnupg|kube|docker|azure|terraform|pulumi)(?:[\\/]|$))' }
)

# ---------------------------------------------------------------------------
# Protected write roots (global configuration / system)
# Hooks start with a reduced environment: variables may be missing, so
# paths are built with explicit fallbacks and without Join-Path on empty values.
# ---------------------------------------------------------------------------
$script:HomeDir = $env:USERPROFILE
if (-not $script:HomeDir) { $script:HomeDir = $env:HOME }
if (-not $script:HomeDir) { $script:HomeDir = 'C:\Users\' + $env:USERNAME }
$script:AppDataDir = $env:APPDATA
if (-not $script:AppDataDir) { $script:AppDataDir = $script:HomeDir + '\AppData\Roaming' }

$script:ProtectedWriteRoots = @('C:\Windows\', 'C:\Program Files\', 'C:\Program Files (x86)\', 'C:\ProgramData\')
$script:ProtectedWriteRoots += ($script:AppDataDir + '\Microsoft\Windows\Start Menu\Programs\Startup')
$script:ProtectedWriteRoots += ($script:HomeDir + '\Documents\PowerShell')
$script:ProtectedWriteRoots += ($script:HomeDir + '\Documents\WindowsPowerShell')
# Claude Code global configuration: protected as the WHOLE tree (before, only
# 5 exact files were protected). The exceptions are the RUNTIME directories (session
# data, not configuration), which the tools must be able to write normally.
$script:ProtectedWriteRoots += ($script:HomeDir + '\.claude')
$script:ProtectedWriteExceptions = @(
    ($script:HomeDir + '\.claude\projects'),
    ($script:HomeDir + '\.claude\todos'),
    ($script:HomeDir + '\.claude\shell-snapshots'),
    ($script:HomeDir + '\.claude\statsig'),
    ($script:HomeDir + '\.claude\file-history'),
    ($script:HomeDir + '\.claude\ide'),
    ($script:HomeDir + '\.claude\logs')
)

$script:ProtectedWriteFiles = @(
    ($script:HomeDir + '\.claude\settings.json'),
    ($script:HomeDir + '\.claude\settings.local.json'),
    ($script:HomeDir + '\.claude\CLAUDE.md'),
    ($script:HomeDir + '\.claude\mcp.json'),
    ($script:HomeDir + '\.claude.json')
)

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

function Get-NormalizedPath {
    <#
        Canonicalizes the path (separators, ADS, trailing space/dot, junction) using
        the shared Hook-Common function when available; fallback GetFullPath.
        A comparison on the raw string is bypassable: "C:/Windows/..." or a path with
        a trailing space do not match the protected prefixes.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $hasCanon = $false
    try { $hasCanon = [bool](Get-Command -Name 'Get-CanonicalPath' -ErrorAction SilentlyContinue) } catch { $hasCanon = $false }
    if ($hasCanon) {
        try {
            # C1 (campaign #3): DIRECT return also of ''. '' from Get-CanonicalPath is
            # the fail-closed sentinel ("not resolvable safely"), NOT
            # "library missing": the caller denies (canonical-unresolved). Before:
            # '' -> fallthrough to GetFullPath (fail-open on the very uncertain case).
            return [string](Get-CanonicalPath -Path $Path)
        } catch {
            return ''
        }
    }
    # Only if the shared library is COMPLETELY missing: direct fallback. Here too a
    # failure -> '' (the caller denies), never the raw path in the clear.
    try {
        return [System.IO.Path]::GetFullPath($Path)
    } catch {
        return ''
    }
}

function Test-ProtectedWrite {
    <# Returns @{Id;Desc} if the write is forbidden, otherwise $null. #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ProjectDir
    )
    $full = Get-NormalizedPath -Path $Path
    if (-not $full) {
        # C1 (campaign #3): fail-closed sentinel — canonicalization did not
        # produce a reliable path: it can NOT be ruled out that the target is
        # protected. (Via the gate the deny arrives earlier as 'sensitive-file':
        # Test-SensitivePath denies on ''; this branch is defense in depth
        # for direct callers.)
        return @{ Id = 'canonical-unresolved'; Desc = 'path not resolvable safely (fail-closed)' }
    }
    $lower = $full.ToLowerInvariant()
    # Boundary shape (class F3): the separator is NATIVE (was the literal '\',
    # which on POSIX appended a backslash to a '/'-path and disabled every match).
    $sep = [string][System.IO.Path]::DirectorySeparatorChar
    $projLower = (Get-NormalizedPath -Path $ProjectDir).ToLowerInvariant().TrimEnd($sep)

    # Order (class F5): the project exemption is the WEAKEST comparison (it depends
    # on a $ProjectDir that may come from the payload cwd) and must come LAST,
    # downstream of the denies. Before: if cwd=$HOME 'became' the project, the exemption triggered
    # BEFORE the config files and ~/.claude/settings.json was writable.
    #   1) EXACT global configuration files -> deny ALWAYS
    #   2) runtime exceptions (inside ~/.claude) -> allow
    #   3) protected roots -> deny (even if the project was resolved wrongly)
    #   4) project exemption -> allow
    foreach ($f in $script:ProtectedWriteFiles) {
        if ($lower -eq $f.ToLowerInvariant()) {
            return @{ Id = 'global-config-write'; Desc = ('protected global configuration: ' + (Get-SensitiveLabel -Path $f)) }
        }
    }
    foreach ($x in $script:ProtectedWriteExceptions) {
        $xl = (Get-NormalizedPath -Path $x).ToLowerInvariant().TrimEnd($sep) + $sep
        if ($lower.StartsWith($xl)) { return $null }   # runtime data: allowed
    }
    foreach ($r in $script:ProtectedWriteRoots) {
        if (-not $r) { continue }
        $rl = $r.ToLowerInvariant().TrimEnd($sep) + $sep
        if ($lower.StartsWith($rl)) {
            return @{ Id = 'system-path-write'; Desc = ('write to a system area: ' + $rl) }
        }
    }
    if ($projLower -and ($lower -eq $projLower -or $lower.StartsWith($projLower + $sep))) { return $null }  # inside the project: allowed
    return $null
}

function Get-CommandProtectedPathHit {
    <#
        Detects a shell command that WRITES to a protected area.
        Heuristic DECLARED in two stages: (1) the command contains a write
        verb; (2) it contains a token that looks like a path and canonicalizes into a
        protected area. Only the first 6 path tokens are tested: it is not a
        shell parser, but it closes the common cases (Set-Content/Out-File/Copy-Item, redirect,
        [IO.File]::WriteAll*, and paths with junctions resolved by the canonical form).
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Command,
        [Parameter(Mandatory)][string]$ProjectDir
    )
    if ([string]::IsNullOrWhiteSpace($Command)) { return '' }
    # Write verb parity (class F6): before, Clear-Content, Set-Item,
    # Set-ItemProperty, Clear-Item and the .NET APIs Append*/Copy/Replace/OpenWrite were missing -> a
    # write to a protected area with those verbs was not even RECOGNIZED as a
    # write (`[IO.File]::AppendAllText('C:\Windows\...\hosts', ...)` passed).
    # The verb is only the first stage: a path token in a protected area is ALSO required.
    # H4 (campaign #2): the verb covered only cmdlets, redirect and a .NET API prefix,
    # but NOT the vehicles that write from a constructor/accessor: File.Open with
    # Write/Create access, FileStream/StreamWriter ::new and New-Object, the downloaders that write
    # to file (-OutFile/-o/-O/--output), `dd of=`, and the interpreter writes
    # (python's open(...,'w'), node's fs.writeFileSync). Same 9 cases from audit #2:
    # all passed. Here the vehicle is RECOGNIZED; the target is decided by the second
    # stage (path token in a protected area), so reads stay allow
    # (open(...,'r'), ::Open(...,'Read')) and benign targets too.
    $writeVerb = '(?i)(?:(^|[\s;&|("''\\/])(set-content|add-content|clear-content|set-item|set-itemproperty|remove-itemproperty|clear-item|out-file|tee-object|new-item|copy-item|move-item|rename-item|remove-item|ri|del|erase|rmdir|rd|ni|cpi|cp|mv|rni|sc|si|sp|ac|clc|cli|tee|export-csv|export-clixml)\b|>>?|\[(?:system\.)?io\.(?:file|directory)\]::(?:write|create|move|delete|copy|replace|append|openwrite)|\[(?:system\.)?io\.(?:file|filestream)\]::open\b[^\r\n;&|]*(?:write|append|create|readwrite)|\[(?:system\.)?io\.streamwriter\]::new|\[(?:system\.)?io\.filestream\]::new[^\r\n;&|]*(?:write|append|create|readwrite)|new-object\s+(?:system\.)?io\.streamwriter|new-object\s+(?:system\.)?io\.filestream[^\r\n;&|]*(?:write|append|create|readwrite)|\b(?:iwr|invoke-webrequest|irm|invoke-restmethod|curl|wget)(?:\.exe)?\b[^\r\n;&|]*(?:-outfile\b|--output-document\b|--output\b|-o\b)|\bdd\b[^\r\n;&|]*\bof=|\b(?:open|fopen)\s*\([^)\r\n;&|]*[''"][wax>]|\.(?:writefile|writefilesync|appendfile|appendfilesync|createwritestream)\b)'
    # F7 (campaign #3): the shell removes quotes BEFORE executing, so the verb
    # check must also see the quote-stripped twin (e.g. Set-"Content", or a path
    # glued across quotes: C:\"Windows"\System32\...).
    $deq = Get-DequotedCommandText -Command $Command
    if ($Command -notmatch $writeVerb -and $deq -notmatch $writeVerb) { return '' }
    # The '/' separators are accepted as much as '\': a "C:/Windows/..." path was not
    # even RECOGNIZED as a path (class: data discovery tied to the canonical
    # form, while the downstream comparison is canonicalized).
    $tokenRe = '(?i)([a-z]:[\\/][^\s;&|"'')]+|[\\/]{2}[^\s;&|"'')]+|~/[^\s;&|"'')]+|~[\\/][^\s;&|"'')]+)'
    # QUOTED paths first: a bare path with spaces ("C:\Program Files\...") is
    # truncated at the first space by the bare token and the protected area would stay INVISIBLE
    # to the check (class: heuristic that loses the case because of how the data is written).
    $quotedRe = '(?i)(["''])((?:[a-z]:[\\/]|[\\/]{2})[^"'']*)\1'
    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches($Command, $quotedRe)) { [void]$candidates.Add($m.Groups[2].Value) }
    foreach ($m in [regex]::Matches($Command, $tokenRe)) { [void]$candidates.Add($m.Groups[1].Value) }
    # Quote-stripped twin (F7): 'C:\"Windows"\System32\...' hides the write target
    # from BOTH regexes above (the quote cuts the bare token at 'C:\' and the
    # quoted group needs the quote right after the drive). On the stripped text
    # there are no quote characters left: the bare token regex sees the real path.
    if ($deq -ne $Command) {
        foreach ($m in [regex]::Matches($deq, $tokenRe)) { [void]$candidates.Add($m.Groups[1].Value) }
    }
    # C2 (use #3, campaign #3): walk budget over the candidates (BOTH passes),
    # summed ONLY when the twin DIFFERS: with no quotes there is no second pass,
    # and adding the identical text would ANTICIPATE the limit (a command of
    # exactly ScanBudgetMaxChars chars was denied fail-closed on a limit never
    # exceeded; found live by the source workspace's boundary case). Via the gate this branch
    # is not reached (the 'scanner-budget' deny triggers first), but the classification
    # is shared with recording and tests: never unlimited walks. Fail-closed:
    # oversize -> deny on the first available candidate (a command whose walk
    # exceeds the budget is not verifiable: it is not granted).
    $budgetText = $Command
    if ($deq -ne $Command) { $budgetText = $Command + ' ' + $deq }
    if ((Get-ScanBudgetVerdict -Text $budgetText) -eq 'oversize') {
        if ($candidates.Count -gt 0) { return $candidates[0] }
        return ''
    }
    $seen = 0
    foreach ($tok in $candidates) {
        $seen++
        if ($seen -gt 8) { break }
        if ($tok.StartsWith('~')) { $tok = Join-Path $script:HomeDir $tok.Substring(2) }
        $prot = Test-ProtectedWrite -Path $tok -ProjectDir $ProjectDir
        if ($prot) { return $tok }
        # Parity with the tool-file channel (finding #25 on the shell channel): SENSITIVE
        # FILES too (.env, keys, credentials, .ssh/.aws/... segments) are protected
        # on write via shell. Before, `Set-Content ~/.ssh/config` passed with no deny
        # nor audit while the Write tool on the same path was denied. Only ABSOLUTE
        # tokens arrive here (drive/UNC/~/inside quotes): relative paths stay out
        # (declared remainder: relative resolution would depend on the process cwd).
        if (Test-SensitivePath -Path $tok) { return $tok }
    }
    return ''
}

# Get-CommandSensitiveTokenHit: DEFINITION MOVED to Hook-Common (M14, campaign #2):
# single copy shared with the recording channel (masking of commands in the logs).
# The gate uses it below identically (runtime resolution from the library dot-source).
# With the library broken the gate path is anyway a recorded fail-open (O2): the
# call is not reachable in the 'lib not parsable' case (fail-open triggers first,
# on Get-HookInput) and, if reached, it falls into the outer catch with an INLINE recorder.

function Get-CommandDeny {
    <# Returns @{Id;Desc} of the first rule that triggers, otherwise $null. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    foreach ($rule in $script:CommandRules) {
        try {
            if ([regex]::IsMatch($Command, $rule.Pattern)) { return @{ Id = $rule.Id; Desc = $rule.Desc } }
        } catch { }
    }
    return $null
}

function Write-Deny {
    param(
        [Parameter(Mandatory)][string]$RuleId,
        [Parameter(Mandatory)][string]$RuleDesc,
        [Parameter(Mandatory)][string]$Tool,
        [AllowEmptyString()][string]$Detail,
        [Parameter(Mandatory)][string]$ProjectDir,
        [Parameter(Mandatory)][string]$EventName
    )
    $reason = 'BLOCKED by the project policy [' + $RuleId + ']: ' + $RuleDesc +
              '. The command is not executed. If you really need it, run it manually outside Claude Code, ' +
              'or remove the rule in .claude/hooks/Block-Destructive.ps1. Audit: .agent/denied-actions.log'
    [void](Add-DeniedRecord -ProjectDir $ProjectDir -Tool $Tool -Detail $Detail -RuleId $RuleId)
    Write-HookJson -EventName $EventName -PermissionDecision 'deny' -Reason $reason
}

# ---------------------------------------------------------------------------
# Main (fail-open on infrastructure errors, with recording)
# ---------------------------------------------------------------------------
$projectDir = $env:CLAUDE_PROJECT_DIR
if (-not $projectDir) { $projectDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }

try {
    . (Join-Path $PSScriptRoot 'Hook-Common.ps1')

    # stdin must be read ONCE only: it is a stream, not a re-readable value.
    $projectDir = Get-ProjectDir -InputObject $null
    $inState = Get-HookInput -Detailed

    # Payload PRESENT but unreadable: the gate cannot decide -> fail-open, but
    # RECORDED (a gate that silently disables itself is the most dangerous failure:
    # it seems to work while it no longer filters anything).
    if ($inState.ParseError) {
        [void](Add-FailureRecord -ProjectDir $projectDir -Component 'Block-Destructive' -Command 'stdin' -ErrorText 'unreadable JSON payload: PreToolUse gate NOT applied (recorded fail-open)' -Cause 'input-unreadable')
        exit 0
    }
    if (-not $inState.HadInput) { exit 0 }

    $input0 = $inState.Object
    $projectDir = Get-ProjectDir -InputObject $input0

    # tool_name missing but the payload is readable: continue as 'unknown' instead of
    # exiting silently (fail-closed: the rules stay applied).
    $tool = [string](Get-JsonProp -Object $input0 -Name 'tool_name' -Default 'unknown')
    $ti = Get-JsonProp -Object $input0 -Name 'tool_input'

    if ($tool -eq 'Bash' -or $tool -eq 'PowerShell' -or $tool -eq 'unknown') {
        $cmd = [string](Get-JsonProp -Object $ti -Name 'command' -Default '')
        # Fail-closed on out-of-scale payload: a huge command can NOT be
        # verified reliably (the regexes scan a limited text).
        if ($cmd.Length -gt 200000) {
            Write-Deny -RuleId 'input-oversize' -RuleDesc 'command payload too large to be verified (fail-closed)' -Tool $tool -Detail ('command len=' + $cmd.Length) -ProjectDir $projectDir -EventName 'PreToolUse'
            exit 0
        }
        # C2 (campaign #3): scan walk budget, specular to input-oversize.
        # A command with tokens that exceed the budget is not verifiable in full
        # (sensitive scanner + protected areas): fail-closed — never let a
        # command pass after the verification was abandoned for cost.
        # F7: the ESTIMATE is the scanner's own one (raw + quote-stripped twin,
        # summed ONLY when they differ), not the raw length alone: the deny lands
        # here with the honest 'scanner-budget' label instead of downstream as a
        # '[SCANNER-OVERSIZE]' hit labelled 'secret-token'.
        $deqGate = Get-DequotedCommandText -Command $cmd
        $budgetGate = $cmd
        if ($deqGate -ne $cmd) { $budgetGate = $cmd + ' ' + $deqGate }
        if ((Get-ScanBudgetVerdict -Text $budgetGate) -eq 'oversize') {
            Write-Deny -RuleId 'scanner-budget' -RuleDesc 'scan walk over budget (fail-closed: command not verifiable in full)' -Tool $tool -Detail ('command len=' + $cmd.Length) -ProjectDir $projectDir -EventName 'PreToolUse'
            exit 0
        }
        $hit = Get-CommandDeny -Command $cmd
        if ($hit) {
            Write-Deny -RuleId $hit.Id -RuleDesc $hit.Desc -Tool $tool -Detail $cmd -ProjectDir $projectDir -EventName 'PreToolUse'
            exit 0
        }
        # H1 (campaign #2): reference to a sensitive file via shell, classified
        # by the SAME tables as the tool-file channel (see Get-CommandSensitiveTokenHit):
        # it closes the entries that the regex catch-all — hand copy — did not enumerate.
        $sensTok = Get-CommandSensitiveTokenHit -Command $cmd
        if ($sensTok) {
            Write-Deny -RuleId 'secret-token' -RuleDesc 'reference to a sensitive file/path in the command (classification from the sensitive tables)' -Tool $tool -Detail ('token: ' + $sensTok) -ProjectDir $projectDir -EventName 'PreToolUse'
            exit 0
        }
        # SHELL write to protected areas: before, the command branch NEVER
        # called Test-ProtectedWrite (class: check applied only to tool-files).
        $hitPath = Get-CommandProtectedPathHit -Command $cmd -ProjectDir $projectDir
        if ($hitPath) {
            Write-Deny -RuleId 'protected-path-write' -RuleDesc ('write to a protected area or to a sensitive file via shell') -Tool $tool -Detail ('path: ' + $hitPath) -ProjectDir $projectDir -EventName 'PreToolUse'
            exit 0
        }
        # 'unknown' continues: the payload may still contain tool_input.file_path.
        if ($tool -ne 'unknown') { exit 0 }
    }

    # Tools that operate on files. The target field depends on the tool: file_path
    # (Read/Write/Edit), notebook_path (NotebookEdit), path (Grep/Glob). But the target
    # may be ELSEWHERE (class F4): Glob selects with `pattern` and Grep filters with
    # `glob` — `{glob:'**/.env'}` or `{pattern:'**/id_rsa'}` did NOT pass through any inspected
    # field and therefore were never classified. (Grep's `pattern` is a
    # search regex, not a path: it is inspected only for Glob, where it IS the path-glob.)
    $filePath = [string](Get-JsonProp -Object $ti -Name 'file_path' -Default '')
    if (-not $filePath) { $filePath = [string](Get-JsonProp -Object $ti -Name 'notebook_path' -Default '') }
    if (-not $filePath) { $filePath = [string](Get-JsonProp -Object $ti -Name 'path' -Default '') }
    $selGlob = [string](Get-JsonProp -Object $ti -Name 'glob' -Default '')
    $selPattern = ''
    if ($tool -ieq 'Glob') { $selPattern = [string](Get-JsonProp -Object $ti -Name 'pattern' -Default '') }

    # ONE sensitive target field is enough to deny (whoever reads `**/.env` reads .env).
    $sensitiveHit = ''
    $sensitiveLabel = ''
    foreach ($cand in @($filePath, $selGlob, $selPattern)) {
        if (-not $cand) { continue }
        if (Test-SensitivePath -Path $cand) { $sensitiveHit = $cand; $sensitiveLabel = Get-SensitiveLabel -Path $cand; break }
    }
    if ($sensitiveLabel) {
        $verb = 'access'
        if ($tool -eq 'Write' -or $tool -eq 'Edit' -or $tool -eq 'NotebookEdit' -or $tool -eq 'MultiEdit') { $verb = 'modification' }
        $reason = 'BLOCKED by the project policy [sensitive-file]: ' + $verb + ' of a file classified as sensitive ("' + $sensitiveLabel + '"). ' +
                  'Rule: the .env/.env.* files, keys, credentials and tokens are not read, printed, archived or' + ' modified automatically. ' +
                  'Audit: .agent/denied-actions.log'
        [void](Add-DeniedRecord -ProjectDir $projectDir -Tool $tool -Detail ($sensitiveLabel + ' <= ' + $sensitiveHit) -RuleId 'sensitive-file')
        Write-HookJson -EventName 'PreToolUse' -PermissionDecision 'deny' -Reason $reason
        exit 0
    }

    if (-not $filePath) { exit 0 }

    # Only the tools that WRITE: Grep/Glob have a "path" but modify nothing.
    if ($tool -eq 'Write' -or $tool -eq 'Edit' -or $tool -eq 'NotebookEdit' -or $tool -eq 'MultiEdit' -or $tool -eq 'unknown') {
        $prot = Test-ProtectedWrite -Path $filePath -ProjectDir $projectDir
        if ($prot) {
            Write-Deny -RuleId $prot.Id -RuleDesc $prot.Desc -Tool $tool -Detail $filePath -ProjectDir $projectDir -EventName 'PreToolUse'
            exit 0
        }
    }

    exit 0
} catch {
    # Declared FAIL-OPEN: an error in the hook must not block the session.
    # The recorder here is INLINE (no dependency on Hook-Common): if it is exactly the
    # library that is broken, the old catch that re-dot-sourced it failed
    # again and the fail-open stayed SILENT (class: recording that depends
    # on the thing that just failed). The message stays visible to the user.
    try {
        $pd = $env:CLAUDE_PROJECT_DIR
        if (-not $pd) { $pd = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
        $agentDir = Join-Path $pd '.agent'
        if (Test-Path -LiteralPath $agentDir) {
            $msg = $_.Exception.Message -replace '\r?\n', ' '
            $msg = $msg -replace '\|', '/'
            # B2 (campaign #3, zero-dependency inline: here the library may be the
            # very cause of the error): the cut does not split a surrogate pair.
            if ($msg.Length -gt 160) {
                $cut = 160
                if ([char]::IsHighSurrogate($msg[$cut - 1]) -and [char]::IsLowSurrogate($msg[$cut])) { $cut-- }
                $msg = $msg.Substring(0, $cut) + '...'
            }
            $row = '| ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + ' | Block-Destructive | hook | ' + $msg + ' | hook-error (fail-open, recorder inline) | rerun |' + "`n"
            # L1 (campaign #2, class LA): the row goes through Hook-Inline.ps1 (gate
            # mutex + retry on transient contention). Library missing or broken ->
            # bare append as before: never worse than before, and here an exception
            # is never propagated.
            $inlineRowWritten = $false
            $inlineLib = Join-Path $PSScriptRoot 'Hook-Inline.ps1'
            if (Test-Path -LiteralPath $inlineLib) {
                try { . $inlineLib } catch { }
            }
            if (Get-Command -Name 'Add-InlineRow' -CommandType Function -ErrorAction SilentlyContinue) {
                try { $inlineRowWritten = [bool](Add-InlineRow -Path (Join-Path $agentDir 'FAILURES.md') -Row $row -ProjectDir $pd) } catch { $inlineRowWritten = $false }
            }
            if (-not $inlineRowWritten) {
                $enc = New-Object System.Text.UTF8Encoding($false)
                [System.IO.File]::AppendAllText((Join-Path $agentDir 'FAILURES.md'), $row, $enc)
            }
        }
        $json = '{"systemMessage":"WARNING: policy hook failed - the gate was NOT applied to this call (fail-open recorded in .agent/FAILURES.md)."}'
        [Console]::Out.Write($json)
    } catch { }
    exit 0
}
