#requires -Version 5.1
<#
.SYNOPSIS
    Filter library for agent text, logs and transcripts: secret redaction + length limiting.
.DESCRIPTION
    PURE LIBRARY, meant to be dot-sourced by Hook-Common.ps1 or by the hooks.
    It does NOT declare a `param()` block and has NO CLI mode: a param() in a
    dot-sourced file gets rebound at every dot-source (even by another
    library), with unpredictable outcomes. The bug class is eliminated at the root.

    Exposed functions:
        Remove-SensitiveContent  -Text                  -> redacted text
        Get-RedactionFindings    -Text                  -> names of the rules that fired
        Limit-Text               -Text -Max [-KeepTail] -> text limited with a marker
        Get-TextWindow           -Text [-Offset] [-Length]

    CLI usage: `core\scripts\Filter-File.ps1 -Path <file>` (separate entry point).
.NOTES
    No content is transmitted anywhere else by this script: it is a pure local filter.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Redaction rules (applied in order; the first one that fires wins on the text)
# ---------------------------------------------------------------------------
$script:RedactionRules = @(
    @{ Id = 'private_key_block'; Pattern = '(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----'; Replace = '[REDACTED:PRIVATE_KEY]' },
    # keyvalue_secret v2 — covers the shapes that v1 let SURVIVE (findings #2/#17):
    #   - QUOTED key in JSON ({"password": "..."}): v1 stopped at the '"' after
    #     the keyword (it needed \s*[:=] but found '"') -> no match;
    #   - snake_case/prefixed keys (DB_PASSWORD, AWS_SECRET_ACCESS_KEY, MY_TOKEN):
    #     the \b before the keyword does not fire between '_' and a letter -> no match;
    #   - multi-token values (Authorization: Bearer <token>): v1 redacted only the
    #     scheme ("Bearer") and left the token in clear;
    #   - values inside quotes ('abc', "abc") now consumed in full.
    # Prefix/suffix limited to {0,24} characters: real keys are short and the
    # scan stays linear even on long texts (no pathological backtracking).
    @{ Id = 'keyvalue_secret';  Pattern = '(?i)(["\x27]?[A-Za-z0-9_.-]{0,24}(?:api[_-]?key|apikey|client[_-]?secret|secret|password|passwd|pwd|token|bearer|authorization|private[_-]?key|seed[_-]?phrase|mnemonic|passphrase)[A-Za-z0-9_.-]{0,24}["\x27]?)\s*[:=]\s*(?:"[^"\r\n]*"|\x27[^\x27\r\n]*\x27|(?:Bearer|Basic|Token)\s+\S+|\S+)'; Replace = '$1=[REDACTED]' },
    @{ Id = 'url_credentials';  Pattern = '(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+):([^/\s@]+)@'; Replace = '$1:[REDACTED]@' },
    @{ Id = 'telegram_bot_token'; Pattern = '\b\d{8,10}:[A-Za-z0-9_-]{30,}\b'; Replace = '[REDACTED:TELEGRAM_TOKEN]' },
    @{ Id = 'jwt';              Pattern = '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'; Replace = '[REDACTED:JWT]' },
    @{ Id = 'aws_access_key';   Pattern = '\b(AKIA|ASIA)[0-9A-Z]{16}\b'; Replace = '[REDACTED:AWS_KEY]' },
    @{ Id = 'google_api_key';   Pattern = '\bAIza[0-9A-Za-z_\-]{30,}\b'; Replace = '[REDACTED:GOOGLE_KEY]' },
    @{ Id = 'github_token';     Pattern = '\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b'; Replace = '[REDACTED:GITHUB_TOKEN]' },
    @{ Id = 'slack_token';      Pattern = '\bxox[baprs]-[A-Za-z0-9-]{10,}\b'; Replace = '[REDACTED:SLACK_TOKEN]' },
    # openai_style_key v2: modern formats contain inner '-' (sk-ant-api03-*,
    # sk-proj-*): [A-Za-z0-9]{20,} does not cross the hyphen and the key stayed in
    # clear (finding #26). The '-' character is now allowed in the token tail.
    @{ Id = 'openai_style_key'; Pattern = '\b(?:sk|pk|rk)-[A-Za-z0-9_-]{20,}\b'; Replace = '[REDACTED:API_KEY]' },
    @{ Id = 'long_hex';         Pattern = '\b[0-9a-fA-F]{64,}\b'; Replace = '[REDACTED:HEX64]' },
    @{ Id = 'long_base64';      Pattern = '\b[A-Za-z0-9+/]{60,}={0,2}\b'; Replace = '[REDACTED:B64]' }
)

function Remove-SensitiveContent {
    <# Applies all redaction rules. Does not throw exceptions: on error it returns the text it received. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $result = $Text
    foreach ($rule in $script:RedactionRules) {
        try { $result = [regex]::Replace($result, $rule.Pattern, $rule.Replace) } catch { }
    }
    return $result
}

function Get-RedactionFindings {
    <#
        ALWAYS returns an array of strings (possibly empty) with the names of the
        rules that found something: for reporting, never the content.
        The array is never unrolled into the pipeline (',' operator): with 0 or 1
        element the caller still receives an array, so `.Count` is always
        valid even under Set-StrictMode -Version Latest.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $found = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrEmpty($Text)) { return , ([string[]]@()) }
    foreach ($rule in $script:RedactionRules) {
        try {
            if ([regex]::IsMatch($Text, $rule.Pattern)) { [void]$found.Add($rule.Id) }
        } catch { }
    }
    return , ([string[]]$found.ToArray())
}

function Limit-Text {
    <#
        Limits the text length by adding an explicit marker.
        -KeepTail: keeps the TAIL (useful for logs) instead of the head.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][int]$Max,
        [switch]$KeepTail
    )
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    if ($Max -le 0 -or $Text.Length -le $Max) { return $Text }
    # B2 (campaign #3, inline: Filter-AgentText has ZERO dependencies on Hook-Common):
    # the cut never splits a surrogate pair (emoji/supplementary).
    if ($KeepTail) {
        $k = $Text.Length - $Max
        if ([char]::IsLowSurrogate($Text[$k])) { $k++ }
        return '[truncated ' + $k + " leading characters]`n" + $Text.Substring($k)
    }
    $k = $Max
    if ([char]::IsHighSurrogate($Text[$k - 1]) -and [char]::IsLowSurrogate($Text[$k])) { $k-- }
    return $Text.Substring(0, $k) + "`n[truncated " + ($Text.Length - $k) + ' trailing characters]'
}

function Get-TextWindow {
    <# Safe [Offset, Offset+Length) window, with a marker if the text was cut. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [int]$Offset = 0,
        [int]$Length = 1200
    )
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    if ($Offset -lt 0) { $Offset = 0 }
    if ($Offset -ge $Text.Length) { return '' }
    # B2 (campaign #3, inline zero dependencies): the window boundaries must not
    # split a surrogate pair (neither at the head nor at the tail).
    if ($Offset -gt 0 -and [char]::IsLowSurrogate($Text[$Offset])) { $Offset++ }
    if ($Offset -ge $Text.Length) { return '' }
    $len = [Math]::Min($Length, $Text.Length - $Offset)
    if ($len -gt 0 -and ($Offset + $len) -lt $Text.Length -and [char]::IsHighSurrogate($Text[$Offset + $len - 1]) -and [char]::IsLowSurrogate($Text[$Offset + $len])) { $len-- }
    $slice = $Text.Substring($Offset, $len)
    if ($Offset + $len -lt $Text.Length) { $slice += "`n[text truncated]" }
    return $slice
}
