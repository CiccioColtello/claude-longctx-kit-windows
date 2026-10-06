#requires -Version 5.1
<#
.SYNOPSIS
    LOCAL Ollama client library for the context digest (best-effort, never blocking).
.DESCRIPTION
    PURE LIBRARY, dot-sourced by the hooks (no `param()` block, no CLI mode:
    a param() in a dot-sourced file is re-bound at every dot-source).
    CLI use: `core\scripts\Invoke-Digest.ps1 -Prompt "<text>"` (separate entry point).

    Security rules:
      - Local endpoints only (127.0.0.1 / localhost / ::1). A non-local host is REFUSED:
        the digest must never go through the cloud.
      - No secret is sent: the caller redacts first (Remove-SensitiveContent).
      - Explicit timeout; on expiry it returns Ok=$false with a reason.
      - The local model is not a security authority: it only produces text for the archive.

    Configuration: .agent/ollama.env (KEY=VALUE), otherwise defaults.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:DigestDefaults = [ordered]@{
    OLLAMA_HOST              = 'http://127.0.0.1:11434'
    OLLAMA_DIGEST_MODEL      = 'qwen3:4b'
    OLLAMA_DIGEST_TIMEOUT    = '45'
    OLLAMA_DIGEST_MAX_INPUT  = '60000'
    OLLAMA_CONTEXT_LENGTH    = '32768'
}

function Get-DigestProp {
    <# Safe property access (this library works even without Hook-Common). #>
    [CmdletBinding()]
    param($Object, [Parameter(Mandatory)][string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    if ($null -eq $prop.Value) { return $Default }
    return $prop.Value
}

function Get-OllamaConfig {
    <#
        Reads .agent/ollama.env (if present) and returns a configuration hashtable.
        The file contains only non-secret variables; missing values use the defaults.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectDir)
    $cfg = @{}
    foreach ($k in $script:DigestDefaults.Keys) { $cfg[$k] = $script:DigestDefaults[$k] }

    $envFile = Join-Path (Join-Path $ProjectDir '.agent') 'ollama.env'
    if (Test-Path -LiteralPath $envFile) {
        try {
            foreach ($line in [System.IO.File]::ReadAllLines($envFile, [System.Text.Encoding]::UTF8)) {
                $t = $line.Trim()
                if ($t.Length -eq 0 -or $t.StartsWith('#')) { continue }
                $idx = $t.IndexOf('=')
                if ($idx -lt 1) { continue }
                $key = $t.Substring(0, $idx).Trim()
                $val = $t.Substring($idx + 1).Trim().Trim('"')
                if ($cfg.ContainsKey($key)) { $cfg[$key] = $val }
            }
        } catch {
            # unreadable file: the defaults are used (explicit fallback)
        }
    }
    return $cfg
}

function Test-LocalOllamaHost {
    <#
        Returns $true only for LOCAL endpoints: the name 'localhost' or a loopback
        IP address (IsLoopback: 127.0.0.0/8 and ::1 in any normalized form).
        The comparison is on the PARSED ADDRESS, not on the string: .NET expands
        IPv6 (::1 -> [0000:...:0001]) and a textual comparison got it wrong.
        IsLoopback is a STATIC method of IPAddress: called as an instance property
        ($ip.IsLoopback) it throws under StrictMode and the catch turned it into a false
        refusal of EVERY IP address (real bug, found by re-running the matrix).
        A remote host is refused: the digest must never go through the cloud.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$HostUri)
    try {
        $u = [System.Uri]$HostUri
        $h = $u.Host.ToLowerInvariant()
        if ($h -eq 'localhost') { return $true }
        $ip = $null
        $bare = $h.Trim('[', ']')
        if ([System.Net.IPAddress]::TryParse($bare, [ref]$ip)) { return [System.Net.IPAddress]::IsLoopback($ip) }
        return $false
    } catch {
        return $false
    }
}

function Invoke-OllamaDigest {
    <#
        Generates a digest via the local Ollama.
        Returns an object:
            @{ Ok = $true;  Text = '<digest>'; Model = '...'; ElapsedSec = N }
            @{ Ok = $false; Error = '<reason>'; Model = '...'; ElapsedSec = N }
        Never throws exceptions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$ProjectDir,
        [string]$Instruction = '',
        [int]$TimeoutSec = 0
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $cfg = Get-OllamaConfig -ProjectDir $ProjectDir
    $model = $cfg['OLLAMA_DIGEST_MODEL']

    try {
        $hostUri = $cfg['OLLAMA_HOST']
        if (-not (Test-LocalOllamaHost -HostUri $hostUri)) {
            return @{ Ok = $false; Error = 'non-local Ollama host: digest rejected'; Model = $model; ElapsedSec = 0 }
        }

        $timeout = $TimeoutSec
        if ($timeout -le 0) { $timeout = [int]$cfg['OLLAMA_DIGEST_TIMEOUT'] }
        if ($timeout -le 0) { $timeout = 45 }
        # DECLARED clamp: the digest must fit the PreCompact hook timeout (60s);
        # a higher config value would kill the hook halfway through the digest.
        if ($timeout -gt 45) { $timeout = 45 }
        if ($timeout -lt 5) { $timeout = 5 }

        $maxInput = [int]$cfg['OLLAMA_DIGEST_MAX_INPUT']
        if ($maxInput -le 0) { $maxInput = 60000 }
        if ($Text.Length -gt $maxInput) {
            # EXPLICIT truncation: the model must know that the material is partial.
            # B2 (campaign #3, inline: this script has zero dependencies on the
            # library): the head cut does not split a surrogate pair.
            $k = $Text.Length - $maxInput
            if ([char]::IsLowSurrogate($Text[$k])) { $k++ }
            $Text = '[truncated ' + $k + " leading characters]`n" + $Text.Substring($k)
        }

        if ([string]::IsNullOrWhiteSpace($Text)) {
            return @{ Ok = $false; Error = 'empty input'; Model = $model; ElapsedSec = 0 }
        }

        if ([string]::IsNullOrWhiteSpace($Instruction)) {
            $Instruction = 'Summarize the material in English, at most 350 words, as a bullet list, with these entries: current goal, decisions made, modified files, tests run, open issues, next step. Do not invent: if an entry does not emerge from the material, write "not present".'
        }

        $payload = @{
            model   = $model
            prompt  = $Instruction + "`n`n--- MATERIAL ---`n" + $Text
            stream  = $false
            # qwen3 and "thinking" models: with the reasoning channel active the
            # num_predict budget is spent in the `thinking` field and `response` comes back
            # EMPTY (the digest ALWAYS failed with "empty response from the local model").
            # think=false is verified on Ollama 0.35.1 with qwen3:4b.
            think   = $false
            options = @{
                temperature = 0.2
                num_ctx     = [int]$cfg['OLLAMA_CONTEXT_LENGTH']
                num_predict = 1200
            }
        } | ConvertTo-Json -Depth 5 -Compress

        $uri = $hostUri.TrimEnd('/') + '/api/generate'
        # EXPLICIT charset=utf-8 (class F20): with 'application/json' alone PS 5.1 uses
        # ISO-8859-1 for the body and every non-ASCII character in the prompt reached the
        # model as mojibake (transcript accents/emoji). The body is already UTF-8.
        # H5 (campaign #2): -MaximumRedirection 0. AllowAutoRedirect (default) followed
        # redirects and the context POST RE-STARTED towards the Location: with 307 the body
        # (435 bytes in the repro with two local TCP servers) reached a SECOND endpoint
        # and its response was used as the digest (Ok=$true, 'H5-REDIRECT-FOLLOWED').
        # Any redirect now FAILS CLOSED (the catch -> Ok=$false): the digest must
        # never leave the intended channel, whatever the Location.
        $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $payload -ContentType 'application/json; charset=utf-8' -TimeoutSec $timeout -MaximumRedirection 0
        $out = [string](Get-DigestProp -Object $resp -Name 'response' -Default '')
        $sw.Stop()
        if ([string]::IsNullOrWhiteSpace($out)) {
            # Useful diagnosis: if the model produced only `thinking`, the flag
            # think=false was not applied (model/API that does not support it).
            $thinkTxt = [string](Get-DigestProp -Object $resp -Name 'thinking' -Default '')
            $why = 'empty response from the local model'
            if (-not [string]::IsNullOrWhiteSpace($thinkTxt)) { $why = 'empty response: the model used only the reasoning channel (think not disabled)' }
            return @{ Ok = $false; Error = $why; Model = $model; ElapsedSec = [int]$sw.Elapsed.TotalSeconds }
        }
        # L2 (campaign #2, class LF): done_reason='length' = the model exhausted
        # num_predict and the response is TRUNCATED halfway — before, a truncated digest
        # was indistinguishable from a complete one. The text now declares it
        # (counter-proof: done_reason='stop' or absent add NOTHING).
        $outText = $out.Trim()
        $doneReason = [string](Get-DigestProp -Object $resp -Name 'done_reason' -Default '')
        if ($doneReason -eq 'length') {
            $outText = $outText + "`n(digest TRUNCATED: token limit reached - partial material)"
        }
        return @{ Ok = $true; Text = $outText; Model = $model; ElapsedSec = [int]$sw.Elapsed.TotalSeconds }
    } catch {
        $sw.Stop()
        return @{ Ok = $false; Error = ('Ollama error: ' + $_.Exception.Message); Model = $model; ElapsedSec = [int]$sw.Elapsed.TotalSeconds }
    }
}

function Test-OllamaAvailable {
    <# Quick (non-blocking) check that the local Ollama responds. Never throws. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectDir, [int]$TimeoutSec = 5)
    try {
        $cfg = Get-OllamaConfig -ProjectDir $ProjectDir
        if (-not (Test-LocalOllamaHost -HostUri $cfg['OLLAMA_HOST'])) { return $false }
        $uri = $cfg['OLLAMA_HOST'].TrimEnd('/') + '/api/tags'
        [void](Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec $TimeoutSec)
        return $true
    } catch {
        return $false
    }
}
