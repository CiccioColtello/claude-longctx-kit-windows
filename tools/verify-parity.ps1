#requires -Version 5.1
# verify-parity.ps1 -- verifies that the core/ directory of the two longctx kit repos
# is BYTE-IDENTICAL (SHA256 per file). core/ is the only part that MUST stay
# identical between the Windows and the macOS variant: OS differences live only
# in the root files (installers, docs) and in the two settings examples.
#
# Usage:
#   verify-parity.ps1 -PathA "D:\claude-longctx-kit-windows"
#   verify-parity.ps1 -PathA <repoA> -PathB <repoB>
# If -PathB is omitted it is deduced by replacing the trailing suffix "windows" with "mac".
# Exit: 0 = PARITY OK | 1 = PARITY FAIL | 2 = usage error.
param(
    [Parameter(Mandatory)][string]$PathA,
    [string]$PathB = ''
)
$ErrorActionPreference = 'Stop'

function Get-Sha256Hex {
    # SHA256 via .NET: robust even where Get-FileHash is not resolvable
    # (same helper as install.ps1/verify.ps1 and core/lib/merge-claude-settings.ps1).
    # Throws on unreadable input: this tool must never report parity it did not prove.
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try { return [BitConverter]::ToString($sha.ComputeHash($fs)).Replace('-', '') }
        finally { $fs.Dispose() }
    } finally { $sha.Dispose() }
}

if (-not $PathB) {
    $candidate = $PathA -replace 'windows\s*$', 'mac'
    if ($candidate -eq $PathA) {
        Write-Host "verify-parity: -PathB not deducible from PathA ('$PathA'). Pass it explicitly."
        exit 2
    }
    $PathB = $candidate
}

$coreA = [System.IO.Path]::Combine($PathA, 'core')
$coreB = [System.IO.Path]::Combine($PathB, 'core')
foreach ($p in @($coreA, $coreB)) {
    if (-not (Test-Path -LiteralPath $p)) { Write-Host "verify-parity: core/ missing: $p"; exit 2 }
}

function Get-RelMap {
    param([string]$Root)
    $map = @{}
    foreach ($f in (Get-ChildItem -LiteralPath $Root -Recurse -File | Sort-Object FullName)) {
        $rel = $f.FullName.Substring($Root.Length).TrimStart('\', '/') -replace '\\', '/'
        $map[$rel] = $f.FullName
    }
    return $map
}

$mapA = Get-RelMap -Root $coreA
$mapB = Get-RelMap -Root $coreB

$onlyA = @($mapA.Keys | Where-Object { -not $mapB.ContainsKey($_) } | Sort-Object)
$onlyB = @($mapB.Keys | Where-Object { -not $mapA.ContainsKey($_) } | Sort-Object)
$diff = 0; $same = 0
foreach ($rel in ($mapA.Keys | Sort-Object)) {
    if (-not $mapB.ContainsKey($rel)) { continue }
    $ha = Get-Sha256Hex -Path $mapA[$rel]
    $hb = Get-Sha256Hex -Path $mapB[$rel]
    if ($ha -eq $hb) { $same++ } else { $diff++; Write-Host ("  DIFFERENT: {0}" -f $rel) }
}

foreach ($rel in $onlyA) { Write-Host ("  ONLY IN A: {0}" -f $rel) }
foreach ($rel in $onlyB) { Write-Host ("  ONLY IN B: {0}" -f $rel) }

$total = $mapA.Count
if ($diff -eq 0 -and $onlyA.Count -eq 0 -and $onlyB.Count -eq 0) {
    Write-Host ("PARITY OK: {0} core files identical byte-by-byte ({1} vs {2})" -f $same, $PathA, $PathB)
    exit 0
}
Write-Host ("PARITY FAIL: {0} identical, {1} different, {2} only-in-A, {3} only-in-B (total A={4})" -f $same, $diff, $onlyA.Count, $onlyB.Count, $total)
exit 1
