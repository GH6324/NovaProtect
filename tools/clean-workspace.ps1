[CmdletBinding(SupportsShouldProcess)]
param([switch]$Apply)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)).TrimEnd('\')
$version = (Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim()
$keep = @('private-signing', 'client-installer', 'novaprotect-vmprotect-2.0.7-final-20261015')
$candidates = [Collections.Generic.List[string]]::new()
foreach ($item in Get-ChildItem -LiteralPath (Join-Path $root 'artifacts') -Force) {
    if ($item.PSIsContainer -and $keep -contains $item.Name) { continue }
    if (-not $item.PSIsContainer -and $item.Name -like 'NovaProtect-Website-*.zip') {
        $candidates.Add($item.FullName)
        continue
    }
    if ($item.Name -match '^(website-(bundle|linux-x64|publish)-|vmp-|vmprotect-|novaprotect-vmprotect-|installer-2\.0\.[0-6]$|install-test-|installed-ui-|language-support-|ui-(verification|vmp)-|test-only-|planner-runtime-|account-runtime-|client-gates-|pre-|method-dump$|NovaPack-VMProtect-Setup-|NovaProtect-Website-2\.0\.)') {
        $candidates.Add($item.FullName)
    }
}
foreach ($relative in @(
    'output','ui\bin','ui\obj','website\bin','website\obj','website\Pages','website\Properties',
    'website\Services','website\wwwroot','website\deploy\__pycache__','website\deploy\novaprotect.service','website\website.csproj',
    'tests\update-client-smoke\bin','tests\update-client-smoke\obj','tests\planner-smoke\bin',
    'tests\planner-smoke\obj','.playwright-cli','_flagtest','_mtest','_poc','_t_prot'
    ,'evidence\vmprotect-runtime'
    ,'evidence\pre-php-install-refactor-20261015-042418'
    ,'evidence\pre-php-refactor-20261015'
)) {
    $path = Join-Path $root $relative
    if (Test-Path -LiteralPath $path) { $candidates.Add($path) }
}

# The source fixtures remain useful, but the old regression corpus contains
# hundreds of generated PE files, copied SDK DLLs, dumps and debugger output.
# None of these files are shipped by NovaProtect or required by the PHP
# website package, so remove only generated extensions/directories while
# retaining the C/C++/C#/Rust/Go/VB fixture sources and lightweight tests.
foreach ($relative in @('tests\__pycache__', 'tests\dbg', 'tools\__pycache__')) {
    $path = Join-Path $root $relative
    if (Test-Path -LiteralPath $path) { $candidates.Add($path) }
}
foreach ($item in Get-ChildItem -LiteralPath (Join-Path $root 'tests') -Directory -Force -ErrorAction SilentlyContinue) {
    if ($item.Name.StartsWith('_', [StringComparison]::Ordinal)) { $candidates.Add($item.FullName) }
}
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $root 'tests') -File -Force -ErrorAction SilentlyContinue) {
    if ($file.Extension -in @('.exe', '.pdb', '.dll', '.txt', '.dat', '.bin', '.bak', '.o', '.pyc')) {
        $candidates.Add($file.FullName)
    }
}
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $root 'tests\samples') -Recurse -File -Force -ErrorAction SilentlyContinue) {
    if ($file.Extension -in @('.exe', '.pdb')) { $candidates.Add($file.FullName) }
}
# Compiled debugger/probe helpers are local investigation output, not runtime
# dependencies. Their source is intentionally retained for provenance.
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $root 'tools') -File -Force -ErrorAction SilentlyContinue) {
    if ($file.Extension -eq '.exe') { $candidates.Add($file.FullName) }
}
foreach ($relative in @('tools\np_parse.ps1', 'tools\sects.py', 'tools\_stubextract.bin')) {
    $path = Join-Path $root $relative
    if (Test-Path -LiteralPath $path) { $candidates.Add($path) }
}
foreach ($file in Get-ChildItem -LiteralPath $root -File) {
    if ($file.Extension -in @('.o','.obj','.exe') -or ($file.Name.StartsWith('_') -and $file.Extension -in @('.txt','.log'))) { $candidates.Add($file.FullName) }
}
foreach ($relative in @('_lea_chk.cpp')) {
    $path = Join-Path $root $relative
    if (Test-Path -LiteralPath $path) { $candidates.Add($path) }
}
foreach ($relative in @('artifacts\NovaProtect-2.0.3-installed-icon.png')) {
    $path = Join-Path $root $relative
    if (Test-Path -LiteralPath $path) { $candidates.Add($path) }
}
foreach ($relative in @('ui-build-diag.txt','stdout.txt','stderr.txt')) {
    $path = Join-Path $root $relative
    if (Test-Path -LiteralPath $path) { $candidates.Add($path) }
}
$rows = foreach ($path in ($candidates | Sort-Object -Unique)) {
    $full = [IO.Path]::GetFullPath($path)
    if (-not $full.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Outside workspace: $full" }
    $item = Get-Item -Force -LiteralPath $full
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing reparse point: $full" }
    if ($item.PSIsContainer) {
        $files = @(Get-ChildItem -LiteralPath $full -Recurse -Force -File)
        $links = @(Get-ChildItem -LiteralPath $full -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
        if ($links.Count) { throw "Reparse point under deletion candidate: $full" }
    } else { $files = @($item) }
    [pscustomobject]@{Path=$full; Files=$files.Count; Bytes=($files | Measure-Object Length -Sum).Sum}
}
$report = Join-Path $root ("evidence\cleanup-$version\cleanup-plan.json")
$reportDir = Split-Path -Parent $report
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
$rows | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $report -Encoding utf8
$bytes = ($rows | Measure-Object Bytes -Sum).Sum
Write-Host ('CLEANUP-PLAN {0} paths; {1:N2} GiB logical bytes; report: {2}' -f @($rows).Count,($bytes/1GB),$report)
if ($Apply) {
    foreach ($row in $rows) {
        if ($PSCmdlet.ShouldProcess($row.Path,'Remove reviewed rebuildable/obsolete output')) {
            Remove-Item -LiteralPath $row.Path -Recurse -Force
        }
    }
    $outputPath = Join-Path $root 'output'
    if (Test-Path -LiteralPath $outputPath) {
        Remove-Item -LiteralPath $outputPath -Recurse -Force
    }
    Write-Host 'CLEANUP-APPLIED (source, private-signing, validated 2.0.7 release and installer preserved)'
}
