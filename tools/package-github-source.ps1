# NovaProtect GitHub source package.
#
# Produces artifacts/github-source/NovaProtect-<version>-source.zip: a public
# snapshot of the *non-core* tree. Core protection IP (the VM engine, the
# wire interpreter, the revirtualizer, the crypto layers, the stub ASM and the
# internal reverse-engineering tooling) is deliberately absent - the product is
# proprietary and only the integration surface, the WinUI client, the website
# and the release tooling are published.
#
# The zip is written in place (no staging copy, no deletes): entries are
# streamed straight from the workspace sources.
[CmdletBinding()]
param(
  [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$tools = $PSScriptRoot
$root = [IO.Path]::GetFullPath((Split-Path -Parent $tools)).TrimEnd('\')
$utf8 = [Text.UTF8Encoding]::new($false)

function Write-Step([string]$message) { Write-Host "==> $message" }

$clientVersion = (Get-Content -Raw -LiteralPath (Join-Path $root 'VERSION')).Trim()
if ($clientVersion -notmatch '^\d+\.\d+\.\d+$') { throw "VERSION must be MAJOR.MINOR.PATCH, got '$clientVersion'" }

& (Join-Path $tools 'version.ps1') -Action Check
if ($LASTEXITCODE -ne 0) { throw 'version policy check failed' }

if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root 'artifacts\github-source' }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$packageName = "NovaProtect-$clientVersion"
$zipPath = Join-Path $OutputDirectory "$packageName-source.zip"

# ---------------------------------------------------------------------------
# Core protection IP: never published, at any depth.
# These are the directories whose entire content is proprietary. Anything the
# public snapshot still needs from them is provided as a generated stand-in
# (see $generated below) so the published tree stays coherent.
# ---------------------------------------------------------------------------
$coreDirs = @(
  'src', 'include', 'runtime', 'tests', 'docs\marketing-build'
)

# Directories never shipped (matched as a path segment at any depth).
$excludeDirs = @(
  '.git', '.vs', '.idea', '.vscode', '.playwright-cli',
  'artifacts', 'output', '_wtest', '_icontest', 'evidence',
  '__pycache__', 'bin', 'obj', 'App_Data'
)
# Directories matched by full relative path (repo-specific scratch).
# NOTE: this script is intentionally stored without a BOM, and Windows
# PowerShell 5.1 decodes a BOM-less UTF-8 file as ANSI. A non-ASCII literal here
# would therefore never match and would fail silently - use ASCII wildcards
# (the marketing folder has a CJK name) or match on a stable ASCII marker.
$excludePaths = @(
  'tests\_reg',
  'docs\archive',
  # Commercial VMProtect SDK: licensed binaries, never redistributable. The
  # public tree only needs the marker macro, which is re-emitted separately.
  'third_party\vmprotect'
)
# Top-level folders whose names are not ASCII are matched through their file
# extension instead of their path (see Test-ExcludedFile). Marketing copy and
# Office documents are never part of a source snapshot.
$excludeExtensionsAnywhere = @('.docx', '.doc', '.pptx', '.xlsx', '.pdf')
# Any path segment containing non-ASCII characters is excluded: such folders are
# local marketing material, and depending on their literal name would break on
# this file's BOM-less ANSI decoding.
function Test-HasNonAsciiSegment([string]$relative) {
  foreach ($segment in $relative.Replace('/', '\').Split('\')) {
    foreach ($ch in $segment.ToCharArray()) { if ([int]$ch -gt 127) { return $true } }
  }
  return $false
}
# Internal reverse-engineering / debugging tooling: names the VM internals and
# the protection flow. Only the release tooling under tools/ is published.
$excludeToolFiles = @(
  'build-regression-core.ps1', 'clean-workspace.ps1', 'cpuidprobe.cpp',
  'dbg32.cpp', 'dbg32b.cpp', 'dbgb.cpp', 'dbgc.cpp', 'dbgd.cpp', 'dbgx64.cpp',
  'debugrun.cpp', 'dump_np.js', 'dump_np.py', 'markchk.cpp', 'memchk.cpp',
  'memdump.cpp', 'noaslr.js', 'nonx.js', 'npdbg.cpp', 'npdbg2.cpp',
  'peb3.cpp', 'pebprobe.cpp', 'pebprobe2.cpp', 'probe2.cpp', 'rtinspect.cpp',
  'trace64.cpp', 'trc.cpp', 'verify_unpack.cpp', 'vmdbg.cpp', 'vmdiag.cpp',
  'vmeval.cpp', 'check_pe_icons.py', 'pedump.ps1'
)
# Internal docs that describe the wire ISA, the trailer layout and the
# revirtualization design.
$excludeDocFiles = @(
  'engine-redesign.md', 'implementation-status.md', 'protection-flow.mmd',
  'rea-analysis-snapshot.json', 'competitor-analysis.md', 'experience-index.md',
  'release-flow-2.0.7.mmd', 'marketing-fact-check-zh-CN.md',
  # Verification reports and the status log quote the runtime's internal state
  # layout (trailer offsets, guest-dispatch semantics, register permutation).
  'verification-report-2026-10-14.md', 'verification-report-2026-10-15.md',
  'verification-report-2026-10-22.md',
  'verification-report-2026-10-22-function-protection.md',
  'field-journal-2026-10-14.md', 'field-journal-2026-10-15.md',
  'installer-fix-report-2026-10-15.md'
)
# File name patterns never shipped.
$excludeFiles = @(
  'NovaProtect.Engine.exe', 'NovaProtect.ManagedHost.exe',
  'VMProtectSDK64.dll', 'VMProtectSDK64.a', 'VMProtectSDK64.lib',
  'hostname32.obj', 'vm_target.o',
  'tests\VMProtectSDK.h', 'tests\VMProtectSDK32.h',
  'tests\VMProtectSDK64.dll', 'tests\hostname32.exe',
  'tests\test_target.exe', 'tests\vm_target.exe',
  'runtime\_*', 'tests\_*',
  'client-integrity.key.xml',
  '_regress_out.txt', '_regress_icon.txt', '_writetest.txt',
  '*.dbg_bak', '*.check', '*.real', 'stub_blob32_dbg.inc',
  '*.pdb', '*.map', '*.log', '*.vmprotect.log',
  '*.tmp', '*.user', '*.suo', 'Thumbs.db', 'desktop.ini', '.DS_Store',
  '*.vmp', '*.pfx', '*.snk', '*.p12', '*.private.pem', 'id_rsa*', '.env',
  '*.novaprotect-build.json', '*.novaprotect-prebuild.json',
  # The seal records the internal source digest of the released tree; it is
  # meaningless (and confusing) in a snapshot that deliberately omits core IP.
  'version-lock.json',
  # The status log carries the same internal detail as the excluded reports.
  'STATUS.md',
  # C/C++ sources only exist in the published tree for the SDK samples.
  '*.cpp', '*.c', '*.cc', '*.h', '*.hpp', '*.S', '*.o', '*.obj', '*.res',
  '*.ld', '*.ldimg', '*.bin', '*.exe'
)
# Generated runtime intermediates (regenerated by build.ps1 -Stub/-Prot/-Mut).
$runtimeGenerated = @('*.o', '*.bin', '*.res', '*.ldimg')

# Files regenerated as public stand-ins because the real ones live in $coreDirs.
# A published clone must still be able to read the marker macros, so the SDK
# header is re-emitted with the same public byte pattern.
$generated = @{
  'include\vmp_markers.h' = @'
#pragma once
// BUILD-TIME STUB for the public source snapshot.
//
// The production header links the commercial VMProtect SDK import library.
// Core protection sources are not part of this repository, so this stand-in
// keeps the same public surface and compiles the marker call sites to no-ops.
// See sdk/include/novaprotect_sdk.h for the supported integration API.

// NovaProtect SDK marker byte pattern. Stable on disk across releases: the
// packer locates regions by this exact encoding, so neither the compiler nor
// the optimisation level may change it.
#if defined(_WIN64)
#define NOVAPROTECT_BEGIN(name) \
    __asm__ volatile(".byte 0x48,0x8D,0x0D,0x00,0x00,0x00,0x00"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop")

#define NOVAPROTECT_END() \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop")
#else
#define NOVAPROTECT_BEGIN(name)
#define NOVAPROTECT_END()
#endif

// Legacy names remain source compatible; the on-disk pattern is unchanged.
#define NOVAPACK_BEGIN(name) NOVAPROTECT_BEGIN(name)
#define NOVAPACK_END() NOVAPROTECT_END()
'@
}

function Test-ExcludedFile([string]$relative) {
  $normalized = $relative.Replace('/', '\')
  $segments = $normalized.Split('\')
  # Marketing/office documents are never source, wherever they live.
  $ext = [IO.Path]::GetExtension($normalized).ToLowerInvariant()
  if ($excludeExtensionsAnywhere -contains $ext) { return $true }
  if (Test-HasNonAsciiSegment $normalized) { return $true }
  if ($segments.Count -ge 2 -and $segments[0] -eq 'tools' -and $segments.Count -eq 2) {
    if ($excludeToolFiles -contains $segments[-1]) { return $true }
  }
  if ($segments.Count -eq 2 -and $segments[0] -eq 'docs') {
    if ($excludeDocFiles -contains $segments[-1]) { return $true }
  }
  # Only tools/*.ps1 and website/*.sh are allowed to carry the generic code
  # extensions above; everywhere else they belong to the core tree.
  $isTooling = $normalized.StartsWith('tools\') -or $normalized.StartsWith('sdk\')
  $isWebsite = $normalized.StartsWith('website\') -or $normalized.StartsWith('installer\')
  foreach ($pattern in $excludeFiles) {
    # Path-style patterns (containing a separator) match the full relative
    # path; bare patterns match the file name at any depth.
    $pathStyle = $pattern.Contains('\')
    if ($pathStyle) {
      if ($normalized -like $pattern) { return $true }
    } else {
      if ($segments[-1] -like $pattern) {
        if (($pattern -in @('*.cpp','*.c','*.cc','*.h','*.hpp','*.S','*.o','*.obj','*.res','*.ld','*.ldimg','*.bin','*.exe')) -and $isTooling) { continue }
        return $true
      }
    }
  }
  if ($segments.Count -eq 2 -and $segments[0] -eq 'runtime') {
    foreach ($pattern in $runtimeGenerated) {
      if ($segments[-1] -like $pattern) { return $true }
    }
  }
  return $false
}

Write-Step "collecting source files for $packageName"
$collected = New-Object System.Collections.Generic.List[string]
$skipped = 0
$stack = New-Object System.Collections.Stack
$stack.Push('')
while ($stack.Count -gt 0) {
  $relative = $stack.Pop()
  $absolute = if ($relative) { Join-Path $root $relative } else { $root }
  foreach ($entry in [IO.Directory]::GetFileSystemEntries($absolute)) {
    $name = [IO.Path]::GetFileName($entry)
    $child = if ($relative) { "$relative\$name" } else { $name }
    if ([IO.Directory]::Exists($entry)) {
      $segment = $child.Replace('/', '\')
      $isExcludedDir = $false
      foreach ($dir in $excludePaths) {
        if ($segment -eq $dir -or $segment.StartsWith($dir + '\', [StringComparison]::OrdinalIgnoreCase)) { $isExcludedDir = $true; break }
      }
      foreach ($dir in $coreDirs) {
        if ($segment -eq $dir -or $segment.StartsWith($dir + '\', [StringComparison]::OrdinalIgnoreCase)) { $isExcludedDir = $true; break }
      }
      if (-not $isExcludedDir -and ($excludeDirs -notcontains $name)) { $stack.Push($child) }
      else { $skipped++ }
      continue
    }
    if (Test-ExcludedFile $child) { $skipped++; continue }
    $collected.Add($child)
  }
}
# Stand-ins live only in $generated; they are not read from the workspace copy
# (whose real header belongs to the core tree).
foreach ($relative in $generated.Keys) {
  if ($collected -notcontains $relative) { $collected.Add($relative) }
}
$collected.Sort()

# ------------------------------------------------------------ safety gate ---
$banned = @('private-signing', 'client-integrity.key.xml', 'vmprotectsdk', 'id_rsa', '.pfx', '.snk', '.p12', 'id_ed25519')
foreach ($relative in $collected) {
  $lower = $relative.Replace('/', '\').ToLowerInvariant()
  foreach ($token in $banned) {
    if ($lower.Contains($token)) { throw "Refusing to package sensitive path: $relative" }
  }
}

# Core protection sources must be proven absent, not merely unlisted: a change
# to $coreDirs or to Test-ExcludedFile must fail loudly here instead of
# silently publishing the engine.
$forbidden = @(
  'src\vm_engine.cpp', 'src\vm_revirt.cpp', 'src\packer.cpp',
  'src\vm_obfuscate.cpp', 'src\crypto_layers.cpp', 'src\stub_blob.h',
  'src\prot_blob.h', 'src\mutation.cpp', 'src\disasm.cpp',
  'runtime\prot64.c', 'runtime\prot64.S', 'runtime\stub.S', 'runtime\mutkern.S',
  'include\vm_isa.h', 'include\wire_table.h', 'include\vm_revirt.h',
  'docs\engine-redesign.md', 'tools\vmdbg.cpp', 'tools\rtinspect.cpp'
)
foreach ($relative in $forbidden) {
  if ($collected -contains $relative) { throw "Core protection source leaked into the public package: $relative" }
}
# A published tree must still contain the integration surface and the site.
foreach ($required in @(
    'VERSION', 'README.md', 'LICENSE', 'build.ps1',
    'sdk\include\novaprotect_sdk.h', 'include\vmp_markers.h',
    'installer\novaprotect.iss', 'ui\NovaProtect.UI.csproj',
    'website\public\index.php', 'tools\package-client-release.ps1'
  )) {
  if ($collected -notcontains $required) { throw "Expected file missing from the package: $required" }
}

$totalBytes = 0L
foreach ($relative in $collected) {
  if ($generated.ContainsKey($relative)) { $totalBytes += $utf8.GetByteCount($generated[$relative]) }
  else { $totalBytes += (Get-Item -LiteralPath (Join-Path $root $relative)).Length }
}
Write-Step "$($collected.Count) files, $([math]::Round($totalBytes / 1MB, 2)) MB ($skipped entries excluded)"

# ------------------------------------------------------------------- zip ----
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$stream = [IO.File]::Open($zipPath, [IO.FileMode]::Create, [IO.FileAccess]::Write)
try {
  $archive = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Create, $true)
  try {
    foreach ($relative in $collected) {
      $entryName = "$packageName/" + $relative.Replace('\', '/')
      if ($generated.ContainsKey($relative)) {
        $entry = $archive.CreateEntry($entryName, [IO.Compression.CompressionLevel]::Optimal)
        $writer = [IO.StreamWriter]::new($entry.Open(), $utf8)
        try { $writer.Write($generated[$relative]) } finally { $writer.Dispose() }
        continue
      }
      [IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
        $archive, (Join-Path $root $relative), $entryName, [IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
  }
  finally { $archive.Dispose() }
}
finally { $stream.Dispose() }

$zipItem = Get-Item -LiteralPath $zipPath
$zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$zipPath.sha256", "$zipHash  $([IO.Path]::GetFileName($zipPath))`n", $utf8)

Write-Host ''
Write-Host "GITHUB-SOURCE-OK version=$clientVersion"
Write-Host "  package : $zipPath"
Write-Host "  size    : $([math]::Round($zipItem.Length / 1MB, 2)) MB ($($collected.Count) files)"
Write-Host "  sha256  : $zipHash"
Write-Host '  note    : add a LICENSE file before publishing so the repository has explicit terms.'
