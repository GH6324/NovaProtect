[CmdletBinding()]
param([switch]$Install)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

# Search order: project-local vendor dir, then sibling VMProtect installs, then
# common absolute paths. The first readable .a + .dll pair wins.
$candidates = @(
  (Join-Path $root 'third_party\vmprotect'),
  (Join-Path (Split-Path -Parent $root) 'VMProtect Professional'),
  'C:\Program Files\VMProtect Professional',
  'C:\VMProtect Professional'
)

$libRel = 'Lib\Windows\MinGW\VMProtectSDK64.a'
$dllRel = 'Lib\Windows\VMProtectSDK64.dll'
$found = $null
foreach ($base in $candidates) {
  $lib = Join-Path $base $libRel
  $dll = Join-Path $base $dllRel
  if ((Test-Path -LiteralPath $lib -PathType Leaf) -and (Test-Path -LiteralPath $dll -PathType Leaf)) {
    $found = [pscustomobject]@{ Root = $base; Library = $lib; Runtime = $dll }
    break
  }
}

if ($null -eq $found) {
  if ($Install) {
    Write-Host '[vmp] no SDK found; install the commercial VMProtect SDK into:' (Join-Path $root 'third_party\vmprotect')
    Write-Host '[vmp] copy "VMProtect Professional" directory there, then rerun the build.'
  }
  Write-Output 'NOVAPROTECT_VMP_SDK=NOT-FOUND'
  exit 1
}

# Vendor into the project so builds are reproducible without relying on a
# sibling directory that may not exist on other machines.
$vendor = Join-Path $root 'third_party\vmprotect'
$vlib = Join-Path $vendor $libRel
$vdll = Join-Path $vendor $dllRel
if ($Install -and $found.Root -ne $vendor) {
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $vlib) | Out-Null
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $vdll) | Out-Null
  Copy-Item -LiteralPath $found.Library -Destination $vlib -Force
  Copy-Item -LiteralPath $found.Runtime -Destination $vdll -Force
  Write-Host "[vmp] vendored SDK to $vendor"
  $found = [pscustomobject]@{ Root = $vendor; Library = $vlib; Runtime = $vdll }
}

Write-Output "NOVAPROTECT_VMP_LIB=$($found.Library)"
Write-Output "NOVAPROTECT_VMP_DLL=$($found.Runtime)"
Write-Output "NOVAPROTECT_VMP_SDK=OK"