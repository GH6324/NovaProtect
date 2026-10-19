# NovaProtect build script (PowerShell, UTF-8 no BOM; VERSION is authoritative)
param(
  [switch]$Stub,     # rebuild stub blobs from .S
  [switch]$Prot,     # rebuild protection runtime blob (runtime/prot64.c)
  [switch]$Mut,      # rebuild mutation kernel template (runtime/mutkern.S)
  [switch]$ManagedHost, # build the CLR-safe encrypted EXE host
  [switch]$Cli,      # build internal NovaProtect.Engine.exe (not a CLI API)
  [switch]$WinUi,    # build the C# WinUI 3 client
  [switch]$All
)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$env:Path = 'C:\mingw\mingw64\bin;' + $env:Path
& (Join-Path $root 'tools\version.ps1') -Action Check
if ($LASTEXITCODE -ne 0) { throw 'version policy check failed' }
if ($All) { $Stub = $true; $Prot = $true; $Mut = $true; $ManagedHost = $true; $Cli = $true; $WinUi = $true }
if (-not ($Stub -or $Prot -or $Mut -or $ManagedHost -or $Cli -or $WinUi)) { $Stub = $true; $Prot = $true; $Mut = $true; $ManagedHost = $true; $Cli = $true; $WinUi = $true }

$utf8 = [System.Text.UTF8Encoding]::new($false)
# The commercial VMProtect SDK is optional. When it is installed next to the
# workspace the build links the real import library; on an open-source clone
# without the SDK the marker calls compile to no-ops (NOVAPROTECT_VMP_STUB)
# and no VMProtectSDK64.dll is required at runtime.
$vmpSdkLibrary = Join-Path (Split-Path -Parent $root) 'VMProtect Professional\Lib\Windows\MinGW\VMProtectSDK64.a'
$vmpSdkRuntime = Join-Path (Split-Path -Parent $root) 'VMProtect Professional\Lib\Windows\VMProtectSDK64.dll'
$vmpDefine = ''
$vmpLink = @()
if (Test-Path -LiteralPath $vmpSdkLibrary) {
  $vmpLink = @($vmpSdkLibrary)
  Write-Host '[vmp] linking VMProtect SDK import library'
} else {
  $vmpDefine = '-DNOVAPROTECT_VMP_STUB'
  Write-Host '[vmp] VMProtect SDK not found; building with no-op SDK markers (NOVAPROTECT_VMP_STUB)'
}
if ($Cli -or $WinUi) { & (Join-Path $root 'tools\client-integrity.ps1') -Action Prepare }

function Build-Stub {
  Push-Location $root
  Write-Host '[stub] assembling x64...'
  & as.exe runtime\stub.S -o runtime\stub.o
  if ($LASTEXITCODE -ne 0) { throw 'as x64 failed' }
  & objcopy.exe -O binary --only-section=.text runtime\stub.o runtime\stub.bin
  if ($LASTEXITCODE -ne 0) { throw 'objcopy x64 failed' }
  Write-Host '[stub] assembling x86...'
  & as.exe --32 runtime\stub32.S -o runtime\stub32.o
  if ($LASTEXITCODE -ne 0) { throw 'as x86 failed' }
  & objcopy.exe -O binary --only-section=.text runtime\stub32.o runtime\stub32.bin
  if ($LASTEXITCODE -ne 0) { throw 'objcopy x86 failed' }

  $b64 = [IO.File]::ReadAllBytes("$root\runtime\stub.bin")
  $b32 = [IO.File]::ReadAllBytes("$root\runtime\stub32.bin")
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine('#pragma once')
  [void]$sb.AppendLine('#include <cstdint>')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine('// Auto-generated unpacker stub blobs. Do not edit by hand.')
  [void]$sb.AppendLine('// Regenerate with: powershell -File build.ps1 -Stub')
  [void]$sb.AppendLine('')
  $sb.AppendLine("inline constexpr uint8_t kUnpackerStub[] = {") | Out-Null
  for ($i = 0; $i -lt $b64.Length; $i += 16) {
    $line = '    '
    for ($j = 0; $j -lt 16 -and ($i + $j) -lt $b64.Length; $j++) {
      $line += ('0x{0:x2}, ' -f $b64[$i + $j])
    }
    $sb.AppendLine($line.TrimEnd()) | Out-Null
  }
  $sb.AppendLine('};') | Out-Null
  $sb.AppendLine("inline constexpr uint32_t kUnpackerStubSize = $($b64.Length);") | Out-Null
  $sb.AppendLine('') | Out-Null
  $sb.AppendLine('inline constexpr uint8_t kUnpackerStub32[] = {') | Out-Null
  for ($i = 0; $i -lt $b32.Length; $i += 16) {
    $line = '    '
    for ($j = 0; $j -lt 16 -and ($i + $j) -lt $b32.Length; $j++) {
      $line += ('0x{0:x2}, ' -f $b32[$i + $j])
    }
    $sb.AppendLine($line.TrimEnd()) | Out-Null
  }
  $sb.AppendLine('};') | Out-Null
  $sb.AppendLine("inline constexpr uint32_t kUnpackerStub32Size = $($b32.Length);") | Out-Null
  [IO.File]::WriteAllText("$root\src\stub_blob.h", $sb.ToString(), $utf8)
  Write-Host "[stub] x64=$($b64.Length) x86=$($b32.Length) -> src\stub_blob.h"
  Pop-Location
}

function Build-Prot {
  Push-Location $root
  Write-Host '[prot] compiling x64 protection runtime...'
  & gcc.exe -c -o runtime\prot64_entry.o runtime\prot64_entry.S
  if ($LASTEXITCODE -ne 0) { throw 'gcc prot64_entry failed' }
  & gcc.exe -c -O2 -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident -fPIC -mno-red-zone -fno-tree-vectorize -Wall -Wextra -o runtime\prot64.o runtime\prot64.c
  if ($LASTEXITCODE -ne 0) { throw 'gcc prot64 failed' }
  & ld.exe -m i386pep -T runtime\prot64.ld --section-alignment 16 --file-alignment 16 -o runtime\prot64.ldimg runtime\prot64_entry.o runtime\prot64.o
  if ($LASTEXITCODE -ne 0) { throw 'ld prot64 failed' }
  & objcopy.exe -O binary -j .np_text -j .np_rdat runtime\prot64.ldimg runtime\prot64.bin
  if ($LASTEXITCODE -ne 0) { throw 'objcopy prot64 failed' }

  $pb = [IO.File]::ReadAllBytes("$root\runtime\prot64.bin")
  if ($pb.Length -eq 0) { throw 'prot64 blob is empty' }
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine('#pragma once')
  [void]$sb.AppendLine('#include <cstdint>')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine('// Auto-generated x64 protection runtime blob (runtime/prot64.c).')
  [void]$sb.AppendLine('// Blob offset 0 is the entry trampoline (np_blob_entry -> np_prot_start).')
  [void]$sb.AppendLine('// Regenerate with: powershell -File build.ps1 -Prot')
  [void]$sb.AppendLine('')
  $sb.AppendLine('inline constexpr uint8_t kProtBlob64[] = {') | Out-Null
  for ($i = 0; $i -lt $pb.Length; $i += 16) {
    $line = '    '
    for ($j = 0; $j -lt 16 -and ($i + $j) -lt $pb.Length; $j++) {
      $line += ('0x{0:x2}, ' -f $pb[$i + $j])
    }
    $sb.AppendLine($line.TrimEnd()) | Out-Null
  }
  $sb.AppendLine('};') | Out-Null
  $sb.AppendLine("inline constexpr uint32_t kProtBlob64Size = $($pb.Length);") | Out-Null
  [IO.File]::WriteAllText("$root\src\prot_blob.h", $sb.ToString(), $utf8)
  Write-Host "[prot] $($pb.Length) bytes -> src\prot_blob.h"
  Pop-Location
}
function Build-Mut {
  Push-Location $root
  Write-Host '[mut] assembling x64 mutation kernel template...'
  & as.exe runtime\mutkern.S -o runtime\mutkern.o
  if ($LASTEXITCODE -ne 0) { throw 'as mutkern failed' }
  & objcopy.exe -O binary --only-section=.text runtime\mutkern.o runtime\mutkern.bin
  if ($LASTEXITCODE -ne 0) { throw 'objcopy mutkern failed' }

  $mb = [IO.File]::ReadAllBytes("$root\runtime\mutkern.bin")
  if ($mb.Length -eq 0) { throw 'mutkern blob is empty' }
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine('#pragma once')
  [void]$sb.AppendLine('#include <cstdint>')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine('// Auto-generated x64 mutation kernel template (runtime/mutkern.S).')
  [void]$sb.AppendLine('// The packer patches four 8-byte constants before emitting the kernel:')
  [void]$sb.AppendLine('//   +2 basis  +28 prime  +47 seed  +64 prime2')
  [void]$sb.AppendLine('// ABI: rcx = buffer, rdx = length -> rax = 64-bit hash.')
  [void]$sb.AppendLine('')
  $sb.AppendLine('inline constexpr uint8_t kMutationKernel64[] = {') | Out-Null
  for ($i = 0; $i -lt $mb.Length; $i += 16) {
    $line = '    '
    for ($j = 0; $j -lt 16 -and ($i + $j) -lt $mb.Length; $j++) {
      $line += ('0x{0:x2}, ' -f $mb[$i + $j])
    }
    $sb.AppendLine($line.TrimEnd()) | Out-Null
  }
  $sb.AppendLine('};') | Out-Null
  $sb.AppendLine("inline constexpr uint32_t kMutationKernel64Size = $($mb.Length);") | Out-Null
  $sb.AppendLine('') | Out-Null
  $sb.AppendLine('constexpr uint32_t kMutKernBasisOff  = 2;') | Out-Null
  $sb.AppendLine('constexpr uint32_t kMutKernPrimeOff  = 28;') | Out-Null
  $sb.AppendLine('constexpr uint32_t kMutKernSeedOff   = 47;') | Out-Null
  $sb.AppendLine('constexpr uint32_t kMutKernPrime2Off = 64;') | Out-Null
  [IO.File]::WriteAllText("$root\src\mutkern_blob.h", $sb.ToString(), $utf8)
  Write-Host "[mut] $($mb.Length) bytes -> src\mutkern_blob.h"
  Pop-Location
}
function Build-Cli {
  Push-Location $root
  Write-Host '[core] compiling NovaProtect.Engine.exe...'
  & windres.exe runtime\novaprotect_cli.rc -O coff -o runtime\novaprotect_cli.res
  if ($LASTEXITCODE -ne 0) { throw 'cli resource build failed' }
  & g++.exe -std=c++17 -O2 -municode $vmpDefine -o NovaProtect.Engine.exe src\main.cpp src\client_gate.cpp src\managed_envelope.cpp src\pe_lib.cpp src\packer.cpp src\packer_meta.cpp src\mutation.cpp src\disasm.cpp src\anti_debug.cpp src\vm_engine.cpp src\vm_obfuscate.cpp src\crypto_layers.cpp runtime\novaprotect_cli.res $vmpLink -Iinclude -Isrc -static -static-libgcc -static-libstdc++ -lbcrypt
  if ($LASTEXITCODE -ne 0) { throw 'cli build failed' }
  Write-Host '[cli] ok'
  Pop-Location
}

function Build-ManagedHost {
  Push-Location $root
  Write-Host '[managed-host] compiling NovaProtect.ManagedHost.exe...'
  & windres.exe runtime\managed_host.rc -O coff -o runtime\managed_host.res
  if ($LASTEXITCODE -ne 0) { throw 'managed host resource build failed' }
  & g++.exe -std=c++17 -O2 -municode $vmpDefine -o NovaProtect.ManagedHost.exe runtime\managed_host.cpp runtime\managed_host.res $vmpLink -static -static-libgcc -static-libstdc++
  if ($LASTEXITCODE -ne 0) { throw 'managed host build failed' }
  Write-Host '[managed-host] ok'
  Pop-Location
}

function Build-WinUi {
  Push-Location $root
  $project = Join-Path $root 'ui\NovaProtect.UI.csproj'
  if (-not (Test-Path $project)) {
    Pop-Location
    throw 'WinUI project not found: ui\NovaProtect.UI.csproj'
  }

  $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
  $msbuild = $null
  if (Test-Path $vswhere) {
    $vsCandidates = @(& $vswhere -products Microsoft.VisualStudio.Product.Community -requires Microsoft.Component.MSBuild -property installationPath)
    $vsCandidates += @(& $vswhere -products Microsoft.VisualStudio.Product.Professional,Microsoft.VisualStudio.Product.Enterprise -requires Microsoft.Component.MSBuild -property installationPath)
    foreach ($vs in $vsCandidates) {
      if ([string]::IsNullOrWhiteSpace($vs)) { continue }
      $candidate = Join-Path $vs 'MSBuild\Current\Bin\MSBuild.exe'
      $sdkResolver = Join-Path $vs 'MSBuild\Current\Bin\SdkResolvers\Microsoft.DotNet.MSBuildSdkResolver\Microsoft.DotNet.MSBuildSdkResolver.dll'
      if ((Test-Path $candidate) -and (Test-Path $sdkResolver)) { $msbuild = $candidate; break }
    }
  }

  Write-Host '[winui] building NovaProtect.UI...'
  if ($msbuild) {
    Write-Host "[winui] using MSBuild: $msbuild"
    & $msbuild $project /restore /t:Build /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
  } else {
    Write-Host '[winui] using dotnet msbuild'
    & dotnet msbuild $project /restore /t:Build /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
  }
  if ($LASTEXITCODE -ne 0) { Pop-Location; throw 'WinUI build failed' }
  Write-Host '[winui] ok'
  if (Test-Path -LiteralPath $vmpSdkRuntime) {
    Copy-Item -LiteralPath $vmpSdkRuntime -Destination (Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\VMProtectSDK64.dll') -Force
  }
  & (Join-Path $root 'tools\client-integrity.ps1') -Action Sign -Directory (Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64')
  Pop-Location
}

if ($Stub) { Build-Stub }
if ($Prot) { Build-Prot }
if ($Mut)  { Build-Mut }
if ($ManagedHost) { Build-ManagedHost }
if ($Cli)  { Build-Cli }
if ($WinUi) { Build-WinUi }
Write-Host 'build complete'







