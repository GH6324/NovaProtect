# NovaProtect regression harness
param([string]$Packer)
$ErrorActionPreference = 'Continue'
$env:Path = 'C:\mingw\mingw64\bin;' + $env:Path
$root = Split-Path -Parent $PSScriptRoot
if (-not $Packer) {
  $version=(Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim()
  $Packer=Join-Path $root "artifacts\test-only-core-$version\CoreRegression.exe"
  if(-not(Test-Path -LiteralPath $Packer)){throw 'Run tools/build-regression-core.ps1 first. Shipping engine accepts genuine UI only.'}
}
$Packer = [IO.Path]::GetFullPath($Packer)
$out  = Join-Path $PSScriptRoot '_reg'
New-Item -ItemType Directory -Force -Path $out | Out-Null
Copy-Item "$PSScriptRoot\VMProtectSDK64.dll" $out -Force -ErrorAction SilentlyContinue
$script:fail = 0

function Run-One {
  param([string]$Name, [string]$In, [string[]]$Options, [string]$Expect, [int]$ExpectExit = 0)
  if (-not (Test-Path -LiteralPath $In)) {
    # fixture binaries are build artifacts stripped from the source package;
    # a missing fixture is an environment limitation, not a product failure
    Write-Host "[SKIP] $Name : fixture missing ($In)"
    return
  }
  $exe = Join-Path $out "$Name.exe"
  Remove-Item $exe -ErrorAction SilentlyContinue
  $pa = @($In, '-o', $exe) + $Options
  $packOut = & $Packer @pa 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { Write-Host "[FAIL] $Name : packer rc=$LASTEXITCODE"; Write-Host ($packOut -split "`n" | Select-Object -Last 6 | Out-String); $script:fail++; return }
  if (-not (Test-Path $exe)) { Write-Host "[FAIL] $Name : no output exe"; $script:fail++; return }
  $po = Join-Path $out "$Name.prog.txt"
  $text = & $exe 2>&1 | Out-String
  $rc = $LASTEXITCODE
  if ($rc -ne $ExpectExit) { Write-Host "[FAIL] $Name : exit=$rc expected=$ExpectExit"; Write-Host $text; $script:fail++; return }
  if ($Expect -and $text -notmatch [regex]::Escape($Expect)) { Write-Host "[FAIL] $Name : output missing '$Expect'"; Write-Host $text; $script:fail++; return }
  [IO.File]::WriteAllText($po, $text, [System.Text.UTF8Encoding]::new($false))
  Write-Host "[ OK ] $Name  (exit=$rc)"
}

function Read-PeFacts {
  param([string]$Path)
  $bytes = [IO.File]::ReadAllBytes($Path)
  $pe = [BitConverter]::ToInt32($bytes, 0x3C)
  $optional = $pe + 24
  $magic = [BitConverter]::ToUInt16($bytes, $optional)
  $dllCharsOff = $optional + 70
  $dirBase = $optional + $(if ($magic -eq 0x20B) { 112 } else { 96 })
  [pscustomobject]@{
    DllCharacteristics = [BitConverter]::ToUInt16($bytes, $dllCharsOff)
    ExportRva = [BitConverter]::ToUInt32($bytes, $dirBase)
    ExportSize = [BitConverter]::ToUInt32($bytes, $dirBase + 4)
    RelocRva = [BitConverter]::ToUInt32($bytes, $dirBase + (5 * 8))
    RelocSize = [BitConverter]::ToUInt32($bytes, $dirBase + (5 * 8) + 4)
  }
}

function Find-MarkerRegion {
  param([string]$Path)
  $bytes = [IO.File]::ReadAllBytes($Path)
  $pe = [BitConverter]::ToInt32($bytes, 0x3C)
  $sections = [BitConverter]::ToUInt16($bytes, $pe + 6)
  $optionalSize = [BitConverter]::ToUInt16($bytes, $pe + 20)
  $table = $pe + 24 + $optionalSize
  $begin = [byte[]](0x48,0x8D,0x0D,0,0,0,0) + ([byte[]](0x90) * 20)
  $end = [byte[]](0x90) * 20
  for ($s = 0; $s -lt $sections; $s++) {
    $row = $table + $s * 40
    $rva = [BitConverter]::ToUInt32($bytes, $row + 12)
    $rawSize = [BitConverter]::ToUInt32($bytes, $row + 16)
    $raw = [BitConverter]::ToUInt32($bytes, $row + 20)
    $chars = [BitConverter]::ToUInt32($bytes, $row + 36)
    if (($chars -band 0x20000000) -eq 0) { continue }
    for ($i = 0; $i + $begin.Length -le $rawSize; $i++) {
      $match = $true
      for ($k = 0; $k -lt $begin.Length; $k++) { if ($bytes[$raw + $i + $k] -ne $begin[$k]) { $match = $false; break } }
      if (-not $match) { continue }
      for ($j = $i + $begin.Length; $j + $end.Length -le $rawSize; $j++) {
        $endMatch = $true
        for ($k = 0; $k -lt $end.Length; $k++) { if ($bytes[$raw + $j + $k] -ne $end[$k]) { $endMatch = $false; break } }
        if ($endMatch) {
          return [pscustomobject]@{ StartRva = $rva + $i + $begin.Length; EndRva = $rva + $j }
        }
      }
    }
  }
  return $null
}

function Read-NppFacts {
  param([string]$Path)
  $bytes = [IO.File]::ReadAllBytes($Path)
  for ($i = 0; $i + 96 -le $bytes.Length; $i++) {
    if ($bytes[$i] -ne 0x4E -or $bytes[$i+1] -ne 0x50 -or $bytes[$i+2] -ne 0x50 -or $bytes[$i+3] -ne 0x31) { continue }
    if ([BitConverter]::ToUInt32($bytes, $i + 4) -notin @(1,2)) { continue }
    return [pscustomobject]@{
      Flags = [BitConverter]::ToUInt32($bytes, $i + 8)
      ExpectedMachine = [BitConverter]::ToUInt64($bytes, $i + 80)
      VmCount = [BitConverter]::ToUInt32($bytes, $i + 88)
      SandboxThreshold = [BitConverter]::ToUInt32($bytes, $i + 96)
      EnvThreshold = [BitConverter]::ToUInt32($bytes, $i + 124)
    }
  }
  return $null
}

function Read-NovaPayloadFacts {
  param([string]$Path)
  $bytes = [IO.File]::ReadAllBytes($Path)
  for ($i = 0; $i + 128 -le $bytes.Length; $i++) {
    if ($bytes[$i] -ne 0x4E -or $bytes[$i+1] -ne 0x4F -or $bytes[$i+2] -ne 0x56 -or $bytes[$i+3] -ne 0x41) { continue }
    if ([BitConverter]::ToUInt32($bytes, $i + 4) -ne 3) { continue }
    $count = [BitConverter]::ToUInt32($bytes, $i + 8)
    if ($count -eq 0 -or $count -gt 4096 -or $i + 128 + $count * 32 -gt $bytes.Length) { continue }
    $flags = @()
    for ($r = 0; $r -lt $count; $r++) { $flags += [BitConverter]::ToUInt32($bytes, $i + 128 + $r * 32 + 12) }
    return [pscustomobject]@{ RegionCount = $count; RegionFlags = $flags }
  }
  return $null
}

# Walks the PE resource directory tree and returns one record per resource
# leaf (type, name/id, payload size, SHA-256 of the payload). Used to prove
# that RT_ICON / RT_GROUP_ICON entries survive protection byte-for-byte.
function Get-IconEntries {
  param([string]$Path)
  $bytes = [IO.File]::ReadAllBytes($Path)
  $result = New-Object System.Collections.ArrayList
  if ($bytes.Length -lt 0x40) { return $result }
  $pe = [BitConverter]::ToInt32($bytes, 0x3C)
  if ($pe -lt 0 -or $pe + 24 -gt $bytes.Length) { return $result }
  $sections = [BitConverter]::ToUInt16($bytes, $pe + 6)
  $optionalSize = [BitConverter]::ToUInt16($bytes, $pe + 20)
  $optional = $pe + 24
  $magic = [BitConverter]::ToUInt16($bytes, $optional)
  $dirBase = $optional + $(if ($magic -eq 0x20B) { 112 } else { 96 })
  if ($dirBase + 24 -gt $bytes.Length) { return $result }
  $rsrcRva = [BitConverter]::ToUInt32($bytes, $dirBase + 16)
  $rsrcSize = [BitConverter]::ToUInt32($bytes, $dirBase + 20)
  if ($rsrcRva -eq 0 -or $rsrcSize -eq 0) { return $result }
  $table = $optional + $optionalSize
  $fileOfRva = {
    param([uint32]$rva)
    for ($s = 0; $s -lt $sections; $s++) {
      $row = $table + $s * 40
      if ($row + 40 -gt $bytes.Length) { break }
      $va = [BitConverter]::ToUInt32($bytes, $row + 12)
      $vsize = [BitConverter]::ToUInt32($bytes, $row + 8)
      $raw = [BitConverter]::ToUInt32($bytes, $row + 20)
      $rawSize = [BitConverter]::ToUInt32($bytes, $row + 16)
      if ($vsize -eq 0) { $vsize = $rawSize }
      if ($rva -ge $va -and $rva -lt $va + [Math]::Max($vsize, $rawSize)) { return [int64]$raw + [int64]($rva - $va) }
    }
    return -1
  }
  $rsrcOff = & $fileOfRva $rsrcRva
  if ($rsrcOff -lt 0) { return $result }
  $pending = New-Object System.Collections.Stack
  $pending.Push(@{ Off = [int]$rsrcOff; Type = -1; Name = 0; Named = -1; IdCount = -1; NodeNameIsString = $false }) | Out-Null
  while ($pending.Count -gt 0) {
    $node = $pending.Pop()
    $off = $node.Off
    if ($off -lt 0 -or $off + 20 -gt $bytes.Length) { continue }
    $named = [BitConverter]::ToUInt16($bytes, $off + 12)
    $idCount = [BitConverter]::ToUInt16($bytes, $off + 14)
    $total = $named + $idCount
    for ($e = 0; $e -lt $total; $e++) {
      $eo = $off + 16 + $e * 8
      if ($eo + 8 -gt $bytes.Length) { continue }
      $name = [BitConverter]::ToUInt32($bytes, $eo)
      $offset = [BitConverter]::ToUInt32($bytes, $eo + 4)
      $typeId = if ($node.Type -eq -1) { $name } else { $node.Type }
      if (($offset -band 0x80000000) -ne 0) {
        $pending.Push(@{ Off = [int]($rsrcOff + ($offset -band 0x7FFFFFFF)); Type = [int]$typeId; Name = $name; Named = [int]$named; IdCount = [int]$idCount; NodeNameIsString = ($name -band 0x80000000) -ne 0 }) | Out-Null
      } else {
        $dataOff = $rsrcOff + $offset
        if ($dataOff + 16 -gt $bytes.Length) { continue }
        $dataRva = [BitConverter]::ToUInt32($bytes, $dataOff)
        $dataSize = [BitConverter]::ToUInt32($bytes, $dataOff + 4)
        if ($dataSize -eq 0 -or $dataSize -gt 0x1000000) { continue }
        $fileOff = & $fileOfRva $dataRva
        if ($fileOff -lt 0 -or $fileOff + $dataSize -gt $bytes.Length) { continue }
        $sha = [BitConverter]::ToString((New-Object System.Security.Cryptography.SHA256CryptoServiceProvider).ComputeHash($bytes, [int]$fileOff, [int]$dataSize)).Replace('-', '')
        # DirNamed/DirIdCount capture the enclosing directory header counts,
        # NameIsString the high-bit encoding of the leaf entry and
        # NodeNameIsString the encoding of the name-level entry above it:
        # Windows rejects a directory whose counts do not match the entry
        # encoding, which is exactly the failure that strips the Explorer icon.
        $result.Add([pscustomobject]@{ Type = [int]$typeId; Name = $name; Size = [int]$dataSize; Hash = $sha; DirNamed = [int]$named; DirIdCount = [int]$idCount; NameIsString = ($name -band 0x80000000) -ne 0; NodeNameIsString = [bool]$node.NodeNameIsString }) | Out-Null
      }
    }
  }
  return $result
}

Write-Host '--- x64 test_target ---'
Run-One 'x64_none'   "$root\tests\test_target.exe" @() 'Hash: 0x6DD33F53'
Run-One 'x64_memory' "$root\tests\test_target.exe" @('-memory') 'Hash: 0x6DD33F53'
Run-One 'x64_ad'     "$root\tests\test_target.exe" @('-ad','3') 'Hash: 0x6DD33F53'
Run-One 'x64_avm'    "$root\tests\test_target.exe" @('-avm','2') 'Hash: 0x6DD33F53'
Run-One 'x64_all'    "$root\tests\test_target.exe" @('-mode','ultra','-mut','3','-vm','9','-ad','3','-avm','2','-memory') 'Hash: 0x6DD33F53'

Write-Host '--- x86 hostname32 ---'
Run-One 'x86_none'   "$root\tests\hostname32.exe" @() 'sudfiona'
Run-One 'x86_all'    "$root\tests\hostname32.exe" @('-mode','ultra','-mut','3','-vm','9','-ad','3','-avm','2','-memory') 'sudfiona'

Write-Host '--- new protection features ---'
Run-One 'x64_resources' "$root\tests\test_target.exe" @('-mode','ultra','-ad','3','-avm','2','-memory','-resources') 'Hash: 0x6DD33F53'
Run-One 'x86_resources' "$root\tests\hostname32.exe" @('-mode','ultra','-ad','3','-avm','2','-memory','-resources') 'sudfiona'
Run-One 'x64_imports'   "$root\tests\test_target.exe" @('-mode','ultra','-memory','-imports') 'Hash: 0x6DD33F53'
Run-One 'x64_imports_ad' "$root\tests\test_target.exe" @('-mode','ultra','-ad','3','-avm','2','-memory','-imports','-resources') 'Hash: 0x6DD33F53'
Run-One 'x86_imports'   "$root\tests\hostname32.exe" @('-mode','ultra','-memory','-imports') 'sudfiona'
Run-One 'x86_imports_ad' "$root\tests\hostname32.exe" @('-mode','ultra','-ad','3','-avm','2','-memory','-imports','-resources') 'sudfiona'

Write-Host '--- sandbox guard / anti-dump / interactive-desktop check ---'
# Every case must still run to completion on a genuine desktop: the sandbox
# score and the headless-env score are both zero here (taskbar + input).
Run-One 'x64_sandbox_guard' "$root\tests\test_target.exe" @('-sandbox-guard') 'Hash: 0x6DD33F53'
Run-One 'x64_anti_dump'    "$root\tests\test_target.exe" @('-anti-dump') 'Hash: 0x6DD33F53'
Run-One 'x64_env_check'    "$root\tests\test_target.exe" @('-env-check') 'Hash: 0x6DD33F53'
Run-One 'x64_sandbox_all'  "$root\tests\test_target.exe" @('-mode','ultra','-mut','3','-vm','9','-ad','3','-avm','2','-memory','-sandbox-guard','-anti-dump','-env-check') 'Hash: 0x6DD33F53'
Run-One 'x64_sandbox_thr'  "$root\tests\test_target.exe" @('-sandbox-guard','-sandbox-threshold','33','-env-check','-env-threshold','5') 'Hash: 0x6DD33F53'

$sboxFacts = Read-NppFacts (Join-Path $out 'x64_sandbox_all.exe')
if ($null -ne $sboxFacts -and ($sboxFacts.Flags -band 0xE00) -eq 0xE00 -and $sboxFacts.SandboxThreshold -eq 40 -and $sboxFacts.EnvThreshold -eq 7) {
  Write-Host '[ OK ] x64_sandbox_all descriptor flags/thresholds'
} else {
  Write-Host ('[FAIL] x64_sandbox_all descriptor: flags=0x{0:X8} sbox={1} env={2}' -f $(if ($null -ne $sboxFacts) { $sboxFacts.Flags } else { 0 }), $(if ($null -ne $sboxFacts) { $sboxFacts.SandboxThreshold } else { -1 }), $(if ($null -ne $sboxFacts) { $sboxFacts.EnvThreshold } else { -1 }))
  $script:fail++
}
$thrFacts = Read-NppFacts (Join-Path $out 'x64_sandbox_thr.exe')
if ($null -ne $thrFacts -and ($thrFacts.Flags -band 0xA00) -eq 0xA00 -and $thrFacts.SandboxThreshold -eq 33 -and $thrFacts.EnvThreshold -eq 5) {
  Write-Host '[ OK ] x64_sandbox_thr descriptor overrides'
} else {
  Write-Host ('[FAIL] x64_sandbox_thr descriptor: flags=0x{0:X8} sbox={1} env={2}' -f $(if ($null -ne $thrFacts) { $thrFacts.Flags } else { 0 }), $(if ($null -ne $thrFacts) { $thrFacts.SandboxThreshold } else { -1 }), $(if ($null -ne $thrFacts) { $thrFacts.EnvThreshold } else { -1 }))
  $script:fail++
}

Write-Host '--- section encryption / trimming / activation ---'
Run-One 'x64_noencrypt' "$root\tests\vm_target.exe" @('-mode','virtualization','-vm','5','-noencrypt') 'VM-OK'
Run-One 'x64_activation_auto' "$root\tests\vm_target.exe" @('-mode','virtualization','-vm','5','-activation','auto') 'VM-OK'
$plainPayload = Read-NovaPayloadFacts (Join-Path $out 'x64_noencrypt.exe')
if ($null -ne $plainPayload -and $plainPayload.RegionCount -gt 0 -and @($plainPayload.RegionFlags | Where-Object { ($_ -band 4) -ne 0 }).Count -eq 0) {
  Write-Host '[ OK ] x64_noencrypt payload flags'
} else { Write-Host '[FAIL] x64_noencrypt payload still marked encrypted'; $script:fail++ }

$machineText = (& $Packer '-machineid' 2>&1 | Out-String).Trim()
$autoFacts = Read-NppFacts (Join-Path $out 'x64_activation_auto.exe')
if ($machineText -match '^[0-9A-Fa-f]{16}$' -and $null -ne $autoFacts -and ($autoFacts.Flags -band 0x100) -ne 0 -and $autoFacts.ExpectedMachine -eq [Convert]::ToUInt64($machineText, 16)) {
  Write-Host '[ OK ] x64_activation_auto metadata'
} else { Write-Host '[FAIL] x64_activation_auto metadata'; $script:fail++ }

$actBad = Join-Path $out 'x64_activation_bad.exe'
Remove-Item $actBad -ErrorAction SilentlyContinue
$null = & $Packer "$root\tests\vm_target.exe" '-o' $actBad '-mode' 'virtualization' '-vm' '5' '-activation' '1' 2>&1
if (Test-Path $actBad) {
  $null = & $actBad 2>&1
  if ($LASTEXITCODE -ne 0) { Write-Host '[ OK ] x64_activation_bad (wrong machine rejected)' }
  else { Write-Host '[FAIL] x64_activation_bad : wrong machine accepted'; $script:fail++ }
} else { Write-Host '[FAIL] x64_activation_bad : pack failed'; $script:fail++ }

$relocExe = Join-Path $out 'x64_stripreloc.exe'
$null = & $Packer "$root\tests\vm_target.exe" '-o' $relocExe '-mode' 'virtualization' '-vm' '5' '-stripreloc' 2>&1
if (Test-Path $relocExe) {
  $facts = Read-PeFacts $relocExe
  $run = & $relocExe 2>&1 | Out-String
  if ($LASTEXITCODE -eq 0 -and $run -match 'VM-OK' -and $facts.RelocRva -eq 0 -and $facts.RelocSize -eq 0 -and (($facts.DllCharacteristics -band 0x40) -eq 0)) {
    Write-Host '[ OK ] x64_stripreloc (directory cleared, ASLR disabled, image runs)'
  } else { Write-Host '[FAIL] x64_stripreloc'; $script:fail++ }
} else { Write-Host '[FAIL] x64_stripreloc : pack failed'; $script:fail++ }

$gcc = 'C:\mingw\mingw64\bin\gcc.exe'
$exportFixture = Join-Path $out 'export_target.exe'
$dllFixture = Join-Path $out 'export_target.dll'
& $gcc '-O2' '-s' "$root\tests\export_target.c" '-o' $exportFixture
if ($LASTEXITCODE -eq 0) {
  $exportOut = Join-Path $out 'x64_stripexport.exe'
  $null = & $Packer $exportFixture '-o' $exportOut '-mode' 'virtualization' '-vm' '0' '-mut' '0' '-stripexport' 2>&1
  if (Test-Path $exportOut) {
    $facts = Read-PeFacts $exportOut
    $run = & $exportOut 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0 -and $run -match 'EXPORT-OK' -and $facts.ExportRva -eq 0 -and $facts.ExportSize -eq 0) {
      Write-Host '[ OK ] x64_stripexport (directory cleared, image runs)'
    } else { Write-Host '[FAIL] x64_stripexport'; $script:fail++ }
  } else { Write-Host '[FAIL] x64_stripexport : pack failed'; $script:fail++ }
} else { Write-Host '[FAIL] export fixture compilation'; $script:fail++ }

& $gcc '-shared' '-O2' '-s' "$root\tests\export_dll.c" '-o' $dllFixture
if ($LASTEXITCODE -eq 0) {
  $dllOut = Join-Path $out 'export_target_np.dll'
  $msg = & $Packer $dllFixture '-o' $dllOut '-stripexport' 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0 -and $msg -match 'blocked for DLL') { Write-Host '[ OK ] dll trimming blocked' }
  else { Write-Host "[FAIL] dll trimming was not blocked: $msg"; $script:fail++ }
} else { Write-Host '[FAIL] DLL fixture compilation'; $script:fail++ }

Write-Host '--- icon preservation (x64) ---'
$windres = 'C:\mingw\mingw64\bin\windres.exe'
$iconResObj = Join-Path $out 'icon_target_res.o'
$iconFixture = Join-Path $out 'icon_target.exe'
Remove-Item $iconResObj -ErrorAction SilentlyContinue
Remove-Item $iconFixture -ErrorAction SilentlyContinue
Push-Location "$root\tests\icon_target"
$null = & $windres 'res.rc' '-o' $iconResObj 2>&1
$windresRc = $LASTEXITCODE
Pop-Location
if ($windresRc -eq 0 -and (Test-Path $iconResObj)) {
  $null = & $gcc '-O2' '-s' "$root\tests\icon_target\main.c" $iconResObj '-o' $iconFixture 2>&1
  if ($LASTEXITCODE -eq 0 -and (Test-Path $iconFixture)) {
    $iconPacked = Join-Path $out 'icon_packed.exe'
    Remove-Item $iconPacked -ErrorAction SilentlyContinue
    $null = & $Packer $iconFixture '-o' $iconPacked '-mode' 'ultra' '-ad' '3' '-avm' '2' '-memory' '-resources' 2>&1
    if (Test-Path $iconPacked) {
      $before = @(Get-IconEntries $iconFixture | Where-Object { $_.Type -eq 3 -or $_.Type -eq 14 } | Sort-Object Type, Name)
      $after = @(Get-IconEntries $iconPacked | Where-Object { $_.Type -eq 3 -or $_.Type -eq 14 } | Sort-Object Type, Name)
      if ($before.Count -ge 2 -and $before.Count -eq $after.Count) {
        $iconOk = $true
        for ($k = 0; $k -lt $before.Count; $k++) {
          if ($before[$k].Type -ne $after[$k].Type -or $before[$k].Name -ne $after[$k].Name -or $before[$k].Size -ne $after[$k].Size -or $before[$k].Hash -ne $after[$k].Hash -or $before[$k].DirNamed -ne $after[$k].DirNamed -or $before[$k].DirIdCount -ne $after[$k].DirIdCount -or $before[$k].NameIsString -ne $after[$k].NameIsString) { $iconOk = $false }
        }
        if ($iconOk) {
          $run = & $iconPacked 2>&1 | Out-String
          if ($LASTEXITCODE -eq 0 -and $run -match 'ICON-FIXTURE-OK') {
            Write-Host "[ OK ] icon preservation ($($before.Count) entries byte-identical incl. directory header counts, image runs)"
          } else { Write-Host "[FAIL] icon preservation : packed image failed: $run"; $script:fail++ }
        } else {
          Write-Host '[FAIL] icon preservation : resource entries changed by the packer'
          for ($k = 0; $k -lt [Math]::Max($before.Count, $after.Count); $k++) {
            $b = if ($k -lt $before.Count) { "type=$($before[$k].Type) name=$($before[$k].Name) size=$($before[$k].Size) dirNamed=$($before[$k].DirNamed) dirId=$($before[$k].DirIdCount) strName=$($before[$k].NameIsString)" } else { '<missing>' }
            $a = if ($k -lt $after.Count) { "type=$($after[$k].Type) name=$($after[$k].Name) size=$($after[$k].Size) dirNamed=$($after[$k].DirNamed) dirId=$($after[$k].DirIdCount) strName=$($after[$k].NameIsString)" } else { '<missing>' }
            if ($b -ne $a) { Write-Host "        before[$k]: $b  after[$k]: $a" }
          }
          $script:fail++
        }
      } else {
        Write-Host "[FAIL] icon preservation : entry count before=$($before.Count) after=$($after.Count)"; $script:fail++
      }
    } else { Write-Host '[FAIL] icon preservation : pack failed'; $script:fail++ }
  } else { Write-Host '[FAIL] icon fixture compilation'; $script:fail++ }
} else { Write-Host '[FAIL] icon fixture resource compilation'; $script:fail++ }

# Mixed named/ID icon entries: the rebuilt resource directory must declare
# NumberOfNamedEntries / NumberOfIdEntries per leaf kind, otherwise Windows
# parses ID entries as string offsets and the Explorer icon disappears.
$mixedResObj = Join-Path $out 'icon_mixed_res.o'
$mixedFixture = Join-Path $out 'icon_mixed.exe'
Remove-Item $mixedResObj -ErrorAction SilentlyContinue
Remove-Item $mixedFixture -ErrorAction SilentlyContinue
Push-Location "$root\tests\icon_target"
$null = & $windres 'mixed.rc' '-o' $mixedResObj 2>&1
$mixedRc = $LASTEXITCODE
Pop-Location
if ($mixedRc -eq 0 -and (Test-Path $mixedResObj)) {
  $null = & $gcc '-O2' '-s' "$root\tests\icon_target\main.c" $mixedResObj '-o' $mixedFixture 2>&1
  if ($LASTEXITCODE -eq 0 -and (Test-Path $mixedFixture)) {
    $mixedPacked = Join-Path $out 'icon_mixed_packed.exe'
    Remove-Item $mixedPacked -ErrorAction SilentlyContinue
    $null = & $Packer $mixedFixture '-o' $mixedPacked '-mode' 'ultra' '-ad' '3' '-avm' '2' '-memory' '-resources' 2>&1
    if (Test-Path $mixedPacked) {
      $mixedBefore = @(Get-IconEntries $mixedFixture | Where-Object { $_.Type -eq 3 -or $_.Type -eq 14 } | Sort-Object Type, Name)
      $mixedAfter = @(Get-IconEntries $mixedPacked | Where-Object { $_.Type -eq 3 -or $_.Type -eq 14 } | Sort-Object Type, Name)
      $mixedNamed = @($mixedBefore | Where-Object { $_.NodeNameIsString }).Count
      if ($mixedNamed -ge 1 -and $mixedBefore.Count -eq $mixedAfter.Count) {
        $mixedOk = $true
        for ($k = 0; $k -lt $mixedBefore.Count; $k++) {
          if ($mixedBefore[$k].Type -ne $mixedAfter[$k].Type -or $mixedBefore[$k].Name -ne $mixedAfter[$k].Name -or $mixedBefore[$k].Size -ne $mixedAfter[$k].Size -or $mixedBefore[$k].Hash -ne $mixedAfter[$k].Hash -or $mixedBefore[$k].DirNamed -ne $mixedAfter[$k].DirNamed -or $mixedBefore[$k].DirIdCount -ne $mixedAfter[$k].DirIdCount -or $mixedBefore[$k].NameIsString -ne $mixedAfter[$k].NameIsString -or $mixedBefore[$k].NodeNameIsString -ne $mixedAfter[$k].NodeNameIsString) { $mixedOk = $false }
        }
        if ($mixedOk) {
          $mixedRun = & $mixedPacked 2>&1 | Out-String
          if ($LASTEXITCODE -eq 0 -and $mixedRun -match 'ICON-FIXTURE-OK') {
            Write-Host "[ OK ] icon directory named/id counts ($($mixedBefore.Count) entries, $mixedNamed named leaves preserved, image runs)"
          } else { Write-Host "[FAIL] icon directory named/id counts : packed image failed: $mixedRun"; $script:fail++ }
        } else {
          Write-Host '[FAIL] icon directory named/id counts : entries or directory headers changed by the packer'
          for ($k = 0; $k -lt [Math]::Max($mixedBefore.Count, $mixedAfter.Count); $k++) {
            $b = if ($k -lt $mixedBefore.Count) { "type=$($mixedBefore[$k].Type) name=$($mixedBefore[$k].Name) dirNamed=$($mixedBefore[$k].DirNamed) dirId=$($mixedBefore[$k].DirIdCount) strName=$($mixedBefore[$k].NameIsString) strNode=$($mixedBefore[$k].NodeNameIsString)" } else { '<missing>' }
            $a = if ($k -lt $mixedAfter.Count) { "type=$($mixedAfter[$k].Type) name=$($mixedAfter[$k].Name) dirNamed=$($mixedAfter[$k].DirNamed) dirId=$($mixedAfter[$k].DirIdCount) strName=$($mixedAfter[$k].NameIsString) strNode=$($mixedAfter[$k].NodeNameIsString)" } else { '<missing>' }
            if ($b -ne $a) { Write-Host "        before[$k]: $b  after[$k]: $a" }
          }
          $script:fail++
        }
      } else {
        Write-Host "[FAIL] icon directory named/id counts : fixture did not produce mixed entries (named=$mixedNamed before=$($mixedBefore.Count) after=$($mixedAfter.Count))"; $script:fail++
      }
    } else { Write-Host '[FAIL] icon directory named/id counts : pack failed'; $script:fail++ }
  } else { Write-Host '[FAIL] icon mixed fixture compilation'; $script:fail++ }
} else { Write-Host '[FAIL] icon mixed fixture resource compilation'; $script:fail++ }

Write-Host '--- SDK marker object selection ---'
$marker = Find-MarkerRegion "$root\tests\vm_target.exe"
if ($null -eq $marker) { Write-Host '[FAIL] marker fixture not found'; $script:fail++ }
else {
  $regionSpec = '{0:X}-{1:X}-virtualization-5-0-0' -f $marker.StartRva, $marker.EndRva
  Run-One 'x64_region_selected' "$root\tests\vm_target.exe" @('-mode','virtualization','-vm','5','-region',$regionSpec) 'VM-OK'
  $selectedFacts = Read-NppFacts (Join-Path $out 'x64_region_selected.exe')
  if ($null -ne $selectedFacts -and $selectedFacts.VmCount -eq 1) { Write-Host '[ OK ] x64_region_selected descriptor count' }
  else { Write-Host '[FAIL] x64_region_selected descriptor count'; $script:fail++ }

  $skipSpec = '{0:X}-{1:X}-skip-5-0-0' -f $marker.StartRva, $marker.EndRva
  $skipExe = Join-Path $out 'x64_region_skip.exe'
  $skipLog = & $Packer "$root\tests\vm_target.exe" '-o' $skipExe '-mode' 'virtualization' '-vm' '5' '-region' $skipSpec 2>&1 | Out-String
  if ($LASTEXITCODE -eq 0 -and $skipLog -match 'disabled by SDK object editor') {
    $run = & $skipExe 2>&1 | Out-String
    $skipFacts = Read-NppFacts $skipExe
    if ($LASTEXITCODE -eq 0 -and $run -match 'VM-OK' -and $null -ne $skipFacts -and $skipFacts.VmCount -eq 0) { Write-Host '[ OK ] x64_region_skip (marker rule honored)' }
    else { Write-Host '[FAIL] x64_region_skip : output failed'; $script:fail++ }
  } else { Write-Host '[FAIL] x64_region_skip : skip rule not observed'; $script:fail++ }

  $fakeSpec = '{0:X}-{1:X}-virtualization-5-0-0' -f ($marker.StartRva + 1), ($marker.EndRva + 1)
  $fakeExe = Join-Path $out 'x64_region_fake.exe'
  $fakeLog = & $Packer "$root\tests\vm_target.exe" '-o' $fakeExe '-mode' 'virtualization' '-vm' '5' '-region' $fakeSpec 2>&1 | Out-String
  $fakeFacts = Read-NppFacts $fakeExe
  if ($LASTEXITCODE -eq 0 -and $fakeLog -match 'not selected in SDK object editor' -and $fakeLog -notmatch 'VM translated' -and $null -ne $fakeFacts -and $fakeFacts.VmCount -eq 0) {
    Write-Host '[ OK ] x64_region_fake (arbitrary range not treated as marker object)'
  } else { Write-Host '[FAIL] x64_region_fake : arbitrary range affected VM selection'; $script:fail++ }
}

$foreignFacts = Read-NppFacts (Join-Path $out 'x64_none.exe')
if ($null -ne $foreignFacts -and $foreignFacts.VmCount -eq 0) { Write-Host '[ OK ] VMProtect SDK calls are not exposed as NovaProtect marker regions' }
else { Write-Host '[FAIL] non-NovaProtect markers produced VM descriptors'; $script:fail++ }

Write-Host '--- project / planner persistence ---'
$plannerOutput = & dotnet run -c Release --project "$root\tests\planner-smoke\NovaProtect.PlannerSmoke.csproj" -- $root 2>&1 | Out-String
if ($LASTEXITCODE -eq 0 -and $plannerOutput -match 'PLANNER-SMOKE-OK') { Write-Host '[ OK ] planner/project persistence smoke' }
else { Write-Host "[FAIL] planner/project persistence smoke: $plannerOutput"; $script:fail++ }

Write-Host '--- watermark / virtual files ---'
$wmExe = Join-Path $out 'wm.exe'
$vfSrc = Join-Path $out 'vf_in.dat'
[IO.File]::WriteAllText($vfSrc, 'NOVA-VF-PAYLOAD-ABC', [System.Text.UTF8Encoding]::new($false))
$packOut = & $Packer "$root\tests\test_target.exe" '-o' $wmExe '-watermark' 'REG-WM-123' '-vf' $vfSrc 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { Write-Host "[FAIL] wm pack"; $script:fail++ }
else {
  $got = (& $Packer $wmExe '-showwatermark' 2>&1 | Out-String).Trim()
  if ($got -match 'REG-WM-123') { Write-Host '[ OK ] watermark readback' } else { Write-Host "[FAIL] watermark readback: $got"; $script:fail++ }
  $lst = (& $Packer $wmExe '-listvf' 2>&1 | Out-String)
  if ($lst -match 'vf_in\.dat') { Write-Host '[ OK ] virtual file list' } else { Write-Host "[FAIL] vf list: $lst"; $script:fail++ }
  $extractDir = Join-Path $out 'extract-vf'
  New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
  $extractedPath = Join-Path $extractDir 'vf_in.dat'
  Remove-Item -LiteralPath $extractedPath -Force -ErrorAction SilentlyContinue
  Push-Location $extractDir
  $ext = (& $Packer $wmExe '-extractvf' 'vf_in.dat' 2>&1 | Out-String)
  $back = if (Test-Path $extractedPath) { [IO.File]::ReadAllText($extractedPath) } else { '' }
  Pop-Location
  if ($back -eq 'NOVA-VF-PAYLOAD-ABC') { Write-Host '[ OK ] virtual file extract' } else { Write-Host "[FAIL] vf extract: $back"; $script:fail++ }
  $rt = & $wmExe 2>&1 | Out-String
  if ($rt -match 'Hash: 0x6DD33F53') { Write-Host '[ OK ] wm image runs' } else { Write-Host "[FAIL] wm image run: $rt"; $script:fail++ }
}

Write-Host '--- licensing (x64) ---'
Run-One 'x64_lic_ok'  "$root\tests\test_target.exe" @('-mode','ultra','-mut','1','-license','NOVA-KEY-2026-ABCD') 'Hash: 0x6DD33F53'
Run-One 'x64_lic_all' "$root\tests\test_target.exe" @('-mode','ultra','-ad','3','-avm','2','-memory','-mut','1','-license','NOVA-KEY-2026-ABCD') 'Hash: 0x6DD33F53'
# negative: corrupt the embedded license blob -> should trip the runtime (non-zero exit)
$licBad = Join-Path $out 'x64_lic_bad.exe'
Remove-Item $licBad -ErrorAction SilentlyContinue
$null = & $Packer "$root\tests\test_target.exe" '-o' $licBad '-mode' 'ultra' '-mut' '1' '-license' 'NOVA-KEY-2026-ABCD' 2>&1
if (Test-Path $licBad) {
  $bytes = [IO.File]::ReadAllBytes($licBad)
  for ($i = 0; $i -lt $bytes.Length - 4; $i++) {
    if ($bytes[$i] -eq 0x4E -and $bytes[$i+1] -eq 0x50 -and $bytes[$i+2] -eq 0x50 -and $bytes[$i+3] -eq 0x31 -and $bytes[$i+4] -in @(1,2)) { $npp = $i }
  }
  $nppVer = [BitConverter]::ToUInt32($bytes, $npp + 4)
  $licBlobOff = if ($nppVer -ge 2) { 128 } else { 96 }
  $bytes[$npp + $licBlobOff] = $bytes[$npp + $licBlobOff] -bxor 0xFF
  [IO.File]::WriteAllBytes($licBad, $bytes)
  $null = & $licBad 2>&1
  if ($LASTEXITCODE -ne 0) { Write-Host '[ OK ] x64_lic_bad (rejected)' } else { Write-Host '[FAIL] x64_lic_bad : accepted a tampered license'; $script:fail++ }
} else {
  Write-Host '[FAIL] x64_lic_bad : pack failed'; $script:fail++
}
Write-Host '--- VM virtualization (x64) ---'
Run-One 'x64_vm' "$root\tests\vm_target.exe" @('-mode','virtualization','-vm','5') 'VM-OK'
Run-One 'x64_vm_all' "$root\tests\vm_target.exe" @('-mode','ultra','-mut','3','-vm','9','-ad','3','-avm','2','-memory') 'VM-OK'

# Negative: corrupt one byte of the embedded VM bytecode. The interpreter must
# then produce a different result, which proves the region really executes in
# the VM instead of falling back to the original native code.
$vmBad = Join-Path $out 'x64_vm_bad.exe'
Remove-Item $vmBad -ErrorAction SilentlyContinue
$null = & $Packer "$root\tests\vm_target.exe" '-o' $vmBad '-mode' 'virtualization' '-vm' '5' 2>&1
if (Test-Path $vmBad) {
  $bytes = [IO.File]::ReadAllBytes($vmBad)
  $npp = -1
  for ($i = 0; $i -lt $bytes.Length - 5; $i++) {
    if ($bytes[$i] -eq 0x4E -and $bytes[$i+1] -eq 0x50 -and $bytes[$i+2] -eq 0x50 -and
        $bytes[$i+3] -eq 0x31 -and $bytes[$i+4] -in @(1,2)) { $npp = $i; break }
  }
  if ($npp -ge 0) {
    $descOff  = [BitConverter]::ToUInt32($bytes, $npp + 20)
    $descCnt  = [BitConverter]::ToUInt32($bytes, $npp + 88)
    if ($descOff -gt 0 -and $descCnt -ge 1) {
      $bcOff = [BitConverter]::ToUInt32($bytes, $npp + $descOff + 8)
      $bcLen = [BitConverter]::ToUInt32($bytes, $npp + $descOff + 12)
      # Corrupt the first instruction's destination operand byte. This is
      # deterministic for any layout: a register byte >= 16 makes the VM
      # ignore the write, so the guest sees the wrong value and reports a
      # mismatch (or the interpreter crashes) - either way the tamper is
      # observable, which proves the bytecode really executes.
      # Corrupt the destination operand of the second instruction
      # (mov rcx, r9). The register byte becomes >= 16 so the VM ignores the
      # write and rcx keeps its entry value, which changes the result.
      $pos = $npp + $bcOff + 4
      $bytes[$pos] = $bytes[$pos] -bxor 0xFF
      [IO.File]::WriteAllBytes($vmBad, $bytes)
      $vmOut = & $vmBad 2>&1 | Out-String
      if ($LASTEXITCODE -ne 0 -and $vmOut -match 'VM-MISMATCH') {
        Write-Host '[ OK ] x64_vm_bad (bytecode executed, tamper detected)'
      } else {
        Write-Host "[FAIL] x64_vm_bad : tampered bytecode still matched"; $script:fail++
      }
    } else { Write-Host '[FAIL] x64_vm_bad : no VM descriptor table'; $script:fail++ }
  } else { Write-Host '[FAIL] x64_vm_bad : NPP1 blob not found'; $script:fail++ }
} else { Write-Host '[FAIL] x64_vm_bad : pack failed'; $script:fail++ }
Write-Host ''
if ($script:fail -eq 0) { Write-Host 'ALL PASS' } else { Write-Host "$script:fail FAILURES" }
exit $script:fail
