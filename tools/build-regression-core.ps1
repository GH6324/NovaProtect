[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$version=(Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim()
$output=Join-Path $root "artifacts\test-only-core-$version"
New-Item -ItemType Directory -Force -Path $output|Out-Null
$gcc='C:\mingw\mingw64\bin\g++.exe'
Push-Location $root
try{
  & $gcc -std=c++17 -O2 -municode -o (Join-Path $output 'CoreRegression.exe') src\main.cpp tests\core_test_gate.cpp src\managed_envelope.cpp src\pe_lib.cpp src\packer.cpp src\packer_meta.cpp src\mutation.cpp src\disasm.cpp src\anti_debug.cpp src\vm_engine.cpp src\vm_obfuscate.cpp src\crypto_layers.cpp -Iinclude -Isrc -static -static-libgcc -static-libstdc++
  if($LASTEXITCODE){throw 'Test-only core build failed'}
}finally{Pop-Location}
Write-Host "TEST-ONLY-CORE $output\CoreRegression.exe (not part of installer/website)"
