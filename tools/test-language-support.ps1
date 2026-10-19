[CmdletBinding()]
param([string]$Packer,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$version=(Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim()
if(-not $Packer){
  & (Join-Path $PSScriptRoot 'test-client-ui.ps1') -OutputDirectory $OutputDirectory
  exit $LASTEXITCODE
}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root "artifacts\language-support-$version"}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$utf8=[Text.UTF8Encoding]::new($false)
$results=@()
foreach($language in @('cpp','csharp','vb','rust','go')){
  $sample=Join-Path $root "tests\samples\$language\$language-sample.exe"
  $protected=Join-Path $OutputDirectory "$language-protected.exe"
  $baseline=& $sample 'E2E' 2>&1 | Out-String
  $baselineExit=$LASTEXITCODE
  if($baselineExit -ne 0){throw "$language baseline failed: $baselineExit"}
  $log=& $Packer $sample '-o' $protected 2>&1 | Out-String
  $protectExit=$LASTEXITCODE
  [IO.File]::WriteAllText((Join-Path $OutputDirectory "$language.protect.log"),$log,$utf8)
  if($protectExit -ne 0){throw "$language protect failed: $protectExit"}
  $observed=& $protected 'E2E' 2>&1 | Out-String
  $runExit=$LASTEXITCODE
  [IO.File]::WriteAllText((Join-Path $OutputDirectory "$language.baseline.txt"),$baseline,$utf8)
  [IO.File]::WriteAllText((Join-Path $OutputDirectory "$language.stdout.txt"),$observed,$utf8)
  if($runExit -ne $baselineExit -or $observed.Trim() -ne $baseline.Trim()){throw "$language runtime differs from same-argument baseline"}
  $results += [ordered]@{
    Language=$language;ProtectExit=$protectExit;RunExit=$runExit;Arguments=@('E2E');
    Options='base';SampleSHA256=(Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash;
    ProtectedSHA256=(Get-FileHash -LiteralPath $protected -Algorithm SHA256).Hash;Bytes=(Get-Item -LiteralPath $protected).Length
  }
  Write-Host "[ OK ] $language protection and same-argument baseline runtime"
}
$results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'results.json') -Encoding UTF8
Write-Host 'LANGUAGE-SAMPLES-OK (5 languages, base options)'
