[CmdletBinding()]
param(
  [string]$InstallerPath,
  [string]$FullOutputPath,
  [string]$UpgradeOutputPath,
  [switch]$Force
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$website = Join-Path $root 'website'
$version = (Get-Content -LiteralPath (Join-Path $website 'VERSION') -Raw).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid website VERSION: $version" }

$releasePath = Join-Path $website 'release.json'
$release = Get-Content -LiteralPath $releasePath -Raw | ConvertFrom-Json
if ([string]$release.websiteVersion -ne $version) { throw "website/release.json websiteVersion must be $version" }
$clientFile = [string]$release.fileName
if ($clientFile -notmatch '^NovaProtect-Setup-\d+\.\d+\.\d+\.exe$') { throw "Invalid release filename: $clientFile" }
if (-not $InstallerPath) { $InstallerPath = Join-Path $root "artifacts\client-installer\$($release.clientVersion)\$clientFile" }
$InstallerPath = [IO.Path]::GetFullPath($InstallerPath)
if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) { throw "Missing installer: $InstallerPath" }

$required = @(
  (Join-Path $website 'app\bootstrap.php'),
  (Join-Path $website 'app\features.php'),
  (Join-Path $website 'app\site.php'),
  (Join-Path $website 'app\portal.php'),
  (Join-Path $website 'app\view.php'),
  (Join-Path $website 'app\version.json'),
  (Join-Path $website 'public\index.php'),
  (Join-Path $website 'public\.user.ini'),
  (Join-Path $website 'public\css\site.css'),
  (Join-Path $website 'public\js\upload-progress.js'),
  (Join-Path $website 'public\assets\novaprotect.png'),
  (Join-Path $website 'public\favicon.ico'),
  (Join-Path $website 'upgrade.sh'),
  (Join-Path $website 'deploy\upgrade.sh'),
  (Join-Path $website 'deploy\migrate.php'),
  (Join-Path $website 'deploy\reset-admin-password.php'),
  (Join-Path $website 'deploy\rollback.sh'),
  (Join-Path $website 'deploy\health-check.sh'),
  (Join-Path $website 'deploy\upgrade-executor.sh'),
  (Join-Path $website 'deploy\novaprotect-upgrade-executor.service'),
  (Join-Path $website 'deploy\novaprotect-upgrade-executor.timer'),
  (Join-Path $website 'deploy\cdnfly-edge-policy.json'),
  (Join-Path $website 'deploy\cdnfly-check.sh'),
  (Join-Path $website 'deploy\CDNFLY.md'),
  (Join-Path $website 'deploy\README.md')
)
foreach ($path in $required) { if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing website file: $path" } }

if (-not $FullOutputPath) { $FullOutputPath = Join-Path $root "artifacts\website-full\$version\NovaProtect-Website-$version-Linux-x64-BaoTa-Full.zip" }
if (-not $UpgradeOutputPath) { $UpgradeOutputPath = Join-Path $root "artifacts\website-upgrade\$version\NovaProtect-Website-$version-Linux-x64-BaoTa-Upgrade.zip" }
$FullOutputPath = [IO.Path]::GetFullPath($FullOutputPath)
$UpgradeOutputPath = [IO.Path]::GetFullPath($UpgradeOutputPath)
if ($FullOutputPath -eq $UpgradeOutputPath) { throw 'FullOutputPath and UpgradeOutputPath must be different.' }

$utf8 = [Text.UTF8Encoding]::new($false)

function Copy-Tree([string]$From, [string]$To) {
  foreach ($file in (Get-ChildItem -LiteralPath $From -Recurse -File)) {
    $relative = $file.FullName.Substring($From.Length).TrimStart('\')
    $destination = Join-Path $To $relative
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
    Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
  }
}

function Write-Utf8([string]$Path, [string]$Content) {
  [IO.Directory]::CreateDirectory((Split-Path -Parent $Path)) | Out-Null
  [IO.File]::WriteAllText($Path, $Content, $utf8)
}

function Write-PackageMetadata([string]$Bundle, [ValidateSet('full', 'upgrade')][string]$Kind) {
  $purpose = if ($Kind -eq 'full') { 'initial-install-and-recovery' } else { 'offline-upgrade' }
  $entryPoints = if ($Kind -eq 'full') { @('install.sh', 'upgrade.sh') } else { @('upgrade.sh') }
  $metadata = [ordered]@{
    product = 'NovaProtect'
    packageType = $Kind
    purpose = $purpose
    websiteVersion = $version
    clientVersion = [string]$release.clientVersion
    entryPoints = $entryPoints
  }
  Write-Utf8 (Join-Path $Bundle 'package.json') (($metadata | ConvertTo-Json -Depth 5) + "`n")
}

function Write-Manifest([string]$Bundle) {
  $manifest = foreach ($file in (Get-ChildItem -LiteralPath $Bundle -Recurse -File | Sort-Object FullName)) {
    $relative = $file.FullName.Substring($Bundle.Length).TrimStart('\').Replace('\','/')
    (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $relative
  }
  Write-Utf8 (Join-Path $Bundle 'SHA256SUMS') (($manifest -join "`n") + "`n")
}

function Normalize-ShellScripts([string]$Bundle) {
  foreach ($script in (Get-ChildItem -LiteralPath $Bundle -Filter '*.sh' -Recurse -File)) {
    $body = [IO.File]::ReadAllText($script.FullName).Replace("`r`n", "`n").Replace("`r", "`n")
    [IO.File]::WriteAllText($script.FullName, $body, $utf8)
  }
}

function New-WebsitePackage([ValidateSet('Full', 'Upgrade')][string]$Kind, [string]$OutputPath) {
  $kindLower = $Kind.ToLowerInvariant()
  $bundle = Join-Path $root "artifacts\.website-bundle-$version-$kindLower"
  if (Test-Path -LiteralPath $bundle) { throw "Bundle already exists; preserve it and use a new version: $bundle" }
  if (Test-Path -LiteralPath $OutputPath) {
    if (-not $Force) { throw "Refusing to overwrite: $OutputPath" }
    # Under hardened execution policies Remove-Item may raise after the
    # deletion has already been applied; tolerate that and re-check below.
    try { Remove-Item -LiteralPath $OutputPath -Force -ErrorAction Stop } catch { }
    if (Test-Path -LiteralPath $OutputPath) { throw "Failed to remove stale output: $OutputPath" }
  }

  try {
    New-Item -ItemType Directory -Force -Path $bundle, (Split-Path -Parent $OutputPath) | Out-Null
    Copy-Tree (Join-Path $website 'app') (Join-Path $bundle 'app')
    Copy-Tree (Join-Path $website 'public') (Join-Path $bundle 'public')
    New-Item -ItemType Directory -Force -Path (Join-Path $bundle 'deploy'), (Join-Path $bundle 'downloads') | Out-Null

    foreach ($name in @('upgrade.sh','migrate.php','reset-admin-password.php','rollback.sh','health-check.sh','upgrade-executor.sh','novaprotect-upgrade-executor.service','novaprotect-upgrade-executor.timer','cdnfly-edge-policy.json','cdnfly-check.sh','CDNFLY.md','README.md','configure_nginx.py','nginx-location.conf')) {
      Copy-Item -LiteralPath (Join-Path $website "deploy\$name") -Destination (Join-Path $bundle "deploy\$name") -Force
    }
    Copy-Item -LiteralPath (Join-Path $website 'upgrade.sh') -Destination (Join-Path $bundle 'upgrade.sh') -Force
    Copy-Item -LiteralPath $releasePath -Destination (Join-Path $bundle 'release.json') -Force
    Copy-Item -LiteralPath (Join-Path $website 'VERSION') -Destination (Join-Path $bundle 'VERSION') -Force
    Copy-Item -LiteralPath $InstallerPath -Destination (Join-Path $bundle ("downloads\$clientFile")) -Force
    Copy-Item -LiteralPath (Join-Path $website 'deploy\README.md') -Destination (Join-Path $bundle 'README.md') -Force

    if ($Kind -eq 'Full') {
      foreach ($name in @('install.sh','entry-install.sh')) {
        Copy-Item -LiteralPath (Join-Path $website "deploy\$name") -Destination (Join-Path $bundle "deploy\$name") -Force
      }
      Copy-Item -LiteralPath (Join-Path $website 'deploy\entry-install.sh') -Destination (Join-Path $bundle 'install.sh') -Force
    }

    Write-PackageMetadata $bundle $kindLower
    Normalize-ShellScripts $bundle
    Write-Manifest $bundle
    Compress-Archive -Path (Join-Path $bundle '*') -DestinationPath $OutputPath -CompressionLevel Optimal

    $verify = Join-Path $PSScriptRoot 'verify-website-package.ps1'
    & $verify -PackagePath $OutputPath -PackageType $Kind
    if ($LASTEXITCODE -ne 0) { throw "Package verification failed: $OutputPath" }
    $hash = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash
    Write-Host "WEBSITE-$($Kind.ToUpperInvariant())-PACKAGE $OutputPath"
    Write-Host "SHA256 $hash"
  }
  finally {
    if (Test-Path -LiteralPath $bundle) {
      try { Remove-Item -LiteralPath $bundle -Recurse -Force -ErrorAction Stop } catch { }
      if (Test-Path -LiteralPath $bundle) { Write-Warning "Bundle directory could not be cleaned: $bundle" }
    }
  }
}

New-WebsitePackage Full $FullOutputPath
New-WebsitePackage Upgrade $UpgradeOutputPath

Write-Host 'WEBSITE-PACKAGES-READY'
Get-Item -LiteralPath $FullOutputPath, $UpgradeOutputPath |
  Select-Object FullName,Length,@{Name='SHA256';Expression={(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}} |
  Format-Table -AutoSize
