[CmdletBinding()]
param(
  [string]$PackagePath,
  [ValidateSet('Full', 'Upgrade')][string]$PackageType,
  [string]$BashPath
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$version = (Get-Content -LiteralPath (Join-Path $root 'website\VERSION') -Raw).Trim()
if (-not $PackagePath) {
  $folder = if ($PackageType -eq 'Upgrade') { 'website-upgrade' } else { 'website-full' }
  $name = if ($PackageType -eq 'Upgrade') { "NovaProtect-Website-$version-Linux-x64-BaoTa-Upgrade.zip" } else { "NovaProtect-Website-$version-Linux-x64-BaoTa-Full.zip" }
  $PackagePath = Join-Path $root "artifacts\$folder\$version\$name"
}
$PackagePath = [IO.Path]::GetFullPath($PackagePath)
if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) { throw "Missing package: $PackagePath" }

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($PackagePath)
try {
  $entries = @{}
  foreach ($entry in $zip.Entries) {
    $name = $entry.FullName.Replace('\','/')
    if ($name.EndsWith('/')) { continue }
    if ($name -match '(^|/)(Pages|Properties|Services|source|bin|obj|App_Data|__pycache__|\.git)(/|$)|(^|/)\.env($|\.)|(^|/)accounts\.json$|(^|/)key-[^/]+\.xml$|\.pdb$|(^|/)\.\./|^/' ) { throw "Forbidden package entry: $name" }
    if ($name -match '\.(cs|cshtml|csproj|dll|so|dylib)$' -or $name -eq 'deploy/novaprotect.service') { throw "Stale ASP.NET/native website entry: $name" }
    if ($entries.ContainsKey($name)) { throw "Duplicate package entry: $name" }
    $entries[$name] = $entry
  }

  function Read-EntryText([string]$name) {
    if (-not $entries.ContainsKey($name)) { throw "Missing package entry: $name" }
    $reader = [IO.StreamReader]::new($entries[$name].Open())
    try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
  }
  function Hash-Entry([string]$name) {
    $stream = $entries[$name].Open()
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
  }

  $metadata = Read-EntryText 'package.json' | ConvertFrom-Json
  $metadataType = ([string]$metadata.packageType).ToLowerInvariant()
  if ($metadataType -notin @('full', 'upgrade')) { throw "Invalid package.json packageType: $metadataType" }
  if ([string]$metadata.product -ne 'NovaProtect') { throw 'Invalid package.json product' }
  if ([string]$metadata.websiteVersion -ne $version) { throw 'package.json websiteVersion mismatch' }
  $actualType = if ($PackageType) { $PackageType.ToLowerInvariant() } else { $metadataType }
  if ($metadataType -ne $actualType) { throw "Package type mismatch: metadata=$metadataType requested=$actualType" }

  $required = @(
    'SHA256SUMS','VERSION','release.json','package.json','README.md','upgrade.sh',
    'app/bootstrap.php','app/features.php','app/site.php','app/portal.php','app/view.php','app/version.json','public/index.php',
    'public/.user.ini','public/css/site.css','public/js/upload-progress.js','public/assets/novaprotect.png','public/favicon.ico',
    'deploy/upgrade.sh','deploy/migrate.php','deploy/reset-admin-password.php','deploy/rollback.sh','deploy/health-check.sh','deploy/upgrade-executor.sh','deploy/novaprotect-upgrade-executor.service','deploy/novaprotect-upgrade-executor.timer','deploy/configure_nginx.py','deploy/nginx-location.conf',
    'deploy/cdnfly-edge-policy.json','deploy/cdnfly-check.sh','deploy/CDNFLY.md'
  )
  if ($actualType -eq 'full') {
    $required += @('install.sh','deploy/install.sh','deploy/configure_nginx.py','deploy/nginx-location.conf','deploy/entry-install.sh')
  }
  foreach ($name in $required) { if (-not $entries.ContainsKey($name)) { throw "Missing package entry: $name" } }
  if (-not ($entries.Keys | Where-Object { $_ -like 'downloads/*' })) { throw 'Missing downloads payload' }

  if ($actualType -eq 'upgrade') {
    foreach ($forbidden in @('install.sh','deploy/install.sh','deploy/entry-install.sh')) {
      if ($entries.ContainsKey($forbidden)) { throw "Upgrade package contains full-install entry: $forbidden" }
    }
  }

  $release = Read-EntryText 'release.json' | ConvertFrom-Json
  if ([string]$release.websiteVersion -ne $version) { throw 'release.json websiteVersion mismatch' }
  if ((Read-EntryText 'VERSION').Trim() -ne $version) { throw 'Package VERSION mismatch' }
  $appVersion = Read-EntryText 'app/version.json' | ConvertFrom-Json
  if ([string]$appVersion.websiteVersion -ne $version) { throw 'PHP websiteVersion mismatch' }
  $clientFile = [string]$release.fileName
  if ($clientFile -notmatch '^NovaProtect-Setup-\d+\.\d+\.\d+\.exe$') { throw 'Invalid release filename' }
  $downloadEntry = "downloads/$clientFile"
  if (-not $entries.ContainsKey($downloadEntry)) { throw "Missing package entry: $downloadEntry" }
  $expectedClientHash = ([string]$release.sha256).ToLowerInvariant()
  if ($expectedClientHash -notmatch '^[a-f0-9]{64}$') { throw 'Invalid release SHA-256' }
  if ((Hash-Entry $downloadEntry) -ne $expectedClientHash) { throw 'Client installer hash does not match release.json' }
  $phpUploadConfig = Read-EntryText 'public/.user.ini'
  if ($phpUploadConfig -notmatch '(?m)^upload_max_filesize=256M$' -or $phpUploadConfig -notmatch '(?m)^post_max_size=260M$') { throw 'PHP-FPM upload limits are missing or too small' }

  $manifest = Read-EntryText 'SHA256SUMS'
  $count = 0
  foreach ($line in $manifest -split "`n" | Where-Object { $_ -ne '' }) {
    if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw "Invalid SHA256SUMS row: $line" }
    $expected = $Matches[1]
    $name = $Matches[2].TrimEnd("`r")
    if (-not $entries.ContainsKey($name)) { throw "Manifest file absent: $name" }
    if ((Hash-Entry $name) -ne $expected) { throw "Package file hash mismatch: $name" }
    $count++
  }
  if ($count -ne $entries.Count - 1) { throw 'Not every archive file is covered by SHA256SUMS' }

  $shellScripts = @('upgrade.sh','deploy/upgrade.sh','deploy/rollback.sh','deploy/health-check.sh','deploy/upgrade-executor.sh')
  if ($actualType -eq 'full') { $shellScripts += @('install.sh','deploy/install.sh') }
  foreach ($script in $shellScripts) {
    $body = Read-EntryText $script
    if ($body.Contains("`r") -or -not $body.StartsWith('#!/usr/bin/env bash')) { throw "Script has invalid LF/shebang: $script" }
  }
  $bootstrapText = Read-EntryText 'app/bootstrap.php'
  if ($bootstrapText -notmatch 'NOVAPROTECT_DATA_DIR') { throw 'PHP bootstrap is incomplete' }
  if ($bootstrapText -match "session_name\('novaprotect\.sid'\)") { throw 'PHP session name contains an invalid dot' }
  if ($bootstrapText -notmatch "session_name\('novaprotect_sid'\)") { throw 'PHP session name is missing' }
  if ($bootstrapText -notmatch "Content-Security-Policy: default-src 'self'") { throw 'PHP security headers are incomplete' }
  if ($bootstrapText -notmatch 'np_admin_password_hash|np_admin_sign_in') { throw 'PHP admin session bootstrap is missing' }
  $installWizardLabel = [string]::new([char[]](0x5B89, 0x88C5, 0x5411, 0x5BFC))
  if ((Read-EntryText 'app/site.php') -notmatch [regex]::Escape($installWizardLabel)) { throw 'PHP install wizard is missing' }
  if ((Read-EntryText 'app/site.php') -notmatch 'action="/admin/login"') { throw 'Admin login form is missing' }
  if ((Read-EntryText 'app/features.php') -notmatch 'minimumClientVersion|forceUpdate|releaseNotes') { throw 'Client release upload contract is missing' }
  if ((Read-EntryText 'app/portal.php') -notmatch 'np_admin_client_releases|np_admin_upgrades') { throw 'Admin release panels are missing' }
  if ((Read-EntryText 'deploy/upgrade.sh') -notmatch 'UPGRADE-PACKAGE-CHECK-OK|maintenance\.json|MIGRATION-OK') { throw 'PHP offline upgrade flow is missing' }
  $resetTool = Read-EntryText 'deploy/reset-admin-password.php'
  if ($resetTool -notmatch "PHP_SAPI !== 'cli'") { throw 'Admin password reset tool is missing the CLI-only guard' }
  if ($resetTool -notmatch 'np_set_admin_password') { throw 'Admin password reset tool does not reuse the shared password writer' }
  if ($resetTool -notmatch 'NOVAPROTECT_DATA_DIR') { throw 'Admin password reset tool does not honour the data directory' }
  if ($resetTool -match '(?i)(?<![a-zA-Z0-9_])password_hash\s*\(' -or $resetTool -match '(?i)(?<![a-zA-Z0-9_])hash_pbkdf2\s*\(') { throw 'Admin password reset tool must not hash passwords on its own' }
  if ((Read-EntryText 'deploy/upgrade.sh') -notmatch 'reset-admin-password\.php.*\$state/bin/reset-admin-password\.php') { throw 'Upgrade script does not install the admin password reset tool' }
  if ($resetTool -notmatch 'site-root' -or $resetTool -notmatch '/www/wwwroot/') { throw 'Admin password reset tool cannot locate the installed site tree' }
  foreach ($installer in @('deploy/install.sh', 'deploy/upgrade.sh')) {
    if (-not $entries.ContainsKey($installer)) { continue }
    if ((Read-EntryText $installer) -notmatch 'state/site-root') { throw "$installer does not record the site root for the reset tool" }
  }
  if ((Read-EntryText 'deploy/cdnfly-edge-policy.json') -notmatch 'application-dynamic|/js/|/_guard/auto\.js|444') { throw 'CDNfly edge policy is incomplete' }
  if ((Read-EntryText 'deploy/cdnfly-check.sh') -notmatch '/admin/login|CDNFLY-PREFLIGHT-OK|/_guard/auto\.js') { throw 'CDNfly preflight is incomplete' }
  if ((Read-EntryText 'deploy/CDNFLY.md') -notmatch 'highest priority|purge|444') { throw 'CDNfly deployment guide is incomplete' }
  if ((Read-EntryText 'deploy/migrate.php') -match "require\s+dirname\(__DIR__\)\s*\.\s*'/app/features\.php'") { throw 'Migration script redeclares bootstrap-loaded features.php' }
  if ((Read-EntryText 'deploy/upgrade.sh') -notmatch 'repair_data_permissions|chown -R www:www') { throw 'Upgrade script does not repair PHP-FPM data permissions' }
  if ($actualType -eq 'full' -and
      (Read-EntryText 'deploy/install.sh') -match 'NovaProtect\.Web|ExecStart=.*NovaProtect\.Web|website\.csproj') {
    throw 'PHP installer still depends on ASP.NET systemd service'
  }
  if ($actualType -eq 'full' -and (Read-EntryText 'deploy/install.sh') -notmatch 'repair_data_permissions|chown -R www:www') {
    throw 'Installer does not repair PHP-FPM data permissions'
  }
  if ($actualType -eq 'full' -and (Read-EntryText 'deploy/install.sh') -notmatch 'reset-admin-password\.php.*\$state/bin/reset-admin-password\.php') {
    throw 'Installer does not install the admin password reset tool'
  }

} finally { $zip.Dispose() }

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python3 -ErrorAction Stop }
$testArguments = @('-B', (Join-Path $root 'tests\website_installer_test.py'), '--package', $PackagePath, '--kind', $actualType)
if (-not $BashPath) { $BashPath = $env:NOVAPROTECT_TEST_BASH }
if (-not $BashPath) {
  # website_installer_test.py needs a GNU bash with coreutils (sha256sum).
  # Probe the usual locations so this also works from a bare PowerShell host.
  $bashCandidates = @()
  $git = Get-Command git -ErrorAction SilentlyContinue
  if ($git) {
    $gitRoot = Split-Path -Parent (Split-Path -Parent $git.Source)
    $bashCandidates += (Join-Path $gitRoot 'usr\bin\bash.exe')
  }
  $pf86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
  $bashCandidates += @(
    (Join-Path $env:ProgramFiles 'Git\bin\bash.exe'),
    (Join-Path $pf86 'Git\bin\bash.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\Git\bin\bash.exe'),
    (Join-Path $env:ProgramFiles 'Git\usr\bin\bash.exe')
  )
  # WorkBuddy Desktop ships a PortableGit under its own vendor directory.
  foreach ($driveRoot in @('D:\', 'C:\')) {
    $bashCandidates += (Join-Path $driveRoot 'WorkBuddy\resources\vendor\PortableGit\usr\bin\bash.exe')
  }
  foreach ($candidate in $bashCandidates) {
    if ($candidate -and (Test-Path -LiteralPath $candidate)) { $BashPath = $candidate; break }
  }
}
if ($BashPath) { $testArguments += @('--bash', $BashPath) }
# unittest reports progress on stderr; under $ErrorActionPreference='Stop'
# Windows PowerShell 5.1 turns native stderr output into a terminating
# NativeCommandError, so relax the preference for this call and rely on the
# exit code instead.
$previousErrorAction = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try { & $python.Source @testArguments } finally { $ErrorActionPreference = $previousErrorAction }
if ($LASTEXITCODE -ne 0) { throw 'Website package entry-point regression failed' }
Write-Host "WEBSITE-$($actualType.ToUpperInvariant())-ARCHIVE-OK ($count files; all hashes match; PHP-FPM package; no ASP.NET/source/private data; LF scripts; Bash entry checks passed)"
Get-Item -LiteralPath $PackagePath | Select-Object Name,Length,@{Name='SHA256';Expression={(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}} | Format-List
