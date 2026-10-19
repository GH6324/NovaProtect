[CmdletBinding()]
param(
  [int]$Port = 5083,
  [string]$PhpPath,
  [string]$ReleaseDirectory,
  [string]$SetupToken,
  [string]$DataDirectory
)

$ErrorActionPreference = 'Stop'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function ConvertTo-LowerHex([byte[]]$Value) {
  return ([BitConverter]::ToString($Value) -replace '-', '').ToLowerInvariant()
}

$root = Split-Path -Parent $PSScriptRoot
$website = Join-Path $root 'website'
$public = Join-Path $website 'public'
$output = Join-Path $root 'output'
$version = (Get-Content -LiteralPath (Join-Path $website 'VERSION') -Raw).Trim()
if (-not (Test-Path -LiteralPath (Join-Path $public 'index.php') -PathType Leaf)) { throw "Missing PHP entrypoint: $public\index.php" }

if (-not $PhpPath) {
  $command = Get-Command php -ErrorAction SilentlyContinue
  if ($command) { $PhpPath = $command.Source }
}
if (-not $PhpPath -or -not (Test-Path -LiteralPath $PhpPath -PathType Leaf)) {
  throw "PHP CLI not found. Install PHP 8.4 or pass -PhpPath C:\path\php.exe."
}
$PhpPath = [IO.Path]::GetFullPath($PhpPath)
New-Item -ItemType Directory -Force -Path $output | Out-Null
if (-not $DataDirectory) { $DataDirectory = Join-Path $output "website-test-data-${version}-${Port}" }
$DataDirectory = [IO.Path]::GetFullPath($DataDirectory)
New-Item -ItemType Directory -Force -Path $DataDirectory | Out-Null
if (-not $ReleaseDirectory) { $ReleaseDirectory = Join-Path $output "website-test-downloads-$version" }
$ReleaseDirectory = [IO.Path]::GetFullPath($ReleaseDirectory)
New-Item -ItemType Directory -Force -Path $ReleaseDirectory | Out-Null
$releaseMetadataPath = Join-Path $website 'release.json'
if (Test-Path -LiteralPath $releaseMetadataPath -PathType Leaf) {
  $releaseMetadata = Get-Content -LiteralPath $releaseMetadataPath -Raw | ConvertFrom-Json
  $installerSource = Join-Path $root ("artifacts\client-installer\{0}\{1}" -f $releaseMetadata.clientVersion, $releaseMetadata.fileName)
  if (Test-Path -LiteralPath $installerSource -PathType Leaf) {
    Copy-Item -LiteralPath $installerSource -Destination (Join-Path $ReleaseDirectory $releaseMetadata.fileName) -Force
  }
}

if (-not $SetupToken) {
  $bytes = New-Object byte[] 32
  $random = [Security.Cryptography.RandomNumberGenerator]::Create()
  try { $random.GetBytes($bytes) } finally { $random.Dispose() }
  $SetupToken = ConvertTo-LowerHex $bytes
}
$hasher = [Security.Cryptography.SHA256]::Create()
try { $tokenHash = $hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($SetupToken)) } finally { $hasher.Dispose() }
$setup = [ordered]@{
  tokenHash = ConvertTo-LowerHex $tokenHash
  expiresAt = ([DateTimeOffset]::UtcNow.AddHours(24).ToString("yyyy-MM-ddTHH:mm:ssZ"))
  websiteVersion = $version
}
$setupJson = $setup | ConvertTo-Json
[IO.File]::WriteAllText((Join-Path $DataDirectory "setup.json"), $setupJson, $utf8NoBom)

$env:NOVAPROTECT_DEV = "1"
$env:NOVAPROTECT_DATA_DIR = $DataDirectory
$env:NOVAPROTECT_RELEASE_DIR = $ReleaseDirectory
$env:NOVAPROTECT_SITE_URL = "http://127.0.0.1:$Port"
$logOut = Join-Path $output "website-$Port.stdout.log"
$logErr = Join-Path $output "website-$Port.stderr.log"
$recordPath = Join-Path $output "website-$Port.test.json"
$arguments = @('-S', "127.0.0.1:$Port", '-t', $public, (Join-Path $public 'index.php'))
# Start-Process builds a case-insensitive dictionary from the environment and
# throws when both HTTPS_PROXY and https_proxy are present (machines that set
# proxy variables in both casings). Drop the duplicates for the child launch
# only; the running session gets them back immediately afterwards.
$proxyNames = 'HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy', 'NO_PROXY', 'no_proxy'
$savedProxy = @{}
foreach ($name in $proxyNames) {
  $value = [Environment]::GetEnvironmentVariable($name, 'Process')
  if ($null -ne $value) {
    $savedProxy[$name] = $value
    [Environment]::SetEnvironmentVariable($name, $null, 'Process')
  }
}
try {
  $process = Start-Process -FilePath $PhpPath -ArgumentList $arguments -WorkingDirectory $public -WindowStyle Hidden -PassThru -RedirectStandardOutput $logOut -RedirectStandardError $logErr
}
finally {
  foreach ($name in @($savedProxy.Keys)) {
    [Environment]::SetEnvironmentVariable($name, $savedProxy[$name], 'Process')
  }
}
$record = [ordered]@{
  Pid = $process.Id
  Path = $PhpPath
  Port = $Port
  WebsiteVersion = $version
  DataDirectory = $DataDirectory
  ReleaseDirectory = $ReleaseDirectory
  Log = $logErr
  StartedAt = [DateTimeOffset]::Now.ToString('O')
}
$recordJson = $record | ConvertTo-Json
[IO.File]::WriteAllText($recordPath, $recordJson, $utf8NoBom)

for ($i = 0; $i -lt 40; $i++) {
  try {
    $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 2
    if ($response.StatusCode -eq 200 -and $response.Content -match "Healthy") {
      Write-Host "WEBSITE-READY Development port=$Port PID=$($process.Id)"
      Write-Host "PHP=$PhpPath"
      Write-Host "DATA=$DataDirectory"
      Write-Host "RELEASES=$ReleaseDirectory"
      Write-Host "SETUP-TOKEN=$SetupToken"
      Write-Host "LOG=$logErr"
      exit 0
    }
  } catch { Start-Sleep -Milliseconds 250 }
}
if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
throw "PHP website did not become ready; inspect $logErr."
