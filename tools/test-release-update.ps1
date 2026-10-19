[CmdletBinding()]
param([Parameter(Mandatory)][string]$ReleaseDirectory,[Parameter(Mandatory)][string]$ProbeDirectory,[Parameter(Mandatory)][string]$Inventory,[Parameter(Mandatory)][string]$OutputDirectory,[string]$Site='http://127.0.0.1:5085/',[string]$Installer)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)).TrimEnd('\')
$ReleaseDirectory=(Resolve-Path -LiteralPath $ReleaseDirectory).Path.TrimEnd('\')
$ProbeDirectory=(Resolve-Path -LiteralPath $ProbeDirectory).Path.TrimEnd('\')
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
if(-not $OutputDirectory.StartsWith($root+'\artifacts\',[StringComparison]::OrdinalIgnoreCase)){throw 'Test output must be in workspace artifacts'}
if(Test-Path -LiteralPath $OutputDirectory){throw 'Preserve previous test output; select a new empty directory'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$records=Get-Content -LiteralPath $Inventory -Raw|ConvertFrom-Json
foreach($source in Get-ChildItem -LiteralPath $ProbeDirectory -Recurse -File){
  $relative=$source.FullName.Substring($ProbeDirectory.Length).TrimStart('\')
  $target=Join-Path $OutputDirectory $relative
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target)|Out-Null
  New-Item -ItemType HardLink -Path $target -Target $source.FullName|Out-Null
}
$count=0
foreach($record in $records){
  if($record.Owned){continue}
  $target=[IO.Path]::GetFullPath((Join-Path $OutputDirectory $record.Path))
  if(-not $target.StartsWith($OutputDirectory+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Runtime target boundary'}
  if(-not(Test-Path -LiteralPath $target -PathType Leaf)){continue}
  $source=Join-Path $ReleaseDirectory $record.Path
  if(-not(Test-Path -LiteralPath $source -PathType Leaf)){continue}
  if((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -ne $record.OriginalSHA256){throw "Probe/production runtime versions differ: $($record.Path)"}
  if((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -eq $record.OriginalSHA256){continue}
  # Checked workspace target: unlink before replacement, never write a hardlink.
  Remove-Item -LiteralPath $target -Force
  Copy-Item -LiteralPath $source -Destination $target
  $count++
}
Write-Host "UPDATE-CONTRACT $count exact transformed release dependencies (test-only harness, not shipped)"
$arguments=@('--site',$Site)
if($Installer){$arguments+=@('--installer',[IO.Path]::GetFullPath($Installer))}
& (Join-Path $OutputDirectory 'NovaProtect.UpdateSmoke.exe') @arguments
if($LASTEXITCODE){throw 'Update contract on transformed release runtime failed'}
