[CmdletBinding()]
param([string]$InstallDirectory)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$version=(Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim()
if (-not $InstallDirectory) { $InstallDirectory=Join-Path $env:TEMP ('NovaProtectInstall'+$version.Replace('.','')) }
$ui=Join-Path $InstallDirectory 'NovaProtect.exe'
$cli=Join-Path $InstallDirectory 'NovaProtect.Engine.exe'
foreach($file in @($ui,$cli,(Join-Path $InstallDirectory 'Assets\NovaProtect.ico'))) {
  if(-not(Test-Path -LiteralPath $file -PathType Leaf)){throw "Missing installed file: $file"}
}
$output=Join-Path $root 'output'
$rejected=Start-Process -FilePath $cli -ArgumentList '-machineid' -PassThru -WindowStyle Hidden
if(-not $rejected.WaitForExit(10000)){Stop-Process -Id $rejected.Id;throw 'Installed direct core call did not fail closed'}
if($rejected.ExitCode -eq 0){throw 'Installed direct core call was accepted'}
& (Join-Path $PSScriptRoot 'verify-client-startup.ps1') -Directory $InstallDirectory
if($LASTEXITCODE){throw 'Installed genuine UI/core invocation failed'}
$process=Start-Process -FilePath $ui -WorkingDirectory $InstallDirectory -PassThru -WindowStyle Hidden
$ready=$false
for($i=0;$i -lt 40;$i++){
  Start-Sleep -Milliseconds 250
  $process.Refresh()
  if($process.HasExited){throw "Installed UI exited: $($process.ExitCode)"}
  if($process.MainWindowHandle -ne 0 -and $process.MainWindowTitle -eq 'NovaProtect' -and $process.Responding){$ready=$true;break}
}
if(-not $ready){throw 'No responsive NovaProtect top-level window'}
Add-Type -AssemblyName System.Drawing
$icon=[Drawing.Icon]::ExtractAssociatedIcon($ui)
if($null -eq $icon){throw 'Installed executable icon not found'}
$bitmap=$icon.ToBitmap()
try{$bitmap.Save((Join-Path $output "installed-icon-$version.png"),[Drawing.Imaging.ImageFormat]::Png)}
finally{$bitmap.Dispose();$icon.Dispose()}
$shortcut=Join-Path ([Environment]::GetFolderPath('Programs')) 'NovaProtect\NovaProtect.lnk'
if(-not(Test-Path -LiteralPath $shortcut)){throw 'NovaProtect Start Menu link missing'}
$shell=New-Object -ComObject WScript.Shell
$target=$shell.CreateShortcut($shortcut).TargetPath
if($target -ne $ui){throw "Unexpected shortcut target: $target"}
$legacyLink=Join-Path ([Environment]::GetFolderPath('Programs')) 'NovaPack\NovaProtect.lnk'
if(Test-Path -LiteralPath $legacyLink){throw 'Legacy NovaPack group link still exists'}
$debug=@(Get-ChildItem -LiteralPath $InstallDirectory -Recurse -File | Where-Object { $_.Extension -in @('.pdb','.map','.vmp') -or $_.Name -like '*.vmprotect.log' })
if($debug.Count){throw 'Debug or VMP configuration files leaked into installation'}
$record=[ordered]@{
  Version=$version;Directory=$InstallDirectory;ProcessId=$process.Id;Title=$process.MainWindowTitle;
  WindowHandle=$process.MainWindowHandle.ToInt64();Responding=$process.Responding;
  FileVersion=(Get-Item -LiteralPath $ui).VersionInfo.FileVersion;DirectCoreRejected=$true;CoreViaUI=$true;
  IconExtracted=$true;StartMenuLink=$shortcut;DebugFilesExcluded=$true;
  UiSha256=(Get-FileHash -LiteralPath $ui -Algorithm SHA256).Hash;
  DllSha256=(Get-FileHash -LiteralPath (Join-Path $InstallDirectory 'NovaProtect.dll') -Algorithm SHA256).Hash;
  CliSha256=(Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash
}
$record | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output "installed-verification-$version.json") -Encoding UTF8
$record | ConvertTo-Json
Write-Host 'INSTALLED-VERIFY-OK (verified UI is left running)'
