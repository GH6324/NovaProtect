[CmdletBinding()]
param([Parameter(Mandatory)][string]$Directory,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)).TrimEnd('\')
$version=(Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim()
$Directory=(Resolve-Path -LiteralPath $Directory).Path.TrimEnd('\')
$evidence=if($OutputDirectory){[IO.Path]::GetFullPath($OutputDirectory)}else{Join-Path $root "artifacts\client-gates-$version"}
if(Test-Path -LiteralPath $evidence){throw 'Preserve previous gate evidence; choose a new version/output before re-running'}
New-Item -ItemType Directory -Path $evidence|Out-Null
$records=[Collections.Generic.List[object]]::new()
Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public static class GateErrorMode { [DllImport("kernel32.dll")] public static extern uint SetErrorMode(uint mode); }'
$oldErrorMode=[GateErrorMode]::SetErrorMode(0x0002)
function Reject([string]$Name,[string]$Executable,[string]$Arguments,[string]$WorkingDirectory){
  $parameters=@{FilePath=$Executable;WorkingDirectory=$WorkingDirectory;PassThru=$true;WindowStyle='Hidden';RedirectStandardOutput=(Join-Path $evidence "$Name.stdout.txt");RedirectStandardError=(Join-Path $evidence "$Name.stderr.txt")}
  if($Arguments){$parameters.ArgumentList=$Arguments}
  $process=Start-Process @parameters
  if(-not $process.WaitForExit(45000)){Stop-Process -Id $process.Id;throw "$Name did not terminate"}
  if($process.ExitCode -eq 0){throw "$Name unexpectedly accepted"}
  $hex='0x'+[Convert]::ToString([int]$process.ExitCode,16).PadLeft(8,'0').ToUpperInvariant()
  $records.Add([ordered]@{Test=$Name;Result='rejected';Exit=$hex})
  Write-Host "GATE-REJECTED $Name $hex"
}
function Trial([string]$Name){
  $target=Join-Path $evidence $Name
  New-Item -ItemType Directory -Path $target|Out-Null
  foreach($file in Get-ChildItem -LiteralPath $Directory -Recurse -File){
    $relative=$file.FullName.Substring($Directory.Length).TrimStart('\')
    $path=Join-Path $target $relative
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path)|Out-Null
    New-Item -ItemType HardLink -Path $path -Target $file.FullName|Out-Null
  }
  return $target
}
function FlipIsolated([string]$Path){
  $bytes=[IO.File]::ReadAllBytes($Path)
  # Unlink BEFORE writing: never mutate the common release through a hardlink.
  Remove-Item -LiteralPath $Path -Force
  $bytes[$bytes.Length-1]=$bytes[$bytes.Length-1] -bxor 1
  [IO.File]::WriteAllBytes($Path,$bytes)
}
Reject 'direct-engine' (Join-Path $Directory 'NovaProtect.Engine.exe') '-machineid' $Directory
Reject 'direct-template' (Join-Path $Directory 'NovaProtect.ManagedHost.exe') '' $Directory
Reject 'external-dotnet-host' (Get-Command dotnet).Source ('"'+(Join-Path $Directory 'NovaProtect.dll')+'"') $Directory
foreach($test in @('tampered-signature','tampered-engine','missing-manifest','renamed-ui')){
  $trial=Trial $test
  try{
    $exe=Join-Path $trial 'NovaProtect.exe'
    switch($test){
      'tampered-signature'{FlipIsolated (Join-Path $trial 'client-integrity.sig')}
      'tampered-engine'{FlipIsolated (Join-Path $trial 'NovaProtect.Engine.exe')}
      'missing-manifest'{Remove-Item -LiteralPath (Join-Path $trial 'client-integrity.manifest') -Force}
      'renamed-ui'{$exe=Join-Path $trial 'ExternalHost.exe';Copy-Item -LiteralPath (Join-Path $trial 'NovaProtect.exe') -Destination $exe}
    }
    Reject $test $exe '' $trial
  }finally{
    $resolved=[IO.Path]::GetFullPath($trial).TrimEnd('\')
    if([IO.Path]::GetDirectoryName($resolved) -ne $evidence){throw 'Trial cleanup boundary'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
  }
}
& (Join-Path $PSScriptRoot 'verify-client-startup.ps1') -Directory $Directory
if($LASTEXITCODE){throw 'Genuine UI positive control failed'}
$records.Add([ordered]@{Test='genuine-ui-engine';Result='pass'})
[ordered]@{Version=$version;Directory=$Directory;Tests=$records}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $evidence 'results.json') -Encoding utf8
Write-Host 'CLIENT-GATES-OK (7 negative cases + genuine UI positive control)'
[void][GateErrorMode]::SetErrorMode($oldErrorMode)
