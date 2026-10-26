[CmdletBinding()]
param(
  [string]$Directory,
  [string]$Target,
  [string]$OutputDirectory,
  [int]$Height = 2600
)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if(-not $Directory){$Directory=Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64'}
if(-not $Target){$Target=Join-Path $root 'tests\samples\cpp\cpp-sample.exe'}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root "artifacts\ui-full-$([DateTime]::Now.ToString('yyyyMMdd-HHmmss'))"}
$Directory=[IO.Path]::GetFullPath($Directory)
New-Item -ItemType Directory -Force -Path $OutputDirectory|Out-Null
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Win5 {
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h,int x,int y,int w,int hgt,bool repaint);
}
'@
$scope=[System.Windows.Automation.TreeScope]::Descendants
$script:process=$null
$script:window=$null
function Find-Id([string]$Id){
  $c=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty,$Id)
  $script:window.FindFirst($scope,$c)
}
function Find-Name([string]$Name,[string]$Type){
  $c=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty,$Name)
  @($script:window.FindAll($scope,$c))|Where-Object { -not $Type -or $_.Current.ControlType.ProgrammaticName -eq "ControlType.$Type" }|Select-Object -First 1
}
function Click($e){ if(-not $e){throw 'control missing'}; $e.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke() }
function Set-Value($e,[string]$v){ if(-not $e){throw 'value control missing'}; $e.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue($v) }
function Get-Value($e){ if(-not $e){return $null}; try{$e.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).Current.Value}catch{$null} }
function Wait-Until([scriptblock]$c,[string]$fail,[int]$sec=90){
  $until=[DateTime]::UtcNow.AddSeconds($sec)
  while([DateTime]::UtcNow -lt $until){
    $script:process.Refresh()
    if($script:process.HasExited){throw "UI exited $($script:process.ExitCode)"}
    if(& $c){return}
    Start-Sleep -Milliseconds 300
  }
  throw $fail
}
try{
  $script:process=Start-Process -FilePath (Join-Path $Directory 'NovaProtect.exe') -WorkingDirectory $Directory -PassThru
  Wait-Until { $script:process.MainWindowHandle -ne 0 } 'UI window not ready'
  [Win5]::MoveWindow($script:process.MainWindowHandle,0,0,1500,$Height,$true)|Out-Null
  Start-Sleep -Milliseconds 1200
  $script:window=[System.Windows.Automation.AutomationElement]::FromHandle($script:process.MainWindowHandle)
  (Find-Name '保护项目' 'ListItem').GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
  Wait-Until { $null -ne (Find-Id 'InputPathBox') } 'protect page not ready'
  Set-Value (Find-Id 'InputPathBox') $Target
  Start-Sleep -Seconds 2
  Click (Find-Name '扫描函数' 'Button')
  Start-Sleep -Seconds 4

  $r=$script:window.Current.BoundingRectangle
  $bmp=New-Object System.Drawing.Bitmap([int]$r.Width,[int]$r.Height)
  $g=[System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen([int]$r.X,[int]$r.Y,0,0,$bmp.Size)
  $bmp.Save((Join-Path $OutputDirectory 'full.png'),[System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose(); $bmp.Dispose()
  Write-Host "shot full.png"

  # Raw text of every text element, plus the log box, as UTF-8 bytes.
  $lines=New-Object System.Collections.Generic.List[string]
  foreach($i in $script:window.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition)){
    try{ $n=$i.Current.Name; $id=$i.Current.AutomationId }catch{continue}
    if([string]::IsNullOrWhiteSpace($n)){continue}
    $lines.Add("$id|$n")
  }
  [IO.File]::WriteAllLines((Join-Path $OutputDirectory 'text.txt'),$lines,[Text.UTF8Encoding]::new($false))
  Write-Host "text.txt lines=$($lines.Count)"
  Write-Host 'FULL-PROBE-OK'
}catch{
  Write-Host "FULL-PROBE-FAILED: $($_.Exception.Message)"
  throw
}finally{
  if($script:process -and -not $script:process.HasExited){try{Stop-Process -Id $script:process.Id}catch{}}
}
