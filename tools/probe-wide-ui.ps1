[CmdletBinding()]
param(
  [string]$Directory,
  [string]$Target,
  [string]$OutputDirectory,
  [switch]$RunProtection
)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if(-not $Directory){$Directory=Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64'}
if(-not $Target){$Target=Join-Path $root 'tests\samples\cpp\cpp-sample.exe'}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root "artifacts\ui-wide-$([DateTime]::Now.ToString('yyyyMMdd-HHmmss'))"}
$Directory=[IO.Path]::GetFullPath($Directory)
New-Item -ItemType Directory -Force -Path $OutputDirectory|Out-Null
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Win2 {
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
function Wait-Until([scriptblock]$c,[string]$fail,[int]$sec=120){
  $until=[DateTime]::UtcNow.AddSeconds($sec)
  while([DateTime]::UtcNow -lt $until){
    $script:process.Refresh()
    if($script:process.HasExited){throw "UI exited $($script:process.ExitCode)"}
    if(& $c){return}
    Start-Sleep -Milliseconds 300
  }
  throw $fail
}
function Shot([string]$name){
  try{
    $r=$script:window.Current.BoundingRectangle
    $bmp=New-Object System.Drawing.Bitmap([int]$r.Width,[int]$r.Height)
    $g=[System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen([int]$r.X,[int]$r.Y,0,0,$bmp.Size)
    $bmp.Save((Join-Path $OutputDirectory $name),[System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "  shot: $name"
  }catch{ Write-Host "  shot failed: $($_.Exception.Message)" }
}
function Dump-Tree([string]$label){
  $lines=New-Object System.Collections.Generic.List[string]
  $items=$script:window.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition)
  foreach($i in $items){
    try{
      $n=$i.Current.Name; $id=$i.Current.AutomationId; $ct=$i.Current.ControlType.ProgrammaticName
      if([string]::IsNullOrWhiteSpace($n)){continue}
      $lines.Add(("{0}|{1}|{2}" -f $id,$ct,$n))
    }catch{}
  }
  $file=Join-Path $OutputDirectory ("tree-{0}.txt" -f $label)
  [IO.File]::WriteAllLines($file,$lines,[Text.UTF8Encoding]::new($false))
  Write-Host "  tree dump: $file ($($lines.Count) elements)"
}
try{
  $script:process=Start-Process -FilePath (Join-Path $Directory 'NovaProtect.exe') -WorkingDirectory $Directory -PassThru
  Wait-Until { $script:process.MainWindowHandle -ne 0 } 'UI window not ready'
  [Win2]::MoveWindow($script:process.MainWindowHandle,0,0,1900,1400,$true)|Out-Null
  Start-Sleep -Milliseconds 900
  $script:window=[System.Windows.Automation.AutomationElement]::FromHandle($script:process.MainWindowHandle)
  $close=Find-Name '关闭' 'Button'
  if($close){ Write-Host "  found startup 关闭 button"; Click $close; Start-Sleep -Milliseconds 400 }
  else { Write-Host "  no startup 关闭 button" }

  (Find-Name '保护项目' 'ListItem').GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
  Wait-Until { $null -ne (Find-Id 'InputPathBox') } 'protect page not ready'
  Set-Value (Find-Id 'InputPathBox') $Target
  Start-Sleep -Seconds 2
  Shot '30-idle-wide.png'
  Dump-Tree 'idle'

  Click (Find-Name '扫描函数' 'Button')
  Start-Sleep -Seconds 4
  Shot '31-scanned-wide.png'
  Dump-Tree 'scanned'

  if($RunProtection){
    Click (Find-Name '添加所有函数' 'Button')
    Start-Sleep -Milliseconds 800
    Click (Find-Name '应用到勾选函数' 'Button')
    Start-Sleep -Milliseconds 800
    Shot '32-added-wide.png'
    Click (Find-Id 'StartButton')
    try{ Wait-Until { (Find-Id 'RunStatusText').Current.Name -in @('保护完成','保护失败','已取消') } 'protect timed out' 240 | Out-Null }catch{}
    Start-Sleep -Milliseconds 900
    Shot '33-result-wide.png'
    Dump-Tree 'result'
  }
  Write-Host 'WIDE-PROBE-OK'
}catch{
  Write-Host "WIDE-PROBE-FAILED: $($_.Exception.Message)"
  throw
}finally{
  if($script:process -and -not $script:process.HasExited){try{Stop-Process -Id $script:process.Id}catch{}}
}
