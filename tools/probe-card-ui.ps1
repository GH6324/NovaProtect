[CmdletBinding()]
param(
  [string]$Directory,
  [string]$Target,
  [string]$OutputDirectory,
  [int]$Width = 1900,
  [int]$Height = 1500
)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if(-not $Directory){$Directory=Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64'}
if(-not $Target){$Target=Join-Path $root 'tests\samples\cpp\cpp-sample.exe'}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root "artifacts\ui-card-$([DateTime]::Now.ToString('yyyyMMdd-HHmmss'))"}
$Directory=[IO.Path]::GetFullPath($Directory)
New-Item -ItemType Directory -Force -Path $OutputDirectory|Out-Null
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Win3 {
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h,int x,int y,int w,int hgt,bool repaint);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
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
function Shot([string]$name){
  try{
    $r=$script:window.Current.BoundingRectangle
    $w=[int]$r.Width; $h=[int]$r.Height
    if($w -le 0 -or $h -le 0 -or $w -gt 20000){ Write-Host "  shot $name skipped (bad rect w=$w h=$h)"; return }
    $bmp=New-Object System.Drawing.Bitmap($w,$h)
    $g=[System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen([int]$r.X,[int]$r.Y,0,0,$bmp.Size)
    $bmp.Save((Join-Path $OutputDirectory $name),[System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "  shot: $name ($w x $h)"
  }catch{ Write-Host "  shot failed: $($_.Exception.Message)" }
}
function Dump-Rows($label){
  $list=Find-Id 'FunctionList'
  $lr=$list.Current.BoundingRectangle
  Write-Host ("{0}: FunctionList X={1} Y={2} W={3} H={4}" -f $label,[int]$lr.X,[int]$lr.Y,[int]$lr.Width,[int]$lr.Height)
  $rows=$list.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition)
  $ri=0; $shown=0
  foreach($row in $rows){
    $ri++
    if($shown -ge 3){break}
    $cells=@()
    foreach($t in $row.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition)){
      try{
        if($t.Current.ControlType.ProgrammaticName -eq 'ControlType.Text' -and $t.Current.Name){
          $r=$t.Current.BoundingRectangle
          $cells+=("{0}@x{1}" -f $t.Current.Name,[int]$r.X)
        }
      }catch{}
    }
    if($cells.Count){ $shown++; Write-Host ("   row{0}: {1}" -f $ri,($cells -join '  ')) }
  }
}
try{
  $script:process=Start-Process -FilePath (Join-Path $Directory 'NovaProtect.exe') -WorkingDirectory $Directory -PassThru
  Wait-Until { $script:process.MainWindowHandle -ne 0 } 'UI window not ready'
  [Win3]::MoveWindow($script:process.MainWindowHandle,0,0,$Width,$Height,$true)|Out-Null
  [Win3]::SetForegroundWindow($script:process.MainWindowHandle)|Out-Null
  Start-Sleep -Milliseconds 1000
  $script:window=[System.Windows.Automation.AutomationElement]::FromHandle($script:process.MainWindowHandle)
  (Find-Name '保护项目' 'ListItem').GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
  Wait-Until { $null -ne (Find-Id 'InputPathBox') } 'protect page not ready'
  Set-Value (Find-Id 'InputPathBox') $Target
  Start-Sleep -Seconds 2
  Click (Find-Name '扫描函数' 'Button')
  Start-Sleep -Seconds 4
  Dump-Rows 'AFTER-SCAN'

  # Scroll the page so the function card is fully visible, then shoot the window.
  $pane=$script:window.FindFirst($scope,(New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty,[System.Windows.Automation.ControlType]::Pane)))
  for($i=0;$i -lt 40;$i++){
    $p=$script:window.FindFirst($scope,(New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty,[System.Windows.Automation.ControlType]::Pane)))
    try{
      $sp=$p.GetCurrentPattern([System.Windows.Automation.ScrollPattern]::Pattern)
      if(-not $sp.Current.VerticallyScrollable){break}
      $sp.ScrollVertical([System.Windows.Automation.ScrollAmount]::NoAmount,[System.Windows.Automation.ScrollAmount]::LargeIncrement)
      Start-Sleep -Milliseconds 120
      $list=Find-Id 'FunctionList'
      $lr=$list.Current.BoundingRectangle
      $win=$script:window.Current.BoundingRectangle
      if($lr.Y -ge $win.Y -and ($lr.Y - $win.Y) -lt 300){ break }
    }catch{ break }
  }
  Start-Sleep -Milliseconds 800
  Shot '40-function-card.png'
  Dump-Rows 'SCROLLED'
  Write-Host 'CARD-PROBE-OK'
}catch{
  Write-Host "CARD-PROBE-FAILED: $($_.Exception.Message)"
  throw
}finally{
  if($script:process -and -not $script:process.HasExited){try{Stop-Process -Id $script:process.Id}catch{}}
}
