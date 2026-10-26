[CmdletBinding()]
param(
  [string]$Directory,
  [string]$OutputDirectory
)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if(-not $Directory){$Directory=Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64'}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root "artifacts\ui-log-$([DateTime]::Now.ToString('yyyyMMdd-HHmmss'))"}
$Directory=[IO.Path]::GetFullPath($Directory)
New-Item -ItemType Directory -Force -Path $OutputDirectory|Out-Null
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Win6f {
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
# Crop the screen region of a control so the pixels can be inspected.
function Crop-Control([string]$Id,[string]$name){
  $e=Find-Id $Id
  if(-not $e){ Write-Host "  $Id missing"; return }
  $r=$e.Current.BoundingRectangle
  if([double]::IsInfinity($r.X) -or $r.Width -le 0){ Write-Host "  $Id not realized"; return }
  $pad=4
  $x=[int]($r.X-$pad); $y=[int]($r.Y-$pad)
  $w=[int]($r.Width+2*$pad); $h=[int]($r.Height+2*$pad)
  if($w -le 0 -or $h -le 0){ return }
  $bmp=New-Object System.Drawing.Bitmap($w,$h)
  $g=[System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($x,$y,0,0,$bmp.Size)
  $bmp.Save((Join-Path $OutputDirectory $name),[System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose(); $bmp.Dispose()
  Write-Host "  cropped $name  (${w}x${h} at $x,$y)"
}
try{
  $script:process=Start-Process -FilePath (Join-Path $Directory 'NovaProtect.exe') -WorkingDirectory $Directory -PassThru
  Wait-Until { $script:process.MainWindowHandle -ne 0 } 'UI window not ready'
  [Win6f]::MoveWindow($script:process.MainWindowHandle,0,0,1600,1100,$true)|Out-Null
  [Win6f]::SetForegroundWindow($script:process.MainWindowHandle)|Out-Null
  Start-Sleep -Milliseconds 1200
  $script:window=[System.Windows.Automation.AutomationElement]::FromHandle($script:process.MainWindowHandle)
  $close=Find-Name '关闭' 'Button'
  if($close){Click $close; Start-Sleep -Milliseconds 400}
  (Find-Name '保护项目' 'ListItem').GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
  Wait-Until { $null -ne (Find-Id 'InputPathBox') } 'protect page not ready'

  # The status card and the log box sit at the bottom of the page. The page
  # uses a vertical ScrollViewer; drive its scrollbar to the bottom so the
  # run-status card ("准备就绪") and the log box are realized on screen.
  $bars=$script:window.FindAll($scope,(New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty,[System.Windows.Automation.ControlType]::ScrollBar)))
  foreach($b in $bars){
    try{
      $o=$b.GetCurrentPattern([System.Windows.Automation.RangeValuePattern]::Pattern)
      if($o.Current.Orientation -eq 'Vertical' -and $o.Current.Maximum -gt $o.Current.Minimum){
        Write-Host ("  vertical scrollbar: min={0} max={1} value={2}" -f $o.Current.Minimum,$o.Current.Maximum,$o.Current.Value)
        $o.SetValue($o.Current.Maximum)
      }
    }catch{}
  }
  Start-Sleep -Milliseconds 1200

  # The status card sits next to the run button; crop it together with the
  # summary line so any garbled text is visible.
  Crop-Control 'RunStatusText' 'crop-runstatus.png'
  Crop-Control 'ConfigSummaryText' 'crop-configsummary.png'
  Crop-Control 'LogBox' 'crop-logbox.png'

  $status=Get-Value (Find-Id 'RunStatusText')
  Write-Host "RunStatusText = '$status'"
  $summary=Get-Value (Find-Id 'ConfigSummaryText')
  if($summary){ Write-Host "ConfigSummaryText = '$summary'" }
  $log=Get-Value (Find-Id 'LogBox')
  if($log){
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'logbox.txt'),$log,[Text.UTF8Encoding]::new($false))
    Write-Host "LogBox length = $($log.Length)"
  }
  Write-Host 'PROBE-OK'
}catch{
  Write-Host "PROBE-FAILED: $($_.Exception.Message)"
  throw
}finally{
  if($script:process -and -not $script:process.HasExited){try{Stop-Process -Id $script:process.Id}catch{}}
}
