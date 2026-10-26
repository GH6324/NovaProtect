[CmdletBinding()]
param(
  [string]$Directory,
  [string]$Target,
  [string]$OutputDirectory
)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if(-not $Directory){$Directory=Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64'}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root "artifacts\ui-bottom-$([DateTime]::Now.ToString('yyyyMMdd-HHmmss'))"}
New-Item -ItemType Directory -Force -Path $OutputDirectory|Out-Null
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WinBot {
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h,int x,int y,int w,int hgt,bool repaint);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
}
'@
[WinBot]::SetProcessDPIAware()|Out-Null
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
    $w=[int]$r.Width; $h=[int]$r.Height
    if($w -le 0 -or $h -le 0){ return }
    $bmp=New-Object System.Drawing.Bitmap($w,$h)
    $g=[System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen([int]$r.X,[int]$r.Y,0,0,$bmp.Size)
    $bmp.Save((Join-Path $OutputDirectory $name),[System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "  shot $name"
  }catch{ Write-Host "  shot $name failed: $($_.Exception.Message)" }
}
# Scroll the page's ScrollViewer to the very bottom so the run-status card
# ("准备就绪") and the log box are actually realized on screen.
function Scroll-Bottom(){
  # Preferred: ask the ScrollViewer for its scrollable range and jump to the end.
  try{
    $sv=Find-Id 'PageScroll'
    if($sv){
      $sp=$sv.GetCurrentPattern([System.Windows.Automation.ScrollPattern]::Pattern)
      $v=$sp.Current.VerticalScrollPercent
      Write-Host "  vertical scroll percent before = $v"
      if($v -lt 100){
        $no=[System.Windows.Automation.ScrollAmount]::NoAmount
        $large=[System.Windows.Automation.ScrollAmount]::LargeIncrement
        for($i=0;$i -lt 80;$i++){
          [void]$sp.Scroll($large,$no,$no)
          Start-Sleep -Milliseconds 60
        }
      }
      Write-Host "  vertical scroll percent after = $($sp.Current.VerticalScrollPercent)"
      if($sp.Current.VerticalScrollPercent -ge 99){ return $true }
    }
  }catch{ Write-Host "  scroll via ScrollPattern failed: $($_.Exception.Message)" }
  # Fallback: mouse wheel over the page body.
  try{
    if(-not ('MouseWheelHelper2' -as [type])){
      Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class MouseWheelHelper2 {
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x,int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f,uint dx,uint dy,int d,IntPtr e);
  public static void Scroll(int x,int y,int clicks){ SetCursorPos(x,y); mouse_event(0x0800,0,0,clicks,IntPtr.Zero); }
}
'@
    }
    $r=$script:window.Current.BoundingRectangle
    [MouseWheelHelper2]::Scroll([int]($r.X+$r.Width/2),[int]($r.Y+$r.Height/2),-150)
    Start-Sleep -Milliseconds 800
    Write-Host "  scrolled via mouse wheel"
    return $true
  }catch{ Write-Host "  mouse scroll failed: $($_.Exception.Message)" }
  return $false
}
try{
  $script:process=Start-Process -FilePath (Join-Path $Directory 'NovaProtect.exe') -WorkingDirectory $Directory -PassThru
  Wait-Until { $script:process.MainWindowHandle -ne 0 } 'UI window not ready'
  [WinBot]::MoveWindow($script:process.MainWindowHandle,0,0,1600,1200,$true)|Out-Null
  [WinBot]::SetForegroundWindow($script:process.MainWindowHandle)|Out-Null
  Start-Sleep -Milliseconds 1500
  $script:window=[System.Windows.Automation.AutomationElement]::FromHandle($script:process.MainWindowHandle)
  $close=Find-Name '关闭' 'Button'
  if($close){Click $close; Start-Sleep -Milliseconds 400}
  (Find-Name '保护项目' 'ListItem').GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
  Wait-Until { $null -ne (Find-Id 'InputPathBox') } 'protect page not ready'

  if($Target){
    Set-Value (Find-Id 'InputPathBox') $Target
    Start-Sleep -Seconds 3
  }

  Scroll-Bottom
  Start-Sleep -Milliseconds 800
  Shot 'bottom.png'

  # The run-status card sits at the very bottom of a long scrolling page.
  # Shrink the window so the bottom of the page is inside the viewport, then
  # screenshot again - otherwise the card is never rasterized on screen.
  try{
    [WinBot]::MoveWindow($script:process.MainWindowHandle,0,0,1100,900,$true)|Out-Null
    Start-Sleep -Milliseconds 900
    Shot 'bottom-small.png'
  }catch{ Write-Host "  resize failed: $($_.Exception.Message)" }

  $statusEl=Find-Id 'RunStatusText'
  $status=$null
  if($statusEl){ $status=$statusEl.Current.Name }
  Write-Host "  RunStatusText=[$status]"
  $summaryEl=Find-Id 'ConfigSummaryText'
  $summary=$null
  if($summaryEl){ $summary=$summaryEl.Current.Name }
  if($summary){ [IO.File]::WriteAllText((Join-Path $OutputDirectory 'summary.txt'),$summary,[Text.UTF8Encoding]::new($false)); Write-Host "  summary len=$($summary.Length)" }
  $logEl=Find-Id 'LogBox'
  $log=$null
  if($logEl){ try{$log=$logEl.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).Current.Value}catch{$log=$logEl.Current.Name} }
  if($null -ne $log){ [IO.File]::WriteAllText((Join-Path $OutputDirectory 'logbox.txt'),$log,[Text.UTF8Encoding]::new($false)); Write-Host "  logbox len=$($log.Length)" }

  # Dump every realized text node so a mojibake patch anywhere on the page shows up.
  $all=@($script:window.FindAll($scope,(New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty,[System.Windows.Automation.ControlType]::Text))))
  $lines=foreach($e in $all){ "{0}|{1}" -f $e.Current.AutomationId,$e.Current.Name }
  [IO.File]::WriteAllLines((Join-Path $OutputDirectory 'text.txt'),$lines,[Text.UTF8Encoding]::new($false))
  Write-Host "  text nodes=$($lines.Count)"
  Write-Host 'PROBE-OK'
}catch{
  Write-Host "PROBE-FAILED: $($_.Exception.Message)"
  throw
}finally{
  if($script:process -and -not $script:process.HasExited){try{Stop-Process -Id $script:process.Id}catch{}}
}
