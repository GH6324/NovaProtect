[CmdletBinding()]
param(
  [string]$Target,
  [string]$Directory,
  [string]$OutputDirectory
)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if(-not $Directory){$Directory=Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64'}
if(-not $Target){$Target=Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\NovaProtect.Engine.exe'}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root "artifacts\ui-crash-$([DateTime]::Now.ToString('yyyyMMdd-HHmmss'))"}
$Directory=[IO.Path]::GetFullPath($Directory)
New-Item -ItemType Directory -Force -Path $OutputDirectory|Out-Null
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Win6g {
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
  }catch{ Write-Host "  shot $name failed" }
}
try{
  $script:process=Start-Process -FilePath (Join-Path $Directory 'NovaProtect.exe') -WorkingDirectory $Directory -PassThru
  Wait-Until { $script:process.MainWindowHandle -ne 0 } 'UI window not ready'
  [Win6g]::MoveWindow($script:process.MainWindowHandle,0,0,1600,1100,$true)|Out-Null
  [Win6g]::SetForegroundWindow($script:process.MainWindowHandle)|Out-Null
  Start-Sleep -Milliseconds 1200
  $script:window=[System.Windows.Automation.AutomationElement]::FromHandle($script:process.MainWindowHandle)
  $close=Find-Name '关闭' 'Button'
  if($close){Click $close; Start-Sleep -Milliseconds 400}
  (Find-Name '保护项目' 'ListItem').GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
  Wait-Until { $null -ne (Find-Id 'InputPathBox') } 'protect page not ready'

  Set-Value (Find-Id 'InputPathBox') $Target
  Start-Sleep -Seconds 3
  Click (Find-Name '扫描函数' 'Button')
  Start-Sleep -Seconds 8
  Click (Find-Name '添加所有函数' 'Button')
  Start-Sleep -Milliseconds 1200
  Click (Find-Name '应用到勾选函数' 'Button')
  Start-Sleep -Milliseconds 1200
  Click (Find-Id 'StartButton')
  try{ Wait-Until { (Find-Id 'RunStatusText').Current.Name -in @('保护完成','保护失败','已取消') } 'protect timed out' 300 | Out-Null }catch{}
  Start-Sleep -Milliseconds 1200
  Write-Host ("STATUS: {0}" -f (Find-Id 'RunStatusText').Current.Name)
  Shot 'crash-state.png'

  $log=Get-Value (Find-Id 'LogBox')
  if($log){
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'protect.log'),$log,[Text.UTF8Encoding]::new($false))
    Write-Host "  log len=$($log.Length)"
  }
  $summary=Get-Value (Find-Id 'ConfigSummaryText')
  if($summary){ Write-Host "  summary len=$($summary.Length)" }
  Write-Host 'PROBE-OK'
}catch{
  Write-Host "PROBE-FAILED: $($_.Exception.Message)"
  throw
}finally{
  if($script:process -and -not $script:process.HasExited){try{Stop-Process -Id $script:process.Id}catch{}}
}
