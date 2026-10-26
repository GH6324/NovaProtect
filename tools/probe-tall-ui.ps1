[CmdletBinding()]
param(
  [string]$Directory,
  [string]$Target,
  [string]$OutputDirectory,
  [int]$Height = 3200,
  [switch]$RunProtection
)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if(-not $Directory){$Directory=Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64'}
if(-not $Target){$Target=Join-Path $root 'tests\samples\cpp\cpp-sample.exe'}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root "artifacts\ui-tall-$([DateTime]::Now.ToString('yyyyMMdd-HHmmss'))"}
$Directory=[IO.Path]::GetFullPath($Directory)
New-Item -ItemType Directory -Force -Path $OutputDirectory|Out-Null
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Win {
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
    $bmp=New-Object System.Drawing.Bitmap([int]$r.Width,[int]$r.Height)
    $g=[System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen([int]$r.X,[int]$r.Y,0,0,$bmp.Size)
    $bmp.Save((Join-Path $OutputDirectory $name),[System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "  shot: $name ($([int]$r.Width)x$([int]$r.Height))"
  }catch{ Write-Host "  shot failed: $($_.Exception.Message)" }
}
try{
  $script:process=Start-Process -FilePath (Join-Path $Directory 'NovaProtect.exe') -WorkingDirectory $Directory -PassThru
  Wait-Until { $script:process.MainWindowHandle -ne 0 } 'UI window not ready'
  [Win]::MoveWindow($script:process.MainWindowHandle,0,0,1400,$Height,$true)|Out-Null
  [Win]::SetForegroundWindow($script:process.MainWindowHandle)|Out-Null
  Start-Sleep -Milliseconds 800
  $script:window=[System.Windows.Automation.AutomationElement]::FromHandle($script:process.MainWindowHandle)
  $close=Find-Name '关闭' 'Button'
  if($close){Click $close; Start-Sleep -Milliseconds 400}

  (Find-Name '保护项目' 'ListItem').GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
  Wait-Until { $null -ne (Find-Id 'InputPathBox') } 'protect page not ready'
  Set-Value (Find-Id 'InputPathBox') $Target
  Start-Sleep -Seconds 2
  Click (Find-Name '扫描函数' 'Button')
  Start-Sleep -Seconds 3
  Shot '20-full-after-scan.png'

  $list=Find-Id 'FunctionList'
  Write-Host '--- rendered rows ---'
  $rows=$list.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition)
  $i=0
  foreach($row in $rows){
    $i++
    if($i -gt 26){break}
    $texts=@()
    foreach($t in $row.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition)){
      try{ if($t.Current.ControlType.ProgrammaticName -eq 'ControlType.Text' -and $t.Current.Name){ $texts+=$t.Current.Name } }catch{}
    }
    if($texts.Count){ Write-Host ("  row {0}: {1}" -f $i, ($texts -join ' | ')) }
  }

  if($RunProtection){
    Click (Find-Name '添加所有函数' 'Button')
    Start-Sleep -Milliseconds 600
    Click (Find-Name '应用到勾选函数' 'Button')
    Start-Sleep -Milliseconds 600
    Write-Host '--- starting protection ---'
    Click (Find-Id 'StartButton')
    $status='?'
    try{
      Wait-Until { (Find-Id 'RunStatusText').Current.Name -in @('保护完成','保护失败','已取消') } 'protect timed out' 180
      $status=(Find-Id 'RunStatusText').Current.Name
    }catch{ $status="TIMEOUT: $($_.Exception.Message)" }
    Write-Host "STATUS: $status"
    Start-Sleep -Milliseconds 600
    Shot '21-full-after-run.png'
    $log=Get-Value (Find-Id 'LogBox')
    if($log){ [IO.File]::WriteAllText((Join-Path $OutputDirectory 'protect.log'),$log,[Text.UTF8Encoding]::new($false)) }
    $dlg=$script:window.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition) | Where-Object { $_.Current.ControlType.ProgrammaticName -eq 'ControlType.Window' }
    foreach($d in $dlg){ Write-Host ("DIALOG: {0}" -f $d.Current.Name) }
  }
  Write-Host 'TALL-PROBE-OK'
}catch{
  Write-Host "TALL-PROBE-FAILED: $($_.Exception.Message)"
  throw
}finally{
  if($script:process -and -not $script:process.HasExited){try{Stop-Process -Id $script:process.Id}catch{}}
}
