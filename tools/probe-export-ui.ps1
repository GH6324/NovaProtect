[CmdletBinding()]
param(
  [string]$Target,
  [string]$Directory,
  [string]$OutputDirectory
)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if(-not $Directory){$Directory=Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64'}
if(-not $Target){$Target='C:\Windows\System32\user32.dll'}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root "artifacts\ui-export-$([DateTime]::Now.ToString('yyyyMMdd-HHmmss'))"}
$Directory=[IO.Path]::GetFullPath($Directory)
New-Item -ItemType Directory -Force -Path $OutputDirectory|Out-Null
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Win6e {
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
try{
  $script:process=Start-Process -FilePath (Join-Path $Directory 'NovaProtect.exe') -WorkingDirectory $Directory -PassThru
  Wait-Until { $script:process.MainWindowHandle -ne 0 } 'UI window not ready'
  [Win6e]::MoveWindow($script:process.MainWindowHandle,0,0,1600,1100,$true)|Out-Null
  [Win6e]::SetForegroundWindow($script:process.MainWindowHandle)|Out-Null
  Start-Sleep -Milliseconds 1200
  $script:window=[System.Windows.Automation.AutomationElement]::FromHandle($script:process.MainWindowHandle)
  $close=Find-Name '关闭' 'Button'
  if($close){Click $close; Start-Sleep -Milliseconds 400}
  (Find-Name '保护项目' 'ListItem').GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
  Wait-Until { $null -ne (Find-Id 'InputPathBox') } 'protect page not ready'

  Set-Value (Find-Id 'InputPathBox') $Target
  Start-Sleep -Seconds 2
  Click (Find-Name '扫描函数' 'Button')
  Start-Sleep -Seconds 6

  # The scan summary states how many functions were found.
  $bar=Find-Id 'FunctionScanBar'
  if($bar){ Write-Host "scan bar: $($bar.Current.Name)" }

  # Switch the filter to the exported functions only, so the export name
  # resolution becomes visible in the list.
  $combo=Find-Id 'FunctionFilterBox'
  if($combo){
    $combo.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern).Expand()
    Start-Sleep -Milliseconds 500
    $item=Find-Name '仅导出函数' 'ListItem'
    if($item){
      $item.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
      Start-Sleep -Milliseconds 1500
      Write-Host 'filter set to: exported only'
    } else { Write-Host 'export filter item not found' }
  }

  $list=Find-Id 'FunctionList'
  $rows=New-Object System.Collections.Generic.List[string]
  if($list){
    foreach($i in $list.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition)){
      try{ $nm=$i.Current.Name }catch{ continue }
      if([string]::IsNullOrWhiteSpace($nm)){ continue }
      $rows.Add($nm)
    }
  }
  [IO.File]::WriteAllLines((Join-Path $OutputDirectory 'export-rows.txt'),$rows,[Text.UTF8Encoding]::new($false))
  Write-Host "export rows realized=$($rows.Count) unique=$(($rows|Sort-Object -Unique).Count)"
  Write-Host '--- first rows ---'
  $rows|Select-Object -First 24|ForEach-Object{ Write-Host "   $_" }
  Write-Host 'PROBE-OK'
}catch{
  Write-Host "PROBE-FAILED: $($_.Exception.Message)"
  throw
}finally{
  if($script:process -and -not $script:process.HasExited){try{Stop-Process -Id $script:process.Id}catch{}}
}
