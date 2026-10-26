[CmdletBinding()]
param(
  [string[]]$Targets,
  [string]$Directory,
  [string]$OutputDirectory
)$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if(-not $Directory){$Directory=Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64'}
if(-not $Targets){$Targets=@((Join-Path $root 'tests\samples\cpp\cpp-sample.exe'))}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root "artifacts\ui-cmp-$([DateTime]::Now.ToString('yyyyMMdd-HHmmss'))"}
$Directory=[IO.Path]::GetFullPath($Directory)
New-Item -ItemType Directory -Force -Path $OutputDirectory|Out-Null
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Win6c {
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
  [Win6c]::MoveWindow($script:process.MainWindowHandle,0,0,1600,1100,$true)|Out-Null
  [Win6c]::SetForegroundWindow($script:process.MainWindowHandle)|Out-Null
  Start-Sleep -Milliseconds 1200
  $script:window=[System.Windows.Automation.AutomationElement]::FromHandle($script:process.MainWindowHandle)
  $close=Find-Name '关闭' 'Button'
  if($close){Click $close; Start-Sleep -Milliseconds 400}
  (Find-Name '保护项目' 'ListItem').GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
  Wait-Until { $null -ne (Find-Id 'InputPathBox') } 'protect page not ready'

  $n=0
  foreach($t in $Targets){
    $n++
    Write-Host "=== target #$n : $t"
    Set-Value (Find-Id 'InputPathBox') $t
    Start-Sleep -Seconds 2
    Click (Find-Name '扫描函数' 'Button')
    Start-Sleep -Seconds 5

    $list=Find-Id 'FunctionList'
    $rows=New-Object System.Collections.Generic.List[string]
    if($list){
      foreach($i in $list.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition)){
        try{ $nm=$i.Current.Name }catch{ continue }
        if([string]::IsNullOrWhiteSpace($nm)){ continue }
        $rows.Add($nm)
      }
    }
    $file="rows-$n.txt"
    [IO.File]::WriteAllLines((Join-Path $OutputDirectory $file),$rows,[Text.UTF8Encoding]::new($false))
    $uniq=($rows|Sort-Object -Unique).Count
    Write-Host "   realized=$($rows.Count) unique=$uniq  -> $file"
    $rows|Select-Object -First 8|ForEach-Object{ Write-Host "     $_" }
  }
  Write-Host 'PROBE-OK'
}catch{
  Write-Host "PROBE-FAILED: $($_.Exception.Message)"
  throw
}finally{
  if($script:process -and -not $script:process.HasExited){try{Stop-Process -Id $script:process.Id}catch{}}
}
