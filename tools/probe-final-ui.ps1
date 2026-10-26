[CmdletBinding()]
param(
  [string]$Directory,
  [string]$Target,
  [string]$OutputDirectory,
  [switch]$RunProtection,
  [switch]$AddAll
)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if(-not $Directory){$Directory=Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64'}
if(-not $Target){$Target=Join-Path $root 'tests\samples\cpp\cpp-sample.exe'}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root "artifacts\ui-final-$([DateTime]::Now.ToString('yyyyMMdd-HHmmss'))"}
$Directory=[IO.Path]::GetFullPath($Directory)
New-Item -ItemType Directory -Force -Path $OutputDirectory|Out-Null
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -AssemblyName System.Drawing
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
    if($script:process.HasExited){return "UI-PROCESS-EXITED"}
    if(& $c){return "OK"}
    Start-Sleep -Milliseconds 300
  }
  return "TIMEOUT"
}
function Into-View($el){
  if(-not $el){return}
  try{ $el.GetCurrentPattern([System.Windows.Automation.ScrollItemPattern]::Pattern).ScrollIntoView() }catch{}
  Start-Sleep -Milliseconds 400
}
function Crop([string]$id,[string]$label){
  try{
    $el=Find-Id $id
    if(-not $el){ Write-Host "  crop $id : missing"; return }
    Into-View $el
    $r=$el.Current.BoundingRectangle
    if($r.Width -le 0 -or $r.Height -le 0){ Write-Host "  crop $id : empty rect"; return }
    $bmp=New-Object System.Drawing.Bitmap([int]$r.Width,[int]$r.Height)
    $g=[System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen([int]$r.X,[int]$r.Y,0,0,$bmp.Size)
    $file=Join-Path $OutputDirectory ("crop-{0}.png" -f $id)
    $bmp.Save($file,[System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "  crop $id -> $file ($([int]$r.Width)x$([int]$r.Height))"
  }catch{ Write-Host "  crop $id failed: $($_.Exception.Message)" }
}
try{
  $script:process=Start-Process -FilePath (Join-Path $Directory 'NovaProtect.exe') -WorkingDirectory $Directory -PassThru
  Wait-Until { $script:process.MainWindowHandle -ne 0 } 'UI window not ready' | Out-Null
  $script:window=[System.Windows.Automation.AutomationElement]::FromHandle($script:process.MainWindowHandle)
  $close=Find-Name '关闭' 'Button'
  if($close){Click $close; Start-Sleep -Milliseconds 400}

  (Find-Name '保护项目' 'ListItem').GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
  Wait-Until { $null -ne (Find-Id 'InputPathBox') } 'protect page not ready' | Out-Null
  Set-Value (Find-Id 'InputPathBox') $Target
  Start-Sleep -Seconds 2
  Click (Find-Name '扫描函数' 'Button')
  Start-Sleep -Seconds 4
  Crop 'FunctionList'
  Crop 'FunctionScanBar'

  if($RunProtection){
    if($AddAll){
      Click (Find-Name '添加所有函数' 'Button')
      Start-Sleep -Milliseconds 800
      Write-Host ("SEL: {0}" -f (Get-Value (Find-Id 'FunctionSelectionSummary')))
      Click (Find-Name '应用到勾选函数' 'Button')
      Start-Sleep -Milliseconds 800
    }
    Write-Host '--- clicking 开始保护 ---'
    Click (Find-Id 'StartButton')
    $state=Wait-Until { (Find-Id 'RunStatusText').Current.Name -in @('保护完成','保护失败','已取消') } 'protect timed out' 240
    Write-Host "WAIT-STATE: $state"
    try{ Write-Host ("RUN-STATUS: {0}" -f (Find-Id 'RunStatusText').Current.Name) }catch{}
    try{ Write-Host ("UI-ALIVE: {0}" -f (-not $script:process.HasExited)) }catch{}
    Start-Sleep -Milliseconds 800
    Crop 'LogBox'
    Crop 'ConfigSummaryText'
    $log=Get-Value (Find-Id 'LogBox')
    if($log){ [IO.File]::WriteAllText((Join-Path $OutputDirectory 'protect.log'),$log,[Text.UTF8Encoding]::new($false)); Write-Host "LOG len=$($log.Length)" }
    $dlg=$script:window.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition) | Where-Object { $_.Current.ControlType.ProgrammaticName -eq 'ControlType.Window' }
    foreach($d in $dlg){
      $txt=($d.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition) | Where-Object { $_.Current.ControlType.ProgrammaticName -eq 'ControlType.Text' } | ForEach-Object { $_.Current.Name }) -join ' / '
      Write-Host ("DIALOG: '{0}' :: {1}" -f $d.Current.Name,$txt)
    }
  }
  Write-Host 'FINAL-PROBE-OK'
}catch{
  Write-Host "FINAL-PROBE-FAILED: $($_.Exception.Message)"
  throw
}finally{
  if($script:process -and -not $script:process.HasExited){try{Stop-Process -Id $script:process.Id}catch{}}
}
