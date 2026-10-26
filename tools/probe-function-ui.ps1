[CmdletBinding()]
param(
  [string]$Directory,
  [string]$Target,
  [string]$OutputDirectory
)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if(-not $Directory){$Directory=Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64'}
if(-not $Target){$Target=Join-Path $root 'tests\samples\cpp\cpp-sample.exe'}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root "artifacts\ui-probe-$([DateTime]::Now.ToString('yyyyMMdd-HHmmss'))"}
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
function Wait-Until([scriptblock]$c,[string]$fail,[int]$sec=60){
  $until=[DateTime]::UtcNow.AddSeconds($sec)
  while([DateTime]::UtcNow -lt $until){
    $script:process.Refresh()
    if($script:process.HasExited){throw "UI exited $($script:process.ExitCode)"}
    if(& $c){return}
    Start-Sleep -Milliseconds 250
  }
  throw $fail
}
function Shot([string]$name){
  try{
    $r=$script:window.Current.BoundingRectangle
    if($r.Width -le 0 -or $r.Height -le 0){return}
    $bmp=New-Object System.Drawing.Bitmap([int]$r.Width,[int]$r.Height)
    $g=[System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen([int]$r.X,[int]$r.Y,0,0,$bmp.Size)
    $bmp.Save((Join-Path $OutputDirectory $name),[System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "  shot: $name"
  }catch{ Write-Host "  shot failed: $($_.Exception.Message)" }
}
function Dump-PageText([string]$label){
  Write-Host "=== TEXT DUMP $label"
  $items=$script:window.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition)
  $seen=@{}
  foreach($i in $items){
    try{ $n=$i.Current.Name; $id=$i.Current.AutomationId; $ct=$i.Current.ControlType.ProgrammaticName }catch{continue}
    if([string]::IsNullOrWhiteSpace($n)){continue}
    $key="$id|$n"
    if($seen.ContainsKey($key)){continue}
    $seen[$key]=1
    if($ct -match 'Text|Edit|Document'){ Write-Host ("  [{0}] {1}" -f $id,$n) }
  }
}
try{
  $script:process=Start-Process -FilePath (Join-Path $Directory 'NovaProtect.exe') -WorkingDirectory $Directory -PassThru
  Wait-Until { $script:process.MainWindowHandle -ne 0 -and $script:process.MainWindowTitle -eq 'NovaProtect' } 'UI window not ready'
  $script:window=[System.Windows.Automation.AutomationElement]::FromHandle($script:process.MainWindowHandle)
  $close=Find-Name '关闭' 'Button'
  if($close){Click $close; Start-Sleep -Milliseconds 300}

  (Find-Name '保护项目' 'ListItem').GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
  Wait-Until { $null -ne (Find-Id 'InputPathBox') } 'protect page not ready'
  Set-Value (Find-Id 'InputPathBox') $Target
  Start-Sleep -Seconds 2
  Shot '01-protect-idle.png'
  Dump-PageText 'IDLE'

  Click (Find-Name '扫描函数' 'Button')
  Start-Sleep -Seconds 2
  Shot '02-after-scan.png'
  Write-Host ("COUNT: {0}" -f (Get-Value (Find-Id 'FunctionCountText')))

  Click (Find-Name '添加所有函数' 'Button')
  Start-Sleep -Milliseconds 800
  Shot '03-add-all.png'
  Write-Host ("SEL-SUMMARY: {0}" -f (Get-Value (Find-Id 'FunctionSelectionSummary')))

  Click (Find-Name '应用到勾选函数' 'Button')
  Start-Sleep -Milliseconds 800
  Shot '04-batch-applied.png'

  Click (Find-Id 'StartButton')
  $status=$null
  try{
    Wait-Until { (Find-Id 'RunStatusText').Current.Name -ne '准备就绪' } 'protect did not start' 30
    Wait-Until { (Find-Id 'RunStatusText').Current.Name -in @('保护完成','保护失败','已取消') } 'protect timed out' 120
    $status=(Find-Id 'RunStatusText').Current.Name
  }catch{
    $status="TIMEOUT/ERROR: $($_.Exception.Message)"
    Write-Host "  ui alive: $(-not $script:process.HasExited)"
  }
  Start-Sleep -Milliseconds 500
  Shot '05-result.png'
  Write-Host ("RUN-STATUS: {0}" -f $status)
  $log=Get-Value (Find-Id 'LogBox')
  if($log){ [IO.File]::WriteAllText((Join-Path $OutputDirectory 'protect.log'),$log,[Text.UTF8Encoding]::new($false)); Write-Host "LOG-SAVED length=$($log.Length)" }
  Write-Host 'UI-PROBE-OK'
}catch{
  Write-Host "PROBE-FAILED: $($_.Exception.Message)"
  throw
}finally{
  if($script:process -and -not $script:process.HasExited){try{Stop-Process -Id $script:process.Id}catch{}}
}
