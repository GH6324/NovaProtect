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
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root "artifacts\ui-probe2-$([DateTime]::Now.ToString('yyyyMMdd-HHmmss'))"}
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
    $bmp=New-Object System.Drawing.Bitmap([int]$r.Width,[int]$r.Height)
    $g=[System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen([int]$r.X,[int]$r.Y,0,0,$bmp.Size)
    $bmp.Save((Join-Path $OutputDirectory $name),[System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "  shot: $name"
  }catch{ Write-Host "  shot failed: $($_.Exception.Message)" }
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
  Click (Find-Name '扫描函数' 'Button')
  Start-Sleep -Seconds 2

  # Scroll the function list into view so the rows are actually rendered.
  $list=Find-Id 'FunctionList'
  if(-not $list){throw 'FunctionList missing'}
  Write-Host '--- scrolling to function card ---'
  for($i=0;$i -lt 60;$i++){
    $r=$script:window.Current.BoundingRectangle
    $rect=$list.Current.BoundingRectangle
    if($rect.Y -ge ($r.Y + 40) -and $rect.Y -lt ($r.Y + $r.Height - 120)){ break }
    $sp=$script:window.FindFirst($scope,(New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty,[System.Windows.Automation.ControlType]::ScrollBar)))
    try{
      $sc=$sp.GetCurrentPattern([System.Windows.Automation.ScrollPattern]::Pattern)
      $sc.Scroll([System.Windows.Automation.ScrollAmount]::NoAmount,[System.Windows.Automation.ScrollAmount]::LargeIncrement)
    }catch{
      try{ $sp.SetFocus(); [System.Windows.Forms.SendKeys]::SendWait('{PGDN}') }catch{}
    }
    Start-Sleep -Milliseconds 150
  }
  Start-Sleep -Milliseconds 700
  Shot '10-function-card.png'

  Write-Host '--- first 8 list rows (rendered text) ---'
  $rows=$list.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition)
  $i=0
  foreach($row in $rows){
    $i++
    if($i -gt 40){break}
    $texts=@()
    foreach($t in $row.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition)){
      try{ if($t.Current.ControlType.ProgrammaticName -eq 'ControlType.Text' -and $t.Current.Name){ $texts+=$t.Current.Name } }catch{}
    }
    if($texts.Count){ Write-Host ("  row {0}: {1}" -f $i, ($texts -join ' | ')) }
  }
  Write-Host 'UI-PROBE2-OK'
}catch{
  Write-Host "PROBE2-FAILED: $($_.Exception.Message)"
  throw
}finally{
  if($script:process -and -not $script:process.HasExited){try{Stop-Process -Id $script:process.Id}catch{}}
}
