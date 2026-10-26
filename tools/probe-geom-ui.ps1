[CmdletBinding()]
param(
  [string]$Directory,
  [string]$Target
)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if(-not $Directory){$Directory=Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64'}
if(-not $Target){$Target=Join-Path $root 'tests\samples\cpp\cpp-sample.exe'}
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
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
try{
  $script:process=Start-Process -FilePath (Join-Path $Directory 'NovaProtect.exe') -WorkingDirectory $Directory -PassThru
  Wait-Until { $script:process.MainWindowHandle -ne 0 } 'UI window not ready'
  $script:window=[System.Windows.Automation.AutomationElement]::FromHandle($script:process.MainWindowHandle)
  (Find-Name '保护项目' 'ListItem').GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
  Wait-Until { $null -ne (Find-Id 'InputPathBox') } 'protect page not ready'
  Set-Value (Find-Id 'InputPathBox') $Target
  Start-Sleep -Seconds 2
  Click (Find-Name '扫描函数' 'Button')
  Start-Sleep -Seconds 4

  $list=Find-Id 'FunctionList'
  $lr=$list.Current.BoundingRectangle
  Write-Host ("FunctionList rect: X={0} Y={1} W={2} H={3}" -f [int]$lr.X,[int]$lr.Y,[int]$lr.Width,[int]$lr.Height)
  $win=$script:window.Current.BoundingRectangle
  Write-Host ("Window rect:       X={0} Y={1} W={2} H={3}" -f [int]$win.X,[int]$win.Y,[int]$win.Width,[int]$win.Height)

  Write-Host ''
  Write-Host '--- per-row geometry (first 3 rows) ---'
  $rows=$list.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition)
  $ri=0
  foreach($row in $rows){
    $ri++
    if($ri -gt 3){break}
    Write-Host ("ROW {0}  rect X={1} Y={2} W={3} H={4}" -f $ri,[int]$row.Current.BoundingRectangle.X,[int]$row.Current.BoundingRectangle.Y,[int]$row.Current.BoundingRectangle.Width,[int]$row.Current.BoundingRectangle.Height)
    foreach($t in $row.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition)){
      try{
        $r=$t.Current.BoundingRectangle
        Write-Host ("    {0,-16} '{1}'  X={2} W={3}" -f $t.Current.ControlType.ProgrammaticName.Replace('ControlType.',''),$t.Current.Name,[int]$r.X,[int]$r.Width)
      }catch{}
    }
  }
  Write-Host ''
  Write-Host '--- duplicate visible text across all realized rows ---'
  $texts=@()
  foreach($row in $rows){
    foreach($t in $row.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition)){
      try{
        if($t.Current.ControlType.ProgrammaticName -eq 'ControlType.Text' -and $t.Current.Name){ $texts+=$t.Current.Name }
      }catch{}
    }
  }
  $groups=$texts | Group-Object | Where-Object { $_.Count -gt 3 } | Sort-Object Count -Descending
  Write-Host ("  total text cells={0}; groups repeated >3 times = {1}" -f $texts.Count, $groups.Count)
  foreach($g in $groups | Select-Object -First 8){ Write-Host ("    x{0}  '{1}'" -f $g.Count,$g.Name) }
  Write-Host 'GEOM-PROBE-OK'
}catch{
  Write-Host "GEOM-PROBE-FAILED: $($_.Exception.Message)"
  throw
}finally{
  if($script:process -and -not $script:process.HasExited){try{Stop-Process -Id $script:process.Id}catch{}}
}
