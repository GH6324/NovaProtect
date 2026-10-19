[CmdletBinding()]
param([string]$Directory,[string]$OutputDirectory,[switch]$LeaveRunning,[switch]$InspectOnly)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$version=(Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim()
if(-not $Directory){$Directory=Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64'}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root "artifacts\ui-verification-$version"}
$Directory=[IO.Path]::GetFullPath($Directory)
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $OutputDirectory|Out-Null
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
$scope=[System.Windows.Automation.TreeScope]::Descendants
$script:process=$null
$script:window=$null
function Find-Id([string]$Id){
  $condition=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty,$Id)
  $script:window.FindFirst($scope,$condition)
}
function Find-Name([string]$Name,[string]$Type){
  $condition=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty,$Name)
  @($script:window.FindAll($scope,$condition))|Where-Object { -not $Type -or $_.Current.ControlType.ProgrammaticName -eq "ControlType.$Type" }|Select-Object -First 1
}
function Click($e){
  if(-not $e){throw 'UI control missing'}
  $e.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
}
function Set-Value($e,[string]$Value){
  if(-not $e){throw 'UI value control missing'}
  $e.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue($Value)
}
function Get-Value($e){$e.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).Current.Value}
function Navigate([string]$Name){
  (Find-Name $Name 'ListItem').GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
}
function Wait-Until([scriptblock]$Condition,[string]$Failure,[int]$Seconds=30){
  $until=[DateTime]::UtcNow.AddSeconds($Seconds)
  while([DateTime]::UtcNow -lt $until){
    $script:process.Refresh()
    if($script:process.HasExited){throw "UI exited with $($script:process.ExitCode)"}
    if(& $Condition){return}
    Start-Sleep -Milliseconds 200
  }
  throw $Failure
}
$results=@()
try{
  $script:process=Start-Process -FilePath (Join-Path $Directory 'NovaProtect.exe') -WorkingDirectory $Directory -PassThru -WindowStyle Hidden
  Wait-Until { $script:process.MainWindowHandle -ne 0 -and $script:process.MainWindowTitle -eq 'NovaProtect' -and $script:process.Responding } 'UI window not ready'
  $script:window=[System.Windows.Automation.AutomationElement]::FromHandle($script:process.MainWindowHandle)
  # The client now surfaces public announcements on startup.  Dismiss that
  # optional dialog so the existing navigation smoke flow can continue.
  $announcementClose=Find-Name '关闭' 'Button'
  if($announcementClose){Click $announcementClose; Start-Sleep -Milliseconds 200}
  Navigate '检查工具'
  Wait-Until { $null -ne (Find-Id 'PathBox') } 'Inspect page not ready'
  Write-Host 'UI-STEP inspect'
  Set-Value (Find-Id 'PathBox') (Join-Path $root 'tests\samples\cpp\cpp-sample.exe')
  Click (Find-Name 'PE 信息' 'Button')
  Wait-Until { (Get-Value (Find-Id 'ResultBox')) -ne '正在检查…' } 'Inspection timed out'
  $inspect=Get-Value (Find-Id 'ResultBox')
  [IO.File]::WriteAllText((Join-Path $OutputDirectory 'inspect.txt'),$inspect,[Text.UTF8Encoding]::new($false))
  if($inspect -notmatch 'Arch: x64'){throw "Genuine UI core invocation rejected: $inspect"}
  Write-Host 'UI-INSPECT-OK (genuine UI -> single-use pipe -> engine)'
  if($InspectOnly){return}
  Click (Find-Name '本机激活 ID' 'Button')
  Write-Host 'UI-STEP machine-id'
  Wait-Until { (Get-Value (Find-Id 'ResultBox')) -match '^[0-9A-Fa-f]{16}$' } 'Machine ID failed through UI'
  $machine=Get-Value (Find-Id 'ResultBox')
  Navigate '保护项目'
  Write-Host 'UI-STEP protect-page'
  Wait-Until { $null -ne (Find-Id 'InputPathBox') } 'Protection page not ready'
  $combo=Find-Id 'PresetBox'
  $combo.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern).Expand()
  Wait-Until { $null -ne (Find-Name '兼容' 'ListItem') } 'Compatibility preset missing'
  (Find-Name '兼容' 'ListItem').GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
  $combo.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern).Collapse()
  Wait-Until { $null -ne (Find-Id 'InputPathBox') } 'Protection inputs unavailable after preset popup'
  foreach($language in @('cpp','csharp','vb','rust','go')){
    Write-Host "UI-STEP $language-input"
    $sample=Join-Path $root "tests\samples\$language\$language-sample.exe"
    $output=Join-Path $OutputDirectory "$language-protected.exe"
    Wait-Until { $null -ne (Find-Id 'InputPathBox') } 'Protection input unavailable after UI update'
    Set-Value (Find-Id 'InputPathBox') $sample
    Wait-Until { $null -ne (Find-Id 'OutputPathBox') } 'Output input unavailable during PE update'
    Set-Value (Find-Id 'OutputPathBox') $output
    Wait-Until { $null -ne (Find-Id 'StartButton') -and (Find-Id 'StartButton').Current.IsEnabled } 'Protection action unavailable during PE update'
    Click (Find-Id 'StartButton')
    Wait-Until { (Find-Id 'RunStatusText').Current.Name -in @('保护完成','保护失败','已取消') } "$language UI protection timed out" 90
    $status=(Find-Id 'RunStatusText').Current.Name
    $log=Get-Value (Find-Id 'LogBox')
    [IO.File]::WriteAllText((Join-Path $OutputDirectory "$language.protect.log"),$log,[Text.UTF8Encoding]::new($false))
    if($status -ne '保护完成'){throw "$language failed through UI: $log"}
    Wait-Until { $null -ne (Find-Name '确定' 'Button') } 'Completion dialog missing'
    Click (Find-Name '确定' 'Button')
    $baseline=& $sample 'E2E' 2>&1|Out-String
    $baselineExit=$LASTEXITCODE
    $observed=& $output 'E2E' 2>&1|Out-String
    $exitCode=$LASTEXITCODE
    if($exitCode -ne $baselineExit -or $observed.Trim() -ne $baseline.Trim()){throw "$language protected runtime differs: $exitCode; $observed"}
    [IO.File]::WriteAllText((Join-Path $OutputDirectory "$language.stdout.txt"),$observed,[Text.UTF8Encoding]::new($false))
    $results+=[ordered]@{Language=$language;Result='pass';Options='UI compatibility preset';RunExit=$exitCode;Bytes=(Get-Item -LiteralPath $output).Length;SHA256=(Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash}
    Write-Host "UI-LANGUAGE-OK $language"
  }
  $components=[ordered]@{}
  foreach($name in @('NovaProtect.exe','NovaProtect.dll','NovaProtect.Engine.exe','NovaProtect.ManagedHost.exe')){
    $components[$name]=(Get-FileHash -LiteralPath (Join-Path $Directory $name) -Algorithm SHA256).Hash.ToLowerInvariant()
  }
  $record=[ordered]@{Version=$version;Directory=$Directory;TestedAt=[DateTimeOffset]::Now.ToString('O');ProcessId=$script:process.Id;Title=$script:process.MainWindowTitle;MachineIdViaUI=$true;ComponentSHA256=$components;Languages=$results}
  $record|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $OutputDirectory 'results.json') -Encoding UTF8
  Write-Host 'UI-E2E-OK (5 languages; no CLI/test backdoor in release)'
}catch{
  Write-Host $_.ScriptStackTrace
  if($script:window){
    $script:window.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition) | ForEach-Object { '{0} | {1}' -f $_.Current.AutomationId,$_.Current.Name } | Set-Content -LiteralPath (Join-Path $OutputDirectory 'failed-ui-tree.txt') -Encoding UTF8
  }
  throw
}finally{
  if($script:process -and -not $LeaveRunning){try{if(-not $script:process.HasExited){Stop-Process -Id $script:process.Id}}catch{}}
}
