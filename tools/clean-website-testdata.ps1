[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)).TrimEnd('\')
foreach($recordFile in Get-ChildItem -LiteralPath (Join-Path $root 'output') -Filter 'website-*.test.json' -File){
  $record=Get-Content -LiteralPath $recordFile.FullName -Raw | ConvertFrom-Json
  $process=Get-Process -Id $record.Pid -ErrorAction SilentlyContinue
  if($process -and $process.Path -eq $record.Path -and $process.Path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){
    Stop-Process -Id $process.Id -Force
    Write-Host "Stopped test site $($record.Port) PID=$($record.Pid)"
  }
}
$targets=@(
  (Join-Path $root 'website\App_Data'),
  (Join-Path $root 'output\website-test-data'),
  (Join-Path $root 'output\website-test-data-205-final'),
  (Join-Path $root 'output\website-test-data-206')
)
$targets+=@(Get-ChildItem -LiteralPath (Join-Path $root 'output') -Directory -Filter 'website-test-data-*' | Where-Object {$_.Name -match '^website-test-data-2\.0\.(6|7)-\d+$'} | ForEach-Object FullName)
foreach($target in $targets){
  $resolved=[IO.Path]::GetFullPath($target).TrimEnd('\')
  if(-not $resolved.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -or
     $resolved -notmatch '\\(website\\App_Data|output\\website-test-data(?:-205-final|-206|-2\.0\.(6|7)-\d+)?)$') {throw "Refusing unexpected cleanup path: $resolved"}
  if(Test-Path -LiteralPath $resolved){Remove-Item -LiteralPath $resolved -Recurse -Force;Write-Host "Removed confirmed test data: $resolved"}
}
Write-Host 'TEST-DATA-CLEAN'
