param([Parameter(Mandatory=$true)][string]$InputDocx,[Parameter(Mandatory=$true)][string]$OutputPdf)
$ErrorActionPreference = 'Stop'
$taskApp = $null
$taskDoc = $null
$taskInitialDocuments = -1
try {
    $taskApp = New-Object -ComObject KWPS.Application
    $taskInitialDocuments = $taskApp.Documents.Count
    if ($taskInitialDocuments -eq 0) { $taskApp.Visible = $false }
    $taskOldAlerts = $taskApp.DisplayAlerts
    $taskApp.DisplayAlerts = 0
    $taskDoc = $taskApp.Documents.Open($InputDocx, $false, $true)
    $taskDoc.ExportAsFixedFormat($OutputPdf, 17)
    Write-Output ('WPS-PDF-OK ' + (Get-Item -LiteralPath $OutputPdf).Length)
} finally {
    if ($null -ne $taskDoc) {
        $taskDoc.Close(0)
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($taskDoc)
    }
    if ($null -ne $taskApp) {
        if ($null -ne $taskOldAlerts) { $taskApp.DisplayAlerts = $taskOldAlerts }
        if ($taskInitialDocuments -eq 0) { $taskApp.Quit() }
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($taskApp)
    }
}
