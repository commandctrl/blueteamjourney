# Remote collection of Windows Forensic Artifacts using KAPE and !SANS_Triage. Prerequisites require Targets folder and Kape.exe in a zip. Sourced from https://github.com/DFIRanjith/Scripts/blob/main/kape.ps1

$zipFilePath = "C:\kape.zip"
$extractPath = "C:\KAPE"

# Check if the extraction directory exists, if not, create it
if (-not (Test-Path -Path $extractPath -PathType Container)) {
    New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
}

# Unzip the file using the built-in ComObject Shell.Application
$shell = New-Object -ComObject Shell.Application
$zipFile = $shell.NameSpace($zipFilePath)
$destination = $shell.NameSpace($extractPath)
$destination.CopyHere($zipFile.Items())

# Wait for the extraction process to complete 
while ($destination.Items().Count -ne $zipFile.Items().Count) {
    Start-Sleep -Seconds 1
}

# Execute the kape.exe with the given parameters
$command = "C:\kape.exe"
$params = "--tsource C:\ --tdest C:\KAPE\output --tflush --target !SANS_Triage --zip kapeoutput"
Start-Process -FilePath $command -ArgumentList $params -Wait
