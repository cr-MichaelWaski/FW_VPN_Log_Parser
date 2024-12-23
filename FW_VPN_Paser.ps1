# Prompt for input folder
$logFolderPath = Read-Host "Enter the path to the folder containing the .log files"
if (!(Test-Path -Path $logFolderPath)) {
    Write-Host "The folder path '$logFolderPath' does not exist. Please check the path and try again." -ForegroundColor Red
    exit
}

# Prompt for output folder
$outputFolderPath = Read-Host "Enter the path to the folder where CSV files will be saved"
if (!(Test-Path -Path $outputFolderPath)) {
    New-Item -ItemType Directory -Path $outputFolderPath | Out-Null
    Write-Host "Output folder created at: $outputFolderPath" -ForegroundColor Green
}

# Get all .log files in the folder
$logFiles = Get-ChildItem -Path $logFolderPath -Filter *.log
if ($logFiles.Count -eq 0) {
    Write-Host "No .log files found in the folder '$logFolderPath'." -ForegroundColor Yellow
    exit
}

# Start jobs for each file
$jobs = @()
foreach ($logFile in $logFiles) {
    Write-Host "Starting processing for: $($logFile.Name)" -ForegroundColor Cyan
    $jobs += Start-Job -ScriptBlock {
        param ($filePath, $outputPath)

        # Initialize a stream reader
        $reader = [System.IO.StreamReader]::new($filePath)
        $outputList = [System.Collections.Generic.List[object]]::new()

        # Process each line in the log file
        while (($line = $reader.ReadLine()) -ne $null) {
            # Parse the log line
            $logEntry = @{}
            foreach ($pair in $line -split " (?=\w+=)") {
                if ($pair -match "^(?<key>\w+)=(?<value>.+)$") {
                    $key = $matches['key']
                    $value = $matches['value'].Trim('"')
                    $logEntry[$key] = $value
                }
            }

            # Add parsed entry to the output list
            $outputList.Add([PSCustomObject]$logEntry) | Out-Null
        }
        $reader.Close()

        # Export to CSV
        $outputFilePath = Join-Path -Path $outputPath -ChildPath ("$($(Split-Path $filePath -Leaf).Replace('.log', '.csv'))")
        $outputList | Export-Csv -Path $outputFilePath -NoTypeInformation

        # Indicate success
        return "Processed: $($filePath)"
    } -ArgumentList $logFile.FullName, $outputFolderPath
}

# Monitor progress
Write-Host "Processing files..." -ForegroundColor Yellow
while (@(Get-Job -State 'Running').Count -gt 0) {
    $completedJobs = Get-Job -State 'Completed'
    foreach ($job in $completedJobs) {
        Write-Host (Receive-Job -Job $job) -ForegroundColor Green
        Remove-Job -Job $job
    }
    Start-Sleep -Seconds 1
}

# Display final results
Write-Host "All files processed successfully!" -ForegroundColor Green
