# Prompt for input folder
$logFolderPath = Read-Host "Enter the path to the folder containing the .log files"
if (!(Test-Path -Path $logFolderPath)) {
    Write-Host "The folder path '$logFolderPath' does not exist. Please check the path and try again." -ForegroundColor Red
    exit
}

# Prompt for output folder
$outputFolderPath = Read-Host "Enter the path to the folder where analysis results will be saved"
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

# Initialize results
$failedConnections = @()
$unusualIPs = @()
$connectionFrequency = @{}

# Process each log file
Write-Host "Processing log files..." -ForegroundColor Yellow
foreach ($logFile in $logFiles) {
    Write-Host "Processing: $($logFile.Name)" -ForegroundColor Cyan

    # Stream-read the log file
    $reader = [System.IO.StreamReader]::new($logFile.FullName)
    while (($line = $reader.ReadLine()) -ne $null) {
        # Parse the log line
        $logEntry = @{}
        foreach ($pair in $line -split " (?=\w+=)") {
            $key, $value = $pair -split "=", 2
            $logEntry[$key] = $value.Trim('"')
        }

        # Analyze failed connections
        if ($logEntry['status'] -eq 'failure' -or $logEntry['result'] -eq 'ERROR') {
            $failedConnections += $logEntry
        }

        # Check for unusual IPs
        if ($logEntry['srccountry'] -notin @("United States", "Canada")) {
            $unusualIPs += $logEntry
        }

        # Track connection frequency (null check for 'remip')
        $ip = $logEntry['remip']
        if (-not [string]::IsNullOrEmpty($ip)) {
            if (-not $connectionFrequency.ContainsKey($ip)) {
                $connectionFrequency[$ip] = 0
            }
            $connectionFrequency[$ip]++
        }
    }
    $reader.Close()
}

# Export failed connections to CSV
Write-Host "Exporting failed connections..." -ForegroundColor Yellow
$failedConnectionsFile = Join-Path -Path $outputFolderPath -ChildPath "FailedConnections.csv"
$failedConnections | Export-Csv -Path $failedConnectionsFile -NoTypeInformation

# Export unusual IPs to CSV
Write-Host "Exporting unusual IPs..." -ForegroundColor Yellow
$unusualIPsFile = Join-Path -Path $outputFolderPath -ChildPath "UnusualIPs.csv"
$unusualIPs | Export-Csv -Path $unusualIPsFile -NoTypeInformation

# Export connection frequency summary to CSV
Write-Host "Exporting connection frequency..." -ForegroundColor Yellow
$connectionFrequencySummary = $connectionFrequency.GetEnumerator() | Sort-Object -Property Value -Descending | ForEach-Object {
    [PSCustomObject]@{
        IPAddress = $_.Key
        Attempts  = $_.Value
    }
}
$connectionFrequencyFile = Join-Path -Path $outputFolderPath -ChildPath "ConnectionFrequency.csv"
$connectionFrequencySummary | Export-Csv -Path $connectionFrequencyFile -NoTypeInformation

Write-Host "Log analysis completed successfully!" -ForegroundColor Green
