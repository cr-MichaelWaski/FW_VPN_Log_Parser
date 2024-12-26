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

# Initialize job collection as an array
$jobs = @()

foreach ($logFile in $logFiles) {
    Write-Host "Starting job for file: $($logFile.Name)" -ForegroundColor Cyan

    # Start a background job for each file
    $jobs += Start-Job -ScriptBlock {
        param ($filePath)

        # Local storage for this file's results
        $localFailedConnections = @()
        $localUnusualIPs = @()
        $connectionFrequency = @{}

        # Stream-read the log file
        $reader = [System.IO.StreamReader]::new($filePath)
        while (($line = $reader.ReadLine()) -ne $null) {
            Write-Host "Processing line: $line" -ForegroundColor DarkGray  # Debug line

            if ($line -match 'remip=(?<remip>[^ ]+).*status=(?<status>[^ ]+).*srccountry=(?<srccountry>[^ ]+)') {
                $remip = $matches['remip']
                $status = $matches['status']
                $srccountry = $matches['srccountry']

                # Analyze failed connections
                if ($status -eq 'failure' -or $status -eq 'ERROR') {
                    $localFailedConnections += [PSCustomObject]@{
                        RemIP       = $remip
                        Status      = $status
                        SrcCountry  = $srccountry
                    }
                }

                # Check for unusual IPs
                if ($srccountry -notin @("United States", "Canada")) {
                    $localUnusualIPs += [PSCustomObject]@{
                        RemIP       = $remip
                        SrcCountry  = $srccountry
                    }
                }

                # Track connection frequency
                if (-not [string]::IsNullOrEmpty($remip)) {
                    if (-not $connectionFrequency.ContainsKey($remip)) {
                        $connectionFrequency[$remip] = 0
                    }
                    $connectionFrequency[$remip]++
                }
            }
        }
        $reader.Close()

        # Return results
        [PSCustomObject]@{
            FailedConnections = $localFailedConnections
            UnusualIPs        = $localUnusualIPs
            ConnectionFrequency = $connectionFrequency
        }
    } -ArgumentList $logFile.FullName
}

# Wait for jobs to complete and collect results
$results = @()
while ($jobs.Count -gt 0) {
    $completedJobs = $jobs | Where-Object { $_.State -eq 'Completed' }
    foreach ($job in $completedJobs) {
        $jobResult = Receive-Job -Job $job
        Write-Host "Job result: $($jobResult | Out-String)" -ForegroundColor DarkGray  # Debug line
        $results += $jobResult
        Remove-Job -Job $job -ErrorAction SilentlyContinue
        $jobs = $jobs | Where-Object { $_.Id -ne $job.Id }  # Remove processed jobs from the collection
    }
    Start-Sleep -Seconds 1
}

# Aggregate results
$failedConnections = @()
$unusualIPs = @()
$connectionFrequency = @{}

foreach ($result in $results) {
    $failedConnections += $result.FailedConnections
    $unusualIPs += $result.UnusualIPs

    foreach ($pair in $result.ConnectionFrequency.GetEnumerator()) {
        if ($connectionFrequency.ContainsKey($pair.Key)) {
            $connectionFrequency[$pair.Key] += $pair.Value
        } else {
            $connectionFrequency[$pair.Key] = $pair.Value
        }
    }
}

# Debug: Check aggregated results
Write-Host "Failed Connections: $($failedConnections.Count)" -ForegroundColor DarkGray
Write-Host "Unusual IPs: $($unusualIPs.Count)" -ForegroundColor DarkGray
Write-Host "Connection Frequency: $($connectionFrequency.Count)" -ForegroundColor DarkGray

# Export failed connections to CSV
if ($failedConnections.Count -gt 0) {
    Write-Host "Exporting failed connections..." -ForegroundColor Yellow
    $failedConnectionsFile = Join-Path -Path $outputFolderPath -ChildPath "FailedConnections.csv"
    $failedConnections | Export-Csv -Path $failedConnectionsFile -NoTypeInformation
} else {
    Write-Host "No failed connections found." -ForegroundColor Yellow
}

# Export unusual IPs to CSV
if ($unusualIPs.Count -gt 0) {
    Write-Host "Exporting unusual IPs..." -ForegroundColor Yellow
    $unusualIPsFile = Join-Path -Path $outputFolderPath -ChildPath "UnusualIPs.csv"
    $unusualIPs | Export-Csv -Path $unusualIPsFile -NoTypeInformation
} else {
    Write-Host "No unusual IPs found." -ForegroundColor Yellow
}

# Export connection frequency summary to CSV
if ($connectionFrequency.Count -gt 0) {
    Write-Host "Exporting connection frequency..." -ForegroundColor Yellow
    $connectionFrequencyFile = Join-Path -Path $outputFolderPath -ChildPath "ConnectionFrequency.csv"
    $connectionFrequency.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            IPAddress = $_.Key
            Attempts  = $_.Value
        }
    } | Export-Csv -Path $connectionFrequencyFile -NoTypeInformation
} else {
    Write-Host "No connection frequency data found." -ForegroundColor Yellow
}

Write-Host "Log analysis completed successfully!" -ForegroundColor Green
