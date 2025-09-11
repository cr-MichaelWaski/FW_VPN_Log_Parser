#Requires -Version 5.1
<#
.SYNOPSIS
    Analyzes firewall/VPN log files for suspicious connection patterns.

.DESCRIPTION
    This script processes log files to identify failed connections, unusual IP addresses,
    and connection frequency patterns. Results are exported to CSV files for further analysis.

.PARAMETER LogFolderPath
    Path to the folder containing .log files to analyze

.PARAMETER OutputFolderPath
    Path where analysis results will be saved

.PARAMETER TrustedCountries
    Array of countries considered trusted (default: "United States", "Canada")

.PARAMETER MinConnectionThreshold
    Minimum number of connections to flag as suspicious (default: 10)

.EXAMPLE
    .\Suspicious_Connection_Analysis.ps1 -LogFolderPath "C:\Logs" -OutputFolderPath "C:\Analysis"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$LogFolderPath,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputFolderPath,
    
    [Parameter(Mandatory = $false)]
    [string[]]$TrustedCountries = @("United States", "Canada"),
    
    [Parameter(Mandatory = $false)]
    [int]$MinConnectionThreshold = 10
)

# Function to validate and prompt for folder paths
function Get-ValidatedPath {
    param(
        [string]$PromptMessage,
        [string]$ProvidedPath,
        [switch]$CreateIfNotExists
    )
    
    $path = $ProvidedPath
    while ([string]::IsNullOrWhiteSpace($path) -or !(Test-Path -Path $path -IsValid)) {
        $path = Read-Host $PromptMessage
        
        if (!(Test-Path -Path $path -IsValid)) {
            Write-Warning "Invalid path format. Please enter a valid path."
            $path = $null
            continue
        }
        
        if (!(Test-Path -Path $path)) {
            if ($CreateIfNotExists) {
                try {
                    New-Item -ItemType Directory -Path $path -Force | Out-Null
                    Write-Host "Created directory: $path" -ForegroundColor Green
                    break
                }
                catch {
                    Write-Error "Failed to create directory: $_"
                    $path = $null
                    continue
                }
            }
            else {
                Write-Warning "Path does not exist: $path"
                $path = $null
            }
        }
    }
    return $path
}

# Get and validate input paths
if ([string]::IsNullOrWhiteSpace($LogFolderPath)) {
    $LogFolderPath = Get-ValidatedPath -PromptMessage "Enter the path to the folder containing the .log files"
}
elseif (!(Test-Path -Path $LogFolderPath)) {
    Write-Error "The folder path '$LogFolderPath' does not exist. Please check the path and try again."
    exit 1
}

if ([string]::IsNullOrWhiteSpace($OutputFolderPath)) {
    $OutputFolderPath = Get-ValidatedPath -PromptMessage "Enter the path to the folder where analysis results will be saved" -CreateIfNotExists
}
elseif (!(Test-Path -Path $OutputFolderPath)) {
    try {
        New-Item -ItemType Directory -Path $OutputFolderPath -Force | Out-Null
        Write-Host "Output folder created at: $OutputFolderPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create output directory: $_"
        exit 1
    }
}

# Function to parse log line into hashtable
function Parse-LogLine {
    param([string]$LogLine)
    
    $logEntry = @{}
    try {
        # Split by space followed by word= pattern, handling quoted values
        $pairs = $LogLine -split ' (?=\w+=)'
        foreach ($pair in $pairs) {
            if ($pair -match '^(\w+)=(.*)$') {
                $key = $matches[1]
                $value = $matches[2].Trim('"')
                $logEntry[$key] = $value
            }
        }
    }
    catch {
        Write-Warning "Failed to parse log line: $LogLine"
    }
    return $logEntry
}

# Function to analyze a single log file
function Analyze-LogFile {
    param(
        [System.IO.FileInfo]$LogFile,
        [hashtable]$FailedConnections,
        [hashtable]$UnusualIPs,
        [hashtable]$ConnectionFrequency
    )
    
    $lineCount = 0
    $processedCount = 0
    
    try {
        $reader = [System.IO.StreamReader]::new($LogFile.FullName)
        
        while (($line = $reader.ReadLine()) -ne $null) {
            $lineCount++
            
            # Skip empty lines
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }
            
            $logEntry = Parse-LogLine -LogLine $line
            if ($logEntry.Count -eq 0) {
                continue
            }
            
            $processedCount++
            
            # Analyze failed connections
            if ($logEntry['status'] -eq 'failure' -or 
                $logEntry['result'] -eq 'ERROR' -or
                $logEntry['action'] -eq 'deny' -or
                $logEntry['disposition'] -eq 'blocked') {
                
                $key = "$($logEntry['remip'] ?? 'unknown')_$($logEntry['dstport'] ?? 'unknown')_$(Get-Date)"
                $FailedConnections[$key] = $logEntry
            }

            # Check for unusual IPs (countries not in trusted list)
            $sourceCountry = $logEntry['srccountry']
            if (![string]::IsNullOrEmpty($sourceCountry) -and $sourceCountry -notin $TrustedCountries) {
                $key = "$($logEntry['remip'] ?? 'unknown')_$sourceCountry"
                $UnusualIPs[$key] = $logEntry
            }

            # Track connection frequency
            $ip = $logEntry['remip']
            if (![string]::IsNullOrEmpty($ip) -and $ip -ne 'unknown') {
                if (!$ConnectionFrequency.ContainsKey($ip)) {
                    $ConnectionFrequency[$ip] = @{
                        Count     = 0
                        FirstSeen = $logEntry['date'] ?? (Get-Date).ToString()
                        LastSeen  = $logEntry['date'] ?? (Get-Date).ToString()
                        Ports     = @()
                    }
                }
                $ConnectionFrequency[$ip].Count++
                $ConnectionFrequency[$ip].LastSeen = $logEntry['date'] ?? (Get-Date).ToString()
                
                $port = $logEntry['dstport']
                if (![string]::IsNullOrEmpty($port) -and $port -notin $ConnectionFrequency[$ip].Ports) {
                    $ConnectionFrequency[$ip].Ports += $port
                }
            }
            
            # Progress indication for large files
            if ($lineCount % 10000 -eq 0) {
                Write-Progress -Activity "Processing $($LogFile.Name)" -Status "Lines processed: $lineCount" -PercentComplete -1
            }
        }
    }
    catch {
        Write-Error "Error processing file $($LogFile.Name): $_"
    }
    finally {
        if ($reader) {
            $reader.Close()
            $reader.Dispose()
        }
        Write-Progress -Activity "Processing $($LogFile.Name)" -Completed
    }
    
    Write-Host "Processed $processedCount valid entries from $lineCount total lines in $($LogFile.Name)" -ForegroundColor Cyan
}

# Get all .log files in the folder
Write-Host "Scanning for log files in: $LogFolderPath" -ForegroundColor Yellow
$logFiles = Get-ChildItem -Path $LogFolderPath -Filter *.log -File

if ($logFiles.Count -eq 0) {
    Write-Warning "No .log files found in the folder '$LogFolderPath'."
    exit 1
}

Write-Host "Found $($logFiles.Count) log file(s) to process" -ForegroundColor Green

# Initialize results using hashtables for better performance
$failedConnections = @{}
$unusualIPs = @{}
$connectionFrequency = @{}

# Process each log file
$totalStartTime = Get-Date
Write-Host "Starting log file analysis..." -ForegroundColor Yellow

foreach ($logFile in $logFiles) {
    $fileStartTime = Get-Date
    Write-Host "Processing: $($logFile.Name) (Size: $([math]::Round($logFile.Length / 1MB, 2)) MB)" -ForegroundColor Cyan
    
    Analyze-LogFile -LogFile $logFile -FailedConnections $failedConnections -UnusualIPs $unusualIPs -ConnectionFrequency $connectionFrequency
    
    $fileEndTime = Get-Date
    $fileProcessTime = $fileEndTime - $fileStartTime
    Write-Host "Completed $($logFile.Name) in $($fileProcessTime.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Green
}

$totalEndTime = Get-Date
$totalProcessTime = $totalEndTime - $totalStartTime
Write-Host "Total processing time: $($totalProcessTime.TotalMinutes.ToString('F2')) minutes" -ForegroundColor Green

# Generate summary statistics
Write-Host "`n=== Analysis Summary ===" -ForegroundColor Magenta
Write-Host "Failed connections detected: $($failedConnections.Count)" -ForegroundColor Yellow
Write-Host "Unusual IP addresses detected: $($unusualIPs.Count)" -ForegroundColor Yellow
Write-Host "Unique IP addresses seen: $($connectionFrequency.Count)" -ForegroundColor Yellow

# Find high-frequency connections
$suspiciousIPs = $connectionFrequency.GetEnumerator() | Where-Object { $_.Value.Count -ge $MinConnectionThreshold }
Write-Host "High-frequency connections (>= $MinConnectionThreshold attempts): $($suspiciousIPs.Count)" -ForegroundColor Yellow

# Export results with error handling
function Export-ResultsToCSV {
    param(
        [hashtable]$Data,
        [string]$FilePath,
        [string]$DataType
    )
    
    try {
        Write-Host "Exporting $DataType..." -ForegroundColor Yellow
        
        if ($Data.Count -eq 0) {
            Write-Warning "No $DataType to export"
            return
        }
        
        $results = switch ($DataType) {
            "Failed Connections" {
                $Data.Values | ForEach-Object {
                    [PSCustomObject]$_
                }
            }
            "Unusual IPs" {
                $Data.Values | ForEach-Object {
                    [PSCustomObject]$_
                }
            }
            "Connection Frequency" {
                $Data.GetEnumerator() | ForEach-Object {
                    [PSCustomObject]@{
                        IPAddress           = $_.Key
                        TotalAttempts       = $_.Value.Count
                        FirstSeen           = $_.Value.FirstSeen
                        LastSeen            = $_.Value.LastSeen
                        UniquePortsAccessed = ($_.Value.Ports -join ', ')
                        RiskLevel           = if ($_.Value.Count -ge $MinConnectionThreshold * 2) { "High" } 
                        elseif ($_.Value.Count -ge $MinConnectionThreshold) { "Medium" } 
                        else { "Low" }
                    }
                } | Sort-Object TotalAttempts -Descending
            }
        }
        
        $results | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported $($results.Count) records to: $FilePath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export $DataType to $FilePath : $_"
    }
}

# Export all results
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$failedConnectionsFile = Join-Path -Path $OutputFolderPath -ChildPath "FailedConnections_$timestamp.csv"
Export-ResultsToCSV -Data $failedConnections -FilePath $failedConnectionsFile -DataType "Failed Connections"

$unusualIPsFile = Join-Path -Path $OutputFolderPath -ChildPath "UnusualIPs_$timestamp.csv"
Export-ResultsToCSV -Data $unusualIPs -FilePath $unusualIPsFile -DataType "Unusual IPs"

$connectionFrequencyFile = Join-Path -Path $OutputFolderPath -ChildPath "ConnectionFrequency_$timestamp.csv"
Export-ResultsToCSV -Data $connectionFrequency -FilePath $connectionFrequencyFile -DataType "Connection Frequency"

# Generate summary report
$summaryFile = Join-Path -Path $OutputFolderPath -ChildPath "AnalysisSummary_$timestamp.txt"
try {
    $summaryContent = @"
=== Firewall/VPN Log Analysis Summary ===
Generated: $(Get-Date)
Log Folder: $LogFolderPath
Files Processed: $($logFiles.Count)
Processing Time: $($totalProcessTime.TotalMinutes.ToString('F2')) minutes

=== Results ===
Failed Connections: $($failedConnections.Count)
Unusual IP Addresses: $($unusualIPs.Count)
Total Unique IPs: $($connectionFrequency.Count)
High-Frequency IPs (>= $MinConnectionThreshold attempts): $($suspiciousIPs.Count)

=== Top 10 Most Active IPs ===
"@
    
    $topIPs = $connectionFrequency.GetEnumerator() | 
    Sort-Object { $_.Value.Count } -Descending | 
    Select-Object -First 10
    
    foreach ($ip in $topIPs) {
        $summaryContent += "`n$($ip.Key): $($ip.Value.Count) connections"
    }
    
    $summaryContent += "`n`n=== Files Generated ===`n"
    $summaryContent += "- $failedConnectionsFile`n"
    $summaryContent += "- $unusualIPsFile`n"
    $summaryContent += "- $connectionFrequencyFile`n"
    $summaryContent += "- $summaryFile`n"
    
    $summaryContent | Out-File -FilePath $summaryFile -Encoding UTF8
    Write-Host "Summary report saved to: $summaryFile" -ForegroundColor Green
}
catch {
    Write-Error "Failed to generate summary report: $_"
}

Write-Host "`n=== Analysis Complete ===" -ForegroundColor Green
Write-Host "All results have been exported to: $OutputFolderPath" -ForegroundColor Cyan

# Offer to open output folder
if ($Host.Name -eq "ConsoleHost") {
    $openFolder = Read-Host "`nWould you like to open the output folder? (y/n)"
    if ($openFolder -eq 'y' -or $openFolder -eq 'Y') {
        try {
            Invoke-Item $OutputFolderPath
        }
        catch {
            Write-Warning "Could not open folder: $_"
        }
    }
}
