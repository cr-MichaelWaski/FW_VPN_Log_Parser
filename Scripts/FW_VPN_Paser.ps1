#Requires -Version 5.1
<#
.SYNOPSIS
    Converts firewall/VPN log files to CSV format using parallel processing.

.DESCRIPTION
    This script processes multiple log files in parallel, parsing key-value pairs from each line
    and converting them to CSV format for easier analysis. Each log file is processed in a 
    separate background job for optimal performance.

.PARAMETER LogFolderPath
    Path to the folder containing .log files to convert

.PARAMETER OutputFolderPath
    Path where CSV files will be saved

.PARAMETER MaxConcurrentJobs
    Maximum number of concurrent jobs to run (default: number of logical processors)

.PARAMETER JobTimeoutMinutes
    Timeout in minutes for individual jobs (default: 30)

.EXAMPLE
    .\FW_VPN_Parser.ps1 -LogFolderPath "C:\Logs" -OutputFolderPath "C:\CSV"

.EXAMPLE
    .\FW_VPN_Parser.ps1 -LogFolderPath "C:\Logs" -OutputFolderPath "C:\CSV" -MaxConcurrentJobs 4
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$LogFolderPath,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputFolderPath,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxConcurrentJobs = [Environment]::ProcessorCount,
    
    [Parameter(Mandatory = $false)]
    [int]$JobTimeoutMinutes = 30
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
    $OutputFolderPath = Get-ValidatedPath -PromptMessage "Enter the path to the folder where CSV files will be saved" -CreateIfNotExists
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

# Enhanced script block for log processing
$logProcessingScript = {
    param ($filePath, $outputPath)
    
    $processedRecords = 0
    $skippedLines = 0
    $startTime = Get-Date
    
    try {
        # Initialize a stream reader
        $reader = [System.IO.StreamReader]::new($filePath)
        $outputList = [System.Collections.Generic.List[object]]::new()

        # Process each line in the log file
        while (($line = $reader.ReadLine()) -ne $null) {
            # Skip empty lines
            if ([string]::IsNullOrWhiteSpace($line)) {
                $skippedLines++
                continue
            }
            
            try {
                # Parse the log line with improved regex
                $logEntry = @{}
                $pairs = $line -split ' (?=\w+=)'
                
                foreach ($pair in $pairs) {
                    if ($pair -match '^(\w+)=(.*)$') {
                        $key = $matches[1]
                        $value = $matches[2].Trim('"')
                        
                        # Handle special characters and ensure valid data
                        if (![string]::IsNullOrEmpty($key)) {
                            $logEntry[$key] = $value
                        }
                    }
                }

                # Only add entries that have actual data
                if ($logEntry.Count -gt 0) {
                    $outputList.Add([PSCustomObject]$logEntry) | Out-Null
                    $processedRecords++
                }
                else {
                    $skippedLines++
                }
            }
            catch {
                $skippedLines++
                # Continue processing other lines even if one fails
            }
        }
        
        # Calculate file size for reporting
        $fileInfo = Get-Item $filePath
        $fileSizeMB = [math]::Round($fileInfo.Length / 1MB, 2)
        
        # Export to CSV with error handling
        $outputFileName = [System.IO.Path]::GetFileNameWithoutExtension($filePath) + ".csv"
        $outputFilePath = Join-Path -Path $outputPath -ChildPath $outputFileName
        
        if ($outputList.Count -gt 0) {
            $outputList | Export-Csv -Path $outputFilePath -NoTypeInformation -Encoding UTF8
            
            $endTime = Get-Date
            $processingTime = ($endTime - $startTime).TotalSeconds
            
            return @{
                Success               = $true
                FilePath              = $filePath
                OutputPath            = $outputFilePath
                RecordsProcessed      = $processedRecords
                LinesSkipped          = $skippedLines
                FileSizeMB            = $fileSizeMB
                ProcessingTimeSeconds = [math]::Round($processingTime, 2)
                Message               = "Successfully processed $processedRecords records from $(Split-Path $filePath -Leaf) ($fileSizeMB MB) in $([math]::Round($processingTime, 2)) seconds"
            }
        }
        else {
            return @{
                Success          = $false
                FilePath         = $filePath
                Message          = "No valid records found in $(Split-Path $filePath -Leaf)"
                RecordsProcessed = 0
                LinesSkipped     = $skippedLines
            }
        }
    }
    catch {
        return @{
            Success  = $false
            FilePath = $filePath
            Message  = "Error processing $(Split-Path $filePath -Leaf): $($_.Exception.Message)"
            Error    = $_.Exception.Message
        }
    }
    finally {
        if ($reader) {
            $reader.Close()
            $reader.Dispose()
        }
    }
}

# Get all .log files in the folder
Write-Host "Scanning for log files in: $LogFolderPath" -ForegroundColor Yellow
$logFiles = Get-ChildItem -Path $LogFolderPath -Filter *.log -File -Recurse

if ($logFiles.Count -eq 0) {
    Write-Warning "No .log files found in the folder '$LogFolderPath'."
    exit 1
}

Write-Host "Found $($logFiles.Count) log file(s) to process" -ForegroundColor Green
Write-Host "Maximum concurrent jobs: $MaxConcurrentJobs" -ForegroundColor Cyan
Write-Host "Job timeout: $JobTimeoutMinutes minutes" -ForegroundColor Cyan

# Calculate total size of files to process
$totalSizeMB = [math]::Round(($logFiles | Measure-Object Length -Sum).Sum / 1MB, 2)
Write-Host "Total data to process: $totalSizeMB MB" -ForegroundColor Cyan

# Start jobs with throttling
$jobs = @()
$jobQueue = [System.Collections.Queue]::new()
$completedJobs = @()
$failedJobs = @()
$startTime = Get-Date

# Add all files to the queue
foreach ($logFile in $logFiles) {
    $jobQueue.Enqueue($logFile)
}

Write-Host "`nStarting parallel processing..." -ForegroundColor Yellow

# Process jobs with throttling
while ($jobQueue.Count -gt 0 -or (Get-Job -State 'Running' | Measure-Object).Count -gt 0) {
    
    # Start new jobs if under the limit and files remain in queue
    while ((Get-Job -State 'Running' | Measure-Object).Count -lt $MaxConcurrentJobs -and $jobQueue.Count -gt 0) {
        $logFile = $jobQueue.Dequeue()
        Write-Host "Starting processing for: $($logFile.Name) (Size: $([math]::Round($logFile.Length / 1MB, 2)) MB)" -ForegroundColor Cyan
        
        $job = Start-Job -ScriptBlock $logProcessingScript -ArgumentList $logFile.FullName, $OutputFolderPath
        $jobs += $job
    }
    
    # Check for completed jobs
    $completedJobsThisIteration = Get-Job -State 'Completed'
    foreach ($job in $completedJobsThisIteration) {
        try {
            $result = Receive-Job -Job $job -ErrorAction Stop
            
            # Handle hashtable serialization issue - convert to PSCustomObject if needed
            if ($result -is [System.Collections.Hashtable]) {
                $resultObj = [PSCustomObject]$result
            }
            else {
                $resultObj = $result
            }
            
            if ($resultObj.Success) {
                Write-Host $resultObj.Message -ForegroundColor Green
                $completedJobs += $resultObj
            }
            else {
                Write-Warning $resultObj.Message
                $failedJobs += $resultObj
            }
        }
        catch {
            Write-Error "Job failed with error: $_"
            $failedJobs += @{
                Success  = $false
                FilePath = "Unknown"
                Message  = "Job failed with error: $_"
                Error    = $_.Exception.Message
            }
        }
        finally {
            Remove-Job -Job $job -Force
        }
    }
    
    # Check for failed jobs
    $failedJobsThisIteration = Get-Job -State 'Failed'
    foreach ($job in $failedJobsThisIteration) {
        $jobName = $job.Name
        Write-Error "Job '$jobName' failed"
        $failedJobs += @{
            Success  = $false
            FilePath = $jobName
            Message  = "Job '$jobName' failed"
            Error    = "Job execution failed"
        }
        Remove-Job -Job $job -Force
    }
    
    # Check for jobs that have exceeded timeout
    $runningJobs = Get-Job -State 'Running'
    foreach ($job in $runningJobs) {
        $jobRunTime = (Get-Date) - $job.PSBeginTime
        if ($jobRunTime.TotalMinutes -gt $JobTimeoutMinutes) {
            Write-Warning "Job for $($job.Name) exceeded timeout of $JobTimeoutMinutes minutes. Stopping job."
            Stop-Job -Job $job
            Remove-Job -Job $job -Force
            $failedJobs += @{
                Success  = $false
                FilePath = $job.Name
                Message  = "Job timed out after $JobTimeoutMinutes minutes"
                Error    = "Timeout"
            }
        }
    }
    
    # Progress update
    $totalCompleted = $completedJobs.Count + $failedJobs.Count
    $percentComplete = if ($logFiles.Count -gt 0) { [math]::Round(($totalCompleted / $logFiles.Count) * 100, 1) } else { 0 }
    
    Write-Progress -Activity "Processing Log Files" -Status "$totalCompleted of $($logFiles.Count) files processed ($percentComplete%)" -PercentComplete $percentComplete
    
    # Brief pause to prevent excessive CPU usage
    Start-Sleep -Milliseconds 500
}

# Final check - wait for any remaining jobs to complete
Write-Host "`nWaiting for any remaining jobs to complete..." -ForegroundColor Yellow
$remainingJobs = Get-Job -State 'Running'
if ($remainingJobs.Count -gt 0) {
    Write-Host "Found $($remainingJobs.Count) jobs still running. Waiting up to 5 more minutes..." -ForegroundColor Yellow
    $finalWaitStart = Get-Date
    
    # Get the IDs of our jobs for comparison
    $jobIds = $jobs | ForEach-Object { $_.Id }
    
    while ((Get-Job -State 'Running').Count -gt 0 -and ((Get-Date) - $finalWaitStart).TotalMinutes -lt 5) {
        $runningCount = (Get-Job -State 'Running').Count
        $elapsedSeconds = ((Get-Date) - $finalWaitStart).TotalSeconds
        Write-Host "  Still waiting... $runningCount jobs running after $([math]::Round($elapsedSeconds, 1)) seconds" -ForegroundColor Yellow
        
        # Check for newly completed jobs
        $newlyCompletedJobs = Get-Job -State 'Completed'
        $processedInThisIteration = 0
        
        foreach ($job in $newlyCompletedJobs) {
            if ($jobIds -contains $job.Id) {
                # Compare by job ID instead of object reference
                $processedInThisIteration++
                try {
                    $result = Receive-Job -Job $job -ErrorAction Stop
                    
                    # Handle hashtable serialization issue - convert to PSCustomObject if needed
                    if ($result -is [System.Collections.Hashtable]) {
                        $resultObj = [PSCustomObject]$result
                    }
                    else {
                        $resultObj = $result
                    }
                    
                    if ($resultObj.Success) {
                        Write-Host $resultObj.Message -ForegroundColor Green
                        $completedJobs += $resultObj
                    }
                    else {
                        Write-Warning $resultObj.Message
                        $failedJobs += $resultObj
                    }
                }
                catch {
                    Write-Error "Job failed with error: $_"
                    $failedJobs += @{
                        Success  = $false
                        FilePath = "Unknown"
                        Message  = "Job failed with error: $_"
                        Error    = $_.Exception.Message
                    }
                }
                finally {
                    Remove-Job -Job $job -Force
                    # Remove this job ID from our tracking list
                    $jobIds = $jobIds | Where-Object { $_ -ne $job.Id }
                }
            }
        }
        
        if ($processedInThisIteration -gt 0) {
            Write-Host "  Processed $processedInThisIteration additional jobs in this iteration" -ForegroundColor Green
        }
        
        Start-Sleep -Milliseconds 1000
    }
    
    # Final check for any completed jobs that weren't caught in the loop
    Write-Host "Final check for any remaining completed jobs..." -ForegroundColor Yellow
    $finalCompletedJobs = Get-Job -State 'Completed'
    $finalProcessedCount = 0
    
    foreach ($job in $finalCompletedJobs) {
        if ($jobIds -contains $job.Id) {
            $finalProcessedCount++
            try {
                $result = Receive-Job -Job $job -ErrorAction Stop
                
                # Handle hashtable serialization issue - convert to PSCustomObject if needed
                if ($result -is [System.Collections.Hashtable]) {
                    $resultObj = [PSCustomObject]$result
                }
                else {
                    $resultObj = $result
                }
                
                if ($resultObj.Success) {
                    Write-Host $resultObj.Message -ForegroundColor Green
                    $completedJobs += $resultObj
                }
                else {
                    Write-Warning $resultObj.Message
                    $failedJobs += $resultObj
                }
            }
            catch {
                Write-Error "Job failed with error: $_"
                $failedJobs += @{
                    Success  = $false
                    FilePath = "Unknown"
                    Message  = "Job failed with error: $_"
                    Error    = $_.Exception.Message
                }
            }
            finally {
                Remove-Job -Job $job -Force
                # Remove this job ID from our tracking list
                $jobIds = $jobIds | Where-Object { $_ -ne $job.Id }
            }
        }
    }
    
    if ($finalProcessedCount -gt 0) {
        Write-Host "Processed $finalProcessedCount additional completed jobs in final check" -ForegroundColor Green
    }
    
    # Handle any jobs that are still running after the final wait
    $stillRunningJobs = Get-Job -State 'Running'
    if ($stillRunningJobs.Count -gt 0) {
        Write-Warning "Found $($stillRunningJobs.Count) jobs still running after final wait. Forcing termination..."
        foreach ($job in $stillRunningJobs) {
            if ($jobIds -contains $job.Id) {
                # Compare by job ID instead of object reference
                Write-Warning "Terminating job for: $($job.Name)"
                Stop-Job -Job $job -Force
                Remove-Job -Job $job -Force
                $failedJobs += @{
                    Success  = $false
                    FilePath = $job.Name
                    Message  = "Job was forcefully terminated after extended wait"
                    Error    = "Forced termination"
                }
            }
        }
    }
}

Write-Host "All job processing completed." -ForegroundColor Green

# Clean up any remaining jobs
Get-Job | Remove-Job -Force

$endTime = Get-Date
$totalProcessingTime = $endTime - $startTime

Write-Progress -Activity "Processing Log Files" -Completed

if ($totalProcessed -ne $logFiles.Count) {
    $unaccounted = $logFiles.Count - $totalProcessed
    Write-Host "Unaccounted files: $unaccounted" -ForegroundColor Yellow
    
    # Check what CSV files actually exist in the output folder
    Write-Host "`nChecking actual CSV files in output folder..." -ForegroundColor Yellow
    $csvFiles = Get-ChildItem -Path $OutputFolderPath -Filter "*.csv" -File
    Write-Host "Found $($csvFiles.Count) CSV files in output folder" -ForegroundColor Yellow
    
    # Cross-reference with original log files to see what's actually been processed
    $actuallyProcessedFiles = @()
    foreach ($logFile in $logFiles) {
        $expectedCsvName = [System.IO.Path]::GetFileNameWithoutExtension($logFile.Name) + ".csv"
        $csvExists = $csvFiles | Where-Object { $_.Name -eq $expectedCsvName }
        
        if ($csvExists) {
            $actuallyProcessedFiles += $logFile.FullName
            # If CSV exists but job wasn't tracked, add it to completed jobs for reporting
            $existsInCompleted = $completedJobs | Where-Object { 
                if ($_ -is [System.Collections.Hashtable]) {
                    $_.ContainsKey('FilePath') -and $_.FilePath -eq $logFile.FullName
                }
                else {
                    $_.FilePath -eq $logFile.FullName
                }
            }
            
            if (-not $existsInCompleted) {
                Write-Host "  Found orphaned CSV: $expectedCsvName - adding to completed jobs" -ForegroundColor Green
                # Try to get file stats for the missing job
                $csvFileInfo = Get-Item $csvExists.FullName
                $csvContent = Import-Csv -Path $csvExists.FullName -ErrorAction SilentlyContinue
                $recordCount = if ($csvContent) { $csvContent.Count } else { 0 }
                
                # Create a synthetic job result for the missing file
                $syntheticJob = [PSCustomObject]@{
                    Success               = $true
                    FilePath              = $logFile.FullName
                    OutputPath            = $csvExists.FullName
                    RecordsProcessed      = $recordCount
                    LinesSkipped          = 0
                    FileSizeMB            = [math]::Round($logFile.Length / 1MB, 2)
                    ProcessingTimeSeconds = 0  # Unknown since job wasn't tracked
                    Message               = "CSV file found but job wasn't tracked - $recordCount records in $expectedCsvName"
                }
                
                $completedJobs += $syntheticJob
                Write-Host "  Added synthetic job result for $($logFile.Name): $recordCount records" -ForegroundColor Green
            }
        }
    }
    
    # Check for any remaining jobs in various states
    $allJobs = Get-Job
    if ($allJobs.Count -gt 0) {
        Write-Host "`nRemaining jobs in system:" -ForegroundColor Yellow
        foreach ($job in $allJobs) {
            Write-Host "  Job: $($job.Name), State: $($job.State), ID: $($job.Id)" -ForegroundColor Yellow
        }
    }
}

# Recalculate totals after potentially adding synthetic jobs
$totalSuccessful = $completedJobs.Count
$totalFailed = $failedJobs.Count
$totalProcessed = $totalSuccessful + $totalFailed

# Generate comprehensive summary report (after potential synthetic job additions)
Write-Host "`n=== Processing Summary ===" -ForegroundColor Magenta
Write-Host "Total files found: $($logFiles.Count)" -ForegroundColor Yellow
Write-Host "Successfully processed: $totalSuccessful" -ForegroundColor Green
Write-Host "Failed: $totalFailed" -ForegroundColor Red

if ($totalProcessed -ne $logFiles.Count) {
    $unaccounted = $logFiles.Count - $totalProcessed
    Write-Host "Unaccounted files: $unaccounted" -ForegroundColor Yellow
}

Write-Host "Total processing time: $($totalProcessingTime.TotalMinutes.ToString('F2')) minutes" -ForegroundColor Cyan
Write-Host "Total data processed: $totalSizeMB MB" -ForegroundColor Cyan

if ($completedJobs.Count -gt 0) {
    # Count records from completed jobs, handling both hashtables and objects
    $totalRecords = 0
    $jobsWithRecords = 0
    
    foreach ($job in $completedJobs) {
        $recordCount = 0
        if ($job -is [System.Collections.Hashtable]) {
            if ($job.ContainsKey('RecordsProcessed') -and $job['RecordsProcessed'] -ne $null -and $job['RecordsProcessed'] -ne "") {
                $recordCount = [int]$job['RecordsProcessed']
                $jobsWithRecords++
            }
        }
        else {
            if ($job.PSObject.Properties.Name -contains 'RecordsProcessed' -and $job.RecordsProcessed -ne $null -and $job.RecordsProcessed -ne "") {
                $recordCount = [int]$job.RecordsProcessed
                $jobsWithRecords++
            }
        }
        $totalRecords += $recordCount
    }
    
    $avgProcessingSpeed = if ($totalProcessingTime.TotalSeconds -gt 0) { 
        [math]::Round($totalRecords / $totalProcessingTime.TotalSeconds, 2) 
    }
    else { 0 }
    
    Write-Host "Total records processed: $totalRecords" -ForegroundColor Green
    Write-Host "Average processing speed: $avgProcessingSpeed records/second" -ForegroundColor Cyan
    
    # Show top 5 largest files processed
    Write-Host "`n=== Top 5 Largest Files Processed ===" -ForegroundColor Magenta
    
    # Create a list of jobs with proper data for sorting, handling both hashtables and objects
    $jobsForDisplay = @()
    foreach ($job in $completedJobs) {
        $jobData = @{}
        
        if ($job -is [System.Collections.Hashtable]) {
            $jobData.FilePath = if ($job.ContainsKey('FilePath')) { $job['FilePath'] } else { "Unknown" }
            $jobData.FileSizeMB = if ($job.ContainsKey('FileSizeMB')) { [double]$job['FileSizeMB'] } else { 0 }
            $jobData.RecordsProcessed = if ($job.ContainsKey('RecordsProcessed')) { [int]$job['RecordsProcessed'] } else { 0 }
            $jobData.ProcessingTimeSeconds = if ($job.ContainsKey('ProcessingTimeSeconds')) { [double]$job['ProcessingTimeSeconds'] } else { 0 }
        }
        else {
            $jobData.FilePath = if ($job.FilePath) { $job.FilePath } else { "Unknown" }
            $jobData.FileSizeMB = if ($job.FileSizeMB) { [double]$job.FileSizeMB } else { 0 }
            $jobData.RecordsProcessed = if ($job.RecordsProcessed) { [int]$job.RecordsProcessed } else { 0 }
            $jobData.ProcessingTimeSeconds = if ($job.ProcessingTimeSeconds) { [double]$job.ProcessingTimeSeconds } else { 0 }
        }
        
        if ($jobData.RecordsProcessed -gt 0) {
            $jobsForDisplay += [PSCustomObject]$jobData
        }
    }
    
    $jobsForDisplay | Sort-Object FileSizeMB -Descending | Select-Object -First 5 | ForEach-Object {
        $fileName = Split-Path $_.FilePath -Leaf
        Write-Host "$fileName : $($_.FileSizeMB) MB, $($_.RecordsProcessed) records, $($_.ProcessingTimeSeconds)s" -ForegroundColor Cyan
    }
}

# Display failed jobs details
if ($failedJobs.Count -gt 0) {
    Write-Host "`n=== Failed Files ===" -ForegroundColor Red
    foreach ($failedJob in $failedJobs) {
        $fileName = Split-Path $failedJob.FilePath -Leaf
        Write-Host "$fileName : $($failedJob.Message)" -ForegroundColor Red
    }
}

# Create summary report file
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$summaryFile = Join-Path -Path $OutputFolderPath -ChildPath "ProcessingSummary_$timestamp.txt"

try {
    $summaryContent = @"
=== FW/VPN Log to CSV Conversion Summary ===
Generated: $(Get-Date)
Input Folder: $LogFolderPath
Output Folder: $OutputFolderPath
Processing Time: $($totalProcessingTime.TotalMinutes.ToString('F2')) minutes

=== Results ===
Total Files Found: $($logFiles.Count)
Successfully Processed: $($completedJobs.Count)
Failed: $($failedJobs.Count)
Total Data Processed: $totalSizeMB MB
"@

    if ($completedJobs.Count -gt 0) {
        # Only count records from jobs that have the RecordsProcessed property
        $jobsWithRecords = $completedJobs | Where-Object { $_.PSObject.Properties.Name -contains 'RecordsProcessed' -and $_.RecordsProcessed -ne $null }
        $totalRecords = if ($jobsWithRecords.Count -gt 0) { 
            ($jobsWithRecords | Measure-Object RecordsProcessed -Sum).Sum 
        }
        else { 0 }
        
        $summaryContent += [Environment]::NewLine + "Total Records Processed: $totalRecords" + [Environment]::NewLine
        $summaryContent += "Average Processing Speed: $avgProcessingSpeed records/second" + [Environment]::NewLine
        
        $summaryContent += [Environment]::NewLine + "=== Successfully Processed Files ===" + [Environment]::NewLine
        foreach ($job in $completedJobs) {
            # Handle both hashtables and objects
            if ($job -is [System.Collections.Hashtable]) {
                $fileName = if ($job.ContainsKey('FilePath')) { Split-Path $job['FilePath'] -Leaf } else { "Unknown" }
                $outputFileName = if ($job.ContainsKey('OutputPath')) { Split-Path $job['OutputPath'] -Leaf } else { "Unknown" }
                $records = if ($job.ContainsKey('RecordsProcessed')) { $job['RecordsProcessed'] } else { 0 }
                $sizeMB = if ($job.ContainsKey('FileSizeMB')) { $job['FileSizeMB'] } else { 0 }
            }
            else {
                $fileName = if ($job.FilePath) { Split-Path $job.FilePath -Leaf } else { "Unknown" }
                $outputFileName = if ($job.OutputPath) { Split-Path $job.OutputPath -Leaf } else { "Unknown" }
                $records = if ($job.RecordsProcessed) { $job.RecordsProcessed } else { 0 }
                $sizeMB = if ($job.FileSizeMB) { $job.FileSizeMB } else { 0 }
            }
            $summaryContent += "$fileName -> $outputFileName ($records records, $sizeMB MB)" + [Environment]::NewLine
        }
    }

    if ($failedJobs.Count -gt 0) {
        $summaryContent += [Environment]::NewLine + "=== Failed Files ===" + [Environment]::NewLine
        foreach ($job in $failedJobs) {
            # Handle both hashtables and objects
            if ($job -is [System.Collections.Hashtable]) {
                $fileName = if ($job.ContainsKey('FilePath')) { Split-Path $job['FilePath'] -Leaf } else { "Unknown" }
                $message = if ($job.ContainsKey('Message')) { $job['Message'] } else { "Unknown error" }
            }
            else {
                $fileName = if ($job.FilePath) { Split-Path $job.FilePath -Leaf } else { "Unknown" }
                $message = if ($job.Message) { $job.Message } else { "Unknown error" }
            }
            $summaryContent += "$fileName : $message" + [Environment]::NewLine
        }
    }

    $summaryContent | Out-File -FilePath $summaryFile -Encoding UTF8
    Write-Host "`nSummary report saved to: $summaryFile" -ForegroundColor Green
}
catch {
    Write-Warning "Failed to create summary report: $_"
}

if ($completedJobs.Count -eq $logFiles.Count) {
    Write-Host "`n=== All files processed successfully! ===" -ForegroundColor Green
}
elseif ($completedJobs.Count -gt 0) {
    Write-Host "`n=== Processing completed with some failures ===" -ForegroundColor Yellow
}
else {
    Write-Host "`n=== Processing failed for all files ===" -ForegroundColor Red
    exit 1
}

Write-Host "All CSV files have been saved to: $OutputFolderPath" -ForegroundColor Cyan

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
