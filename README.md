# VPN Log Analysis Tool

## Overview
The **VPN Log Analysis Tool** is a PowerShell script designed to parse VPN log files, extract critical data, and perform analyses to assist in investigating ransomware events and other security incidents.

### Key Features:
- **Failed Connections Log**: Identifies and exports all failed VPN connection attempts.
- **Unusual IPs Log**: Flags connections from unexpected countries.
- **Connection Frequency Analysis**: Tracks repeated connection attempts by remote IPs.
- **Output**: Generates CSV files for easy analysis in Excel or other tools.

---

## How It Works
The script processes `.log` files containing VPN connection data, extracts key-value pairs, and analyzes them based on defined criteria.

### Example Log Entry:



---

## Outputs
The script generates the following CSV files in the specified output folder:

1. **`FailedConnections.csv`**
   - Contains VPN connection attempts that failed (`status="failure"` or `result="ERROR"`).
   - Key fields include:
     - `remip`: Remote IP address.
     - `srccountry`: Source country.
     - `status`: Failure status.
     - `date` and `time`: When the failure occurred.

2. **`UnusualIPs.csv`**
   - Lists connections from unexpected or high-risk countries.

3. **`ConnectionFrequency.csv`**
   - Summarizes connection attempts by remote IP (`remip`), including a count of attempts.

---

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/your-repo/vpn-log-analysis-tool.git


cd vpn-log-analysis-tool

Usage
Run the Script: Open PowerShell and execute the script:

powershell
Copy code
.\vpn-log-analysis-tool.ps1
Provide Input and Output Paths:

Input: Specify the folder containing .log files to analyze.
Output: Specify the folder where the CSV results will be saved.
Monitor Progress:

The script provides real-time feedback as it processes files.
Review Outputs:

Open the generated CSV files in Excel or another tool for analysis.
