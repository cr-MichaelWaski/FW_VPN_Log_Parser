Suspicious_Connection_Analysis

How to Use the Failed Connections Log in a Ransomware Investigation
1. Identify Unauthorized Access Attempts
Look for repeated failed connection attempts from unfamiliar or suspicious IP addresses (remip).
Correlate remip with threat intelligence or IP reputation services to identify malicious actors.
2. Examine Login Behavior
Unusual IPs:
Compare the source country (srccountry) of the remote IPs with the expected regions for your organization.
Investigate any connections from high-risk regions or countries where your organization does not operate.
Timing of Failures:
Review timestamps (date and time) for clusters of failed attempts. Sudden bursts might indicate brute-force attacks.
3. Analyze Patterns for Brute-Force Attacks
Check for:
A single remip attempting multiple connections over a short period.
Multiple user values from the same remip to identify brute-force username guessing.
4. Identify the Potential Entry Point
Review logs for a progression from failed to successful connection attempts.
If a ransomware actor gained access, there might be a single successful connection after a series of failed ones.
5. Correlate with Other Logs
Use the data in FailedConnections.csv to correlate with:
Firewall logs to see if the IP was blocked.
Endpoint logs to verify if any sessions were established.
Active Directory logs to check if any accounts were compromised.
6. Monitor VPN Tunnel Names
Review the vpntunnel field to identify if a specific tunnel (e.g., "Radpartners") was targeted. This might indicate attackers focusing on specific assets or partners.
