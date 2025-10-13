# FortiGate VPN Log Parser & Security Intelligence Toolkit

A comprehensive collection of OPAL queries for analyzing FortiGate firewall and VPN logs in Observe. This toolkit transforms basic log analysis into enterprise-grade security intelligence with automated threat detection, risk assessment, and behavioral analysis.

##  Features

- **Automated Threat Detection** - Intelligent scoring and classification of security threats
- **Geographic Intelligence** - Complete geo-location analysis with ASN and anonymous proxy detection
- **Risk Assessment** - Multi-dimensional risk scoring and pattern recognition
- **Behavioral Analysis** - Communication patterns, anomaly detection, and trend analysis
- **Data Exfiltration Detection** - Advanced analysis of suspicious data transfer patterns
- **Network Flow Intelligence** - Comprehensive communication flow analysis

##  Analytics Categories

###  **Threat Intelligence & Source Analysis**

- **[Source IP Threat Intelligence Analysis](FortiGate/Source%20IP%20Threat%20Intelligence%20Analysis)** - Advanced source IP threat detection with automated risk scoring
- **[Remote IP Threat Intelligence Analysis](FortiGate/Remote%20IP%20Threat%20Intelligence%20Analysis)** - External IP behavior analysis and scanning detection
- **[Remote IPs targeting the most users](FortiGate/Remote%20IPs%20targeting%20the%20most%20users)** - Multi-target attack detection and campaign analysis

###  **Traffic Analysis & Data Flow**

- **[Biggest data movers (bytes)](<FortiGate/Biggest%20data%20movers%20(bytes)>)** - High-volume data transfer analysis with geo-intelligence
- **[Bytes sent vs received (exfil quick check)](<FortiGate/Bytes%20sent%20vs%20received%20(exfil%20quick%20check)>)** - Data exfiltration detection and baseline analysis
- **[Hourly Communication Flow Intelligence](FortiGate/Hourly%20Communication%20Flow%20Intelligence)** - Comprehensive network flow analysis by hour

###  **Security Posture & Policy Analysis**

- **[Firewall Security Posture Analysis](FortiGate/Firewall%20Security%20Posture%20Analysis)** - Overall security stance assessment with policy effectiveness
- **[Top policies causing denies-resets](FortiGate/Top%20policies%20causing%20denies-resets)** - Policy performance and threat blocking analysis
- **[Service and Action Anomaly Detection](FortiGate/Service%20and%20Action%20Anomaly%20Detection)** - Behavioral anomaly detection with baseline comparison

###  **Temporal & Trend Analysis**

- **[Timeframe](FortiGate/Timeframe)** - Log coverage analysis and temporal boundaries
- **[Hourly trend (quick spike scan)](<FortiGate/Hourly%20trend%20(quick%20spike%20scan)>)** - Traffic spike detection and hourly pattern analysis

###  **Geographic & Destination Analysis**

- **[Top DestinationIP on 2025-08-18](FortiGate/Top%20DestinationIP%20on%202025-08-18)** - Destination analysis with enhanced geo-intelligence
- **[Remote IPs in window (first seen)](<FortiGate/Remote%20IPs%20in%20window%20(first%20seen)>)** - New threat detection and first-seen analysis

##  Setup & Requirements

### Prerequisites

- **Observe Platform** with OPAL query support
- **FortiGate firewall logs** ingested into Observe
- **MaxMind GeoIP databases** for geographic intelligence
- **ASN databases** for autonomous system lookups

### Required Data Fields

Your FortiGate logs should contain these key fields:

```
FIELDS.date          - Log date (YYYY-MM-DD)
FIELDS.time          - Log time (HH:MM:SS)
FIELDS.srcip         - Source IP address
FIELDS.dstip         - Destination IP address
FIELDS.remip         - Remote IP (VPN logs)
FIELDS.action        - Firewall action (accept/deny/close)
FIELDS.service       - Service name
FIELDS.dstport       - Destination port
FIELDS.sentbyte      - Bytes sent
FIELDS.rcvdbyte      - Bytes received
FIELDS.policyid      - Policy ID
FIELDS.policyname    - Policy name
FIELDS.srccountry    - Source country (if available)
```

##  Usage Guide

### Quick Start

1. **Choose your analysis** - Select the appropriate query for your investigation
2. **Adjust time filters** - Update date/time filters to match your analysis window
3. **Configure thresholds** - Modify threat detection thresholds based on your environment
4. **Run in Observe** - Execute the OPAL query in your Observe workspace

### Common Usage Patterns

####  **Threat Hunting**

```opal
// Hunt for high-risk sources
filter RiskLevel != "NORMAL"

// Focus on scanning activity
filter ThreatScore = "HIGH_SCANNING"

// Geographic threat analysis
filter Country = "Russia" or Country = "China"
```

####  **Security Assessment**

```opal
// Check security posture
filter SecurityPosture = "PERMISSIVE"

// Analyze policy effectiveness
filter PolicyType = "GLOBAL_THREAT_BLOCKER"

// Review anomalies
filter AnomalyType != "NORMAL"
```

####  **Data Exfiltration Detection**

```opal
// Large outbound transfers
filter TotalSent > 1000000 and ExfilRatio > 5

// International upload patterns
filter FlowType = "UPLOAD_HEAVY" and CommunicationPattern = "INTERNATIONAL_FLOW"
```

##  Key Features by Query

###  **Automated Threat Scoring**

All queries include intelligent threat classification:

- `HIGH_SCANNING` - Active reconnaissance/scanning
- `MODERATE_SCANNING` - Potential threat activity
- `BLOCKED_ATTACKER` - Persistent blocked sources
- `PROXY_SCANNING` - Anonymous proxy-based threats

###  **Geographic Intelligence**

Enhanced with MaxMind GeoIP data:

- City/State/Country resolution
- Anonymous proxy detection
- ASN and hosting provider identification
- International vs domestic traffic analysis

###  **Pattern Recognition**

Advanced behavioral analysis:

- Communication flow patterns
- Data transfer anomalies
- Service targeting analysis
- Temporal attack patterns

##  Customization

### Adjusting Thresholds

Modify detection thresholds based on your environment:

```opal
// High-volume scanning threshold
UniqueDestinations > 50 and UniqueServices > 10

// Data exfiltration detection
TotalSent > 1000000 and ExfilRatio > 5

// Anomaly detection sensitivity
EventAnomalyRatio > 3 or EventAnomalyRatio < 0.1
```

### Time Window Configuration

Easy time period adjustments:

```opal
// Single day analysis
filter Date = "2025-09-17"

// Hour-specific analysis
filter Date = "2025-09-17" and HourPart = "15"

// Date range analysis
filter FirstSeen >= "2025-09-17"
```

### Geographic Filtering

Focus analysis on specific regions:

```opal
// Exclude domestic traffic
filter is_null(DstCountry) or DstCountry != "United States"

// High-risk countries
filter Country in ("Russia", "China", "North Korea")

// Cloud providers
filter ASN in ("M247 Europe SRL", "AMAZON-02")
```

##  Output Interpretation

### Threat Scores

- **HIGH** - Immediate investigation required
- **MEDIUM** - Monitor closely, potential threat
- **LOW** - Baseline monitoring
- **NORMAL** - Standard activity

### Activity Patterns

- **GLOBAL_TARGETING** - Multi-country attack campaigns
- **FOCUSED_ATTACK** - Concentrated targeting
- **SERVICE_SCANNING** - Service enumeration
- **DATA_EXFILTRATION_PATTERN** - Suspicious uploads

### Communication Types

- **HIGH_VOLUME_FLOW** - Large data transfers (>1GB)
- **INTERNATIONAL_FLOW** - Cross-border communications
- **BULK_DATA_TRANSFER** - File transfer patterns
- **PERSISTENT_BLOCKED** - Ongoing attack attempts

##  Security Use Cases

### 1. **Daily Threat Assessment**

- Run Source IP Threat Intelligence Analysis
- Review Firewall Security Posture Analysis
- Check Service and Action Anomaly Detection

### 2. **Incident Investigation**

- Use Hourly Communication Flow Intelligence for specific time windows
- Analyze data flows with Biggest data movers
- Check first-seen analysis for new threats

### 3. **Compliance Reporting**

- Firewall Security Posture for policy effectiveness
- Geographic analysis for data sovereignty
- Timeframe analysis for audit coverage

### 4. **Threat Hunting**

- Remote IP Threat Intelligence for external threats
- Policy analysis for attack vectors
- Anomaly detection for unknown threats
