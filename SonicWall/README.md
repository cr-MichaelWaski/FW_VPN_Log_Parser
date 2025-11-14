# SonicWall VPN/Firewall OPAL Queries

These queries mirror the FortiGate analyses but adapted for SonicWall logs in Observe (OPAL). They use robust field coalescing so they work across common SonicWall syslog variants (Classic vs Enhanced) and custom pipelines.

## Prerequisites

- Observe with OPAL query support
- SonicWall firewall/VPN logs ingested
- Optional: MaxMind GeoIP and ASN datasets for geo/ASN enrichments

## Field Mapping (canonical → common SonicWall field names)

The queries normalize into canonical names using `coalesce(...)`. If your pipeline uses different names, update the coalescing lists at the top of each query.

- Timestamp: `FIELDS.timestamp`, `FIELDS.time`, `FIELDS.@timestamp`
- Action: `FIELDS.action`, `FIELDS.act`
- Type/Subtype: `FIELDS.subtype`, `FIELDS.type`, `FIELDS.event_type`, `FIELDS.event_subtype`
- User: `FIELDS.user`, `FIELDS.usr`, `FIELDS.username`
- SourceIP: `FIELDS.srcip`, `FIELDS.src`, `FIELDS.source_ip`
- DestinationIP: `FIELDS.dstip`, `FIELDS.dst`, `FIELDS.destination_ip`
- RemoteIP (VPN): `FIELDS.remip`, `FIELDS.src`, `FIELDS.remote_ip`
- Service/Application: `FIELDS.service`, `FIELDS.svc`, `FIELDS.application`
- Protocol: `FIELDS.proto`, `FIELDS.protocol`
- Src/Dst Port: `FIELDS.srcport`/`FIELDS.dstport`, `FIELDS.sport`/`FIELDS.dport`, `FIELDS.source_port`/`FIELDS.dest_port`
- Bytes: `FIELDS.sentbyte`/`FIELDS.rcvdbyte`, `FIELDS.sent`/`FIELDS.rcvd`, `FIELDS.bytes_out`/`FIELDS.bytes_in`
- Policy/Rule: `FIELDS.policyid`/`FIELDS.policyname`, `FIELDS.rule`/`FIELDS.rule_id`/`FIELDS.rule_name`
- Reason/Message: `FIELDS.reason`, `FIELDS.msg`, `FIELDS.message`
- Zones/Interfaces: `FIELDS.srcintfrole`/`FIELDS.dstintfrole`, `FIELDS.src_zone`/`FIELDS.dst_zone`, `FIELDS.szone`/`FIELDS.dzone`

## Selecting SonicWall data

Each query starts with a path/vendor filter similar to:

```opal
make_col path:lower(string(EXTRA.path))
filter contains(string(path), "sonic") or contains(string(path), "sonicwall")
  or lower(string(FIELDS.vendor)) = "sonicwall"
```

Adjust this to match your dataset routing if needed.

## Usage

- Open a query in Observe and tune time filters/thresholds as needed.
- If a field is missing, update the `coalesce(...)` lists near the top of the query.
- Geo/ASN enrichments require the corresponding datasets in your workspace.

## Contents

- VPN analytics: successes vs failures, after-hours logins, password spraying, account sharing indicators, remote IP risk, tunnel flapping, top noisy users
- Firewall/traffic: biggest data movers, bytes sent vs received, top policies causing denies/resets, hourly trends and flows, remote/source IP threat intelligence, first-seen IPs, allow/deny mixes, timeframe coverage
