# DNS Theory Index

This folder has been split into smaller topic files for readability and maintenance.

## Reading Order

- [Resolution Flow](01_resolution_flow.md)
- [DNS Hierarchy](02_hierarchy.md)
- [DNS Records](03_records.md)
- [DNS Caching](04_caching.md)
- [DNS Transport](05_transport.md)
- [DNSSEC](06_dnssec.md)
- [Reverse DNS](07_reverse.md)
- [Active Directory & DNS](08_active_directory.md)
- [Enterprise DNS Architecture](09_enterprise_architecture.md)
- [Cloud DNS](10_cloud_dns.md)
- [Attacker Perspective](11_attacker.md)
- [Common DNS Attacks](12_attacks.md)
- [Defender Perspective](13_defender.md)
- [BIND / named.conf note](bind_note.md)

## Notes

The BIND explanation discussed earlier is now captured in [bind_note.md](bind_note.md).
    - Example: `partner.com → 10.50.0.53` (partner's internal DNS, over VPN)
    - Example: AWS internal zones (`*.us-east-1.compute.internal`) forwarded to AWS VPC DNS

### DNS Filtering / RPZ (Response Policy Zones)

- Recursive resolvers intercept queries and return NXDOMAIN or a sinkhole IP for known-bad domains
- **Implementation**: Cisco Umbrella, Infoblox, Pi-hole, BIND RPZ, Windows DNS RPZ
- **What it catches**: Malware C2 domains, phishing domains, newly registered domains, DGA domains flagged by threat intel
- **What it misses**: Attacker domains not yet in blocklists, DoH bypasses, direct IP connections

### Security Zone Separation

- Never expose internal DNS servers to the internet
- External authoritative servers should contain only what needs to be public
- Internal recursive resolvers should only be reachable from internal networks
- Monitor for queries leaving the org that should only be internal (e.g., `*.corp.local` queries appearing on public DNS)

---

## Cloud DNS

### AWS Route 53

**Architecture**:

- Hosted zones: Public (internet-resolvable) or Private (VPC-only)
- Private hosted zones: Associated with one or more VPCs. Only instances in those VPCs can resolve.
- Resolver: VPC default resolver at `VPC_CIDR_base + 2` (e.g., `10.0.0.2`)
- Route 53 Resolver: Manages inbound/outbound DNS resolution across VPC boundaries and on-premises

**Routing policies**:

- Simple, Weighted, Latency, Failover, Geolocation, Geoproximity, Multivalue
- Health checks integrated — Route 53 can remove unhealthy records from responses

**Security**:

- Route 53 Resolver Query Logging → CloudWatch Logs or S3 → critical for detection
- DNSSEC signing supported for public hosted zones
- Private hosted zones are invisible to external resolvers — but don't put secrets in DNS names
- Resolver DNS Firewall: Block/allow domains at the VPC resolver level (similar to RPZ)
- Watch for: overly permissive Resolver inbound endpoints, misconfigured private zone associations exposing internal naming to unintended VPCs

### Azure DNS

**Architecture**:

- Public DNS zones: Hosted in Azure, globally distributed authoritative
- Private DNS zones: Resolved only by VNets linked to the zone
- Azure-provided DNS: `168.63.129.16` — the magic Azure resolver available to all VMs. Resolves private zones linked to the VNet.
- Azure DNS Private Resolver: For hybrid architectures, routes DNS between on-prem and Azure

**Security**:

- DNS Analytics: Azure Monitor workbook for DNS query logging and anomaly detection
- Private DNS zones + VNet links: Controls which VNets can resolve internal zones
- Watch for: public DNS zones with internal naming conventions exposed accidentally, private resolver endpoints exposed without NSG controls
- Azure Firewall DNS Proxy: Forces DNS through Azure Firewall for logging and filtering
- Diagnostic logs for DNS Private Resolver → Log Analytics → queryable for threat hunting

---

## Attacker Perspective — Reconnaissance

### NS Lookups

```bash
dig NS target.com
nslookup -type=NS target.com
```

**What it reveals**: DNS provider (Cloudflare, Route53, GoDaddy), whether they have internal vs external NS split, number of authoritative servers (resilience posture)

### MX Enumeration

```bash
dig MX target.com
```

**What it reveals**: Email provider (O365, Google Workspace, Proofpoint, Mimecast), email security stack, whether they have inbound email filtering

### Subdomain Enumeration

- **Brute force**: Try common names against authoritative servers (`admin`, `vpn`, `mail`, `api`, `dev`, `staging`, `internal`)
- **Certificate Transparency logs**: crt.sh, Censys — TLS certs issued for `*.target.com` or `internal.target.com` are public
- **DNS datasets**: SecurityTrails, VirusTotal, Shodan passive DNS
- **Web crawling**: Extract subdomains from JavaScript, HTML, redirects

```bash
amass enum -d target.com
subfinder -d target.com
```

**What it reveals**: Internal service naming conventions, cloud infrastructure (`s3.target.com`, `api-dev.target.com`), forgotten/unpatched systems (`legacy.target.com`), partner integrations

### Zone Transfer Testing

```bash
dig axfr @ns1.target.com target.com
```

If it works: instant complete inventory of all DNS records. Critical finding every time.

### DNS Fingerprinting

- Identify DNS software version via `CHAOS TXT version.bind @ns1.target.com`
- Some resolvers reveal software/version in error messages or banner records
- Used to identify vulnerable resolver versions

---

## Common DNS Attacks

### DNS Cache Poisoning

**How it works**:

1. Attacker sends a query to the target recursive resolver for a domain the attacker controls (e.g., `attacker-bait.com`)
2. While the resolver is looking up `attacker-bait.com`, the attacker floods it with forged responses for `targetbank.com A 1.2.3.4` with the transaction ID guessed or predicted
3. If the forged response arrives before the real one and the transaction ID matches, the resolver caches the poisoned entry
4. All subsequent clients of that resolver get the attacker's IP for `targetbank.com` until TTL expires

**Requirements**:

- Predictable or brute-forceable transaction IDs
- Non-randomized source ports (increases attack surface 65535x with port randomization)
- No DNSSEC validation at the resolver

**Impact**: All clients using the poisoned resolver are redirected. Phishing, credential harvesting, malware delivery.

**Detection**:

- Unexplained changes in resolved IPs for known domains
- Multiple failed transaction IDs for the same domain in short time (brute force attempt)
- High volume of UDP/53 responses arriving at resolver without corresponding queries

**Mitigations**: DNSSEC validation, source port randomization, 0x20 encoding, DNS-over-TLS/HTTPS

---

### DNS Spoofing

Broader term — any technique that causes a resolver or client to accept a false DNS record. Cache poisoning is one implementation. Others include:

- ARP poisoning + DNS response injection on the LAN
- BGP hijacking to intercept traffic to a recursive resolver
- Rogue DHCP assigning a malicious DNS server IP to clients

**Detection**: Compare DNS responses across multiple resolvers. Monitor for resolver IP changes in DHCP logs.

---

### DNS Hijacking

Attacker modifies where DNS queries are sent, rather than the responses:

- **Router-level**: Compromise home/SOHO router, change DNS server IP in DHCP settings
- **ISP-level**: Rare, but ISPs have injected NXDOMAIN responses for monetization (NXD hijacking)
- **Registrar-level**: Compromise domain registrar account, change NS records for target's domain
- **Malware-level**: Modify hosts file or change OS DNS configuration directly

**Detection**: Monitor your own NS records via external checking (tools like DNSTracer, or custom monitoring hitting authoritative servers directly). Certificate Transparency monitoring for unauthorized certs.

---

### Dangling DNS Records

Occurs when a DNS record points to a resource that no longer exists or is no longer owned.

**Examples**:

- `blog.corp.com CNAME corp.wordpress.com` — WordPress account deleted
- `cdn.corp.com CNAME corp.azureedge.net` — Azure CDN endpoint deleted
- `staging.corp.com A 52.x.x.x` — EC2 instance terminated, IP released back to pool

**Attack**:

1. Attacker discovers dangling record (via recon — CNAME points to unclaimed resource)
2. Attacker claims the resource (creates WordPress account, claims Azure subdomain, gets the EC2 IP)
3. Attacker now controls content served at `blog.corp.com` — valid TLS cert obtainable via ACME challenge

**Detection**:

- Scan your DNS records and validate every CNAME/A target is still owned/valid
- Tools: `can-i-take-over-xyz` (GitHub), `dnstwist`, manual recon
- Monitor CT logs for certs issued for your subdomains that you didn't request

---

### Subdomain Takeover

Specific case of dangling DNS: CNAME points to a platform that allows claiming the subdomain.

**Vulnerable platforms historically**: GitHub Pages, Heroku, Fastly, Zendesk, Azure (various), AWS S3 buckets, Shopify

**Impact**: Attacker serves arbitrary content under victim's subdomain. Cookie theft if cookies are scoped to `.corp.com`. Phishing under legitimate domain. Bypasses email security (sent from `@corp.com` subdomain).

**Mitigation**: Remove DNS records for decommissioned resources immediately. Audit CNAME targets regularly.

---

### Zone Transfer Exposure

Already covered in recon. From an attack impact perspective:

- Reveals complete internal naming structure if internal DNS is exposed
- Reveals security tooling hostnames (`siem.corp.local`, `edr-mgmt.corp.local`)
- Reveals domain controller names, backup server names, jumpbox names
- Accelerates lateral movement planning

**Mitigation**: Restrict AXFR by source IP in BIND (`allow-transfer { 10.0.0.2; };`) or Windows DNS ACLs.

---

### DNS Amplification

**Attack type**: DDoS reflection/amplification

**Flow**:

1. Attacker sends many small DNS queries with **spoofed source IP** (victim's IP) to open resolvers
2. Queries request large record types (ANY, DNSKEY, TXT) — 40-byte query → 4000-byte response = 100x amplification
3. Resolver sends large responses to the victim's IP
4. Victim is flooded with UDP traffic they never requested

**Requirements**: Open recursive resolvers on the internet (resolvers that answer queries from any source IP)

**Impact**: Network-layer DDoS against the victim. Difficult to block because traffic comes from legitimate resolver IPs.

**Detection (for operators of resolvers)**: Unexpected high-volume outbound responses, queries from single IPs for large record types, asymmetric query/response volume ratio

**Mitigation**: Close your resolvers (don't run open recursive resolvers). Rate limiting. BCP38 ingress filtering to prevent IP spoofing at the source.

---

### DNS Tunneling

**Concept**: Encode arbitrary data into DNS queries and responses to create a covert channel.

**How it works**:

```
Client (infected host)
    │
    └─→ Query: aGVsbG8gd29ybGQ.exfil.attacker.com TXT
                │──────────────│
                 base64-encoded data payload
    
Authoritative server (attacker controls)
    │
    └─→ Response TXT record contains base64-encoded response
    
Repeat until full communication channel established
```

**Use cases for attackers**:

- Bypass network firewalls that allow DNS but block other traffic
- Exfiltrate data from air-gapped or heavily filtered networks
- C2 communication channel (dnscat2, iodine, dns2tcp, Cobalt Strike DNS beacon)

**Detection signals**:

- High query volume for same domain or pattern
- Unusually long subdomain labels (>50 chars)
- High entropy in subdomain names (base64/hex-encoded data)
- High TXT record volume in responses
- DNS queries with no corresponding HTTP/application traffic
- Same FQDN queried repeatedly at regular intervals (beaconing pattern)
- High ratio of bytes in DNS query vs other protocols for that host

**Hunting query logic (Splunk pseudo)**:

```
index=dns
| eval subdomain_len=len(query) - len(replace(query, ".", "")) - len(eTLD)
| where subdomain_len > 40
| stats count by src_ip, query_base
| where count > 50
```

---

### Fast Flux

**Concept**: Rapidly rotate A records for a domain (every 60–300 seconds) across many compromised hosts (botnet). Makes the domain impossible to block by IP.

**Single flux**: Only A records rotate **Double flux**: Both A records AND NS records rotate (harder to take down)

**Use cases**: Malware C2, phishing pages, botnet infrastructure

**Detection signals**:

- Very short TTLs (< 300s) for a domain
- Many different IPs returned for the same domain over time
- IPs distributed across many ASNs/countries
- Passive DNS data showing IP rotation

---

### Domain Generation Algorithms (DGA)

**Concept**: Malware generates C2 domain names algorithmically using a seed (often date-based). Attacker pre-registers only the domains they need. AV/blocklists can't block all possible domains.

**Examples**: Conficker (generates 50,000 domains/day), Locky, Emotet, Necurs

**Detection signals**:

- NXDOMAINs in high volume from a single host (most DGA domains aren't registered yet)
- Queried domains match DGA patterns: pronounceable garbage (`xkrtzpqml.com`), fixed-length names, specific TLD patterns
- Query burst patterns — DGA malware often queries many domains in rapid succession looking for the live one

**Detection tools/techniques**:

- DGA classifiers (machine learning on domain name entropy, n-gram analysis, consonant/vowel ratios)
- Threat intel feeds with known DGA families
- NXDOMAIN rate anomaly per host
- RITA (Real Intelligence Threat Analytics) — open source, specifically designed for this

---

### DNS-based C2

Beyond tunneling — using DNS for command and control:

- **TXT record C2**: Commands encoded in TXT records, responses via query subdomains
- **Low-frequency beaconing**: One DNS query every 5 minutes, mimics normal traffic
- **DNS as drop zone**: Malware checks specific TXT records for instructions ("update", "sleep", "exfil")
- **C2 over DoH**: Malware uses Cloudflare/Google DoH to encrypt queries from inspection

**Examples**: Cobalt Strike DNS Beacon, DNSMessenger, OilRig/APT34 DNS tunneling tool, SUNBURST (SolarWinds) — used DNS for C2 activation check

**Detection**:

- Periodic/regular DNS queries to same domain at fixed intervals = beaconing
- Domains with low historical traffic suddenly queried by many internal hosts
- Query patterns that don't match normal browser/application behavior (no HTTPS traffic following the DNS query)
- Monitor for queries to DoH endpoints you don't manage

---

## Defender Perspective

### What to Monitor

|Signal|Why It Matters|
|---|---|
|High query volume per host|Tunneling, DGA, beaconing|
|High NXDOMAIN rate per host|DGA malware, misconfiguration|
|Long subdomain length|Tunneling|
|High entropy subdomains|Tunneling, encoded data|
|Short TTL domains|Fast flux C2|
|Many IPs per domain over time|Fast flux|
|Queries to newly registered domains|Phishing, C2|
|Queries to rare/low-rep domains|C2|
|Missing PTR records on queried IPs|Suspicious infrastructure|
|AXFR attempts|Zone transfer probing|
|DNS to non-corporate resolvers|Policy violation, DoH bypass|
|ANY record queries|Amplification probing|
|CHAOS TXT queries|DNS fingerprinting|

---

### Logging

**Windows DNS Server Logs**:

- Enable via DNS Manager → server → Debug Logging
- Or via ETW (Event Tracing for Windows) — more efficient
- Event ID 256/257: Query sent/received (ETW)
- Fields: query name, query type, source IP, response code, response data

**BIND Logs**:

```
logging {
    channel query_log {
        file "/var/log/named/queries.log" versions 10 size 20m;
        severity dynamic;
        print-time yes;
        print-category yes;
    };
    category queries { query_log; };
};
```

Key fields: timestamp, client IP, query name, query type, response code

**Recursive Resolver Logs**:

- Unbound, dnsmasq: similar structured logging
- Critical fields: `src_ip`, `query`, `qtype`, `rcode`, `answer_ip`, `TTL`

**Cloud DNS Logs**:

- AWS: Route 53 Resolver Query Logging → CloudWatch/S3 (JSON format, per-VPC)
- Azure: DNS Private Resolver diagnostic logs → Log Analytics
- GCP: Cloud DNS logging → Cloud Logging

**Key fields for investigation**:

- Source IP (which internal host made the query)
- Query name + type
- Response code (NXDOMAIN, SERVFAIL, NOERROR)
- Response IPs
- Response TTL
- Timestamp (calculate inter-query timing for beaconing detection)

---

### Threat Hunting

**DNS Tunneling Hunt**:

1. Calculate average subdomain length per domain per source IP
2. Flag domains where average subdomain label length > 40 chars
3. Calculate Shannon entropy of subdomain labels — base64/hex = high entropy
4. Look for domains with >N queries but zero corresponding HTTPS connections
5. Time-series analysis: identify periodic query patterns (automated, not human)

**DGA Hunt**:

1. Correlate DNS queries with NXDOMAIN responses per host over 24h
2. Hosts with NXDOMAIN rate > baseline threshold are candidates
3. Apply DGA classifier to unique queried domains (entropy, length, n-gram model)
4. Cross-reference with known DGA families' algorithms (MITRE ATT&CK, open-source classifiers)

**Fast Flux Hunt**:

1. Query passive DNS data for domains seen internally
2. Flag domains where >N unique IPs were returned within 24h
3. Flag domains with TTL < 300s that are queried frequently
4. Cross-reference IPs against threat intel (often malware-as-a-service infrastructure)

**Beaconing Hunt**:

1. Extract all DNS query pairs (src_ip, query_name) with timestamps
2. Calculate inter-query intervals for each pair
3. Flag pairs with very consistent intervals (low standard deviation) over 6+ hours
4. Known beaconing intervals: Cobalt Strike DNS default = 60s, many malware use 300s or 3600s

**Phishing Infrastructure Hunt**:

1. Extract newly registered domains queried by internal hosts (WHOIS age < 30 days)
2. Calculate typosquatting distance between queried domains and your org's domains (`dnstwist` logic)
3. Check TLS cert transparency for look-alike certs
4. Cross-reference with VirusTotal, Shodan, RiskIQ

---

## DNS Packet Analysis

### Packet Structure

```
DNS Packet
├── Header (12 bytes fixed)
│   ├── ID (16 bits) — matches query to response
│   ├── Flags (16 bits)
│   │   ├── QR: Query(0) or Response(1)
│   │   ├── Opcode: Standard(0), Inverse(1), Status(2)
│   │   ├── AA: Authoritative Answer
│   │   ├── TC: Truncated (use TCP)
│   │   ├── RD: Recursion Desired (client sets)
│   │   ├── RA: Recursion Available (server sets)
│   │   ├── Z: Reserved
│   │   ├── AD: Authentic Data (DNSSEC)
│   │   ├── CD: Checking Disabled (DNSSEC)
│   │   └── RCODE: Response code (0=OK, 2=SERVFAIL, 3=NXDOMAIN, 5=REFUSED)
│   ├── QDCOUNT: Number of questions
│   ├── ANCOUNT: Number of answers
│   ├── NSCOUNT: Number of authority records
│   └── ARCOUNT: Number of additional records
│
├── Question Section
│   ├── QNAME: Domain name (label encoding)
│   ├── QTYPE: Record type (1=A, 28=AAAA, 5=CNAME, 15=MX, 16=TXT, 255=ANY)
│   └── QCLASS: 1=IN (Internet)
│
├── Answer Section
│   └── RR: name, type, class, TTL, rdlength, rdata
│
├── Authority Section
│   └── NS records pointing to authoritative servers
│
└── Additional Section
    └── A records for NS servers named in authority (glue)
```

### Wireshark Analysis

**Display filter for DNS**: `dns`

**Useful filters**:

```
dns.flags.response == 0              # Only queries
dns.flags.response == 1              # Only responses
dns.flags.rcode == 3                 # NXDOMAIN responses
dns.qry.type == 16                   # TXT queries
dns.qry.type == 255                  # ANY queries (potential amplification)
dns.qry.name contains "attacker"     # Domain filter
frame.len > 512 && udp.port == 53    # Large UDP DNS (potential amplification or tunneling)
dns.flags.tc == 1                    # Truncated (triggers TCP retry)
```

**What to look for in investigation**:

- Transaction ID matching between query and response (poisoning: forged responses with correct ID)
- Response IPs not matching expected authoritative range
- Large response payloads for TXT/ANY queries
- Many queries from single source to varied domains (DGA pattern)
- Identical subdomains with slowly incrementing base64 content (tunneling)
- Timing analysis: automated queries have machine-precise intervals; human browsing is irregular

**IOC identification in packets**:

- Long subdomains = tunneling or DGA
- High-entropy strings in query names = encoded data
- NXDOMAIN floods from one host = DGA
- Responses pointing to known bad IPs
- Unsigned records in DNSSEC-signed zones

---

## Tools

### Offensive Tools

#### dig

The standard. Does everything.

```bash
# Basic query
dig A google.com

# Query specific server
dig @8.8.8.8 A google.com

# Zone transfer
dig axfr @ns1.target.com target.com

# Short output
dig +short A google.com

# Trace full resolution path
dig +trace google.com

# All records
dig ANY target.com

# Reverse lookup
dig -x 8.8.8.8

# DNSSEC validation
dig +dnssec A google.com
```

#### nslookup

Older, interactive mode useful for quick checks. Less flexible than dig.

```bash
nslookup -type=MX target.com
nslookup -type=TXT target.com 8.8.8.8
```

#### host

Simpler output than dig. Good for quick scripting.

```bash
host -t MX target.com
host -a target.com        # All records
host -l target.com ns1.target.com  # Zone transfer attempt
```

#### dnsenum

Automated enumeration: NS, MX, zone transfer attempt, brute-force subdomains, reverse lookup on discovered IPs.

```bash
dnsenum --enum target.com
dnsenum --dnsserver ns1.target.com --enum target.com -f /usr/share/wordlists/subdomains.txt
```

#### dnsrecon

More refined than dnsenum. Better structured output. Supports multiple enumeration modes.

```bash
dnsrecon -d target.com -t std        # Standard recon
dnsrecon -d target.com -t axfr       # Zone transfer
dnsrecon -d target.com -t brt -D /path/to/wordlist  # Brute force
dnsrecon -d target.com -t zonewalk   # NSEC zone walking
```

#### fierce

Subdomain enumeration via DNS brute force + IP range reverse lookups.

```bash
fierce --domain target.com
fierce --domain target.com --wordlist /path/to/wordlist
```

#### amass

Most comprehensive subdomain enumeration. Active + passive. Uses 50+ sources (CT logs, passive DNS, APIs).

```bash
amass enum -d target.com                          # Passive + active
amass enum -passive -d target.com                 # Passive only (no direct queries to target)
amass enum -d target.com -config config.ini       # With API keys configured
```

#### subfinder

Faster than amass for passive-only enumeration. Uses 40+ sources.

```bash
subfinder -d target.com
subfinder -d target.com -o subdomains.txt
subfinder -dL domains.txt -all    # All sources
```

#### massdns

High-performance DNS resolver for brute-forcing. Can resolve millions of names per minute.

```bash
massdns -r resolvers.txt -t A subdomains.txt -o S > results.txt
```

#### dnsx

Takes input from other tools (subfinder, amass), resolves them, filters valid ones.

```bash
subfinder -d target.com | dnsx -a -resp      # Resolve + show A records
cat subdomains.txt | dnsx -filter-code NXDOMAIN -o active.txt
```

---

### Defensive Tools

#### Wireshark

Packet-level DNS inspection. Use display filters above. Key for forensics and malware analysis. `tshark` for command-line version (scriptable).

```bash
tshark -r capture.pcap -Y "dns" -T fields -e frame.time -e ip.src -e dns.qry.name -e dns.resp.name -e dns.a
```

#### Zeek (formerly Bro)

Network traffic analyzer that generates structured DNS logs automatically.

**`dns.log` fields**:

- `ts`, `uid`, `id.orig_h` (src), `id.resp_h` (resolver), `proto`, `query`, `qtype_name`, `rcode_name`, `answers`, `TTLs`, `rejected`

**Zeek is the primary DNS telemetry source in many SOC environments**. All hunting queries above translate directly to Zeek `dns.log` queries in Splunk/Elastic.

#### Suricata

Network IDS/IPS. DNS-specific rules:

- Detect ANY record queries (amplification probing)
- Detect long subdomain labels (tunneling)
- Detect known DGA patterns
- Detect queries to known C2 domains

#### Security Onion

Combines Zeek + Suricata + Elasticsearch + Kibana. Out-of-box DNS visibility. Use Hunt interface for DNS hunting queries.

#### Splunk

Primary SIEM for DNS analytics at scale. See Detection Engineering section for specific queries.

#### Microsoft Sentinel

Azure-native SIEM. DNS Connectors:

- Azure DNS Analytics solution
- Windows DNS Server connector (via Log Analytics agent or AMA)
- DNS normalization via ASIM (Advanced Security Information Model) — normalizes fields across sources

---

## Detection Engineering

### DNS Sigma Rules

**DNS Tunneling (Long Subdomain)**:

```yaml
title: Potential DNS Tunneling via Long Subdomain
status: experimental
logsource:
    category: dns
detection:
    selection:
        QueryName|re: '^[a-zA-Z0-9+/]{40,}\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    condition: selection
falsepositives:
    - Some CDN and cloud providers use long encoded subdomains
    - Azure AD device registration uses long subdomains
level: medium
```

**NXDOMAIN Flood (DGA)**:

```yaml
title: High NXDOMAIN Rate - Potential DGA Activity
status: experimental
logsource:
    category: dns
detection:
    selection:
        QueryStatus: 'NXDOMAIN'
    timeframe: 5m
    condition: selection | count() by SourceIP > 100
falsepositives:
    - Misconfigured applications
    - Vulnerability scanners
level: high
```

**DNS ANY Record Query**:

```yaml
title: DNS ANY Record Query - Potential Amplification Reconnaissance
logsource:
    category: dns
detection:
    selection:
        QueryType: 'ANY'
    filter:
        SourceIP|cidr: '10.0.0.0/8'   # Tune to your internal ranges
    condition: selection and not filter
level: medium
```

**DNS over Non-Standard Resolver**:

```yaml
title: DNS Query to Non-Corporate Resolver
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationPort: 53
    filter:
        DestinationIP|cidr:
            - '10.0.0.0/8'     # Internal DNS servers
            - '192.168.0.0/16'
    condition: selection and not filter
falsepositives:
    - Legitimate DoH clients (browsers with custom DNS settings)
    - VPN clients
level: medium
```

### DNS Anomaly Detection

**Baseline approaches**:

- Per-host: Average queries/hour, unique domains/hour, NXDOMAIN rate, average query length
- Per-domain: Historical query frequency, IP diversity, TTL stability
- Network-wide: Top queried domains, newly seen domains, query type distribution

**Statistical anomalies to flag**:

- Host exceeds 3σ above its own baseline NXDOMAIN rate
- Domain queried by >N hosts that never previously queried it (newly seen domain going wide fast)
- Periodic query patterns with standard deviation < 1s over 4h+ window
- Sudden appearance of high-entropy domain in query logs

**Machine learning approaches**:

- Shannon entropy threshold on subdomain labels (> 3.5 bits/char = suspicious for base32/64)
- N-gram language model: compare domain names to English/dictionary words — DGA domains score poorly
- Isolation Forest / DBSCAN on {query_rate, nxdomain_rate, unique_domains, avg_len} per host

### False Positive Considerations

|Detection|Common FPs|
|---|---|
|Long subdomains|Azure AD, CDNs (Akamai/CloudFront), Docker image hashes|
|High NXDOMAIN|Misconfigured apps, internal service discovery|
|ANY queries|Dig/nslookup troubleshooting, some monitoring tools|
|Short TTL domains|Legitimate CDNs, Google, Cloudflare|
|High entropy|Encrypted DNS (DoH), some CDN URL structures|
|DNS to external resolvers|Browser DoH, VPN clients, developer tools|

---

## Troubleshooting

### NXDOMAIN — Name Does Not Exist

**Symptoms**: Client gets NXDOMAIN, application fails to connect

**Investigation**:

```bash
# Does the record exist at authoritative?
dig @ns1.corp.com internal-app.corp.com

# Does it exist at recursive?
dig @10.0.0.53 internal-app.corp.com

# Check for typo / case sensitivity
dig internal-APP.corp.com   # DNS is case-insensitive in lookup but check zone

# Check negative TTL (how long will NXDOMAIN be cached?)
dig SOA corp.com | grep -i "minimum"
```

**Root causes**: Record never created, record deleted, zone not loaded, wrong zone file, propagation lag (new record, waiting for secondary sync)

---

### SERVFAIL — Server Failure

**Symptoms**: Resolver returns SERVFAIL, application times out

**Investigation**:

```bash
# Does the authoritative server respond?
dig @ns1.corp.com corp.com SOA

# Is the recursive resolver reaching the authoritative?
dig +trace corp.com

# Is DNSSEC the cause?
dig +cd corp.com   # +cd disables DNSSEC checking — if this works, DNSSEC is the problem
dig corp.com DNSKEY
```

**Root causes**: Authoritative server unreachable, DNSSEC validation failure, recursive resolver misconfiguration, expired zone (serial not updated, secondary refuses to serve)

---

### Delegation Issues

**Symptoms**: External DNS works, but only for parent zone. Subdomain delegation doesn't resolve.

**Investigation**:

```bash
# Does parent zone have correct NS records for child?
dig NS sub.corp.com @ns1.corp.com

# Are glue records present?
dig +norec NS sub.corp.com @a.gtld-servers.net

# Does the delegated NS actually respond?
dig @ns1.sub.corp.com sub.corp.com SOA
```

**Root causes**: NS records not published in parent zone, glue records missing, child NS server not listening/unreachable, mismatched NS records between parent and child zone

---

### DNSSEC Failures

**Symptoms**: SERVFAIL on DNSSEC-validating resolvers, but works with `+cd` flag or non-validating resolver

**Investigation**:

```bash
# Test with DNSSEC disabled
dig +cd corp.com

# Check DNSKEY
dig DNSKEY corp.com

# Check DS records at parent
dig DS corp.com @parent-ns

# Validate full chain
dig +dnssec +multiline A corp.com

# Online validator
# https://dnssec-debugger.verisignlabs.com/
# https://dnsviz.net/
```

**Root causes**: Expired RRSIG (most common), DS/DNSKEY mismatch after key rollover, zone signed with algorithm not supported by validator, NSEC/NSEC3 mismatch

---

### Propagation Issues

**Symptoms**: Record updated but some clients still get old answer

**Root cause**: TTL-based — old records cached until TTL expires

**Investigation**:

```bash
# Check TTL on current cached response
dig A target.corp.com
# Look at TTL in answer section — counts down from original TTL

# Query multiple resolvers to see what they have cached
dig @8.8.8.8 A target.corp.com
dig @1.1.1.1 A target.corp.com
dig @authoritative-ns A target.corp.com

# If you need fast propagation next time: lower TTL 24-48h before making change
```

---

### Resolver Issues

**Symptoms**: All DNS fails from specific clients or segment

**Investigation**:

```bash
# Test basic connectivity to resolver
nc -uzv 10.0.0.53 53

# Test resolver directly
dig @10.0.0.53 google.com

# Check forwarder chain
dig @10.0.0.53 +trace google.com

# Check resolver logs for errors
tail -f /var/log/named/default.log   # BIND
Get-WinEvent -LogName "DNS Server" | Where-Object {$_.LevelDisplayName -eq "Error"}  # Windows
```

**Root causes**: Resolver service down, firewall blocking UDP/53 to resolver, forwarder unreachable, resolver misconfiguration after update

---

## Interview Preparation

### Security Analyst Questions

- Walk me through what happens when a user types `google.com` into their browser. Go deeper than "DNS resolves it."
- What's the difference between an authoritative and a recursive DNS server? Why does the distinction matter for security?
- A user reports they're being redirected to a fake login page. DNS seems involved. How do you investigate?
- What's a dangling DNS record? Can you describe a real attack scenario and how you'd find one?
- What DNS record types would you check first when investigating a phishing domain?
- How would you use DNS to determine what email security stack a company is running without touching their systems?
- What's the security implication of an open recursive resolver?

### SOC Analyst Questions

- You see a single internal host generating 500 NXDOMAIN responses in 5 minutes. What's your process?
- What does a DNS tunneling attack look like in your logs? What fields do you look at?
- How would you differentiate between DGA malware and a misconfigured application both causing NXDOMAIN floods?
- A host is querying `a8Fk3Xp1mN2.exfil-domain.com` with TXT responses of 400+ characters every 30 seconds. Describe what you think is happening and your response steps.
- What's your first DNS check when a user can't authenticate to corporate systems?
- How would you confirm or rule out DNS hijacking during an incident?
- What's the difference between DNS spoofing and DNS hijacking?

### Security Engineer Questions

- How would you design DNS infrastructure to prevent zone transfer exposure?
- What are the security trade-offs of deploying DNSSEC in an enterprise environment?
- How would you implement DNS logging across a hybrid environment (on-prem Windows DNS + Azure)?
- What controls would you put in place to detect and prevent DNS-based C2 in your environment?
- Describe how you'd build a detection for fast flux domains.
- What DNS changes would you recommend to harden an Active Directory environment against external reconnaissance?
- How does RPZ (Response Policy Zone) work and what are its limitations?

### Cloud Security Questions

- What's the difference between AWS Route 53 public and private hosted zones? What's the security implication of each?
- How would you restrict DNS resolution to specific VPCs in AWS?
- A developer accidentally made an internal Route 53 private zone public. What's the impact and remediation?
- How do you enable DNS query logging in Azure? Where does it go and how do you query it?
- What's Azure Private DNS and when would you use it vs. custom DNS servers on VMs?
- How does Azure DNS Private Resolver work for hybrid connectivity?
- What DNS misconfigurations commonly appear in cloud environments in bug bounties or pentests?

### Detection Engineering Questions

- Write a detection logic for DNS tunneling. What features would you extract? What thresholds would you set?
- How would you baseline normal DNS behavior for an organization to improve detection accuracy?
- What's the false positive rate challenge with NXDOMAIN-based DGA detection, and how do you address it?
- How would you hunt for beaconing behavior in DNS logs specifically?
- Describe a Sigma rule you'd write for detecting DNS queries to newly registered domains.
- What fields in DNS logs are most valuable for threat hunting, and why?
- How would you approach tuning a DNS anomaly detection model to reduce analyst fatigue?
- If DNS over HTTPS is being used by malware to bypass your DNS logging, how would you compensate at the detection layer?

---