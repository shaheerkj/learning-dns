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

### DNS Spoofing

Broader term — any technique that causes a resolver or client to accept a false DNS record. Cache poisoning is one implementation. Others include:

- ARP poisoning + DNS response injection on the LAN
- BGP hijacking to intercept traffic to a recursive resolver
- Rogue DHCP assigning a malicious DNS server IP to clients

**Detection**: Compare DNS responses across multiple resolvers. Monitor for resolver IP changes in DHCP logs.

### DNS Hijacking

Attacker modifies where DNS queries are sent, rather than the responses:

- **Router-level**: Compromise home/SOHO router, change DNS server IP in DHCP settings
- **ISP-level**: Rare, but ISPs have injected NXDOMAIN responses for monetization (NXD hijacking)
- **Registrar-level**: Compromise domain registrar account, change NS records for target's domain
- **Malware-level**: Modify hosts file or change OS DNS configuration directly

**Detection**: Monitor your own NS records via external checking (tools like DNSTracer, or custom monitoring hitting authoritative servers directly). Certificate Transparency monitoring for unauthorized certs.

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

### Subdomain Takeover

Specific case of dangling DNS: CNAME points to a platform that allows claiming the subdomain.

**Vulnerable platforms historically**: GitHub Pages, Heroku, Fastly, Zendesk, Azure (various), AWS S3 buckets, Shopify

**Impact**: Attacker serves arbitrary content under victim's subdomain. Cookie theft if cookies are scoped to `.corp.com`. Phishing under legitimate domain. Bypasses email security (sent from `@corp.com` subdomain).

**Mitigation**: Remove DNS records for decommissioned resources immediately. Audit CNAME targets regularly.

### Zone Transfer Exposure

Already covered in recon. From an attack impact perspective:

- Reveals complete internal naming structure if internal DNS is exposed
- Reveals security tooling hostnames (`siem.corp.local`, `edr-mgmt.corp.local`)
- Reveals domain controller names, backup server names, jumpbox names
- Accelerates lateral movement planning

**Mitigation**: Restrict AXFR by source IP in BIND (`allow-transfer { 10.0.0.2; };`) or Windows DNS ACLs.

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

### Fast Flux

**Concept**: Rapidly rotate A records for a domain (every 60–300 seconds) across many compromised hosts (botnet). Makes the domain impossible to block by IP.

**Single flux**: Only A records rotate **Double flux**: Both A records AND NS records rotate (harder to take down)

**Use cases**: Malware C2, phishing pages, botnet infrastructure

**Detection signals**:

- Very short TTLs (< 300s) for a domain
- Many different IPs returned for the same domain over time
- IPs distributed across many ASNs/countries
- Passive DNS data showing IP rotation

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
