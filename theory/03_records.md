## DNS Records

### A — IPv4 Address

- Maps hostname → IPv4
- **Enterprise use**: Everything. Web servers, internal services, workstations (via DHCP-registered DNS)
- **Security**: A records for newly registered domains pointing to known malicious IPs. Multiple A records for the same domain rotating rapidly = fast flux. Wildcard A records on attacker domains catch all subdomains for phishing.

### AAAA — IPv6 Address

- Maps hostname → IPv6
- **Security**: Many orgs log/monitor IPv4 DNS but miss AAAA. Attackers use AAAA records for C2 when IPv4 monitoring is tight. Organizations that haven't deployed IPv6 but still resolve AAAA queries may leak internal topology.

### CNAME — Canonical Name

- Alias from one hostname to another. Can't coexist with other records at the same name (except DNSSEC).
- **Enterprise use**: `www.corp.com CNAME loadbalancer.corp.com` — allows the real backend to change without updating every reference
- **Security**: Dangling CNAMEs → subdomain takeover. If `blog.corp.com CNAME corp.wordpress.com` and the WordPress account is abandoned, an attacker claims it and controls `blog.corp.com`. Also: CNAME chains can obscure the final destination in investigation.

### MX — Mail Exchange

- Points to the mail server(s) for a domain. Has a priority value (lower = higher priority).
- **Enterprise use**: Routing inbound email. Multiple MX records for redundancy.
- **Security**: MX enumeration reveals email infrastructure and security posture. An MX pointing to a cloud provider (e.g., `*.protection.outlook.com`) identifies email security stack. Absence of SPF/DMARC TXT records is detectable via DNS.

### TXT — Text

- Free-form text. Originally for human-readable notes, now carries structured machine-readable data.
- **Enterprise use**: SPF (`v=spf1 include:... ~all`), DKIM public keys (`v=DKIM1; k=rsa; p=...`), DMARC policy, domain ownership verification, ACME challenges for TLS certs
- **Security**: Extremely high abuse potential. DNS tunneling tools encode data into TXT records. Long/high-entropy TXT query responses are a key detection signal. SPF misconfigurations (overly permissive `+all`) enable spoofing. Check TXT records during recon for info leakage.

### NS — Name Server

- Delegates authority for a zone to specific name servers
- **Enterprise use**: Defines who's authoritative. Published at parent zone as delegation.
- **Security**: NS enumeration identifies the DNS provider. Some providers have known vulnerabilities or misconfigurations (e.g., zone transfer enabled). Unexpected NS changes = hijacking. Monitor your own NS records for unauthorized changes.

### PTR — Pointer (Reverse DNS)

- Maps IP → hostname. Lives in `in-addr.arpa.` (IPv4) or `ip6.arpa.` (IPv6) zones
- **Security**: Mismatched or missing PTR records can trigger spam filters and alert on suspicious infrastructure. Attackers spinning up C2 infrastructure often don't bother with PTR records. PTR records on scanning IPs help attribute reconnaissance.

### SOA — Start of Authority

- One per zone. Contains: primary NS, admin email, serial number, refresh/retry/expire intervals, negative TTL
- **Security**: SOA serial numbers reveal how frequently a zone changes (useful for recon timing). MNAME field reveals the primary authoritative server. Negative TTL (NXDOMAIN TTL) affects how long negative cache entries persist.

### SRV — Service

- Encodes: service, protocol, priority, weight, port, target hostname
- Format: `_service._proto.domain TTL IN SRV priority weight port target`
- **Enterprise/AD use**: Domain controller discovery, Kerberos KDC location, LDAP server discovery — all via SRV records
- **Security**: SRV enumeration reveals internal services, ports, and architecture. In AD environments, `_ldap._tcp.dc._msdcs.domain.com` directly identifies domain controllers.

### CAA — Certification Authority Authorization

- Specifies which CAs are allowed to issue TLS certs for a domain
- **Enterprise use**: Prevents unauthorized certificate issuance even if a CA is compromised or deceived
- **Security**: Absence of CAA records = any CA can issue for your domain. Check competitor domains during recon. Monitor CT logs for certs issued outside your CAA policy.
