## DNS Transport

### UDP/53 — Default

- Used for standard queries and responses
- Max payload: 512 bytes (original spec), 4096 bytes with EDNS0 extension
- Connectionless — no handshake, no verification of source IP
- Why UDP: Low overhead, low latency, DNS query-response fits in a single packet for most records
- **Security implication**: Source IP is trivially spoofable. This is the foundation of amplification/reflection attacks and cache poisoning.

### TCP/53 — Fallback and transfers

Used when:

- Response exceeds UDP size limit (truncation flag `TC=1` triggers TCP retry)
- Zone transfers (AXFR/IXFR) — always TCP
- Some DNSSEC responses (large RRSIG payloads)
- DNS-over-TCP for reliability

**Security implication**: TCP/53 outbound that isn't just retries or zone transfers is anomalous. DNS tunneling tools sometimes use TCP/53 for higher bandwidth.

### AXFR — Full Zone Transfer

- Transfers entire zone from primary to secondary NS
- Used for zone replication between authoritative servers
- **Should only be allowed between authorized NS pairs**
- **One of the most common DNS misconfigs**: open AXFR lets anyone dump your entire DNS zone — all hostnames, IPs, internal naming conventions, and infrastructure layout

```bash
dig axfr @ns1.target.com target.com
```

If this returns data, it's a critical finding.

### IXFR — Incremental Zone Transfer

- Only transfers changes since last serial number
- More efficient than AXFR for large zones
- Same security requirements as AXFR — restrict by IP

### DNS-over-HTTPS (DoH) / DNS-over-TLS (DoT)

- Encrypts DNS queries so they can't be intercepted or logged by network middleboxes
- **Defender problem**: Breaks DNS visibility in network monitoring. Attackers deliberately use DoH to bypass DNS logging. Malware increasingly uses DoH (Cloudflare 1.1.1.1, Google 8.8.8.8) to hide C2 traffic.
- **Detection**: Block known DoH resolver IPs at the perimeter and force traffic through your monitored resolver. Alert on HTTPS traffic to 1.1.1.1:443, 8.8.8.8:443 from endpoints that shouldn't be doing their own DNS.
