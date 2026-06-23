## Reverse DNS

IPv4 reverse DNS lives in `in-addr.arpa.`. The IP is reversed and `.in-addr.arpa.` is appended:

```
IP: 192.168.1.50
PTR query: 50.1.168.192.in-addr.arpa → hostname
```

IPv6 uses `ip6.arpa.` with each nibble reversed.

**Authority**: ISPs own the PTR zone for IP blocks they allocate. If you have a /24, your ISP delegates that block to you so you can set your own PTR records.

### Enterprise Use

- Reverse lookups for server identification in logs (replace IPs with hostnames)
- Email: Many MTAs reject email from IPs without PTR records, or where PTR doesn't forward-confirm (FCrDNS check)
- Network management tools, monitoring systems
- Authentication for some services (e.g., some SSH configs, Kerberos in strict mode)

### Security Use

- **Attribution**: Legitimate services typically have PTR records. C2 infrastructure often doesn't.
- **Log enrichment**: Enrich IP-based logs with hostnames for faster triage
- **Anomaly detection**: A PTR mismatch (forward and reverse don't agree) is a signal worth noting
- **OSINT**: Reverse DNS on ASN ranges reveals infrastructure ownership
