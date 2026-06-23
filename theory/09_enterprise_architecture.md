## Enterprise DNS Architecture

### Typical Split-DNS Architecture

```
Internet                  DMZ                        Internal Network
────────────────────────────────────────────────────────────────────

External Users         External DNS (Authoritative)   Internal DNS (Auth + Recursive)
    │                  ┌─────────────────────┐        ┌─────────────────────────────┐
    └─→ corp.com  ───→ │ ns1.corp.com        │        │ internal-dns01.corp.local   │
                       │ ns2.corp.com        │        │ internal-dns02.corp.local   │
                       │ (Only public data)  │        │ (All internal zones)        │
                       └─────────────────────┘        └─────────────┬───────────────┘
                                                                     │
                                                          Forwarders │
                                                                     ▼
                                                            Upstream Resolver
                                                            (ISP / 8.8.8.8 / 
                                                             Security DNS)
```

### Forwarders

- Internal DNS servers forward external queries to upstream resolvers rather than recursing themselves
- **Conditional forwarders**: Forward specific domains to specific resolvers
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
