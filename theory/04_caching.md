## DNS Caching

### Cache Layers

```
Browser cache (Chrome: chrome://net-internals/#dns)
    └─→ OS cache (nscd, dnsmasq, Windows DNS Client service)
          └─→ Recursive resolver cache (your DNS server)
                └─→ Authoritative server (no cache — it's the source)
```

### TTL (Time-to-Live)

Seconds a DNS record stays cached before the resolver re-queries. Set per-record by the zone owner.

| TTL                | Trade-off                          |
| ------------------ | ---------------------------------- |
| Low (60–300s)      | Fast propagation, more query load  |
| High (3600–86400s) | Better performance, slow to change |
| Negative (SOA)     | How long NXDOMAIN is cached        |

### Security implications

**Poisoning window** — longer TTL = poisoned record stays cached longer = more victims hit

Attacker poisons `bank.com A → 1.2.3.4` on a resolver with TTL 86400. Every user hitting that resolver for the next 24 hours gets sent to the attacker's server — even if the real `bank.com` zone is completely clean.

**Fast flux** — malware/botnets set TTL to 0–60s so IPs rotate faster than blocklists can update

A botnet C2 domain `c2.evil.com` has TTL 30s and cycles through 500 IPs across compromised hosts. A threat feed flags `1.2.3.4` — by the time the block is pushed to firewalls, the domain already resolves to `5.6.7.8`. The domain stays alive, the block is useless.

**Stale cache** — even after you fix a DNS record, old cached IPs keep routing traffic to the bad destination until TTL expires

Your company's `login.corp.com` got hijacked and pointed at a phishing server. You regain control and update the record immediately. But every ISP resolver that cached it with TTL 3600 still serves the old IP for up to another hour. Users on those resolvers keep hitting the phishing page despite the fix being live.

**Negative cache DoS** — inject a fake NXDOMAIN and the resolver stops querying that domain for the entire negative TTL duration

Attacker poisons a resolver into believing `api.target.com` doesn't exist (NXDOMAIN). The SOA negative TTL is 3600. For the next hour, every client behind that resolver gets `NXDOMAIN` for `api.target.com` — no retries, no fallback — the domain is effectively unreachable from their perspective without touching the target's infrastructure at all

### Kaminsky Attack (2008)

DNS resolvers accept the first valid-looking response they receive. An attacker triggers DNS queries for random subdomains (e.g., `abc.bank.com`) and floods the resolver with forged DNS replies. If a forged reply correctly guesses the transaction ID and source port before the legitimate response arrives, the resolver caches malicious data.

The attack targets **NS records** rather than individual A records, allowing the attacker to redirect **all subdomains** of a domain to a malicious nameserver.

**Mitigations:**

- Source port randomization
- DNSSEC (cryptographic validation of DNS records)
- 0x20 encoding (randomized letter casing in queries)

**Impact:** Enables redirection of users to attacker-controlled websites, facilitating phishing, malware delivery, and man-in-the-middle attacks.
