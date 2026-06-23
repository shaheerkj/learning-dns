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
