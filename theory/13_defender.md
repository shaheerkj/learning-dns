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

### Logging

**Windows DNS Server Logs**:

- Enable via DNS Manager → server → Debug Logging
- Or via ETW (Event Tracing for Windows) — more efficient
- Event ID 256/257: Query sent/received (ETW)
- Fields: query name, query type, source IP, response code, response data

**BIND Logs**:

```text
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
