## DNS Hierarchy

```
.                          ← Root (invisible trailing dot)
├── com.
│   ├── google.com.
│   │   ├── www.google.com.
│   │   └── mail.google.com.
│   └── microsoft.com.
├── net.
├── org.
└── uk.
    └── co.uk.
        └── bbc.co.uk.
```

**Why the hierarchy exists**:

- Distributes administrative control — no single entity controls all names
- Enables delegation — a parent zone delegates authority for a child zone by publishing NS records
- Enables scaling — each zone is managed independently
- Makes the system fault-tolerant — failure in one zone doesn't cascade globally

**Key concepts**:

|Concept|What it means|
|---|---|
|**Zone**|An administrative unit of the namespace. A zone can contain multiple subdomains unless those are delegated.|
|**Delegation**|Parent zone publishes NS records pointing to child zone's authoritative servers.|
|**Glue records**|A records for name servers that live inside the zone they serve (avoids circular dependency).|
|**Authority**|The authoritative server is the final word for a zone. If it says the record doesn't exist, it doesn't.|
|**SOA**|Start of Authority — marks the top of a zone, defines serial, refresh/retry/expire timers, and negative TTL.|
