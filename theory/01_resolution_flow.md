## Resolution Flow

### Components

| Component                | Role                                                                                                     |
| ------------------------ | -------------------------------------------------------------------------------------------------------- |
| **Stub Resolver**        | Client-side resolver (OS). Sends queries, doesn't recurse. Caches locally.                               |
| **Recursive Resolver**   | Does the actual work. Walks the hierarchy on behalf of the stub. Usually your ISP, corp DNS, or 8.8.8.8. |
| **Root Servers**         | 13 logical root server clusters (a–m.root-servers.net). Know where all TLD servers are.                  |
| **TLD Servers**          | Authoritative for `.com`, `.net`, `.org`, etc. Know who's authoritative for each second-level domain.    |
| **Authoritative Server** | Holds the actual zone data. Returns the final answer.                                                    |

### Resolution Walk: `google.com`

```
Browser
  │
  ▼
Stub Resolver (OS)
  │  Cache miss → query recursive resolver
  ▼
Recursive Resolver (e.g., 8.8.8.8)
  │
  ├─→ Root Server (.) 
  │     don't have it, forward to TLD
  │
  ├─→ .com TLD Server
  │     "I don't know google.com, but it's delegated to ns1.google.com / ns2.google.com"
  │
  ├─→ Authoritative Server (ns1.google.com)
  │     "google.com A 142.250.x.x, TTL 300"
  │
  └─→ Returns answer to Stub Resolver
        │
        └─→ Browser opens TCP connection to 142.250.x.x
```

**Key behaviors**:

- Each step is a separate UDP query with its own timeout and retry
- Recursive resolver caches each intermediate answer (NS records for `.com`, NS records for `google.com`, and the final A record) separately with their individual TTLs
- The stub resolver caches the final answer
- The browser has its own DNS cache on top of the OS
- If any intermediate server is unreachable, the recursive resolver tries other NS records for that zone
