## Active Directory & DNS

AD is fundamentally dependent on DNS. Domain controllers, Kerberos, LDAP, and site topology all use DNS for service discovery.

### SRV Records AD Uses

|Record|Resolves To|
|---|---|
|`_ldap._tcp.dc._msdcs.<domain>`|All domain controllers|
|`_kerberos._tcp.<domain>`|KDC (Kerberos Key Distribution Center)|
|`_kpasswd._tcp.<domain>`|Kerberos password change service|
|`_ldap._tcp.<site>._sites.dc._msdcs.<domain>`|DCs in a specific site|
|`_gc._tcp.<forest>`|Global Catalog servers|

### DC Discovery Flow

```
Client needs to authenticate to domain corp.local
    │
    └─→ DNS query: _ldap._tcp.dc._msdcs.corp.local SRV
          │
          └─→ Returns: priority weight port dc01.corp.local
                │
                └─→ Client contacts dc01.corp.local for LDAP/Kerberos
```

### Why DNS Failures = AD Failures

- If a client can't resolve `_ldap._tcp.dc._msdcs.domain.com`, it can't find a DC
- No DC → no Kerberos ticket → no authentication → no logon
- Group Policy can't apply (requires DC LDAP connection, which requires DNS)
- DFS namespaces fail (DFS uses DNS for referrals)
- Replication between DCs uses DNS to locate replication partners

**Operational implication**: When a user calls saying they can't log in after a network change, check DNS first. When DCs aren't replicating, check DNS. When GPO isn't applying, check DNS.

### Security Implications

- AD DNS (typically BIND or Windows DNS integrated with AD) often allows **dynamic updates** — machines register their own A/PTR records
- Insecure dynamic updates allow any domain-joined machine to overwrite DNS records → DNS poisoning from inside
- AD-integrated DNS stores zone data in AD, replicates via LDAP — compromise AD, compromise DNS
- Enumerating SRV records is one of the first things an attacker does after getting a foothold: `_ldap._tcp.dc._msdcs.domain.com` immediately identifies every DC
