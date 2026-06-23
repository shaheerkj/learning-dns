## BIND / named.conf Note

If another server is authoritative for `lab.local`, this local BIND instance should not use `type master` for that zone. Common alternatives are:

### Slave / Secondary

```conf
zone "lab.local" {
    type slave;
    file "/var/cache/bind/slaves/lab.local.db";
    masters { 10.10.0.20; };
};
```

Use this when the other server is the master and this server should keep an automatic copy of the zone.

### Stub

```conf
zone "lab.local" {
    type stub;
    file "/var/cache/bind/stub/lab.local.db";
    masters { 10.10.0.20; };
};
```

Use this when you only want NS delegation data for the zone.

### Forward

```conf
zone "lab.local" {
    type forward;
    forwarders { 10.10.0.20; };
    forward only;
};
```

Use this when you want all lookups for the zone to go directly to the authoritative server.

### No zone stanza

If this server should only resolve `lab.local` recursively and not host special handling for it, remove the `zone "lab.local"` block entirely.

### Security note

Avoid open recursion and open transfers outside lab environments. Prefer restricting `allow-recursion` and `allow-transfer` to trusted IPs.
