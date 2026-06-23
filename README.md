# DNS Lab

Small DNS lab for testing BIND behavior, zone files, and DNS concepts.

## Layout

- `bind/` - BIND config and zone data
- `theory/` - DNS notes split into focused topics
- `docker-compose.yml` - Lab containers and network

## Run

```bash
docker compose up -d
```

The `ns1` container exposes BIND on host port `5353` for both UDP and TCP.

## Notes

- The lab network uses `10.10.0.0/24`
- `ns1` is the DNS server at `10.10.0.10`
- `theory/main.md` is an index into the topic files in `theory/`