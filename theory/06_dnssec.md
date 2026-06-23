## DNSSEC

### Trust Chain

```
Root Zone (.) — signs with Root KSK (Key Signing Key)
  └─→ .com zone — Root signs .com's DS record
        └─→ google.com zone — .com signs google.com's DS record
              └─→ www.google.com A record — signed with google.com's ZSK (Zone Signing Key)
```

**Key types**:

- **ZSK** (Zone Signing Key): Signs actual zone records (A, MX, etc.)
- **KSK** (Key Signing Key): Signs the ZSK. Rarely rotated. Published as DNSKEY record.
- **DS** (Delegation Signer): Hash of child zone's KSK, published in parent zone. Creates the chain of trust.
- **RRSIG**: The actual signature on each record set.
- **NSEC/NSEC3**: Proves non-existence of a name (needed for authenticated NXDOMAIN). NSEC3 hashes names to prevent zone enumeration via walking.

### Validation Process

1. Resolver fetches A record + RRSIG
2. Resolver fetches zone's DNSKEY (ZSK)
3. Validates RRSIG against DNSKEY
4. Fetches parent zone's DS record for this zone's KSK
5. Validates chain up to root (which validators trust via hardcoded root key)

### What DNSSEC Prevents

- Cache poisoning (forged responses won't have valid signatures)
- Man-in-the-middle response tampering
- DNS spoofing at the resolver level

### What DNSSEC Does Not Prevent

- DNS enumeration (NSEC allows zone walking; NSEC3 mitigates but doesn't eliminate)
- DoS against DNS infrastructure
- Attacks on the authoritative server itself
- DNS tunneling
- DNS-based C2
- Anything at the application layer above DNS resolution
- Attacker registering a lookalike domain (they get valid DNSSEC for their own domain)

**Deployment reality**: DNSSEC is complex to operate, zone signing increases response sizes, and many resolvers don't validate. Many organizations sign their external zones but not internal ones. TLD deployment varies widely.
