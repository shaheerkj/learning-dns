## Cloud DNS

### AWS Route 53

**Architecture**:

- Hosted zones: Public (internet-resolvable) or Private (VPC-only)
- Private hosted zones: Associated with one or more VPCs. Only instances in those VPCs can resolve.
- Resolver: VPC default resolver at `VPC_CIDR_base + 2` (e.g., `10.0.0.2`)
- Route 53 Resolver: Manages inbound/outbound DNS resolution across VPC boundaries and on-premises

**Routing policies**:

- Simple, Weighted, Latency, Failover, Geolocation, Geoproximity, Multivalue
- Health checks integrated — Route 53 can remove unhealthy records from responses

**Security**:

- Route 53 Resolver Query Logging → CloudWatch Logs or S3 → critical for detection
- DNSSEC signing supported for public hosted zones
- Private hosted zones are invisible to external resolvers — but don't put secrets in DNS names
- Resolver DNS Firewall: Block/allow domains at the VPC resolver level (similar to RPZ)
- Watch for: overly permissive Resolver inbound endpoints, misconfigured private zone associations exposing internal naming to unintended VPCs

### Azure DNS

**Architecture**:

- Public DNS zones: Hosted in Azure, globally distributed authoritative
- Private DNS zones: Resolved only by VNets linked to the zone
- Azure-provided DNS: `168.63.129.16` — the magic Azure resolver available to all VMs. Resolves private zones linked to the VNet.
- Azure DNS Private Resolver: For hybrid architectures, routes DNS between on-prem and Azure

**Security**:

- DNS Analytics: Azure Monitor workbook for DNS query logging and anomaly detection
- Private DNS zones + VNet links: Controls which VNets can resolve internal zones
- Watch for: public DNS zones with internal naming conventions exposed accidentally, private resolver endpoints exposed without NSG controls
- Azure Firewall DNS Proxy: Forces DNS through Azure Firewall for logging and filtering
- Diagnostic logs for DNS Private Resolver → Log Analytics → queryable for threat hunting
