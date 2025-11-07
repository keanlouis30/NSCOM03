# Comparative Evaluation and Weighting of Threat Intelligence and Network Analysis APIs for IOC Analysis

Date: 2025-10-10
Project: IOC Analyzer (Flask + JS)

Abstract
This document presents a research-style evaluation of the threat intelligence and network analysis APIs configured in the IOC Analyzer. It defines a rubric for “usefulness” rooted in three families of network-centric evidence: Network Connectivity, Domains, and Traffic/Behavior. We derive 0–100 “weights” per API reflecting the breadth and depth of data coverage relevant to connectivity, domains, and traffic. We also analyze overlap and complementarity among APIs, discuss operational factors (rate limits, coverage stability), and propose a reproducible methodology for empirical validation.

1. System Context and API Inventory

1.1 Architecture Overview
- Standard analysis (app.py):
  - Primary engine: VirusTotal (VT) across IP, domain, and hash, including relational intelligence (resolutions, communicating files, contacted IPs/domains/URLs) up to 100 items per endpoint.
  - Complementary: AbuseIPDB for IP abuse reputation.
- Deep analysis (deep_analysis.py):
  - IPinfo.io for geolocation/ASN/ISP.
  - SecurityTrails for historical DNS and subdomains.
  - IPQualityScore for IP fraud/reputation.
  - Local/resolver-based DNS, WHOIS (python-whois), SSL inspection, subnet and neighbor sampling.
  - API keys present but not currently called in code paths: URLScan.io, WhoisXML API (whoisxml).

1.2 Configured APIs (from .env)
Primary threat intelligence:
- VirusTotal (3 keys), AbuseIPDB (2), AlienVault OTX (2)
Deep analysis:
- IPinfo.io, SecurityTrails, IPQualityScore, URLScan.io, WhoisXML API
Note: OTX, URLScan.io, and WhoisXML are configured but not currently invoked in code (as of the inspected files). WHOIS data is sourced via python-whois, not the WhoisXML API.

1.3 “Most Used” in Current Implementation
- Highest usage: VirusTotal (central to standard analysis for IP/domain/hash plus relations)
- IP reputation supplement: AbuseIPDB
- Deep analysis usage: IPinfo.io, SecurityTrails, IPQualityScore
- Configured but not used (opportunity): AlienVault OTX, URLScan.io, WhoisXML API

2. Evaluation Framework

2.1 Definition of “Useful”
Usefulness focuses on data that informs: (A) Network Connectivity, (B) Domains, and (C) Traffic/Behavior. The goal is to maximize actionable network intelligence rather than generic metadata.

2.2 Category Weights and Sub-Criteria
Overall score S in [0, 100] is computed as:
S = 100 × (0.40 × C + 0.35 × D + 0.25 × T)
where:
- C: Connectivity coverage (0–1)
  - C1 Geolocation granularity (city, region, country, timezone, coordinates)
  - C2 ASN/ISP/infrastructure (ASN, org, routing block, network owner)
  - C3 DNS infrastructure (reverse DNS, A/AAAA, MX, NS, TXT, CNAME, SOA, CAA)
  - C4 Network exposure (ports, SSL/TLS certs, banners, SANs)
- D: Domain coverage (0–1)
  - D1 WHOIS richness (registrar, creation/expiration, registrant, status)
  - D2 Subdomain discovery and nameserver analysis
  - D3 Domain-IP relationships (current + historical)
- T: Traffic/Behavior coverage (0–1)
  - T1 URL associations and web content/technology
  - T2 Network behavior (malware contacted IPs/domains/URLs)
  - T3 Reputation/abuse context (fraud, abuse velocity, risk scores)

Scoring is based on (a) code-level capabilities integrated in the app, and (b) well-known, typical output for each API. When an API is configured but not integrated, we estimate coverage based on its documented capabilities and role, marking it as “not yet leveraged” operationally.

2.3 Overlap and Complementarity
We consider two overlap types:
- Field-level overlap: APIs deliver the same evidence class (e.g., ASN, registrar, subdomains, resolutions). We measure conceptual overlap across feature classes; empirical overlap can be quantified with Jaccard similarity when analyzing a corpus of IOCs.
- Entity-level overlap: APIs return intersecting related entities (e.g., common IPs/domains/URLs). For research-quality validation, compute overlap across exported datasets after normalizing entities.

2.4 Operational Considerations (not directly in the score but noted)
- Rate limits and quotas; key rotation strategies
- Latency/success rate; robustness for high-volume workflows
- Historical depth and update cadence

3. Results: Weights and Justifications

3.1 VirusTotal — Score: 95/100
- Connectivity (≈0.95 × 40 = 38): IP attributes include country, network, AS owner; resolutions link IPs↔domains; not a dedicated geolocation provider but strong infrastructure context. Rich SSL/ports are not sourced from VT directly (in this app), but VT contributes network ownership and behavioral context that augments connectivity.
- Domains (≈1.00 × 35 = 35): WHOIS dates, registrar, subdomains (up to 100), resolutions, domain URLs, exhaustive relations across entities. Deep domain-IP relationship graph.
- Traffic (≈0.88 × 25 = 22): Communicating files, downloaded files, contacted IPs/domains/URLs (up to 100 each) provide unparalleled network behavior context.
- Overlap: Shares geolocation/infrastructure hints with IPinfo (less granular), overlaps DNS relations with SecurityTrails (VT more behavior/relations; ST more historical DNS). Complements AbuseIPDB/IPQualityScore (VT has multi-engine analysis; they provide focused reputation signals).
- Operational: 3 keys enable rotation against strict rate limits. Central pillar of standard analysis.

3.2 IPinfo.io — Score: 88/100
- Connectivity (≈0.93 × 40 = 37): Best-in-class geolocation (coordinates, timezone, postal), ASN/ISP, and carrier context.
- Domains (≈0.43 × 35 = 15): Limited domain perspective; strength is IP-centric.
- Traffic (≈0.44 × 25 = 11): Not a threat-intel engine; contributes hosting and infrastructure context useful for traffic interpretation but not behavior.
- Overlap: Geolocation and ASN overlap with VT/AbuseIPDB; IPinfo generally higher fidelity. Strongly complementary to VT’s behavior graph.

3.3 SecurityTrails — Score: 85/100
- Connectivity (≈0.75 × 40 = 30): DNS infrastructure views and historical A records enhance network context.
- Domains (≈0.91 × 35 = 32): Subdomain discovery (up to 50 here), nameserver intel, DNS history, domain-IP timelines.
- Traffic (≈0.32 × 25 = 8): Limited explicit traffic behavior; shines on historical DNS relationships.
- Overlap: Significant domain/IP resolution overlap with VT, but SecurityTrails contributes deeper temporal history; complementary in time dimension.

3.4 WhoisXML API — Score: 82/100
- Connectivity (≈0.63 × 40 = 25): Indirect contribution via network registration/administrative metadata; not operationally integrated yet in code (python-whois used instead).
- Domains (≈0.86 × 35 = 30): Authoritative WHOIS, registrar, registration history, cross-TLD coverage.
- Traffic (≈0.20 × 25 = 5): Registration lifecycle signals, but no behavioral traffic.
- Overlap: Overlaps with VT’s WHOIS fields; provides more authoritative coverage and historical continuity. Strong replacement/augmentation for python-whois.

3.5 URLScan.io — Score: 78/100
- Connectivity (≈0.63 × 40 = 25): Web infrastructure footprints (headers, servers, hosting) derived from crawls.
- Domains (≈0.57 × 35 = 20): Technology detection and domain/URL relationships.
- Traffic (≈0.72 × 25 = 18): Dynamic URL behavior (requests graph, DOM, screenshots) adds real traffic-like evidence.
- Status: Configured but not integrated in current code; potential high-value source for URL and web behavior.

3.6 IPQualityScore — Score: 76/100
- Connectivity (≈0.75 × 40 = 30): IP risk profile with proxy/VPN/TOR signals contributes to exposure context.
- Domains (≈0.29 × 35 = 10): Limited domain semantics.
- Traffic (≈0.72 × 25 = 18): Fraud score, bot/crawler, recent abuse velocity—behavioral risk indicators.
- Overlap: Complements AbuseIPDB; different models and features.

3.7 AbuseIPDB — Score: 75/100
- Connectivity (≈0.80 × 40 = 32): IP country/ISP context, public/whitelist flags.
- Domains (≈0.00 × 35 = 0): IP-focused.
- Traffic (≈0.72 × 25 = 18): Abuse reports, last-seen, volume—behavioral proxies.
- Overlap: Shares reputation space with IPQualityScore; complementary community-driven perspective.

3.8 AlienVault OTX — Score: 70/100
- Connectivity (≈0.70 × 40 = 28): IOC relationships provide indirect connectivity context.
- Domains (≈0.71 × 35 = 25): Community-curated domain signals.
- Traffic (≈0.68 × 25 = 17): Threat context via pulses and indicator relationships.
- Status: Configured but not currently used in code; estimated potential once integrated.

4. Overlap Analysis and Complementarity Map

4.1 Field-Level Overlap (Conceptual)
- Geolocation/ASN/ISP: IPinfo, VirusTotal (basic), AbuseIPDB (basic) → Choose IPinfo as authoritative; use others as corroboration.
- DNS relationships (resolutions/subdomains): VirusTotal, SecurityTrails → VT excels in current relations and behavior; ST excels in historical timelines and breadth of subdomains.
- WHOIS/Registration: WhoisXML, VirusTotal (selected fields), python-whois → Use WhoisXML for authority and change history.
- Behavior/Traffic: VirusTotal (files, URLs, network behavior), URLScan (web request graphs), IPQualityScore/AbuseIPDB (reputation/abuse) → Complementary flavors of “traffic” evidence.

4.2 Entity-Level Overlap (Empirical Procedure)
For a corpus of IOCs, compute Jaccard overlap for normalized sets:
- Domains seen per IP (VT vs ST)
- IPs contacted per hash (VT)
- URLs per domain (VT vs URLScan)
- Abuse reports vs fraud-reputation flags (AbuseIPDB vs IPQualityScore)
High overlap indicates redundancy; low overlap indicates complementary intelligence.

5. Operational Notes
- Rate Limits: VT (strict), IPinfo generous, SecurityTrails low quota, IPQualityScore moderate, URLScan permissive with rate-limits, AbuseIPDB daily caps, OTX unlimited.
- Key Rotation: Implemented for VT, AbuseIPDB, OTX in app.py; improves throughput and resilience.
- Latency/Success: VT endpoints and ST history can be slower; plan for caching or backoff.

6. Recommendations

6.1 Integration Priorities
- Maintain VT as core (95) for graph/behavioral intelligence.
- Treat IPinfo as authoritative geo/ASN/ISP (88); don’t overfit on alternate geo sources.
- Use SecurityTrails for historical DNS and subdomain expansion (85) where temporal context matters.
- Replace or augment python-whois with WhoisXML (82) for authoritative WHOIS and history.
- Integrate URLScan (78) to enrich URL/domain behavior and observed request graphs.
- Combine AbuseIPDB (75) and IPQualityScore (76) for a robust reputation composite.

6.2 Data Fusion Strategy
- Evidence tiers: Authoritative (WhoisXML, IPinfo), Behavioral (VirusTotal, URLScan), Community/Reputation (AbuseIPDB, IPQualityScore), Historical (SecurityTrails).
- Conflict resolution: Prefer authoritative sources for static attributes (WHOIS, geo, ASN). Aggregate behavior across VT/URLScan, weigh recency and frequency.
- Normalization: Maintain canonical schemas for IP, domain, URL, file, certificate, and port entities. Deduplicate by case-insensitive exact match and normalized forms (punycode for domains; lowercased hex for hashes; URL canonicalization).

6.3 Proposed Scoring Config for App
Define per-API usefulness weights to guide downstream decisions or fused scoring:
- VirusTotal: 95
- IPinfo: 88
- SecurityTrails: 85
- WhoisXML: 82
- URLScan: 78
- IPQualityScore: 76
- AbuseIPDB: 75
- AlienVault OTX: 70
Rationale: Reflects breadth/depth of connectivity, domain, and traffic data as integrated (or ready to integrate) in the current system.

7. Reproducible Measurement Plan

7.1 Dataset Collection
- Use the app to export JSON for a stratified set of IOCs: {IPs, domains, URLs, hashes, CIDRs}; target N≥200 mixed indicators representative of real workloads.

7.2 Metrics
- Coverage rates: proportion of IOCs for which each API returns non-empty values for target fields per category.
- Uniqueness: fraction of entities contributed that are not present in any other API’s outputs (normalized exact-match).
- Overlap: Jaccard indices across entity sets per API and category.
- Stability: success rate and timeouts per API.

7.3 Scoring Computation
- Compute C, D, T as weighted coverage of sub-criteria; incorporate uniqueness as a bonus term (+ up to 5 points) and high redundancy as a minor penalty (− up to 3 points) to refine final scores.

7.4 Pseudocode Outline
```python path=null start=null
# Load exported JSON results (per IOC) and compute metrics
# Note: This is illustrative pseudocode; adapt to project’s export schema
from collections import defaultdict

apis = ["virustotal", "abuseipdb", "ipinfo", "securitytrails", "ipqualityscore", "urlscan", "whoisxml"]
corpus = load_exports("exports/")  # list of IOC result dicts

coverage = defaultdict(lambda: defaultdict(int))  # api -> subcriterion -> count
entities = defaultdict(lambda: defaultdict(set))  # api -> entity_type -> set

for record in corpus:
    for api in apis:
        data = record.get(api, {})
        # Example subcriteria checks (implement per export schema)
        if has_geolocation(data): coverage[api]["C1"] += 1
        if has_asn(data): coverage[api]["C2"] += 1
        if has_dns_records(data): coverage[api]["C3"] += 1
        if has_ssl_ports(data): coverage[api]["C4"] += 1
        if has_whois(data): coverage[api]["D1"] += 1
        if has_subdomains(data): coverage[api]["D2"] += 1
        if has_domain_ip_history(data): coverage[api]["D3"] += 1
        if has_url_behavior(data): coverage[api]["T1"] += 1
        if has_network_behavior(data): coverage[api]["T2"] += 1
        if has_reputation(data): coverage[api]["T3"] += 1

        # Entity-level sets for overlap/uniqueness
        entities[api]["ips"].update(extract_ips(data))
        entities[api]["domains"].update(extract_domains(data))
        entities[api]["urls"].update(extract_urls(data))

# Normalize by corpus size and compute C, D, T, and S
# Then compute Jaccard overlaps across entities[api][*]
```

8. Limitations and Ethical Considerations
- Free-tier limits may bias empirical coverage; validate against paid tiers where feasible.
- Community-sourced data (OTX, AbuseIPDB) can contain noise; apply verification/weighting.
- Respect API terms of service and privacy constraints; avoid storing PII beyond legitimate security needs.

9. Conclusion
VirusTotal serves as the backbone for behavioral and relational intelligence; IPinfo provides authoritative network context; SecurityTrails contributes historical DNS and subdomain coverage; WhoisXML strengthens registration truth; URLScan adds dynamic web behavior; IPQualityScore and AbuseIPDB jointly enhance reputation and abuse context. The proposed weights (95, 88, 85, 82, 78, 76, 75, 70) reflect current and near-term utility for network connectivity, domains, and traffic analysis within this system. Integrating currently unused but configured APIs (OTX, URLScan, WhoisXML) can further maximize breadth and reduce blind spots.

