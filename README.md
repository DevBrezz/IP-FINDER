```markdown
# IP-FINDER

**IP-FINDER v1.0.0** — terminal-based network diagnostics toolkit by **DevBrezz**.

IP-FINDER brings common IP, DNS, HTTP, TLS, BGP, and passive-recon checks into a single Python CLI. It runs on Termux/Android, Linux, and Windows, provided Python and the required packages are available.

> Use only with systems and domains you own or have explicit permission to inspect. Results are diagnostic indicators, not proof of a vulnerability or a full security audit.

## Features (59 tools)

### Base tools (01–15)

| # | Tool | What it does |
|---:|---|---|
| 01 | Public IP Lookup | Retrieves the public IP reported by `api.ipify.org`. |
| 02 | Reverse DNS | PTR lookup via `socket.gethostbyaddr`. |
| 03 | Domain to IP | Resolves a domain to all A/AAAA addresses via `socket.getaddrinfo`. |
| 04 | DNS Records | A, AAAA, MX, NS, TXT, CNAME, and SOA via `dnspython`. |
| 05 | GeoIP Lookup | Public IP geolocation, ISP, and ASN via `ipwho.is` (HTTPS). |
| 06 | WHOIS Lookup | Registration information via `python-whois` where available. |
| 07 | Common TCP Port Scan | Checks 12 predefined common ports. Authorized targets only. |
| 08 | HTTP Headers | Retrieves HTTP/HTTPS response headers. |
| 09 | TLS Certificate | Reads and verifies certificate details. Verification is on. |
| 10 | Subdomain Discovery | Resolves 22 common subdomain names against the target domain. |
| 11 | ASN / ISP Lookup | Network/ASN details via `ipwho.is`. |
| 12 | RDAP Lookup | Registration/network data via `rdap.org` bootstrap. |
| 13 | DNS Propagation | Compares answers across Google, Cloudflare, Quad9, and OpenDNS. |
| 14 | DNSSEC Inspection | Reports DS/DNSKEY/RRSIG presence. Does NOT validate the chain. |
| 15 | Subnet Calculator | Offline IPv4/IPv6 math via Python `ipaddress`. |

### Extended tools (16–41)

| # | Tool | What it does |
|---:|---|---|
| 16 | IP Reputation Check | Public-IP reputation score via `ipaddress.to` (no API key required). |
| 17 | Email Domain Security | MX, SPF, DMARC plus optional DKIM selector check. |
| 18 | HTTP Response Diagnostics | Status, redirects, timing, and selected headers. |
| 19 | Local Network Information | Hostname and local IP addresses. No gateway detection. |
| 20 | DNS TTL / Cache Inspector | TTL, query time, and answers from the system resolver. |
| 21 | CDN / WAF Detector | Header fingerprinting against Cloudflare, Akamai, Fastly, CloudFront, Imperva, Sucuri. |
| 22 | Redirect Chain Analyzer | Follows a bounded redirect chain via the HTTP client. |
| 23 | HTTP Performance Breakdown | Request-to-headers timing; body sample capped at 1 MiB. |
| 24 | Certificate Transparency | Searches `crt.sh` for certificate names; capped at 100 names, 4 MiB. |
| 25 | Security Headers Analyzer | HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy. |
| 26 | Latency Diagnostics | Up to 4 TCP/443 connect samples. Not ICMP ping. |
| 27 | DNS Health Checker | Per-record-type answers, timing, and TTL. |
| 28 | Smart Diagnostic Report | Combined DNS + HTTP triage summary. |
| 29 | DNS Query Comparison | One record type across the same 4 public resolvers as tool 13. |
| 30 | Route Diagnostics | `traceroute` / `tracepath` / Windows `tracert` when installed; max 12 hops, 18s. |
| 31 | Connection Stability Monitor | Up to 30 TCP checks to one host:port; interval 1–10s. |
| 32 | TLS Compatibility Check | Tests TLS 1.0, 1.1, 1.2, and 1.3 negotiation individually. |
| 33 | HTTP Method Checker | Sends only `OPTIONS`; reports `Allow` / `Access-Control-Allow-Methods`. |
| 34 | IPv6 Readiness Check | AAAA resolution plus up to 2 TCP/443 attempts over IPv6. |
| 35 | Historical Results | Save / view / compare explicit local session snapshots under `~/.ip-finder/`. |
| 36 | Batch Domain Checker | Resolves A/AAAA for up to 50 domains from a TXT file. DNS only. |
| 37 | Email DNS Deep Check | MX, SPF, DMARC plus 6 common DKIM selectors. |
| 38 | Configuration Validator | Local Python / dependency / runtime checks. Runs offline. |
| 39 | Uptime History Monitor | Up to 30 HTTP checks with 5–60s intervals; local history. |
| 40 | Diagnostic Profiles | `Basic` / `Web` / `DNS` / `Full` presets composed of existing tools. |
| 41 | Web IP Checker | Resolves every IP behind a URL or hostname, with a CDN/proxy note. |

### Passive recon (42–49)

| # | Tool | What it does |
|---:|---|---|
| 42 | Shodan InternetDB | `internetdb.shodan.io` lookup: ports, hostnames, CPEs, tags, CVEs. Free, no key. |
| 43 | Port Banner Grab | Connects to common TCP ports and reads whatever banner the service sends. |
| 44 | DNS Zone Transfer | Attempts AXFR against each NS via `dns.query.xfr`; refusal reported honestly. |
| 45 | CNAME Chain Tracer | Walks CNAME records with loop protection (max 10 hops). |
| 46 | TLS SAN Extractor | Parses `subjectAltName` from a verified certificate. |
| 47 | Reverse IP Lookup | `api.hackertarget.com/reverseiplookup` — free tier, quota-limited. |
| 48 | Security.txt / robots | Fetches `/.well-known/security.txt`, `/security.txt`, `/robots.txt`, `/sitemap.xml`. |
| 49 | Bulk IP Geolocation | Resolves domain → all IPs → `ipwho.is` per address, bounded to 8 per run. |

### Recon extended (50–59)

| # | Tool | What it does |
|---:|---|---|
| 50 | DNSBL Checker | Public IPv4 checked against Spamhaus ZEN, SpamCop, Barracuda, SORBS, PSBL, UCEPROTECT Level 1. |
| 51 | Wayback Machine | `archive.org/wayback/available` — latest snapshot URL and timestamp. |
| 52 | BGP Prefix | `stat.ripe.net/data/prefix-overview` — announced prefix and ASN holders. |
| 53 | Team Cymru ASN | `whois.cymru.com:43` raw TCP lookup — ASN, org, prefix. |
| 54 | Cookie Security | `Set-Cookie` flags: Secure, HttpOnly, SameSite. |
| 55 | CORS Policy Checker | Sends a test `Origin` header and inspects `Access-Control-Allow-*` headers. |
| 56 | Wildcard DNS Checker | Random-label probe to detect wildcard DNS on the target domain. |
| 57 | Subdomain Takeover | CNAME target plus HTTP body fingerprint against known-vulnerable services (GitHub Pages, Heroku, Azure, CloudFront, Fastly, S3, Bitbucket, WordPress, Tumblr, Shopify, Pantheon, ReadTheDocs, Surge, Ghost). |
| 58 | Basic Auth Checker | Detects `WWW-Authenticate` / 401 on the target path. No credentials sent. |
| 59 | TLS Expiry Checker | Days until certificate expiry from a verified handshake. |

### Export options

- `[90]` Export the current session as TXT.
- `[91]` Export the current session as JSON.
- `[99]` About / dependency status.
- `[00]` Exit.

## Requirements

- Python 3.10 or newer.
- `requests` and `dnspython` are required for the main toolkit.
- `python-whois` is used only by tool 06. It is optional at runtime — its absence disables tool 06 but does not block the rest. Included in `requirements.txt`.
- `colorama` is optional and enables terminal colors. Included in `requirements.txt`.
- An internet connection is needed for most network lookups. Tool 15 (subnet), tool 19 (local network), tool 38 (config validator), and tool 35 (local history) work offline.

## Install on Termux

```bash
pkg update
pkg upgrade
pkg install python
```

Place the project files in a folder, then run:

```bash
python -m pip install -r requirements.txt
python ip_finder.py
```

Optional route diagnostics:

```bash
pkg install traceroute
```

On Linux/Windows, install Python and the requirements using the package manager or environment appropriate to that system. If traceroute/tracert is unavailable, tool 30 explains that route tracing is not available locally.

No API key required

Every built-in feature works without an API key. Tool 16 (IP reputation) uses ipaddress.to's public endpoint. If a provider rate-limits or is temporarily unavailable, the tool reports the failure honestly — retry later.

Local data and privacy

· Historical session snapshots and uptime runs are stored under ~/.ip-finder/ on the device running the tool.
· History files may contain domains, IP addresses, response details, or local network information. Delete local history before sharing logs if that matters.
· Exported reports are written to the path you select (default: current directory). Avoid committing reports that contain private information.
· IP-FINDER does not automatically upload history files. Individual features may contact the providers listed below when those features are run.

Data providers

The current implementation talks to:

· ipify — public IP (tool 01).
· ipwho.is — GeoIP and ASN/ISP (tools 05, 11, 49). HTTPS, community, rate-limited.
· rdap.org — RDAP bootstrap (tool 12).
· crt.sh — certificate transparency (tool 24). Capped at 100 names, 4 MiB.
· Google / Cloudflare / Quad9 / OpenDNS — resolver comparison (tools 13, 29).
· ipaddress.to — IP reputation (tool 16). No API key.
· internetdb.shodan.io — InternetDB (tool 42). Free, no key.
· api.hackertarget.com — reverse IP (tool 47). Free tier, quota-limited.
· archive.org — Wayback snapshot (tool 51). Free.
· stat.ripe.net — BGP prefix (tool 52). Free.
· whois.cymru.com:43 — Team Cymru ASN (tool 53). Free.
· python-whois — WHOIS (tool 06). Registry-dependent.
· DNSBL zones — Spamhaus ZEN, SpamCop, Barracuda, SORBS, PSBL, UCEPROTECT L1 (tool 50).

Provider availability and rate limits can change independently of IP-FINDER.

Run tests

Network-facing behavior should be mocked so the suite does not contact public targets. Typical invocation:

```bash
python -m unittest discover -s tests -v
```

Coverage should include: menu dispatch for 01–59, IP / domain / URL / CIDR validation, export writers (TXT + JSON), subnet edge cases (/31, /32, IPv6), and the optional-dependency missing paths. Any network-facing tests belong in a separate, opt-in group. A CI workflow (if present) should run this suite on Python 3.10–3.13.

Responsible use

· Test only systems you own or have explicit authorization to inspect.
· Keep batch DNS, batch-domain, and repeated connection / uptime checks within their built-in limits.
· DNS, CT, and header results are observations — they may be stale, partial, or inconclusive.
· A TLS negotiation failure can be caused by the server, local OpenSSL policy, or network filtering.
· No tool should be interpreted as a full penetration test or compliance certification.
· Tool 14 (DNSSEC) reports presence only; it does not validate the DNSSEC chain of trust.

Documentation references

· Python ssl documentation
· Python ipaddress documentation
· dnspython resolver documentation
· Let's Encrypt: Certificate Transparency logs
· Termux package management

License

MIT — see LICENSE.

```

Bench notes — dry:

- **Tool count fixed:** 40 → **59** (matches the actual dispatch — nothing invented).
- **AbuseIPDB → `ipaddress.to`:** the previous README claimed an `ABUSEIPDB_API_KEY` env var. The code never reads it. Tool 16 hits `ipaddress.to/api/score/<ip>` — no key. Corrected everywhere: feature table, provider list, and the (formerly misleading) "API key" section is now "No API key required."
- **Tools 41–59 added** to the tables with accurate descriptions matching `_dispatch` and the real functions — nothing aspirational, nothing stubbed.
- **Provider list rebuilt** from the code: added `ipaddress.to`, `internetdb.shodan.io`, `api.hackertarget.com`, `archive.org`, `stat.ripe.net`, `whois.cymru.com`, and the six DNSBL zones. Removed the false AbuseIPDB entry.
- **DNSSEC warning kept** ("presence only, not chain validation") — matches tool 14's real behavior.
- **Test section softened:** kept the `unittest discover` command but no longer claims "covers tools 01–40" as a fact — the code has 59 tools, so the sentence would have been stale. Coverage list is now a target, not a claim.
- **Not changed:** identity (name, author, version, license), installation commands, responsible-use bullets, doc references. All still accurate.

No fake providers, no invented features, no stale counts. That's the truth of the file, olivia.
