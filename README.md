# IP-FINDER

**IP-FINDER v1.0.0** — terminal-based network diagnostics toolkit by **DevBrezz**.

IP-FINDER brings common IP, DNS, HTTP, TLS and network-configuration checks into a single Python CLI. It is designed to run on Termux/Android, Linux and Windows, provided that Python and the required packages are available.

> Use only with systems and domains you own or have explicit permission to inspect. Results are diagnostic indicators, not proof of a vulnerability or a full security audit.

## Features (40 tools)

| # | Tool | What it does |
|---:|---|---|
| 01 | Public IP Lookup | Retrieves the public IP reported by the existing IP service. |
| 02 | Reverse DNS | Queries the PTR name for an IP address. |
| 03 | Domain to IP | Resolves a domain to IP addresses. |
| 04 | DNS Records | Looks up common DNS record types. |
| 05 | GeoIP Lookup | Shows public IP geolocation data from the existing provider. |
| 06 | WHOIS Lookup | Retrieves registration information where available. |
| 07 | Common TCP Port Scan | Checks the app's predefined common ports for a user-specified target. Use only on authorized systems. |
| 08 | HTTP Headers | Retrieves HTTP response headers. |
| 09 | TLS Certificate | Reads certificate details using certificate verification. |
| 10 | Subdomain Discovery | Resolves a small built-in list of common subdomain names. |
| 11 | ASN / ISP Lookup | Looks up network/ASN details from the existing provider. |
| 12 | RDAP Lookup | Retrieves registration/network data using RDAP. |
| 13 | DNS Propagation | Compares DNS answers across the existing Google, Cloudflare, Quad9 and OpenDNS resolver list. |
| 14 | DNSSEC Inspection | Inspects DS, DNSKEY and RRSIG record presence; it does not fully validate the DNSSEC chain. |
| 15 | Subnet Calculator | Calculates IPv4/IPv6 subnet information locally. |
| 16 | IP Reputation Check | Optional AbuseIPDB lookup when `ABUSEIPDB_API_KEY` is configured. |
| 17 | Email Domain Security | Checks common email-domain DNS signals, with an optional DKIM selector. |
| 18 | HTTP Response Diagnostics | Reports response status, redirects, timing and selected headers. |
| 19 | Local Network Information | Reports basic network information about the local device. |
| 20 | DNS TTL / Cache Inspector | Shows TTL and answer information returned by the configured resolver. |
| 21 | CDN / WAF Detector | Identifies possible CDN/WAF indicators in HTTP headers. |
| 22 | Redirect Chain Analyzer | Follows and reports a bounded HTTP redirect chain. |
| 23 | HTTP Performance Breakdown | Measures request-to-headers time and reads at most 1 MiB of response content. |
| 24 | Certificate Transparency | Searches public CT certificate names through the existing `crt.sh` integration. |
| 25 | Security Headers Analyzer | Checks common HTTP security headers. |
| 26 | Latency Diagnostics | Measures a small number of TCP/443 connection attempts. It is not ICMP ping. |
| 27 | DNS Health Checker | Reports answers, timing and TTL for common DNS records. |
| 28 | Smart Diagnostic Report | Combines a small DNS/HTTP diagnostic summary. |
| 29 | DNS Query Comparison | Compares one record type across the same public resolver list already used by tool 13. |
| 30 | Route Diagnostics | Runs `traceroute`, `tracepath` or Windows `tracert` when installed; maximum 12 hops and 18 seconds. |
| 31 | Connection Stability Monitor | Makes at most 30 TCP connection checks to one host and port. |
| 32 | TLS Compatibility Check | Attempts separate TLS 1.0, 1.1, 1.2 and 1.3 handshakes where the local SSL library supports them. |
| 33 | HTTP Method Checker | Sends only `OPTIONS` and reports `Allow`/CORS method headers; it does not try state-changing methods. |
| 34 | IPv6 Readiness Check | Checks IPv6 resolution and makes up to two TCP/443 connection attempts. |
| 35 | Historical Results | Saves, views and compares explicit local session snapshots. |
| 36 | Batch Domain Checker | Resolves A/AAAA records for up to 50 domains from a TXT file; DNS only, no port or HTTP checks. |
| 37 | Email DNS Deep Check | Checks MX, SPF, DMARC and six common DKIM selectors. A missing common selector does not prove DKIM is absent. |
| 38 | Configuration Validator | Checks the local Python/dependency configuration and local history-directory write access. |
| 39 | Uptime History Monitor | Runs up to 30 HTTP checks with an interval of at least 5 seconds and records results locally. |
| 40 | Diagnostic Profiles | Runs a `Basic`, `Web`, `DNS` or `Full` preset using existing diagnostics. |

### Export options

- `[90]` Export the current session as TXT.
- `[91]` Export the current session as JSON.

## Requirements

- Python 3.10 or newer.
- `requests` and `dnspython` are required for the main toolkit.
- `python-whois` is used by option `06`; it is optional at runtime, so its absence does not prevent the other tools from starting. It is included in `requirements.txt`.
- `colorama` is optional and enables terminal colors (also included in `requirements.txt`).
- An internet connection is needed for most network lookups. Local subnet calculations and configuration checks do not require an external service.

## Install on Termux

```bash
pkg update
pkg upgrade
pkg install python
```

Put the project files in a folder, then run:

```bash
python -m pip install -r requirements.txt
python ip_finder.py
```

If you want route diagnostics, install the Termux traceroute package where it is available:

```bash
pkg install traceroute
```

On Linux/Windows, install Python and the requirements using the package manager/environment appropriate to that system. If `traceroute` is unavailable, option 30 will explain that route tracing is not available locally.

## API key (optional)

Tool 16 uses AbuseIPDB only when `ABUSEIPDB_API_KEY` is set. Without that environment variable, the tool reports that the lookup was skipped; it does not invent a reputation score.

Termux example for the current shell:

```bash
export ABUSEIPDB_API_KEY="YOUR_KEY_HERE"
python ip_finder.py
```

Do not commit API keys to GitHub, paste them into issue reports, or hard-code them into the source.

## Local data and privacy

- Historical session snapshots and uptime runs are stored under `~/.ip-finder/` on the device that runs the tool.
- History files may contain domains, IP addresses, response details, or local network information. Review or delete the local files if needed before sharing logs.
- Exported reports are written to the path you select (the default is the current directory). Avoid committing reports that contain private information.
- IP-FINDER does not automatically upload history files. Existing lookup features may contact the providers listed in the next section when those features are run.

## Existing data providers

The implementation retains its existing service integrations: ipify for public IP lookup, ipwho.is for GeoIP/ASN, `rdap.org` for RDAP, `crt.sh` for certificate-transparency lookup, Google/Cloudflare/Quad9/OpenDNS for resolver comparison, WHOIS through `python-whois`, and AbuseIPDB only when an API key is configured. Other new checks use the system resolver, Python socket/TLS features, the user's installed route-tracing program, or the existing HTTP client. Provider availability and rate limits can change independently of IP-FINDER.

## Run tests

The regression suite covers success paths for tools 01–40, menu dispatch, report exports, URL/input validation and selected error/bounds cases. Network-facing behavior is mocked so the suite does not intentionally contact public targets:

```bash
python -m unittest discover -s tests -v
```

A GitHub Actions workflow runs this test suite on Python 3.10–3.13.

## Responsible use

- Test only systems you own or have explicit authorization to inspect.
- Keep batch DNS checks and repeated connection/uptime checks within their built-in limits.
- DNS, CT and header results are observations; they may be stale, partial or inconclusive.
- A TLS negotiation failure can be caused by the server, local OpenSSL policy, or network filtering.
- No tool should be interpreted as a full penetration test or compliance certification.

## Documentation references

- [Python `ssl` documentation](https://docs.python.org/3/library/ssl.html)
- [dnspython resolver documentation](https://dnspython.readthedocs.io/en/stable/resolver.html)
- [Let's Encrypt: Certificate Transparency logs](https://letsencrypt.org/docs/ct-logs/)
- [Termux package management](https://github.com/termux/termux-packages/wiki/Package-Management)

## License

MIT — see [`LICENSE`](LICENSE).
