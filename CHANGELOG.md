# Changelog

## v1.0.0

- Retained the IP-FINDER name, DevBrezz author label and version constant.
- Expanded the interactive menu to 40 tools.
- Added DNS resolver comparison, route diagnostics, bounded TCP stability checks, TLS version compatibility checks, HTTP OPTIONS inspection, IPv6 readiness, local history, batch DNS, deeper email DNS checks, configuration validation, bounded uptime monitoring and preset diagnostic profiles.
- Added TXT/JSON export documentation, local privacy notes, tests and GitHub Actions workflow.


## v1.0.0 — verification fixes

- Expanded regression coverage to exercise successful mocked paths for tools 01–40 and verify that every numbered menu option dispatches to a handler.
- Made malformed URL/IPv6 syntax return a validation error instead of escaping as a parser exception.
- Changed header-only HTTP checks to stream responses and close them promptly rather than downloading page content unnecessarily.
- Bounded Certificate Transparency response consumption to 4 MiB in addition to the 100-name result cap.
- Fixed ASN formatting when the provider already returns an `AS` prefix.
- Corrected email DNS deep-check status reporting so timeout/error markers are not reported as MX or DKIM records.
- Made `python-whois` optional at runtime; its absence no longer prevents the rest of the toolkit from starting.
- Hardened local history viewing/comparison against malformed entries.
